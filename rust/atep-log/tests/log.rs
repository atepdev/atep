use std::sync::{Arc, Mutex};

use atep_core::attestation::claims;
use atep_core::consts::*;
use atep_core::envelope::{sign, submitted_form, with_unprotected, SignParams};
use atep_core::keys::Identity;
use atep_core::log::{hash_leaf, verify_consistency, Checkpoint, InclusionCheck, OfflineInclusion};
use atep_core::srl::{RevocationEntry, RevokedId};
use atep_core::trust::{Rule, TrustPolicy};
use atep_core::verify::{verify, Policy};
use atep_log::client::{exchange_remote, LogClient, RemoteInclusion};
use atep_log::gossip::{exchange, NoProofs, Observation};
use atep_log::http::{handle, spawn, Request};
use atep_log::testkit::*;
use atep_log::{Log, LogConfig, SubmitErr};

const NOW: i64 = 1_800_000_000;

fn open(dir: &TempDir, now: i64) -> Log {
    Log::open_with(dir.path(), Some(ident(1)), LogConfig::default(), now).unwrap()
}

fn code(e: SubmitErr) -> String {
    match e {
        SubmitErr::Rejected(e) => e.code.to_string(),
        SubmitErr::Log(e) => panic!("log error {e}"),
    }
}

fn checker(log: &Log) -> OfflineInclusion {
    OfflineInclusion {
        trusted_logs: vec![log.log_id()],
        known_bundles: vec![],
    }
}

#[test]
fn policy_is_the_first_entry_and_has_a_proof() {
    let dir = TempDir::new("policy");
    let mut log = open(&dir, NOW);
    assert_eq!(log.tree_size(), 1);
    let first = &log.entries_meta()[0];
    assert!(first.is_policy);
    assert_eq!(first.claim.as_deref(), Some(atep_log::POLICY_CLAIM));
    let leaf = first.leaf;
    let (idx, proof) = log.inclusion_proof(&leaf, NOW).unwrap().unwrap();
    assert_eq!(idx, 0);
    let raw = log.read_entry(0).unwrap();
    let used = checker(&log)
        .check(&raw, Some(&proof.to_value()), NOW)
        .unwrap();
    assert_eq!(used.tree_size, 1);
    // The policy endpoint serves it with the admission rules.
    let m = Mutex::new(log);
    let r = handle(&m, &Request::new("GET", "/v1/policy", vec![]), NOW);
    assert_eq!(r.status, 200);
    let j = r.json_body().unwrap();
    assert_eq!(j["first-entry"], true);
    assert!(j["policy"]["admission"].as_array().unwrap().len() >= 5);
    assert_eq!(j["policy"]["checkpoint-interval-seconds"], 3600);
    assert!(j["policy"]["key-custody"].as_str().unwrap().contains("HSM"));
}

#[test]
fn submit_returns_a_verifiable_proof_and_is_idempotent() {
    let dir = TempDir::new("submit");
    let mut log = open(&dir, NOW);
    let (ca, alice) = (ident(2), ident(3));
    let att = attest(
        &ca,
        alice.agent_id(),
        claims::OPERATOR,
        text_map(&[("name", "Acme")]),
        NOW - 10,
        90,
    );
    let out = log.submit(&att, NOW).unwrap();
    assert!(!out.duplicate);
    assert_eq!(out.index, 1);
    let used = checker(&log)
        .check(
            &submitted_form(&att).unwrap(),
            Some(&out.proof.to_value()),
            NOW,
        )
        .unwrap();
    assert_eq!(used.tree_size, 2);
    // Embed the proof (-70012) and resubmit: same entry, no growth.
    let with_proof = with_unprotected(
        &att,
        vec![(HDR_INCLUSION_PROOF, Some(out.proof.to_value()))],
    )
    .unwrap();
    let again = log.submit(&with_proof, NOW + 5).unwrap();
    assert!(again.duplicate);
    assert_eq!(again.index, out.index);
    assert_eq!(log.tree_size(), 2);
    let again2 = log.submit(&att, NOW + 6).unwrap();
    assert!(again2.duplicate);
    // The proof also verifies as part of an envelope: inclusion required by
    // the trust policy, online check by the log itself.
    let tp = TrustPolicy {
        roots: vec![ca.agent_id()],
        rules: vec![Rule::new(claims::OPERATOR)],
        require_inclusion: true,
        trusted_logs: vec![log.log_id()],
        ..TrustPolicy::default()
    };
    let bob = Identity::generate(true).unwrap();
    let payload = SignParams::new(b"hi", CT_DATA, [9; 16], NOW - 1);
    let env = atep_core::encrypt(
        &sign(&alice, &payload).unwrap(),
        bob.public(),
        &atep_core::EncryptRandomness {
            x25519_ephemeral: [5; 32],
            mlkem_m: [6; 32],
            iv: [7; 12],
        },
    )
    .unwrap();
    let pol = Policy {
        recipient: Some(&bob),
        trust: Some(tp.clone()),
        attestations: vec![with_proof.clone()],
        ..Policy::default()
    };
    let v = verify(&env, &pol, NOW).unwrap();
    assert_eq!(v.checkpoint.unwrap().log, log.log_id());
    let online = Policy {
        recipient: Some(&bob),
        trust: Some(tp),
        attestations: vec![att.clone()],
        inclusion: Some(&log),
        ..Policy::default()
    };
    assert!(verify(&env, &online, NOW).is_ok());
}

#[test]
fn only_valid_trust_documents_are_admitted() {
    let dir = TempDir::new("reject");
    let mut log = open(&dir, NOW);
    let (ca, alice) = (ident(2), ident(3));
    let good = attest(
        &ca,
        alice.agent_id(),
        claims::OPERATOR,
        text_map(&[("name", "Acme")]),
        NOW - 10,
        90,
    );

    // Data envelope (signed, not encrypted-labelled): never logged.
    let data = sign(
        &alice,
        &SignParams::new(b"payload", CT_DATA, [1; 16], NOW - 1),
    )
    .unwrap();
    assert_eq!(code(log.submit(&data, NOW).unwrap_err()), "data_envelope");
    // Encrypted envelope.
    let bob = Identity::generate(true).unwrap();
    let enc = atep_core::encrypt(
        &data,
        bob.public(),
        &atep_core::EncryptRandomness {
            x25519_ephemeral: [5; 32],
            mlkem_m: [6; 32],
            iv: [7; 12],
        },
    )
    .unwrap();
    assert_eq!(
        code(log.submit(&enc, NOW).unwrap_err()),
        "encrypted_envelope"
    );
    // A checkpoint cannot be submitted.
    let cp = log.latest_checkpoint().unwrap().raw.clone();
    assert_eq!(
        code(log.submit(&cp, NOW).unwrap_err()),
        "content_type_not_loggable"
    );
    // Garbage and trailing bytes.
    assert_eq!(code(log.submit(b"\x01\x02", NOW).unwrap_err()), "malformed");
    let mut trailing = good.clone();
    trailing.push(0);
    assert_eq!(code(log.submit(&trailing, NOW).unwrap_err()), "malformed");
    // Altered signature: step 4 inside verification_failed.
    let mut bad_sig = good.clone();
    let n = bad_sig.len();
    // Flip a byte in the middle of the last signature.
    bad_sig[n - 100] ^= 1;
    match log.submit(&bad_sig, NOW).unwrap_err() {
        SubmitErr::Rejected(e) => {
            assert_eq!(e.code, "verification_failed");
            assert!(e.rejection.is_some());
        }
        _ => panic!(),
    }
    // Expired.
    let expired = attest(
        &ca,
        alice.agent_id(),
        claims::OPERATOR,
        text_map(&[("name", "x")]),
        NOW - 100 * DAY,
        30,
    );
    assert_eq!(
        code(log.submit(&expired, NOW).unwrap_err()),
        "verification_failed"
    );
    // Unknown claim in the core namespace.
    let bogus = attest(
        &ca,
        alice.agent_id(),
        "https://atep.dev/claims/trustworthy",
        text_map(&[]),
        NOW - 10,
        90,
    );
    assert_eq!(
        code(log.submit(&bogus, NOW).unwrap_err()),
        "claim_vocabulary"
    );
    // Own namespace is open.
    let own = attest(
        &ca,
        alice.agent_id(),
        "https://example.com/claims/fleet",
        text_map(&[]),
        NOW - 10,
        90,
    );
    assert!(log.submit(&own, NOW).is_ok());
    // domain-control needs data.domain.
    let dc = attest(
        &ca,
        alice.agent_id(),
        claims::DOMAIN_CONTROL,
        text_map(&[("domain", "Example.COM")]),
        NOW - 10,
        90,
    );
    assert_eq!(code(log.submit(&dc, NOW).unwrap_err()), "schema_invalid");
    // Lifetime over 400 days: build by hand because issuance refuses it.
    let att = atep_core::attestation::Attestation {
        subject: alice.agent_id(),
        issuer: ca.agent_id(),
        claim: claims::OPERATOR.into(),
        data: text_map(&[]),
        evidence: None,
        evidence_uri: None,
        id: [4; 16],
    };
    let payload = att.encode();
    let mut p = SignParams::new(&payload, CT_ATTESTATION, [2; 16], NOW - 10);
    p.expires_at = Some(NOW - 10 + 401 * DAY);
    let long = sign(&ca, &p).unwrap();
    assert_eq!(
        code(log.submit(&long, NOW).unwrap_err()),
        "lifetime_exceeded"
    );
    // Issuer field differs from the signer.
    let mut forged = att.clone();
    forged.issuer = alice.agent_id();
    let payload = forged.encode();
    let mut p = SignParams::new(&payload, CT_ATTESTATION, [3; 16], NOW - 10);
    p.expires_at = Some(NOW + DAY);
    let mism = sign(&ca, &p).unwrap();
    assert_eq!(code(log.submit(&mism, NOW).unwrap_err()), "schema_invalid");
    // Unknown signer without an inline bundle.
    let stranger = ident(9);
    let mut ap = atep_core::attestation::AttestationParams::new(
        alice.agent_id(),
        claims::OPERATOR,
        NOW - 10,
        NOW + 30 * DAY,
    )
    .unwrap();
    ap.include_bundle = false;
    ap.data = text_map(&[]);
    let nobundle = atep_core::attestation::issue(&stranger, &ap).unwrap();
    match log.submit(&nobundle, NOW).unwrap_err() {
        SubmitErr::Rejected(e) => assert_eq!(
            e.rejection.unwrap().code.as_str(),
            "signer_bundle_unavailable"
        ),
        _ => panic!(),
    }
    // But once the log knows the bundle, later submissions may omit it.
    log.submit(&good, NOW).unwrap();
    let mut ap = atep_core::attestation::AttestationParams::new(
        stranger.agent_id(),
        claims::OPERATOR,
        NOW - 10,
        NOW + 30 * DAY,
    )
    .unwrap();
    ap.include_bundle = false;
    ap.data = text_map(&[]);
    let later = atep_core::attestation::issue(&ca, &ap).unwrap();
    assert!(log.submit(&later, NOW).is_ok());
    // Nothing rejected was logged.
    let before = log.tree_size();
    let _ = log.submit(&data, NOW);
    assert_eq!(log.tree_size(), before);
}

#[test]
fn srl_rules_and_revoked_issuers() {
    let dir = TempDir::new("srl");
    let mut log = open(&dir, NOW);
    let (ca, alice) = (ident(2), ident(3));
    let entry = |who: &Identity, at: i64| RevocationEntry {
        id: RevokedId::Identity(who.agent_id()),
        reason: "compromised".into(),
        revoked_at: at,
    };
    let s1 = srl(&ca, 1, NOW - 100, vec![]);
    assert!(log.submit(&s1, NOW).is_ok());
    // Same sequence, different content, and lower sequences are rollbacks.
    let s1b = srl(&ca, 1, NOW - 90, vec![]);
    assert_eq!(code(log.submit(&s1b, NOW).unwrap_err()), "srl_rollback");
    let s2 = srl(&ca, 2, NOW - 50, vec![entry(&alice, NOW - 40)]);
    assert!(log.submit(&s2, NOW).is_ok());
    // alice is now compromised from NOW-40: her later attestations fail step 8.
    let a = attest(
        &alice,
        ident(4).agent_id(),
        claims::OPERATOR,
        text_map(&[]),
        NOW - 10,
        30,
    );
    match log.submit(&a, NOW).unwrap_err() {
        SubmitErr::Rejected(e) => assert_eq!(e.rejection.unwrap().step, 8),
        _ => panic!(),
    }
    // One issued before the revocation is fine.
    let old = attest(
        &alice,
        ident(4).agent_id(),
        claims::OPERATOR,
        text_map(&[("n", "1")]),
        NOW - 60,
        30,
    );
    assert!(log.submit(&old, NOW).is_ok());
}

#[test]
fn consistency_and_checkpoints_follow_the_tree() {
    let dir = TempDir::new("cons");
    let mut log = open(&dir, NOW);
    let ca = ident(2);
    let mut cps = vec![log.latest_checkpoint().unwrap().clone()];
    for i in 0..9u8 {
        let att = attest(
            &ca,
            ident(10 + i).agent_id(),
            claims::OPERATOR,
            text_map(&[]),
            NOW - 10,
            90,
        );
        log.submit(&att, NOW + i as i64).unwrap();
        cps.push(log.latest_checkpoint().unwrap().clone());
    }
    assert_eq!(log.tree_size(), 10);
    for a in &cps {
        for b in &cps {
            if a.size <= b.size {
                let p = log.consistency(a.size, b.size).unwrap();
                assert!(verify_consistency(
                    a.size, b.size, &a.root, &b.root, &p.path
                ));
            }
        }
    }
    assert!(log.consistency(5, 99).is_err());
    assert!(log.consistency(6, 5).is_err());
    // On demand checkpoint, and cadence.
    assert!(!log.checkpoint_due(NOW + 100));
    assert!(log.checkpoint_due(NOW + 3600 + 10));
    let before = log.checkpoints().len();
    log.checkpoint(NOW + 200).unwrap();
    assert_eq!(log.checkpoints().len(), before + 1);
    // The checkpoint is a verifiable signed envelope with the right type.
    let c = log.latest_checkpoint().unwrap();
    let used = checker(&log).load_checkpoint(&c.raw, NOW + 200).unwrap();
    assert_eq!(used.tree_size, 10);
    let v = verify(&c.raw, &Policy::default(), NOW + 200).unwrap();
    assert_eq!(v.content_type, "application/atep-checkpoint+cbor");
    let cp = Checkpoint::from_payload(&v.payload).unwrap();
    assert_eq!(cp.root_hash, c.root);
}

#[test]
fn reload_recovers_and_tampering_is_detected() {
    let dir = TempDir::new("reload");
    let ca = ident(2);
    let (root_before, size_before);
    {
        let mut log = open(&dir, NOW);
        for i in 0..4u8 {
            let att = attest(
                &ca,
                ident(20 + i).agent_id(),
                claims::OPERATOR,
                text_map(&[("n", "x")]),
                NOW - 10,
                90,
            );
            log.submit(&att, NOW + i as i64).unwrap();
        }
        root_before = log.latest_checkpoint().unwrap().root;
        size_before = log.tree_size();
    }
    // Reopen later (attestations are valid; checkpoints and entries re-verify).
    {
        let log = Log::open(dir.path(), LogConfig::default(), NOW + 100 * DAY).unwrap();
        assert_eq!(log.tree_size(), size_before);
        assert_eq!(log.checkpoints().last().unwrap().root, root_before);
    }
    // A crash in the middle of an append: torn tail is cut off.
    let entries = dir.path().join("entries.rec");
    let good = std::fs::read(&entries).unwrap();
    let mut torn = good.clone();
    torn.extend_from_slice(&[0, 0, 0xff, 0xff, 1, 2, 3]);
    std::fs::write(&entries, &torn).unwrap();
    {
        let mut log = Log::open(dir.path(), LogConfig::default(), NOW + 200).unwrap();
        assert_eq!(log.tree_size(), size_before);
        let att = attest(
            &ca,
            ident(40).agent_id(),
            claims::OPERATOR,
            text_map(&[]),
            NOW - 10,
            90,
        );
        log.submit(&att, NOW + 300).unwrap();
        assert_eq!(log.tree_size(), size_before + 1);
    }
    // A crash after the entry was written but before the checkpoint: the next
    // start issues the missing checkpoint.
    let cps = dir.path().join("checkpoints.rec");
    {
        let data = std::fs::read(&cps).unwrap();
        // Remove the last record by truncating at its start.
        let mut pos = 8;
        let mut last_start = 8;
        while pos < data.len() {
            last_start = pos;
            let n = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4 + n + 8;
        }
        std::fs::write(&cps, &data[..last_start]).unwrap();
    }
    {
        let log = Log::open(dir.path(), LogConfig::default(), NOW + 400).unwrap();
        assert_eq!(log.latest_checkpoint().unwrap().size, log.tree_size());
    }
    // Rewriting history: replace entry 2 by a different, perfectly valid
    // document. Every entry still verifies, but the signed checkpoints no
    // longer match the tree.
    let loaded = atep_log::store::RecordFile::read_all(&entries).unwrap();
    let evil = {
        let att = attest(
            &ca,
            ident(77).agent_id(),
            claims::OPERATOR,
            text_map(&[("n", "evil")]),
            NOW - 10,
            90,
        );
        let mut rec = NOW.to_be_bytes().to_vec();
        rec.extend_from_slice(&submitted_form(&att).unwrap());
        rec
    };
    let fresh = TempDir::new("rewrite");
    std::fs::copy(
        dir.path().join("identity.key"),
        fresh.path().join("identity.key"),
    )
    .unwrap();
    std::fs::copy(&cps, fresh.path().join("checkpoints.rec")).unwrap();
    {
        let (mut f, _, _) =
            atep_log::store::RecordFile::open(&fresh.path().join("entries.rec")).unwrap();
        for (i, r) in loaded.iter().enumerate() {
            f.append(if i == 2 { &evil } else { &r.payload }).unwrap();
        }
    }
    let err = Log::open(fresh.path(), LogConfig::default(), NOW + 500)
        .err()
        .unwrap();
    assert!(
        matches!(&err, atep_log::LogError::Corrupt(m) if m.contains("altered") || m.contains("does not match")),
        "{err}"
    );
    // A flipped byte inside an entry is also fatal.
    let mut data = std::fs::read(&entries).unwrap();
    let mid = data.len() / 2;
    data[mid] ^= 1;
    let broken = TempDir::new("flip");
    std::fs::copy(
        dir.path().join("identity.key"),
        broken.path().join("identity.key"),
    )
    .unwrap();
    std::fs::copy(&cps, broken.path().join("checkpoints.rec")).unwrap();
    std::fs::write(broken.path().join("entries.rec"), &data).unwrap();
    assert!(matches!(
        Log::open(broken.path(), LogConfig::default(), NOW + 500),
        Err(atep_log::LogError::Corrupt(_))
    ));
    // Opening a directory twice at the same time is refused.
    let _held = Log::open(dir.path(), LogConfig::default(), NOW + 500).unwrap();
    assert!(Log::open(dir.path(), LogConfig::default(), NOW + 500).is_err());
}

#[test]
fn directories_and_lookup_derive_from_the_log() {
    let dir = TempDir::new("dirs");
    let mut log = open(&dir, NOW);
    let (root, ca, alice) = (ident(2), ident(3), ident(4));
    log.submit(
        &delegate(&root, ca.agent_id(), &[claims::OPERATOR], NOW - 20),
        NOW,
    )
    .unwrap();
    log.submit(
        &domain_control(&ca, ca.agent_id(), "ca.example.com", NOW - 20),
        NOW,
    )
    .unwrap();
    log.submit(
        &attest(
            &ca,
            alice.agent_id(),
            claims::OPERATOR,
            text_map(&[("name", "A")]),
            NOW - 10,
            90,
        ),
        NOW,
    )
    .unwrap();
    log.submit(
        &attest(
            &ca,
            alice.agent_id(),
            "https://example.com/claims/x",
            text_map(&[]),
            NOW - 10,
            90,
        ),
        NOW,
    )
    .unwrap();
    let m = Mutex::new(log);
    let get = |p: &str| {
        handle(&m, &Request::new("GET", p, vec![]), NOW)
            .json_body()
            .unwrap()
    };
    let issuers = get("/v1/issuers");
    let ca_row = issuers["issuers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["issuer"] == ca.agent_id().to_text())
        .unwrap();
    assert_eq!(ca_row["delegated-claims"][0], claims::OPERATOR);
    assert_eq!(ca_row["delegated-by"][0], root.agent_id().to_text());
    assert_eq!(
        ca_row["srl-urls"][0],
        "https://ca.example.com/.well-known/atep-revocations.cbor"
    );
    assert!(ca_row["claims"].as_array().unwrap().len() >= 3);
    let one = get(&format!("/v1/issuers?issuer={}", root.agent_id().to_text()));
    assert_eq!(one["issuers"].as_array().unwrap().len(), 1);
    let claim_dir = get("/v1/claims");
    let ops = claim_dir["claim-types"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["claim"] == claims::OPERATOR)
        .unwrap();
    assert_eq!(ops["entries"], 1);
    assert_eq!(ops["core"], true);
    assert!(ops["definition"].is_string());
    let custom = claim_dir["claim-types"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["claim"] == "https://example.com/claims/x")
        .unwrap();
    assert_eq!(custom["core"], false);
    // Lookup by subject, with and without a claim filter; percent encoded id.
    let l = get(&format!(
        "/v1/lookup?subject={}",
        alice.agent_id().to_text().replace(':', "%3A")
    ));
    assert_eq!(l["entries"].as_array().unwrap().len(), 2);
    let l = get(&format!(
        "/v1/lookup?subject={}&claim=operator",
        alice.agent_id()
    ));
    assert_eq!(l["entries"].as_array().unwrap().len(), 1);
    let bad = handle(
        &m,
        &Request::new("GET", "/v1/lookup?subject=nope", vec![]),
        NOW,
    );
    assert_eq!(bad.status, 400);
    assert_eq!(
        handle(&m, &Request::new("GET", "/v1/nothing", vec![]), NOW).status,
        404
    );
}

#[test]
fn http_server_end_to_end() {
    let dir = TempDir::new("http");
    let log = Arc::new(Mutex::new(open(&dir, NOW)));
    let log_id = log.lock().unwrap().log_id();
    let server = spawn(log.clone(), "127.0.0.1:0", Arc::new(|| NOW + 1)).unwrap();
    let client = LogClient::new(&format!("http://{}", server.addr)).unwrap();
    let ca = ident(2);
    let att = attest(
        &ca,
        ident(3).agent_id(),
        claims::OPERATOR,
        text_map(&[("name", "A")]),
        NOW - 10,
        90,
    );
    let (proof, dup) = client.submit(&att).unwrap();
    assert!(!dup);
    let checker = OfflineInclusion {
        trusted_logs: vec![log_id],
        known_bundles: vec![],
    };
    checker
        .check(
            &submitted_form(&att).unwrap(),
            Some(&proof.to_value()),
            NOW + 1,
        )
        .unwrap();
    let (_, dup) = client.submit(&att).unwrap();
    assert!(dup);
    // JSON submit and error shape.
    let body = serde_json::json!({ "envelope": base64_url(&att) }).to_string();
    let r = client
        .request(
            "POST",
            "/v1/submit",
            Some("application/json"),
            None,
            body.as_bytes(),
        )
        .unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(r.json().unwrap()["status"], "duplicate");
    let data = sign(&ident(3), &SignParams::new(b"x", CT_DATA, [1; 16], NOW)).unwrap();
    let r = client
        .request("POST", "/v1/submit", Some("application/cbor"), None, &data)
        .unwrap();
    assert_eq!(r.status, 422);
    assert_eq!(r.json().unwrap()["error"], "data_envelope");
    // Proofs, checkpoints, entries.
    let leaf = hash_leaf(&submitted_form(&att).unwrap());
    let p2 = client.inclusion_proof(&leaf).unwrap();
    assert_eq!(p2.leaf_index, proof.leaf_index);
    let cp = client.checkpoint().unwrap();
    let used = checker.load_checkpoint(&cp, NOW + 1).unwrap();
    assert_eq!(used.tree_size, 2);
    let cps = client.checkpoints_since(0).unwrap();
    assert!(cps.len() >= 2);
    let entries = client.entries(0, 10).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[1].1, submitted_form(&att).unwrap());
    let cons = client.consistency(1, 2).unwrap();
    assert_eq!(cons.path.len(), 1);
    // Remote online inclusion check.
    let remote = RemoteInclusion {
        client: client.clone(),
        trusted_logs: vec![log_id],
        known_bundles: vec![],
    };
    assert!(remote
        .check(&submitted_form(&att).unwrap(), None, NOW + 1)
        .is_ok());
    assert!(remote.check(b"not logged", None, NOW + 1).is_err());
    // Unsupported things.
    assert!(LogClient::new("https://x").is_err());
    let r = client
        .request("POST", "/v1/submit", None, None, &vec![0u8; 70_000])
        .unwrap();
    assert_eq!(r.status, 413);
    let r = client.get("/v1/proof/inclusion?leaf-hash=zz").unwrap();
    assert_eq!(r.status, 400);
    let r = client
        .get(&format!(
            "/v1/proof/inclusion?leaf-hash={}",
            hex::encode([7u8; 32])
        ))
        .unwrap();
    assert_eq!(r.status, 404);
}

fn base64_url(b: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(b)
}

#[test]
fn periodic_checkpoints_are_issued() {
    let dir = TempDir::new("periodic");
    let cfg = LogConfig {
        checkpoint_interval_secs: 1,
        ..LogConfig::default()
    };
    let log = Arc::new(Mutex::new(
        Log::open_with(dir.path(), Some(ident(1)), cfg, NOW).unwrap(),
    ));
    let clock = Arc::new(Mutex::new(NOW));
    let c2 = clock.clone();
    let _server = spawn(
        log.clone(),
        "127.0.0.1:0",
        Arc::new(move || *c2.lock().unwrap()),
    )
    .unwrap();
    let before = log.lock().unwrap().checkpoints().len();
    *clock.lock().unwrap() = NOW + 5;
    for _ in 0..40 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if log.lock().unwrap().checkpoints().len() > before {
            return;
        }
    }
    panic!("no periodic checkpoint was issued");
}

/// Two logs share one key but hold different histories: a log that shows
/// different trees to different viewers.
fn fork(label: &str, entries: &[(u8, &str)]) -> (TempDir, Log) {
    let dir = TempDir::new(label);
    let mut log = Log::open_with(dir.path(), Some(ident(50)), LogConfig::default(), NOW).unwrap();
    for (i, (who, name)) in entries.iter().enumerate() {
        let att = attest(
            &ident(60),
            ident(*who).agent_id(),
            claims::OPERATOR,
            text_map(&[("name", name)]),
            NOW - 10,
            90,
        );
        log.submit(&att, NOW + i as i64 + 1).unwrap();
    }
    (dir, log)
}

#[test]
fn gossip_detects_a_log_that_equivocates() {
    // Honest logs A and C, and a log B that has two histories (B1 and B2).
    let (_da, mut a) = fork("ga", &[]);
    let da2 = TempDir::new("gc");
    let mut c = Log::open_with(da2.path(), Some(ident(51)), LogConfig::default(), NOW).unwrap();
    // B's first entry (its policy) is identical in both views only if issued
    // at the same time with the same randomness; hedged signing makes the
    // policy entries differ already, so the two views disagree from index 0.
    let (_d1, mut b1) = fork("b1", &[(70, "one"), (71, "two")]);
    let (_d2, mut b2) = fork("b2", &[(70, "one"), (72, "other")]);
    assert_eq!(b1.log_id(), b2.log_id());
    assert_eq!(b1.tree_size(), b2.tree_size());
    assert_ne!(
        b1.latest_checkpoint().unwrap().root,
        b2.latest_checkpoint().unwrap().root
    );

    // A talks to B1, C talks to B2: neither sees a problem alone.
    let (ra, _) = exchange(&mut a, &mut b1, NOW + 10);
    assert!(ra.splits.is_empty());
    let (rc, _) = exchange(&mut c, &mut b2, NOW + 10);
    assert!(rc.splits.is_empty());
    // A and C gossip: C relays what it saw from B2, A compares with B1.
    let (ra, rc) = exchange(&mut a, &mut c, NOW + 20);
    let evidence = ra
        .splits
        .iter()
        .chain(rc.splits.iter())
        .next()
        .expect("split view detected");
    assert_eq!(evidence.log, b1.log_id());
    assert!(evidence.confirm(NOW + 20));
    assert_eq!(
        a.gossip_state().evidence().len() + c.gossip_state().evidence().len(),
        2
    );
    // Evidence survives a restart.
    let dir_a = a.dir().to_path_buf();
    drop(a);
    let a = Log::open(&dir_a, LogConfig::default(), NOW + 30).unwrap();
    assert_eq!(a.gossip_state().evidence().len(), 1);

    // A different size: B1 grows, B2 grows differently; the consistency
    // proof B supplies does not match the earlier checkpoint.
    let att = |n: &str| {
        attest(
            &ident(60),
            ident(73).agent_id(),
            claims::OPERATOR,
            text_map(&[("name", n)]),
            NOW - 10,
            90,
        )
    };
    b2.submit(&att("x"), NOW + 40).unwrap();
    b2.submit(&att("y"), NOW + 41).unwrap();
    let mut d = Log::open_with(
        TempDir::new("gd").path(),
        Some(ident(52)),
        LogConfig::default(),
        NOW,
    )
    .unwrap();
    let b1_cp = b1.latest_checkpoint().unwrap().raw.clone();
    let b2_cp = b2.latest_checkpoint().unwrap().raw.clone();
    assert!(matches!(
        d.observe_checkpoint(&b1_cp, NOW + 50, &NoProofs).unwrap(),
        Observation::New
    ));
    match d.observe_checkpoint(&b2_cp, NOW + 50, &b2).unwrap() {
        Observation::Split(ev) => assert!(ev.confirm(NOW + 50)),
        other => panic!("expected a split view, got {other:?}"),
    }
}

#[test]
fn honest_logs_gossip_without_alarms() {
    let (_da, mut a) = fork("ha", &[(80, "a")]);
    let db = TempDir::new("hb");
    let mut b = Log::open_with(db.path(), Some(ident(53)), LogConfig::default(), NOW).unwrap();
    for round in 0..3 {
        let att = attest(
            &ident(60),
            ident(90 + round).agent_id(),
            claims::OPERATOR,
            text_map(&[]),
            NOW - 10,
            90,
        );
        a.submit(&att, NOW + 10 * round as i64 + 1).unwrap();
        let (ra, rb) = exchange(&mut a, &mut b, NOW + 10 * round as i64 + 2);
        assert!(ra.splits.is_empty() && rb.splits.is_empty());
        assert_eq!(rb.rejected + ra.rejected, 0);
    }
    // B has seen A's checkpoints of growing sizes, each consistent.
    let seen = b.gossip_state().of_log(&a.log_id());
    assert_eq!(seen.len(), 3);
    // Exchanging again learns nothing new.
    let (ra, rb) = exchange(&mut a, &mut b, NOW + 100);
    assert!(ra.splits.is_empty() && rb.splits.is_empty());
    assert!(ra.new_checkpoints <= 1 && rb.new_checkpoints <= 1);
}

#[test]
fn gossip_over_http_finds_the_split() {
    let (_d1, b1) = fork("hb1", &[(70, "one")]);
    let (_d2, b2) = fork("hb2", &[(72, "other")]);
    let b1 = Arc::new(Mutex::new(b1));
    let b2 = Arc::new(Mutex::new(b2));
    let s1 = spawn(b1.clone(), "127.0.0.1:0", Arc::new(|| NOW + 60)).unwrap();
    let s2 = spawn(b2.clone(), "127.0.0.1:0", Arc::new(|| NOW + 60)).unwrap();
    // Honest observers A and C.
    let da = TempDir::new("hoa");
    let dc = TempDir::new("hoc");
    let a = Arc::new(Mutex::new(
        Log::open_with(da.path(), Some(ident(54)), LogConfig::default(), NOW).unwrap(),
    ));
    let c = Arc::new(Mutex::new(
        Log::open_with(dc.path(), Some(ident(55)), LogConfig::default(), NOW).unwrap(),
    ));
    let sa = spawn(a.clone(), "127.0.0.1:0", Arc::new(|| NOW + 60)).unwrap();
    let c1 = LogClient::new(&format!("http://{}", s1.addr)).unwrap();
    let c2 = LogClient::new(&format!("http://{}", s2.addr)).unwrap();
    let ca = LogClient::new(&format!("http://{}", sa.addr)).unwrap();
    assert!(exchange_remote(&a, &c1, NOW + 60)
        .unwrap()
        .splits
        .is_empty());
    assert!(exchange_remote(&c, &c2, NOW + 60)
        .unwrap()
        .splits
        .is_empty());
    // C gossips with A: A's relay of B1 meets C's B2.
    let r = exchange_remote(&c, &ca, NOW + 60).unwrap();
    assert!(!r.splits.is_empty(), "{r:?}");
    assert!(r.splits.iter().all(|s| s.confirm(NOW + 60)));
    // And A's own endpoint reports the evidence too.
    let j = ca.get_json("/v1/gossip").unwrap();
    assert!(!j["observed"].as_array().unwrap().is_empty());
}
