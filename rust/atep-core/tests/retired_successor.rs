//! Library level tests of `retired` and `successor` (spec section 7,
//! "Retirement and succession"), independent of the vector files. The vectors
//! (`retired-*`, `successor-*`, `srl-context`, `log-admission`, `monitor`) are
//! the conformance suite; these tests cover the API and the edges the tables
//! do not.

use atep_core::attestation::{claims, Attestation, AttestationParams};
use atep_core::cbor::Value;
use atep_core::consts::*;
use atep_core::envelope::{sign, SignMode, SignParams};
use atep_core::keys::{AgentId, Identity, Seeds};
use atep_core::srl::{
    create, ingest, ingest_in, LoadContext, MemorySrlCache, RevocationEntry, RevokedId, Srl,
};
use atep_core::{verify, ErrorCode, Policy, TrustPolicy};

const NOW: i64 = 1_800_000_000;

fn ident(n: u8) -> Identity {
    Identity::from_seeds(Seeds {
        ed25519: [n; 32],
        mldsa65: [n + 1; 32],
        x25519: None,
        mlkem768: None,
    })
    .unwrap()
}

fn text_map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (Value::text(k), v))
            .collect(),
    )
}

fn attestation(subject: AgentId, issuer: AgentId, claim: &str, data: Value) -> Attestation {
    Attestation {
        subject,
        issuer,
        claim: claim.into(),
        data,
        evidence: None,
        evidence_uri: None,
        id: [1; 16],
    }
}

/// A retirement of `x` issued at `issued` that expires at `expires`.
fn retirement(x: &Identity, issued: i64, expires: i64, id: u8, bundle: bool) -> Vec<u8> {
    let mut p = AttestationParams::new(x.agent_id(), claims::RETIRED, issued, expires).unwrap();
    p.id = [id; 16];
    p.nonce = [id; 16];
    p.mode = SignMode::Deterministic;
    p.allow_long_default = true;
    p.include_bundle = bundle;
    atep_core::attestation::issue(x, &p).unwrap()
}

/// A trust document envelope from `x` (an SRL type, so it may travel unencrypted).
fn doc_from(x: &Identity, issued: i64, bundle: bool) -> Vec<u8> {
    let payload = Value::Map(vec![]).encode();
    let mut p = SignParams::new(&payload, CT_SRL, [9; 16], issued);
    p.mode = SignMode::Deterministic;
    p.include_bundle = bundle;
    sign(x, &p).unwrap()
}

#[test]
fn layouts_of_retired_and_successor() {
    let (a, b) = (ident(1).agent_id(), ident(3).agent_id());
    let empty = || Value::Map(vec![]);
    let reason = |v: Value| text_map(vec![("reason", v)]);
    let ok = |att: Attestation| att.validate_claim_data().is_ok();

    // retired: subject equals issuer, data {} or a text reason, other members free.
    assert!(ok(attestation(a, a, claims::RETIRED, empty())));
    assert!(ok(attestation(
        a,
        a,
        claims::RETIRED,
        reason(Value::text("done"))
    )));
    assert!(ok(attestation(
        a,
        a,
        claims::RETIRED,
        text_map(vec![("note", Value::Int(7)), ("reason", Value::text("x"))])
    )));
    assert!(!ok(attestation(b, a, claims::RETIRED, empty())));
    assert!(!ok(attestation(
        a,
        a,
        claims::RETIRED,
        reason(Value::Int(5))
    )));

    // successor: subject differs from issuer, same reason rule.
    assert!(ok(attestation(b, a, claims::SUCCESSOR, empty())));
    assert!(ok(attestation(
        b,
        a,
        claims::SUCCESSOR,
        reason(Value::text("rotation"))
    )));
    assert!(!ok(attestation(a, a, claims::SUCCESSOR, empty())));
    assert!(!ok(attestation(
        b,
        a,
        claims::SUCCESSOR,
        reason(Value::Int(5))
    )));

    // The layouts bind issuance too: a tool cannot issue a malformed one.
    let x = ident(1);
    let p = AttestationParams::new(b, claims::RETIRED, NOW - 100, NOW + 100).unwrap();
    assert!(atep_core::attestation::issue(&x, &p).is_err());
    let p = AttestationParams::new(x.agent_id(), claims::SUCCESSOR, NOW - 100, NOW + 100).unwrap();
    assert!(atep_core::attestation::issue(&x, &p).is_err());
}

#[test]
fn policy_member_follow_succession() {
    let parse = |s: &str| TrustPolicy::from_json(&serde_json::from_str(s).unwrap());
    assert!(!parse("{}").unwrap().follow_succession);
    assert!(
        parse(r#"{"follow_succession": true}"#)
            .unwrap()
            .follow_succession
    );
    assert!(
        !parse(r#"{"follow_succession": false}"#)
            .unwrap()
            .follow_succession
    );
    assert!(parse(r#"{"follow_succession": "yes"}"#).is_err());
    assert!(parse(r#"{"follow_succession": 1}"#).is_err());
    // Members the specification does not define stay errors.
    assert!(parse(r#"{"follow_successors": true}"#).is_err());
    assert!(parse(r#"{"follow_succession": true, "extra": 1}"#).is_err());
}

#[test]
fn a_retirement_without_inline_bundle_uses_the_bundle_of_the_envelope_under_verification() {
    let x = ident(1);
    let r = retirement(&x, NOW - 1_000, NOW + 86_400, 1, false);
    // E carries X's bundle inline; R does not and nothing is cached.
    let e = doc_from(&x, NOW - 10, true);
    let pol = Policy {
        attestations: vec![r.clone()],
        ..Policy::default()
    };
    let err = verify(&e, &pol, NOW).unwrap_err();
    assert_eq!((err.step, err.code), (8, ErrorCode::SignerRevoked));
    // With neither the envelope's bundle nor a cached one, R cannot be
    // validated and is ignored (E needs a cached bundle to verify at all).
    let e2 = doc_from(&x, NOW - 10, false);
    let cached = Policy {
        known_bundles: vec![x.public().clone()],
        attestations: vec![r],
        ..Policy::default()
    };
    let err = verify(&e2, &cached, NOW).unwrap_err();
    assert_eq!((err.step, err.code), (8, ErrorCode::SignerRevoked));
}

#[test]
fn only_a_retirement_of_the_signer_counts() {
    let (x, y) = (ident(1), ident(3));
    let r_y = retirement(&y, NOW - 1_000, NOW + 86_400, 2, true);
    let e = doc_from(&x, NOW - 10, true);
    let pol = Policy {
        attestations: vec![r_y],
        ..Policy::default()
    };
    assert!(verify(&e, &pol, NOW).is_ok());
    // A store of garbage and of non attestations is silently ignored.
    let pol = Policy {
        attestations: vec![vec![0xff], b"nope".to_vec(), doc_from(&x, NOW - 10, true)],
        ..Policy::default()
    };
    assert!(verify(&e, &pol, NOW).is_ok());
}

#[test]
fn the_earliest_of_the_union_wins() {
    let x = ident(1);
    let r_late = retirement(&x, NOW - 100, NOW + 86_400, 3, true);
    let r_early = retirement(&x, NOW - 5_000, NOW + 86_400, 4, true);
    let pol = Policy {
        attestations: vec![r_late, r_early],
        ..Policy::default()
    };
    // Between the two retirements: only the earlier one applies.
    let between = doc_from(&x, NOW - 2_000, true);
    assert_eq!(verify(&between, &pol, NOW).unwrap_err().step, 8);
    let before = doc_from(&x, NOW - 5_001, true);
    assert!(verify(&before, &pol, NOW).is_ok());
}

#[test]
fn loading_an_srl_uses_the_cache_as_context() {
    let (a, b) = (ident(1), ident(3));
    let mk = |who: &Identity, seq: i64, issued: i64, revoked: Vec<RevocationEntry>| {
        let s = Srl {
            issuer: who.agent_id(),
            sequence: seq,
            issued_at: issued,
            next_update: issued + 86_400,
            revoked,
        };
        create(who, &s, [seq as u8; 16], SignMode::Deterministic, true).unwrap()
    };
    let names_b = RevocationEntry {
        id: RevokedId::Identity(b.agent_id()),
        reason: "compromised".into(),
        revoked_at: NOW - 1_000,
    };
    let mut cache = MemorySrlCache::new();
    ingest(&mut cache, &mk(&a, 1, NOW - 500, vec![names_b]), &[], NOW).unwrap();
    // B was revoked from NOW - 1000 on: a list issued after that cannot load.
    let late = mk(&b, 1, NOW - 100, vec![]);
    let err = ingest(&mut cache, &late, &[], NOW).unwrap_err();
    assert_eq!((err.step, err.code), (8, ErrorCode::SignerRevoked));
    // One issued before it can.
    let early = mk(&b, 1, NOW - 2_000, vec![]);
    assert!(ingest(&mut cache, &early, &[], NOW).is_ok());
}

#[test]
fn a_failed_reload_of_the_cached_bytes_is_no_change() {
    let x = ident(1);
    // A list that names its own issuer from before its own issued-at.
    let s = Srl {
        issuer: x.agent_id(),
        sequence: 1,
        issued_at: NOW - 100,
        next_update: NOW + 86_400,
        revoked: vec![RevocationEntry {
            id: RevokedId::Identity(x.agent_id()),
            reason: "retired".into(),
            revoked_at: NOW - 200,
        }],
    };
    let raw = create(&x, &s, [1; 16], SignMode::Deterministic, true).unwrap();
    let mut cache = MemorySrlCache::new();
    assert!(ingest(&mut cache, &raw, &[], NOW).is_ok());
    // The cache now holds it, and a reload would fail step 8: it is no change.
    assert!(ingest(&mut cache, &raw, &[], NOW).is_ok());
    // A newer list of the same issuer does fail, the cached list revokes X.
    let newer = Srl {
        sequence: 2,
        ..s.clone()
    };
    let raw2 = create(&x, &newer, [2; 16], SignMode::Deterministic, true).unwrap();
    let err = ingest(&mut cache, &raw2, &[], NOW).unwrap_err();
    assert_eq!((err.step, err.code), (8, ErrorCode::SignerRevoked));
}

#[test]
fn a_retired_issuer_cannot_publish_through_the_local_store() {
    let x = ident(1);
    let r = retirement(&x, NOW - 1_000, NOW + 86_400, 5, true);
    let s = Srl {
        issuer: x.agent_id(),
        sequence: 1,
        issued_at: NOW - 500,
        next_update: NOW + 86_400,
        revoked: vec![],
    };
    let raw = create(&x, &s, [1; 16], SignMode::Deterministic, true).unwrap();
    let store = [r];
    let cx = LoadContext {
        attestations: &store,
        ..LoadContext::bundles(&[])
    };
    let mut cache = MemorySrlCache::new();
    let err = ingest_in(&mut cache, &raw, &cx, NOW).unwrap_err();
    assert_eq!((err.step, err.code), (8, ErrorCode::SignerRevoked));
    // Without the store the same bytes load (the context is what decides).
    assert!(ingest(&mut cache, &raw, &[], NOW).is_ok());
}
