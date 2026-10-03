//! M2 test vectors: attestations, chains, SRLs, log proofs and ATEP-R.
//! Generated and checked like the M1 vectors (see `vectors.rs`); the formats
//! are documented in `vectors/README.md`.

use serde_json::{json, Map, Value as J};

use crate::attestation::{self, claims, Attestation, AttestationParams};
use crate::cbor::Value;
use crate::consts::*;
use crate::encrypt::{encrypt, EncryptRandomness};
use crate::envelope::{
    sign, submitted_form, with_unprotected, SignMode, SignParams, SignedEnvelope,
};
use crate::json::{checkpoint_json, rejection_json};
use crate::keys::{sha256, AgentId, Identity};
use crate::log::{
    audit_path, consistency_proof, create_checkpoint, hash_leaf, merkle_root, Checkpoint,
    CheckpointPair, ConsistencyEvidence, ConsistencyProof, InclusionProof, OfflineInclusion,
};
use crate::srl::{self, MemorySrlCache, RevocationEntry, RevokedId, Srl, SrlPolicy, StaleMode};
use crate::vectors::*;

#[path = "vectors_anchor.rs"]
mod anchor;
#[path = "vectors_discovery.rs"]
mod discovery;
#[path = "vectors_retired.rs"]
mod retired;

const DAY: i64 = 86_400;

struct Net {
    root: Identity,
    ca1: Identity,
    ca2: Identity,
    log: Identity,
    controller: Identity,
    certifier: Identity,
    alice: Identity,
    bob: Identity,
    carol: Identity,
    mallory: Identity,
}

fn ident(name: &str, enc: bool) -> R<Identity> {
    Identity::from_seeds(vector_seeds(name, enc))
}

fn net() -> R<Net> {
    Ok(Net {
        root: ident("root", false)?,
        ca1: ident("ca1", false)?,
        ca2: ident("ca2", false)?,
        log: ident("log", false)?,
        controller: ident("controller", false)?,
        certifier: ident("certifier", false)?,
        alice: ident("alice", false)?,
        bob: ident("bob", true)?,
        carol: ident("carol", true)?,
        mallory: ident("mallory", false)?,
    })
}

// ---------------------------------------------------------------------------
// Attestation builders

struct A<'a> {
    issuer: &'a Identity,
    subject: AgentId,
    claim: &'a str,
    data: Value,
    evidence: bool,
    label: &'a str,
    issued: i64,
    expires: i64,
}

impl<'a> A<'a> {
    /// Issued 20 days before NOW, valid for another 120.
    fn std(issuer: &'a Identity, subject: AgentId, claim: &'a str, label: &'a str) -> A<'a> {
        A {
            issuer,
            subject,
            claim,
            data: Value::Map(vec![]),
            evidence: false,
            label,
            issued: NOW - 20 * DAY,
            expires: NOW + 120 * DAY,
        }
    }
    fn data(mut self, d: Value) -> Self {
        self.data = d;
        self
    }
    fn evidence(mut self) -> Self {
        self.evidence = true;
        self
    }
    fn window(mut self, issued: i64, expires: i64) -> Self {
        self.issued = issued;
        self.expires = expires;
        self
    }
    fn id(&self) -> [u8; 16] {
        label_hash(&format!("att/{}", self.label))[..16]
            .try_into()
            .unwrap()
    }
    fn evidence_hash(&self) -> Option<[u8; 32]> {
        self.evidence
            .then(|| label_hash(&format!("evidence/{}", self.label)))
    }
}

fn text_map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (Value::text(k), v))
            .collect(),
    )
}

fn texts(items: &[&str]) -> Value {
    Value::Array(items.iter().map(|t| Value::text(t)).collect())
}

/// Issue through the library helper (checks lifetime tiers and claim rules).
fn issue_att(a: &A) -> R<Vec<u8>> {
    let mut p = AttestationParams::new(a.subject, a.claim, a.issued, a.expires)?;
    p.data = a.data.clone();
    p.evidence = a.evidence_hash();
    p.id = a.id();
    p.nonce = nonce(&format!("att/{}", a.label));
    p.mode = SignMode::Deterministic;
    p.allow_long_default = true;
    attestation::issue(a.issuer, &p)
}

/// Sign an attestation payload without any of the issuance checks, optionally
/// editing the payload map first. Used to build invalid attestations.
fn forge_att(a: &A, edit: impl FnOnce(&mut Vec<(Value, Value)>)) -> R<Vec<u8>> {
    let att = Attestation {
        subject: a.subject,
        issuer: a.issuer.agent_id(),
        claim: a.claim.to_string(),
        data: a.data.clone(),
        evidence: a.evidence_hash(),
        evidence_uri: None,
        id: a.id(),
    };
    let mut v = att.to_value();
    if let Value::Map(m) = &mut v {
        edit(m);
    }
    let payload = v.encode();
    let mut sp = SignParams::new(
        &payload,
        CT_ATTESTATION,
        nonce(&format!("att/{}", a.label)),
        a.issued,
    );
    sp.expires_at = Some(a.expires);
    sp.mode = SignMode::Deterministic;
    sign(a.issuer, &sp)
}

fn drop_key(m: &mut Vec<(Value, Value)>, key: &str) {
    m.retain(|(k, _)| k.as_text() != Some(key));
}

fn set_key(m: &mut [(Value, Value)], key: &str, val: Value) {
    for (k, v) in m.iter_mut() {
        if k.as_text() == Some(key) {
            *v = val;
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Envelopes under test

fn envelope_for(
    net: &Net,
    sender: &Identity,
    label: &str,
    class: Option<&str>,
    payload: Vec<u8>,
    inline: &[&[u8]],
) -> R<Vec<u8>> {
    let mut sp = SignParams::new(&payload, CT_DATA, nonce(label), NOW - 60);
    sp.expires_at = Some(NOW + 3_600);
    sp.mode = SignMode::Deterministic;
    sp.command_class = class;
    let mut signed = sign(sender, &sp)?;
    if !inline.is_empty() {
        let list = inline
            .iter()
            .map(|a| Value::decode(a))
            .collect::<Result<Vec<_>, _>>()?;
        signed = with_unprotected(&signed, vec![(HDR_ATTESTATIONS, Some(Value::Array(list)))])?;
    }
    let rnd = EncryptRandomness {
        x25519_ephemeral: label_hash(&format!("{label}/x25519-ephemeral")),
        mlkem_m: label_hash(&format!("{label}/mlkem-m")),
        iv: label_hash(&format!("{label}/iv"))[..12].try_into().unwrap(),
    };
    encrypt(&signed, net.bob.public(), &rnd)
}

fn rule(claim: &str) -> J {
    json!({ "claim": claim })
}

fn trust_json(roots: &[&Identity], rules: Vec<J>, extra: J) -> J {
    let mut m = Map::new();
    m.insert(
        "roots".into(),
        roots
            .iter()
            .map(|r| J::String(r.agent_id().to_text()))
            .collect::<Vec<_>>()
            .into(),
    );
    m.insert("rules".into(), rules.into());
    if let Some(o) = extra.as_object() {
        for (k, v) in o {
            m.insert(k.clone(), v.clone());
        }
    }
    J::Object(m)
}

fn policy_with(net: &Net, trust: J) -> PolicySpec {
    let mut p = pol(NOW);
    p.recipient = Some(net.bob.seeds().clone());
    p.trust = Some(trust);
    p
}

/// Run the verifier on the vector and record it, checking that the outcome is
/// the one the vector is meant to show.
fn push_verify(
    out: &mut Vec<Vector>,
    category: &'static str,
    name: &str,
    description: &str,
    cbor: Vec<u8>,
    policy: PolicySpec,
    want: Option<(u8, &str)>,
) -> R<()> {
    let policy_json = policy.to_json();
    let expected = run_verify(&cbor, &policy_json)?;
    match want {
        None => {
            if expected["ok"] != true {
                return Err(e(format!(
                    "generator bug: {category}/{name} gave {expected}"
                )));
            }
        }
        Some((step, code)) => {
            if expected["ok"] != false || expected["step"] != step || expected["error"] != code {
                return Err(e(format!(
                    "generator bug: {category}/{name} wanted step {step} {code}, got {expected}"
                )));
            }
        }
    }
    out.push(Vector {
        category,
        name: name.to_string(),
        description: description.to_string(),
        cbor,
        inputs: json!({ "policy": policy_json }),
        expected,
    });
    Ok(())
}

// ---------------------------------------------------------------------------
// SRL and log builders

fn mk_srl(
    issuer: &Identity,
    label: &str,
    seq: i64,
    issued: i64,
    next: i64,
    revoked: Vec<RevocationEntry>,
) -> R<Vec<u8>> {
    let s = Srl {
        issuer: issuer.agent_id(),
        sequence: seq,
        issued_at: issued,
        next_update: next,
        revoked,
    };
    srl::create(
        issuer,
        &s,
        nonce(&format!("srl/{label}")),
        SignMode::Deterministic,
        true,
    )
}

fn unrelated() -> RevocationEntry {
    RevocationEntry {
        id: RevokedId::Attestation(
            label_hash("unrelated-attestation")[..16]
                .try_into()
                .unwrap(),
        ),
        reason: "withdrawn".into(),
        revoked_at: NOW - DAY,
    }
}

fn revoke_att(id: [u8; 16], reason: &str, at: i64) -> RevocationEntry {
    RevocationEntry {
        id: RevokedId::Attestation(id),
        reason: reason.into(),
        revoked_at: at,
    }
}

fn revoke_identity(who: &Identity, at: i64) -> RevocationEntry {
    RevocationEntry {
        id: RevokedId::Identity(who.agent_id()),
        reason: "compromised".into(),
        revoked_at: at,
    }
}

fn fresh_srl(issuer: &Identity, label: &str, mut revoked: Vec<RevocationEntry>) -> R<Vec<u8>> {
    revoked.insert(0, unrelated());
    mk_srl(issuer, label, 1, NOW - 3_600, NOW + 82_800, revoked)
}

fn stale_srl(issuer: &Identity, label: &str) -> R<Vec<u8>> {
    mk_srl(
        issuer,
        label,
        1,
        NOW - 3 * DAY,
        NOW - 2 * DAY,
        vec![unrelated()],
    )
}

/// A log tree of `size` leaves holding the given submitted envelopes at the
/// given indices, with a checkpoint signed by `log`.
struct Tree {
    leaves: Vec<Vec<u8>>,
    checkpoint: Vec<u8>,
}

fn build_tree(log: &Identity, label: &str, size: usize, at: &[(usize, &[u8])]) -> R<Tree> {
    let mut leaves: Vec<Vec<u8>> = (0..size)
        .map(|i| format!("log filler leaf {i}").into_bytes())
        .collect();
    for (i, env) in at {
        leaves[*i] = submitted_form(env)?;
    }
    let cp = Checkpoint {
        tree_size: size as i64,
        root_hash: merkle_root(&leaves),
        timestamp: NOW - 600,
    };
    let checkpoint = create_checkpoint(
        log,
        &cp,
        nonce(&format!("cp/{label}")),
        SignMode::Deterministic,
    )?;
    Ok(Tree { leaves, checkpoint })
}

impl Tree {
    fn proof(&self, index: usize) -> R<Value> {
        Ok(InclusionProof {
            leaf_index: index as i64,
            audit_path: audit_path(index, &self.leaves),
            checkpoint: Value::decode(&self.checkpoint)?,
        }
        .to_value())
    }

    /// The attestation with its proof under `-70012`.
    fn attach(&self, att: &[u8], index: usize) -> R<Vec<u8>> {
        with_unprotected(att, vec![(HDR_INCLUSION_PROOF, Some(self.proof(index)?))])
    }
}

fn flip_path(att: &[u8]) -> R<Vec<u8>> {
    let mut v = Value::decode(att)?;
    if let Value::Tag(_, inner) = &mut v {
        if let Value::Array(a) = inner.as_mut() {
            if let Value::Map(m) = &mut a[1] {
                for (k, val) in m.iter_mut() {
                    if *k != Value::Int(HDR_INCLUSION_PROOF) {
                        continue;
                    }
                    if let Value::Map(pm) = val {
                        for (pk, pv) in pm.iter_mut() {
                            if pk.as_text() != Some("audit-path") {
                                continue;
                            }
                            if let Value::Array(path) = pv {
                                flip_last(&mut path[0]);
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(v.encode())
}

// ---------------------------------------------------------------------------
// Generation

pub(crate) fn generate(out: &mut Vec<Vector>) -> R<()> {
    let n = net()?;
    identity_vectors(out)?;
    attestation_vectors(out, &n)?;
    chain_vectors(out, &n)?;
    srl_vectors(out, &n)?;
    log_vectors(out, &n)?;
    atep_r_vectors(out, &n)?;
    m3_log_vectors(out, &n)?;
    // Appended last: the manifest order of the earlier vectors never moves.
    retired::generate(out, &n)?;
    // Appended after those: the anchoring and discovery vectors.
    anchor::generate(out, &n)?;
    discovery::generate(out, &n)?;
    // Draft 08: the vector for rust finding 57 is built with the other ATEP-R
    // vectors but listed last, so that the manifest order of every earlier
    // vector stays as it was.
    if let Some(i) = out
        .iter()
        .position(|v| v.name == "motion-member-peer-motion-stale-srl")
    {
        let v = out.remove(i);
        out.push(v);
    }
    // Draft 09: the first batch of known gaps, after everything else.
    retired::generate_gaps(out, &n)?;
    chain_gap_vectors(out, &n)?;
    Ok(())
}

/// Draft 09 batch, known gaps 9 and 15: the chain depth boundary and replay
/// checking across attestations. Appended last like the other gap vectors.
fn chain_gap_vectors(out: &mut Vec<Vector>, n: &Net) -> R<()> {
    let c = standard_chain(n)?;
    let all: [&[u8]; 3] = [&c.ca2_alice, &c.ca1_ca2, &c.root_ca1];
    let op = || vec![rule(claims::OPERATOR)];
    push_verify(
        out,
        "chain-positive",
        "depth-exactly-at-max-depth",
        "The three attestation chain of `three-level-chain` with max_depth 3: a chain of exactly max_depth attestations is within the bound. Accepted.",
        alice_env(n, "c-depth-at-max", &all)?,
        policy_with(n, trust_json(&[&n.root], op(), json!({"max_depth": 3}))),
        None,
    )?;
    push_verify(
        out,
        "chain-positive",
        "direct-claim-at-max-depth-1",
        "The root issues `operator` to alice directly (a chain of one) and the policy sets max_depth 1. Accepted.",
        alice_env(
            n,
            "c-direct-max1",
            &[&issue_att(
                &A::std(&n.root, n.alice.agent_id(), claims::OPERATOR, "root-alice-max1")
                    .data(text_map(vec![("name", Value::text("Acme Robotics Ltd"))])),
            )?],
        )?,
        policy_with(
            n,
            trust_json(
                &[&n.root],
                vec![json!({"claim": claims::OPERATOR, "root": n.root.agent_id().to_text()})],
                json!({"max_depth": 1}),
            ),
        ),
        None,
    )?;
    let mut p = policy_with(n, trust_json(&[&n.root], op(), json!({})));
    p.seen_nonces = vec![nonce("att/ca2-alice")];
    push_verify(
        out,
        "chain-positive",
        "attestation-nonce-in-seen-nonces",
        "The nonce of the inline `operator` attestation is in `seen_nonces`. Replay checking (step 6) applies to the outer envelope only: candidates are verified with it off. Accepted.",
        alice_env(n, "c-att-nonce-seen", &all)?,
        p,
        None,
    )?;
    Ok(())
}

fn identity_vectors(out: &mut Vec<Vector>) -> R<()> {
    for name in ["root", "ca1", "ca2", "log", "controller", "certifier"] {
        let seeds = vector_seeds(name, false);
        let id = Identity::from_seeds(seeds.clone())?;
        let bundle = id.public().encode();
        out.push(Vector {
            category: "identity",
            name: name.to_string(),
            description: format!(
                "Key bundle and Agent ID for `{name}` (signing keys only), used by the M2 vectors."
            ),
            cbor: bundle.clone(),
            inputs: json!({ "seeds": seeds_json(&seeds) }),
            expected: json!({
                "agent_id": id.agent_id().to_text(),
                "did": id.agent_id().to_did(),
                "agent_id_hex": hx(&id.agent_id().0),
                "bundle_len": bundle.len(),
                "ed25519_public_hex": hx(&id.public().ed25519),
                "mldsa65_public_sha256": hx(&sha256(&id.public().mldsa65)),
            }),
        });
    }
    Ok(())
}

fn attestation_vectors(out: &mut Vec<Vector>, n: &Net) -> R<()> {
    struct Case<'a> {
        name: &'a str,
        description: &'a str,
        a: A<'a>,
        evidence_uri: Option<&'a str>,
    }
    let alice = n.alice.agent_id();
    let cases = vec![
        Case {
            name: "operator-90-days",
            description: "Core `operator` claim, 90 day lifetime.",
            a: A::std(&n.ca2, alice, claims::OPERATOR, "v-operator")
                .data(text_map(vec![("name", Value::text("Acme Robotics Ltd"))]))
                .window(NOW - 10 * DAY, NOW + 80 * DAY),
            evidence_uri: None,
        },
        Case {
            name: "issuer-authority-delegation",
            description: "`issuer-authority` delegation: data.claims lists the claim types the subject may issue.",
            a: A::std(&n.root, n.ca1.agent_id(), claims::ISSUER_AUTHORITY, "v-authority").data(
                text_map(vec![(
                    "claims",
                    texts(&[claims::ISSUER_AUTHORITY, claims::OPERATOR]),
                )]),
            ),
            evidence_uri: None,
        },
        Case {
            name: "audited-400-days-with-evidence",
            description: "Audit-backed claim with an evidence hash and the full 400 day lifetime (the hard maximum, allowed).",
            a: A::std(&n.certifier, alice, claims::AUDITED, "v-audited")
                .data(text_map(vec![
                    ("audit", Value::text("SOC 2 Type II")),
                    ("date", Value::text("2026-09-01")),
                ]))
                .evidence()
                .window(NOW - 100 * DAY, NOW + 300 * DAY),
            evidence_uri: Some("https://auditor.example/reports/2026-09-01"),
        },
        Case {
            name: "fleet-member",
            description: "ATEP-R `fleet-member` claim from a fleet controller.",
            a: A::std(&n.controller, alice, claims::robotics::FLEET_MEMBER, "v-fleet-member")
                .data(text_map(vec![("fleet", Value::text("fleet-7"))])),
            evidence_uri: None,
        },
        Case {
            name: "safety-certified",
            description: "ATEP-R `safety-certified` claim: evidence hash required, 365 day lifetime.",
            a: A::std(&n.certifier, alice, claims::robotics::SAFETY_CERTIFIED, "v-safety-certified")
                .data(text_map(vec![
                    ("standard", Value::text("ISO 3691-4")),
                    ("date", Value::text("2026-09-01")),
                ]))
                .evidence()
                .window(NOW - 30 * DAY, NOW + 335 * DAY),
            evidence_uri: None,
        },
    ];
    for c in cases {
        let mut p = AttestationParams::new(c.a.subject, c.a.claim, c.a.issued, c.a.expires)?;
        p.data = c.a.data.clone();
        p.evidence = c.a.evidence_hash();
        p.evidence_uri = c.evidence_uri.map(str::to_string);
        p.id = c.a.id();
        p.nonce = nonce(&format!("att/{}", c.a.label));
        p.mode = SignMode::Deterministic;
        let env = attestation::issue(c.a.issuer, &p)?;
        let att = attestation::build(c.a.issuer, &p)?;
        out.push(Vector {
            category: "attestation",
            name: c.name.to_string(),
            description: c.description.to_string(),
            cbor: env.clone(),
            inputs: json!({
                "issuer_seeds": seeds_json(c.a.issuer.seeds()),
                "subject": c.a.subject.to_text(),
                "claim": c.a.claim,
                "data_hex": hx(&c.a.data.encode()),
                "evidence_hex": p.evidence.map(|e| hx(&e)),
                "evidence_uri": p.evidence_uri,
                "id_hex": hx(&p.id),
                "nonce_hex": hx(&p.nonce),
                "issued_at": c.a.issued,
                "expires_at": c.a.expires,
            }),
            expected: json!({
                "issuer": c.a.issuer.agent_id().to_text(),
                "payload_hex": hx(&att.encode()),
                "envelope_len": env.len(),
                "envelope_sha256": hx(&sha256(&env)),
            }),
        });
    }
    Ok(())
}

/// The standard chain: root -> ca1 -> ca2 -> alice (operator).
struct Chain {
    root_ca1: Vec<u8>,
    ca1_ca2: Vec<u8>,
    ca2_alice: Vec<u8>,
}

fn standard_chain(n: &Net) -> R<Chain> {
    Ok(Chain {
        root_ca1: issue_att(
            &A::std(
                &n.root,
                n.ca1.agent_id(),
                claims::ISSUER_AUTHORITY,
                "root-ca1",
            )
            .data(text_map(vec![(
                "claims",
                texts(&[claims::ISSUER_AUTHORITY, claims::OPERATOR]),
            )])),
        )?,
        ca1_ca2: issue_att(
            &A::std(
                &n.ca1,
                n.ca2.agent_id(),
                claims::ISSUER_AUTHORITY,
                "ca1-ca2",
            )
            .data(text_map(vec![("claims", texts(&[claims::OPERATOR]))])),
        )?,
        ca2_alice: operator_att(n, "ca2-alice", NOW - 20 * DAY, NOW + 120 * DAY)?,
    })
}

fn operator_att(n: &Net, label: &str, issued: i64, expires: i64) -> R<Vec<u8>> {
    issue_att(
        &A::std(&n.ca2, n.alice.agent_id(), claims::OPERATOR, label)
            .data(text_map(vec![("name", Value::text("Acme Robotics Ltd"))]))
            .window(issued, expires),
    )
}

fn alice_env(n: &Net, label: &str, inline: &[&[u8]]) -> R<Vec<u8>> {
    envelope_for(n, &n.alice, label, None, payload_for(label), inline)
}

fn chain_vectors(out: &mut Vec<Vector>, n: &Net) -> R<()> {
    let c = standard_chain(n)?;
    let all: [&[u8]; 3] = [&c.ca2_alice, &c.ca1_ca2, &c.root_ca1];
    let op = || vec![rule(claims::OPERATOR)];
    let std_policy = || policy_with(n, trust_json(&[&n.root], op(), json!({})));
    let cp = "chain-positive";
    let cn = "chain-negative";

    // ---- positives
    push_verify(
        out,
        cp,
        "three-level-chain",
        "alice carries three attestations inline: root delegates to ca1, ca1 delegates to ca2, ca2 issues `operator` to alice. Policy: `operator` from a chain to root.",
        alice_env(n, "c-three-level", &all)?,
        std_policy(),
        None,
    )?;
    push_verify(
        out,
        cp,
        "root-direct-claim",
        "The root issues `operator` to alice directly (chain of one). The rule names the root explicitly.",
        alice_env(
            n,
            "c-root-direct",
            &[&issue_att(
                &A::std(&n.root, n.alice.agent_id(), claims::OPERATOR, "root-alice")
                    .data(text_map(vec![("name", Value::text("Acme Robotics Ltd"))])),
            )?],
        )?,
        policy_with(
            n,
            trust_json(
                &[&n.root],
                vec![json!({"claim": claims::OPERATOR, "root": n.root.agent_id().to_text()})],
                json!({}),
            ),
        ),
        None,
    )?;
    let mut p = std_policy();
    p.attestations = all.iter().map(|a| a.to_vec()).collect();
    push_verify(
        out,
        cp,
        "chain-out-of-band-attestations",
        "The same chain, but alice's envelope carries no inline attestations; the verifier already holds them (policy.attestations).",
        alice_env(n, "c-oob", &[])?,
        p,
        None,
    )?;
    let aged = |label: &str, days: i64| -> R<Vec<u8>> {
        operator_att(n, label, NOW - days * DAY, NOW + (170 - days) * DAY)
    };
    let age_rule = vec![json!({"claim": claims::OPERATOR, "max_age_days": 30})];
    push_verify(
        out,
        cp,
        "claim-age-boundary",
        "The `operator` attestation was issued exactly 30 days ago and the rule allows 30 days.",
        alice_env(
            n,
            "c-age-ok",
            &[&aged("ca2-alice-30d", 30)?, &c.ca1_ca2, &c.root_ca1],
        )?,
        policy_with(n, trust_json(&[&n.root], age_rule.clone(), json!({}))),
        None,
    )?;
    let audited = issue_att(
        &A::std(
            &n.certifier,
            n.alice.agent_id(),
            claims::AUDITED,
            "certifier-alice-audited",
        )
        .data(text_map(vec![("audit", Value::text("SOC 2 Type II"))]))
        .evidence()
        .window(NOW - 100 * DAY, NOW + 300 * DAY),
    )?;
    push_verify(
        out,
        cp,
        "two-rules-two-roots",
        "Two roots and two rules: `operator` must chain to root, `audited` (a 400 day audit-backed attestation) must chain to certifier and be at most 120 days old.",
        alice_env(
            n,
            "c-two-roots",
            &[&c.ca2_alice, &c.ca1_ca2, &c.root_ca1, &audited],
        )?,
        policy_with(
            n,
            trust_json(
                &[&n.root, &n.certifier],
                vec![
                    json!({"claim": claims::OPERATOR, "root": n.root.agent_id().to_text()}),
                    json!({"claim": claims::AUDITED, "root": n.certifier.agent_id().to_text(), "max_age_days": 120}),
                ],
                json!({}),
            ),
        ),
        None,
    )?;
    let unrelated_srl = |who: &Identity, label: &str| {
        fresh_srl(who, label, vec![revoke_identity(&n.mallory, NOW - DAY)])
    };
    let mut p = std_policy();
    p.srls = vec![
        unrelated_srl(&n.root, "pos-root")?,
        unrelated_srl(&n.ca1, "pos-ca1")?,
        unrelated_srl(&n.ca2, "pos-ca2")?,
    ];
    push_verify(
        out,
        cp,
        "chain-with-fresh-srls",
        "Fresh SRLs for all three issuers; none names an attestation of the chain. No warnings.",
        alice_env(n, "c-fresh-srls", &all)?,
        p,
        None,
    )?;
    let mut p = policy_with(
        n,
        trust_json(&[&n.root], op(), json!({"srl": {"on_stale": "fail-open"}})),
    );
    p.srls = vec![stale_srl(&n.root, "pos-stale-root")?];
    push_verify(
        out,
        cp,
        "stale-srl-fail-open",
        "The root's SRL is past next-update and the policy is fail-open: accepted with warnings (stale root SRL, no SRL for ca1 and ca2).",
        alice_env(n, "c-stale-open", &all)?,
        p,
        None,
    )?;

    // Inclusion proofs: one tree of 7 leaves holding the three attestations.
    let tree = build_tree(
        &n.log,
        "main",
        7,
        &[(2, &c.root_ca1), (4, &c.ca1_ca2), (6, &c.ca2_alice)],
    )?;
    let with_proofs = [
        tree.attach(&c.ca2_alice, 6)?,
        tree.attach(&c.ca1_ca2, 4)?,
        tree.attach(&c.root_ca1, 2)?,
    ];
    let proofs: Vec<&[u8]> = with_proofs.iter().map(|v| v.as_slice()).collect();
    let incl_policy = || {
        policy_with(
            n,
            trust_json(
                &[&n.root],
                op(),
                json!({"require_inclusion": true, "trusted_logs": [n.log.agent_id().to_text()]}),
            ),
        )
    };
    push_verify(
        out,
        cp,
        "valid-inclusion-proof",
        "Every attestation carries an inclusion proof (-70012) against one checkpoint of a 7 leaf log; the policy requires proofs and trusts that log. The result names the checkpoint used.",
        alice_env(n, "c-incl-ok", &proofs)?,
        incl_policy(),
        None,
    )?;

    // ---- negatives
    push_verify(
        out,
        cn,
        "broken-chain",
        "ca2 issued the claim but there is no issuer-authority attestation for ca2 (the ca1 to ca2 link is missing). Expect step 9.",
        alice_env(n, "c-broken", &[&c.ca2_alice, &c.root_ca1])?,
        std_policy(),
        Some((9, "chain_broken")),
    )?;
    let ca1_ca2_audited_only = issue_att(
        &A::std(
            &n.ca1,
            n.ca2.agent_id(),
            claims::ISSUER_AUTHORITY,
            "ca1-ca2-audited-only",
        )
        .data(text_map(vec![("claims", texts(&[claims::AUDITED]))])),
    )?;
    push_verify(
        out,
        cn,
        "unauthorized-issuer",
        "ca2 holds an issuer-authority attestation, but it lists only `audited`, not `operator`. Expect step 9.",
        alice_env(
            n,
            "c-unauthorized",
            &[&c.ca2_alice, &ca1_ca2_audited_only, &c.root_ca1],
        )?,
        std_policy(),
        Some((9, "issuer_not_authorized")),
    )?;
    let audited_leaf = issue_att(
        &A::std(
            &n.ca2,
            n.alice.agent_id(),
            claims::AUDITED,
            "ca2-alice-audited",
        )
        .evidence()
        .window(NOW - 20 * DAY, NOW + 200 * DAY),
    )?;
    push_verify(
        out,
        cn,
        "delegation-exceeds-delegator",
        "ca1 delegates `audited` to ca2, but root never gave ca1 authority over `audited`: a delegator can only hand on what it holds. Expect step 9.",
        alice_env(
            n,
            "c-exceeds",
            &[&audited_leaf, &ca1_ca2_audited_only, &c.root_ca1],
        )?,
        policy_with(
            n,
            trust_json(&[&n.root], vec![rule(claims::AUDITED)], json!({})),
        ),
        Some((9, "issuer_not_authorized")),
    )?;
    push_verify(
        out,
        cn,
        "expired-attestation",
        "The `operator` attestation expired 20 days ago (its envelope fails step 5). Expect step 9 with cause step 5.",
        alice_env(
            n,
            "c-expired",
            &[
                &operator_att(n, "ca2-alice-expired", NOW - 200 * DAY, NOW - 20 * DAY)?,
                &c.ca1_ca2,
                &c.root_ca1,
            ],
        )?,
        std_policy(),
        Some((9, "attestation_invalid")),
    )?;
    let too_long = forge_att(
        &A::std(
            &n.ca2,
            n.alice.agent_id(),
            claims::OPERATOR,
            "ca2-alice-401d",
        )
        .data(text_map(vec![("name", Value::text("Acme Robotics Ltd"))]))
        .window(NOW - 10 * DAY, NOW - 10 * DAY + 401 * DAY),
        |_| {},
    )?;
    push_verify(
        out,
        cn,
        "attestation-lifetime-over-400-days",
        "The `operator` attestation is currently valid but its expires-at minus issued-at is 401 days. Expect step 9.",
        alice_env(n, "c-401d", &[&too_long, &c.ca1_ca2, &c.root_ca1])?,
        std_policy(),
        Some((9, "attestation_lifetime_exceeded")),
    )?;
    let leaf_id = A::std(&n.ca2, n.alice.agent_id(), claims::OPERATOR, "ca2-alice").id();
    let mut p = std_policy();
    p.srls = vec![fresh_srl(
        &n.ca2,
        "neg-ca2-revokes",
        vec![revoke_att(leaf_id, "withdrawn", NOW - 3 * DAY)],
    )?];
    push_verify(
        out,
        cn,
        "attestation-on-issuer-srl",
        "ca2's SRL lists the id of the `operator` attestation as withdrawn. Expect step 9.",
        alice_env(n, "c-on-srl", &all)?,
        p,
        Some((9, "attestation_revoked")),
    )?;
    let mut p = std_policy();
    p.srls = vec![fresh_srl(
        &n.root,
        "neg-root-compromised-ca1",
        vec![revoke_identity(&n.ca1, NOW - 30 * DAY)],
    )?];
    push_verify(
        out,
        cn,
        "issuer-compromised-on-srl",
        "root's SRL lists ca1 as compromised since 30 days ago, and ca1's attestation for ca2 was issued 20 days ago: that attestation fails step 8. Expect step 9 with cause step 8.",
        alice_env(n, "c-issuer-compromised", &all)?,
        p,
        Some((9, "attestation_invalid")),
    )?;
    let mut p = std_policy();
    p.srls = vec![fresh_srl(
        &n.root,
        "neg-root-compromised-alice",
        vec![revoke_identity(&n.alice, NOW - 7_200)],
    )?];
    push_verify(
        out,
        cn,
        "subject-compromised-on-srl",
        "root's SRL lists alice (the signer and subject) as compromised since before her envelope's issued-at. Rejected at step 8, before any policy is evaluated.",
        alice_env(n, "c-subject-compromised", &all)?,
        p,
        Some((8, "signer_revoked")),
    )?;
    push_verify(
        out,
        cn,
        "depth-exceeded",
        "The chain needs three attestations but the policy sets max_depth 2. Expect step 9.",
        alice_env(n, "c-depth", &all)?,
        policy_with(n, trust_json(&[&n.root], op(), json!({"max_depth": 2}))),
        Some((9, "chain_depth_exceeded")),
    )?;
    let ca1_ca2_cycle = issue_att(
        &A::std(
            &n.ca1,
            n.ca2.agent_id(),
            claims::ISSUER_AUTHORITY,
            "cyc-ca1-ca2",
        )
        .data(text_map(vec![(
            "claims",
            texts(&[claims::ISSUER_AUTHORITY, claims::OPERATOR]),
        )])),
    )?;
    let ca2_ca1_cycle = issue_att(
        &A::std(
            &n.ca2,
            n.ca1.agent_id(),
            claims::ISSUER_AUTHORITY,
            "cyc-ca2-ca1",
        )
        .data(text_map(vec![(
            "claims",
            texts(&[claims::ISSUER_AUTHORITY, claims::OPERATOR]),
        )])),
    )?;
    push_verify(
        out,
        cn,
        "chain-cycle",
        "ca1 and ca2 delegate to each other and neither chains to the root. Expect step 9.",
        alice_env(
            n,
            "c-cycle",
            &[&c.ca2_alice, &ca1_ca2_cycle, &ca2_ca1_cycle],
        )?,
        std_policy(),
        Some((9, "chain_cycle")),
    )?;
    push_verify(
        out,
        cn,
        "rule-claim-missing",
        "The policy requires `audited`; alice carries only `operator`. Expect step 9.",
        alice_env(n, "c-missing", &all)?,
        policy_with(
            n,
            trust_json(&[&n.root], vec![rule(claims::AUDITED)], json!({})),
        ),
        Some((9, "claim_missing")),
    )?;
    push_verify(
        out,
        cn,
        "claim-too-old",
        "The `operator` attestation was issued 31 days ago; the rule allows 30. Expect step 9.",
        alice_env(
            n,
            "c-too-old",
            &[&aged("ca2-alice-31d", 31)?, &c.ca1_ca2, &c.root_ca1],
        )?,
        policy_with(n, trust_json(&[&n.root], age_rule, json!({}))),
        Some((9, "claim_too_old")),
    )?;
    push_verify(
        out,
        cn,
        "rule-root-restriction",
        "The rule demands a chain to certifier, but the chain ends at root (a configured root, but not the one the rule names). Expect step 9.",
        alice_env(n, "c-root-restriction", &all)?,
        policy_with(
            n,
            trust_json(
                &[&n.root, &n.certifier],
                vec![json!({"claim": claims::OPERATOR, "root": n.certifier.agent_id().to_text()})],
                json!({}),
            ),
        ),
        Some((9, "chain_broken")),
    )?;
    let mut bad = with_proofs.clone();
    bad[0] = flip_path(&bad[0])?;
    let bad_refs: Vec<&[u8]> = bad.iter().map(|v| v.as_slice()).collect();
    push_verify(
        out,
        cn,
        "bad-inclusion-proof",
        "The proof on the `operator` attestation has its first audit path hash altered. Expect step 9.",
        alice_env(n, "c-bad-proof", &bad_refs)?,
        incl_policy(),
        Some((9, "inclusion_proof_invalid")),
    )?;
    push_verify(
        out,
        cn,
        "inclusion-proof-missing",
        "The policy requires inclusion proofs but the `operator` attestation carries none. Expect step 9.",
        alice_env(
            n,
            "c-no-proof",
            &[&c.ca2_alice, &with_proofs[1], &with_proofs[2]],
        )?,
        incl_policy(),
        Some((9, "inclusion_proof_missing")),
    )?;
    let rogue = build_tree(
        &n.mallory,
        "rogue",
        7,
        &[(2, &c.root_ca1), (4, &c.ca1_ca2), (6, &c.ca2_alice)],
    )?;
    let rogue_proofs = [
        rogue.attach(&c.ca2_alice, 6)?,
        rogue.attach(&c.ca1_ca2, 4)?,
        rogue.attach(&c.root_ca1, 2)?,
    ];
    let rogue_refs: Vec<&[u8]> = rogue_proofs.iter().map(|v| v.as_slice()).collect();
    push_verify(
        out,
        cn,
        "inclusion-proof-untrusted-log",
        "The proofs are valid but the checkpoint is signed by a log (mallory) that is not in trusted_logs. Expect step 9.",
        alice_env(n, "c-rogue-log", &rogue_refs)?,
        incl_policy(),
        Some((9, "checkpoint_untrusted")),
    )?;
    let mut p = policy_with(n, trust_json(&[&n.root], op(), json!({})));
    p.srls = vec![stale_srl(&n.root, "neg-stale-root")?];
    push_verify(
        out,
        cn,
        "srl-stale-fail-closed",
        "The root's SRL is past next-update and the policy is fail-closed (the default for stale lists). Expect step 9.",
        alice_env(n, "c-stale-closed", &all)?,
        p,
        Some((9, "srl_stale")),
    )?;
    push_verify(
        out,
        cn,
        "srl-missing-fail-closed",
        "No SRL is cached for any issuer and the policy sets on_missing to fail-closed. Expect step 9.",
        alice_env(n, "c-missing-closed", &all)?,
        policy_with(
            n,
            trust_json(
                &[&n.root],
                op(),
                json!({"srl": {"on_missing": "fail-closed"}}),
            ),
        ),
        Some((9, "srl_unavailable")),
    )?;
    let no_id = forge_att(
        &A::std(
            &n.ca2,
            n.alice.agent_id(),
            claims::OPERATOR,
            "ca2-alice-noid",
        )
        .data(text_map(vec![("name", Value::text("Acme Robotics Ltd"))])),
        |m| drop_key(m, "id"),
    )?;
    push_verify(
        out,
        cn,
        "attestation-schema-invalid",
        "The attestation payload has no `id` field, so it fails the section 7 schema although the envelope itself verifies. Expect step 9.",
        alice_env(n, "c-schema", &[&no_id, &c.ca1_ca2, &c.root_ca1])?,
        std_policy(),
        Some((9, "attestation_schema_invalid")),
    )?;
    let wrong_issuer = forge_att(
        &A::std(
            &n.ca2,
            n.alice.agent_id(),
            claims::OPERATOR,
            "ca2-alice-wrongissuer",
        )
        .data(text_map(vec![("name", Value::text("Acme Robotics Ltd"))])),
        |m| set_key(m, "issuer", Value::bytes(&n.root.agent_id().0)),
    )?;
    push_verify(
        out,
        cn,
        "attestation-issuer-mismatch",
        "The payload names root as `issuer` but the envelope is signed by ca2. Expect step 9.",
        alice_env(
            n,
            "c-issuer-mismatch",
            &[&wrong_issuer, &c.ca1_ca2, &c.root_ca1],
        )?,
        std_policy(),
        Some((9, "attestation_issuer_mismatch")),
    )?;
    let audited_no_evidence = forge_att(
        &A::std(
            &n.root,
            n.alice.agent_id(),
            claims::AUDITED,
            "root-alice-noevidence",
        ),
        |_| {},
    )?;
    push_verify(
        out,
        cn,
        "audited-without-evidence",
        "An `audited` attestation without the REQUIRED evidence hash. Expect step 9.",
        alice_env(n, "c-no-evidence", &[&audited_no_evidence])?,
        policy_with(
            n,
            trust_json(&[&n.root], vec![rule(claims::AUDITED)], json!({})),
        ),
        Some((9, "attestation_schema_invalid")),
    )?;
    let bad_sig = mutate(&c.ca2_alice, |a| flip_last(sig_slot(a, 0)))?;
    push_verify(
        out,
        cn,
        "attestation-bad-signature",
        "The EdDSA signature of the `operator` attestation has its last byte flipped. Expect step 9 with cause step 4.",
        alice_env(n, "c-att-badsig", &[&bad_sig, &c.ca1_ca2, &c.root_ca1])?,
        std_policy(),
        Some((9, "attestation_invalid")),
    )?;
    Ok(())
}

fn srl_vectors(out: &mut Vec<Vector>, n: &Net) -> R<()> {
    let leaf_id = A::std(&n.ca2, n.alice.agent_id(), claims::OPERATOR, "ca2-alice").id();
    let entries = vec![
        revoke_att(leaf_id, "withdrawn", NOW - 3 * DAY),
        revoke_identity(&n.mallory, NOW - 2 * DAY),
    ];
    struct Case {
        name: &'static str,
        description: &'static str,
        cbor: Vec<u8>,
        on_stale: &'static str,
        cached: Option<Vec<u8>>,
    }
    let fresh = |seq: i64| {
        mk_srl(
            &n.root,
            &format!("v{seq}"),
            seq,
            NOW - 3_600,
            NOW + 82_800,
            entries.clone(),
        )
    };
    let payload_no_next = text_map(vec![
        ("issuer", Value::bytes(&n.root.agent_id().0)),
        ("sequence", Value::Int(1)),
        ("issued-at", Value::Int(NOW - 3_600)),
        ("revoked", Value::Array(vec![])),
    ])
    .encode();
    let mut sp = SignParams::new(&payload_no_next, CT_SRL, nonce("srl/schema"), NOW - 3_600);
    sp.mode = SignMode::Deterministic;
    let schema_invalid = sign(&n.root, &sp)?;
    let mismatch = {
        let s = Srl {
            issuer: n.ca1.agent_id(),
            sequence: 1,
            issued_at: NOW - 3_600,
            next_update: NOW + 82_800,
            revoked: vec![],
        };
        let payload = s.encode();
        let mut sp = SignParams::new(&payload, CT_SRL, nonce("srl/mismatch"), NOW - 3_600);
        sp.mode = SignMode::Deterministic;
        sign(&n.root, &sp)?
    };
    let good = fresh(7)?;
    let cases = vec![
        Case {
            name: "srl-valid",
            description: "A fresh SRL from root: sequence 7, one withdrawn attestation and one compromised identity (mallory).",
            cbor: good.clone(),
            on_stale: "fail-closed",
            cached: None,
        },
        Case {
            name: "srl-stale-fail-open",
            description: "The SRL is past next-update; with on_stale fail-open the list is still used and a warning is returned.",
            cbor: stale_srl(&n.root, "v-stale")?,
            on_stale: "fail-open",
            cached: None,
        },
        Case {
            name: "srl-stale-fail-closed",
            description: "The same stale SRL with on_stale fail-closed. Expect step 9.",
            cbor: stale_srl(&n.root, "v-stale")?,
            on_stale: "fail-closed",
            cached: None,
        },
        Case {
            name: "srl-bad-signature",
            description: "ML-DSA-65 signature last byte flipped. Expect step 4.",
            cbor: mutate(&good, |a| flip_last(sig_slot(a, 1)))?,
            on_stale: "fail-closed",
            cached: None,
        },
        Case {
            name: "srl-issuer-mismatch",
            description: "The payload names ca1 as issuer but the envelope is signed by root. Expect step 9.",
            cbor: mismatch,
            on_stale: "fail-closed",
            cached: None,
        },
        Case {
            name: "srl-schema-invalid",
            description: "The payload has no next-update field. Expect step 9.",
            cbor: schema_invalid,
            on_stale: "fail-closed",
            cached: None,
        },
        Case {
            name: "srl-sequence-rollback",
            description: "The cache already holds root's SRL with sequence 7; this one has sequence 4. Expect step 9.",
            cbor: fresh(4)?,
            on_stale: "fail-closed",
            cached: Some(good.clone()),
        },
        Case {
            name: "srl-sequence-conflict",
            description: "The cache holds a different SRL from root with the same sequence 7. Expect step 9.",
            cbor: mk_srl(&n.root, "v7-other", 7, NOW - 3_600, NOW + 82_800, vec![])?,
            on_stale: "fail-closed",
            cached: Some(good.clone()),
        },
    ];
    for c in cases {
        let inputs = json!({
            "now": NOW,
            "srl_policy": { "on_stale": c.on_stale },
            "known_bundles": [],
            "cached_srl_hex": c.cached.as_ref().map(|b| hx(b)),
        });
        let expected = run_srl(&c.cbor, &inputs)?;
        out.push(Vector {
            category: "srl",
            name: c.name.to_string(),
            description: c.description.to_string(),
            cbor: c.cbor,
            inputs,
            expected,
        });
    }
    Ok(())
}

fn log_vectors(out: &mut Vec<Vector>, n: &Net) -> R<()> {
    let c = standard_chain(n)?;
    let att = &c.ca2_alice;
    let tree5 = build_tree(&n.log, "log5", 5, &[(3, att)])?;
    let tree7 = build_tree(&n.log, "log7", 7, &[(6, att)])?;
    let rogue = build_tree(&n.mallory, "rogue5", 5, &[(3, att)])?;
    let valid5 = tree5.attach(att, 3)?;
    let altered = with_unprotected(&valid5, vec![(-70099, Some(Value::Int(1)))])?;
    struct Case {
        name: &'static str,
        description: &'static str,
        check: &'static str,
        cbor: Vec<u8>,
    }
    let cases = vec![
        Case {
            name: "checkpoint-valid",
            description: "A checkpoint of a 5 leaf log signed by the trusted log.",
            check: "checkpoint",
            cbor: tree5.checkpoint.clone(),
        },
        Case {
            name: "checkpoint-untrusted-log",
            description: "A well formed checkpoint signed by a log that is not trusted. Expect step 9.",
            check: "checkpoint",
            cbor: rogue.checkpoint.clone(),
        },
        Case {
            name: "checkpoint-bad-signature",
            description: "Checkpoint with the ML-DSA-65 signature altered. Expect step 9 wrapping step 4.",
            check: "checkpoint",
            cbor: mutate(&tree5.checkpoint, |a| flip_last(sig_slot(a, 1)))?,
        },
        Case {
            name: "inclusion-valid",
            description: "An attestation with an inclusion proof: leaf 3 of 5. The leaf hash is SHA-256(0x00 || attestation without its -70012 header).",
            check: "inclusion",
            cbor: valid5.clone(),
        },
        Case {
            name: "inclusion-valid-odd-tree",
            description: "Leaf 6 (the last) of a 7 leaf tree, which exercises the unbalanced right edge of RFC 9162.",
            check: "inclusion",
            cbor: tree7.attach(att, 6)?,
        },
        Case {
            name: "inclusion-wrong-audit-path",
            description: "First audit path hash altered. Expect step 9.",
            check: "inclusion",
            cbor: flip_path(&valid5)?,
        },
        Case {
            name: "inclusion-altered-envelope",
            description: "The attestation was changed (an extra unprotected header) after it was logged, so its leaf hash differs. Expect step 9.",
            check: "inclusion",
            cbor: altered,
        },
        Case {
            name: "inclusion-missing-proof",
            description: "An attestation with no -70012 header. Expect step 9.",
            check: "inclusion",
            cbor: att.clone(),
        },
        Case {
            name: "inclusion-untrusted-log",
            description: "A valid proof against a checkpoint of an untrusted log. Expect step 9.",
            check: "inclusion",
            cbor: rogue.attach(att, 3)?,
        },
    ];
    for c in cases {
        let inputs = json!({
            "now": NOW,
            "check": c.check,
            "trusted_logs": [n.log.agent_id().to_text()],
        });
        let expected = run_log(&c.cbor, &inputs)?;
        out.push(Vector {
            category: "log",
            name: c.name.to_string(),
            description: c.description.to_string(),
            cbor: c.cbor,
            inputs,
            expected,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// M3 log vectors: consistency proofs and split views

/// Leaf inputs of a synthetic history; `rewrite` replaces one leaf.
fn history(size: usize, rewrite: Option<usize>) -> Vec<Vec<u8>> {
    (0..size)
        .map(|i| {
            if rewrite == Some(i) {
                format!("rewritten log leaf {i}").into_bytes()
            } else {
                format!("log filler leaf {i}").into_bytes()
            }
        })
        .collect()
}

fn signed_cp(log: &Identity, label: &str, leaves: &[Vec<u8>], timestamp: i64) -> R<Vec<u8>> {
    let cp = Checkpoint {
        tree_size: leaves.len() as i64,
        root_hash: merkle_root(leaves),
        timestamp,
    };
    create_checkpoint(
        log,
        &cp,
        nonce(&format!("cp/{label}")),
        SignMode::Deterministic,
    )
}

fn proof_between(from: usize, leaves: &[Vec<u8>]) -> ConsistencyProof {
    let hashes: Vec<[u8; 32]> = leaves.iter().map(|l| hash_leaf(l)).collect();
    ConsistencyProof {
        from: from as i64,
        to: leaves.len() as i64,
        path: consistency_proof(from, &hashes),
    }
}

fn m3_log_vectors(out: &mut Vec<Vector>, n: &Net) -> R<()> {
    let log = &n.log;
    let t = NOW - 600;
    let h8 = history(8, None);
    let forged8 = history(8, Some(1));
    let cp_env = |label: &str, l: &[Vec<u8>], ts: i64, by: &Identity| -> R<Value> {
        Ok(Value::decode(&signed_cp(by, label, l, ts)?)?)
    };
    let evidence = |old: Value, new: Value, proof: ConsistencyProof| {
        ConsistencyEvidence { old, new, proof }.to_value().encode()
    };
    let pair = |a: Value, b: Value, proof: Option<ConsistencyProof>| {
        CheckpointPair { a, b, proof }.to_value().encode()
    };

    let old3 = cp_env("m3/c3", &h8[..3], t - 7_200, log)?;
    let old4 = cp_env("m3/c4", &h8[..4], t - 7_200, log)?;
    let old5 = cp_env("m3/c5", &h8[..5], t - 3_600, log)?;
    let new7 = cp_env("m3/c7", &h8[..7], t, log)?;
    let new8 = cp_env("m3/c8", &h8, t, log)?;
    let new8_forged = cp_env("m3/f8", &forged8, t, log)?;

    let mut flipped = proof_between(3, &h8);
    flipped.path[0][0] ^= 1;
    let mut truncated = proof_between(3, &h8);
    truncated.path.pop();
    let rogue8 = cp_env("m3/r8", &h8, t, &n.mallory)?;
    let bad_payload = {
        let payload = Value::Map(vec![
            (Value::text("tree-size"), Value::Int(5)),
            (Value::text("timestamp"), Value::Int(t)),
        ])
        .encode();
        let mut p = SignParams::new(&payload, CT_CHECKPOINT, nonce("cp/m3/schema"), t);
        p.mode = SignMode::Deterministic;
        sign(log, &p)?
    };
    let same5_later = cp_env("m3/c5b", &h8[..5], t, log)?;
    // The same log signs a different tree of the same size.
    let split6_a = cp_env("m3/s6a", &h8[..6], t, log)?;
    let split6_b = cp_env("m3/s6b", &forged8[..6], t, log)?;

    struct Case {
        name: &'static str,
        description: &'static str,
        check: &'static str,
        cbor: Vec<u8>,
    }
    let cases = vec![
        Case {
            name: "consistency-valid",
            description: "Checkpoints of the same log at tree sizes 3 and 8 and the RFC 9162 consistency proof between them.",
            check: "consistency",
            cbor: evidence(old3.clone(), new8.clone(), proof_between(3, &h8)),
        },
        Case {
            name: "consistency-valid-power-of-two",
            description: "Old tree size 4 (a power of two, so the old root is the first proof node) to size 7.",
            check: "consistency",
            cbor: evidence(old4, new7, proof_between(4, &h8[..7])),
        },
        Case {
            name: "consistency-same-size",
            description: "Two checkpoints of tree size 5 with different timestamps and the same root; the proof is empty.",
            check: "consistency",
            cbor: evidence(old5.clone(), same5_later, proof_between(5, &h8[..5])),
        },
        Case {
            name: "consistency-invalid-path",
            description: "First hash of the consistency path altered. Expect step 9 consistency_proof_invalid.",
            check: "consistency",
            cbor: evidence(old3.clone(), new8.clone(), flipped),
        },
        Case {
            name: "consistency-truncated-path",
            description: "Last hash removed from the consistency path. Expect step 9 consistency_proof_invalid.",
            check: "consistency",
            cbor: evidence(old3.clone(), new8.clone(), truncated),
        },
        Case {
            name: "consistency-rewritten-history",
            description: "The log rewrote leaf 1 after signing the size 3 checkpoint, then signed a size 8 checkpoint over the rewritten tree and an honest looking proof from that tree. Expect step 9 consistency_proof_invalid.",
            check: "consistency",
            cbor: evidence(old3.clone(), new8_forged.clone(), proof_between(3, &forged8)),
        },
        Case {
            name: "consistency-shrinking-tree",
            description: "The later checkpoint has a smaller tree size than the earlier one. Expect step 9 consistency_proof_invalid.",
            check: "consistency",
            cbor: evidence(
                new8.clone(),
                old3.clone(),
                ConsistencyProof {
                    from: 8,
                    to: 3,
                    path: vec![],
                },
            ),
        },
        Case {
            name: "consistency-untrusted-log",
            description: "A valid proof between a trusted checkpoint and a checkpoint signed by an untrusted log. Expect step 9 checkpoint_untrusted.",
            check: "consistency",
            cbor: evidence(old3, rogue8, proof_between(3, &h8)),
        },
        Case {
            name: "checkpoint-schema-invalid",
            description: "A checkpoint with a valid signature from the trusted log whose payload lacks root-hash. Expect step 9 checkpoint_schema_invalid.",
            check: "checkpoint",
            cbor: bad_payload,
        },
        Case {
            name: "split-view-none",
            description: "Two checkpoints of one log, sizes 5 and 8, with a valid consistency proof: no split view.",
            check: "split-view",
            cbor: pair(old5.clone(), new8.clone(), Some(proof_between(5, &h8))),
        },
        Case {
            name: "split-view-same-size",
            description: "Two valid signed checkpoints of the same log for tree size 6 with different root hashes. Expect step 9 split_view_detected.",
            check: "split-view",
            cbor: pair(split6_a, split6_b, None),
        },
        Case {
            name: "split-view-failed-consistency",
            description: "A size 5 checkpoint from one view and a size 8 checkpoint from another view whose history differs at leaf 1; the proof is valid for the second view only. Expect step 9 split_view_detected.",
            check: "split-view",
            cbor: pair(old5.clone(), new8_forged, Some(proof_between(5, &forged8))),
        },
        Case {
            name: "split-view-missing-proof",
            description: "Checkpoints of sizes 5 and 8 without a consistency proof cannot be compared. Expect step 9 consistency_proof_invalid.",
            check: "split-view",
            cbor: pair(old5, new8, None),
        },
    ];
    for c in cases {
        let inputs = json!({
            "now": NOW,
            "check": c.check,
            "trusted_logs": [n.log.agent_id().to_text()],
        });
        let expected = run_log(&c.cbor, &inputs)?;
        out.push(Vector {
            category: "log",
            name: c.name.to_string(),
            description: c.description.to_string(),
            cbor: c.cbor,
            inputs,
            expected,
        });
    }
    Ok(())
}

fn estop_payload(label: &str) -> Vec<u8> {
    command_payload(label, "e-stop")
}

fn command_payload(label: &str, command: &str) -> Vec<u8> {
    text_map(vec![
        ("command", Value::text(command)),
        ("reason", Value::text(label)),
    ])
    .encode()
}

fn atep_r_vectors(out: &mut Vec<Vector>, n: &Net) -> R<()> {
    use claims::robotics as rc;
    let alice = n.alice.agent_id();
    let ctrl = n.controller.agent_id();
    let fleet = || text_map(vec![("fleet", Value::text("fleet-7"))]);

    let root_ctrl_auth = issue_att(
        &A::std(&n.root, ctrl, claims::ISSUER_AUTHORITY, "ar-root-ctrl-auth").data(text_map(vec![
            (
                "claims",
                texts(&[rc::FLEET_MEMBER, rc::SENSOR_SOURCE, rc::PEER_MOTION]),
            ),
        ])),
    )?;
    let fm = issue_att(&A::std(&n.controller, alice, rc::FLEET_MEMBER, "ar-fm").data(fleet()))?;
    let fm_expired = issue_att(
        &A::std(&n.controller, alice, rc::FLEET_MEMBER, "ar-fm-expired")
            .data(fleet())
            .window(NOW - 300 * DAY, NOW - 120 * DAY),
    )?;
    let sensor = issue_att(
        &A::std(&n.controller, alice, rc::SENSOR_SOURCE, "ar-sensor")
            .data(text_map(vec![("sensors", texts(&["lidar-front"]))])),
    )?;
    let peers = |who: &Identity| {
        text_map(vec![(
            "peers",
            Value::Array(vec![Value::bytes(&who.agent_id().0)]),
        )])
    };
    let peer_ok = issue_att(
        &A::std(&n.controller, alice, rc::PEER_MOTION, "ar-peer-ok").data(peers(&n.bob)),
    )?;
    let peer_wrong = issue_att(
        &A::std(&n.controller, alice, rc::PEER_MOTION, "ar-peer-wrong").data(peers(&n.carol)),
    )?;
    let sc_data = || {
        text_map(vec![
            ("standard", Value::text("ISO 3691-4")),
            ("date", Value::text("2026-09-01")),
        ])
    };
    let sc_alice = issue_att(
        &A::std(&n.certifier, alice, rc::SAFETY_CERTIFIED, "ar-sc-alice")
            .data(sc_data())
            .evidence()
            .window(NOW - 30 * DAY, NOW + 335 * DAY),
    )?;
    let sc_alice_expired = issue_att(
        &A::std(
            &n.certifier,
            alice,
            rc::SAFETY_CERTIFIED,
            "ar-sc-alice-expired",
        )
        .data(sc_data())
        .evidence()
        .window(NOW - 400 * DAY, NOW - 35 * DAY),
    )?;
    let sc_ctrl = issue_att(
        &A::std(&n.certifier, ctrl, rc::SAFETY_CERTIFIED, "ar-sc-ctrl")
            .data(sc_data())
            .evidence()
            .window(NOW - 30 * DAY, NOW + 335 * DAY),
    )?;
    let fc = issue_att(&A::std(&n.root, ctrl, rc::FLEET_CONTROLLER, "ar-fc").data(fleet()))?;
    let sa = issue_att(&A::std(&n.root, ctrl, rc::SAFETY_AUTHORITY, "ar-sa").data(fleet()))?;
    let ma = issue_att(&A::std(&n.root, ctrl, rc::MAINTENANCE_AUTHORITY, "ar-ma").data(fleet()))?;

    let policy = || {
        policy_with(
            n,
            trust_json(&[&n.root, &n.certifier], vec![], json!({"atep_r": true})),
        )
    };
    let member_chain = |extra: &[&[u8]]| -> Vec<Vec<u8>> {
        let mut v: Vec<Vec<u8>> = extra.iter().map(|a| a.to_vec()).collect();
        v.push(root_ctrl_auth.clone());
        v
    };
    // An encrypted ATEP-R envelope from `sender` carrying these attestations.
    let env = |sender: &Identity,
               label: &str,
               class: &str,
               payload: Vec<u8>,
               inline: Vec<Vec<u8>>|
     -> R<Vec<u8>> {
        let refs: Vec<&[u8]> = inline.iter().map(|v| v.as_slice()).collect();
        envelope_for(n, sender, label, Some(class), payload, &refs)
    };
    // Motion, actuation, maintenance and non e-stop safety fail closed on a
    // missing SRL too, so those vectors carry fresh SRLs for the issuers.
    let strict = |who: &[&Identity]| -> R<PolicySpec> {
        let mut p = policy();
        for w in who {
            let label = format!("ar-fresh-{}", &w.agent_id().base32()[..8]);
            p.srls.push(fresh_srl(w, &label, vec![])?);
        }
        Ok(p)
    };
    let (root, ctl, cert) = (&n.root, &n.controller, &n.certifier);
    let pos = "atep-r-positive";
    let neg = "atep-r-negative";
    let pl = payload_for;
    let one = |a: &[u8]| vec![a.to_vec()];
    let two = |a: &[u8], b: &[u8]| vec![a.to_vec(), b.to_vec()];

    // telemetry
    push_verify(out, pos, "telemetry-fleet-member",
        "telemetry from a fleet-member: alice holds `fleet-member` from the controller, who holds issuer-authority from the root.",
        env(&n.alice, "ar-telemetry", "telemetry", pl("ar-telemetry"), member_chain(&[&fm]))?, policy(), None)?;
    push_verify(
        out,
        neg,
        "telemetry-no-fleet-member",
        "telemetry from mallory, who holds no claims. Expect step 9.",
        env(
            &n.mallory,
            "ar-telemetry-none",
            "telemetry",
            pl("ar-telemetry-none"),
            vec![],
        )?,
        policy(),
        Some((9, "claim_missing")),
    )?;
    let mut p = policy();
    p.srls = vec![stale_srl(&n.root, "ar-stale-root")?];
    push_verify(out, pos, "telemetry-stale-srl-continues",
        "telemetry with the root's SRL past next-update: telemetry may continue, so it is accepted with warnings.",
        env(&n.alice, "ar-telemetry-stale", "telemetry", pl("ar-telemetry-stale"), member_chain(&[&fm]))?, p, None)?;
    // sensor
    push_verify(
        out,
        pos,
        "sensor-fleet-member-and-sensor-source",
        "sensor data from a unit with `fleet-member` and `sensor-source`.",
        env(
            &n.alice,
            "ar-sensor",
            "sensor",
            pl("ar-sensor"),
            member_chain(&[&fm, &sensor]),
        )?,
        policy(),
        None,
    )?;
    push_verify(
        out,
        neg,
        "sensor-missing-sensor-source",
        "sensor data from a unit that is only a fleet-member. Expect step 9.",
        env(
            &n.alice,
            "ar-sensor-no-src",
            "sensor",
            pl("ar-sensor-no-src"),
            member_chain(&[&fm]),
        )?,
        policy(),
        Some((9, "claim_missing")),
    )?;
    // coordination
    push_verify(
        out,
        pos,
        "coordination-fleet-member",
        "coordination (task claims) from a fleet-member.",
        env(
            &n.alice,
            "ar-coord",
            "coordination",
            pl("ar-coord"),
            member_chain(&[&fm]),
        )?,
        policy(),
        None,
    )?;
    push_verify(out, neg, "coordination-expired-fleet-member",
        "coordination from a unit whose `fleet-member` attestation expired. Expect step 9 with cause step 5.",
        env(&n.alice, "ar-coord-expired", "coordination", pl("ar-coord-expired"), member_chain(&[&fm_expired]))?, policy(), Some((9, "attestation_invalid")))?;
    // motion
    push_verify(
        out,
        pos,
        "motion-from-fleet-controller",
        "motion from the fleet controller (`fleet-controller` issued directly by the root).",
        env(
            &n.controller,
            "ar-motion-ctrl",
            "motion",
            pl("ar-motion-ctrl"),
            one(&fc),
        )?,
        strict(&[root])?,
        None,
    )?;
    push_verify(
        out,
        pos,
        "motion-from-member-with-peer-motion",
        "motion from a fleet-member whose `peer-motion` delegation lists the receiver (bob).",
        env(
            &n.alice,
            "ar-motion-peer",
            "motion",
            pl("ar-motion-peer"),
            member_chain(&[&fm, &peer_ok]),
        )?,
        strict(&[root, ctl])?,
        None,
    )?;
    push_verify(
        out,
        neg,
        "motion-member-without-peer-motion",
        "motion from a fleet-member with no `peer-motion` delegation. Expect step 9.",
        env(
            &n.alice,
            "ar-motion-nopeer",
            "motion",
            pl("ar-motion-nopeer"),
            member_chain(&[&fm]),
        )?,
        strict(&[root, ctl])?,
        Some((9, "claim_missing")),
    )?;
    push_verify(
        out,
        neg,
        "motion-peer-motion-lists-other-peer",
        "the `peer-motion` delegation lists carol, not the receiver bob. Expect step 9.",
        env(
            &n.alice,
            "ar-motion-wrongpeer",
            "motion",
            pl("ar-motion-wrongpeer"),
            member_chain(&[&fm, &peer_wrong]),
        )?,
        strict(&[root, ctl])?,
        Some((9, "claim_data_mismatch")),
    )?;
    let mut p = policy();
    p.srls = vec![stale_srl(&n.root, "ar-stale-root")?];
    push_verify(
        out,
        neg,
        "motion-stale-srl-fails-closed",
        "motion with the root's SRL past next-update: fails closed. Expect step 9.",
        env(
            &n.controller,
            "ar-motion-stale",
            "motion",
            pl("ar-motion-stale"),
            one(&fc),
        )?,
        p,
        Some((9, "srl_stale")),
    )?;
    let mut p = strict(&[ctl])?;
    p.srls.insert(0, stale_srl(&n.root, "ar-stale-root")?);
    push_verify(
        out,
        neg,
        "motion-member-peer-motion-stale-srl",
        "motion from a fleet-member whose `peer-motion` delegation lists the receiver, with the root's SRL past next-update. The fleet-controller alternative fails with `claim_missing` and the peer-motion alternative with `srl_stale`: the stale list is the cause that applies to the alternative that matches, so it is the one reported. Expect step 9 `srl_stale` (Draft 08, rust finding 57).",
        env(
            &n.alice,
            "ar-motion-peer-stale",
            "motion",
            pl("ar-motion-peer-stale"),
            member_chain(&[&fm, &peer_ok]),
        )?,
        p,
        Some((9, "srl_stale")),
    )?;
    let mut p = policy();
    p.srls = vec![fresh_srl(
        &n.root,
        "ar-root-comp-ctrl",
        vec![revoke_identity(&n.controller, NOW - DAY)],
    )?];
    push_verify(
        out,
        neg,
        "motion-sender-compromised",
        "root's SRL lists the controller as compromised since a day ago. Expect step 8.",
        env(
            &n.controller,
            "ar-motion-comp",
            "motion",
            pl("ar-motion-comp"),
            one(&fc),
        )?,
        p,
        Some((8, "signer_revoked")),
    )?;
    let fc_id = A::std(&n.root, ctrl, rc::FLEET_CONTROLLER, "ar-fc").id();
    let mut p = policy();
    p.srls = vec![fresh_srl(
        &n.root,
        "ar-root-revokes-fc",
        vec![revoke_att(fc_id, "withdrawn", NOW - DAY)],
    )?];
    push_verify(
        out,
        neg,
        "motion-fleet-controller-revoked",
        "the root's SRL withdrew the controller's `fleet-controller` attestation. Expect step 9.",
        env(
            &n.controller,
            "ar-motion-revoked",
            "motion",
            pl("ar-motion-revoked"),
            one(&fc),
        )?,
        p,
        Some((9, "attestation_revoked")),
    )?;
    // actuation
    push_verify(
        out,
        pos,
        "actuation-controller-and-safety-certified",
        "actuation from the controller with `fleet-controller` and `safety-certified`.",
        env(
            &n.controller,
            "ar-act",
            "actuation",
            pl("ar-act"),
            two(&fc, &sc_ctrl),
        )?,
        strict(&[root, cert])?,
        None,
    )?;
    push_verify(
        out,
        neg,
        "actuation-without-safety-certified",
        "actuation from the controller without `safety-certified`. Expect step 9.",
        env(
            &n.controller,
            "ar-act-nosc",
            "actuation",
            pl("ar-act-nosc"),
            one(&fc),
        )?,
        strict(&[root])?,
        Some((9, "claim_missing")),
    )?;
    // safety
    push_verify(
        out,
        pos,
        "safety-geofence-from-safety-authority",
        "a geofence update from the holder of `safety-authority`.",
        env(
            &n.controller,
            "ar-geofence",
            "safety",
            command_payload("ar-geofence", "geofence-update"),
            one(&sa),
        )?,
        strict(&[root])?,
        None,
    )?;
    push_verify(out, neg, "safety-geofence-from-certified-member",
        "a geofence update from a certified fleet-member: only e-stop is open to members. Expect step 9.",
        env(&n.alice, "ar-geofence-member", "safety", command_payload("ar-geofence-member", "geofence-update"), member_chain(&[&fm, &sc_alice]))?, strict(&[root, ctl, cert])?, Some((9, "claim_missing")))?;
    push_verify(
        out,
        pos,
        "estop-from-certified-fleet-member",
        "an e-stop from a fleet-member holding `safety-certified` (no `safety-authority` needed).",
        env(
            &n.alice,
            "ar-estop",
            "safety",
            estop_payload("ar-estop"),
            member_chain(&[&fm, &sc_alice]),
        )?,
        policy(),
        None,
    )?;
    push_verify(out, pos, "estop-with-expired-claims",
        "an e-stop is honored although the sender's `fleet-member` and `safety-certified` attestations have expired.",
        env(&n.alice, "ar-estop-expired", "safety", estop_payload("ar-estop-expired"), member_chain(&[&fm_expired, &sc_alice_expired]))?, policy(), None)?;
    let mut p = policy();
    p.srls = vec![stale_srl(&n.certifier, "ar-stale-certifier")?];
    push_verify(
        out,
        pos,
        "estop-stale-srl-continues",
        "an e-stop with a certifier SRL past next-update: honored with warnings.",
        env(
            &n.alice,
            "ar-estop-stale",
            "safety",
            estop_payload("ar-estop-stale"),
            member_chain(&[&fm, &sc_alice]),
        )?,
        p,
        None,
    )?;
    push_verify(
        out,
        neg,
        "estop-from-uncertified-fleet-member",
        "an e-stop from a fleet-member without `safety-certified`. Expect step 9.",
        env(
            &n.alice,
            "ar-estop-nosc",
            "safety",
            estop_payload("ar-estop-nosc"),
            member_chain(&[&fm]),
        )?,
        policy(),
        Some((9, "claim_missing")),
    )?;
    let sc_id = A::std(&n.certifier, alice, rc::SAFETY_CERTIFIED, "ar-sc-alice").id();
    let mut p = policy();
    p.srls = vec![fresh_srl(
        &n.certifier,
        "ar-cert-revokes",
        vec![revoke_att(sc_id, "withdrawn", NOW - DAY)],
    )?];
    push_verify(out, neg, "estop-safety-certified-revoked",
        "the certifier withdrew the sender's `safety-certified`; the e-stop relaxation covers expiry only, not revocation. Expect step 9.",
        env(&n.alice, "ar-estop-revoked", "safety", estop_payload("ar-estop-revoked"), member_chain(&[&fm, &sc_alice]))?, p, Some((9, "attestation_revoked")))?;
    // maintenance
    push_verify(
        out,
        pos,
        "maintenance-from-maintenance-authority",
        "a firmware update from the holder of `maintenance-authority`.",
        env(
            &n.controller,
            "ar-maint",
            "maintenance",
            pl("ar-maint"),
            one(&ma),
        )?,
        strict(&[root])?,
        None,
    )?;
    push_verify(
        out,
        neg,
        "maintenance-from-fleet-member",
        "a firmware update from a plain fleet-member. Expect step 9.",
        env(
            &n.alice,
            "ar-maint-member",
            "maintenance",
            pl("ar-maint-member"),
            member_chain(&[&fm]),
        )?,
        strict(&[root, ctl])?,
        Some((9, "claim_missing")),
    )?;
    // structure
    push_verify(
        out,
        neg,
        "missing-command-class",
        "an encrypted envelope without the -70014 header under an ATEP-R policy. Expect step 1.",
        envelope_for(n, &n.alice, "ar-nocls", None, pl("ar-nocls"), &[])?,
        policy(),
        Some((1, "missing_command_class")),
    )?;
    push_verify(
        out,
        neg,
        "unknown-command-class",
        "command-class `teleport` is not in the table. Expect step 1.",
        env(&n.alice, "ar-badcls", "teleport", pl("ar-badcls"), vec![])?,
        policy(),
        Some((1, "unknown_command_class")),
    )?;
    let unenc = {
        let payload = pl("ar-unenc");
        let mut sp = SignParams::new(&payload, CT_SRL, nonce("ar-unenc"), NOW - 60);
        sp.mode = SignMode::Deterministic;
        sp.command_class = Some("telemetry");
        sign(&n.alice, &sp)?
    };
    push_verify(out, neg, "unencrypted-atep-r-envelope",
        "a signed-only envelope (trust document content type) carrying a command class: ATEP-R requires sign-then-encrypt. Expect step 1.",
        unenc, policy(), Some((1, "atep_r_unencrypted")))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Checking

fn srl_json(s: &Srl, now: i64, warning: Option<String>) -> J {
    let mut o = Map::new();
    o.insert("ok".into(), true.into());
    o.insert("issuer".into(), s.issuer.to_text().into());
    o.insert("sequence".into(), s.sequence.into());
    o.insert("issued_at".into(), s.issued_at.into());
    o.insert("next_update".into(), s.next_update.into());
    o.insert("stale".into(), s.is_stale(now).into());
    o.insert(
        "revoked".into(),
        s.revoked
            .iter()
            .map(|e| match &e.id {
                RevokedId::Attestation(id) => json!({
                    "kind": "attestation", "id_hex": hx(id), "reason": e.reason, "revoked_at": e.revoked_at
                }),
                RevokedId::Identity(id) => json!({
                    "kind": "identity", "id": id.to_text(), "reason": e.reason, "revoked_at": e.revoked_at
                }),
            })
            .collect::<Vec<_>>()
            .into(),
    );
    if let Some(w) = warning {
        o.insert("warnings".into(), json!([w]));
    }
    J::Object(o)
}

fn run_srl(cbor: &[u8], inputs: &J) -> R<J> {
    let now = jint(inputs, "now")?;
    let on_stale = StaleMode::parse(jstr(jget(inputs, "srl_policy")?, "on_stale")?)
        .ok_or_else(|| e("bad on_stale"))?;
    // Optional verifier context (spec section 8, "Loading an SRL"): the local
    // attestation store and directly supplied revocations.
    let store: Vec<Vec<u8>> = match inputs.get("attestations").and_then(|a| a.as_array()) {
        Some(list) => list
            .iter()
            .map(|a| unhex(a.as_str().ok_or_else(|| e("attestations entry"))?))
            .collect::<R<Vec<_>>>()?,
        None => Vec::new(),
    };
    let revocations = match inputs.get("revocations") {
        Some(r) => parse_revocations(r)?,
        None => Vec::new(),
    };
    let cx = srl::LoadContext {
        attestations: &store,
        revocations: &revocations,
        ..srl::LoadContext::bundles(&[])
    };
    let mut cache = MemorySrlCache::new();
    if let Some(c) = inputs.get("cached_srl_hex").and_then(|c| c.as_str()) {
        srl::ingest_in(&mut cache, &unhex(c)?, &cx, now)
            .map_err(|x| e(format!("cached srl: {x}")))?;
    }
    match srl::ingest_in(&mut cache, cbor, &cx, now) {
        Err(x) => Ok(rejection_json(&x)),
        Ok(s) => {
            let policy = SrlPolicy {
                on_stale,
                on_missing: StaleMode::FailOpenWithWarning,
            };
            match srl::current_for(Some(&cache), &s.issuer, now, &policy) {
                Err(x) => Ok(rejection_json(&x)),
                Ok((_, w)) => Ok(srl_json(&s, now, w)),
            }
        }
    }
}

fn run_log(cbor: &[u8], inputs: &J) -> R<J> {
    let now = jint(inputs, "now")?;
    let trusted = jget(inputs, "trusted_logs")?
        .as_array()
        .ok_or_else(|| e("trusted_logs"))?
        .iter()
        .map(|t| AgentId::parse(t.as_str().unwrap_or("")))
        .collect::<Result<Vec<_>, _>>()?;
    let checker = OfflineInclusion {
        trusted_logs: trusted,
        known_bundles: vec![],
    };
    let result = match jstr(inputs, "check")? {
        "checkpoint" => checker.load_checkpoint(cbor, now),
        "inclusion" => {
            let env = SignedEnvelope::decode(cbor).map_err(|x| e(x.to_string()))?;
            let submitted = submitted_form(cbor)?;
            crate::log::InclusionCheck::check(
                &checker,
                &submitted,
                env.inclusion_proof.as_ref(),
                now,
            )
        }
        "consistency" | "split-view" => {
            let doc = Value::decode(cbor)?;
            let pair = if jstr(inputs, "check")? == "consistency" {
                let ev = ConsistencyEvidence::from_value(&doc).map_err(|x| e(x.0))?;
                checker
                    .check_consistency(&ev, now)
                    .map(|(a, b)| ("old", "new", a, b))
            } else {
                let p = CheckpointPair::from_value(&doc).map_err(|x| e(x.0))?;
                checker
                    .check_split_view(&p, now)
                    .map(|(a, b)| ("a", "b", a, b))
            };
            return Ok(match pair {
                Ok((ka, kb, a, b)) => {
                    json!({ "ok": true, ka: checkpoint_json(&a), kb: checkpoint_json(&b) })
                }
                Err(x) => rejection_json(&x),
            });
        }
        other => return Err(e(format!("unknown log check {other}"))),
    };
    Ok(match result {
        Ok(cp) => json!({ "ok": true, "checkpoint": checkpoint_json(&cp) }),
        Err(x) => rejection_json(&x),
    })
}

pub(crate) fn check(category: &str, cbor: &[u8], inputs: &J, expected: &J) -> R<()> {
    match category {
        "attestation" => {
            let issuer = Identity::from_seeds(seeds_from_json(jget(inputs, "issuer_seeds")?)?)?;
            let subject = AgentId::parse(jstr(inputs, "subject")?)?;
            let mut p = AttestationParams::new(
                subject,
                jstr(inputs, "claim")?,
                jint(inputs, "issued_at")?,
                jint(inputs, "expires_at")?,
            )?;
            p.data = Value::decode(&unhex(jstr(inputs, "data_hex")?)?)?;
            p.evidence = match inputs.get("evidence_hex").and_then(|v| v.as_str()) {
                Some(h) => Some(
                    unhex(h)?
                        .try_into()
                        .map_err(|_| e("evidence must be 32 bytes"))?,
                ),
                None => None,
            };
            p.evidence_uri = inputs
                .get("evidence_uri")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            p.id = jhex::<16>(inputs, "id_hex")?;
            p.nonce = jhex::<16>(inputs, "nonce_hex")?;
            p.mode = SignMode::Deterministic;
            if attestation::issue(&issuer, &p)? != cbor {
                return Err(e("attestation bytes differ"));
            }
            let v = crate::verify::verify(cbor, &crate::verify::Policy::default(), NOW)
                .map_err(|x| e(format!("attestation does not verify: {x}")))?;
            if hx(&v.payload) != jstr(expected, "payload_hex")?
                || v.signer.to_text() != jstr(expected, "issuer")?
                || hx(&sha256(cbor)) != jstr(expected, "envelope_sha256")?
            {
                return Err(e("attestation expected values differ"));
            }
            Attestation::from_payload(&v.payload).map_err(|x| e(x.0))?;
            Ok(())
        }
        "srl" | "srl-context" => {
            let got = run_srl(cbor, inputs)?;
            if &got != expected {
                return Err(e(format!("result {got} != expected {expected}")));
            }
            Ok(())
        }
        "log" => {
            let got = run_log(cbor, inputs)?;
            if &got != expected {
                return Err(e(format!("result {got} != expected {expected}")));
            }
            Ok(())
        }
        "log-admission" => {
            let got = retired::run_admission(cbor, inputs)?;
            if &got != expected {
                return Err(e(format!("result {got} != expected {expected}")));
            }
            Ok(())
        }
        "monitor" => {
            let got = retired::run_monitor(cbor, inputs)?;
            if &got != expected {
                return Err(e(format!("result {got} != expected {expected}")));
            }
            Ok(())
        }
        "checkpoint-hash" | "anchor-record" | "chain-id" | "anchor-envelope" | "require-anchor" => {
            anchor::check(category, cbor, inputs, expected)
        }
        "registry-endpoint" | "domain-binding" => {
            discovery::check(category, cbor, inputs, expected)
        }
        other => Err(e(format!("unknown category {other}"))),
    }
}
