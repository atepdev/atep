//! Library level tests of the M2 trust engine (step 9), SRL cache wiring and
//! ATEP-R enforcement, independent of the vector files.

use atep_core::atep_r::{self, Outcome};
use atep_core::attestation::{authority_data, claims, AttestationParams};
use atep_core::cbor::Value;
use atep_core::consts::*;
use atep_core::envelope::{sign, with_unprotected, SignMode, SignParams};
use atep_core::keys::{AgentId, Identity, Seeds};
use atep_core::log::{CheckpointUsed, InclusionCheck};
use atep_core::srl::{ingest, MemorySrlCache, RevocationEntry, RevokedId, Srl, SrlPolicy};
use atep_core::{
    encrypt, verify, EncryptRandomness, ErrorCode, Policy, Rejection, Rule, TrustPolicy,
};

const NOW: i64 = 1_800_000_000;
const DAY: i64 = 86_400;

fn ident(n: u8, enc: bool) -> Identity {
    Identity::from_seeds(Seeds {
        ed25519: [n; 32],
        mldsa65: [n + 1; 32],
        x25519: enc.then_some([n + 2; 32]),
        mlkem768: enc.then_some([n + 3; 64]),
    })
    .unwrap()
}

fn att(
    issuer: &Identity,
    subject: AgentId,
    claim: &str,
    data: Value,
    issued: i64,
    expires: i64,
    id: u8,
) -> Vec<u8> {
    let mut p = AttestationParams::new(subject, claim, issued, expires).unwrap();
    p.data = data;
    p.id = [id; 16];
    p.nonce = [id; 16];
    p.mode = SignMode::Deterministic;
    p.allow_long_default = true;
    atep_core::attestation::issue(issuer, &p).unwrap()
}

fn std_att(issuer: &Identity, subject: AgentId, claim: &str, data: Value, id: u8) -> Vec<u8> {
    att(
        issuer,
        subject,
        claim,
        data,
        NOW - 10 * DAY,
        NOW + 60 * DAY,
        id,
    )
}

/// Encrypted envelope from `sender` to `to` with inline attestations.
fn envelope(
    sender: &Identity,
    to: &Identity,
    class: Option<&str>,
    payload: &[u8],
    inline: &[Vec<u8>],
) -> Vec<u8> {
    let mut sp = SignParams::new(payload, CT_DATA, [5; 16], NOW - 10);
    sp.expires_at = Some(NOW + 600);
    sp.mode = SignMode::Deterministic;
    sp.command_class = class;
    let mut signed = sign(sender, &sp).unwrap();
    if !inline.is_empty() {
        let list = inline.iter().map(|a| Value::decode(a).unwrap()).collect();
        signed =
            with_unprotected(&signed, vec![(HDR_ATTESTATIONS, Some(Value::Array(list)))]).unwrap();
    }
    let rnd = EncryptRandomness {
        x25519_ephemeral: [9; 32],
        mlkem_m: [8; 32],
        iv: [7; 12],
    };
    encrypt(&signed, to.public(), &rnd).unwrap()
}

fn claims_data(list: &[&str]) -> Value {
    authority_data(list)
}

fn trust(roots: &[&Identity], rules: Vec<Rule>) -> TrustPolicy {
    TrustPolicy {
        roots: roots.iter().map(|r| r.agent_id()).collect(),
        rules,
        ..TrustPolicy::default()
    }
}

#[test]
fn three_level_chain_and_variants() {
    let (root, a, b, subj, bob) = (
        ident(10, false),
        ident(20, false),
        ident(30, false),
        ident(40, false),
        ident(50, true),
    );
    let r_a = std_att(
        &root,
        a.agent_id(),
        claims::ISSUER_AUTHORITY,
        claims_data(&[claims::ISSUER_AUTHORITY, claims::OPERATOR]),
        1,
    );
    let a_b = std_att(
        &a,
        b.agent_id(),
        claims::ISSUER_AUTHORITY,
        claims_data(&[claims::OPERATOR]),
        2,
    );
    let b_s = std_att(&b, subj.agent_id(), claims::OPERATOR, Value::Map(vec![]), 3);
    let good = envelope(
        &subj,
        &bob,
        None,
        b"x",
        &[b_s.clone(), a_b.clone(), r_a.clone()],
    );
    let pol = |t: TrustPolicy| Policy {
        recipient: Some(&bob),
        trust: Some(t),
        ..Policy::default()
    };
    let t = trust(&[&root], vec![Rule::new("operator")]);
    let v = verify(&good, &pol(t.clone()), NOW).unwrap();
    assert_eq!(v.claims.len(), 1);
    assert_eq!(v.claims[0].chain.len(), 3);
    assert_eq!(v.claims[0].root, root.agent_id());
    assert_eq!(v.claims[0].expires_at, NOW + 60 * DAY);
    assert!(v.checkpoint.is_none());

    // No root configured: nothing chains.
    let none = trust(&[], vec![Rule::new("operator")]);
    assert_eq!(
        verify(&good, &pol(none), NOW).unwrap_err().code,
        ErrorCode::ChainBroken
    );
    // Unknown claim.
    let t2 = trust(&[&root], vec![Rule::new("audited")]);
    assert_eq!(
        verify(&good, &pol(t2), NOW).unwrap_err().code,
        ErrorCode::ClaimMissing
    );
    // No rules: step 9 passes and returns no claims.
    let t3 = trust(&[&root], vec![]);
    assert!(verify(&good, &pol(t3), NOW).unwrap().claims.is_empty());
    // A rule naming a root outside the configured set is a policy error.
    let mut rule = Rule::new("operator");
    rule.root = Some(subj.agent_id());
    let t4 = trust(&[&root], vec![rule]);
    assert_eq!(
        verify(&good, &pol(t4), NOW).unwrap_err().code,
        ErrorCode::PolicyInvalid
    );
    // Depth bound.
    let mut t5 = t.clone();
    t5.max_depth = 3;
    verify(&good, &pol(t5.clone()), NOW).unwrap();
    t5.max_depth = 2;
    assert_eq!(
        verify(&good, &pol(t5), NOW).unwrap_err().code,
        ErrorCode::ChainDepthExceeded
    );
    // Out-of-band attestations work the same.
    let bare = envelope(&subj, &bob, None, b"x", &[]);
    let mut p = pol(t.clone());
    p.attestations = vec![b_s.clone(), a_b.clone(), r_a.clone()];
    verify(&bare, &p, NOW).unwrap();
    // Garbage in the pool is ignored.
    p.attestations.push(b"junk".to_vec());
    verify(&bare, &p, NOW).unwrap();
}

#[test]
fn delegation_cannot_exceed_delegator() {
    let (root, a, b, subj, bob) = (
        ident(10, false),
        ident(20, false),
        ident(30, false),
        ident(40, false),
        ident(50, true),
    );
    // root lets a issue only `operator` (and further delegation); a hands b `audited`.
    let r_a = std_att(
        &root,
        a.agent_id(),
        claims::ISSUER_AUTHORITY,
        claims_data(&[claims::ISSUER_AUTHORITY, claims::OPERATOR]),
        1,
    );
    let a_b = std_att(
        &a,
        b.agent_id(),
        claims::ISSUER_AUTHORITY,
        claims_data(&[claims::AUDITED]),
        2,
    );
    let mut p =
        AttestationParams::new(subj.agent_id(), "audited", NOW - DAY, NOW + 100 * DAY).unwrap();
    p.evidence = Some([1; 32]);
    p.id = [3; 16];
    p.mode = SignMode::Deterministic;
    let b_s = atep_core::attestation::issue(&b, &p).unwrap();
    let env = envelope(&subj, &bob, None, b"x", &[b_s, a_b, r_a]);
    let pol = Policy {
        recipient: Some(&bob),
        trust: Some(trust(&[&root], vec![Rule::new("audited")])),
        ..Policy::default()
    };
    assert_eq!(
        verify(&env, &pol, NOW).unwrap_err().code,
        ErrorCode::IssuerNotAuthorized
    );
}

/// An inclusion checker that accepts everything, as the M3 log client might.
struct AcceptAll;
impl InclusionCheck for AcceptAll {
    fn check(&self, _s: &[u8], _p: Option<&Value>, now: i64) -> Result<CheckpointUsed, Rejection> {
        Ok(CheckpointUsed {
            log: AgentId([7; 32]),
            tree_size: 1,
            root_hash: [0; 32],
            timestamp: now,
        })
    }
}

#[test]
fn inclusion_check_hook() {
    let (root, subj, bob) = (ident(10, false), ident(40, false), ident(50, true));
    let a = std_att(
        &root,
        subj.agent_id(),
        claims::OPERATOR,
        Value::Map(vec![]),
        1,
    );
    let env = envelope(&subj, &bob, None, b"x", &[a]);
    let mut t = trust(&[&root], vec![Rule::new("operator")]);
    t.require_inclusion = true;
    // default offline checker: no proof present
    let pol = Policy {
        recipient: Some(&bob),
        trust: Some(t.clone()),
        ..Policy::default()
    };
    assert_eq!(
        verify(&env, &pol, NOW).unwrap_err().code,
        ErrorCode::InclusionProofMissing
    );
    // custom checker through the trait
    let hook = AcceptAll;
    let pol = Policy {
        recipient: Some(&bob),
        trust: Some(t),
        inclusion: Some(&hook),
        ..Policy::default()
    };
    let v = verify(&env, &pol, NOW).unwrap();
    assert_eq!(v.checkpoint.unwrap().tree_size, 1);
}

fn make_srl(
    issuer: &Identity,
    seq: i64,
    issued: i64,
    next: i64,
    revoked: Vec<RevocationEntry>,
) -> Vec<u8> {
    atep_core::srl::create(
        issuer,
        &Srl {
            issuer: issuer.agent_id(),
            sequence: seq,
            issued_at: issued,
            next_update: next,
            revoked,
        },
        [seq as u8; 16],
        SignMode::Deterministic,
        true,
    )
    .unwrap()
}

#[test]
fn srl_cache_feeds_step_8_and_step_9() {
    let (root, subj, bob) = (ident(10, false), ident(40, false), ident(50, true));
    let a = std_att(
        &root,
        subj.agent_id(),
        claims::OPERATOR,
        Value::Map(vec![]),
        1,
    );
    let env = envelope(&subj, &bob, None, b"x", &[a]);
    let t = trust(&[&root], vec![Rule::new("operator")]);

    // fresh and empty list: fine, no warnings
    let mut cache = MemorySrlCache::new();
    ingest(
        &mut cache,
        &make_srl(&root, 1, NOW - 100, NOW + 1000, vec![]),
        &[],
        NOW,
    )
    .unwrap();
    let pol = Policy {
        recipient: Some(&bob),
        trust: Some(t.clone()),
        srls: Some(&cache),
        ..Policy::default()
    };
    assert!(verify(&env, &pol, NOW).unwrap().warnings.is_empty());

    // attestation withdrawn
    let mut cache = MemorySrlCache::new();
    let list = make_srl(
        &root,
        1,
        NOW - 100,
        NOW + 1000,
        vec![RevocationEntry {
            id: RevokedId::Attestation([1; 16]),
            reason: "withdrawn".into(),
            revoked_at: NOW - 50,
        }],
    );
    ingest(&mut cache, &list, &[], NOW).unwrap();
    let pol = Policy {
        recipient: Some(&bob),
        trust: Some(t.clone()),
        srls: Some(&cache),
        ..Policy::default()
    };
    assert_eq!(
        verify(&env, &pol, NOW).unwrap_err().code,
        ErrorCode::AttestationRevoked
    );

    // subject compromised before it signed: step 8, even with no trust policy
    let mut cache = MemorySrlCache::new();
    let list = make_srl(
        &root,
        1,
        NOW - 100,
        NOW + 1000,
        vec![RevocationEntry {
            id: RevokedId::Identity(subj.agent_id()),
            reason: "compromised".into(),
            revoked_at: NOW - 10,
        }],
    );
    ingest(&mut cache, &list, &[], NOW).unwrap();
    let pol = Policy {
        recipient: Some(&bob),
        srls: Some(&cache),
        ..Policy::default()
    };
    let e = verify(&env, &pol, NOW).unwrap_err();
    assert_eq!((e.step, e.code), (8, ErrorCode::SignerRevoked));

    // stale list: closed by default, open with a warning on request
    let mut cache = MemorySrlCache::new();
    ingest(
        &mut cache,
        &make_srl(&root, 1, NOW - 2000, NOW - 1000, vec![]),
        &[],
        NOW,
    )
    .unwrap();
    let pol = Policy {
        recipient: Some(&bob),
        trust: Some(t.clone()),
        srls: Some(&cache),
        ..Policy::default()
    };
    assert_eq!(
        verify(&env, &pol, NOW).unwrap_err().code,
        ErrorCode::SrlStale
    );
    let mut open = t;
    open.srl = SrlPolicy::LENIENT;
    let pol = Policy {
        recipient: Some(&bob),
        trust: Some(open),
        srls: Some(&cache),
        ..Policy::default()
    };
    assert_eq!(verify(&env, &pol, NOW).unwrap().warnings.len(), 1);
}

#[test]
fn atep_r_table_and_failsafe() {
    use claims::robotics as rc;
    let (root, ctl, member, bob) = (
        ident(10, false),
        ident(20, false),
        ident(40, false),
        ident(50, true),
    );
    let auth = std_att(
        &root,
        ctl.agent_id(),
        claims::ISSUER_AUTHORITY,
        claims_data(&[rc::FLEET_MEMBER]),
        1,
    );
    let fm = std_att(
        &ctl,
        member.agent_id(),
        rc::FLEET_MEMBER,
        Value::Map(vec![]),
        2,
    );
    let mut t = trust(&[&root], vec![]);
    t.atep_r = true;
    t.srl = SrlPolicy::STRICT;
    let pol = Policy {
        recipient: Some(&bob),
        trust: Some(t),
        ..Policy::default()
    };
    // telemetry: fleet-member is enough, and a missing SRL does not stop it
    let telemetry = envelope(
        &member,
        &bob,
        Some("telemetry"),
        b"t",
        &[fm.clone(), auth.clone()],
    );
    match atep_r::enforce(&telemetry, &pol, NOW) {
        Outcome::Honor(v) => {
            assert_eq!(v.command_class.as_deref(), Some("telemetry"));
            assert_eq!(v.warnings.len(), 2);
        }
        Outcome::Ignore(r) => panic!("{r}"),
    }
    // motion from the same unit is ignored (no fleet-controller, no peer-motion)
    let motion = envelope(
        &member,
        &bob,
        Some("motion"),
        b"m",
        &[fm.clone(), auth.clone()],
    );
    assert!(matches!(
        atep_r::enforce(&motion, &pol, NOW),
        Outcome::Ignore(_)
    ));
    // no command class, unknown class, no encryption
    let nocls = envelope(&member, &bob, None, b"m", &[]);
    assert_eq!(
        verify(&nocls, &pol, NOW).unwrap_err().code,
        ErrorCode::MissingCommandClass
    );
    let bad = envelope(&member, &bob, Some("fly"), b"m", &[]);
    assert_eq!(
        verify(&bad, &pol, NOW).unwrap_err().code,
        ErrorCode::UnknownCommandClass
    );
    // an ordinary (non ATEP-R) policy ignores the class header
    let plain = Policy {
        recipient: Some(&bob),
        ..Policy::default()
    };
    assert_eq!(
        verify(&bad, &plain, NOW).unwrap().command_class.as_deref(),
        Some("fly")
    );
}

#[test]
fn step_9_runs_with_no_attestations_for_empty_rules() {
    let (subj, bob) = (ident(40, false), ident(50, true));
    let env = envelope(&subj, &bob, None, b"x", &[]);
    let pol = Policy {
        recipient: Some(&bob),
        trust: Some(TrustPolicy::default()),
        ..Policy::default()
    };
    assert!(verify(&env, &pol, NOW).unwrap().claims.is_empty());
}
