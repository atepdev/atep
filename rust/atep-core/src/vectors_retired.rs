//! Vectors for `retired` and `successor` (spec section 12, "Cases for
//! `retired` and `successor`", cases RT1 to RT31 and SU1 to SU26). A child of
//! `vectors_trust`, which supplies the builders. The formats are documented in
//! `vectors/README.md` and `vectors/RETIRED-SUCCESSOR-NOTES.md`.
//!
//! Identities (seeds as for every vector, `SHA-256("ATEP-vectors-v1/<name>/<field>")`):
//! `x` retires, `y` is any other identity, `o0`, `o` and `s` are an old
//! identity, its successor and the successor's successor as the case needs,
//! `i` and `p` are root issuers and `bob` is the recipient of every data
//! envelope. They are signing-only except `bob`.

use super::*;
use crate::admission::{AdmissionState, CoreClaimRules, SubmitError};
use crate::error::AtepError;
use crate::keys::PublicBundle;
use crate::succession::{chain_links, SuccessorLink};
use crate::verify::{verify, Revocation, RevocationReason};

/// The instant of the retirement `R` of the spec tables (`T_r`).
const T_R: i64 = 1_799_990_000;
/// `expires-at` of the long lived attestations of the tables.
const FAR: i64 = 1_830_000_000;
/// The default `issued-at` of the data envelope under test.
const T_E: i64 = 1_799_999_000;

struct Cast {
    x: Identity,
    y: Identity,
    o0: Identity,
    o: Identity,
    s: Identity,
    i: Identity,
    p: Identity,
    log: Identity,
}

fn cast() -> R<Cast> {
    Ok(Cast {
        x: ident("x", false)?,
        y: ident("y", false)?,
        o0: ident("o0", false)?,
        o: ident("o", false)?,
        s: ident("s", false)?,
        i: ident("i", false)?,
        p: ident("p", false)?,
        log: ident("log", false)?,
    })
}

/// What a vector is meant to show.
enum Want {
    Accept,
    Reject(u8, &'static str),
    /// A step 9 rejection of a candidate that failed steps 1 to 8: step, code,
    /// cause step, cause code.
    Cause(u8, &'static str, u8, &'static str),
}

/// A data envelope signed by `sender` at `issued`, no `expires-at`, encrypted
/// to bob as in the chain vectors, carrying `inline` attestations.
fn env_at(
    n: &Net,
    sender: &Identity,
    label: &str,
    issued: i64,
    class: Option<&str>,
    payload: Vec<u8>,
    inline: &[&[u8]],
) -> R<Vec<u8>> {
    let mut sp = SignParams::new(&payload, CT_DATA, nonce(label), issued);
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
    encrypt(&signed, n.bob.public(), &rnd)
}

/// Run the verifier and record the vector, checking the outcome. Returns the
/// recorded result so that a case can assert more than the error code.
fn push(
    out: &mut Vec<Vector>,
    category: &'static str,
    name: &str,
    description: &str,
    cbor: Vec<u8>,
    policy: PolicySpec,
    want: Want,
) -> R<J> {
    let policy_json = policy.to_json();
    let expected = run_verify(&cbor, &policy_json)?;
    let ok = match &want {
        Want::Accept => expected["ok"] == true,
        Want::Reject(step, code) => {
            expected["ok"] == false
                && expected["step"] == *step
                && expected["error"] == *code
                && expected.get("cause").is_none()
        }
        Want::Cause(step, code, cs, cc) => {
            expected["ok"] == false
                && expected["step"] == *step
                && expected["error"] == *code
                && expected["cause"] == json!({ "step": cs, "error": cc })
        }
    };
    if !ok {
        return Err(e(format!(
            "generator bug: {category}/{name} gave {expected}"
        )));
    }
    out.push(Vector {
        category,
        name: name.to_string(),
        description: description.to_string(),
        cbor,
        inputs: json!({ "policy": policy_json }),
        expected: expected.clone(),
    });
    Ok(expected)
}

fn revoke_identity_as(who: &Identity, reason: &str, at: i64) -> RevocationEntry {
    RevocationEntry {
        id: RevokedId::Identity(who.agent_id()),
        reason: reason.into(),
        revoked_at: at,
    }
}

/// An SRL that names nothing but an unrelated attestation, issued at `issued`
/// and fresh at `NOW`.
fn srl_issued(
    issuer: &Identity,
    label: &str,
    issued: i64,
    next: i64,
    mut revoked: Vec<RevocationEntry>,
) -> R<Vec<u8>> {
    revoked.insert(0, unrelated());
    mk_srl(issuer, label, 1, issued, next, revoked)
}

/// `retired` attestation of `who` itself.
fn retired_att(who: &Identity, label: &str, issued: i64, expires: i64) -> R<Vec<u8>> {
    issue_att(&A::std(who, who.agent_id(), claims::RETIRED, label).window(issued, expires))
}

/// `operator` attestation from `issuer` about `subject`.
fn op_att(issuer: &Identity, subject: &Identity, label: &str, issued: i64) -> R<Vec<u8>> {
    issue_att(
        &A::std(issuer, subject.agent_id(), claims::OPERATOR, label)
            .data(operator_data())
            .window(issued, FAR),
    )
}

/// `successor` attestation: `old` names `new` as its successor.
fn successor_att(
    old: &Identity,
    new: AgentId,
    label: &str,
    issued: i64,
    expires: i64,
) -> R<Vec<u8>> {
    issue_att(&A::std(old, new, claims::SUCCESSOR, label).window(issued, expires))
}

/// `issuer-authority` attestation delegating `listed` to `subject`.
fn authority_att(issuer: &Identity, subject: AgentId, label: &str, listed: &[&str]) -> R<Vec<u8>> {
    issue_att(
        &A::std(issuer, subject, claims::ISSUER_AUTHORITY, label)
            .data(text_map(vec![("claims", texts(listed))])),
    )
}

fn operator_data() -> Value {
    text_map(vec![("name", Value::text("Acme Robotics Ltd"))])
}

pub(super) fn generate(out: &mut Vec<Vector>, n: &Net) -> R<()> {
    let c = cast()?;
    retired_vectors(out, n, &c)?;
    successor_vectors(out, n, &c)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// RT1 to RT31

fn retired_vectors(out: &mut Vec<Vector>, n: &Net, c: &Cast) -> R<()> {
    let pos = "retired-positive";
    let neg = "retired-negative";
    let x = c.x.agent_id();
    let y = c.y.agent_id();
    let ret = |label: &str, issued: i64, expires: i64| retired_att(&c.x, label, issued, expires);
    // R: the retirement of X of the tables.
    let r = ret("rt/r", T_R, FAR)?;
    let r_id = A::std(&c.x, x, claims::RETIRED, "rt/r").id();
    let store = |list: &[&[u8]]| -> PolicySpec {
        let mut p = pol(NOW);
        p.recipient = Some(n.bob.seeds().clone());
        p.attestations = list.iter().map(|a| a.to_vec()).collect();
        p
    };
    let ex = |label: &str, t: i64| env_at(n, &c.x, label, t, None, payload_for(label), &[]);
    // The SRL of X is issued before T_r: a retired issuer cannot publish later.
    let srl_x = |label: &str| srl_issued(&c.x, label, 1_799_980_000, NOW + 82_800, vec![]);
    let fresh = |who: &Identity, label: &str| fresh_srl(who, label, vec![]);

    // RT1 to RT3: the boundary.
    push(out, pos, "rt01-envelope-before-retirement",
        "RT1. The store holds R (retired at 1799990000); X signs a data envelope issued at 1799989999, one second before. Accepted.",
        ex("rt/e1", 1_799_989_999)?, store(&[&r]), Want::Accept)?;
    push(out, neg, "rt02-boundary-is-inclusive",
        "RT2. The store holds R (retired at 1799990000); X signs a data envelope issued at 1799990000, the same second. The boundary is inclusive. Expect step 8 signer_revoked.",
        ex("rt/e2", T_R)?, store(&[&r]), Want::Reject(8, "signer_revoked"))?;
    push(out, neg, "rt03-envelope-after-retirement",
        "RT3. The store holds R; X signs a data envelope issued at 1799999999, after the retirement. Expect step 8 signer_revoked.",
        ex("rt/e3", 1_799_999_999)?, store(&[&r]), Want::Reject(8, "signer_revoked"))?;

    // RT4: the expiry of a retirement is not compared.
    let r_expired = ret("rt/r-expired", T_R, 1_799_995_000)?;
    push(out, neg, "rt04-expired-retirement-still-counts",
        "RT4. The store holds a retirement of X issued at 1799990000 whose expires-at 1799995000 is already past; the data envelope is issued at 1799999000. Retirement is permanent, its expiry is not compared. Expect step 8 signer_revoked.",
        ex("rt/e4", T_E)?, store(&[&r_expired]), Want::Reject(8, "signer_revoked"))?;

    // RT5: an inline retirement is not read at step 8.
    push(out, pos, "rt05-inline-retirement-is-ignored",
        "RT5. The store is empty and R travels only inside the -70009 array of the data envelope (issued at 1799999000). Inline attestations are not read at step 8, because an envelope could simply omit them. Accepted.",
        env_at(n, &c.x, "rt/e5", T_E, None, payload_for("rt/e5"), &[&r])?, store(&[]), Want::Accept)?;

    // RT6: a retired attestation for another subject is not a retirement.
    let r_other = forge_att(
        &A::std(&c.x, y, claims::RETIRED, "rt/r-other").window(T_R, FAR),
        |_| {},
    )?;
    push(out, pos, "rt06a-retired-for-another-subject-is-ignored",
        "RT6, first part. The store holds an attestation with claim retired, issuer X and subject Y (not a valid retirement), issued at 1799990000; X signs a data envelope issued at 1799999000. Accepted.",
        ex("rt/e6a", T_E)?, store(&[&r_other]), Want::Accept)?;
    let mut p = store(&[]);
    p.trust = Some(trust_json(&[&c.x], vec![rule(claims::RETIRED)], json!({})));
    push(out, neg, "rt06b-retired-for-another-subject-as-candidate",
        "RT6, second part. The same attestation as a step 9 candidate: Y signs a data envelope carrying it inline and the policy requires the claim `retired`. Its layout is wrong (subject differs from issuer). Expect step 9 attestation_schema_invalid.",
        env_at(n, &c.y, "rt/e6b", T_E, None, payload_for("rt/e6b"), &[&r_other])?, p,
        Want::Reject(9, "attestation_schema_invalid"))?;

    // RT7 to RT9: a retirement that is not valid is ignored.
    let r_badsig = mutate(&r, |a| flip_last(sig_slot(a, 0)))?;
    push(out, pos, "rt07-bad-signature-retirement-is-ignored",
        "RT7. The store holds R with the last byte of its EdDSA signature changed (it fails step 4 and is ignored, not an error); the data envelope is issued at 1799999000. Accepted.",
        ex("rt/e7", T_E)?, store(&[&r_badsig]), Want::Accept)?;
    let r_reason = forge_att(
        &A::std(&c.x, x, claims::RETIRED, "rt/r-reason")
            .data(text_map(vec![("reason", Value::Int(5))]))
            .window(T_R, FAR),
        |_| {},
    )?;
    push(out, pos, "rt08-non-text-reason-retirement-is-ignored",
        "RT8. The store holds a retirement whose data is {\"reason\": 5}, a schema failure, so it is ignored; the data envelope is issued at 1799999000. Accepted.",
        ex("rt/e8", T_E)?, store(&[&r_reason]), Want::Accept)?;
    let r_long = forge_att(
        &A::std(&c.x, x, claims::RETIRED, "rt/r-401d").window(T_R, 1_834_636_400),
        |_| {},
    )?;
    push(out, pos, "rt09-401-day-retirement-is-ignored",
        "RT9. The store holds a retirement with expires-at 1834636400, 401 days after its issued-at, over the 400 day limit, so it is ignored; the data envelope is issued at 1799999000. Accepted.",
        ex("rt/e9", T_E)?, store(&[&r_long]), Want::Accept)?;

    // RT10: an SRL cannot lift a retirement.
    let mut p = store(&[&r]);
    p.srls = vec![srl_issued(
        &c.x,
        "rt/srl-x-lifts",
        1_799_980_000,
        NOW + 82_800,
        vec![revoke_att(r_id, "withdrawn", NOW - DAY)],
    )?];
    push(out, neg, "rt10-srl-cannot-lift-a-retirement",
        "RT10. The store holds R and the cached SRL of X (issued at 1799980000) has a 16 byte entry naming the id of R. An issuer cannot lift its own retirement by withdrawing the attestation. The data envelope is issued at 1799999000. Expect step 8 signer_revoked.",
        ex("rt/e10", T_E)?, p, Want::Reject(8, "signer_revoked"))?;

    // RT11, RT12: an SRL identity entry with reason retired.
    let srl_entry = |label: &str, who: &Identity, reason: &str, at: i64| {
        fresh_srl(who, label, vec![revoke_identity_as(&c.x, reason, at)])
    };
    let mut p = store(&[]);
    p.srls = vec![srl_entry("rt/srl-i-retired", &c.i, "retired", T_R)?];
    push(out, neg, "rt11-srl-entry-retired-boundary",
        "RT11. The store is empty; the cached SRL of i has the identity entry {X, retired, 1799990000}; the data envelope is issued at 1799990000. Any identity entry counts, whatever its reason. Expect step 8 signer_revoked.",
        ex("rt/e11", T_R)?, p, Want::Reject(8, "signer_revoked"))?;
    let mut p = store(&[]);
    p.srls = vec![srl_entry("rt/srl-i-retired", &c.i, "retired", T_R)?];
    push(
        out,
        pos,
        "rt12-srl-entry-retired-before",
        "RT12. As RT11 with the data envelope issued at 1799989999. Accepted.",
        ex("rt/e12", 1_799_989_999)?,
        p,
        Want::Accept,
    )?;

    // RT13: a directly supplied revocation.
    let mut p = store(&[]);
    p.revocations = vec![Revocation {
        id: x,
        reason: RevocationReason::Retired,
        revoked_at: T_R,
    }];
    push(out, neg, "rt13-direct-revocation-retired",
        "RT13. The store is empty; the verifier was given the revocation {X, retired, 1799990000} directly; the data envelope is issued at 1799990000. Expect step 8 signer_revoked.",
        ex("rt/e13", T_R)?, p, Want::Reject(8, "signer_revoked"))?;

    // RT14, RT15: compromised earlier than the retirement.
    let mut p = store(&[&r]);
    p.srls = vec![srl_entry(
        "rt/srl-i-comp-early",
        &c.i,
        "compromised",
        1_799_980_000,
    )?];
    push(out, neg, "rt14-earlier-compromised-instant-wins",
        "RT14. The store holds R (retired at 1799990000) and the cached SRL of i lists X as compromised from 1799980000; the data envelope is issued at 1799985000, between the two. The union takes the earliest instant. Expect step 8 signer_revoked.",
        ex("rt/e14", 1_799_985_000)?, p, Want::Reject(8, "signer_revoked"))?;
    let mut p = store(&[&r]);
    p.srls = vec![srl_entry(
        "rt/srl-i-comp-early",
        &c.i,
        "compromised",
        1_799_980_000,
    )?];
    push(out, pos, "rt15-before-earlier-compromised-instant",
        "RT15. As RT14 with the data envelope issued at 1799979999, before both instants. Accepted.",
        ex("rt/e15", 1_799_979_999)?, p, Want::Accept)?;

    // RT16, RT17: compromised later than the retirement.
    let mut p = store(&[&r]);
    p.srls = vec![srl_entry(
        "rt/srl-i-comp-late",
        &c.i,
        "compromised",
        1_799_995_000,
    )?];
    push(out, neg, "rt16-retirement-applies-before-later-compromised-entry",
        "RT16. The store holds R (retired at 1799990000) and the cached SRL of i lists X as compromised from 1799995000; the data envelope is issued at 1799992000. The retirement applies although the entry is later. Expect step 8 signer_revoked.",
        ex("rt/e16", 1_799_992_000)?, p, Want::Reject(8, "signer_revoked"))?;
    let mut p = store(&[&r]);
    p.srls = vec![srl_entry(
        "rt/srl-i-comp-late",
        &c.i,
        "compromised",
        1_799_995_000,
    )?];
    push(
        out,
        pos,
        "rt17-before-retirement-and-later-compromised-entry",
        "RT17. As RT16 with the data envelope issued at 1799989999. Accepted.",
        ex("rt/e17", 1_799_989_999)?,
        p,
        Want::Accept,
    )?;

    // RT18, RT19: a retired attestation is exempt from the retirement rule.
    let mut p = store(&[&r]);
    p.recipient = None;
    push(out, pos, "rt18-retirement-itself-is-exempt",
        "RT18. The store holds R; R itself is verified as an envelope with no policy. A `retired` attestation of X is exempt from the retirement rule. Accepted.",
        r.clone(), p, Want::Accept)?;
    let r2 = ret("rt/r2", 1_799_995_000, FAR)?;
    let mut p = store(&[&r]);
    p.recipient = None;
    push(out, pos, "rt19-second-retirement-is-exempt",
        "RT19. The store holds R; a second retirement R2 of X issued at 1799995000 is verified. Accepted (a retirement can be re-issued or renewed).",
        r2.clone(), p, Want::Accept)?;

    // RT20: the exemption does not cover an SRL entry.
    let mut p = store(&[&r]);
    p.recipient = None;
    p.srls = vec![srl_entry(
        "rt/srl-i-comp-early",
        &c.i,
        "compromised",
        1_799_980_000,
    )?];
    push(out, neg, "rt20-exemption-does-not-cover-an-srl-entry",
        "RT20. The store holds R and the cached SRL of i lists X as compromised from 1799980000; R itself (issued at 1799990000) is verified. The exemption is from the retirement rule only. Expect step 8 signer_revoked.",
        r.clone(), p, Want::Reject(8, "signer_revoked"))?;

    // RT21, RT22: attestations issued by the retired identity.
    let op_x = |label: &str, issued: i64| op_att(&c.x, &c.y, label, issued);
    let policy_x = |store_list: &[&[u8]]| -> PolicySpec {
        let mut p = store(store_list);
        p.trust = Some(trust_json(&[&c.x], vec![rule(claims::OPERATOR)], json!({})));
        p.srls = vec![srl_x("rt/srl-x").unwrap()];
        p
    };
    let before = op_x("rt/op-before", 1_799_980_000)?;
    let got = push(out, pos, "rt21-claim-issued-before-the-retirement",
        "RT21. The store holds R; the policy has the root X and the rule `operator`; Y holds an `operator` attestation from X issued at 1799980000, before the retirement. It stays valid. Accepted, the claim is reported.",
        env_at(n, &c.y, "rt/e21", T_E, None, payload_for("rt/e21"), &[&before])?,
        policy_x(&[&r]), Want::Accept)?;
    if got["claims"][0]["chain"].as_array().map(|a| a.len()) != Some(1) {
        return Err(e_("RT21 chain"));
    }
    let after = op_x("rt/op-after", T_R)?;
    push(out, neg, "rt22-claim-issued-at-the-retirement",
        "RT22. As RT21 with the `operator` attestation issued at 1799990000, the instant of the retirement. As a step 9 candidate it fails step 8. Expect step 9 attestation_invalid with cause step 8 signer_revoked.",
        env_at(n, &c.y, "rt/e22", T_E, None, payload_for("rt/e22"), &[&after])?,
        policy_x(&[&r]), Want::Cause(9, "attestation_invalid", 8, "signer_revoked"))?;

    // RT23: a delegation by the retired identity.
    let p_x = authority_att(&c.p, x, "rt/p-x-authority", &[claims::OPERATOR])?;
    let op_via = op_x("rt/op-via", 1_799_985_000)?;
    let mut p = store(&[&r]);
    p.trust = Some(trust_json(&[&c.p], vec![rule(claims::OPERATOR)], json!({})));
    p.srls = vec![fresh(&c.p, "rt/srl-p")?, srl_x("rt/srl-x")?];
    let got = push(out, pos, "rt23-delegation-by-the-retired-identity",
        "RT23. The store holds R; the root is p, which delegated `operator` to X; Y holds an `operator` attestation from X issued at 1799985000, before the retirement. Accepted; the chain is the claim attestation and the delegation.",
        env_at(n, &c.y, "rt/e23", T_E, None, payload_for("rt/e23"), &[&op_via, &p_x])?, p, Want::Accept)?;
    if got["claims"][0]["chain"].as_array().map(|a| a.len()) != Some(2) {
        return Err(e_("RT23 chain"));
    }

    // RT26 to RT29: ATEP-R.
    use claims::robotics as rc;
    let atep_r = |roots: &[&Identity]| -> J { trust_json(roots, vec![], json!({"atep_r": true})) };
    let estop = |label: &str| command_payload(label, "e-stop");
    let sc_data = || {
        text_map(vec![
            ("standard", Value::text("ISO 3691-4")),
            ("date", Value::text("2026-09-01")),
        ])
    };
    let fm_x = issue_att(
        &A::std(&c.i, x, rc::FLEET_MEMBER, "rt/fm-x")
            .data(text_map(vec![("fleet", Value::text("fleet-7"))])),
    )?;
    let sc_x = issue_att(
        &A::std(&c.i, x, rc::SAFETY_CERTIFIED, "rt/sc-x")
            .data(sc_data())
            .evidence()
            .window(NOW - 30 * DAY, NOW + 335 * DAY),
    )?;
    let estop_policy = || -> R<PolicySpec> {
        let mut p = store(&[&r]);
        p.trust = Some(atep_r(&[&c.i]));
        p.srls = vec![fresh(&c.i, "rt/srl-i")?];
        Ok(p)
    };
    push(out, neg, "rt26-estop-from-a-retired-identity",
        "RT26. ATEP-R; X holds `fleet-member` and `safety-certified` from the trusted root i; class safety, payload {\"command\": \"e-stop\"}; the store holds R; the data envelope is issued at 1799999000. The e-stop relaxation covers claim expiry only. Expect step 8 signer_revoked.",
        env_at(n, &c.x, "rt/e26", T_E, Some("safety"), estop("rt/e26"), &[&fm_x, &sc_x])?,
        estop_policy()?, Want::Reject(8, "signer_revoked"))?;
    let got = push(out, pos, "rt27-estop-before-the-retirement",
        "RT27. As RT26 with the data envelope issued at 1799989999, before the retirement. Accepted, the claims are reported.",
        env_at(n, &c.x, "rt/e27", 1_799_989_999, Some("safety"), estop("rt/e27"), &[&fm_x, &sc_x])?,
        estop_policy()?, Want::Accept)?;
    if got["claims"].as_array().map(|a| a.len()) != Some(2) {
        return Err(e_("RT27 claims"));
    }

    // RT28, RT29: the stale SRL of a retired issuer.
    let srl_x_stale = || srl_issued(&c.x, "rt/srl-x-stale", 1_799_980_000, 1_799_999_000, vec![]);
    let p_x_auth = |label: &str, listed: &[&str]| authority_att(&c.p, x, label, listed);
    let fc_y = issue_att(
        &A::std(&c.x, y, rc::FLEET_CONTROLLER, "rt/fc-y")
            .data(text_map(vec![("fleet", Value::text("fleet-7"))]))
            .window(1_799_900_000, FAR),
    )?;
    let auth_fc = p_x_auth("rt/p-x-fc", &[rc::FLEET_CONTROLLER])?;
    let mut p = store(&[&r]);
    p.trust = Some(atep_r(&[&c.p]));
    p.srls = vec![fresh(&c.p, "rt/srl-p")?, srl_x_stale()?];
    push(out, neg, "rt28-motion-stale-srl-of-retired-issuer",
        "RT28. ATEP-R motion from Y; Y's `fleet-controller` attestation was issued by X (issued at 1799900000, before the retirement) under a delegation from the root p; the cached SRL of X has next-update 1799999000 and that of p is fresh; the store holds R. A retired issuer cannot publish a newer list, and motion fails closed on a stale one. Expect step 9 srl_stale.",
        env_at(n, &c.y, "rt/e28", T_E, Some("motion"), payload_for("rt/e28"), &[&fc_y, &auth_fc])?,
        p, Want::Reject(9, "srl_stale"))?;
    let fm_y = issue_att(
        &A::std(&c.x, y, rc::FLEET_MEMBER, "rt/fm-y")
            .data(text_map(vec![("fleet", Value::text("fleet-7"))]))
            .window(1_799_900_000, FAR),
    )?;
    let sc_y = issue_att(
        &A::std(&c.x, y, rc::SAFETY_CERTIFIED, "rt/sc-y")
            .data(sc_data())
            .evidence()
            .window(1_799_900_000, FAR),
    )?;
    let auth_both = p_x_auth("rt/p-x-both", &[rc::FLEET_MEMBER, rc::SAFETY_CERTIFIED])?;
    let mut p = store(&[&r]);
    p.trust = Some(atep_r(&[&c.p]));
    p.srls = vec![fresh(&c.p, "rt/srl-p")?, srl_x_stale()?];
    let got = push(out, pos, "rt29-estop-stale-srl-of-retired-issuer-warns",
        "RT29. ATEP-R e-stop from Y; Y's `fleet-member` and `safety-certified` attestations were issued by X before the retirement under a delegation from the root p; the SRLs are as in RT28; the store holds R. An e-stop continues on a stale list with a warning. Accepted with the warning for the list of X.",
        env_at(n, &c.y, "rt/e29", T_E, Some("safety"), estop("rt/e29"), &[&fm_y, &sc_y, &auth_both])?,
        p, Want::Accept)?;
    let want_warning = format!(
        "SRL of {} is past next-update 1799999000; using the stale copy",
        x.to_text()
    );
    if got["warnings"] != json!([want_warning]) {
        return Err(e_("RT29 warning"));
    }

    // SRL loading in the verifier's context: RT24 and RT25.
    let srl_x_after = srl_issued(&c.x, "rt/srl-x-after", 1_799_995_000, NOW + 82_800, vec![])?;
    srl_vector(
        out,
        "rt24-retired-issuer-cannot-publish-an-srl",
        "RT24. The store holds R (retired at 1799990000); an SRL signed by X with issued-at 1799995000 is loaded. A retired issuer cannot publish any further list: step 8 applies to the SRL in the verifier's own context. Rejected at load, step 8 signer_revoked.",
        srl_x_after,
        None,
        &[&r],
        &[],
    )?;
    let self_entry = mk_srl(
        &c.x,
        "rt/srl-x-final",
        1,
        1_799_985_000,
        NOW + 82_800,
        vec![unrelated(), revoke_identity_as(&c.x, "retired", T_R)],
    )?;
    srl_vector(
        out,
        "rt25-final-srl-naming-its-own-issuer",
        "RT25. An SRL signed by X with issued-at 1799985000 that holds the entry {X, retired, 1799990000} (strictly later than its own issued-at) is loaded, and then the same bytes are loaded again into the cache that holds it. Both loads are accepted.",
        self_entry.clone(),
        Some(self_entry),
        &[],
        &[],
    )?;

    // Log admission: RT30 and RT31.
    let op_after_x = op_att(&c.x, &c.y, "rt/op-by-x-late", T_E)?;
    admission_vector(
        out,
        c,
        "rt30-log-refuses-a-document-after-a-retirement",
        "RT30. The log holds R; an `operator` attestation signed by X with issued-at 1799999000 is submitted. Refused verification_failed: step 8 signer_revoked (the log uses the retired attestations it holds as the local attestation store).",
        op_after_x,
        &[&r],
        Err(("verification_failed", Some((8, "signer_revoked")))),
    )?;
    admission_vector(
        out,
        c,
        "rt31a-log-admits-a-second-retirement",
        "RT31, first part. The log holds R; a second retirement R2 of X (issued at 1799995000) is submitted. Admitted like the first.",
        r2,
        &[&r],
        Ok(()),
    )?;
    let r_wrong = forge_att(
        &A::std(&c.x, y, claims::RETIRED, "rt/r-wrong-subject").window(NOW - 20 * DAY, FAR),
        |_| {},
    )?;
    admission_vector(
        out,
        c,
        "rt31b-log-refuses-a-retirement-for-another-subject",
        "RT31, second part. A `retired` attestation with issuer X and subject Y is submitted to a log that holds nothing. Refused schema_invalid.",
        r_wrong,
        &[],
        Err(("schema_invalid", None)),
    )?;
    Ok(())
}

fn e_(m: &str) -> AtepError {
    e(format!("generator bug: {m}"))
}

// ---------------------------------------------------------------------------
// SU1 to SU26

fn successor_vectors(out: &mut Vec<Vector>, n: &Net, c: &Cast) -> R<()> {
    let pos = "successor-positive";
    let neg = "successor-negative";
    let (o, s, i) = (c.o.agent_id(), c.s.agent_id(), c.i.agent_id());
    let op = claims::OPERATOR;
    // A_O: `operator` from I about O. SUC: O names S as its successor.
    let a_o = issue_att(
        &A::std(&c.i, o, op, "su/a-o")
            .data(operator_data())
            .window(1_799_000_000, FAR),
    )?;
    let suc = successor_att(&c.o, s, "su/suc", 1_799_500_000, FAR)?;
    let suc_id = A::std(&c.o, s, claims::SUCCESSOR, "su/suc").id();
    let a_s_att = A::std(&c.i, s, op, "su/a-s").data(operator_data());
    let a_s = issue_att(&a_s_att)?;
    let a_s_id = a_s_att.id();

    // The fixture policy: roots [I], rule `operator` from I, follow_succession.
    let trust = |extra: J| -> J {
        trust_json(
            &[&c.i],
            vec![json!({"claim": op, "root": i.to_text()})],
            extra,
        )
    };
    let follow = || json!({"follow_succession": true});
    let policy = |t: J| -> PolicySpec {
        let mut p = pol(NOW);
        p.recipient = Some(n.bob.seeds().clone());
        p.trust = Some(t);
        p
    };
    // Fresh SRLs of I and O that name nothing. O's was issued before any
    // retirement or compromise instant of the cases, so that it still loads.
    let srl_i = || fresh_srl(&c.i, "su/srl-i", vec![]);
    let srl_o = || srl_issued(&c.o, "su/srl-o", 1_799_400_000, NOW + 82_800, vec![]);
    let with_srls = |mut p: PolicySpec| -> R<PolicySpec> {
        p.srls = vec![srl_i()?, srl_o()?];
        Ok(p)
    };
    let env = |label: &str, inline: &[&[u8]]| {
        env_at(n, &c.s, label, T_E, None, payload_for(label), inline)
    };
    let base = || with_srls(policy(trust(follow())));
    let retired_o = |label: &str, issued: i64| retired_att(&c.o, label, issued, FAR);

    // SU1: the claim is inherited.
    let got = push(out, pos, "su01-claim-inherited-through-succession",
        "SU1. Policy: roots [i], rule `operator` from i, follow_succession. S signs; inline: A_O (`operator` from i about O, issued 1799000000) and SUC (O names S, issued 1799500000). The ordinary evaluation fails with claim_missing, then one hop of succession finds the claim. Accepted; the chain is A_O then SUC and expires_at is 1830000000.",
        env("su/e01", &[&a_o, &suc])?, base()?, Want::Accept)?;
    let chain = &got["claims"][0]["chain"];
    if chain.as_array().map(|a| a.len()) != Some(2)
        || chain[0]["subject"] != o.to_text()
        || chain[1]["claim"] != claims::SUCCESSOR
        || got["claims"][0]["expires_at"] != FAR
    {
        return Err(e_("SU1 chain"));
    }
    // SU2 to SU4.
    push(out, neg, "su02-follow-succession-absent",
        "SU2. As SU1 with follow_succession absent from the policy: a successor attestation is an ordinary attestation and nothing else. Expect step 9 claim_missing.",
        env("su/e02", &[&a_o, &suc])?, with_srls(policy(trust(json!({}))))?, Want::Reject(9, "claim_missing"))?;
    push(
        out,
        neg,
        "su03-successor-without-claim",
        "SU3. Only SUC is carried: there is nothing to inherit. Expect step 9 claim_missing.",
        env("su/e03", &[&suc])?,
        base()?,
        Want::Reject(9, "claim_missing"),
    )?;
    push(
        out,
        neg,
        "su04-claim-without-successor",
        "SU4. Only A_O is carried: nothing links S to O. Expect step 9 claim_missing.",
        env("su/e04", &[&a_o])?,
        base()?,
        Want::Reject(9, "claim_missing"),
    )?;

    // SU5 to SU7: a negative result about S itself is final.
    let got = push(out, pos, "su05-own-claim-is-used",
        "SU5. As SU1 and S also holds A_S, an `operator` attestation from i about S. The ordinary evaluation succeeds; the chain is A_S alone.",
        env("su/e05", &[&a_o, &suc, &a_s])?, base()?, Want::Accept)?;
    if got["claims"][0]["chain"].as_array().map(|a| a.len()) != Some(1) {
        return Err(e_("SU5 chain"));
    }
    let mut p = base()?;
    p.srls[0] = fresh_srl(
        &c.i,
        "su/srl-i-revokes-a-s",
        vec![revoke_att(a_s_id, "withdrawn", NOW - DAY)],
    )?;
    push(out, neg, "su06-own-claim-revoked-is-final",
        "SU6. As SU5 and the SRL of i names A_S. The failure is about S itself, not claim_missing, so the claim of O is not used. Expect step 9 attestation_revoked.",
        env("su/e06", &[&a_o, &suc, &a_s])?, p, Want::Reject(9, "attestation_revoked"))?;
    let a_s_old = issue_att(
        &A::std(&c.i, s, op, "su/a-s-old")
            .data(operator_data())
            .window(1_790_000_000, 1_820_000_000),
    )?;
    let old_rule = |extra: J| -> J {
        trust_json(
            &[&c.i],
            vec![json!({"claim": op, "root": i.to_text(), "max_age_days": 10})],
            extra,
        )
    };
    push(out, neg, "su07-own-claim-too-old-is-final",
        "SU7. As SU5 with A_S issued at 1790000000 and max_age_days 10 in the rule. Expect step 9 claim_too_old.",
        env("su/e07", &[&a_o, &suc, &a_s_old])?, with_srls(policy(old_rule(follow())))?, Want::Reject(9, "claim_too_old"))?;

    // SU8: only one hop.
    let a_o0 = issue_att(
        &A::std(&c.i, c.o0.agent_id(), op, "su/a-o0")
            .data(operator_data())
            .window(1_799_000_000, FAR),
    )?;
    let suc1 = successor_att(&c.o0, o, "su/suc1", 1_799_400_000, FAR)?;
    let mut p = base()?;
    p.srls.push(srl_issued(
        &c.o0,
        "su/srl-o0",
        1_799_300_000,
        NOW + 82_800,
        vec![],
    )?);
    push(out, neg, "su08-second-hop-is-not-followed",
        "SU8. A_O0 (`operator` about O0), SUC1 (O0 names O) and SUC (O names S). S inherits what O holds and nothing that only O0 holds; a second hop is not an error and is never followed. Expect step 9 claim_missing.",
        env("su/e08", &[&a_o0, &suc1, &suc])?, p, Want::Reject(9, "claim_missing"))?;

    // SU9, SU10: the old identity retires.
    let mut p = base()?;
    p.attestations = vec![retired_o("su/ret-o-at", 1_799_500_000)?];
    push(out, neg, "su09-old-identity-retired-at-the-successor-instant",
        "SU9. The store holds a retirement of O issued at 1799500000, the instant of SUC. SUC fails step 8 (inclusive boundary) and is not followed: an old identity must issue the successor attestation strictly before it retires. Expect step 9 claim_missing.",
        env("su/e09", &[&a_o, &suc])?, p, Want::Reject(9, "claim_missing"))?;
    let mut p = base()?;
    p.attestations = vec![retired_o("su/ret-o-after", 1_799_500_001)?];
    push(
        out,
        pos,
        "su10-old-identity-retired-one-second-later",
        "SU10. As SU9 with the retirement issued at 1799500001, one second after SUC. Accepted.",
        env("su/e10", &[&a_o, &suc])?,
        p,
        Want::Accept,
    )?;

    // SU11, SU12: the old identity is compromised.
    let comp = |at: i64| -> R<PolicySpec> {
        let mut p = base()?;
        p.srls[0] = fresh_srl(
            &c.i,
            "su/srl-i-comp",
            vec![revoke_identity_as(&c.o, "compromised", at)],
        )?;
        Ok(p)
    };
    push(out, neg, "su11-old-identity-compromised-at-the-successor-instant",
        "SU11. The cached SRL of i lists O as compromised from 1799500000, the instant of SUC. SUC fails step 8 and is not followed. Expect step 9 claim_missing.",
        env("su/e11", &[&a_o, &suc])?, comp(1_799_500_000)?, Want::Reject(9, "claim_missing"))?;
    push(out, pos, "su12-successor-predates-the-compromise",
        "SU12. As SU11 with revoked-at 1799500001. SUC was issued before the compromise and stays valid. Accepted.",
        env("su/e12", &[&a_o, &suc])?, comp(1_799_500_001)?, Want::Accept)?;

    // SU13: the successor attestation expired.
    let suc_expired = successor_att(&c.o, s, "su/suc-expired", 1_799_500_000, 1_799_999_999)?;
    push(out, neg, "su13-successor-attestation-expired",
        "SU13. SUC has expires-at 1799999999, before now: the succession has ended. Expect step 9 claim_missing.",
        env("su/e13", &[&a_o, &suc_expired])?, base()?, Want::Reject(9, "claim_missing"))?;

    // SU14: a successor attestation that fails its layout.
    let suc_self = forge_att(
        &A::std(&c.s, s, claims::SUCCESSOR, "su/suc-self").window(1_799_500_000, FAR),
        |_| {},
    )?;
    push(out, neg, "su14a-successor-naming-its-own-issuer",
        "SU14, first part. A_O and a `successor` attestation with issuer S and subject S, a schema failure. Expect step 9 claim_missing.",
        env("su/e14a", &[&a_o, &suc_self])?, base()?, Want::Reject(9, "claim_missing"))?;
    let suc_reason = forge_att(
        &A::std(&c.o, s, claims::SUCCESSOR, "su/suc-reason")
            .data(text_map(vec![("reason", Value::Int(5))]))
            .window(1_799_500_000, FAR),
        |_| {},
    )?;
    push(out, neg, "su14b-successor-with-non-text-reason",
        "SU14, second part. A_O and a `successor` attestation from O to S whose data is {\"reason\": 5}, a schema failure. Expect step 9 claim_missing.",
        env("su/e14b", &[&a_o, &suc_reason])?, base()?, Want::Reject(9, "claim_missing"))?;

    // SU15 to SU17: the SRL of the old identity.
    let mut p = base()?;
    p.srls[1] = srl_issued(
        &c.o,
        "su/srl-o-names-suc",
        1_799_400_000,
        NOW + 82_800,
        vec![revoke_att(suc_id, "withdrawn", NOW - DAY)],
    )?;
    push(out, neg, "su15-srl-of-the-old-identity-withdraws-the-successor",
        "SU15. The SRL of O names the id of SUC. An entry of the SRL of O withdraws the successor attestation. Expect step 9 claim_missing.",
        env("su/e15", &[&a_o, &suc])?, p, Want::Reject(9, "claim_missing"))?;
    let stale_o = || srl_issued(&c.o, "su/srl-o-stale", 1_799_400_000, 1_799_999_000, vec![]);
    let mut p = base()?;
    p.srls[1] = stale_o()?;
    push(out, neg, "su16-stale-srl-of-the-old-identity-fail-closed",
        "SU16. The SRL of O has next-update 1799999000 and srl.on_stale is fail-closed (the default): SUC fails with srl_stale, which a retiring identity avoids by publishing a final list with a suitable next-update. Expect step 9 claim_missing.",
        env("su/e16", &[&a_o, &suc])?, p, Want::Reject(9, "claim_missing"))?;
    let mut p = with_srls(policy(trust(
        json!({"follow_succession": true, "srl": {"on_stale": "fail-open"}}),
    )))?;
    p.srls[1] = stale_o()?;
    let got = push(
        out,
        pos,
        "su17-stale-srl-of-the-old-identity-fail-open",
        "SU17. As SU16 with srl.on_stale fail-open. Accepted, with the warning for the list of O.",
        env("su/e17", &[&a_o, &suc])?,
        p,
        Want::Accept,
    )?;
    let w = format!(
        "SRL of {} is past next-update 1799999000; using the stale copy",
        o.to_text()
    );
    if got["warnings"] != json!([w]) {
        return Err(e_("SU17 warning"));
    }

    // SU18: the claim of O is too old, the error is the one without succession.
    push(out, neg, "su18-inherited-claim-too-old",
        "SU18. As SU1 with max_age_days 10 in the rule: A_O (issued 1799000000) is too old, the pair fails, and the rule reports the error it already had. Expect step 9 claim_missing.",
        env("su/e18", &[&a_o, &suc])?, with_srls(policy(old_rule(follow())))?, Want::Reject(9, "claim_missing"))?;

    // SU19, SU20: the chain through succession is one deeper.
    let d1 = authority_att(&c.p, i, "su/d1", &[op])?;
    let deep = |max_depth: i64| -> R<PolicySpec> {
        let t = trust_json(
            &[&c.p],
            vec![json!({"claim": op, "root": c.p.agent_id().to_text()})],
            json!({"follow_succession": true, "max_depth": max_depth}),
        );
        let mut p = policy(t);
        p.srls = vec![srl_i()?, srl_o()?, fresh_srl(&c.p, "su/srl-p", vec![])?];
        Ok(p)
    };
    let got = push(out, pos, "su19-succession-with-a-delegation-at-max-depth-3",
        "SU19. Roots [p]; A_O is issued by i; D1 is an `issuer-authority` attestation from p to i listing `operator`; max_depth 3. Accepted; the chain is A_O, SUC, D1 (three attestations).",
        env("su/e19", &[&a_o, &suc, &d1])?, deep(3)?, Want::Accept)?;
    if got["claims"][0]["chain"].as_array().map(|a| a.len()) != Some(3) {
        return Err(e_("SU19 chain"));
    }
    push(out, neg, "su20-succession-is-one-deeper-than-the-direct-chain",
        "SU20. As SU19 with max_depth 2. The direct chain A_O, D1 would pass at depth 2, but the chain through succession needs three attestations. Expect step 9 claim_missing.",
        env("su/e20", &[&a_o, &suc, &d1])?, deep(2)?, Want::Reject(9, "claim_missing"))?;

    // SU21, SU22: ATEP-R.
    let fm_o = issue_att(
        &A::std(&c.i, o, claims::robotics::FLEET_MEMBER, "su/fm-o")
            .data(text_map(vec![("fleet", Value::text("fleet-7"))]))
            .window(1_799_000_000, FAR),
    )?;
    let ar = |extra: J| -> R<PolicySpec> {
        let mut m = extra;
        m["atep_r"] = json!(true);
        with_srls(policy(trust_json(&[&c.i], vec![], m)))
    };
    let got = push(out, pos, "su21-atep-r-class-requirement-through-succession",
        "SU21. ATEP-R, class telemetry; the policy has the root i, no other rule, follow_succession; A_O is a `fleet-member` attestation about O from i; SUC. The class requirement is a rule of the same kind and works on the inherited attestation. Accepted, command_class telemetry, chain A_O then SUC.",
        env_at(n, &c.s, "su/e21", T_E, Some("telemetry"), payload_for("su/e21"), &[&fm_o, &suc])?, ar(follow())?, Want::Accept)?;
    if got["command_class"] != "telemetry"
        || got["claims"][0]["chain"].as_array().map(|a| a.len()) != Some(2)
    {
        return Err(e_("SU21 result"));
    }
    push(
        out,
        neg,
        "su22-atep-r-without-follow-succession",
        "SU22. As SU21 with follow_succession absent. Expect step 9 claim_missing.",
        env_at(
            n,
            &c.s,
            "su/e22",
            T_E,
            Some("telemetry"),
            payload_for("su/e22"),
            &[&fm_o, &suc],
        )?,
        ar(json!({}))?,
        Want::Reject(9, "claim_missing"),
    )?;

    // SU23: both pool sources.
    let mut p = base()?;
    p.attestations = vec![suc.clone()];
    push(out, pos, "su23-successor-from-the-local-store",
        "SU23. SUC is in the verifier's local attestation store and A_O is inline: both are pool sources. Accepted.",
        env("su/e23", &[&a_o])?, p, Want::Accept)?;

    // SU24: the retirement of O does not retire S.
    let mut p = base()?;
    p.attestations = vec![retired_o("su/ret-o-late", T_R)?];
    push(out, pos, "su24-retirement-of-the-old-identity-does-not-retire-the-successor",
        "SU24. The store holds a retirement of O issued at 1799990000, after SUC. O's retirement does not retire S, and SUC (issued before it) stays valid. Accepted.",
        env("su/e24", &[&a_o, &suc])?, p, Want::Accept)?;

    // SU25: the monitor alert.
    let suc_old = successor_att(&c.o0, o, "su/mon-suc1", 1_799_400_000, FAR)?;
    let suc_new = successor_att(&c.o, s, "su/mon-suc", 1_799_500_000, FAR)?;
    monitor_vector(
        out,
        "su25-successor-chain-alert",
        "SU25. The log holds SUC1 (issuer O0, subject O) at entry 0 and SUC (issuer O, subject S) at entry 1. The monitor raises successor_chain for the entry of SUC only; a single hop is not an alert.",
        &[&suc_old, &suc_new],
    )?;

    // SU26: admission.
    let suc_self_log = forge_att(
        &A::std(&c.o, o, claims::SUCCESSOR, "su/log-self").window(NOW - 20 * DAY, FAR),
        |_| {},
    )?;
    admission_vector(
        out,
        c,
        "su26-log-refuses-a-successor-naming-its-own-issuer",
        "SU26. A `successor` attestation with subject equal to issuer is submitted to a log that holds nothing. Refused schema_invalid.",
        suc_self_log,
        &[],
        Err(("schema_invalid", None)),
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Vectors that are not verification vectors

fn srl_vector(
    out: &mut Vec<Vector>,
    name: &str,
    description: &str,
    cbor: Vec<u8>,
    cached: Option<Vec<u8>>,
    store: &[&[u8]],
    revocations: &[Revocation],
) -> R<()> {
    let inputs = json!({
        "now": NOW,
        "srl_policy": { "on_stale": "fail-closed" },
        "known_bundles": [],
        "cached_srl_hex": cached.as_ref().map(|b| hx(b)),
        "attestations": store.iter().map(|a| hx(a)).collect::<Vec<_>>(),
        "revocations": revocations.iter().map(|r| json!({
            "id": r.id.to_text(), "reason": r.reason.as_str(), "revoked_at": r.revoked_at,
        })).collect::<Vec<_>>(),
    });
    let expected = run_srl(&cbor, &inputs)?;
    out.push(Vector {
        category: "srl-context",
        name: name.to_string(),
        description: description.to_string(),
        cbor,
        inputs,
        expected,
    });
    Ok(())
}

/// The refusal of a log, in the form of the vectors.
fn admission_json(r: Result<(), SubmitError>, kind: &str) -> J {
    match r {
        Ok(()) => json!({ "ok": true, "document": kind }),
        Err(x) => {
            let mut o = Map::new();
            o.insert("ok".into(), false.into());
            o.insert("refusal".into(), x.code.into());
            if let Some(r) = &x.rejection {
                o.insert("step".into(), r.step.into());
                o.insert("error".into(), r.code.as_str().into());
            }
            J::Object(o)
        }
    }
}

/// Admit `logged` in order, then `cbor`, with the rules every log applies.
pub(super) fn run_admission(cbor: &[u8], inputs: &J) -> R<J> {
    let now = jint(inputs, "now")?;
    let max = jint(inputs, "max_envelope_bytes")? as usize;
    let log = AgentId::parse(jstr(inputs, "log")?)?;
    let mut state = AdmissionState::default();
    for l in jget(inputs, "logged")?
        .as_array()
        .ok_or_else(|| e("logged"))?
    {
        let raw = unhex(l.as_str().ok_or_else(|| e("logged entry"))?)?;
        state
            .submit(&raw, log, &CoreClaimRules, max, now)
            .map_err(|x| e(format!("logged entry was refused: {x}")))?;
    }
    let result = state.submit(cbor, log, &CoreClaimRules, max, now);
    Ok(match result {
        Ok(adm) => admission_json(
            Ok(()),
            match adm.doc {
                crate::admission::Doc::Attestation(_) => "attestation",
                crate::admission::Doc::Srl(_) => "srl",
            },
        ),
        Err(x) => admission_json(Err(x), ""),
    })
}

/// The refusal a log is expected to give: its reason and, for a failed
/// verification, the step and error code.
type Refusal = (&'static str, Option<(u8, &'static str)>);

fn admission_vector(
    out: &mut Vec<Vector>,
    c: &Cast,
    name: &str,
    description: &str,
    cbor: Vec<u8>,
    logged: &[&[u8]],
    want: Result<(), Refusal>,
) -> R<()> {
    let inputs = json!({
        "now": NOW,
        "log": c.log.agent_id().to_text(),
        "max_envelope_bytes": 65_536,
        "logged": logged.iter().map(|a| hx(a)).collect::<Vec<_>>(),
    });
    let expected = run_admission(&cbor, &inputs)?;
    let ok = match &want {
        Ok(()) => expected["ok"] == true,
        Err((refusal, step)) => {
            expected["ok"] == false
                && expected["refusal"] == *refusal
                && match step {
                    Some((st, code)) => expected["step"] == *st && expected["error"] == *code,
                    None => expected.get("step").is_none(),
                }
        }
    };
    if !ok {
        return Err(e(format!(
            "generator bug: log-admission/{name} gave {expected}"
        )));
    }
    out.push(Vector {
        category: "log-admission",
        name: name.to_string(),
        description: description.to_string(),
        cbor,
        inputs,
        expected,
    });
    Ok(())
}

/// The alerts about `successor` chains for a log whose entries are `entries`.
pub(super) fn run_monitor(cbor: &[u8], inputs: &J) -> R<J> {
    let _ = jint(inputs, "now")?;
    let doc = Value::decode(cbor)?;
    let list = doc
        .as_map()
        .and_then(|m| m.iter().find(|(k, _)| k.as_text() == Some("entries")))
        .and_then(|(_, v)| v.as_array())
        .ok_or_else(|| e("monitor vector needs a map with `entries`"))?;
    let mut links = Vec::new();
    for (idx, ent) in list.iter().enumerate() {
        let raw = ent.encode();
        let env = SignedEnvelope::decode(&raw).map_err(|x| e(x.to_string()))?;
        let mut pol = crate::verify::Policy::default();
        if let Some(b) = &env.signer_bundle {
            pol.known_bundles.push(PublicBundle::from_value(b)?);
        }
        // As the monitor does: verified as of its own issuance time.
        let v = verify(&raw, &pol, env.headers.issued_at)
            .map_err(|x| e(format!("log entry {idx} does not verify: {x}")))?;
        if v.content_type != CT_ATTESTATION {
            continue;
        }
        let att = Attestation::from_payload(&v.payload).map_err(|x| e(x.0))?;
        if att.claim == claims::SUCCESSOR {
            links.push(SuccessorLink {
                entry: idx as u64,
                issuer: att.issuer,
                subject: att.subject,
            });
        }
    }
    let alerts: Vec<J> = chain_links(&links)
        .into_iter()
        .map(|l| {
            json!({
                "alert": "successor_chain",
                "entry": l.entry,
                "issuer": l.issuer.to_text(),
                "subject": l.subject.to_text(),
            })
        })
        .collect();
    Ok(json!({ "alerts": alerts }))
}

fn monitor_vector(
    out: &mut Vec<Vector>,
    name: &str,
    description: &str,
    entries: &[&[u8]],
) -> R<()> {
    let doc = Value::Map(vec![(
        Value::text("entries"),
        Value::Array(
            entries
                .iter()
                .map(|a| Value::decode(a))
                .collect::<Result<Vec<_>, _>>()?,
        ),
    )]);
    let cbor = doc.encode();
    let inputs = json!({ "now": NOW, "check": "alerts" });
    let expected = run_monitor(&cbor, &inputs)?;
    if expected["alerts"].as_array().map(|a| a.len()) != Some(1)
        || expected["alerts"][0]["entry"] != 1
    {
        return Err(e_("SU25 alerts"));
    }
    out.push(Vector {
        category: "monitor",
        name: name.to_string(),
        description: description.to_string(),
        cbor,
        inputs,
        expected,
    });
    Ok(())
}
