//! Verification, spec section 10, all ten steps. Step 9 (policy, attestations,
//! chains, revocation lists, inclusion proofs) lives in `trust.rs` and
//! `atep_r.rs`.

use crate::atep_r::{self, CommandClass};
use crate::attestation::Attestation;
use crate::cbor::Value;
use crate::consts::*;
use crate::encrypt::EncryptedEnvelope;
use crate::envelope::{sig_structure, Headers, SignedEnvelope};
use crate::error::{ErrorCode, Rejection};
use crate::keys::{sha256, AgentId, Identity, PublicBundle};
use crate::log::{CheckpointUsed, InclusionCheck};
use crate::srl::{self, SrlCache};
use crate::trust::{self, Rule, Step9Input, TrustPolicy, VerifiedClaim};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevocationReason {
    Retired,
    Compromised,
}

impl RevocationReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            RevocationReason::Retired => "retired",
            RevocationReason::Compromised => "compromised",
        }
    }
}

/// A directly supplied revocation entry naming an identity (spec section 8).
/// Entries from cached SRLs (`Policy::srls`) are consulted as well.
#[derive(Clone, Debug)]
pub struct Revocation {
    pub id: AgentId,
    pub reason: RevocationReason,
    pub revoked_at: i64,
}

/// Verifier inputs besides the envelope and the clock.
pub struct Policy<'a> {
    /// Recipient identity, needed to open tag 96 envelopes.
    pub recipient: Option<&'a Identity>,
    /// Cached public bundles, consulted when the envelope carries none.
    pub known_bundles: Vec<PublicBundle>,
    /// Nonces already seen (step 6). Empty means no replay information.
    pub seen_nonces: Vec<[u8; 16]>,
    /// Cached revocation entries for identities (step 8).
    pub revocations: Vec<Revocation>,
    /// Payload supplied out of band when the envelope payload is nil.
    pub detached_payload: Option<Vec<u8>>,
    /// Allowed future skew for issued-at, seconds.
    pub max_skew_secs: i64,
    /// Trust policy for step 9: roots, rules, depth, revocation freshness,
    /// inclusion proofs, ATEP-R. `None` skips step 9.
    pub trust: Option<TrustPolicy>,
    /// Extra attestations (encoded envelopes) the verifier knows about, in
    /// addition to the ones inline in the envelope (`-70009`).
    pub attestations: Vec<Vec<u8>>,
    /// Cached SRLs: feed step 8 and the per-attestation revocation checks.
    pub srls: Option<&'a dyn SrlCache>,
    /// Inclusion proof checker. When `None` and the policy requires proofs,
    /// the offline checker over `trust.trusted_logs` is used.
    pub inclusion: Option<&'a dyn InclusionCheck>,
}

impl Default for Policy<'_> {
    fn default() -> Self {
        Policy {
            recipient: None,
            known_bundles: Vec::new(),
            seen_nonces: Vec::new(),
            revocations: Vec::new(),
            detached_payload: None,
            max_skew_secs: DEFAULT_SKEW_SECS,
            trust: None,
            attestations: Vec::new(),
            srls: None,
            inclusion: None,
        }
    }
}

/// Positive result (step 10).
#[derive(Clone, Debug)]
pub struct Verified {
    pub signer: AgentId,
    pub content_type: String,
    pub issued_at: i64,
    pub expires_at: Option<i64>,
    pub nonce: [u8; 16],
    pub encrypted: bool,
    /// The claims that satisfied the policy, one per rule.
    pub claims: Vec<VerifiedClaim>,
    /// The log checkpoint relied on, if inclusion proofs were checked.
    pub checkpoint: Option<CheckpointUsed>,
    /// Command class of an ATEP-R envelope (header -70014), if present.
    pub command_class: Option<String>,
    /// Fail-open conditions that were tolerated (stale or missing SRLs).
    pub warnings: Vec<String>,
    pub payload: Vec<u8>,
}

fn r(step: u8, code: ErrorCode, d: impl Into<String>) -> Rejection {
    Rejection::new(step, code, d)
}

fn check_signature_shape(env: &SignedEnvelope) -> Result<(), Rejection> {
    if env.signatures.len() != 2 {
        return Err(r(
            1,
            ErrorCode::SignatureCountInvalid,
            format!(
                "ATEP-1 requires exactly two signatures, found {}",
                env.signatures.len()
            ),
        ));
    }
    let has = |alg: i64| env.signatures.iter().filter(|s| s.alg == alg).count() == 1;
    if !(has(ALG_EDDSA) && has(ALG_MLDSA65)) {
        return Err(r(
            1,
            ErrorCode::AlgorithmSuiteMismatch,
            "signatures must be one EdDSA and one ML-DSA-65 under ATEP-1",
        ));
    }
    Ok(())
}

/// Verify an ATEP envelope. `now` is Unix seconds.
pub fn verify(data: &[u8], policy: &Policy, now: i64) -> Result<Verified, Rejection> {
    verify_core(data, policy, now, false)
}

/// What steps 1 to 7 leave behind for the later steps.
struct Decoded {
    env: SignedEnvelope,
    encrypted: bool,
    bundle: PublicBundle,
    payload: Vec<u8>,
}

/// `verify` with one extra switch used when evaluating attestations for an
/// ATEP-R e-stop: `relax_expiry` skips the `expires-at` comparison of step 5.
pub(crate) fn verify_core(
    data: &[u8],
    policy: &Policy,
    now: i64,
    relax_expiry: bool,
) -> Result<Verified, Rejection> {
    let Decoded {
        env,
        encrypted,
        bundle,
        payload,
    } = steps_1_to_7(data, policy, now, relax_expiry)?;
    let h = &env.headers;
    let atep_r_on = policy.trust.as_ref().is_some_and(|t| t.atep_r);

    // Step 8: signer status.
    let signer = AgentId(h.signer);
    step_8(policy, &bundle, &signer, h, &payload, now)?;

    // Step 9: policy evaluation.
    let mut claims = Vec::new();
    let mut checkpoint: Option<CheckpointUsed> = None;
    let mut warnings: Vec<String> = Vec::new();
    if let Some(tp) = &policy.trust {
        tp.check_anchor_rules()?;
        let inline: Vec<Vec<u8>> = match &env.attestations {
            Some(Value::Array(a)) => a.iter().map(|v| v.encode()).collect(),
            _ => Vec::new(),
        };
        let mut run = |requirements: Vec<Vec<Vec<Rule>>>, relax: bool, srl: srl::SrlPolicy| {
            if requirements.is_empty() {
                return Ok(());
            }
            let out = trust::evaluate(
                policy,
                tp,
                Step9Input {
                    signer,
                    inline: inline.clone(),
                    requirements,
                    relax_expiry: relax,
                    srl,
                },
                now,
            )?;
            claims.extend(out.claims);
            checkpoint = match (checkpoint.take(), out.checkpoint) {
                (Some(a), Some(b)) => {
                    Some(if (b.timestamp, b.tree_size) > (a.timestamp, a.tree_size) {
                        b
                    } else {
                        a
                    })
                }
                (a, b) => a.or(b),
            };
            for w in out.warnings {
                if !warnings.contains(&w) {
                    warnings.push(w);
                }
            }
            Ok::<(), Rejection>(())
        };
        run(
            tp.rules.iter().map(|x| vec![vec![x.clone()]]).collect(),
            false,
            tp.srl,
        )?;
        if atep_r_on {
            // Presence and validity of the class were checked at step 1.
            let class = CommandClass::parse(h.command_class.as_deref().unwrap_or(""))
                .expect("checked at step 1");
            let estop = class == CommandClass::Safety && atep_r::is_estop(&payload);
            let local = policy.recipient.map(|i| i.agent_id());
            let req = atep_r::requirements(class, estop, local);
            run(vec![req.groups], req.relax_expiry, req.srl)?;
        }
    }

    // Step 10: return.
    Ok(Verified {
        signer,
        content_type: h.content_type.clone(),
        issued_at: h.issued_at,
        expires_at: h.expires_at,
        nonce: h.nonce,
        encrypted,
        claims,
        checkpoint,
        command_class: h.command_class.clone(),
        warnings,
        payload,
    })
}

/// Steps 1 to 7 of section 10: decode, decrypt, resolve the signer, verify
/// both signatures, check time, replay and the payload digest.
fn steps_1_to_7(
    data: &[u8],
    policy: &Policy,
    now: i64,
    relax_expiry: bool,
) -> Result<Decoded, Rejection> {
    // Step 1: decode.
    let v = Value::decode(data).map_err(|e| r(1, ErrorCode::MalformedCbor, e.to_string()))?;
    let (env, encrypted) = match &v {
        Value::Tag(t, _) if *t == TAG_COSE_ENCRYPT => {
            let outer = EncryptedEnvelope::from_value(&v)?;
            // Step 2: decrypt.
            let recipient = policy.recipient.ok_or_else(|| {
                r(
                    2,
                    ErrorCode::NoRecipientKey,
                    "envelope is encrypted but no recipient identity was provided",
                )
            })?;
            let inner_bytes = outer.decrypt(recipient)?;
            let iv = Value::decode(&inner_bytes)
                .map_err(|e| r(1, ErrorCode::MalformedCbor, format!("inner envelope: {e}")))?;
            (SignedEnvelope::from_value(&iv)?, true)
        }
        _ => (SignedEnvelope::from_value(&v)?, false),
    };
    check_signature_shape(&env)?;
    let h = &env.headers;
    if h.content_type == CT_ATTESTATION && h.expires_at.is_none() {
        return Err(r(
            1,
            ErrorCode::MissingExpiresAt,
            "expires-at is REQUIRED for attestations",
        ));
    }
    if !encrypted && !is_trust_document(&h.content_type) {
        return Err(r(
            1,
            ErrorCode::UnencryptedNonTrustDocument,
            format!(
                "content type `{}` must be encrypted; only trust documents may be signed-only",
                h.content_type
            ),
        ));
    }

    let atep_r_on = policy.trust.as_ref().is_some_and(|t| t.atep_r);
    if atep_r_on {
        if !encrypted {
            return Err(r(
                1,
                ErrorCode::AtepRUnencrypted,
                "ATEP-R envelopes MUST be sign-then-encrypt",
            ));
        }
        match h.command_class.as_deref() {
            None => {
                return Err(r(
                    1,
                    ErrorCode::MissingCommandClass,
                    "command-class (-70014) is REQUIRED in ATEP-R envelopes",
                ))
            }
            Some(c) if CommandClass::parse(c).is_none() => {
                return Err(r(
                    1,
                    ErrorCode::UnknownCommandClass,
                    format!("`{c}` is not an ATEP-R command class"),
                ))
            }
            Some(_) => {}
        }
    }

    // Step 3: resolve the signer.
    let bundle = match &env.signer_bundle {
        Some(bv) => {
            PublicBundle::from_value(bv).map_err(|e| r(3, ErrorCode::SignerBundleInvalid, e.0))?
        }
        None => policy
            .known_bundles
            .iter()
            .find(|b| b.agent_id().0 == h.signer)
            .cloned()
            .ok_or_else(|| {
                r(
                    3,
                    ErrorCode::SignerBundleUnavailable,
                    "no inline bundle and signer not in cache",
                )
            })?,
    };
    if bundle.agent_id().0 != h.signer {
        return Err(r(
            3,
            ErrorCode::SignerIdMismatch,
            "SHA-256 of the signer bundle does not equal the signer header",
        ));
    }
    if env.signatures.iter().any(|s| s.kid != h.signer) {
        return Err(r(
            3,
            ErrorCode::KidMismatch,
            "a signature kid does not equal the signer header",
        ));
    }

    // Step 4: both signatures over the same payload.
    let payload: Vec<u8> = match (&env.payload, &policy.detached_payload) {
        (Some(p), _) => p.clone(),
        (None, Some(p)) => p.clone(),
        (None, None) => {
            return Err(r(
                4,
                ErrorCode::DetachedPayloadMissing,
                "payload is detached and none was supplied",
            ))
        }
    };
    for alg in [ALG_EDDSA, ALG_MLDSA65] {
        let s = env.signatures.iter().find(|s| s.alg == alg).unwrap();
        let msg = sig_structure(&env.body_protected_raw, &s.protected_raw, &payload);
        let ok = if alg == ALG_EDDSA {
            bundle.verify_ed25519(&msg, &s.signature)
        } else {
            bundle.verify_mldsa65(&msg, &s.signature)
        };
        if !ok {
            let code = if alg == ALG_EDDSA {
                ErrorCode::EddsaSignatureInvalid
            } else {
                ErrorCode::MldsaSignatureInvalid
            };
            return Err(r(4, code, "signature does not verify"));
        }
    }

    // Step 5: time.
    if h.issued_at > now.saturating_add(policy.max_skew_secs) {
        return Err(r(
            5,
            ErrorCode::IssuedInFuture,
            format!(
                "issued-at {} is more than {} s after now {}",
                h.issued_at, policy.max_skew_secs, now
            ),
        ));
    }
    if let Some(e) = h.expires_at {
        if e <= now && !relax_expiry {
            return Err(r(
                5,
                ErrorCode::Expired,
                format!("expires-at {e} is not later than now {now}"),
            ));
        }
    }

    // Step 6: replay.
    if policy.seen_nonces.contains(&h.nonce) {
        return Err(r(6, ErrorCode::NonceReplayed, "nonce was already seen"));
    }

    // Step 7: payload digest.
    if sha256(&payload) != h.payload_digest {
        return Err(r(
            7,
            ErrorCode::PayloadDigestMismatch,
            "SHA-256 of the payload does not equal payload-digest",
        ));
    }

    Ok(Decoded {
        env,
        encrypted,
        bundle,
        payload,
    })
}

/// Step 8: the signer MUST NOT be revoked as of `issued-at` (spec section 10).
/// Revoked means: a 32 byte identity entry in a cached SRL or a directly
/// supplied entry with `revoked-at` at or before `issued-at`, whatever its
/// reason, or a valid retirement in the local attestation store whose
/// `issued-at` is at or before this envelope's, unless this envelope is itself
/// a `retired` attestation of the signer. The sources are a union, so the
/// effective instant is the earliest.
fn step_8(
    policy: &Policy,
    signer_bundle: &PublicBundle,
    signer: &AgentId,
    h: &Headers,
    payload: &[u8],
    now: i64,
) -> Result<(), Rejection> {
    if let Some(cache) = policy.srls {
        if let Some((from, e)) = srl::identity_revoked(cache, signer, h.issued_at) {
            return Err(r(
                8,
                ErrorCode::SignerRevoked,
                format!(
                    "signer is listed as {} since {} in the SRL of {from}",
                    e.reason, e.revoked_at
                ),
            ));
        }
    }
    if let Some(rev) = policy
        .revocations
        .iter()
        .find(|x| x.id == *signer && x.revoked_at <= h.issued_at)
    {
        return Err(r(
            8,
            ErrorCode::SignerRevoked,
            format!(
                "signer is listed as {} since {}",
                rev.reason.as_str(),
                rev.revoked_at
            ),
        ));
    }
    let exempt = h.content_type == CT_ATTESTATION && is_retirement_payload(payload, signer);
    if !exempt {
        if let Some(at) = retired_as_of(policy, signer_bundle, signer, h.issued_at, now) {
            return Err(r(
                8,
                ErrorCode::SignerRevoked,
                format!(
                    "signer retired at {at}, at or before issued-at {}",
                    h.issued_at
                ),
            ));
        }
    }
    Ok(())
}

/// Loose reading of a payload: claim `retired` with `subject` and `issuer`
/// both `who`. Used for the exemption of step 8 and to pick store entries
/// worth validating.
fn is_retirement_payload(payload: &[u8], who: &AgentId) -> bool {
    let Ok(v) = Value::decode(payload) else {
        return false;
    };
    let Some(m) = v.as_map() else {
        return false;
    };
    let get = |k: &str| {
        m.iter()
            .find(|(key, _)| key.as_text() == Some(k))
            .map(|(_, v)| v)
    };
    get("claim").and_then(|c| c.as_text()) == Some(crate::attestation::claims::RETIRED)
        && get("subject").and_then(|c| c.as_bytes()) == Some(&who.0[..])
        && get("issuer").and_then(|c| c.as_bytes()) == Some(&who.0[..])
}

/// The earliest `issued-at` of a valid retirement of `who` in the local
/// attestation store, provided it is at or before `issued_at`.
fn retired_as_of(
    policy: &Policy,
    signer_bundle: &PublicBundle,
    who: &AgentId,
    issued_at: i64,
    now: i64,
) -> Option<i64> {
    let mut best: Option<i64> = None;
    for raw in &policy.attestations {
        if let Some(at) = valid_retirement(raw, policy, signer_bundle, who, now) {
            if at <= issued_at && best.is_none_or(|b| at < b) {
                best = Some(at);
            }
        }
    }
    best
}

/// Is `raw` a valid retirement of `who` (spec section 7): signed by `who`,
/// claim `retired` with `subject` and `issuer` both `who`, passing steps 1 to 7
/// as an unencrypted envelope with the expiry not compared and replay checking
/// off, the attestation schema and rules, and the 400 day limit. Returns its
/// `issued-at`. Anything else in the store is silently ignored here. The
/// bundle of `who` is the inline one, a cached one, or `signer_bundle`, the
/// bundle resolved for the envelope under verification (same signer).
pub(crate) fn valid_retirement(
    raw: &[u8],
    policy: &Policy,
    signer_bundle: &PublicBundle,
    who: &AgentId,
    now: i64,
) -> Option<i64> {
    // Cheap loose checks first, so that only retirements of `who` cost a
    // signature verification.
    let env = SignedEnvelope::decode(raw).ok()?;
    if env.headers.signer != who.0 || env.headers.content_type != CT_ATTESTATION {
        return None;
    }
    if !is_retirement_payload(env.payload.as_deref()?, who) {
        return None;
    }
    let mut known = policy.known_bundles.clone();
    known.push(signer_bundle.clone());
    let sub = Policy {
        known_bundles: known,
        max_skew_secs: policy.max_skew_secs,
        ..Policy::default()
    };
    let d = steps_1_to_7(raw, &sub, now, true).ok()?;
    if d.encrypted || d.bundle.agent_id() != *who {
        return None;
    }
    let att = Attestation::from_payload(&d.payload).ok()?;
    att.validate_claim_data().ok()?;
    if att.claim != crate::attestation::claims::RETIRED || att.subject != *who || att.issuer != *who
    {
        return None;
    }
    let h = &d.env.headers;
    if h.expires_at? - h.issued_at > MAX_ATTESTATION_LIFETIME_SECS {
        return None;
    }
    Some(h.issued_at)
}
