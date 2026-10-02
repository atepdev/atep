//! Log admission rules (spec section 9, "Admission"): what a transparency log
//! checks before it appends an attestation or an SRL. The engine lives here so
//! that the reference log (`atep-log`) and the vector checker run the same
//! code; the claim-specific extras of a particular log are a [`ClaimRules`]
//! hook.
//!
//! An accepted submission passes verification steps 1 to 8 (with the signer
//! bundle inline or already known to the log, the identity entries of the
//! logged SRLs as revocations and the logged `retired` attestations as the
//! local attestation store), the payload schema of its media type, the 400 day
//! lifetime limit and the claim rules. Whether a claim is *authorized* (issuer
//! delegation) is not the log's business: no issuer is trusted by the
//! protocol, monitors judge that.

use std::collections::HashMap;

use crate::attestation::{check_lifetime, claims, Attestation};
use crate::cbor::Value;
use crate::consts::*;
use crate::envelope::{submitted_form, SignedEnvelope};
use crate::error::Rejection;
use crate::keys::{AgentId, PublicBundle};
use crate::log::hash_leaf;
use crate::srl::{RevokedId, Srl};
use crate::verify::{verify, Policy, Revocation, RevocationReason};

pub type BundleMap = HashMap<AgentId, PublicBundle>;

/// Why a submission was refused: a stable `code`, a human `detail` and, for a
/// failed verification, the underlying rejection.
#[derive(Debug, Clone)]
pub struct SubmitError {
    pub code: &'static str,
    pub detail: String,
    pub rejection: Option<Rejection>,
}

impl SubmitError {
    pub fn new(code: &'static str, detail: impl Into<String>) -> SubmitError {
        SubmitError {
            code,
            detail: detail.into(),
            rejection: None,
        }
    }

    fn from_rejection(code: &'static str, r: Rejection) -> SubmitError {
        SubmitError {
            code,
            detail: r.to_string(),
            rejection: Some(r),
        }
    }
}

impl std::fmt::Display for SubmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for SubmitError {}

/// The parsed document of an accepted submission.
#[derive(Debug, Clone)]
pub enum Doc {
    Attestation(Attestation),
    Srl(Srl),
}

/// An accepted submission, ready to append.
#[derive(Debug, Clone)]
pub struct Admitted {
    /// The envelope without its `-70012` header: the bytes that are hashed.
    pub submitted: Vec<u8>,
    pub leaf: [u8; 32],
    pub issuer: AgentId,
    pub issued_at: i64,
    pub expires_at: Option<i64>,
    pub bundle: Option<PublicBundle>,
    pub doc: Doc,
}

/// State the admission rules look at.
pub struct Context<'a> {
    pub log_id: AgentId,
    pub bundles: &'a BundleMap,
    /// Identity entries of the SRLs already logged (step 8).
    pub revocations: &'a [Revocation],
    /// The `retired` attestations already logged, in their submitted form: the
    /// local attestation store of step 8 (spec section 7).
    pub retirements: &'a [Vec<u8>],
    /// Highest SRL sequence logged per issuer.
    pub srl_sequences: &'a HashMap<AgentId, i64>,
    pub max_envelope_bytes: usize,
}

/// Claim-specific admission rules that run after the generic attestation
/// checks, in the order: vocabulary, then the layouts the log enforces.
pub trait ClaimRules {
    fn check(&self, att: &Attestation, cx: &Context) -> Result<(), SubmitError>;
}

/// The rules every log applies: the reserved namespace is closed to the 14
/// core claim types, `domain-control` carries a canonical `data.domain` and
/// `registry-endpoint` carries a valid `data.url` and `data.kind` (spec
/// sections 7 and 9).
pub struct CoreClaimRules;

impl ClaimRules for CoreClaimRules {
    fn check(&self, att: &Attestation, _cx: &Context) -> Result<(), SubmitError> {
        if att.claim.starts_with(claims::NS) && !is_core_claim(&att.claim) {
            return Err(vocabulary_error(&att.claim));
        }
        check_registry_endpoint_claim(att)?;
        check_domain_control(att)
    }
}

/// Endpoint kinds of `registry-endpoint` (extension names start with `x-`).
pub const ENDPOINT_KINDS: [&str; 4] = ["registry", "verifier", "mcp", "a2a"];

/// Longest `registry-endpoint` URL, characters.
pub const MAX_ENDPOINT_URL: usize = 2048;

/// `registry-endpoint` needs `data.url` and `data.kind` as spec section 7
/// defines them; a violation is `schema_invalid` at a log.
pub fn check_registry_endpoint_claim(att: &Attestation) -> Result<(), SubmitError> {
    if att.claim == claims::REGISTRY_ENDPOINT {
        check_registry_endpoint(att).map_err(|m| SubmitError::new("schema_invalid", m))?;
    }
    Ok(())
}

/// Check the `data` of a `registry-endpoint` attestation: `url` is an `https`
/// URL and `kind` a known kind or an `x-` extension.
pub fn check_registry_endpoint(att: &Attestation) -> Result<(), String> {
    let url = att
        .data_get("url")
        .and_then(|v| v.as_text())
        .ok_or("registry-endpoint needs `data.url`, an https URL")?;
    if !valid_https_url(url) {
        return Err("`data.url` must be an https URL of at most 2048 characters with a host, no credentials and no whitespace".into());
    }
    let kind = att
        .data_get("kind")
        .and_then(|v| v.as_text())
        .ok_or("registry-endpoint needs `data.kind`")?;
    if !valid_kind(kind) {
        return Err(format!(
            "`data.kind` must be one of {} or an extension `x-<name>`",
            ENDPOINT_KINDS.join(", ")
        ));
    }
    Ok(())
}

/// `registry`, `verifier`, `mcp`, `a2a`, or `x-` followed by one or more
/// lowercase letters, digits and hyphens.
pub fn valid_kind(kind: &str) -> bool {
    ENDPOINT_KINDS.contains(&kind)
        || kind.strip_prefix("x-").is_some_and(|r| {
            !r.is_empty()
                && r.bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
}

/// An `https` URL of at most [`MAX_ENDPOINT_URL`] characters with a host, no
/// credentials and no whitespace or control characters.
pub fn valid_https_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    if url.chars().count() > MAX_ENDPOINT_URL || url.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return false;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    !authority.is_empty() && !authority.contains('@') && !authority.starts_with(':')
}

pub fn vocabulary_error(claim: &str) -> SubmitError {
    SubmitError::new(
        "claim_vocabulary",
        format!(
            "`{claim}` is not a claim type of the core namespace {}; use your own namespace",
            claims::NS
        ),
    )
}

/// `domain-control` needs `data.domain`, a canonical lowercase DNS name.
pub fn check_domain_control(att: &Attestation) -> Result<(), SubmitError> {
    if att.claim == claims::DOMAIN_CONTROL {
        match domain_of(att) {
            Some(d) if valid_domain(d) => {}
            _ => {
                return Err(SubmitError::new(
                    "schema_invalid",
                    "domain-control needs `data.domain`, a lowercase DNS name",
                ))
            }
        }
    }
    Ok(())
}

/// A plausible canonical DNS name: lowercase letters, digits and hyphens in
/// labels of 1 to 63 characters, at most 253 characters, no trailing dot.
pub fn valid_domain(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 253
        && d.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
}

/// The domain a `domain-control` attestation names (`data.domain`).
pub fn domain_of(att: &Attestation) -> Option<&str> {
    att.data_get("domain")?.as_text()
}

/// Claim types the core namespace admits.
pub fn is_core_claim(claim: &str) -> bool {
    claims::CORE.contains(&claim) || claims::robotics::ALL.contains(&claim)
}

fn lifted(r: Rejection) -> SubmitError {
    SubmitError::from_rejection("verification_failed", r)
}

/// Validate a submission at time `now`.
pub fn check(
    raw: &[u8],
    cx: &Context,
    rules: &dyn ClaimRules,
    now: i64,
) -> Result<Admitted, SubmitError> {
    if raw.len() > cx.max_envelope_bytes {
        return Err(SubmitError::new(
            "too_large",
            format!(
                "envelope is {} bytes, the log accepts at most {}",
                raw.len(),
                cx.max_envelope_bytes
            ),
        ));
    }
    let top = Value::decode(raw).map_err(|e| {
        SubmitError::new("malformed", format!("not strict deterministic CBOR: {e}"))
    })?;
    match &top {
        Value::Tag(TAG_COSE_ENCRYPT, _) => {
            return Err(SubmitError::new(
                "encrypted_envelope",
                "encrypted envelopes are exchanged between agents and are never logged (spec section 16 point 5)",
            ))
        }
        Value::Tag(TAG_COSE_SIGN, _) => {}
        _ => {
            return Err(SubmitError::new(
                "malformed",
                "expected a COSE_Sign envelope (tag 98)",
            ))
        }
    }
    let env = SignedEnvelope::decode(raw).map_err(lifted)?;
    let ct = env.headers.content_type.as_str();
    match ct {
        CT_ATTESTATION | CT_SRL => {}
        CT_CHECKPOINT => {
            return Err(SubmitError::new(
                "content_type_not_loggable",
                "checkpoints are issued by the log itself and are not logged",
            ))
        }
        other => {
            return Err(SubmitError::new(
                "data_envelope",
                format!(
                    "content type `{other}` is not a trust document; data envelopes are never logged (spec section 16 point 5)"
                ),
            ))
        }
    }
    let submitted = submitted_form(raw)
        .map_err(|e| SubmitError::new("malformed", format!("cannot normalize envelope: {e}")))?;
    let policy = Policy {
        known_bundles: cx.bundles.values().cloned().collect(),
        revocations: cx.revocations.to_vec(),
        attestations: cx.retirements.to_vec(),
        ..Policy::default()
    };
    let v = verify(&submitted, &policy, now).map_err(lifted)?;
    let bundle =
        match &env.signer_bundle {
            Some(b) => Some(PublicBundle::from_value(b).map_err(|e| {
                SubmitError::new("verification_failed", format!("signer bundle: {e}"))
            })?),
            None => None,
        };
    let leaf = hash_leaf(&submitted);
    let doc = if ct == CT_ATTESTATION {
        let att = Attestation::from_payload(&v.payload)
            .map_err(|e| SubmitError::new("schema_invalid", e.0))?;
        att.validate_claim_data()
            .map_err(|e| SubmitError::new("schema_invalid", e.0))?;
        if att.issuer != v.signer {
            return Err(SubmitError::new(
                "schema_invalid",
                "attestation `issuer` does not equal the envelope signer",
            ));
        }
        let expires = v
            .expires_at
            .ok_or_else(|| SubmitError::new("schema_invalid", "attestation has no expires-at"))?;
        check_lifetime(
            &att.claim,
            att.evidence.is_some(),
            expires - v.issued_at,
            false,
        )
        .map_err(|m| SubmitError::new("lifetime_exceeded", m))?;
        rules.check(&att, cx)?;
        Doc::Attestation(att)
    } else {
        let srl =
            Srl::from_payload(&v.payload).map_err(|e| SubmitError::new("schema_invalid", e.0))?;
        if srl.issuer != v.signer {
            return Err(SubmitError::new(
                "schema_invalid",
                "SRL `issuer` does not equal the envelope signer",
            ));
        }
        if let Some(prev) = cx.srl_sequences.get(&srl.issuer) {
            if srl.sequence <= *prev {
                return Err(SubmitError::new(
                    "srl_rollback",
                    format!(
                        "SRL sequence {} is not above the logged sequence {prev} of this issuer",
                        srl.sequence
                    ),
                ));
            }
        }
        Doc::Srl(srl)
    };
    Ok(Admitted {
        submitted,
        leaf,
        issuer: v.signer,
        issued_at: v.issued_at,
        expires_at: v.expires_at,
        bundle,
        doc,
    })
}

/// Identity entries of an SRL as step 8 revocations (every identity entry
/// counts, spec section 8).
pub fn revocations_of(srl: &Srl) -> Vec<Revocation> {
    srl.revoked
        .iter()
        .filter_map(|e| match &e.id {
            RevokedId::Identity(id) => Some(Revocation {
                id: *id,
                reason: if e.reason == "retired" {
                    RevocationReason::Retired
                } else {
                    RevocationReason::Compromised
                },
                revoked_at: e.revoked_at,
            }),
            _ => None,
        })
        .collect()
}

/// A stateful reference log for the vector checker: an ordered list of what
/// has been admitted, from which the admission context is derived exactly as
/// `atep-log` derives it.
#[derive(Default)]
pub struct AdmissionState {
    pub bundles: BundleMap,
    pub revocations: Vec<Revocation>,
    pub retirements: Vec<Vec<u8>>,
    pub srl_sequences: HashMap<AgentId, i64>,
    pub leaves: Vec<[u8; 32]>,
}

impl AdmissionState {
    /// Admit `raw` at `now` and, when accepted, record it. A repeat of a
    /// logged document is answered as a duplicate before any validation.
    pub fn submit(
        &mut self,
        raw: &[u8],
        log_id: AgentId,
        rules: &dyn ClaimRules,
        max_envelope_bytes: usize,
        now: i64,
    ) -> Result<Admitted, SubmitError> {
        let adm = {
            let cx = Context {
                log_id,
                bundles: &self.bundles,
                revocations: &self.revocations,
                retirements: &self.retirements,
                srl_sequences: &self.srl_sequences,
                max_envelope_bytes,
            };
            check(raw, &cx, rules, now)?
        };
        self.record(&adm);
        Ok(adm)
    }

    pub fn record(&mut self, adm: &Admitted) {
        if let Some(b) = &adm.bundle {
            self.bundles.entry(adm.issuer).or_insert_with(|| b.clone());
        }
        match &adm.doc {
            Doc::Srl(s) => {
                self.revocations.extend(revocations_of(s));
                self.srl_sequences.insert(s.issuer, s.sequence);
            }
            Doc::Attestation(a) => {
                if a.claim == claims::RETIRED {
                    self.retirements.push(adm.submitted.clone());
                }
            }
        }
        self.leaves.push(adm.leaf);
    }
}
