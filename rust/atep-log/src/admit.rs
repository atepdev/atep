//! Submission validation. The log accepts only public trust documents:
//! attestations and SRLs. It rejects encrypted envelopes and data envelopes
//! (spec section 16 point 5: envelopes exchanged between agents are never
//! logged) and checkpoints (the log writes those itself).
//!
//! An accepted submission passes verification steps 1 to 8 (with the signer
//! bundle inline or already known to the log), the payload schema of its media
//! type, the 400 day lifetime limit and the vocabulary rule for the core claim
//! namespace (14 claim types). Whether a claim is *authorized* (issuer delegation) is not the
//! log's business: no issuer is trusted by the protocol, monitors judge that.

use atep_core::admission::{
    check_domain_control, check_registry_endpoint_claim, vocabulary_error, ClaimRules,
    Context as CoreContext,
};
use atep_core::attestation::{claims, Attestation};
use atep_core::keys::AgentId;
use atep_core::verify::Revocation;

pub use atep_core::admission::{
    domain_of, is_core_claim, revocations_of, valid_domain, Admitted, BundleMap, Doc, SubmitError,
};

/// Claim type of the log policy entry, a self-issued attestation of the log.
/// Provisional (Rust finding 33).
pub const POLICY_CLAIM: &str = "https://atep.dev/log/policy";

/// State the admission rules look at.
pub struct Context<'a> {
    pub log_id: AgentId,
    pub bundles: &'a BundleMap,
    pub revocations: &'a [Revocation],
    /// The `retired` attestations already logged (submitted form): the local
    /// attestation store of step 8.
    pub retirements: &'a [Vec<u8>],
    /// Highest SRL sequence logged per issuer.
    pub srl_sequences: &'a std::collections::HashMap<AgentId, i64>,
    pub max_envelope_bytes: usize,
}

/// The reference log's claim rules: the closed core vocabulary of 14 claim
/// types, the `registry-endpoint` layout, `domain-control` and the log policy
/// claim.
pub struct LogClaimRules;

impl ClaimRules for LogClaimRules {
    fn check(&self, att: &Attestation, cx: &CoreContext) -> Result<(), SubmitError> {
        if att.claim.starts_with(claims::NS) && !is_core_claim(&att.claim) {
            return Err(vocabulary_error(&att.claim));
        }
        check_registry_endpoint_claim(att)?;
        check_domain_control(att)?;
        if att.claim == POLICY_CLAIM && att.issuer != cx.log_id {
            return Err(SubmitError::new(
                "claim_vocabulary",
                "only the log itself may issue log policy attestations",
            ));
        }
        Ok(())
    }
}

/// Validate a submission at time `now`.
pub fn check(raw: &[u8], cx: &Context, now: i64) -> Result<Admitted, SubmitError> {
    let core = CoreContext {
        log_id: cx.log_id,
        bundles: cx.bundles,
        revocations: cx.revocations,
        retirements: cx.retirements,
        srl_sequences: cx.srl_sequences,
        max_envelope_bytes: cx.max_envelope_bytes,
    };
    atep_core::admission::check(raw, &core, &LogClaimRules, now)
}
