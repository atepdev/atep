//! Typed monitor alerts.

use atep_core::keys::AgentId;
use atep_log::gossip::SplitEvidence;
use serde_json::{json, Value as J};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Alert {
    /// A `domain-control` attestation for a watched domain names a subject the
    /// monitor did not authorize.
    UnauthorizedDomainControl {
        entry: u64,
        domain: String,
        watched: String,
        subject: AgentId,
        issuer: AgentId,
    },
    /// An issuer issued a claim type outside its delegated `issuer-authority`
    /// (or handed on authority it does not hold).
    IssuerOutsideAuthority {
        entry: u64,
        issuer: AgentId,
        claim: String,
        subject: AgentId,
        reason: String,
    },
    /// Strict mode: an issuer with no delegation at all and not a root.
    UndelegatedIssuer {
        entry: u64,
        issuer: AgentId,
        claim: String,
    },
    /// A logged `successor` attestation whose issuer is itself the subject of
    /// another logged `successor` attestation: succession spans two or more
    /// hops, and a verifier follows one (spec section 7). `entry` is the later
    /// link of the chain.
    SuccessorChain {
        entry: u64,
        issuer: AgentId,
        subject: AgentId,
    },
    /// A newer checkpoint is not an extension of an older one: failed
    /// consistency proof.
    InconsistentCheckpoint {
        from: u64,
        to: u64,
        detail: String,
        /// `{a, b, proof}` document: the two signed checkpoints and the proof.
        evidence: Vec<u8>,
    },
    /// The log did not supply what is needed to check a step of the history.
    CheckpointGap { from: u64, to: u64, detail: String },
    /// A later checkpoint has a smaller tree.
    TreeShrank { from: u64, to: u64 },
    /// The entries served do not reproduce the signed root.
    EntryRootMismatch { tree_size: u64, detail: String },
    /// The log did not return entries it committed to.
    EntryGap { from: u64, to: u64, detail: String },
    /// A logged entry fails verification or does not parse.
    EntryInvalid { entry: u64, detail: String },
    /// A checkpoint failed verification or comes from the wrong log.
    BadCheckpoint { detail: String },
    /// Two signed checkpoints of one log that cannot share a history.
    SplitView {
        log: AgentId,
        reason: String,
        /// `{a, b, proof?}` document of the evidence (CBOR).
        evidence: Vec<u8>,
    },
    /// The log could not be reached.
    SourceUnavailable { detail: String },
}

impl Alert {
    pub fn split(ev: &SplitEvidence) -> Alert {
        Alert::SplitView {
            log: ev.log,
            reason: ev.reason.clone(),
            evidence: ev.to_pair_cbor(),
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Alert::UnauthorizedDomainControl { .. } => "unauthorized_domain_control",
            Alert::IssuerOutsideAuthority { .. } => "issuer_outside_authority",
            Alert::UndelegatedIssuer { .. } => "undelegated_issuer",
            Alert::SuccessorChain { .. } => "successor_chain",
            Alert::InconsistentCheckpoint { .. } => "inconsistent_checkpoint",
            Alert::CheckpointGap { .. } => "checkpoint_gap",
            Alert::TreeShrank { .. } => "tree_shrank",
            Alert::EntryRootMismatch { .. } => "entry_root_mismatch",
            Alert::EntryGap { .. } => "entry_gap",
            Alert::EntryInvalid { .. } => "entry_invalid",
            Alert::BadCheckpoint { .. } => "bad_checkpoint",
            Alert::SplitView { .. } => "split_view",
            Alert::SourceUnavailable { .. } => "source_unavailable",
        }
    }

    /// Entry index the alert is about, if any.
    pub fn entry(&self) -> Option<u64> {
        match self {
            Alert::UnauthorizedDomainControl { entry, .. }
            | Alert::IssuerOutsideAuthority { entry, .. }
            | Alert::UndelegatedIssuer { entry, .. }
            | Alert::SuccessorChain { entry, .. }
            | Alert::EntryInvalid { entry, .. } => Some(*entry),
            _ => None,
        }
    }

    /// Stable identity used to report each finding once.
    pub fn key(&self) -> String {
        match self {
            Alert::SourceUnavailable { .. } => self.kind().to_string(),
            Alert::SplitView { evidence, .. } => {
                format!(
                    "split:{}",
                    atep_core::keys::sha256(evidence)
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                )
            }
            Alert::UnauthorizedDomainControl { entry, watched, .. } => {
                format!("{}:{entry}:{watched}", self.kind())
            }
            _ => format!("{}:{}", self.kind(), self.to_json()),
        }
    }

    pub fn to_json(&self) -> J {
        let mut j = match self {
            Alert::UnauthorizedDomainControl {
                entry,
                domain,
                watched,
                subject,
                issuer,
            } => json!({
                "entry": entry, "domain": domain, "watched-domain": watched,
                "subject": subject.to_text(), "issuer": issuer.to_text(),
            }),
            Alert::IssuerOutsideAuthority {
                entry,
                issuer,
                claim,
                subject,
                reason,
            } => json!({
                "entry": entry, "issuer": issuer.to_text(), "claim": claim,
                "subject": subject.to_text(), "reason": reason,
            }),
            Alert::UndelegatedIssuer {
                entry,
                issuer,
                claim,
            } => json!({
                "entry": entry, "issuer": issuer.to_text(), "claim": claim,
            }),
            Alert::SuccessorChain {
                entry,
                issuer,
                subject,
            } => json!({
                "entry": entry, "issuer": issuer.to_text(), "subject": subject.to_text(),
            }),
            Alert::InconsistentCheckpoint {
                from,
                to,
                detail,
                evidence,
            } => json!({
                "from": from, "to": to, "detail": detail, "evidence": base64_url(evidence),
            }),
            Alert::CheckpointGap { from, to, detail } => json!({
                "from": from, "to": to, "detail": detail,
            }),
            Alert::TreeShrank { from, to } => json!({ "from": from, "to": to }),
            Alert::EntryRootMismatch { tree_size, detail } => json!({
                "tree-size": tree_size, "detail": detail,
            }),
            Alert::EntryGap { from, to, detail } => json!({
                "from": from, "to": to, "detail": detail,
            }),
            Alert::EntryInvalid { entry, detail } => json!({ "entry": entry, "detail": detail }),
            Alert::BadCheckpoint { detail } => json!({ "detail": detail }),
            Alert::SplitView {
                log,
                reason,
                evidence,
            } => json!({
                "log": log.to_text(), "reason": reason,
                "evidence": base64_url(evidence),
            }),
            Alert::SourceUnavailable { detail } => json!({ "detail": detail }),
        };
        j["alert"] = json!(self.kind());
        j
    }
}

fn base64_url(b: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(b)
}

impl std::fmt::Display for Alert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let j = self.to_json();
        let mut parts = Vec::new();
        if let Some(o) = j.as_object() {
            for (k, v) in o {
                if k == "alert" || k == "evidence" {
                    continue;
                }
                let s = match v {
                    J::String(s) => s.clone(),
                    other => other.to_string(),
                };
                parts.push(format!("{k}={s}"));
            }
        }
        write!(f, "ALERT {}: {}", self.kind(), parts.join(" "))
    }
}
