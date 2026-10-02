//! The published log policy (spec section 9, "First log operator"): admission
//! rules, retention, availability, checkpoint cadence and key custody. It is
//! issued as a self-attestation of the log (subject and issuer are the log,
//! claim [`crate::POLICY_CLAIM`], the policy in `data`) so it can be the first
//! entry of the tree and carry an inclusion proof like any other document.

use atep_core::attestation::claims;
use atep_core::cbor::Value;
use atep_core::keys::AgentId;

/// Operator configuration. The strings are published verbatim in the policy.
#[derive(Clone, Debug)]
pub struct LogConfig {
    pub operator: String,
    /// A fresh checkpoint is issued at least this often (spec: hourly).
    pub checkpoint_interval_secs: i64,
    pub max_envelope_bytes: usize,
    pub retention: String,
    pub availability: String,
    pub key_custody: String,
    /// Lifetime of the policy attestation before it is re-issued.
    pub policy_lifetime_days: i64,
}

impl Default for LogConfig {
    fn default() -> Self {
        LogConfig {
            operator: "AIRAD LABS".into(),
            checkpoint_interval_secs: 3600,
            max_envelope_bytes: 64 * 1024,
            retention: "Entries are retained indefinitely and never deleted or rewritten.".into(),
            availability: "Reference deployment, best effort. No availability commitment.".into(),
            key_custody: "The log signing key is a hybrid Ed25519 and ML-DSA-65 identity held in a file readable only by the log process. Production operators should keep it in an HSM or a key service and rotate it with a successor attestation.".into(),
            policy_lifetime_days: 365,
        }
    }
}

fn t(s: &str) -> Value {
    Value::text(s)
}

fn texts(items: &[&str]) -> Value {
    Value::Array(items.iter().map(|s| Value::text(s)).collect())
}

/// The `data` map of the policy attestation. `core-claims` lists the 14 core
/// claim types of spec section 7: the seven core types (with
/// `registry-endpoint`) and the seven robotics types (`operator` is shared and
/// listed once).
pub fn policy_data(cfg: &LogConfig, log: &AgentId) -> Value {
    let mut core: Vec<&str> = claims::CORE.to_vec();
    core.extend(
        claims::robotics::ALL
            .iter()
            .filter(|c| **c != claims::OPERATOR),
    );
    Value::Map(vec![
        (t("version"), Value::Int(1)),
        (t("log"), t(&log.to_text())),
        (t("operator"), t(&cfg.operator)),
        (
            t("admission"),
            texts(&[
                "Only attestations (application/atep-attestation+cbor) and signed revocation lists (application/atep-srl+cbor) are accepted.",
                "Encrypted envelopes and data envelopes are never logged (spec section 16 point 5); checkpoints are written by the log only.",
                "A submission must pass verification steps 1 to 8 and the schema of its media type; the signer bundle must be inline or already logged.",
                "Claim types under https://atep.dev/claims/ must belong to the core vocabulary of 14 claim types; claim types in other namespaces are open.",
                "An attestation may not live longer than 400 days; domain-control needs data.domain, a lowercase DNS name; registry-endpoint needs data.url (an https URL) and data.kind.",
                "SRL sequence numbers must increase per issuer.",
                "Subjects are agents and organizations, never natural persons (spec section 16 point 1); this is operator policy, enforced through the closed core vocabulary and review.",
                "Duplicates are accepted idempotently and return the existing inclusion proof.",
                "The log makes no judgement of issuer authority; monitors do (spec section 9).",
            ]),
        ),
        (t("retention"), t(&cfg.retention)),
        (t("availability"), t(&cfg.availability)),
        (
            t("checkpoint-interval-seconds"),
            Value::Int(cfg.checkpoint_interval_secs),
        ),
        (
            t("checkpoint-media-type"),
            t(atep_core::consts::CT_CHECKPOINT),
        ),
        (t("max-envelope-bytes"), Value::Int(cfg.max_envelope_bytes as i64)),
        (t("key-custody"), t(&cfg.key_custody)),
        (t("core-namespace"), t(claims::NS)),
        (t("core-claims"), texts(&core)),
        (
            t("commitments"),
            texts(&[
                "Publish the log data and APIs so anyone can run an independent log or monitor.",
                "Participate in checkpoint gossip with every independent log.",
                "Add a neutral or multi-party operator at the earlier of the first independent implementation or a second operator being ready.",
            ]),
        ),
    ])
}
