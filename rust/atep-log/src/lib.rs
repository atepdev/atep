//! ATEP transparency log and registry service (spec section 9, milestone M3).
//!
//! * [`store`]: crash-safe append-only record files.
//! * [`tree`]: the RFC 9162 Merkle tree with an incremental frontier.
//! * [`admit`]: what the log accepts (spec sections 5, 7, 8 and 16).
//! * [`policy`]: the published log policy, recorded as the first log entry.
//! * [`log`]: the log itself: submission, checkpoints, proofs, entries, lookup,
//!   issuer and claim-type directories.
//! * [`anchor`]: the optional `Witness` hook and anchor records (anchoring hooks, spec section 9).
//! * [`gossip`]: checkpoint exchange and split view detection.
//! * [`claimdefs`]: claim-type definitions and CDDL schemas (the resolver data).
//! * [`routes`] and [`openapi`]: the route table and the OpenAPI 3.1 document built from it.
//! * [`domain_binding`]: the `domain-control` record checker (`.well-known/atep.json`, `_atep.<domain>`).
//! * [`http`] and [`client`]: the HTTP/1.1 API and a minimal client.

pub mod admit;
pub mod anchor;
pub mod claimdefs;
pub mod client;
pub mod directory;
pub mod domain_binding;
pub mod gossip;
pub mod http;
pub mod log;
pub mod openapi;
pub mod policy;
pub mod routes;
pub mod store;
pub mod testkit;
pub mod tree;

pub use admit::{SubmitError, POLICY_CLAIM};
pub use anchor::{AnchorEntry, CheckpointAnchors, NoopWitness, Witness, WitnessError};
pub use log::{CheckpointRec, EntryKind, EntryMeta, Log, SubmitErr, SubmitOutcome};
pub use policy::LogConfig;

use std::fmt;

/// Failures of the log itself (storage, corruption), as opposed to a rejected
/// submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogError {
    Io(String),
    /// Stored data failed re-verification: a damaged file or rewritten history.
    Corrupt(String),
    Crypto(String),
    Config(String),
}

impl fmt::Display for LogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogError::Io(m) => write!(f, "i/o error: {m}"),
            LogError::Corrupt(m) => write!(f, "log data failed verification: {m}"),
            LogError::Crypto(m) => write!(f, "crypto error: {m}"),
            LogError::Config(m) => write!(f, "configuration error: {m}"),
        }
    }
}

impl std::error::Error for LogError {}

impl From<atep_core::AtepError> for LogError {
    fn from(e: atep_core::AtepError) -> Self {
        LogError::Crypto(e.0)
    }
}

/// Current Unix time in seconds.
pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub(crate) fn b64(b: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(b)
}

pub(crate) fn unb64(s: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).ok()
}
