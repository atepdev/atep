//! Anchoring hooks of the log (anchoring hooks, spec section 9). Nothing here depends on a
//! chain and nothing produces an anchor by default.
//!
//! * A [`Witness`] writes a checkpoint hash to some external witness and
//!   returns the [`AnchorRecord`] describing it. [`NoopWitness`] does nothing.
//!   Chain adapters (milestone M5) are later implementations of the trait.
//! * The log signs each anchor record as an envelope with the provisional
//!   media type `application/atep-anchor+cbor` ([`atep_core::consts::CT_ANCHOR`]),
//!   payload the deterministic CBOR of the record, signer the log. It stores
//!   the envelopes in `anchors.rec` and serves them next to the checkpoint
//!   they belong to.

use std::fmt;

use atep_core::anchor::AnchorRecord;

/// Why a witness did not produce an anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessError {
    /// No witness is configured (the no-op witness): nothing to do, not a failure.
    Disabled,
    /// The witness could not anchor now; retry at the next checkpoint.
    Failed(String),
}

impl fmt::Display for WitnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WitnessError::Disabled => write!(f, "no witness configured"),
            WitnessError::Failed(m) => write!(f, "witness failed: {m}"),
        }
    }
}

impl std::error::Error for WitnessError {}

/// An external witness of checkpoints. `Send` so a log holding one can sit
/// behind the server's mutex.
pub trait Witness: Send {
    /// Commit `checkpoint_hash` (see `atep_core::log::checkpoint_hash`) to the
    /// witness and describe the result. The returned record's
    /// `checkpoint_hash` must equal the argument.
    fn anchor(&self, checkpoint_hash: &[u8; 32]) -> Result<AnchorRecord, WitnessError>;
}

/// The default witness: anchors nothing.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopWitness;

impl Witness for NoopWitness {
    fn anchor(&self, _checkpoint_hash: &[u8; 32]) -> Result<AnchorRecord, WitnessError> {
        Err(WitnessError::Disabled)
    }
}

/// A stored anchor: the record and the log-signed envelope that carries it.
#[derive(Clone, Debug)]
pub struct AnchorEntry {
    pub record: AnchorRecord,
    pub raw: Vec<u8>,
}

/// The anchors of one published checkpoint, as served by the log and read by
/// monitors. `anchors` is empty for a log that does not anchor.
#[derive(Clone, Debug)]
pub struct CheckpointAnchors {
    pub tree_size: u64,
    pub checkpoint_hash: [u8; 32],
    pub anchors: Vec<AnchorRecord>,
}

pub use atep_core::anchor::{check_published_anchor, parse_anchor_envelope};
