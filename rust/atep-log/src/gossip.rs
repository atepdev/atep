//! Checkpoint gossip (spec section 9): logs and monitors exchange signed
//! checkpoints so that a log showing different trees to different viewers is
//! caught. Two valid signed checkpoints of one log for the same tree size with
//! different roots, or a failing consistency proof between two of its
//! checkpoints, is a split view; the two checkpoints are transferable evidence.

use std::collections::HashMap;

use atep_core::cbor::Value;
use atep_core::consts::CT_CHECKPOINT;
use atep_core::error::{ErrorCode, Rejection};
use atep_core::keys::AgentId;
use atep_core::log::{
    verify_consistency, Checkpoint, CheckpointPair, ConsistencyProof, OfflineInclusion,
};
use atep_core::verify::{verify, Policy};

/// Supplies consistency proofs for a log (the log itself, or a remote peer).
pub trait ProofSource {
    fn consistency_proof(&self, from: u64, to: u64) -> Option<ConsistencyProof>;
}

/// No proofs available: only same-size comparisons are decisive.
pub struct NoProofs;

impl ProofSource for NoProofs {
    fn consistency_proof(&self, _: u64, _: u64) -> Option<ConsistencyProof> {
        None
    }
}

/// Proofs supplied by the sender of a gossip message.
pub struct ProofList(pub Vec<ConsistencyProof>);

impl ProofSource for ProofList {
    fn consistency_proof(&self, from: u64, to: u64) -> Option<ConsistencyProof> {
        self.0
            .iter()
            .find(|p| p.from as u64 == from && p.to as u64 == to)
            .cloned()
    }
}

/// A checkpoint this node has seen from some log.
#[derive(Clone, Debug)]
pub struct Seen {
    pub log: AgentId,
    pub size: i64,
    pub root: [u8; 32],
    pub timestamp: i64,
    /// Canonical checkpoint hash (`atep_core::log::checkpoint_hash`).
    pub hash: [u8; 32],
    pub raw: Vec<u8>,
}

/// Proof that a log equivocated: two of its signed checkpoints that cannot
/// belong to one append-only history.
#[derive(Clone, Debug)]
pub struct SplitEvidence {
    pub log: AgentId,
    pub a: Vec<u8>,
    pub b: Vec<u8>,
    pub proof: Option<ConsistencyProof>,
    pub reason: String,
}

impl SplitEvidence {
    /// The `{a, b, proof?}` document of the split-view vectors.
    pub fn to_pair_cbor(&self) -> Vec<u8> {
        CheckpointPair {
            a: Value::decode(&self.a).unwrap_or(Value::Null),
            b: Value::decode(&self.b).unwrap_or(Value::Null),
            proof: self.proof.clone(),
        }
        .to_value()
        .encode()
    }

    pub fn from_pair_cbor(log: AgentId, doc: &[u8]) -> Option<SplitEvidence> {
        let pair = CheckpointPair::from_value(&Value::decode(doc).ok()?).ok()?;
        Some(SplitEvidence {
            log,
            a: pair.a.encode(),
            b: pair.b.encode(),
            proof: pair.proof,
            reason: String::new(),
        })
    }

    /// Independently confirm the evidence: it must make
    /// `OfflineInclusion::check_split_view` report a split view.
    pub fn confirm(&self, now: i64) -> bool {
        let checker = OfflineInclusion {
            trusted_logs: vec![self.log],
            known_bundles: vec![],
        };
        let Ok(doc) = Value::decode(&self.to_pair_cbor()) else {
            return false;
        };
        let Ok(pair) = CheckpointPair::from_value(&doc) else {
            return false;
        };
        matches!(
            checker.check_split_view(&pair, now),
            Err(r) if r.code == ErrorCode::SplitViewDetected
        )
    }
}

#[derive(Clone, Debug)]
pub enum Observation {
    /// Not seen before and consistent with everything compared.
    New,
    /// Already known.
    Known,
    Split(Box<SplitEvidence>),
}

const MAX_PER_LOG: usize = 256;

/// What one node has seen from other logs.
#[derive(Default, Clone)]
pub struct GossipState {
    seen: HashMap<AgentId, Vec<Seen>>,
    evidence: Vec<SplitEvidence>,
}

/// Verify a checkpoint envelope from any log (steps 1 to 8, content type and
/// schema). Trust in the signer is the caller's decision.
pub fn parse_checkpoint(raw: &[u8], now: i64) -> Result<Seen, Rejection> {
    let v = verify(raw, &Policy::default(), now)?;
    if v.content_type != CT_CHECKPOINT {
        return Err(Rejection::new(
            9,
            ErrorCode::CheckpointSchemaInvalid,
            "not a checkpoint",
        ));
    }
    let cp = Checkpoint::from_payload(&v.payload)
        .map_err(|e| Rejection::new(9, ErrorCode::CheckpointSchemaInvalid, e.0))?;
    Ok(Seen {
        log: v.signer,
        size: cp.tree_size,
        root: cp.root_hash,
        timestamp: cp.timestamp,
        hash: atep_core::log::checkpoint_hash(&v.payload),
        raw: raw.to_vec(),
    })
}

impl GossipState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a checkpoint and compare it with what is known of the same log.
    pub fn observe(
        &mut self,
        raw: &[u8],
        now: i64,
        proofs: &dyn ProofSource,
    ) -> Result<Observation, Rejection> {
        let new = parse_checkpoint(raw, now)?;
        let list = self.seen.entry(new.log).or_default();
        if list.iter().any(|s| s.raw == raw) {
            return Ok(Observation::Known);
        }
        let mk = |old: &Seen, proof: Option<ConsistencyProof>, reason: String| {
            Observation::Split(Box::new(SplitEvidence {
                log: new.log,
                a: old.raw.clone(),
                b: new.raw.clone(),
                proof,
                reason,
            }))
        };
        let mut result = None;
        if let Some(old) = list.iter().find(|s| s.size == new.size) {
            if old.root != new.root {
                result = Some(mk(
                    old,
                    None,
                    format!(
                        "two signed checkpoints of tree size {} carry different roots",
                        new.size
                    ),
                ));
            }
        }
        if result.is_none() {
            let lower = list
                .iter()
                .filter(|s| s.size < new.size)
                .max_by_key(|s| s.size);
            let upper = list
                .iter()
                .filter(|s| s.size > new.size)
                .min_by_key(|s| s.size);
            for (small, large) in [(lower, Some(&new)), (Some(&new), upper)] {
                let (Some(small), Some(large)) = (small, large) else {
                    continue;
                };
                let Some(p) = proofs.consistency_proof(small.size as u64, large.size as u64) else {
                    continue;
                };
                if p.from != small.size
                    || p.to != large.size
                    || !verify_consistency(
                        small.size as u64,
                        large.size as u64,
                        &small.root,
                        &large.root,
                        &p.path,
                    )
                {
                    let old = if std::ptr::eq(small, &new) {
                        large
                    } else {
                        small
                    };
                    result = Some(mk(
                        old,
                        Some(p),
                        format!(
                            "checkpoint of size {} is not a prefix of the one of size {}",
                            small.size, large.size
                        ),
                    ));
                    break;
                }
            }
        }
        if let Some(Observation::Split(ev)) = &result {
            // Order the pair by size for the evidence document.
            self.evidence.push((**ev).clone());
            // Keep the checkpoint too, so the node can show what it saw.
        }
        let list = self.seen.entry(new.log).or_default();
        list.push(new);
        list.sort_by_key(|s| s.size);
        if list.len() > MAX_PER_LOG {
            list.remove(0);
        }
        Ok(result.unwrap_or(Observation::New))
    }

    /// Latest checkpoint seen per log.
    pub fn latest(&self) -> Vec<&Seen> {
        let mut v: Vec<&Seen> = self
            .seen
            .values()
            .filter_map(|l| l.iter().max_by_key(|s| (s.size, s.timestamp)))
            .collect();
        v.sort_by_key(|s| s.log);
        v
    }

    /// Every checkpoint seen, for relaying.
    pub fn all(&self) -> Vec<&Seen> {
        let mut v: Vec<&Seen> = self.seen.values().flatten().collect();
        v.sort_by_key(|s| (s.log, s.size));
        v
    }

    pub fn of_log(&self, log: &AgentId) -> &[Seen] {
        self.seen.get(log).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn evidence(&self) -> &[SplitEvidence] {
        &self.evidence
    }

    pub(crate) fn clear_evidence(&mut self) {
        self.evidence.clear();
    }

    pub(crate) fn push_evidence(&mut self, ev: SplitEvidence) {
        self.evidence.push(ev);
    }
}

/// What one side of an exchange learned.
#[derive(Debug, Default)]
pub struct ExchangeReport {
    /// Split views detected, as evidence.
    pub splits: Vec<SplitEvidence>,
    /// Checkpoints that were new to the receiving side.
    pub new_checkpoints: usize,
    /// Checkpoints that failed verification.
    pub rejected: usize,
}

/// Exchange checkpoints between two logs in one process: each log hands the
/// other its latest own checkpoint (with itself as the proof source) and every
/// third-party checkpoint it has observed (relay, no proofs), and each
/// compares what it receives with what it already knows. Returns what `a`
/// and `b` learned.
pub fn exchange(
    a: &mut crate::log::Log,
    b: &mut crate::log::Log,
    now: i64,
) -> (ExchangeReport, ExchangeReport) {
    let bundle = |l: &crate::log::Log| -> (Option<Vec<u8>>, Vec<Vec<u8>>) {
        (
            l.latest_checkpoint().map(|c| c.raw.clone()),
            l.gossip_state()
                .all()
                .iter()
                .map(|s| s.raw.clone())
                .collect(),
        )
    };
    let (a_own, a_relay) = bundle(a);
    let (b_own, b_relay) = bundle(b);
    let mut ra = ExchangeReport::default();
    let mut rb = ExchangeReport::default();
    let deliver = |to: &mut crate::log::Log,
                   report: &mut ExchangeReport,
                   own: Option<Vec<u8>>,
                   relay: Vec<Vec<u8>>,
                   from: &dyn ProofSource| {
        let items = own
            .into_iter()
            .map(|r| (r, true))
            .chain(relay.into_iter().map(|r| (r, false)));
        for (raw, is_own) in items {
            let src: &dyn ProofSource = if is_own { from } else { &NoProofs };
            match to.observe_checkpoint(&raw, now, src) {
                Ok(Observation::New) => report.new_checkpoints += 1,
                Ok(Observation::Known) => {}
                Ok(Observation::Split(ev)) => report.splits.push(*ev),
                Err(_) => report.rejected += 1,
            }
        }
    };
    deliver(b, &mut rb, a_own, a_relay, &*a);
    deliver(a, &mut ra, b_own, b_relay, &*b);
    (ra, rb)
}
