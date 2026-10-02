//! The transparency log: an append-only list of attestations and SRLs, an
//! RFC 9162 Merkle tree over `SHA-256(0x00 || submitted envelope)`, and signed
//! checkpoints (`application/atep-checkpoint+cbor`) under the log's own hybrid
//! identity.
//!
//! Data directory:
//!
//! * `identity.key`   the log's secret key file (mode 0600)
//! * `entries.rec`    one record per entry: `logged-at (8 bytes) || envelope`
//! * `checkpoints.rec` signed checkpoint envelopes
//! * `anchors.rec`   log-signed anchor records (`application/atep-anchor+cbor`);
//!   optional, absent in data directories written before the anchoring hooks
//! * `peers.rec`      checkpoints of other logs seen through gossip
//! * `evidence.rec`   split view evidence (`{a, b, proof?}` documents)
//! * `LOCK`           advisory lock held while a process has the log open
//!
//! `open` re-verifies everything: each entry is re-validated as at its logging
//! time, the tree is rebuilt, and every stored checkpoint must carry a valid
//! signature of this log and the root of the tree at its size. A damaged or
//! rewritten history therefore stops the log from starting.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use atep_core::anchor::{validate_chain_id, AnchorRecord};
use atep_core::attestation::{claims, Attestation, AttestationParams};
use atep_core::cbor::Value;
use atep_core::consts::*;
use atep_core::envelope::{sign, submitted_form, SignParams};
use atep_core::error::{ErrorCode, Rejection};
use atep_core::keys::{fill_random, AgentId, Identity, PublicBundle};
use atep_core::log::{
    checkpoint_hash, hash_leaf, Checkpoint, CheckpointUsed, ConsistencyProof, InclusionCheck,
    InclusionProof,
};
use atep_core::verify::{verify, Policy, Revocation};

use crate::admit::{self, BundleMap, Context, Doc, SubmitError, POLICY_CLAIM};
use crate::anchor::{parse_anchor_envelope, AnchorEntry, Witness, WitnessError};
use crate::gossip::{GossipState, Observation, ProofSource, SplitEvidence};
use crate::policy::{policy_data, LogConfig};
use crate::store::RecordFile;
use crate::tree::Tree;
use crate::LogError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    Attestation,
    Srl,
}

/// Metadata of one entry, kept in memory; the envelope stays on disk.
#[derive(Clone, Debug)]
pub struct EntryMeta {
    pub index: u64,
    pub leaf: [u8; 32],
    pub offset: u64,
    pub logged_at: i64,
    pub kind: EntryKind,
    pub issuer: AgentId,
    pub subject: Option<AgentId>,
    pub claim: Option<String>,
    pub issued_at: i64,
    pub expires_at: Option<i64>,
    pub att_id: Option<[u8; 16]>,
    pub srl_sequence: Option<i64>,
    /// `data.domain` of a `domain-control` attestation.
    pub domain: Option<String>,
    /// Claim types listed by an `issuer-authority` attestation.
    pub delegated: Vec<String>,
    pub is_policy: bool,
}

/// A signed checkpoint the log issued.
#[derive(Clone, Debug)]
pub struct CheckpointRec {
    pub size: u64,
    pub root: [u8; 32],
    pub timestamp: i64,
    /// Canonical checkpoint hash: SHA-256 of the signed checkpoint payload.
    pub hash: [u8; 32],
    pub raw: Vec<u8>,
}

/// Result of a submission: the Signed Inclusion Proof of spec section 9.
#[derive(Clone, Debug)]
pub struct SubmitOutcome {
    pub index: u64,
    pub leaf: [u8; 32],
    /// True when the envelope was already logged (idempotent resubmission).
    pub duplicate: bool,
    pub proof: InclusionProof,
}

impl SubmitOutcome {
    /// The `-70012` header value, CBOR encoded, ready to embed.
    pub fn proof_cbor(&self) -> Vec<u8> {
        self.proof.to_value().encode()
    }
}

pub struct Log {
    dir: PathBuf,
    identity: Identity,
    cfg: LogConfig,
    entries: RecordFile,
    cps: RecordFile,
    anchors_file: RecordFile,
    anchors: Vec<AnchorEntry>,
    witness: Option<Box<dyn Witness>>,
    peers: RecordFile,
    evidence: RecordFile,
    _lock: File,
    tree: Tree,
    metas: Vec<EntryMeta>,
    by_leaf: HashMap<[u8; 32], u64>,
    by_subject: HashMap<AgentId, Vec<u64>>,
    bundles: BundleMap,
    revocations: Vec<Revocation>,
    /// Logged `retired` attestations (submitted form), the local attestation
    /// store of step 8 at admission.
    retirements: Vec<Vec<u8>>,
    srl_sequences: HashMap<AgentId, i64>,
    checkpoints: Vec<CheckpointRec>,
    gossip: GossipState,
}

fn corrupt<T>(msg: impl Into<String>) -> Result<T, LogError> {
    Err(LogError::Corrupt(msg.into()))
}

fn io(path: &Path, e: std::io::Error) -> LogError {
    LogError::Io(format!("{}: {e}", path.display()))
}

fn load_or_create_identity(dir: &Path, given: Option<Identity>) -> Result<Identity, LogError> {
    let path = dir.join("identity.key");
    if path.exists() {
        let id = Identity::from_secret_file(&fs::read(&path).map_err(|e| io(&path, e))?)?;
        if let Some(g) = given {
            if g.agent_id() != id.agent_id() {
                return Err(LogError::Config(
                    "the data directory belongs to a different log identity".into(),
                ));
            }
        }
        return Ok(id);
    }
    let id = match given {
        Some(g) => g,
        None => Identity::generate(false)?,
    };
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| io(&path, e))?;
    f.write_all(&id.to_secret_file())
        .map_err(|e| io(&path, e))?;
    f.sync_all().map_err(|e| io(&path, e))?;
    Ok(id)
}

fn meta_of(
    a: &admit::Admitted,
    index: u64,
    offset: u64,
    logged_at: i64,
    log: &AgentId,
) -> EntryMeta {
    let mut m = EntryMeta {
        index,
        leaf: a.leaf,
        offset,
        logged_at,
        kind: EntryKind::Srl,
        issuer: a.issuer,
        subject: None,
        claim: None,
        issued_at: a.issued_at,
        expires_at: a.expires_at,
        att_id: None,
        srl_sequence: None,
        domain: None,
        delegated: Vec::new(),
        is_policy: false,
    };
    match &a.doc {
        Doc::Attestation(att) => {
            m.kind = EntryKind::Attestation;
            m.subject = Some(att.subject);
            m.claim = Some(att.claim.clone());
            m.att_id = Some(att.id);
            if att.claim == claims::DOMAIN_CONTROL {
                m.domain = admit::domain_of(att).map(str::to_string);
            }
            if att.claim == claims::ISSUER_AUTHORITY {
                m.delegated = att.authority_claims().unwrap_or_default();
            }
            m.is_policy = att.claim == POLICY_CLAIM && att.issuer == *log;
        }
        Doc::Srl(s) => m.srl_sequence = Some(s.sequence),
    }
    m
}

impl Log {
    /// Open (or create) the log in `dir`, re-verify its contents, make sure the
    /// policy is recorded and that a checkpoint covers every entry.
    pub fn open(dir: &Path, cfg: LogConfig, now: i64) -> Result<Log, LogError> {
        Self::open_with(dir, None, cfg, now)
    }

    /// As [`Log::open`] with a given identity for a new data directory.
    pub fn open_with(
        dir: &Path,
        identity: Option<Identity>,
        cfg: LogConfig,
        now: i64,
    ) -> Result<Log, LogError> {
        fs::create_dir_all(dir).map_err(|e| io(dir, e))?;
        let lock_path = dir.join("LOCK");
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .map_err(|e| io(&lock_path, e))?;
        lock.try_lock().map_err(|_| {
            LogError::Config(format!("{} is in use by another process", dir.display()))
        })?;
        let identity = load_or_create_identity(dir, identity)?;
        let (entries, loaded_entries, torn_e) = RecordFile::open(&dir.join("entries.rec"))?;
        let (cps, loaded_cps, _) = RecordFile::open(&dir.join("checkpoints.rec"))?;
        let (anchors_file, loaded_anchors, _) = RecordFile::open(&dir.join("anchors.rec"))?;
        let (peers, loaded_peers, _) = RecordFile::open(&dir.join("peers.rec"))?;
        let (evidence, loaded_ev, _) = RecordFile::open(&dir.join("evidence.rec"))?;
        let mut log = Log {
            dir: dir.to_path_buf(),
            identity,
            cfg,
            entries,
            cps,
            anchors_file,
            anchors: Vec::new(),
            witness: None,
            peers,
            evidence,
            _lock: lock,
            tree: Tree::default(),
            metas: Vec::new(),
            by_leaf: HashMap::new(),
            by_subject: HashMap::new(),
            bundles: HashMap::new(),
            revocations: Vec::new(),
            retirements: Vec::new(),
            srl_sequences: HashMap::new(),
            checkpoints: Vec::new(),
            gossip: GossipState::new(),
        };
        let _ = torn_e;
        // Entries: re-validate each as at its logging time.
        for rec in loaded_entries {
            if rec.payload.len() < 8 {
                return corrupt(format!("entry {} is too short", log.metas.len()));
            }
            let logged_at = i64::from_be_bytes(rec.payload[..8].try_into().unwrap());
            let raw = &rec.payload[8..];
            let index = log.metas.len() as u64;
            let cx = Context {
                log_id: log.identity.agent_id(),
                bundles: &log.bundles,
                revocations: &log.revocations,
                retirements: &log.retirements,
                srl_sequences: &log.srl_sequences,
                max_envelope_bytes: usize::MAX,
            };
            let adm = admit::check(raw, &cx, logged_at).map_err(|e| {
                LogError::Corrupt(format!("entry {index} fails re-verification: {e}"))
            })?;
            if adm.submitted != raw {
                return corrupt(format!("entry {index} is not in submitted form"));
            }
            if log.by_leaf.contains_key(&adm.leaf) {
                return corrupt(format!("entry {index} duplicates an earlier entry"));
            }
            log.record(adm, rec.offset, logged_at);
        }
        // Checkpoints: signed by this log, root equal to the tree at that size.
        let own = log.identity.public().clone();
        let mut last: Option<(u64, i64)> = None;
        for (i, rec) in loaded_cps.into_iter().enumerate() {
            let cp = Self::parse_own_checkpoint(&rec.payload, &own)
                .map_err(|m| LogError::Corrupt(format!("checkpoint {i}: {m}")))?;
            if cp.size as usize > log.tree.len() {
                return corrupt(format!(
                    "checkpoint {i} covers {} entries but the log holds {}",
                    cp.size,
                    log.tree.len()
                ));
            }
            if log.tree.root_at(cp.size as usize) != cp.root {
                return corrupt(format!(
                    "checkpoint {i} (tree size {}) does not match the entries: history was altered",
                    cp.size
                ));
            }
            if let Some((s, t)) = last {
                if cp.size < s || cp.timestamp < t {
                    return corrupt(format!("checkpoint {i} goes backwards"));
                }
            }
            last = Some((cp.size, cp.timestamp));
            log.checkpoints.push(cp);
        }
        // Anchors: signed by this log, for a checkpoint it published.
        for (i, rec) in loaded_anchors.into_iter().enumerate() {
            let e = Self::parse_own_anchor(&rec.payload, &own)
                .map_err(|m| LogError::Corrupt(format!("anchor {i}: {m}")))?;
            if !log
                .checkpoints
                .iter()
                .any(|c| c.hash == e.record.checkpoint_hash)
            {
                return corrupt(format!(
                    "anchor {i} is for a checkpoint this log never signed"
                ));
            }
            if log.has_anchor(&e.record) {
                return corrupt(format!("anchor {i} duplicates an earlier anchor"));
            }
            log.anchors.push(e);
        }
        for rec in loaded_peers {
            // Peer checkpoints that no longer verify are dropped, not fatal.
            let _ = log
                .gossip
                .observe(&rec.payload, i64::MAX / 2, &crate::gossip::NoProofs);
        }
        // Evidence found by replaying peers is rediscovered; the stored
        // evidence (which may hold proofs) is the record.
        log.gossip.clear_evidence();
        for rec in loaded_ev {
            if let Ok(doc) = Value::decode(&rec.payload) {
                if let Ok(pair) = atep_core::log::CheckpointPair::from_value(&doc) {
                    if let Ok(s) = crate::gossip::parse_checkpoint(&pair.a.encode(), i64::MAX / 2) {
                        log.gossip.push_evidence(SplitEvidence {
                            log: s.log,
                            a: pair.a.encode(),
                            b: pair.b.encode(),
                            proof: pair.proof,
                            reason: "recorded evidence".into(),
                        });
                    }
                }
            }
        }
        log.ensure_policy(now)?;
        if log.checkpoints.last().map(|c| c.size as usize) != Some(log.tree.len()) {
            log.checkpoint(now)?;
        }
        Ok(log)
    }

    fn parse_own_checkpoint(raw: &[u8], own: &PublicBundle) -> Result<CheckpointRec, String> {
        let policy = Policy {
            known_bundles: vec![own.clone()],
            ..Policy::default()
        };
        // Verified at its own issued-at, so an old checkpoint does not expire.
        let env = atep_core::envelope::SignedEnvelope::decode(raw).map_err(|e| e.to_string())?;
        let v = verify(raw, &policy, env.headers.issued_at).map_err(|e| e.to_string())?;
        if v.signer != own.agent_id() {
            return Err("signed by a different identity".into());
        }
        if v.content_type != CT_CHECKPOINT {
            return Err("wrong content type".into());
        }
        let cp = Checkpoint::from_payload(&v.payload).map_err(|e| e.0)?;
        Ok(CheckpointRec {
            size: cp.tree_size as u64,
            root: cp.root_hash,
            timestamp: cp.timestamp,
            hash: checkpoint_hash(&v.payload),
            raw: raw.to_vec(),
        })
    }

    fn parse_own_anchor(raw: &[u8], own: &PublicBundle) -> Result<AnchorEntry, String> {
        let env = atep_core::envelope::SignedEnvelope::decode(raw).map_err(|e| e.to_string())?;
        let (signer, record) =
            parse_anchor_envelope(raw, env.headers.issued_at).map_err(|e| e.to_string())?;
        if signer != own.agent_id() {
            return Err("signed by a different identity".into());
        }
        Ok(AnchorEntry {
            record,
            raw: raw.to_vec(),
        })
    }

    fn has_anchor(&self, r: &AnchorRecord) -> bool {
        self.anchors.iter().any(|a| {
            a.record.checkpoint_hash == r.checkpoint_hash
                && a.record.chain_id == r.chain_id
                && a.record.transaction_id == r.transaction_id
        })
    }

    /// Index an admitted entry that is already stored (or about to be).
    fn record(&mut self, adm: admit::Admitted, offset: u64, logged_at: i64) {
        let index = self.metas.len() as u64;
        let meta = meta_of(&adm, index, offset, logged_at, &self.identity.agent_id());
        if let Some(b) = adm.bundle {
            self.bundles.entry(adm.issuer).or_insert(b);
        }
        match &adm.doc {
            Doc::Srl(s) => {
                self.revocations.extend(admit::revocations_of(s));
                self.srl_sequences.insert(s.issuer, s.sequence);
            }
            Doc::Attestation(a) => {
                self.by_subject.entry(a.subject).or_default().push(index);
                if a.claim == claims::RETIRED {
                    self.retirements.push(adm.submitted.clone());
                }
            }
        }
        self.by_leaf.insert(adm.leaf, index);
        self.tree.push(adm.leaf);
        self.metas.push(meta);
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn log_id(&self) -> AgentId {
        self.identity.agent_id()
    }

    pub fn config(&self) -> &LogConfig {
        &self.cfg
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn tree_size(&self) -> u64 {
        self.tree.len() as u64
    }

    pub fn entries_meta(&self) -> &[EntryMeta] {
        &self.metas
    }

    pub fn checkpoints(&self) -> &[CheckpointRec] {
        &self.checkpoints
    }

    pub fn latest_checkpoint(&self) -> Option<&CheckpointRec> {
        self.checkpoints.last()
    }

    /// Anchor records for the checkpoint whose canonical hash is `hash`
    /// (empty when none; always empty for a log without a witness).
    pub fn anchors_for(&self, hash: &[u8; 32]) -> Vec<&AnchorEntry> {
        self.anchors
            .iter()
            .filter(|a| &a.record.checkpoint_hash == hash)
            .collect()
    }

    /// Every anchor the log holds, in the order recorded.
    pub fn anchors(&self) -> &[AnchorEntry] {
        &self.anchors
    }

    /// Configure (or remove, with `None`) the witness. The default is none.
    pub fn set_witness(&mut self, witness: Option<Box<dyn Witness>>) {
        self.witness = witness;
    }

    pub fn has_witness(&self) -> bool {
        self.witness.is_some()
    }

    /// Sign and store an anchor record for a checkpoint this log published.
    /// Refuses unknown checkpoints, unknown chain ids and duplicates.
    pub fn record_anchor(
        &mut self,
        record: AnchorRecord,
        now: i64,
    ) -> Result<&AnchorEntry, LogError> {
        validate_chain_id(&record.chain_id)?;
        if !self
            .checkpoints
            .iter()
            .any(|c| c.hash == record.checkpoint_hash)
        {
            return Err(LogError::Config(
                "the anchor is for a checkpoint this log did not publish".into(),
            ));
        }
        if self.has_anchor(&record) {
            return Err(LogError::Config("the anchor is already recorded".into()));
        }
        let payload = record.encode();
        let mut nonce = [0u8; 16];
        fill_random(&mut nonce)?;
        let params = SignParams::new(&payload, CT_ANCHOR, nonce, now);
        let raw = sign(&self.identity, &params)?;
        self.anchors_file.append(&raw)?;
        self.anchors.push(AnchorEntry { record, raw });
        Ok(self.anchors.last().expect("just pushed"))
    }

    /// Ask the configured witness to anchor the latest checkpoint, unless that
    /// checkpoint already has an anchor. `Ok(None)` when there is no witness,
    /// the witness is the no-op one, or nothing is pending. A failing witness
    /// is an error the caller reports; the log itself is unaffected and the
    /// next call retries.
    pub fn witness_latest(&mut self, now: i64) -> Result<Option<AnchorEntry>, WitnessError> {
        let Some(w) = &self.witness else {
            return Ok(None);
        };
        let Some(hash) = self.checkpoints.last().map(|c| c.hash) else {
            return Ok(None);
        };
        if !self.anchors_for(&hash).is_empty() {
            return Ok(None);
        }
        let record = match w.anchor(&hash) {
            Ok(r) => r,
            Err(WitnessError::Disabled) => return Ok(None),
            Err(e) => return Err(e),
        };
        if record.checkpoint_hash != hash {
            return Err(WitnessError::Failed(
                "the witness anchored a different checkpoint hash".into(),
            ));
        }
        self.record_anchor(record, now)
            .map(|e| Some(e.clone()))
            .map_err(|e| WitnessError::Failed(e.to_string()))
    }

    pub fn gossip_state(&self) -> &GossipState {
        &self.gossip
    }

    /// True when the latest checkpoint is older than the configured interval.
    pub fn checkpoint_due(&self, now: i64) -> bool {
        match self.checkpoints.last() {
            None => true,
            Some(c) => now - c.timestamp >= self.cfg.checkpoint_interval_secs,
        }
    }

    /// Issue and store a fresh signed checkpoint of the current tree.
    pub fn checkpoint(&mut self, now: i64) -> Result<&CheckpointRec, LogError> {
        let ts = self
            .checkpoints
            .last()
            .map_or(now, |c| now.max(c.timestamp));
        let cp = Checkpoint {
            tree_size: self.tree.len() as i64,
            root_hash: self.tree.root(),
            timestamp: ts,
        };
        let payload = cp.encode();
        let hash = checkpoint_hash(&payload);
        let mut nonce = [0u8; 16];
        fill_random(&mut nonce)?;
        let params = SignParams::new(&payload, CT_CHECKPOINT, nonce, ts);
        let raw = sign(&self.identity, &params)?;
        self.cps.append(&raw)?;
        self.checkpoints.push(CheckpointRec {
            size: self.tree.len() as u64,
            root: cp.root_hash,
            timestamp: ts,
            hash,
            raw,
        });
        Ok(self.checkpoints.last().expect("just pushed"))
    }

    /// Checkpoint that covers leaf `index`: the latest one, issued now if the
    /// latest does not cover it yet.
    fn covering_checkpoint(&mut self, index: u64, now: i64) -> Result<CheckpointRec, LogError> {
        if self.checkpoints.last().is_none_or(|c| c.size <= index) {
            self.checkpoint(now)?;
        }
        Ok(self.checkpoints.last().expect("checked").clone())
    }

    fn build_proof(&self, index: u64, cp: &CheckpointRec) -> Result<InclusionProof, LogError> {
        Ok(InclusionProof {
            leaf_index: index as i64,
            audit_path: self.tree.audit_path(index as usize, cp.size as usize),
            checkpoint: Value::decode(&cp.raw).map_err(|e| LogError::Crypto(e.to_string()))?,
        })
    }

    /// Submit an attestation or SRL. Idempotent: a repeat returns the existing
    /// entry with a proof against the latest checkpoint.
    pub fn submit(&mut self, raw: &[u8], now: i64) -> Result<SubmitOutcome, SubmitErr> {
        let cx = Context {
            log_id: self.identity.agent_id(),
            bundles: &self.bundles,
            revocations: &self.revocations,
            retirements: &self.retirements,
            srl_sequences: &self.srl_sequences,
            max_envelope_bytes: self.cfg.max_envelope_bytes,
        };
        // Duplicates are recognized before validation so that a document that
        // has expired since is still answered with its entry.
        if let Ok(sub) = submitted_form(raw) {
            if let Some(&index) = self.by_leaf.get(&hash_leaf(&sub)) {
                let cp = self.covering_checkpoint(index, now)?;
                return Ok(SubmitOutcome {
                    index,
                    leaf: hash_leaf(&sub),
                    duplicate: true,
                    proof: self.build_proof(index, &cp)?,
                });
            }
        }
        let adm = admit::check(raw, &cx, now).map_err(SubmitErr::Rejected)?;
        if let Some(&index) = self.by_leaf.get(&adm.leaf) {
            let cp = self.covering_checkpoint(index, now)?;
            return Ok(SubmitOutcome {
                index,
                leaf: adm.leaf,
                duplicate: true,
                proof: self.build_proof(index, &cp)?,
            });
        }
        let mut rec = now.to_be_bytes().to_vec();
        rec.extend_from_slice(&adm.submitted);
        let offset = self.entries.append(&rec)?;
        let leaf = adm.leaf;
        self.record(adm, offset, now);
        let index = self.metas.len() as u64 - 1;
        let cp = self.covering_checkpoint(index, now)?;
        Ok(SubmitOutcome {
            index,
            leaf,
            duplicate: false,
            proof: self.build_proof(index, &cp)?,
        })
    }

    /// Record the log policy as an entry when it is missing, changed or
    /// about to expire.
    fn ensure_policy(&mut self, now: i64) -> Result<(), LogError> {
        let data = policy_data(&self.cfg, &self.log_id());
        let current = self.policy_entry();
        if let Some(m) = current {
            let raw = self.read_entry(m.index)?;
            let att = Self::decode_attestation(&raw)?;
            let fresh = m.expires_at.is_some_and(|e| e > now + 30 * 86_400);
            if att.data.encode() == data.encode() && fresh {
                return Ok(());
            }
        }
        let id = self.log_id();
        let mut p = AttestationParams::new(
            id,
            POLICY_CLAIM,
            now,
            now + self.cfg.policy_lifetime_days * 86_400,
        )?;
        p.data = data;
        p.allow_long_default = true;
        let raw = atep_core::attestation::issue(&self.identity, &p)?;
        match self.submit(&raw, now) {
            Ok(_) => Ok(()),
            Err(SubmitErr::Rejected(e)) => Err(LogError::Config(format!(
                "the log policy was refused by the log's own admission rules: {e}"
            ))),
            Err(SubmitErr::Log(e)) => Err(e),
        }
    }

    fn decode_attestation(raw: &[u8]) -> Result<Attestation, LogError> {
        let env = atep_core::envelope::SignedEnvelope::decode(raw)
            .map_err(|e| LogError::Corrupt(e.to_string()))?;
        let payload = env
            .payload
            .ok_or_else(|| LogError::Corrupt("entry has no payload".into()))?;
        Attestation::from_payload(&payload).map_err(|e| LogError::Corrupt(e.0))
    }

    /// The latest policy entry (the first entry of a log is its policy).
    pub fn policy_entry(&self) -> Option<&EntryMeta> {
        self.metas.iter().rev().find(|m| m.is_policy)
    }

    /// Envelope bytes of entry `index` in submitted form.
    pub fn read_entry(&self, index: u64) -> Result<Vec<u8>, LogError> {
        let m = self
            .metas
            .get(index as usize)
            .ok_or_else(|| LogError::Config(format!("no entry {index}")))?;
        let rec = self.entries.read_at(m.offset)?;
        Ok(rec[8..].to_vec())
    }

    pub fn find_leaf(&self, leaf: &[u8; 32]) -> Option<u64> {
        self.by_leaf.get(leaf).copied()
    }

    /// Inclusion proof for a logged leaf against the latest checkpoint.
    pub fn inclusion_proof(
        &mut self,
        leaf: &[u8; 32],
        now: i64,
    ) -> Result<Option<(u64, InclusionProof)>, LogError> {
        let Some(index) = self.find_leaf(leaf) else {
            return Ok(None);
        };
        let cp = self.covering_checkpoint(index, now)?;
        Ok(Some((index, self.build_proof(index, &cp)?)))
    }

    /// Root hash of the first `size` entries.
    pub fn root_at(&self, size: u64) -> [u8; 32] {
        self.tree.root_at(size as usize)
    }

    /// Consistency proof between two tree sizes (`from <= to <= tree size`).
    pub fn consistency(&self, from: u64, to: u64) -> Result<ConsistencyProof, String> {
        if from > to {
            return Err("`from` is greater than `to`".into());
        }
        if to > self.tree_size() {
            return Err(format!("`to` exceeds the tree size {}", self.tree_size()));
        }
        Ok(ConsistencyProof {
            from: from as i64,
            to: to as i64,
            path: self.tree.consistency(from as usize, to as usize),
        })
    }

    pub fn entries_by_subject(&self, subject: &AgentId) -> Vec<&EntryMeta> {
        self.by_subject
            .get(subject)
            .map(|v| v.iter().map(|i| &self.metas[*i as usize]).collect())
            .unwrap_or_default()
    }

    /// Verify and record a checkpoint of another log seen through gossip.
    /// Persists new checkpoints and split view evidence.
    pub fn observe_checkpoint(
        &mut self,
        raw: &[u8],
        now: i64,
        proofs: &dyn ProofSource,
    ) -> Result<Observation, Rejection> {
        let obs = self.gossip.observe(raw, now, proofs)?;
        match &obs {
            Observation::New => {
                let _ = self.peers.append(raw);
            }
            Observation::Split(ev) => {
                let _ = self.peers.append(raw);
                let _ = self.evidence.append(&ev.to_pair_cbor());
            }
            Observation::Known => {}
        }
        Ok(obs)
    }
}

/// A submission can fail because it is invalid or because the log could not
/// store it.
#[derive(Debug)]
pub enum SubmitErr {
    Rejected(SubmitError),
    Log(LogError),
}

impl From<LogError> for SubmitErr {
    fn from(e: LogError) -> Self {
        SubmitErr::Log(e)
    }
}

impl std::fmt::Display for SubmitErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubmitErr::Rejected(e) => write!(f, "{e}"),
            SubmitErr::Log(e) => write!(f, "{e}"),
        }
    }
}

impl ProofSource for Log {
    fn consistency_proof(&self, from: u64, to: u64) -> Option<ConsistencyProof> {
        self.consistency(from, to).ok()
    }
}

/// Online inclusion check: the log answers from its own state. The supplied
/// proof, if any, is not needed because the log can look the leaf up.
impl InclusionCheck for Log {
    fn check(
        &self,
        submitted: &[u8],
        _proof: Option<&Value>,
        _now: i64,
    ) -> Result<CheckpointUsed, Rejection> {
        let leaf = hash_leaf(submitted);
        let Some(index) = self.find_leaf(&leaf) else {
            return Err(Rejection::new(
                9,
                ErrorCode::InclusionProofMissing,
                "the document is not in this log",
            ));
        };
        let Some(cp) = self.checkpoints.iter().rev().find(|c| c.size > index) else {
            return Err(Rejection::new(
                9,
                ErrorCode::InclusionProofInvalid,
                "no checkpoint covers the entry yet",
            ));
        };
        Ok(CheckpointUsed {
            log: self.log_id(),
            tree_size: cp.size as i64,
            root_hash: cp.root,
            timestamp: cp.timestamp,
        })
    }
}
