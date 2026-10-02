//! Transparency log primitives (spec section 9): RFC 9162 style Merkle tree
//! hashing and inclusion proofs, signed checkpoints, the inclusion proof
//! structure carried under header `-70012`, and the [`InclusionCheck`] trait
//! that the M3 log service implements.
//!
//! Leaf hash of an envelope is `SHA-256(0x00 || submitted envelope bytes)`, where
//! the submitted envelope is the attestation without its `-70012` header
//! (see docs/implementation-findings/rust-findings.md).

use sha2::{Digest, Sha256};

use crate::attestation::{fixed_bytes, schema, text_entries, uint, SchemaError};
use crate::cbor::Value;
use crate::consts::*;
use crate::envelope::{sign, SignMode, SignParams};
use crate::error::{AtepError, ErrorCode, Rejection};
use crate::keys::{AgentId, Identity, PublicBundle};
use crate::verify::{verify, Policy};

pub fn hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(data);
    h.finalize().into()
}

pub fn hash_children(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Largest power of two strictly smaller than `n` (n >= 2).
fn split(n: usize) -> usize {
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// Merkle Tree Hash (RFC 9162 section 2.1.1) over the leaf inputs.
pub fn merkle_root(leaves: &[Vec<u8>]) -> [u8; 32] {
    match leaves.len() {
        0 => Sha256::digest([]).into(),
        1 => hash_leaf(&leaves[0]),
        n => {
            let k = split(n);
            hash_children(&merkle_root(&leaves[..k]), &merkle_root(&leaves[k..]))
        }
    }
}

/// Audit path for leaf `index` (RFC 9162 section 2.1.3.1).
pub fn audit_path(index: usize, leaves: &[Vec<u8>]) -> Vec<[u8; 32]> {
    let n = leaves.len();
    if n <= 1 {
        return Vec::new();
    }
    let k = split(n);
    if index < k {
        let mut p = audit_path(index, &leaves[..k]);
        p.push(merkle_root(&leaves[k..]));
        p
    } else {
        let mut p = audit_path(index - k, &leaves[k..]);
        p.push(merkle_root(&leaves[..k]));
        p
    }
}

/// Verify an inclusion proof (RFC 9162 section 2.1.3.2).
pub fn verify_inclusion(
    leaf_hash: &[u8; 32],
    leaf_index: u64,
    tree_size: u64,
    path: &[[u8; 32]],
    root: &[u8; 32],
) -> bool {
    if leaf_index >= tree_size {
        return false;
    }
    let mut fnode = leaf_index;
    let mut snode = tree_size - 1;
    let mut r = *leaf_hash;
    for p in path {
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            r = hash_children(p, &r);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            r = hash_children(&r, p);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    snode == 0 && &r == root
}

/// Checkpoint payload (`application/atep-checkpoint+cbor`): text keys
/// `tree-size`, `root-hash`, `timestamp`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub tree_size: i64,
    pub root_hash: [u8; 32],
    pub timestamp: i64,
}

impl Checkpoint {
    pub fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::text("tree-size"), Value::Int(self.tree_size)),
            (Value::text("root-hash"), Value::bytes(&self.root_hash)),
            (Value::text("timestamp"), Value::Int(self.timestamp)),
        ])
    }

    pub fn encode(&self) -> Vec<u8> {
        self.to_value().encode()
    }

    pub fn from_value(v: &Value) -> Result<Checkpoint, SchemaError> {
        let (mut size, mut root, mut ts) = (None, None, None);
        for (k, val) in text_entries(v)? {
            match k {
                "tree-size" => size = Some(uint(val, "tree-size")?),
                "root-hash" => root = Some(fixed_bytes::<32>(val, "root-hash")?),
                "timestamp" => ts = Some(uint(val, "timestamp")?),
                other => return schema(format!("unknown field `{other}`")),
            }
        }
        let need = |n: &str| SchemaError(format!("missing field `{n}`"));
        Ok(Checkpoint {
            tree_size: size.ok_or_else(|| need("tree-size"))?,
            root_hash: root.ok_or_else(|| need("root-hash"))?,
            timestamp: ts.ok_or_else(|| need("timestamp"))?,
        })
    }

    pub fn from_payload(payload: &[u8]) -> Result<Checkpoint, SchemaError> {
        let v = Value::decode(payload).map_err(|e| SchemaError(e.to_string()))?;
        Checkpoint::from_value(&v)
    }

    /// The canonical [`checkpoint_hash`] of this checkpoint.
    pub fn hash(&self) -> [u8; 32] {
        checkpoint_hash(&self.encode())
    }
}

/// Canonical checkpoint hash: `SHA-256` of the checkpoint payload bytes, the
/// deterministic CBOR map `{tree-size, root-hash, timestamp}` that the log
/// signs under `application/atep-checkpoint+cbor`. This is the value an
/// anchor commits to (anchoring hooks, spec section 9). Pass the payload exactly as signed.
pub fn checkpoint_hash(payload: &[u8]) -> [u8; 32] {
    Sha256::digest(payload).into()
}

/// Sign a checkpoint as the log identity.
pub fn create_checkpoint(
    log: &Identity,
    cp: &Checkpoint,
    nonce: [u8; 16],
    mode: SignMode,
) -> Result<Vec<u8>, AtepError> {
    let payload = cp.encode();
    let mut p = SignParams::new(&payload, CT_CHECKPOINT, nonce, cp.timestamp);
    p.mode = mode;
    sign(log, &p)
}

/// The inclusion proof of spec section 9, carried under `-70012`: text keys
/// `leaf-index`, `audit-path` and `checkpoint` (the signed checkpoint envelope
/// embedded as a CBOR value).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InclusionProof {
    pub leaf_index: i64,
    pub audit_path: Vec<[u8; 32]>,
    pub checkpoint: Value,
}

impl InclusionProof {
    pub fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::text("leaf-index"), Value::Int(self.leaf_index)),
            (
                Value::text("audit-path"),
                Value::Array(self.audit_path.iter().map(|h| Value::bytes(h)).collect()),
            ),
            (Value::text("checkpoint"), self.checkpoint.clone()),
        ])
    }

    pub fn from_value(v: &Value) -> Result<InclusionProof, SchemaError> {
        let (mut idx, mut path, mut cp) = (None, None, None);
        for (k, val) in text_entries(v)? {
            match k {
                "leaf-index" => idx = Some(uint(val, "leaf-index")?),
                "audit-path" => {
                    let Some(a) = val.as_array() else {
                        return schema("`audit-path` must be an array");
                    };
                    path = Some(
                        a.iter()
                            .map(|h| fixed_bytes::<32>(h, "audit-path entry"))
                            .collect::<Result<Vec<_>, _>>()?,
                    );
                }
                "checkpoint" => cp = Some(val.clone()),
                other => return schema(format!("unknown field `{other}`")),
            }
        }
        let need = |n: &str| SchemaError(format!("missing field `{n}`"));
        Ok(InclusionProof {
            leaf_index: idx.ok_or_else(|| need("leaf-index"))?,
            audit_path: path.ok_or_else(|| need("audit-path"))?,
            checkpoint: cp.ok_or_else(|| need("checkpoint"))?,
        })
    }
}

/// The checkpoint a verifier relied on (verification step 10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointUsed {
    pub log: AgentId,
    pub tree_size: i64,
    pub root_hash: [u8; 32],
    pub timestamp: i64,
}

/// Checks that an attestation is included in a log. The M3 log service
/// (`atep-log`) provides implementations that look the leaf up in the log or
/// fetch the proof from a remote one.
///
/// `submitted` is the attestation envelope as submitted to the log (without its
/// `-70012` header); `proof` is the value of that header, if any.
pub trait InclusionCheck {
    fn check(
        &self,
        submitted: &[u8],
        proof: Option<&Value>,
        now: i64,
    ) -> Result<CheckpointUsed, Rejection>;
}

/// Offline checker: the proof carries its checkpoint; the checkpoint must be
/// signed by one of the trusted logs.
#[derive(Default, Clone)]
pub struct OfflineInclusion {
    pub trusted_logs: Vec<AgentId>,
    /// Bundles of logs that do not inline theirs.
    pub known_bundles: Vec<PublicBundle>,
}

fn bad(code: ErrorCode, msg: impl Into<String>) -> Rejection {
    Rejection::new(9, code, msg)
}

impl OfflineInclusion {
    /// Verify a checkpoint envelope: steps 1 to 8, content type, a trusted
    /// signer and the checkpoint schema.
    pub fn load_checkpoint(&self, raw: &[u8], now: i64) -> Result<CheckpointUsed, Rejection> {
        let policy = Policy {
            known_bundles: self.known_bundles.clone(),
            ..Policy::default()
        };
        let v = verify(raw, &policy, now).map_err(|e| {
            bad(
                ErrorCode::InclusionProofInvalid,
                "checkpoint envelope failed verification",
            )
            .with_cause(e)
        })?;
        if v.content_type != CT_CHECKPOINT {
            return Err(bad(
                ErrorCode::InclusionProofInvalid,
                "checkpoint has the wrong content type",
            ));
        }
        if !self.trusted_logs.contains(&v.signer) {
            return Err(bad(
                ErrorCode::CheckpointUntrusted,
                format!("checkpoint signer {} is not a trusted log", v.signer),
            ));
        }
        let cp = Checkpoint::from_payload(&v.payload)
            .map_err(|e| bad(ErrorCode::CheckpointSchemaInvalid, e.0))?;
        Ok(CheckpointUsed {
            log: v.signer,
            tree_size: cp.tree_size,
            root_hash: cp.root_hash,
            timestamp: cp.timestamp,
        })
    }
}

impl InclusionCheck for OfflineInclusion {
    fn check(
        &self,
        submitted: &[u8],
        proof: Option<&Value>,
        now: i64,
    ) -> Result<CheckpointUsed, Rejection> {
        let proof = proof.ok_or_else(|| {
            bad(
                ErrorCode::InclusionProofMissing,
                "attestation carries no inclusion proof (-70012)",
            )
        })?;
        let p = InclusionProof::from_value(proof)
            .map_err(|e| bad(ErrorCode::InclusionProofInvalid, e.0))?;
        let used = self.load_checkpoint(&p.checkpoint.encode(), now)?;
        let ok = verify_inclusion(
            &hash_leaf(submitted),
            p.leaf_index as u64,
            used.tree_size as u64,
            &p.audit_path,
            &used.root_hash,
        );
        if !ok {
            return Err(bad(
                ErrorCode::InclusionProofInvalid,
                "audit path does not lead to the checkpoint root hash",
            ));
        }
        Ok(used)
    }
}

// ---------------------------------------------------------------------------
// Tree functions over leaf hashes, consistency proofs (RFC 9162 section 2.1.4)

/// Merkle Tree Hash over already hashed leaves (`hash_leaf` outputs).
pub fn root_of_hashes(h: &[[u8; 32]]) -> [u8; 32] {
    match h.len() {
        0 => Sha256::digest([]).into(),
        1 => h[0],
        n => {
            let k = split(n);
            hash_children(&root_of_hashes(&h[..k]), &root_of_hashes(&h[k..]))
        }
    }
}

/// Audit path for leaf `index` over hashed leaves.
pub fn audit_path_of_hashes(index: usize, h: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let n = h.len();
    if n <= 1 {
        return Vec::new();
    }
    let k = split(n);
    if index < k {
        let mut p = audit_path_of_hashes(index, &h[..k]);
        p.push(root_of_hashes(&h[k..]));
        p
    } else {
        let mut p = audit_path_of_hashes(index - k, &h[k..]);
        p.push(root_of_hashes(&h[..k]));
        p
    }
}

fn subproof(m: usize, h: &[[u8; 32]], complete: bool, out: &mut Vec<[u8; 32]>) {
    let n = h.len();
    if m == n {
        if !complete {
            out.push(root_of_hashes(h));
        }
        return;
    }
    let k = split(n);
    if m <= k {
        subproof(m, &h[..k], complete, out);
        out.push(root_of_hashes(&h[k..]));
    } else {
        subproof(m - k, &h[k..], false, out);
        out.push(root_of_hashes(&h[..k]));
    }
}

/// Consistency proof between the first `first` leaves and all of `h`
/// (RFC 9162 section 2.1.4.1). Empty for `first` of 0 or `h.len()`.
pub fn consistency_proof(first: usize, h: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut out = Vec::new();
    if first == 0 || first >= h.len() {
        return out;
    }
    subproof(first, h, true, &mut out);
    out
}

/// Verify a consistency proof (RFC 9162 section 2.1.4.2): the tree of size
/// `second` with root `second_hash` extends the tree of size `first` with
/// root `first_hash`.
pub fn verify_consistency(
    first: u64,
    second: u64,
    first_hash: &[u8; 32],
    second_hash: &[u8; 32],
    proof: &[[u8; 32]],
) -> bool {
    if first > second {
        return false;
    }
    if first == second {
        return proof.is_empty() && first_hash == second_hash;
    }
    if first == 0 {
        // Every tree extends the empty tree.
        let empty: [u8; 32] = Sha256::digest([]).into();
        return proof.is_empty() && first_hash == &empty;
    }
    let mut path: Vec<[u8; 32]> = Vec::with_capacity(proof.len() + 1);
    if first.is_power_of_two() {
        path.push(*first_hash);
    }
    path.extend_from_slice(proof);
    if path.is_empty() {
        return false;
    }
    let mut fnode = first - 1;
    let mut snode = second - 1;
    while fnode & 1 == 1 {
        fnode >>= 1;
        snode >>= 1;
    }
    let mut fr = path[0];
    let mut sr = path[0];
    for c in &path[1..] {
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            fr = hash_children(c, &fr);
            sr = hash_children(c, &sr);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            sr = hash_children(&sr, c);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    snode == 0 && &fr == first_hash && &sr == second_hash
}

/// A consistency proof as exchanged between a log and its monitors: text keys
/// `from`, `to`, `path` (provisional layout, see docs/implementation-findings/rust-findings.md).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsistencyProof {
    pub from: i64,
    pub to: i64,
    pub path: Vec<[u8; 32]>,
}

impl ConsistencyProof {
    pub fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::text("from"), Value::Int(self.from)),
            (Value::text("to"), Value::Int(self.to)),
            (
                Value::text("path"),
                Value::Array(self.path.iter().map(|h| Value::bytes(h)).collect()),
            ),
        ])
    }

    pub fn from_value(v: &Value) -> Result<ConsistencyProof, SchemaError> {
        let (mut from, mut to, mut path) = (None, None, None);
        for (k, val) in text_entries(v)? {
            match k {
                "from" => from = Some(uint(val, "from")?),
                "to" => to = Some(uint(val, "to")?),
                "path" => {
                    let Some(a) = val.as_array() else {
                        return schema("`path` must be an array");
                    };
                    path = Some(
                        a.iter()
                            .map(|h| fixed_bytes::<32>(h, "path entry"))
                            .collect::<Result<Vec<_>, _>>()?,
                    );
                }
                other => return schema(format!("unknown field `{other}`")),
            }
        }
        let need = |n: &str| SchemaError(format!("missing field `{n}`"));
        Ok(ConsistencyProof {
            from: from.ok_or_else(|| need("from"))?,
            to: to.ok_or_else(|| need("to"))?,
            path: path.ok_or_else(|| need("path"))?,
        })
    }
}

fn pair_value(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (Value::text(k), v))
            .collect(),
    )
}

fn parse_pair(
    v: &Value,
    names: [&str; 2],
) -> Result<([Value; 2], Option<ConsistencyProof>), SchemaError> {
    let (mut a, mut b, mut proof) = (None, None, None);
    for (k, val) in text_entries(v)? {
        if k == names[0] {
            a = Some(val.clone());
        } else if k == names[1] {
            b = Some(val.clone());
        } else if k == "proof" {
            proof = Some(ConsistencyProof::from_value(val)?);
        } else {
            return schema(format!("unknown field `{k}`"));
        }
    }
    let need = |n: &str| SchemaError(format!("missing field `{n}`"));
    Ok((
        [
            a.ok_or_else(|| need(names[0]))?,
            b.ok_or_else(|| need(names[1]))?,
        ],
        proof,
    ))
}

/// Two checkpoints of one log plus the proof that the later extends the
/// earlier: CBOR map `{old, new, proof}` with the checkpoint envelopes
/// embedded as CBOR values. This is the document of the `consistency` vectors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsistencyEvidence {
    pub old: Value,
    pub new: Value,
    pub proof: ConsistencyProof,
}

impl ConsistencyEvidence {
    pub fn to_value(&self) -> Value {
        pair_value(vec![
            ("old", self.old.clone()),
            ("new", self.new.clone()),
            ("proof", self.proof.to_value()),
        ])
    }

    pub fn from_value(v: &Value) -> Result<ConsistencyEvidence, SchemaError> {
        let ([old, new], proof) = parse_pair(v, ["old", "new"])?;
        Ok(ConsistencyEvidence {
            old,
            new,
            proof: proof.ok_or_else(|| SchemaError("missing field `proof`".into()))?,
        })
    }
}

/// Two signed checkpoints received from (supposedly) one log, with an
/// optional consistency proof, for gossip comparison: CBOR map `{a, b, proof?}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointPair {
    pub a: Value,
    pub b: Value,
    pub proof: Option<ConsistencyProof>,
}

impl CheckpointPair {
    pub fn to_value(&self) -> Value {
        let mut e = vec![("a", self.a.clone()), ("b", self.b.clone())];
        if let Some(p) = &self.proof {
            e.push(("proof", p.to_value()));
        }
        pair_value(e)
    }

    pub fn from_value(v: &Value) -> Result<CheckpointPair, SchemaError> {
        let ([a, b], proof) = parse_pair(v, ["a", "b"])?;
        Ok(CheckpointPair { a, b, proof })
    }
}

fn consistency_bad(msg: impl Into<String>) -> Rejection {
    bad(ErrorCode::ConsistencyProofInvalid, msg)
}

impl OfflineInclusion {
    /// Check that `new` extends `old`: both are checkpoints of the same
    /// trusted log and the proof leads from the old root to the new one.
    pub fn check_consistency(
        &self,
        ev: &ConsistencyEvidence,
        now: i64,
    ) -> Result<(CheckpointUsed, CheckpointUsed), Rejection> {
        let old = self.load_checkpoint(&ev.old.encode(), now)?;
        let new = self.load_checkpoint(&ev.new.encode(), now)?;
        if old.log != new.log {
            return Err(consistency_bad(
                "the checkpoints are signed by different logs",
            ));
        }
        if new.tree_size < old.tree_size {
            return Err(consistency_bad("the tree shrank between the checkpoints"));
        }
        if ev.proof.from != old.tree_size || ev.proof.to != new.tree_size {
            return Err(consistency_bad(
                "the proof sizes do not match the checkpoint tree sizes",
            ));
        }
        if !verify_consistency(
            old.tree_size as u64,
            new.tree_size as u64,
            &old.root_hash,
            &new.root_hash,
            &ev.proof.path,
        ) {
            return Err(consistency_bad(
                "the proof does not lead from the old root to the new root",
            ));
        }
        Ok((old, new))
    }

    /// Compare two checkpoints claimed to come from one log. Same tree size
    /// with different roots, or a failing consistency proof, is a split view
    /// (`split_view_detected`); two checkpoints that agree return `Ok`.
    pub fn check_split_view(
        &self,
        pair: &CheckpointPair,
        now: i64,
    ) -> Result<(CheckpointUsed, CheckpointUsed), Rejection> {
        let a = self.load_checkpoint(&pair.a.encode(), now)?;
        let b = self.load_checkpoint(&pair.b.encode(), now)?;
        if a.log != b.log {
            return Err(consistency_bad(
                "the checkpoints are signed by different logs",
            ));
        }
        let split = |msg: String| bad(ErrorCode::SplitViewDetected, msg);
        if a.tree_size == b.tree_size {
            if a.root_hash != b.root_hash {
                return Err(split(format!(
                    "two signed checkpoints of tree size {} carry different root hashes",
                    a.tree_size
                )));
            }
            return Ok((a, b));
        }
        let (small, large) = if a.tree_size < b.tree_size {
            (&a, &b)
        } else {
            (&b, &a)
        };
        let Some(proof) = &pair.proof else {
            return Err(consistency_bad(
                "checkpoints of different sizes need a consistency proof",
            ));
        };
        if proof.from != small.tree_size || proof.to != large.tree_size {
            return Err(consistency_bad(
                "the proof sizes do not match the checkpoint tree sizes",
            ));
        }
        if !verify_consistency(
            small.tree_size as u64,
            large.tree_size as u64,
            &small.root_hash,
            &large.root_hash,
            &proof.path,
        ) {
            return Err(split(format!(
                "the checkpoint of size {} is not a prefix of the one of size {}",
                small.tree_size, large.tree_size
            )));
        }
        Ok((a, b))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Seeds;

    fn leaves(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(|i| format!("leaf {i}").into_bytes()).collect()
    }

    #[test]
    fn rfc6962_known_root() {
        // Single leaf and the empty tree.
        assert_eq!(merkle_root(&[]), <[u8; 32]>::from(Sha256::digest([])));
        let one = vec![b"x".to_vec()];
        assert_eq!(merkle_root(&one), hash_leaf(b"x"));
        let two = vec![b"a".to_vec(), b"b".to_vec()];
        assert_eq!(
            merkle_root(&two),
            hash_children(&hash_leaf(b"a"), &hash_leaf(b"b"))
        );
    }

    #[test]
    fn inclusion_proofs_for_all_sizes() {
        for n in 1..=17 {
            let ls = leaves(n);
            let root = merkle_root(&ls);
            for i in 0..n {
                let path = audit_path(i, &ls);
                assert!(
                    verify_inclusion(&hash_leaf(&ls[i]), i as u64, n as u64, &path, &root),
                    "n={n} i={i}"
                );
                // wrong index, wrong leaf and truncated path fail
                if n > 1 {
                    let j = (i + 1) % n;
                    assert!(!verify_inclusion(
                        &hash_leaf(&ls[i]),
                        j as u64,
                        n as u64,
                        &path,
                        &root
                    ));
                }
                assert!(!verify_inclusion(
                    &hash_leaf(b"other"),
                    i as u64,
                    n as u64,
                    &path,
                    &root
                ));
                if !path.is_empty() {
                    assert!(!verify_inclusion(
                        &hash_leaf(&ls[i]),
                        i as u64,
                        n as u64,
                        &path[1..],
                        &root
                    ));
                }
            }
        }
    }

    fn log_identity() -> Identity {
        Identity::from_seeds(Seeds {
            ed25519: [41; 32],
            mldsa65: [42; 32],
            x25519: None,
            mlkem768: None,
        })
        .unwrap()
    }

    fn proof_for(submitted: &[u8], log: &Identity, now: i64) -> Value {
        let mut ls = leaves(5);
        ls[3] = submitted.to_vec();
        let cp = Checkpoint {
            tree_size: 5,
            root_hash: merkle_root(&ls),
            timestamp: now - 10,
        };
        let env = create_checkpoint(log, &cp, [1; 16], SignMode::Deterministic).unwrap();
        InclusionProof {
            leaf_index: 3,
            audit_path: audit_path(3, &ls),
            checkpoint: Value::decode(&env).unwrap(),
        }
        .to_value()
    }

    #[test]
    fn offline_checker() {
        let log = log_identity();
        let checker = OfflineInclusion {
            trusted_logs: vec![log.agent_id()],
            known_bundles: vec![],
        };
        // checkpoint envelope has its bundle inline
        let proof = proof_for(b"submitted attestation", &log, 1_000);
        let used = checker
            .check(b"submitted attestation", Some(&proof), 1_000)
            .unwrap();
        assert_eq!(used.tree_size, 5);
        assert_eq!(used.log, log.agent_id());
        // altered envelope
        let e = checker
            .check(b"submitted attestation!", Some(&proof), 1_000)
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::InclusionProofInvalid);
        // missing proof
        let e = checker.check(b"x", None, 1_000).unwrap_err();
        assert_eq!(e.code, ErrorCode::InclusionProofMissing);
        // untrusted log
        let other = OfflineInclusion::default();
        let e = other
            .check(b"submitted attestation", Some(&proof), 1_000)
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::CheckpointUntrusted);
        // garbage proof
        let e = checker
            .check(b"x", Some(&Value::Int(1)), 1_000)
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::InclusionProofInvalid);
    }

    fn hashed(n: usize) -> Vec<[u8; 32]> {
        leaves(n).iter().map(|l| hash_leaf(l)).collect()
    }

    #[test]
    fn hash_functions_match_leaf_input_functions() {
        for n in 0..=12 {
            assert_eq!(root_of_hashes(&hashed(n)), merkle_root(&leaves(n)));
        }
        for i in 0..9 {
            assert_eq!(
                audit_path_of_hashes(i, &hashed(9)),
                audit_path(i, &leaves(9))
            );
        }
    }

    #[test]
    fn consistency_proofs_for_all_size_pairs() {
        let all = hashed(24);
        for n in 1..=24 {
            for m in 0..=n {
                let proof = consistency_proof(m, &all[..n]);
                let old = root_of_hashes(&all[..m]);
                let new = root_of_hashes(&all[..n]);
                assert!(
                    verify_consistency(m as u64, n as u64, &old, &new, &proof),
                    "m={m} n={n}"
                );
                if m > 0 && m < n {
                    // wrong old root, wrong new root, flipped and truncated path
                    let other = hash_leaf(b"other");
                    assert!(!verify_consistency(
                        m as u64, n as u64, &other, &new, &proof
                    ));
                    assert!(!verify_consistency(
                        m as u64, n as u64, &old, &other, &proof
                    ));
                    let mut flipped = proof.clone();
                    flipped[0][0] ^= 1;
                    assert!(!verify_consistency(
                        m as u64, n as u64, &old, &new, &flipped
                    ));
                    assert!(!verify_consistency(
                        m as u64,
                        n as u64,
                        &old,
                        &new,
                        &proof[1..]
                    ));
                    let mut longer = proof.clone();
                    longer.push(other);
                    assert!(!verify_consistency(m as u64, n as u64, &old, &new, &longer));
                }
            }
        }
        // a rewritten history is not consistent
        let mut forged = hashed(10);
        forged[2] = hash_leaf(b"rewritten");
        let proof = consistency_proof(5, &forged);
        assert!(!verify_consistency(
            5,
            10,
            &root_of_hashes(&hashed(5)),
            &root_of_hashes(&forged),
            &proof
        ));
    }
}
