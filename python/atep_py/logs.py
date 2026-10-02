"""Transparency log: RFC 9162 Merkle proofs, checkpoints, inclusion, consistency, split view."""
import hashlib

from . import cbor, identity
from . import envelope as E
from .core import Reject, verify_signed, _is_int


def leaf_hash(leaf):
    return hashlib.sha256(b"\x00" + leaf).digest()


def node_hash(l, r):
    return hashlib.sha256(b"\x01" + l + r).digest()


def empty_root():
    return hashlib.sha256(b"").digest()


def verify_inclusion_path(leaf_h, index, size, path, root):
    """RFC 9162 section 2.1.3.2."""
    if index >= size:
        return False
    fn, sn = index, size - 1
    r = leaf_h
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(first, second, path, first_root, second_root):
    """RFC 9162 section 2.1.4.2, plus the first == 0 and equal size rules."""
    if first > second:
        return False
    if first == 0:
        return len(path) == 0 and first_root == empty_root()
    if first == second:
        return len(path) == 0 and first_root == second_root
    path = list(path)
    if first & (first - 1) == 0:
        path = [first_root] + path
    if not path:
        return False
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == first_root and sr == second_root and sn == 0


# ---- merkle tree helpers for tests / generation ----

def mth(leaves):
    n = len(leaves)
    if n == 0:
        return empty_root()
    if n == 1:
        return leaf_hash(leaves[0])
    k = 1
    while k * 2 < n:
        k *= 2
    return node_hash(mth(leaves[:k]), mth(leaves[k:]))


def audit_path(m, leaves):
    n = len(leaves)
    if n <= 1:
        return []
    k = 1
    while k * 2 < n:
        k *= 2
    if m < k:
        return audit_path(m, leaves[:k]) + [mth(leaves[k:])]
    return audit_path(m - k, leaves[k:]) + [mth(leaves[:k])]


def consistency_path(m, leaves):
    def sub(m, leaves, b):
        n = len(leaves)
        if m == n:
            return [] if b else [mth(leaves)]
        k = 1
        while k * 2 < n:
            k *= 2
        if m <= k:
            return sub(m, leaves[:k], b) + [mth(leaves[k:])]
        return sub(m - k, leaves[k:], False) + [mth(leaves[:k])]
    if m == 0 or m == len(leaves):
        return []
    return sub(m, leaves, True)


# ---- checkpoints ----

def checkpoint_dict(signer, payload):
    return {"log": identity.agent_id_text(signer), "tree_size": payload["tree-size"],
            "root_hash": payload["root-hash"].hex(), "timestamp": payload["timestamp"]}


def parse_checkpoint_payload(payload):
    try:
        p = cbor.loads(payload)
    except cbor.CborError:
        raise Reject(9, "checkpoint_schema_invalid")
    if not (isinstance(p, dict) and set(p.keys()) == {"tree-size", "root-hash", "timestamp"}
            and _is_int(p["tree-size"]) and p["tree-size"] >= 0
            and isinstance(p["root-hash"], bytes) and len(p["root-hash"]) == 32
            and _is_int(p["timestamp"]) and p["timestamp"] >= 0):
        raise Reject(9, "checkpoint_schema_invalid")
    return p


def check_checkpoint(cp, ctx, trusted_logs):
    """cp: bytes or decoded envelope value. Returns (signer, payload map)."""
    signer, p, _ = check_checkpoint_full(cp, ctx, trusted_logs)
    return signer, p


def check_checkpoint_full(cp, ctx, trusted_logs):
    """As check_checkpoint, also returning the verified payload bytes (the input of the checkpoint hash)."""
    c = ctx.derive(check_replay=False, recipient=None, detached_payload=None, atep_r=False)
    try:
        s = verify_signed(cp, c, allow_encrypted=False)
    except Reject as r:
        raise Reject(9, "inclusion_proof_invalid", cause={"step": r.step, "error": r.error})
    if s.content_type != E.CT_CHECKPOINT:
        raise Reject(9, "checkpoint_schema_invalid", detail="content type")
    if s.signer not in trusted_logs:
        raise Reject(9, "checkpoint_untrusted")
    p = parse_checkpoint_payload(s.payload_bytes)
    return s.signer, p, s.payload_bytes


def check_inclusion(att_value, ctx, trusted_logs):
    """att_value: decoded attestation envelope carrying -70012. Returns checkpoint dict."""
    proof = att_value.value[1].get(E.U_PROOF)
    if proof is None:
        raise Reject(9, "inclusion_proof_missing")
    if not (isinstance(proof, dict) and set(proof.keys()) == {"leaf-index", "audit-path", "checkpoint"}
            and _is_int(proof["leaf-index"]) and proof["leaf-index"] >= 0
            and isinstance(proof["audit-path"], list)
            and all(isinstance(h, bytes) and len(h) == 32 for h in proof["audit-path"])):
        raise Reject(9, "inclusion_proof_invalid", detail="proof structure")
    signer, p = check_checkpoint(proof["checkpoint"], ctx, trusted_logs)
    leaf = E.submitted_form(att_value)
    if not verify_inclusion_path(leaf_hash(leaf), proof["leaf-index"], p["tree-size"],
                                 proof["audit-path"], p["root-hash"]):
        raise Reject(9, "inclusion_proof_invalid")
    return checkpoint_dict(signer, p)


def _check_proof_struct(pr):
    return (isinstance(pr, dict) and set(pr.keys()) == {"from", "to", "path"}
            and _is_int(pr["from"]) and _is_int(pr["to"]) and pr["from"] >= 0 and pr["to"] >= 0
            and isinstance(pr["path"], list)
            and all(isinstance(h, bytes) and len(h) == 32 for h in pr["path"]))


def check_consistency(data, ctx, trusted_logs):
    try:
        m = cbor.loads(data)
    except cbor.CborError:
        raise Reject(9, "consistency_proof_invalid", detail="malformed")
    if not (isinstance(m, dict) and set(m.keys()) == {"old", "new", "proof"}):
        raise Reject(9, "consistency_proof_invalid", detail="structure")
    s_old, p_old = check_checkpoint(m["old"], ctx, trusted_logs)
    s_new, p_new = check_checkpoint(m["new"], ctx, trusted_logs)
    if s_old != s_new:
        raise Reject(9, "consistency_proof_invalid", detail="different logs")
    if p_new["tree-size"] < p_old["tree-size"]:
        raise Reject(9, "consistency_proof_invalid", detail="shrinking")
    pr = m["proof"]
    if not _check_proof_struct(pr):
        raise Reject(9, "consistency_proof_invalid", detail="proof structure")
    if pr["from"] != p_old["tree-size"] or pr["to"] != p_new["tree-size"]:
        raise Reject(9, "consistency_proof_invalid", detail="proof sizes")
    if not verify_consistency(pr["from"], pr["to"], pr["path"], p_old["root-hash"], p_new["root-hash"]):
        raise Reject(9, "consistency_proof_invalid")
    return {"old": checkpoint_dict(s_old, p_old), "new": checkpoint_dict(s_new, p_new)}


def check_split_view(data, ctx, trusted_logs):
    try:
        m = cbor.loads(data)
    except cbor.CborError:
        raise Reject(9, "consistency_proof_invalid", detail="malformed")
    if not (isinstance(m, dict) and set(m.keys()) <= {"a", "b", "proof"} and {"a", "b"} <= set(m.keys())):
        raise Reject(9, "consistency_proof_invalid", detail="structure")
    sa, pa = check_checkpoint(m["a"], ctx, trusted_logs)
    sb, pb = check_checkpoint(m["b"], ctx, trusted_logs)
    if sa != sb:
        raise Reject(9, "consistency_proof_invalid", detail="different logs")
    out = {"a": checkpoint_dict(sa, pa), "b": checkpoint_dict(sb, pb)}
    if pa["tree-size"] == pb["tree-size"]:
        if pa["root-hash"] != pb["root-hash"]:
            raise Reject(9, "split_view_detected")
        return out
    # order by size
    if pa["tree-size"] < pb["tree-size"]:
        small, large = pa, pb
    else:
        small, large = pb, pa
    pr = m.get("proof")
    if pr is None or not _check_proof_struct(pr):
        raise Reject(9, "consistency_proof_invalid", detail="missing proof")
    if pr["from"] != small["tree-size"] or pr["to"] != large["tree-size"]:
        raise Reject(9, "consistency_proof_invalid", detail="proof sizes")
    if not verify_consistency(pr["from"], pr["to"], pr["path"], small["root-hash"], large["root-hash"]):
        raise Reject(9, "split_view_detected")
    return out
