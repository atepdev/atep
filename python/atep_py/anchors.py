"""Anchoring (spec section 9): chain-id, checkpoint hash, anchor record, published anchor check,
and the `require_anchor` policy rules (section 7)."""
import hashlib
import re

from . import cbor, identity
from . import envelope as E
from .core import Reject, Context, verify_signed, _is_int

REGISTERED_CHAINS = ("solana-mainnet", "ethereum-mainnet", "bitcoin-mainnet", "opentimestamps", "rekor")
_EXT = re.compile(r"x-[a-z0-9]([a-z0-9-]*[a-z0-9])?")
MAX_U64 = 2 ** 64 - 1


def chain_id_kind(text):
    """'registered', 'extension' or None. A pure function of the text (section 9, chain-id registry)."""
    if not isinstance(text, str):
        return None
    if text in REGISTERED_CHAINS:
        return "registered"
    if len(text.encode("utf-8")) <= 64 and _EXT.fullmatch(text):
        return "extension"
    return None


def checkpoint_hash(payload_bytes):
    """SHA-256 of the checkpoint payload bytes (section 9)."""
    return hashlib.sha256(payload_bytes).digest()


# ---- anchor record ----

class AnchorRecordInvalid(Exception):
    pass


def _uint(v):
    return _is_int(v) and 0 <= v <= MAX_U64


def record_from_value(m):
    """Validate a decoded map; returns the record dict used in vector results."""
    if not isinstance(m, dict):
        raise AnchorRecordInvalid("not a map")
    required = {"checkpoint-hash", "chain-id", "transaction-id", "anchored-at"}
    keys = set(m.keys())
    if not (required <= keys <= required | {"block-height"}):
        raise AnchorRecordInvalid("keys")
    h = m["checkpoint-hash"]
    if not (isinstance(h, bytes) and len(h) == 32):
        raise AnchorRecordInvalid("checkpoint-hash")
    if chain_id_kind(m["chain-id"]) is None:
        raise AnchorRecordInvalid("chain-id")
    t = m["transaction-id"]
    if not (isinstance(t, str) and 1 <= len(t.encode("utf-8")) <= 512):
        raise AnchorRecordInvalid("transaction-id")
    if "block-height" in m and not _uint(m["block-height"]):
        raise AnchorRecordInvalid("block-height")
    if not _uint(m["anchored-at"]):
        raise AnchorRecordInvalid("anchored-at")
    return {"checkpoint_hash": h.hex(), "chain_id": m["chain-id"], "transaction_id": t,
            "block_height": m.get("block-height"), "anchored_at": m["anchored-at"]}


def decode_record(data):
    """Anchor record payload bytes (strict deterministic CBOR) to the record dict, or AnchorRecordInvalid."""
    try:
        m = cbor.loads(data)
    except cbor.CborError as e:
        raise AnchorRecordInvalid("cbor: %s" % e)
    return record_from_value(m)


def encode_record(rec):
    """Record dict (as returned by decode_record) to deterministic CBOR; no block-height key when None."""
    m = {"checkpoint-hash": bytes.fromhex(rec["checkpoint_hash"]), "chain-id": rec["chain_id"],
         "transaction-id": rec["transaction_id"], "anchored-at": rec["anchored_at"]}
    if rec.get("block_height") is not None:
        m["block-height"] = rec["block_height"]
    return cbor.dumps(m)


# ---- published anchor ----

def check_published_anchor(data, ctx, log, checkpoint_hash_hex):
    """A log-signed anchor envelope taken as published (section 9). In order: steps 1 to 8 (failure reported as
    it is), content type, record schema, signer is `log`, hash equals the checkpoint looked at.
    Returns {ok, log, record}; raises Reject."""
    c = ctx.derive(check_replay=False, recipient=None, detached_payload=None, atep_r=False)
    s = verify_signed(data, c, allow_encrypted=False)
    if s.content_type != E.CT_ANCHOR:
        raise Reject(9, "anchor_content_type_invalid")
    try:
        rec = decode_record(s.payload_bytes)
    except AnchorRecordInvalid:
        raise Reject(9, "anchor_schema_invalid")
    try:
        want = identity.parse_agent_id(log)
    except ValueError:
        raise Reject(9, "anchor_log_mismatch")
    if s.signer != want:
        raise Reject(9, "anchor_log_mismatch")
    if rec["checkpoint_hash"] != checkpoint_hash_hex:
        raise Reject(9, "anchor_checkpoint_mismatch")
    return {"ok": True, "log": identity.agent_id_text(s.signer), "record": rec}


# ---- require_anchor policy member ----

def parse_require_anchor(v):
    """The `require_anchor` array of a trust policy. Raises ValueError (a configuration error)."""
    if not isinstance(v, list):
        raise ValueError("require_anchor is not an array")
    rules = []
    for r in v:
        if not isinstance(r, dict):
            raise ValueError("rule is not an object")
        ages = [k for k in ("max_age_days", "max_age_hours") if k in r]
        if not (set(r) <= {"log", "chain", "max_age_days", "max_age_hours"} and "log" in r and "chain" in r
                and len(ages) == 1):
            raise ValueError("rule members")
        if not isinstance(r["log"], str):
            raise ValueError("log")
        log = identity.parse_agent_id(r["log"])
        if chain_id_kind(r["chain"]) is None:
            raise ValueError("chain")
        age = r[ages[0]]
        if not (_is_int(age) and 1 <= age <= MAX_U64):
            raise ValueError("age")
        rules.append({"log": identity.agent_id_text(log), "chain": r["chain"], ages[0]: age})
    return rules
