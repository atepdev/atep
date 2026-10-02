"""Signed revocation lists (spec section 8)."""
from . import cbor, identity
from . import envelope as E
from .core import Reject, verify_signed, _is_int


def _uint(v):
    return _is_int(v) and v >= 0


def parse_srl_payload(payload):
    try:
        p = cbor.loads(payload)
    except cbor.CborError:
        raise Reject(9, "srl_schema_invalid", detail="payload not CBOR")
    if not (isinstance(p, dict) and set(p.keys()) == {"issuer", "sequence", "issued-at", "next-update", "revoked"}):
        raise Reject(9, "srl_schema_invalid", detail="keys")
    if not (isinstance(p["issuer"], bytes) and len(p["issuer"]) == 32 and _uint(p["sequence"])
            and _uint(p["issued-at"]) and _uint(p["next-update"]) and isinstance(p["revoked"], list)):
        raise Reject(9, "srl_schema_invalid", detail="types")
    if p["next-update"] <= p["issued-at"]:
        raise Reject(9, "srl_schema_invalid", detail="next-update")
    entries = []
    for e in p["revoked"]:
        if not (isinstance(e, dict) and set(e.keys()) == {"id", "reason", "revoked-at"}
                and isinstance(e["id"], bytes) and len(e["id"]) in (16, 32)
                and isinstance(e["reason"], str) and _uint(e["revoked-at"])):
            raise Reject(9, "srl_schema_invalid", detail="entry")
        entries.append((e["id"], e["reason"], e["revoked-at"]))
    return p, entries


def stale_warning(issuer_id, next_update):
    return "SRL of %s is past next-update %d; using the stale copy" % (identity.agent_id_text(issuer_id), next_update)


def load_srl(data, ctx, on_stale="fail-closed"):
    """Verify and load an SRL into ctx.srl_cache. Returns (entry, warnings). Raises Reject."""
    raw = bytes(data)
    cur = ctx.srl_cache
    for e in cur.values():
        if e["raw"] == raw:
            return e, []          # exactly the bytes already cached: accepted, no change (section 8)
    c = ctx.derive(check_replay=False, recipient=None, detached_payload=None, atep_r=False)
    s = verify_signed(raw, c, allow_encrypted=False)
    if s.content_type != E.CT_SRL:
        raise Reject(9, "srl_schema_invalid", detail="content type")
    p, entries = parse_srl_payload(s.payload_bytes)
    if p["issuer"] != s.signer:
        raise Reject(9, "srl_issuer_mismatch")
    cached = ctx.srl_cache.get(p["issuer"])
    if cached is not None:
        if p["sequence"] < cached["sequence"]:
            raise Reject(9, "srl_rollback")
        if p["sequence"] == cached["sequence"] and cached["raw"] != raw:
            raise Reject(9, "srl_sequence_conflict")
    entry = {
        "raw": raw, "issuer": p["issuer"], "sequence": p["sequence"],
        "issued_at": p["issued-at"], "next_update": p["next-update"],
        "entries": entries,
        "attestation_ids": set(i for i, _, _ in entries if len(i) == 16),
        "identity_revocations": [(i, r, t) for i, r, t in entries if len(i) == 32],
    }
    warnings = []
    entry["stale"] = ctx.now >= entry["next_update"]
    if entry["stale"]:
        if on_stale == "fail-closed":
            raise Reject(9, "srl_stale")
        warnings.append(stale_warning(entry["issuer"], entry["next_update"]))
    ctx.srl_cache[p["issuer"]] = entry
    return entry, warnings


def describe(entry):
    out = []
    for i, r, t in entry["entries"]:
        if len(i) == 16:
            out.append({"kind": "attestation", "id_hex": i.hex(), "reason": r, "revoked_at": t})
        else:
            out.append({"kind": "identity", "id": identity.agent_id_text(i), "reason": r, "revoked_at": t})
    return out
