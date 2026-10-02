"""Top level verify(envelope, policy) returning the structured result of section 10."""
import hashlib

from . import cbor, identity
from . import envelope as E
from .core import Reject, Context, verify_signed
from . import srl as srlmod
from . import policy as pol


def context_from_json(p):
    """Build a Context from the `policy` object of a verification vector."""
    recipient = identity.Identity(p["recipient_seeds"]) if p.get("recipient_seeds") else None
    known = {}
    for h in p.get("known_bundles", []):
        try:
            pub = identity.PublicIdentity(cbor.loads(bytes.fromhex(h)))
            known[pub.agent_id] = pub.bundle_value
        except Exception:
            pass
    revs = []
    for r in p.get("revocations", []):
        revs.append((identity.parse_agent_id(r["id"]), r["reason"], r["revoked_at"]))
    detached = bytes.fromhex(p["detached_payload_hex"]) if p.get("detached_payload_hex") else None
    ctx = Context(p["now"], p.get("max_skew_secs", 300), recipient, known,
                  set(bytes.fromhex(n) for n in p.get("seen_nonces", [])), revs, detached,
                  attestations=[bytes.fromhex(h) for h in p.get("attestations", [])])
    trust = p.get("trust")
    ctx.atep_r = bool(trust and trust.get("atep_r"))
    return ctx


def verify(data, ctx, trust=None, extra_attestations=(), srls=()):
    """Returns the ok result dict; raises Reject on failure."""
    on_stale = (trust or {}).get("srl", {}).get("on_stale", "fail-closed")
    for raw in srls:
        srlmod.load_srl(raw, ctx, on_stale="fail-open")   # staleness is judged per lookup in step 9
    s = verify_signed(data, ctx)
    claims, cp, warnings = [], None, []
    if trust is not None:
        claims, cp, warnings = pol.evaluate(s.signer, None, s, ctx, trust, extra_attestations)
    res = {
        "ok": True,
        "signer": identity.agent_id_text(s.signer),
        "content_type": s.content_type,
        "issued_at": s.issued_at,
        "expires_at": s.expires_at,
        "nonce_hex": s.nonce.hex(),
        "encrypted": s.encrypted,
        "claims": claims,
        "checkpoint": cp,
    }
    if warnings:
        res["warnings"] = warnings
    if s.command_class is not None:
        res["command_class"] = s.command_class
    res["payload_hex"] = s.payload_bytes.hex()
    return res


def verify_json(data, p):
    """Run verification with a vector `policy` object; never raises Reject."""
    try:
        ctx = context_from_json(p)
        return verify(data, ctx, p.get("trust"),
                      [bytes.fromhex(h) for h in p.get("attestations", [])],
                      [bytes.fromhex(h) for h in p.get("srls", [])])
    except Reject as r:
        return r.as_dict()
