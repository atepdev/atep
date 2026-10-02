"""Attestation constants and the section 7 schema plus claim rules (shared by core and policy)."""
from .core_errors import Reject

CLAIMS = "https://atep.dev/claims/"
R = CLAIMS + "robotics/"
ISSUER_AUTH = CLAIMS + "issuer-authority"
RETIRED = CLAIMS + "retired"
SUCCESSOR = CLAIMS + "successor"
MAX_LIFETIME = 400 * 86400

AUDIT_BACKED = (CLAIMS + "audited", R + "safety-certified")


def expand_claim(c):
    return c if "://" in c else CLAIMS + c


def _bytes_n(v, n):
    return isinstance(v, bytes) and len(v) == n


def validate_attestation_payload(p):
    """Section 7 schema plus claim rules. Raises Reject(9, attestation_schema_invalid)."""
    def bad(why):
        raise Reject(9, "attestation_schema_invalid", detail=why)
    if not isinstance(p, dict):
        bad("not a map")
    allowed = {"subject", "issuer", "claim", "data", "evidence", "evidence-uri", "id"}
    if not set(p.keys()) <= allowed:
        bad("unknown key")
    for k in ("subject", "issuer", "claim", "data", "id"):
        if k not in p:
            bad("missing " + k)
    if not (_bytes_n(p["subject"], 32) and _bytes_n(p["issuer"], 32) and isinstance(p["claim"], str)
            and isinstance(p["data"], dict) and all(isinstance(k, str) for k in p["data"])
            and _bytes_n(p["id"], 16)):
        bad("type")
    if "evidence" in p and not _bytes_n(p["evidence"], 32):
        bad("evidence type")
    if "evidence-uri" in p and not isinstance(p["evidence-uri"], str):
        bad("evidence-uri type")
    if p["claim"] in AUDIT_BACKED and "evidence" not in p:
        bad("evidence required")
    if p["claim"] == ISSUER_AUTH:
        cl = p["data"].get("claims")
        if not (isinstance(cl, list) and all(isinstance(x, str) for x in cl)):
            bad("issuer-authority needs data.claims")
    if p["claim"] == RETIRED and p["subject"] != p["issuer"]:
        bad("retired: subject must equal issuer")
    if p["claim"] == SUCCESSOR and p["subject"] == p["issuer"]:
        bad("successor: subject must differ from issuer")
    if p["claim"] in (RETIRED, SUCCESSOR) and "reason" in p["data"] and not isinstance(p["data"]["reason"], str):
        bad("reason must be text")


