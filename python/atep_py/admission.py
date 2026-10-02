"""Log admission, restricted to the `registry-endpoint` claim (spec sections 7 and 9).

Atep-py has no log. This module implements the admission rules of section 9 only as far as a submitted
`registry-endpoint` attestation needs them, as a pure function of the submission bytes: no log state, no
resubmission, no SRL or retirement store. Other claims are outside its scope."""
import re
import unicodedata

from . import cbor
from . import envelope as E
from .core import Reject, Context, verify_signed
from .claims import CLAIMS, MAX_LIFETIME, validate_attestation_payload

REGISTRY_ENDPOINT = CLAIMS + "registry-endpoint"
CORE_CLAIMS = frozenset(CLAIMS + n for n in (
    "domain-control", "operator", "successor", "retired", "issuer-authority", "audited", "registry-endpoint",
    "robotics/fleet-member", "robotics/fleet-controller", "robotics/safety-certified",
    "robotics/sensor-source", "robotics/safety-authority", "robotics/maintenance-authority",
    "robotics/peer-motion"))
ENDPOINT_KINDS = ("registry", "verifier", "mcp", "a2a")
_EXT_KIND = re.compile(r"x-[a-z0-9-]+")
MAX_URL = 2048


def _bad_char(c):
    return c.isspace() or unicodedata.category(c) in ("Cc", "Cf", "Zs", "Zl", "Zp")


def valid_endpoint_url(url):
    """`https` (lowercase) URL of at most 2,048 characters with a host, no credentials, no whitespace or control."""
    if not (isinstance(url, str) and len(url) <= MAX_URL and url.startswith("https://")):
        return False
    if any(_bad_char(c) for c in url):
        return False
    rest = url[len("https://"):]
    end = len(rest)
    for ch in "/?#":
        i = rest.find(ch)
        if i != -1:
            end = min(end, i)
    authority = rest[:end]
    if "@" in authority:
        return False
    if authority.startswith("["):
        j = authority.find("]")
        host = authority[:j + 1] if j != -1 else ""
    else:
        host = authority.split(":", 1)[0]
    return host != ""


def valid_endpoint_kind(kind):
    return isinstance(kind, str) and (kind in ENDPOINT_KINDS or _EXT_KIND.fullmatch(kind) is not None)


def check_registry_endpoint_data(data):
    """The `data` rule of section 7: True when `data.url` and `data.kind` are as defined."""
    return isinstance(data, dict) and valid_endpoint_url(data.get("url")) and valid_endpoint_kind(data.get("kind"))


def admit_registry_endpoint(raw, now, max_envelope_bytes):
    """Admission of one submitted attestation, in the order of the section 9 table, for the claim
    `registry-endpoint`. Returns {ok: True, document: attestation} or {ok: False, refusal, ...}."""
    def refuse(name, **kw):
        d = {"ok": False, "refusal": name}
        d.update(kw)
        return d
    if len(raw) > max_envelope_bytes:
        return refuse("too_large")
    try:
        value = cbor.loads(raw)
    except cbor.CborError:
        return refuse("malformed")
    if not (isinstance(value, cbor.Tag) and value.tag in (96, 98)):
        return refuse("malformed")
    if value.tag == 96:
        return refuse("encrypted_envelope")
    try:
        s = verify_signed(value, Context(now, check_replay=False), allow_encrypted=False)
    except Reject as r:
        if r.step == 1 and r.error in ("malformed_envelope",):
            return refuse("malformed")
        # the content type rule comes first in the table, but needs the protected header, which step 1 reads
        ct = _content_type(value)
        if ct is not None and ct != E.CT_ATTESTATION:
            return _ct_refusal(ct, refuse)
        return refuse("verification_failed", step=r.step, error=r.error)
    if s.content_type != E.CT_ATTESTATION:
        return _ct_refusal(s.content_type, refuse)
    try:
        p = cbor.loads(s.payload_bytes)
        validate_attestation_payload(p)
    except (cbor.CborError, Reject):
        return refuse("schema_invalid")
    if p["issuer"] != s.signer:
        return refuse("schema_invalid")
    if s.expires_at - s.issued_at > MAX_LIFETIME:
        return refuse("lifetime_exceeded")
    if p["claim"].startswith(CLAIMS) and p["claim"] not in CORE_CLAIMS:
        return refuse("claim_vocabulary")
    if p["claim"] == REGISTRY_ENDPOINT and not check_registry_endpoint_data(p["data"]):
        return refuse("schema_invalid")
    return {"ok": True, "document": "attestation"}


def _content_type(value):
    try:
        prot = cbor.loads(value.value[0])
        ct = prot.get(E.H_CT)
        return ct if isinstance(ct, str) else None
    except Exception:
        return None


def _ct_refusal(ct, refuse):
    if ct == E.CT_CHECKPOINT:
        return refuse("content_type_not_loggable")
    if ct == E.CT_SRL:
        return refuse("unsupported_here")        # SRL admission is outside this module
    return refuse("data_envelope")
