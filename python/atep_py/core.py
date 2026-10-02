"""Verification steps 1 to 8 (spec section 10) plus decryption."""
import hashlib

from . import cbor, ed25519, mldsa, mlkem, x25519, aesgcm, identity
from .cbor import Tag, CborError
from . import envelope as E
from .claims import RETIRED, MAX_LIFETIME, validate_attestation_payload


from .core_errors import Reject


ATEP_R_CLASSES = ("telemetry", "sensor", "coordination", "motion", "actuation", "safety", "maintenance")


class Context(object):
    """Everything steps 1 to 8 need."""

    def __init__(self, now, max_skew=300, recipient=None, known_bundles=None,
                 seen_nonces=None, revocations=None, detached_payload=None,
                 srl_cache=None, check_replay=True, atep_r=False, ignore_expiry=False,
                 attestations=None):
        self.now = now
        self.max_skew = max_skew
        self.recipient = recipient
        self.known_bundles = known_bundles or {}   # agent_id bytes -> bundle value
        self.seen_nonces = seen_nonces or set()
        self.revocations = revocations or []       # (agent_id bytes, reason, revoked_at)
        self.detached_payload = detached_payload
        self.srl_cache = srl_cache if srl_cache is not None else {}
        self.check_replay = check_replay
        self.atep_r = atep_r
        self.ignore_expiry = ignore_expiry
        # local attestation store (raw encoded envelopes); step 8 reads valid retirements from it
        self.attestations = attestations if attestations is not None else []
        self.retirement_cache = {}                 # shared by derived contexts

    def derive(self, **kw):
        c = Context(self.now, self.max_skew, self.recipient, self.known_bundles,
                    self.seen_nonces, self.revocations, self.detached_payload,
                    self.srl_cache, self.check_replay, self.atep_r, self.ignore_expiry,
                    self.attestations)
        c.retirement_cache = self.retirement_cache
        for k, v in kw.items():
            setattr(c, k, v)
        return c


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _decode(data):
    try:
        return cbor.loads(data)
    except CborError as e:
        raise Reject(1, "malformed_cbor", detail=str(e))


class Signed(object):
    pass


def check_signed(value, bare, ctx):
    """Step 1 for a tag 98 value. bare: not wrapped in tag 96 (encryption rule applies)."""
    if not (isinstance(value, Tag) and value.tag == 98):
        raise Reject(1, "not_signed_envelope")
    v = value.value
    if not (isinstance(v, list) and len(v) == 4):
        raise Reject(1, "malformed_envelope")
    body, unprot, payload, sigs = v
    if not (isinstance(body, bytes) and isinstance(unprot, dict)
            and (payload is None or isinstance(payload, bytes)) and isinstance(sigs, list)):
        raise Reject(1, "malformed_envelope")
    prot = _decode(body)
    if not isinstance(prot, dict):
        raise Reject(1, "malformed_envelope")
    if E.H_VER not in prot:
        raise Reject(1, "missing_field", detail="atep-version")
    if not (_is_int(prot[E.H_VER]) and prot[E.H_VER] == 1):
        raise Reject(1, "unsupported_version")
    if E.H_SUITE not in prot:
        raise Reject(1, "missing_field", detail="suite")
    if prot[E.H_SUITE] != E.SUITE:
        raise Reject(1, "unsupported_suite")
    ct = prot.get(E.H_CT)
    if not isinstance(ct, str):
        raise Reject(1, "missing_field", detail="content type")
    signer = prot.get(E.H_SIGNER)
    if not (isinstance(signer, bytes) and len(signer) == 32):
        raise Reject(1, "missing_field", detail="signer")
    if not _is_int(prot.get(E.H_IAT)):
        raise Reject(1, "missing_field", detail="issued-at")
    if E.H_EXP in prot and not _is_int(prot[E.H_EXP]):
        raise Reject(1, "invalid_field", detail="expires-at")
    nonce = prot.get(E.H_NONCE)
    if not (isinstance(nonce, bytes) and len(nonce) == 16):
        raise Reject(1, "missing_field", detail="nonce")
    digest = prot.get(E.H_DIGEST)
    if not (isinstance(digest, bytes) and len(digest) == 32):
        raise Reject(1, "missing_field", detail="payload-digest")
    if E.H_CLASS in prot and not isinstance(prot[E.H_CLASS], str):
        raise Reject(1, "invalid_field", detail="command-class")
    # signature shape
    if len(sigs) != 2:
        raise Reject(1, "signature_count_invalid")
    parsed = []
    for s in sigs:
        if not (isinstance(s, list) and len(s) == 3 and isinstance(s[0], bytes)
                and isinstance(s[1], dict) and len(s[1]) == 0 and isinstance(s[2], bytes)):
            raise Reject(1, "signature_shape_invalid")
        sp = _decode(s[0])
        if not (isinstance(sp, dict) and set(sp.keys()) == {1, 4} and _is_int(sp[1])
                and isinstance(sp[4], bytes) and len(sp[4]) == 32):
            raise Reject(1, "signature_shape_invalid")
        parsed.append((sp[1], sp[4], s[0], s[2]))
    algs = sorted(p[0] for p in parsed)
    if algs != sorted([E.ALG_EDDSA, E.ALG_MLDSA]):
        raise Reject(1, "signature_count_invalid", detail="algorithms do not match suite")
    if ct == E.CT_ATTESTATION and E.H_EXP not in prot:
        raise Reject(1, "missing_expires_at")
    if bare and ct not in E.TRUST_DOC_TYPES:
        raise Reject(1, "unencrypted_non_trust_document")
    if ctx is not None and ctx.atep_r:
        if bare:
            raise Reject(1, "atep_r_unencrypted")
        if E.H_CLASS not in prot:
            raise Reject(1, "missing_command_class")
        if prot[E.H_CLASS] not in ATEP_R_CLASSES:
            raise Reject(1, "unknown_command_class")
    s = Signed()
    s.value = value
    s.body = body
    s.prot = prot
    s.unprot = unprot
    s.payload = payload
    s.sigs = parsed
    s.content_type = ct
    s.signer = signer
    s.issued_at = prot[E.H_IAT]
    s.expires_at = prot.get(E.H_EXP)
    s.nonce = nonce
    s.digest = digest
    s.command_class = prot.get(E.H_CLASS)
    return s


def check_encrypted(value):
    """Step 1 for a tag 96 value; returns parsed parts."""
    v = value.value
    if not (isinstance(v, list) and len(v) == 4):
        raise Reject(1, "malformed_envelope")
    prot_b, unprot, ct, recips = v
    if not (isinstance(prot_b, bytes) and isinstance(unprot, dict) and isinstance(ct, bytes)
            and isinstance(recips, list)):
        raise Reject(1, "malformed_envelope")
    prot = _decode(prot_b)
    if not isinstance(prot, dict):
        raise Reject(1, "malformed_envelope")
    if E.H_VER not in prot:
        raise Reject(1, "missing_field", detail="atep-version")
    if not (_is_int(prot[E.H_VER]) and prot[E.H_VER] == 1):
        raise Reject(1, "unsupported_version")
    if E.H_SUITE not in prot:
        raise Reject(1, "missing_field", detail="suite")
    if prot[E.H_SUITE] != E.SUITE:
        raise Reject(1, "unsupported_suite")
    if not (_is_int(prot.get(1)) and prot[1] == E.ALG_A256GCM):
        raise Reject(1, "unsupported_content_algorithm")
    iv = unprot.get(5)
    if not (isinstance(iv, bytes) and len(iv) == 12):
        raise Reject(1, "malformed_envelope", detail="iv")
    if len(recips) != 1:
        raise Reject(1, "recipient_count_invalid")
    r = recips[0]
    if not (isinstance(r, list) and len(r) == 3 and isinstance(r[0], bytes)
            and isinstance(r[1], dict) and isinstance(r[2], bytes)):
        raise Reject(1, "malformed_envelope")
    rprot = _decode(r[0])
    if not (isinstance(rprot, dict) and rprot.get(1) == E.ALG_HYBRID_KEM and len(rprot) == 1):
        raise Reject(1, "unsupported_recipient_algorithm")
    return prot_b, iv, ct, r[1]


def decrypt(value, ctx):
    """Steps 1 (outer) and 2. Returns inner tag 98 value."""
    prot_b, iv, ct, ru = check_encrypted(value)
    if ctx.recipient is None or not getattr(ctx.recipient, "has_encryption_keys", False):
        raise Reject(2, "no_recipient_key")
    kid = ru.get(4)
    if kid != ctx.recipient.agent_id:
        raise Reject(2, "not_addressed_to_recipient")
    eph = ru.get(-1)
    kem_ct = ru.get(E.U_KEMCT)
    if not (isinstance(eph, dict) and set(eph.keys()) == {1, 3, -1, -2} and eph[1] == 1
            and eph[3] == -25 and eph[-1] == 4 and isinstance(eph[-2], bytes) and len(eph[-2]) == 32
            and isinstance(kem_ct, bytes) and len(kem_ct) == mlkem.CT_LEN):
        raise Reject(2, "kem_failure", detail="bad recipient header")
    ss_x = x25519.x25519(ctx.recipient.x_sk, eph[-2])
    if ss_x == bytes(32):
        raise Reject(2, "kem_failure", detail="all-zero shared secret")
    try:
        ss_pq = mlkem.decaps(ctx.recipient.kem_dk, kem_ct)
    except ValueError:
        raise Reject(2, "kem_failure")
    key = E.derive_key(ss_x, ss_pq, eph[-2], ctx.recipient.keys["x25519"], kem_ct)
    pt = aesgcm.decrypt(key, iv, ct, cbor.dumps(["Encrypt", prot_b, b""]))
    if pt is None:
        raise Reject(2, "aead_failure")
    inner = _decode(pt)
    return inner


def verify_signed(data, ctx, allow_encrypted=True):
    """Steps 1 to 8. data is bytes or a decoded value. Returns Signed (with .encrypted)."""
    value = _decode(data) if isinstance(data, (bytes, bytearray)) else data
    encrypted = False
    if isinstance(value, Tag) and value.tag == 96:
        if not allow_encrypted:
            raise Reject(1, "unexpected_encryption")
        encrypted = True
        inner = decrypt(value, ctx)
        s = check_signed(inner, False, ctx)
    elif isinstance(value, Tag) and value.tag == 98:
        s = check_signed(value, True, ctx)
    else:
        raise Reject(1, "not_atep_envelope")
    s.encrypted = encrypted
    _step3_to_8(s, ctx)
    return s


def _step3_to_8(s, ctx):
    _step3_to_7(s, ctx)
    # step 8
    for rid, reason, revoked_at in ctx.revocations:
        if rid == s.signer and revoked_at <= s.issued_at:
            raise Reject(8, "signer_revoked")
    for entry in ctx.srl_cache.values():
        for rid, reason, revoked_at in entry["identity_revocations"]:
            if rid == s.signer and revoked_at <= s.issued_at:
                raise Reject(8, "signer_revoked")
    if ctx.attestations and not _is_retirement_of(s, s.payload_bytes):
        t = retirement_instant(ctx, s.signer, s.bundle_value)
        if t is not None and t <= s.issued_at:
            raise Reject(8, "signer_revoked")


def _is_retirement_of(s, payload):
    """True when s is itself a `retired` attestation of its signer (exempt from the retirement rule)."""
    if s.content_type != E.CT_ATTESTATION:
        return False
    try:
        p = cbor.loads(payload)
    except CborError:
        return False
    return (isinstance(p, dict) and p.get("claim") == RETIRED
            and p.get("subject") == s.signer and p.get("issuer") == s.signer)


def retirement_instant(ctx, signer, fallback_bundle):
    """Smallest issued-at of a valid retirement of `signer` in the local store, or None."""
    best = None
    for idx, raw in enumerate(ctx.attestations):
        key = (idx, signer, fallback_bundle is not None)
        if key not in ctx.retirement_cache:
            ctx.retirement_cache[key] = _valid_retirement(raw, signer, ctx, fallback_bundle)
        t = ctx.retirement_cache[key]
        if t is not None and (best is None or t < best):
            best = t
    return best


def _valid_retirement(raw, x, ctx, fallback_bundle):
    """issued-at of a valid retirement of x held in `raw`, else None (an invalid entry is ignored)."""
    try:
        value = cbor.loads(raw)
        if not (isinstance(value, Tag) and value.tag == 98):
            return None
        c = ctx.derive(check_replay=False, recipient=None, detached_payload=None, atep_r=False,
                       ignore_expiry=True, attestations=[])
        s = check_signed(value, True, c)
        if s.signer != x or s.content_type != E.CT_ATTESTATION or s.payload is None:
            return None
        _step3_to_7(s, c, fallback_bundle)
        p = cbor.loads(s.payload_bytes)
        validate_attestation_payload(p)
        if p["claim"] != RETIRED or p["subject"] != x or p["issuer"] != x:
            return None
        if s.expires_at - s.issued_at > MAX_LIFETIME:
            return None
        return s.issued_at
    except (Reject, CborError):
        return None


def _step3_to_7(s, ctx, fallback_bundle=None):
    # step 3
    bv = s.unprot.get(E.U_BUNDLE)
    if bv is None:
        bv = ctx.known_bundles.get(s.signer)
        if bv is None:
            bv = fallback_bundle
        if bv is None:
            raise Reject(3, "signer_bundle_unavailable")
    try:
        pub = identity.PublicIdentity(bv)
    except identity.BundleError as e:
        raise Reject(3, "bundle_invalid", detail=str(e))
    if pub.agent_id != s.signer:
        raise Reject(3, "signer_id_mismatch")
    for alg, kid, _, _ in s.sigs:
        if kid != s.signer:
            raise Reject(3, "signer_id_mismatch", detail="signature kid")
    s.bundle = pub
    s.bundle_value = bv
    # step 4
    payload = s.payload
    if payload is None:
        payload = ctx.detached_payload
        if payload is None:
            raise Reject(4, "detached_payload_missing")
    by_alg = dict((a, (sp, sig)) for a, _, sp, sig in s.sigs)
    sp, sig = by_alg[E.ALG_EDDSA]
    if not ed25519.verify_strict(pub.keys["ed25519"], E.sig_structure(s.body, sp, payload), sig):
        raise Reject(4, "eddsa_signature_invalid")
    sp, sig = by_alg[E.ALG_MLDSA]
    if not mldsa.verify(pub.keys["mldsa65"], E.sig_structure(s.body, sp, payload), sig):
        raise Reject(4, "mldsa_signature_invalid")
    # step 5
    if s.issued_at > ctx.now + ctx.max_skew:
        raise Reject(5, "issued_in_future")
    if s.expires_at is not None and not ctx.ignore_expiry and s.expires_at <= ctx.now:
        raise Reject(5, "expired")
    # step 6
    if ctx.check_replay and s.nonce in ctx.seen_nonces:
        raise Reject(6, "nonce_replayed")
    # step 7
    if hashlib.sha256(payload).digest() != s.digest:
        raise Reject(7, "payload_digest_mismatch")
    s.payload_bytes = payload
