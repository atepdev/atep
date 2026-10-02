"""Identity, key bundle and Agent ID (spec section 4)."""
import base64
import hashlib

from . import cbor, ed25519, x25519, mldsa, mlkem


def b32_encode(b):
    return base64.b32encode(b).decode("ascii").lower().rstrip("=")


def agent_id_text(agent_id):
    return "atep:" + b32_encode(agent_id)


def agent_id_did(agent_id):
    return "did:atep:" + b32_encode(agent_id)


def parse_agent_id(text):
    """Accepts only the canonical lowercase forms atep:<52 chars> or did:atep:<52 chars>."""
    if text.startswith("did:atep:"):
        s = text[len("did:atep:"):]
    elif text.startswith("atep:"):
        s = text[len("atep:"):]
    else:
        raise ValueError("not an Agent ID")
    if len(s) != 52 or s != s.lower():
        raise ValueError("not canonical")
    try:
        b = base64.b32decode(s.upper() + "====")
    except Exception:
        raise ValueError("bad base32")
    if len(b) != 32 or b32_encode(b) != s:
        raise ValueError("not canonical")
    return b


def ed25519_key(x):
    return {1: 1, 3: -8, -1: 6, -2: x}


def mldsa65_key(pub):
    return {1: 7, 3: -49, -1: pub}


def x25519_key(x):
    return {1: 1, 3: -25, -1: 4, -2: x}


def mlkem768_key(pub):
    return {1: 7, 3: -70010, -1: pub}


def bundle_value(ed_pub, pq_pub, x_pub=None, kem_pub=None):
    b = [ed25519_key(ed_pub), mldsa65_key(pq_pub)]
    if x_pub is not None and kem_pub is not None:
        b.append([x25519_key(x_pub), mlkem768_key(kem_pub)])
    return b


class BundleError(Exception):
    pass


def _exact(m, template):
    if not isinstance(m, dict) or set(m.keys()) != set(template.keys()):
        return False
    for k, t in template.items():
        v = m[k]
        if isinstance(t, int):
            if not (isinstance(v, int) and not isinstance(v, bool) and v == t):
                return False
        else:  # byte length
            if not (isinstance(v, bytes) and len(v) == t[0]):
                return False
    return True


def parse_bundle_value(v):
    """Validate the exact bundle form; return dict of public keys."""
    if not isinstance(v, list) or len(v) not in (2, 3):
        raise BundleError("bundle must be a 2 or 3 element array")
    if not _exact(v[0], {1: 1, 3: -8, -1: 6, -2: (32,)}):
        raise BundleError("bad Ed25519 key")
    if not _exact(v[1], {1: 7, 3: -49, -1: (1952,)}):
        raise BundleError("bad ML-DSA-65 key")
    out = {"ed25519": v[0][-2], "mldsa65": v[1][-1], "x25519": None, "mlkem768": None}
    if len(v) == 3:
        e = v[2]
        if not isinstance(e, list) or len(e) != 2:
            raise BundleError("bad enc keys")
        if not _exact(e[0], {1: 1, 3: -25, -1: 4, -2: (32,)}):
            raise BundleError("bad X25519 key")
        if not _exact(e[1], {1: 7, 3: -70010, -1: (1184,)}):
            raise BundleError("bad ML-KEM-768 key")
        out["x25519"] = e[0][-2]
        out["mlkem768"] = e[1][-1]
    return out


def bundle_agent_id(bundle_value):
    return hashlib.sha256(cbor.dumps(bundle_value)).digest()


class PublicIdentity(object):
    def __init__(self, bundle_value):
        self.keys = parse_bundle_value(bundle_value)
        self.bundle_value = bundle_value
        self.bundle = cbor.dumps(bundle_value)
        self.agent_id = hashlib.sha256(self.bundle).digest()

    @property
    def text(self):
        return agent_id_text(self.agent_id)


class Identity(PublicIdentity):
    """Full identity from seeds (hex strings or bytes)."""

    def __init__(self, seeds):
        def b(x):
            return bytes.fromhex(x) if isinstance(x, str) else x
        self.ed_sk = b(seeds["ed25519"])
        self.mldsa_xi = b(seeds["mldsa65"])
        ed_pub = ed25519.public_key(self.ed_sk)
        pq_pub, self.mldsa_sk = mldsa.keygen_internal(self.mldsa_xi)
        x_pub = kem_pub = None
        self.x_sk = self.kem_dk = None
        if seeds.get("x25519") and seeds.get("mlkem768"):
            self.x_sk = b(seeds["x25519"])
            x_pub = x25519.public_key(self.x_sk)
            kem_pub, self.kem_dk = mlkem.keygen_from_seed(b(seeds["mlkem768"]))
        PublicIdentity.__init__(self, bundle_value(ed_pub, pq_pub, x_pub, kem_pub))

    @property
    def has_encryption_keys(self):
        return self.x_sk is not None
