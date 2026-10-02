#!/usr/bin/env python3
"""Independent partial check of the M1 and M2 vectors using the `cryptography` package.

Verifies, without any ATEP library code: the Ed25519 signature of a signed
envelope over a hand-built Sig_structure, the Agent ID (SHA-256 of the
canonical bundle), and the X25519, HKDF-SHA-256 and AES-256-GCM steps of the
encryption vector (the ML-KEM shared secret is taken from the published
intermediates because `cryptography` has no ML-KEM).

M2 additions: the Ed25519 signature, payload schema and agent ID binding of an
attestation and of an SRL, and the RFC 9162 Merkle inclusion proof of
`log/inclusion-valid` (leaf hash, audit path, and the Ed25519 signature on the
checkpoint). M3 additions: an independent RFC 9162 section 2.1.4.2 consistency
proof verifier run over the `consistency-*` and `split-view-*` log vectors. Not cross-checked here: ML-DSA-65 signatures (no library),
chain walking, SRL freshness and the ATEP-R rules (those are exercised only by
the Rust checker; an independent implementation will cover them in M4).

Usage: python3 crosscheck.py   (needs: pip install cryptography)
"""
import hashlib
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

V = os.path.dirname(os.path.abspath(__file__)) + "/"


def dec(b, i=0):
    ib = b[i]
    m, a = ib >> 5, ib & 31
    i += 1
    if m == 7:
        return {20: False, 21: True, 22: None}[a], i
    if a < 24:
        n = a
    else:
        ln = {24: 1, 25: 2, 26: 4, 27: 8}[a]
        n = int.from_bytes(b[i : i + ln], "big")
        i += ln
    if m == 0:
        return n, i
    if m == 1:
        return -1 - n, i
    if m == 2:
        return bytes(b[i : i + n]), i + n
    if m == 3:
        return b[i : i + n].decode(), i + n
    if m == 4:
        out = []
        for _ in range(n):
            x, i = dec(b, i)
            out.append(x)
        return out, i
    if m == 5:
        out = {}
        for _ in range(n):
            k, i = dec(b, i)
            v, i = dec(b, i)
            out[k] = v
        return out, i
    if m == 6:
        x, i = dec(b, i)
        return ("tag", n, x), i
    raise ValueError("unsupported")


def head(m, n):
    if n < 24:
        return bytes([m << 5 | n])
    if n < 256:
        return bytes([m << 5 | 24, n])
    if n < 65536:
        return bytes([m << 5 | 25]) + n.to_bytes(2, "big")
    return bytes([m << 5 | 26]) + n.to_bytes(4, "big")


def bstr(x):
    return head(2, len(x)) + x


def tstr(s):
    return head(3, len(s)) + s.encode()


# 1. Ed25519 over the Sig_structure, and the Agent ID.
raw = open(V + "verify-positive/signed-trust-doc-inline-bundle.cbor", "rb").read()
(_, tag, arr), end = dec(raw)
assert tag == 98 and end == len(raw)
body_protected, unprotected, payload, sigs = arr
ed_pub = unprotected[-70008][0][-2]
sign_protected, _, signature = sigs[0]
sig_structure = (
    head(4, 5) + tstr("Signature") + bstr(body_protected) + bstr(sign_protected)
    + bstr(b"") + bstr(payload)
)
Ed25519PublicKey.from_public_bytes(ed_pub).verify(signature, sig_structure)
print("ed25519 signature OK")
signer = dec(body_protected)[0][-70002]
bundle = open(V + "identity/alice.cbor", "rb").read()
assert hashlib.sha256(bundle).digest() == signer
print("agent id OK")

# 2. X25519 + HKDF + AES-GCM of the encryption vector.
meta = json.load(open(V + "encryption/alice-to-bob.expected.json"))
inter = meta["expected"]["intermediate"]
raw = open(V + "encryption/alice-to-bob.cbor", "rb").read()
(_, tag, arr), _ = dec(raw)
assert tag == 96
protected, unprotected, ciphertext, recipients = arr
rh = recipients[0][1]
eph, kem_ct = rh[-1][-2], rh[-70013]
bob_sk = X25519PrivateKey.from_private_bytes(
    bytes.fromhex(meta["inputs"]["recipient_seeds"]["x25519"])
)
ss_x = bob_sk.exchange(X25519PublicKey.from_public_bytes(eph))
assert ss_x.hex() == inter["ss_x25519_hex"]
bob_pub = bob_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
info = b"ATEP-1-KEM" + eph + bob_pub + kem_ct
assert info.hex() == inter["hkdf_info_hex"]
ss_pq = bytes.fromhex(inter["ss_mlkem768_hex"])
try:
    hk = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info)
except TypeError:  # old cryptography releases require a backend argument
    from cryptography.hazmat.backends import default_backend

    hk = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info, backend=default_backend())
key = hk.derive(ss_x + ss_pq)
assert key.hex() == inter["aes_key_hex"]
aad = head(4, 3) + tstr("Encrypt") + bstr(protected) + bstr(b"")
plaintext = AESGCM(key).decrypt(unprotected[5], ciphertext, aad)
assert plaintext.hex() == meta["inputs"]["inner_envelope_hex"]
print("x25519, hkdf and aes-gcm OK; inner envelope recovered")


# ---- M2 ------------------------------------------------------------------


def enc(x):
    """Deterministic CBOR encoder for the value model returned by dec()."""
    if x is None:
        return b"\xf6"
    if x is True:
        return b"\xf5"
    if x is False:
        return b"\xf4"
    if isinstance(x, int):
        return head(0, x) if x >= 0 else head(1, -1 - x)
    if isinstance(x, bytes):
        return bstr(x)
    if isinstance(x, str):
        return tstr(x)
    if isinstance(x, list):
        return head(4, len(x)) + b"".join(enc(i) for i in x)
    if isinstance(x, dict):
        items = sorted((enc(k), enc(v)) for k, v in x.items())
        return head(5, len(items)) + b"".join(k + v for k, v in items)
    if isinstance(x, tuple) and x[0] == "tag":
        return head(6, x[1]) + enc(x[2])
    raise ValueError(type(x))


def signed_parts(raw):
    """Decode a tag 98 envelope; verify its Ed25519 signature; return (arr, headers, payload)."""
    (_, tag, arr), end = dec(raw)
    assert tag == 98 and end == len(raw)
    body_protected, unprotected, payload, sigs = arr
    hdr = dec(body_protected)[0]
    bundle = unprotected[-70008]
    assert hashlib.sha256(enc(bundle)).digest() == hdr[-70002], "agent id binds the inline bundle"
    ed_pub = bundle[0][-2]
    sign_protected, _, signature = sigs[0]
    sig_structure = (
        head(4, 5) + tstr("Signature") + bstr(body_protected) + bstr(sign_protected)
        + bstr(b"") + bstr(payload)
    )
    Ed25519PublicKey.from_public_bytes(ed_pub).verify(signature, sig_structure)
    assert hashlib.sha256(payload).digest() == hdr[-70006], "payload digest"
    return arr, hdr, dec(payload)[0]


# Attestation: signature, schema (spec section 7), issuer equals signer.
_, hdr, att = signed_parts(open(V + "attestation/operator-90-days.cbor", "rb").read())
assert hdr[3] == "application/atep-attestation+cbor" and -70004 in hdr
assert set(att) == {"subject", "issuer", "claim", "data", "id"}, set(att)
assert att["issuer"] == hdr[-70002] and len(att["subject"]) == 32 and len(att["id"]) == 16
assert hdr[-70004] - hdr[-70003] <= 400 * 86400
print("attestation signature, schema and lifetime OK")

# SRL: signature and schema (section 8).
_, hdr, srl = signed_parts(open(V + "srl/srl-valid.cbor", "rb").read())
assert hdr[3] == "application/atep-srl+cbor"
assert set(srl) == {"issuer", "sequence", "issued-at", "next-update", "revoked"}
assert srl["issuer"] == hdr[-70002] and srl["next-update"] > srl["issued-at"]
assert all(set(e) == {"id", "reason", "revoked-at"} and len(e["id"]) in (16, 32) for e in srl["revoked"])
print("srl signature and schema OK")


# Inclusion proof (RFC 9162 section 2.1.3.2) against the signed checkpoint.
def h(prefix, *parts):
    return hashlib.sha256(prefix + b"".join(parts)).digest()


def verify_inclusion(leaf, index, size, path, root):
    if index >= size:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = h(b"\x01", p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = h(b"\x01", r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


raw = open(V + "log/inclusion-valid.cbor", "rb").read()
(_, tag, arr), _ = dec(raw)
proof = arr[1][-70012]
cp_raw = enc(proof["checkpoint"])
_, cp_hdr, cp = signed_parts(cp_raw)
assert cp_hdr[3] == "application/atep-checkpoint+cbor" and set(cp) == {"tree-size", "root-hash", "timestamp"}
arr[1].pop(-70012)
submitted = enc(("tag", 98, arr))
leaf = h(b"\x00", submitted)
assert verify_inclusion(leaf, proof["leaf-index"], cp["tree-size"], proof["audit-path"], cp["root-hash"])
assert not verify_inclusion(h(b"\x00", submitted + b"x"), proof["leaf-index"], cp["tree-size"], proof["audit-path"], cp["root-hash"])
print("checkpoint signature and merkle inclusion proof OK")


# M3: consistency proofs (RFC 9162 section 2.1.4.2) and split views, checked
# against the signed checkpoints with this script's own implementation.
def verify_consistency(first, second, first_hash, second_hash, path):
    if first > second:
        return False
    if first == second:
        return not path and first_hash == second_hash
    if first == 0:
        return not path and first_hash == hashlib.sha256(b"").digest()
    path = ([first_hash] if first & (first - 1) == 0 else []) + list(path)
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
            fr = h(b"\x01", c, fr)
            sr = h(b"\x01", c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = h(b"\x01", sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == first_hash and sr == second_hash


def cons_doc(name):
    return dec(open(V + "log/" + name + ".cbor", "rb").read())[0]


def cp_of(env):
    _, hdr, cp = signed_parts(enc(env))
    assert hdr[3] == "application/atep-checkpoint+cbor"
    return cp


for name, ok in [
    ("consistency-valid", True),
    ("consistency-valid-power-of-two", True),
    ("consistency-same-size", True),
    ("consistency-invalid-path", False),
    ("consistency-truncated-path", False),
    ("consistency-rewritten-history", False),
]:
    doc = cons_doc(name)
    old, new = cp_of(doc["old"]), cp_of(doc["new"])
    p = doc["proof"]
    assert p["from"] == old["tree-size"] and p["to"] == new["tree-size"]
    got = verify_consistency(old["tree-size"], new["tree-size"], old["root-hash"], new["root-hash"], p["path"])
    assert got == ok, name
doc = cons_doc("split-view-same-size")
a, b = cp_of(doc["a"]), cp_of(doc["b"])
assert a["tree-size"] == b["tree-size"] and a["root-hash"] != b["root-hash"]
doc = cons_doc("split-view-failed-consistency")
a, b = cp_of(doc["a"]), cp_of(doc["b"])
assert not verify_consistency(a["tree-size"], b["tree-size"], a["root-hash"], b["root-hash"], doc["proof"]["path"])
doc = cons_doc("split-view-none")
a, b = cp_of(doc["a"]), cp_of(doc["b"])
assert verify_consistency(a["tree-size"], b["tree-size"], a["root-hash"], b["root-hash"], doc["proof"]["path"])
print("consistency proofs and split view vectors OK")
