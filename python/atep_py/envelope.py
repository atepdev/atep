"""Envelope construction (signing, encryption) and low level structure helpers."""
import hashlib

from . import cbor, ed25519, mldsa, mlkem, x25519, aesgcm
from .cbor import Tag
from .hkdf import hkdf_sha256

SUITE = "ATEP-1"
H_CT, H_VER, H_SIGNER, H_IAT, H_EXP, H_NONCE, H_DIGEST, H_SUITE, H_CLASS = (
    3, -70001, -70002, -70003, -70004, -70005, -70006, -70007, -70014)
U_BUNDLE, U_ATTS, U_PROOF, U_KEMCT = -70008, -70009, -70012, -70013
ALG_EDDSA, ALG_MLDSA, ALG_A256GCM, ALG_HYBRID_KEM = -8, -49, 3, -70011

CT_ATTESTATION = "application/atep-attestation+cbor"
CT_SRL = "application/atep-srl+cbor"
CT_CHECKPOINT = "application/atep-checkpoint+cbor"
CT_ANCHOR = "application/atep-anchor+cbor"
CT_DATA = "application/atep+cbor"
TRUST_DOC_TYPES = (CT_ATTESTATION, CT_SRL, CT_CHECKPOINT, CT_ANCHOR)


def sig_structure(body_protected, sign_protected, payload):
    return cbor.dumps(["Signature", body_protected, sign_protected, b"", payload])


def sign(identity, payload, content_type, nonce, issued_at, expires_at=None,
         detached=False, include_bundle=False, command_class=None,
         unprotected=None, rnd=bytes(32), suite=SUITE, version=1):
    prot = {
        H_CT: content_type,
        H_VER: version,
        H_SIGNER: identity.agent_id,
        H_IAT: issued_at,
        H_NONCE: nonce,
        H_DIGEST: hashlib.sha256(payload).digest(),
        H_SUITE: suite,
    }
    if expires_at is not None:
        prot[H_EXP] = expires_at
    if command_class is not None:
        prot[H_CLASS] = command_class
    body_protected = cbor.dumps(prot)
    unprot = dict(unprotected or {})
    if include_bundle:
        unprot[U_BUNDLE] = identity.bundle_value
    sp_ed = cbor.dumps({1: ALG_EDDSA, 4: identity.agent_id})
    sp_pq = cbor.dumps({1: ALG_MLDSA, 4: identity.agent_id})
    s_ed = ed25519.sign(identity.ed_sk, sig_structure(body_protected, sp_ed, payload))
    s_pq = mldsa.sign(identity.mldsa_sk, sig_structure(body_protected, sp_pq, payload), rnd)
    env = Tag(98, [body_protected, unprot, None if detached else payload,
                   [[sp_ed, {}, s_ed], [sp_pq, {}, s_pq]]])
    return cbor.dumps(env)


def enc_protected():
    return cbor.dumps({1: ALG_A256GCM, H_VER: 1, H_SUITE: SUITE})


def derive_key(ss_x, ss_pq, eph_pub, rcpt_x_pub, kem_ct):
    return hkdf_sha256(b"", ss_x + ss_pq,
                       b"ATEP-1-KEM" + eph_pub + rcpt_x_pub + kem_ct, 32)


def encrypt(inner, recipient, eph_sk, mlkem_m, iv):
    """recipient: PublicIdentity with encryption keys. Returns tag 96 bytes."""
    if recipient.keys["x25519"] is None:
        raise ValueError("recipient has no encryption keys")
    eph_pub = x25519.public_key(eph_sk)
    ss_x = x25519.x25519(eph_sk, recipient.keys["x25519"])
    if ss_x == bytes(32):
        raise ValueError("all-zero X25519 shared secret")
    ss_pq, kem_ct = mlkem.encaps_internal(recipient.keys["mlkem768"], mlkem_m)
    key = derive_key(ss_x, ss_pq, eph_pub, recipient.keys["x25519"], kem_ct)
    prot = enc_protected()
    aad = cbor.dumps(["Encrypt", prot, b""])
    ct = aesgcm.encrypt(key, iv, inner, aad)
    rprot = cbor.dumps({1: ALG_HYBRID_KEM})
    env = Tag(96, [prot, {5: iv}, ct,
                   [[rprot, {4: recipient.agent_id,
                             -1: {1: 1, 3: -25, -1: 4, -2: eph_pub},
                             U_KEMCT: kem_ct}, b""]]])
    return cbor.dumps(env), {"eph_pub": eph_pub, "ss_x": ss_x, "ss_pq": ss_pq,
                             "kem_ct": kem_ct, "key": key,
                             "info": b"ATEP-1-KEM" + eph_pub + recipient.keys["x25519"] + kem_ct}


def submitted_form(env_value):
    """The attestation envelope with the -70012 unprotected entry removed, re-encoded."""
    body, unprot, payload, sigs = env_value.value
    u = dict(unprot)
    u.pop(U_PROOF, None)
    return cbor.dumps(Tag(98, [body, u, payload, sigs]))
