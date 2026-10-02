import hashlib
import os
import unittest

from atep_py import cbor, identity, envelope as E
from atep_py.core import Context, Reject, verify_signed
from atep_py.verify import verify

SEEDS_A = {"ed25519": "11" * 32, "mldsa65": "22" * 32}
SEEDS_B = {"ed25519": "33" * 32, "mldsa65": "44" * 32, "x25519": "55" * 32, "mlkem768": "66" * 64}


class ProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a = identity.Identity(SEEDS_A)
        cls.b = identity.Identity(SEEDS_B)

    def sign(self, **kw):
        args = dict(payload=b"hi", content_type=E.CT_DATA, nonce=bytes(16), issued_at=1000,
                    expires_at=2000, include_bundle=True)
        args.update(kw)
        return E.sign(self.a, **args)

    def encrypted(self, **kw):
        out, _ = E.encrypt(self.sign(**kw), self.b, bytes(range(32)), bytes(32), bytes(12))
        return out

    def test_agent_id_forms(self):
        t = identity.agent_id_text(self.a.agent_id)
        self.assertEqual(len(t), 5 + 52)
        self.assertEqual(identity.parse_agent_id(t), self.a.agent_id)
        self.assertEqual(identity.parse_agent_id("did:" + t), self.a.agent_id)
        with self.assertRaises(ValueError):
            identity.parse_agent_id(t.upper())
        self.assertEqual(len(self.a.keys), 4)

    def test_bundle_without_enc_keys_has_two_elements(self):
        self.assertEqual(len(self.a.bundle_value), 2)
        self.assertEqual(len(self.b.bundle_value), 3)

    def test_encrypted_roundtrip(self):
        ctx = Context(1500, recipient=self.b)
        r = verify(self.encrypted(), ctx)
        self.assertTrue(r["ok"])
        self.assertTrue(r["encrypted"])
        self.assertEqual(r["payload_hex"], b"hi".hex())

    def test_unencrypted_data_rejected_step1(self):
        with self.assertRaises(Reject) as c:
            verify(self.sign(), Context(1500))
        self.assertEqual((c.exception.step, c.exception.error), (1, "unencrypted_non_trust_document"))

    def test_non_deterministic_envelope_rejected_step1(self):
        wide = b"\xd9\x00\x62" + bytes(self.sign(content_type=E.CT_SRL))[2:]
        with self.assertRaises(Reject) as c:
            verify(wide, Context(1500))
        self.assertEqual((c.exception.step, c.exception.error), (1, "malformed_cbor"))

    def test_trailing_bytes_rejected(self):
        with self.assertRaises(Reject) as c:
            verify(self.sign(content_type=E.CT_SRL) + b"\x00", Context(1500))
        self.assertEqual(c.exception.step, 1)

    def test_time_boundaries(self):
        env = self.sign(content_type=E.CT_SRL, issued_at=1800, expires_at=2000)
        verify(env, Context(1500))                      # issued exactly now + 300 is fine
        with self.assertRaises(Reject) as c:
            verify(env, Context(1499))
        self.assertEqual(c.exception.error, "issued_in_future")
        with self.assertRaises(Reject) as c:
            verify(env, Context(2000))
        self.assertEqual(c.exception.error, "expired")

    def test_detached_requires_payload(self):
        env = self.sign(content_type=E.CT_SRL, detached=True)
        with self.assertRaises(Reject) as c:
            verify(env, Context(1500))
        self.assertEqual((c.exception.step, c.exception.error), (4, "detached_payload_missing"))
        verify(env, Context(1500, detached_payload=b"hi"))

    def test_revocation_boundary_inclusive(self):
        env = self.sign(content_type=E.CT_SRL, issued_at=1000)
        with self.assertRaises(Reject) as c:
            verify(env, Context(1500, revocations=[(self.a.agent_id, "compromised", 1000)]))
        self.assertEqual((c.exception.step, c.exception.error), (8, "signer_revoked"))
        verify(env, Context(1500, revocations=[(self.a.agent_id, "compromised", 1001)]))

    def test_wrong_algorithm_pair_rejected(self):
        v = cbor.loads(self.sign(content_type=E.CT_SRL))
        v.value[3] = [v.value[3][0], v.value[3][0]]
        with self.assertRaises(Reject) as c:
            verify(cbor.dumps(v), Context(1500))
        self.assertEqual(c.exception.step, 1)
