import hashlib
import os
import unittest

from atep_py import cbor, ed25519, x25519, aesgcm, mldsa, mlkem, logs


class CborTests(unittest.TestCase):
    def test_roundtrip_and_ordering(self):
        v = {3: "a", -70001: 1, 1: b"x", -1: [1, None, True]}
        enc = cbor.dumps(v)
        self.assertEqual(cbor.loads(enc), v)
        self.assertEqual(cbor.dumps(cbor.loads(enc)), enc)

    def test_rejects_non_deterministic(self):
        bad = [
            bytes.fromhex("1801"),            # non-shortest int
            bytes.fromhex("5f4101ff"),        # indefinite bstr
            bytes.fromhex("a201020103"),      # duplicate key (1: 2, 1: 3)
            bytes.fromhex("a2020101 01".replace(" ", "")),  # keys out of order (2 then 1)
            bytes.fromhex("f93c00"),          # float
            bytes.fromhex("f7"),              # undefined
            bytes.fromhex("c101"),            # tag 1 not allowed
            bytes.fromhex("0101"),            # trailing bytes
            bytes.fromhex("1b8000000000000000"),  # beyond int64
            bytes.fromhex("6180"),            # invalid utf-8
        ]
        for b in bad:
            with self.assertRaises(cbor.CborError, msg=b.hex()):
                cbor.loads(b)

    def test_depth_bound(self):
        data = b"\x81" * 40 + b"\x00"
        with self.assertRaises(cbor.CborError):
            cbor.loads(data)

    def test_tags(self):
        self.assertEqual(cbor.loads(cbor.dumps(cbor.Tag(98, [1]))), cbor.Tag(98, [1]))


class ClassicalTests(unittest.TestCase):
    def test_ed25519_rfc8032(self):
        sk = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        pk = ed25519.public_key(sk)
        self.assertEqual(pk.hex(), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        sig = ed25519.sign(sk, b"")
        self.assertEqual(sig.hex(), "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
        self.assertTrue(ed25519.verify_strict(pk, b"", sig))
        self.assertFalse(ed25519.verify_strict(pk, b"x", sig))

    def test_ed25519_strict_rejects_noncanonical_s(self):
        sk = bytes(range(32))
        pk = ed25519.public_key(sk)
        sig = ed25519.sign(sk, b"m")
        s = int.from_bytes(sig[32:], "little") + ed25519.L
        forged = sig[:32] + s.to_bytes(32, "little")
        self.assertFalse(ed25519.verify_strict(pk, b"m", forged))

    def test_ed25519_strict_rejects_small_order_key(self):
        ident = (1).to_bytes(32, "little")  # identity point
        self.assertFalse(ed25519.verify_strict(ident, b"m", ident + bytes(32)))

    def test_x25519_rfc7748(self):
        k = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        self.assertEqual(x25519.x25519(k, u).hex(),
                         "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")

    def test_aes_gcm_nist(self):
        out = aesgcm.encrypt(bytes(32), bytes(12), bytes(16), b"")
        self.assertEqual(out.hex(), "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919")
        self.assertEqual(aesgcm.decrypt(bytes(32), bytes(12), out, b""), bytes(16))
        bad = out[:-1] + bytes([out[-1] ^ 1])
        self.assertIsNone(aesgcm.decrypt(bytes(32), bytes(12), bad, b""))


class PostQuantumTests(unittest.TestCase):
    def test_mldsa_roundtrip(self):
        pk, sk = mldsa.keygen_internal(bytes(range(32)))
        self.assertEqual(len(pk), 1952)
        sig = mldsa.sign(sk, b"hello")
        self.assertEqual(len(sig), 3309)
        self.assertEqual(sig, mldsa.sign(sk, b"hello"))  # deterministic
        self.assertTrue(mldsa.verify(pk, b"hello", sig))
        self.assertFalse(mldsa.verify(pk, b"hellO", sig))
        self.assertFalse(mldsa.verify(pk, b"hello", sig[:-1] + bytes([sig[-1] ^ 1])))

    def test_mlkem_roundtrip(self):
        ek, dk = mlkem.keygen_internal(bytes(range(32)), bytes(range(32, 64)))
        self.assertEqual(len(ek), 1184)
        k, c = mlkem.encaps_internal(ek, bytes(32))
        self.assertEqual(len(c), 1088)
        self.assertEqual(mlkem.decaps(dk, c), k)
        c2 = c[:-1] + bytes([c[-1] ^ 1])
        self.assertNotEqual(mlkem.decaps(dk, c2), k)  # implicit rejection


class MerkleTests(unittest.TestCase):
    def test_proofs_all_sizes(self):
        leaves = [bytes([i]) * 3 for i in range(9)]
        for n in range(1, 10):
            root = logs.mth(leaves[:n])
            for m in range(n):
                p = logs.audit_path(m, leaves[:n])
                self.assertTrue(logs.verify_inclusion_path(logs.leaf_hash(leaves[m]), m, n, p, root))
                self.assertFalse(logs.verify_inclusion_path(logs.leaf_hash(b"x"), m, n, p, root))
            for first in range(0, n + 1):
                p = logs.consistency_path(first, leaves[:n])
                self.assertTrue(logs.verify_consistency(first, n, p, logs.mth(leaves[:first]), root),
                                (first, n))
                if first and first < n:
                    self.assertFalse(logs.verify_consistency(first, n, p, logs.mth(leaves[:first]), b"\0" * 32))
