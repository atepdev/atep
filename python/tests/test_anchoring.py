import unittest

from atep_py import anchors, admission, domain, cbor, envelope as E
from atep_py.core import Reject
from atep_py.policy import TrustPolicy

LOG = "atep:" + "a" * 52
H = "ab" * 32


class ChainIdTests(unittest.TestCase):
    def test_table(self):
        self.assertEqual(anchors.chain_id_kind("rekor"), "registered")
        self.assertEqual(anchors.chain_id_kind("x-acme-ledger"), "extension")
        self.assertEqual(anchors.chain_id_kind("x-" + "a" * 62), "extension")
        for bad in ("x-" + "a" * 63, "x-", "x--a", "x-a-", "x-A", "Rekor", "rekor ", "rekor\n", "", None, 7, "x-é"):
            self.assertIsNone(anchors.chain_id_kind(bad), bad)


class AnchorRecordTests(unittest.TestCase):
    def rec(self, **kw):
        m = {"checkpoint-hash": bytes(32), "chain-id": "rekor", "transaction-id": "t", "anchored-at": 5}
        m.update(kw)
        return m

    def test_roundtrip_without_height(self):
        raw = cbor.dumps(self.rec())
        r = anchors.decode_record(raw)
        self.assertIsNone(r["block_height"])
        self.assertEqual(anchors.encode_record(r), raw)

    def test_height_zero_kept(self):
        raw = cbor.dumps(self.rec(**{"block-height": 0}))
        self.assertEqual(anchors.encode_record(anchors.decode_record(raw)), raw)

    def test_rejects(self):
        for m in (self.rec(**{"block-height": None}), self.rec(**{"block-height": -1}), self.rec(extra=1),
                  self.rec(**{"chain-id": "solana"}), self.rec(**{"transaction-id": ""}),
                  self.rec(**{"transaction-id": "x" * 513}), [1]):
            with self.assertRaises(anchors.AnchorRecordInvalid):
                anchors.decode_record(cbor.dumps(m))
        with self.assertRaises(anchors.AnchorRecordInvalid):
            anchors.decode_record(cbor.dumps(self.rec()) + b"\x00")


class RequireAnchorTests(unittest.TestCase):
    def test_parse_and_normalize(self):
        r = anchors.parse_require_anchor([{"log": "did:atep:" + "a" * 52, "chain": "rekor", "max_age_hours": 1}])
        self.assertEqual(r, [{"log": LOG, "chain": "rekor", "max_age_hours": 1}])
        self.assertEqual(TrustPolicy({"require_anchor": []}).require_anchor, [])

    def test_invalid(self):
        ok = {"log": LOG, "chain": "rekor", "max_age_days": 1}
        for v in (None, {}, [1], [dict(ok, max_age_days=0)], [dict(ok, max_age_hours=1)], [dict(ok, max_age_days=1.5)],
                  [dict(ok, max_age_days=True)], [dict(ok, extra=1)], [{"log": LOG, "chain": "rekor"}],
                  [ok, dict(ok, chain="nope")], [dict(ok, max_age_days=2 ** 64)]):
            with self.assertRaises(Reject) as c:
                TrustPolicy({"require_anchor": v})
            self.assertEqual(c.exception.error, "policy_invalid")
        with self.assertRaises(Reject):
            TrustPolicy({"require-anchor": []})


class MediaTypeTests(unittest.TestCase):
    def test_anchor_type_is_trust_document(self):
        self.assertIn(E.CT_ANCHOR, E.TRUST_DOC_TYPES)
        self.assertNotIn("application/atep-anchor+json", E.TRUST_DOC_TYPES)


class AdmissionDataTests(unittest.TestCase):
    def test_urls(self):
        v = admission.valid_endpoint_url
        self.assertTrue(v("https://a.example:8443/p?q=1"))
        self.assertTrue(v("https://" + "a" * 2040))
        for bad in ("http://a.example", "https:///v1", "https://:8443/", "https://u:p@a.example/",
                    "https://a.example/a b", "https://a.example/\x00", "a.example", "HTTPS://a.example",
                    "https://" + "a" * 2041, None, 3):
            self.assertFalse(v(bad), bad)

    def test_kinds(self):
        k = admission.valid_endpoint_kind
        for ok in ("registry", "verifier", "mcp", "a2a", "x-acme-queue"):
            self.assertTrue(k(ok))
        for bad in ("", "x-", "x-Acme", "x-acme_queue", "Registry", "other", None):
            self.assertFalse(k(bad))


class DomainTests(unittest.TestCase):
    def test_outcome_table(self):
        o = domain.outcome
        self.assertEqual(o("listed", "absent"), "bound")
        self.assertEqual(o("listed", "not-listed"), "not-bound")
        self.assertEqual(o("not-listed", "unavailable"), "indeterminate")
        self.assertEqual(o("invalid", "absent"), "not-bound")
        self.assertEqual(o("listed", "unavailable", True), "indeterminate")
        self.assertEqual(o("listed", "absent", True), "not-bound")
        self.assertEqual(o("listed", "listed", True), "bound")

    def test_domain_names(self):
        for ok in ("example.com", "a-b.c1", "x" * 63):
            self.assertTrue(domain.valid_domain(ok))
        for bad in ("Example.com", "example.com.", "a..b", "-a.com", "a-.com", "a_b.com", "x" * 64, "", "a" * 254):
            self.assertFalse(domain.valid_domain(bad), bad)

    def test_txt_terms(self):
        counted, ids = domain.txt_authorized_set(["v=atep1", ["v=atep1 id=atep:", "bad"], " v=atep1", "v=atep10"])
        self.assertTrue(counted)
        self.assertEqual(ids, set())
        self.assertEqual(domain.txt_authorized_set(["v=atep10 id=x"]), (False, set()))
