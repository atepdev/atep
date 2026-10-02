import json
import os
import unittest

from atep_py import vectors

VDIR = os.environ.get("ATEP_VECTORS") or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "vectors")


@unittest.skipUnless(os.path.exists(os.path.join(VDIR, "manifest.json")), "vectors directory not found")
class VectorTests(unittest.TestCase):
    pass


def _make(cat, name):
    def t(self):
        if cat in vectors.SKIPS:
            self.skipTest("%s: %s" % (cat, vectors.SKIPS[cat]))
        problems = vectors.run_vector(VDIR, cat, name)
        self.assertEqual(problems, [], "%s/%s" % (cat, name))
    return t


if os.path.exists(os.path.join(VDIR, "manifest.json")):
    with open(os.path.join(VDIR, "manifest.json")) as _f:
        _vectors = json.load(_f)["vectors"]
    for v in _vectors:
        n = "test_%s_%s" % (v["category"].replace("-", "_"), v["name"].replace("-", "_"))
        setattr(VectorTests, n, _make(v["category"], v["name"]))
