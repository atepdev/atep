"""ROS-free tests. Run from examples/ros2: python3 -m unittest discover -s tests -v
Needs python/ on the path (set below). Uses the repository's test vectors as the envelopes."""
import json
import os
import sys
import unittest
from types import SimpleNamespace

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "python"))
sys.path.insert(0, os.path.join(HERE, ".."))
from atep_ros2_example.verifier import EnvelopeReceiver  # noqa: E402


def vector(category, name):
    base = os.path.join(ROOT, "vectors", category, name)
    with open(base + ".expected.json") as f:
        spec = json.load(f)
    with open(base + ".cbor", "rb") as f:
        return f.read(), spec["inputs"]["policy"]


class StubBus:
    """Stands in for DDS: delivers a message to every subscriber, like a topic."""
    def __init__(self): self.subs = []
    def subscribe(self, cb): self.subs.append(cb)
    def publish(self, msg): return [cb(msg) for cb in self.subs]


def make(policy, accepted, rejected):
    rx = EnvelopeReceiver(policy["recipient_seeds"], policy["trust"], clock=lambda: policy["now"],
                          on_accept=lambda r, m: accepted.append(r), on_reject=lambda r, m: rejected.append(r))
    bus = StubBus()
    bus.subscribe(rx.handle)
    return rx, bus


class ReceiverTests(unittest.TestCase):
    def setUp(self):
        self.data, self.policy = vector("atep-r-positive", "telemetry-fleet-member")
        self.ok, self.bad = [], []
        self.rx, self.bus = make(self.policy, self.ok, self.bad)

    def msg(self, data=None, cls="telemetry"):
        return SimpleNamespace(envelope=data or self.data, command_class=cls)

    def test_accepted(self):
        [r] = self.bus.publish(self.msg())
        self.assertTrue(r["ok"])
        self.assertEqual((r["command_class"], len(self.ok), len(self.bad)), ("telemetry", 1, 0))

    def test_tampered(self):
        bad = bytearray(self.data); bad[-20] ^= 1
        [r] = self.bus.publish(self.msg(bytes(bad)))
        self.assertFalse(r["ok"])
        self.assertIn(r["step"], (1, 2))
        self.assertEqual(len(self.bad), 1)

    def test_unattested_for_this_verifier(self):
        other_root = dict(self.policy["trust"], roots=["atep:" + "a" * 52])
        ok, bad = [], []
        rx, bus = make(dict(self.policy, trust=other_root), ok, bad)
        [r] = bus.publish(self.msg())
        self.assertEqual((r["ok"], r["step"]), (False, 9))

    def test_replay(self):
        self.bus.publish(self.msg())
        [r] = self.bus.publish(self.msg())
        self.assertEqual((r["ok"], r["step"], r["error"]), (False, 6, "nonce_replayed"))

    def test_mislabelled_class(self):
        [r] = self.bus.publish(self.msg(cls="motion"))
        self.assertEqual((r["ok"], r["error"]), (False, "message_class_mismatch"))


if __name__ == "__main__":
    unittest.main()
