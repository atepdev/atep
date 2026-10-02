"""ROS-free ATEP-R receiver logic. Uses only atep_py (the independent Python implementation).

The ROS node and the unit tests both call EnvelopeReceiver.handle(msg); `msg` is anything with
`.envelope` (bytes-like) and `.command_class` (str), which is what atep_msgs/msg/Envelope has.
"""
from atep_py.verify import verify_json


class EnvelopeReceiver:
    def __init__(self, recipient_seeds, trust, known_bundles=(), clock=None, on_accept=None, on_reject=None):
        self.recipient_seeds = recipient_seeds        # dict of hex seeds (a real unit loads these from a key file)
        self.trust = dict(trust, atep_r=True)         # ATEP-R is a verifier setting, not something an envelope claims
        self.known_bundles = list(known_bundles)      # hex of cached signer bundles
        self.clock = clock                            # () -> unix seconds
        self.seen = set()                             # replay set, filled only after full success
        self.on_accept = on_accept or (lambda r, msg: None)
        self.on_reject = on_reject or (lambda r, msg: None)

    def handle(self, msg):
        policy = {
            "now": self.clock(), "max_skew_secs": 300, "recipient_seeds": self.recipient_seeds,
            "known_bundles": self.known_bundles, "seen_nonces": sorted(self.seen), "trust": self.trust,
        }
        r = verify_json(bytes(msg.envelope), policy)
        if r["ok"] and r.get("command_class") != msg.command_class:   # message field is untrusted metadata
            r = {"ok": False, "step": 0, "error": "message_class_mismatch"}
        if r["ok"]:
            self.seen.add(r["nonce_hex"])
            self.on_accept(r, msg)
        else:
            self.on_reject(r, msg)
        return r
