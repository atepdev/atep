# ATEP-R over MQTT

The MQTT payload is the envelope: the sign-then-encrypt bytes (CBOR tag 96) that every other carrier in `examples/` moves. Nothing is wrapped, base64 encoded or re-signed. Spec section 17 says the MQTT adapter is "envelope as payload, topic conventions for fleet, unit and class"; the exact topic shape below is this example's choice, not a normative rule.

## Topic convention

```
fleet/<fleet>/<unit>/<class>        class is one of the seven ATEP-R command classes
fleet/f1/u2/telemetry               a message to unit u2 of fleet f1
fleet/f1/u2/+                       what unit u2 subscribes to
```

The topic is routing metadata and is not trusted. Brokers and relays can read it and can rewrite it. The subscriber therefore verifies the envelope first and then requires the topic class to equal the signed `command-class` header; a mismatch is refused (`topic_class_mismatch`). Because ATEP-R envelopes are encrypted to one recipient, a unit subscribes to its own `<unit>` segment.

## Files

| File | Role |
| --- | --- |
| `atep-mqtt.mjs` | the adapter: `buildEnvelope`, `publishEnvelope`, `subscribeVerified` (45 lines) |
| `demo.mjs` | in-process broker, one publishing unit, one verifying unit |
| `mqtt.test.mjs` | node:test cases, see below |

## Run

Needs Node 18 or later and a built `js/` (`js/dist` exists). The example has its own `package.json` so that `examples/package.json` is unchanged; `@atep/core` comes from `file:../../js`, the broker is `aedes` 1.2 (pure JavaScript, MQTT over TCP) and the client is `mqtt` 5.

```
cd examples/mqtt
npm install
npm test          # 5 tests against a real aedes broker on a loopback TCP port
npm run demo
```

Tests: attested and encrypted envelope accepted; tampered envelope rejected (step 1 or 2); sender with no attestation rejected at step 9 (`claim_missing`); topic class that differs from the signed class refused; replayed envelope rejected at step 6.

## What it does not do

* The receiver keeps its replay set in memory (a restart forgets it), uses `trust.rules = []` so only the ATEP-R class requirement is enforced, and passes no revocation lists, so telemetry proceeds without revocation status. Motion and other fail-closed classes would need SRLs (`srls: [...]`) in the policy.
* No sessions or group keys (spec section 17): every message does a hybrid KEM. No broadcast to a fleet topic.
* The broker is not authenticated and not TLS; ATEP does not need it to be. Use TLS in addition, never instead.
* MQTT 5 only through the `mqtt` client library defaults; no retained messages or QoS 2 handling is designed here.
