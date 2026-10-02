# ATEP-R reference demo (AIRAD LABS)

A hosted copy runs in the browser at https://atep.dev/demo/ (generated from this folder by `node site/build-demo.mjs`; this folder stays the source of truth). Three simulated units on a map exchange real ATEP-R envelopes. Unit 1 is the fleet controller, Unit 2 a certified member, Unit 3 a member whose identity is revoked mid-run. The viewer sees ciphertext in flight, Unit 3's motion command rejected with the failing step and error code named, and the fleet carrying on. Its purpose is to make the robotics profile (ATEP-R, spec section 17) visible: what a receiver checks, what it refuses, and why, using the real verifier. It is an illustration, not a product: the map, movement, clock and the "certified" status of Unit 2 are simulated and no real certification is implied.

## Run

```
node demo/serve.mjs          # then open http://127.0.0.1:8088/   (optional port argument)
node demo/selftest.mjs       # headless self-test, no browser, exit code 1 on failure
```

Plain HTML, CSS and vanilla ES modules. No framework, no build step, no network needed after load. The page must be served over http (browsers refuse to load WebAssembly modules from `file://`); `serve.mjs` does that with the right MIME types.

## Layout of this folder

- `index.html`, `style.css`, `src/ui.mjs`: the UI (DOM and SVG only).
- `src/engine.mjs`: the scenario engine, no DOM. Used by both the UI and the self-test.
- `src/cbor.mjs`: tiny CBOR encoder and decoder for the command payloads.
- `vendor/atep-core/`: a copy of the built `@atep/core` package (`js/dist`: Rust compiled to WASM plus glue). `js/` itself is untouched.
- `selftest.mjs`, `serve.mjs`.

## What each part shows

- **Fleet map**: units move (simulated). Dashed lines and a padlocked envelope glyph show each message in flight, labelled with its real size and the first bytes of ciphertext. Units differ by color, shape and number. The hatched zone is a keep-out area. Clicking or tabbing to an envelope in flight selects it.
- **Controls**: Play/Pause, Step, Restart (generates fresh identities), speed, "Revoke Unit 3 now" (manual trigger; otherwise the script revokes at tick 8), and a stale revocation list toggle.
- **Envelope log**: every envelope with class, sender, receiver, size, verified or rejected with step and error code, and what the receiver did. Click a row to inspect it.
- **Inspect envelope**: "Decrypt as recipient" opens it with the intended recipient's keys and shows the plaintext command and the verified claims chain. "Try as outside observer" attempts the same with an unrelated identity and fails with the real decrypt error (step 2, `not_addressed_to_recipient`). A recipient can also open an envelope the verifier rejected: the plaintext is readable but the result stays rejected.
- **Attack row**: replay a captured envelope (step 6, `nonce_replayed`), tamper one byte (step 2, `aead_failure`), forge from an unattested identity (step 9, `claim_missing`), motion command from a member lacking the claim (step 9, `claim_missing`). Each is really built and sent to the real verifier.
- **Stale SRL toggle** (optional): the operator's revocation list is past `next-update`. Motion then fails closed (step 9, `srl_stale`) while telemetry continues with a warning, as in section 17.
- **Live trust policy and claims**: the policy object given to the verifier, the command class table, the revocation lists in force, and every attestation each unit holds (struck through once Unit 3 is revoked).

## Scripted run (also asserted by the self-test)

Ticks 1 to 7: telemetry, motion from the controller, a sensor report, a peer motion command from Unit 3 to Unit 2 (allowed by Unit 3's `peer-motion` claim), a coordination claim, and an actuation command (needs `fleet-controller` + `safety-certified`), all verified. Tick 8: the fleet operator publishes an SRL naming Unit 3 as compromised. Tick 9: Unit 3's motion command (a waypoint through the keep-out zone) and telemetry are rejected at step 8 (`signer_revoked`); Unit 2 ignores them. Ticks 10 to 12: the fleet continues. After that the demo idles with a repeating pattern and Unit 3 keeps being refused.

## Real versus simulated

Real: key generation (Ed25519 + ML-DSA-65 signing keys, X25519 + ML-KEM-768 encryption keys) for the root issuer, the safety certifier, three units, an observer and an intruder; every attestation (`fleet-controller`, `fleet-member`, `issuer-authority`, `safety-certified` with evidence hash, `sensor-source`, `peer-motion`); every signed revocation list; every envelope (sign, attach attestations, hybrid encrypt); every verification (spec section 10 steps 1 to 10 plus the ATEP-R command class rules), including the error codes and steps shown; all decrypt attempts. All of this is `@atep/core` (the Rust reference crate compiled to WASM).

Simulated: the map, unit movement and the keep-out zone, battery values, the scripted timeline, and the simulated clock (2 seconds per tick, starting at a fixed Unix time, so runs are reproducible; random nonces and signatures still differ per run).

Simplifications to be aware of: every envelope carries the sender's attestations inline, so envelopes are 25 to 34 KB, larger than the roughly 5 KB the spec quotes for a minimal telemetry envelope that relies on cached attestations. Sessions and group keys (spec section 17) are not modeled; each message uses a per-message hybrid KEM. Revocation distribution is instantaneous to all units. Units' SRL caches are not a separate component; each receiver is given the current lists on every verification.
