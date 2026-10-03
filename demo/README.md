# ATEP-R live simulator

A hosted copy runs in the browser at https://atep.dev/demo/ (generated from this folder by `node site/build-demo.mjs`; this folder stays the source of truth). Four simulated units on a map exchange real ATEP-R envelopes. Unit 1 is the fleet controller, Unit 2 and Unit 4 are certified members, Unit 3 is a member whose identity is revoked mid-run. The viewer sees ciphertext in flight, Unit 3's motion command rejected with the failing step and error code named, the fleet carrying on, and certified members verifying each other and coordinating directly while the controller is unreachable. Its purpose is to make the robotics profile (ATEP-R, spec section 17) visible: what a receiver checks, what it refuses, and why, using the real verifier. It is an illustration, not a product: the map, movement, clock and the "certified" status of Units 2 and 4 are simulated and no real certification is implied.

## Run

```
node demo/serve.mjs          # then open http://127.0.0.1:8088/   (optional port argument)
node demo/selftest.mjs       # headless self-test, no browser, exit code 1 on failure
```

The self-test makes 80 assertions (it prints `80 passed, 0 failed`): every scripted message with its real result, the offline and stale cases, the attacks, the decrypt controls and the pending revocation.

Plain HTML, CSS and vanilla ES modules. No framework, no build step, no network needed after load. The page must be served over http (browsers refuse to load WebAssembly modules from `file://`); `serve.mjs` does that with the right MIME types.

## Layout of this folder

- `index.html`, `style.css`, `src/ui.mjs`: the UI (DOM and SVG only).
- `src/engine.mjs`: the scenario engine, no DOM. Used by both the UI and the self-test.
- `src/cbor.mjs`: tiny CBOR encoder and decoder for the command payloads.
- `vendor/atep-core/`: a copy of the built `@atep/core` package (`js/dist`: Rust compiled to WASM plus glue). `js/` itself is untouched.
- `selftest.mjs`, `serve.mjs`.

## What each part shows

- **Fleet map**: units move (simulated). Dashed lines and a padlocked envelope glyph show each message in flight, labelled with its real size and the first bytes of ciphertext. Units differ by color, shape and number (diamond 1, circle 2, triangle 3, hexagon 4). An envelope to or from the offline controller travels part of the way and stops with a 'not delivered' badge. The demo is dark only (it sets `color-scheme: dark`). The hatched zone is a keep-out area. Clicking or tabbing to an envelope in flight selects it.
- **Controls**: Play/Pause, Step, Restart (generates fresh identities), speed, "Revoke Unit 3 now" (manual trigger; otherwise the script revokes at tick 8), a stale revocation list toggle, and "Controller goes offline" (see below).
- **Envelope log**: every envelope with class, sender, receiver, size, verified or rejected with step and error code, and what the receiver did, newest first. Click a row to inspect it. On screens 1400 px wide and up, the toolbar button "Log beside map" puts the log to the right of the fleet map, at the map's height, scrolling inside its own panel with a sticky header; it stays on the newest row unless you have scrolled down. The choice is remembered in the browser (local storage, if allowed); with no saved choice it is on for very wide, ultrawide-shaped windows (at least 2200 px wide and twice as wide as tall).
- **Inspect envelope**: "Decrypt as recipient" opens it with the intended recipient's keys and shows the plaintext command and the verified claims chain. "Try as outside observer" attempts the same with an unrelated identity and fails with the real decrypt error (step 2, `not_addressed_to_recipient`). A recipient can also open an envelope the verifier rejected: the plaintext is readable but the result stays rejected.
- **Attack row**: replay a captured envelope (step 6, `nonce_replayed`), tamper one byte (step 2, `aead_failure`), forge from an unattested identity (step 9, `claim_missing`), motion command from a member lacking the claim (step 9, `claim_missing`). Each is really built and sent to the real verifier.
- **Stale SRL toggle** (optional): the operator's revocation list is past `next-update`. Motion from the controller then fails closed (step 9, `srl_stale`) while telemetry continues with a warning, as in section 17. With the controller offline the toggle probes run between members instead: a peer motion from Unit 4 to Unit 2 is rejected at step 9, telemetry continues with a warning and an e-stop from Unit 4 is still accepted with a warning. The peer motion error code is `srl_stale` (spec section 10 step 9, Draft 08, decision 83): the `fleet-controller` alternative fails because Unit 4 does not hold it and the `fleet-member` alternative fails because of the stale root list, and a stale list is what the verifier reports. The demo also re-verifies the same envelope against a fresh list (accepted) and says so in the log.
- **Controller goes offline** (button with `aria-pressed`, plus an on-screen state indicator): Unit 1 neither sends nor receives. Messages to or from it are logged as "NOT DELIVERED: controller offline" in a distinct style, with no step and no error code, because nothing was verified. Units 2, 3 and 4 keep exchanging and verifying messages using the attestations and revocation lists they saved earlier. The limit is shown too: if "Revoke Unit 3 now" is pressed while the controller is offline, the operator's list is signed but pending, and Unit 3 is still accepted until the controller returns and delivers it. The attack buttons re-route to members while the controller is offline.
- **Live trust policy and claims**: the policy object given to the verifier, the command class table, the revocation lists in force, and every attestation each unit holds (struck through once Unit 3 is revoked).

## Scripted run (also asserted by the self-test)

Ticks 1 to 7: telemetry, motion from the controller, a sensor report, a peer motion command from Unit 3 to Unit 2 (allowed by Unit 3's `peer-motion` claim), the same unit's motion command to Unit 4 (its `peer-motion` does not name Unit 4: rejected at step 9, `claim_data_mismatch`), coordination claims and a path reservation between Units 2 and 4, and an actuation command (needs `fleet-controller` + `safety-certified`), all verified except that one. Tick 8: the fleet operator publishes an SRL naming Unit 3 as compromised. Tick 9: Unit 3's motion command (a waypoint through the keep-out zone) and telemetry are rejected at step 8 (`signer_revoked`); Unit 2 ignores them. Ticks 10 to 12: the fleet continues.

Ticks 13 to 19: the controller is offline. Messages to or from Unit 1 are not delivered (tick 13). Units 2 and 4 exchange a path reservation, a task claim and telemetry, all accepted. Tick 15: a peer motion from Unit 4 to Unit 2 is accepted (Unit 4's `peer-motion` names Unit 2), and Unit 3 is still refused at step 8 from the list held earlier. Tick 16: Unit 2 sends Unit 4 a motion command presenting no `peer-motion` delegation: rejected at step 9, `claim_missing`. Tick 17: Unit 4 sends Unit 2 an actuation command: rejected at step 9, `claim_missing` (needs `fleet-controller` + `safety-certified`). Tick 18: Unit 4 sends Unit 2 an e-stop (class `safety`, from a `fleet-member` with `safety-certified`): accepted, Unit 2 stops for two ticks. Tick 19: telemetry both ways. Tick 20: the controller is back online and its traffic is delivered again. After that the demo idles with a repeating pattern (including direct member traffic) and Unit 3 keeps being refused.

| Tick | Message | Real verifier result |
| --- | --- | --- |
| 1 | telemetry from Units 2, 3, 4 to Unit 1 | accepted |
| 2 | motion, Unit 1 to Units 2 and 3 | accepted |
| 3 | sensor, Unit 2 to Unit 1 | accepted |
| 4 | motion, Unit 3 to Unit 2 | accepted |
| 4 | motion, Unit 3 to Unit 4 | rejected, step 9, `claim_data_mismatch` |
| 5 | coordination, Unit 2 to Unit 1; path reservation, Unit 2 to Unit 4 | accepted |
| 6 | actuation, Unit 1 to Unit 2 | accepted |
| 7 | telemetry, Unit 3 to Unit 1 | accepted |
| 8 | SRL naming Unit 3 published | |
| 9 | motion and telemetry from Unit 3 | rejected, step 8, `signer_revoked` |
| 10 to 12 | controller motion, telemetry, coordination | accepted |
| 13 | telemetry Unit 2 to Unit 1, motion Unit 1 to Unit 2 | not delivered: controller offline (not verified) |
| 13 | path reservation Unit 2 to Unit 4; telemetry Unit 4 to Unit 2 | accepted |
| 14 | task claim Unit 4 to Unit 2; telemetry Unit 2 to Unit 4 | accepted |
| 15 | motion, Unit 4 to Unit 2 (peer-motion names Unit 2) | accepted |
| 15 | motion, Unit 3 to Unit 2 | rejected, step 8, `signer_revoked` |
| 16 | motion, Unit 2 to Unit 4, no peer-motion presented | rejected, step 9, `claim_missing` |
| 17 | actuation, Unit 4 to Unit 2 | rejected, step 9, `claim_missing` |
| 18 | e-stop, Unit 4 to Unit 2 | accepted |
| 19 | telemetry both ways between Units 2 and 4 | accepted |
| 20 | controller back online: motion and telemetry | accepted |

## Real versus simulated

Real: key generation (Ed25519 + ML-DSA-65 signing keys, X25519 + ML-KEM-768 encryption keys) for the root issuer, the safety certifier, four units, an observer and an intruder; every attestation (`fleet-controller`, `fleet-member`, `issuer-authority`, `safety-certified` with evidence hash, `sensor-source`, `peer-motion`); every signed revocation list; every envelope (sign, attach attestations, hybrid encrypt); every verification (spec section 10 steps 1 to 10 plus the ATEP-R command class rules), including the error codes and steps shown; all decrypt attempts. All of this is `@atep/core` (the Rust reference crate compiled to WASM).

Simulated: the map, unit movement and the keep-out zone, battery values, the scripted timeline, the moment the controller is declared offline (nothing is really disconnected: the engine simply does not deliver envelopes to or from Unit 1, and does not verify them), and the simulated clock (2 seconds per tick, starting at a fixed Unix time, so runs are reproducible; random nonces and signatures still differ per run).

Simplifications to be aware of: every envelope carries the sender's attestations inline, so envelopes are 25 to 34 KB, larger than the roughly 5 KB the spec quotes for a minimal telemetry envelope that relies on cached attestations. Sessions and group keys (spec section 17) are not modeled; each message uses a per-message hybrid KEM. Revocation distribution is instantaneous to all units while the controller is online and impossible while it is offline. Units' SRL caches are not a separate component; each receiver is given the lists in force on every verification, which are the ones it received before the controller went offline. Unit 4's `data.peers` check follows spec section 17: a `peer-motion` that does not name the receiver is `claim_data_mismatch`, a member with no `peer-motion` at all is `claim_missing`. Map payloads are encoded as deterministic CBOR, because the real verifier recognizes an e-stop only when the payload decodes strictly.
