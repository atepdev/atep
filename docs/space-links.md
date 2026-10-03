# ATEP on relayed space links: a design note

**Status of this note.** This is a design discussion, not part of the specification and not a profile. Nothing here has been implemented, simulated or tested with any space protocol stack, flight computer or ground system. It was written by the ATEP project, not reviewed by anyone who builds space communication systems, and the statements about other standards come from general knowledge and must be checked against the current texts before anyone relies on them. It is published so that people who know these systems can tell us what is wrong. ATEP is not independently audited, and "quantum-safe" here means the hybrid use of the finalized NIST post-quantum standards, not "quantum-proof".

The question: a spacecraft, lander or rover talks to the ground through relays (an orbiter, a ground station network, a store-and-forward service). What does ATEP give such a link, what does it not give, and what would a space profile have to decide? The reference for every ATEP rule cited below is the [specification](../spec/ATEP-Specification-Draft-08.md).

## 1. What ATEP gives, assuming the keys are safe

* **Who sent it.** Every signature is a hybrid pair (Ed25519 and ML-DSA-65). An Agent ID is the SHA-256 of the sender's public keys, so a receiver can recognize a known sender without any lookup (spec section 4).
* **That it was not changed.** A change after signing makes verification fail (steps 1 to 4 of spec section 10). A relay that forwards the bytes cannot alter them undetected.
* **Who may read it.** A data envelope is encrypted to the recipient (hybrid X25519 and ML-KEM-768 with AES-256-GCM). Relays carry ciphertext they cannot read. The signer is hidden from observers of an encrypted envelope.
* **What the sender is allowed to do.** Attestations from third parties say, for example, that a sender may issue a class of command. The receiver checks them against issuer keys it already holds (spec sections 7 and 10, step 9).
* **Offline.** Steps 1 to 8 of verification need no network. Step 9 needs cached issuer keys and revocation lists. The caches must have been filled earlier.

Put plainly: assuming the private keys stay private and the primitives hold, undetected tampering with an envelope and impersonation of an identity are infeasible. That is all ATEP claims, and the assumption is a large one (section 3).

## 2. What ATEP does not do

A relayed link has more adversaries than "someone who edits the bytes". ATEP does nothing about most of them, and a deployment must not assume otherwise.

| Threat | What ATEP does |
| --- | --- |
| Jamming, or loss of the link | Nothing. It is a physical and link-layer problem. |
| A relay drops envelopes | Nothing. The receiver never sees them and cannot know. Acknowledgement and retransmission belong to the transport. |
| A relay or the link delays envelopes | Bounded only by `expires-at`. A delayed envelope that is still inside its validity window verifies as if it were fresh. ATEP cannot tell that it was held. |
| Reordering | Nothing. Order is a transport property. |
| Replay | The nonce check (step 6) rejects a re-sent envelope only for a verifier that keeps a nonce cache. A verifier without one relies on short expiry and on request identifiers in the application (spec section 11). |
| Withholding revocation lists | A relay that withholds a signed revocation list (SRL) cannot forge one, but it can keep the receiver from learning about a revocation. See section 4. |
| Traffic analysis | Little. Envelope sizes, timing and addressing metadata at the carrier are visible. Encryption hides the signer and the payload, not that a message of a certain size was sent at a certain time. |
| Compromised keys or endpoint | Nothing beyond revocation and short attestation lifetimes. A compromised signing key signs valid envelopes until it is revoked and the revocation arrives. |
| Flooding and resource exhaustion | Nothing. Verifying a hybrid signature costs real computation (section 4). |
| Whether the payload is true or safe | Nothing. A verified payload is still data, not instructions (spec section 11). |

## 3. Assumptions a deployment would need to make true

1. **Key custody.** The reference implementation keeps keys in memory or files. A flight system needs a hardware-backed or otherwise protected store, and a plan for loss, compromise and rotation. ATEP has the mechanisms (revocation, `retired`, `successor`), not the custody.
2. **Caches filled before the pass.** Issuer keys, SRLs and any attestations must be on board before they are needed. Provisioning is a ground procedure that ATEP does not define.
3. **A clock.** Verification compares `issued-at` and `expires-at` with the receiver's `now` (step 5). Section 4 explains why this matters more here than on the ground.
4. **A relay that is not trusted for content.** The design lets a relay be untrusted for integrity and confidentiality. It still has to be trusted, or monitored, for availability.

## 4. Constraints that matter on these links

**Size.** The hybrid construction is large. The specification gives signatures of 64 B (Ed25519) plus 3,309 B (ML-DSA-65), about 3.4 KB per envelope, public keys of about 2 KB per identity bundle, and an ML-KEM-768 ciphertext of 1,088 B per recipient. A minimal encrypted telemetry envelope is about 5 KB when the receiver already holds the sender's attestations and bundle; envelopes that carry attestations inline are far larger (the demo's are 25 to 34 KB). On a low-rate link, that is a large overhead for a short command. The specification already lets a sender omit inline attestations after the first exchange and rely on the receiver's cache. A profile would need a size budget, a rule for when the bundle and attestations travel, and a position on fragmentation (a transport matter, not an ATEP one).

**Time and skew.** Step 5 rejects an envelope whose `issued-at` is more than the allowed skew (default and recommended 300 s) in the future of the receiver's clock, and rejects one whose `expires-at` has passed. Two consequences:

* Light-time delay is not the problem for the skew check, because an envelope that arrives later than it was issued is not "in the future". A receiver whose clock runs behind the sender's by more than the skew is the problem: it rejects fresh envelopes as `issued_in_future`. Spacecraft clock drift and the time source therefore decide whether the default works.
* `expires-at` must be set longer than the worst delay and the longest hold in any store-and-forward hop, or valid commands expire in transit. Setting it very long widens the replay window for a verifier that keeps no nonce state.

A profile would have to state the time source, the permitted skew and how senders choose `expires-at`.

**Revocation freshness.** A verifier MUST fetch each issuer's SRL at least once per `next-update` interval (recommended 24 hours). A stale or missing list fails closed for the ATEP-R classes `motion`, `actuation`, `maintenance` and non e-stop `safety`, and continues with a warning for telemetry, sensor, coordination and e-stop. On a link with contact windows, an asset may be unable to refresh a list for days, and fail-closed classes would then refuse every command. The choices a profile has to make are real safety trade-offs: longer `next-update` windows (a revocation is learned later), different fail modes per class, or a different distribution path for lists. This note does not pick one.

**Attestation lifetimes.** Attestations are 30 to 180 days by default and at most 400 days (spec section 7). An asset that is out of contact for long stretches needs a renewal plan, and the issuer's own key rotation (`successor`) needs a path to the asset.

**Replay state.** The nonce check needs a cache whose size and lifetime fit the validity windows in use. A constrained verifier may not keep one; then expiry and application-level sequence numbers carry the load, and the profile should say so.

**Compute.** Verification includes a hybrid signature check. The specification states that the reference code has not been run on constrained hardware, and the figures it gives for a Cortex-A class computer or a Cortex-M4 are unmeasured estimates. Nothing here is known about radiation-tolerant or flight-qualified processors. It has to be measured.

## 5. How it might sit next to space protocol stacks

This section is the least certain. It describes where ATEP could plausibly fit, from general knowledge of the standards, and nothing was tested.

* **Delay- and disruption-tolerant networking.** The Bundle Protocol (RFC 9171) is store-and-forward and has its own security extensions (BPSec, RFC 9172 and RFC 9173), which protect blocks of a bundle hop by hop or end to end. An ATEP envelope is an opaque byte string, so it can be the payload of a bundle. The two layers answer different questions: BPSec protects the bundle as carried by the network, ATEP gives the application an identity, an authority check and offline verification that do not depend on how the bytes travelled. They would not replace each other. Whether one deployment needs both is for the deployment to decide.
* **CCSDS link security.** Link-layer security for space data frames (the CCSDS Space Data Link Security protocol) protects frames over a link, typically with keys shared between the two ends of that link. ATEP is a public-key, end-to-end, application-level mechanism and is not a link-layer protocol. Layering ATEP above a protected link is plausible; replacing the link layer is not what it does.
* **Fit is not a claim.** No space agency, standards body or vendor has reviewed, adopted or endorsed any of this. ATEP's media types, header labels and the CBOR tag are provisional and unregistered (spec section 5).

## 6. What a space profile would have to decide

ATEP-R (spec section 17) is the model: a profile is a setting of the verifier for a channel, not something an envelope claims. A profile for relayed space links would have to specify, at least:

1. the time source and the permitted skew, and how senders choose `expires-at` across store-and-forward hops;
2. SRL freshness windows and fail modes per command class, in line with contact schedules;
3. the replay defense for verifiers without a nonce cache (sequence numbers, challenge-response, or short windows);
4. a size budget and the rule for when bundles and attestations travel;
5. command classes and the claims they need (ATEP-R's seven classes may or may not map);
6. how issuers and trust roots are provisioned before launch, and how they are rotated afterwards;
7. test vectors for the new rules, including long delays and drifting clocks, which no vector covers today.

What must not change: agents and organizations are subjects, never individuals; there is no global score; no mandatory root or log; no reputation in the core (spec section 16); and no chain, token or on-chain lookup required anywhere in the core or the clients. A space profile that needed any of these would be a different protocol.

## 7. What would make this real

* Review by people who build space communication and flight systems, and their corrections to sections 2, 4 and 5.
* Measurements of hybrid verification on flight-like processors.
* A concrete scenario (one relay topology, one command set) to write the profile against.
* Vectors for time skew and long delay, and an implementation by someone outside the project.

Until then this note is a map of the questions, not an answer. Corrections and use cases are welcome as public issues (see [`CONTRIBUTING.md`](../CONTRIBUTING.md)); security problems go through [`SECURITY.md`](../SECURITY.md).
