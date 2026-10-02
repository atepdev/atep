# Implementation findings: the Rust reference implementation

These are the ambiguities, gaps and contradictions in the ATEP specification that were found while implementing it in Rust (`rust/`): the identity and envelope code, the trust layer, the transparency log, the monitor, and the anchoring and discovery vectors. Each entry gives the spec section, the problem, a proposed fix, what the Rust code does, and the resolution.

How to read the numbers:

* "Draft N" in this file refers to an internal working draft. Drafts 00 to 06 were not published. [Draft 07](../../spec/ATEP-Specification-Draft-07.md) is the first public draft and carries every resolution recorded here (its Appendix A explains the numbering). Section and decision numbers cited in the Resolution lines are those of the internal drafts and are kept in Draft 07.
* The entries are kept as they were written; only references to files that are not part of the public repository were removed.
* A companion file, [python-findings.md](python-findings.md), lists the findings of an implementation written without access to the Rust code.

## Entries from the first milestone (Draft 01)

Status: all 17 entries are resolved in Draft 02 (Draft 02, ). Each entry ends with a Resolution line. The vectors were not changed.

Each entry: section, problem, proposed fix, and what the Rust reference implementation does meanwhile.

## 1. COSE_Signature `kid` value is unspecified
Section 5 says each COSE_Signature has protected header `{1: alg, 4: kid}` but never says what `kid` holds.
Proposed fix: `kid` is the signer's 32-byte Agent ID in both entries, and a verifier MUST reject a signature whose `kid` differs from the `signer` header.
Implementation: kid = Agent ID bytes; mismatch is rejected at step 3 (`kid_mismatch`).
Resolution: Resolved in Draft 02, section 5 (Signatures array) and section 10 step 3. As proposed.

## 2. Unprotected header labels for the bundle and inline attestations
Section 5 says the unprotected header MAY carry the signer bundle and inline attestations but assigns no labels.
Proposed fix: add provisional labels `-70008` signer-bundle (the bundle array of section 4, embedded as a CBOR value, not a bstr) and `-70009` attestations (array of nested envelopes).
Implementation: uses exactly those labels. `-70009` is parsed as a known name in the JSON view but not processed until M2.
Resolution: Resolved in Draft 02, section 5 (Unprotected header, Provisional labels). As proposed, plus the inclusion proof now has label -70012 (the Draft 01 CDDL used -70010, which collides in number with the ML-KEM-768 alg id).

## 3. Media types for SRLs and log checkpoints
Sections 5 and 7 name `application/atep-attestation+cbor` but section 5 also lists "revocation lists and log checkpoints" as the other unencrypted trust documents without giving media types, so a verifier cannot apply the "unencrypted only if trust document" rule to them.
Proposed fix: define `application/atep-srl+cbor` and `application/atep-checkpoint+cbor`.
Implementation: uses those two provisional types.
Resolution: Resolved in Draft 02, section 5 (Provisional labels table), sections 8 and 9. As proposed.

## 4. Content type alone decides whether encryption is required
Section 5 lets header 3 be "the payload's own media type". A sender can label any payload with a trust document media type and so skip encryption. The rule is purely label based.
Proposed fix: state that a verifier of an unencrypted envelope MUST also validate the payload against the trust document schema for that media type (M2 for attestations), and reject if it does not parse.
Implementation: M1 checks the label only. Step 1 rejects unencrypted non-trust-document types.
Resolution: Resolved in Draft 02, section 5 (Encryption rule). Modified: the proposed MUST reject at step 1 on schema failure contradicts the M1 vectors (their `application/atep-attestation+cbor` payloads are not attestation-shaped and must verify). The spec states the label decides step 1, and that any consumer interpreting the payload as a trust document MUST schema-validate it. See Code follow-ups.

## 5. Hybrid KEM wire format is not defined
Sections 5 and 6 say "COSE_Encrypt wrapping the signed envelope, hybrid X25519 + ML-KEM-768" but define no recipient structure, header labels, algorithm identifiers or outer protected header.
Proposed fix: specify (as implemented here): `96([protected{1:3(A256GCM), -70001:1, -70007:"ATEP-1"}, {5: iv12}, ciphertext, [[ {1:-70011}, {4: recipient AgentID, -1: ephemeral X25519 COSE_Key, -70013: ML-KEM-768 ciphertext}, h'' ]]])` with AAD = Enc_structure `["Encrypt", protected, h'']`. Provisional ids: `-70010` ML-KEM-768 key alg, `-70011` ATEP-1 hybrid KEM recipient alg, `-70013` KEM ciphertext header. Putting version and suite in the outer protected header lets step 1 check them before decryption.
Resolution: Resolved in Draft 02, section 6 (Encrypted envelope wire format). As proposed.

## 6. KDF input layout is ambiguous and omits ciphertext binding
Section 6 gives "KDF(ss_classical || ss_pq || context)" and "Context string ATEP-1-KEM" without saying salt, info, or output length, and the context shown inside the KDF input conflicts with HKDF's separate `info`.
Proposed fix: HKDF-SHA-256, salt empty, ikm = ss_x25519 || ss_mlkem768, info = `"ATEP-1-KEM" || eph_x25519_pub || recipient_x25519_pub || mlkem_ciphertext`, 32 byte output. Binding the public values follows combiner practice for X25519-based hybrids (X-Wing style) and costs nothing.
Implementation: exactly this. Vectors publish all intermediates.
Resolution: Resolved in Draft 02, section 6 (Key derivation). As proposed.

## 7. COSE_Key encodings and algorithm identifiers
Section 4 says each public key is a COSE_Key "with its alg set" but gives no kty/crv/alg values, and the enc_keys element layout is open.
Proposed fix: Ed25519 `{1:1, 3:-8, -1:6, -2:x}`; ML-DSA-65 `{1:7 (AKP), 3:-49, -1:pub}`; X25519 `{1:1, 3:-25, -1:4, -2:x}`; ML-KEM-768 `{1:7, 3:-70010, -1:pub}`; bundle `[ed, mldsa, [x25519, mlkem]?]` where the third element is omitted (not null) when absent. `-49` for ML-DSA-65 and kty 7 follow draft-ietf-cose-dilithium and are provisional.
Resolution: Resolved in Draft 02, section 4 (Key bundle table and Agent ID). As proposed.

## 8. ML-DSA signing mode, context and message
Section 5 says both signatures cover "the same Sig_structure" but not which FIPS 204 variant. Hedged and deterministic signing both verify, but vectors need one choice.
Proposed fix: pure ML-DSA (FIPS 204 Algorithm 2/3, not HashML-DSA), empty context string, message = the encoded RFC 9052 Sig_structure with empty external_aad. Vectors use the deterministic variant (rnd = 32 zero bytes). Ed25519 is pure EdDSA over the same bytes, verified in strict mode (rejects non-canonical S and small-order components).
Resolution: Resolved in Draft 02, section 5 (Sig_structure and signing modes). As proposed; signing MAY be hedged or deterministic, vectors use deterministic.

## 9. Receiver strictness for CBOR
Section 12 says to treat all CBOR per RFC 8949 deterministic rules "when signing" only. A receiver that re-encodes parsed values (for the Agent ID) would otherwise accept non-canonical bundles.
Proposed fix: a verifier MUST reject any ATEP structure that is not deterministically encoded (shortest-form heads, definite lengths, sorted unique map keys) at step 1.
Implementation: strict decoder, rejects at step 1 (`malformed_cbor`). Floats and undefined are also rejected as ATEP uses none.
Resolution: Resolved in Draft 02, section 5 (Encoding rules), section 12 and step 1. As proposed, with trailing bytes rejected and a MAY bound on nesting depth (reference: 32).

## 10. Step 1 versus step 2 order for encrypted envelopes
Step 1 requires the protected header to contain every REQUIRED field, but for tag 96 the signed headers exist only after step 2. Step 10 also says to "reject on first failure".
Proposed fix: step 1 applies to the outer COSE_Encrypt (tag, version, suite, algorithm) and is applied again to the inner COSE_Sign after step 2, still reported as step 1.
Implementation: as proposed. Inner decode failures are reported as step 1.
Resolution: Resolved in Draft 02, section 10 steps 1 and 2. As proposed; the step 1 sub-order from the vectors is written out.

## 11. Step 8 boundary
Step 8 rejects when `revoked-at` is earlier than `issued-at`; an envelope issued exactly at `revoked-at` is undefined. Section 8 says "after revoked-at".
Proposed fix: reject when `revoked-at <= issued-at` (fail safe), and state it.
Implementation: `<=`.
Resolution: Resolved in Draft 02, section 8 (Identity revocation) and section 10 step 8. As proposed (`<=`).

## 12. Detached payload delivery
Section 5 allows a nil payload bound by the digest, but step 4 and 7 do not say where the verifier gets the bytes.
Proposed fix: add that the verifier is given the payload out of band and rejects (step 4) when a detached envelope is verified without it.
Implementation: `Policy.detached_payload`; missing payload is `detached_payload_missing` at step 4.
Resolution: Resolved in Draft 02, section 5 (Payload) and section 10 step 4. As proposed.

## 13. Signature order and counting
Section 5 says "exactly two" signatures, one EdDSA and one ML-DSA-65, but not their order, and section 10 lists the check under no step.
Proposed fix: signers emit EdDSA first, verifiers accept either order; the shape check (exactly one of each, no extras) belongs to step 1 as part of "algorithm identifiers match the suite".
Implementation: as proposed; `signature_count_invalid` and `algorithm_suite_mismatch` at step 1.
Resolution: Resolved in Draft 02, section 5 (Signatures array) and section 10 step 1. As proposed.

## 14. Size estimates in section 5
Section 5 says about 100 bytes of headers and about 4.5 KB for a 1 KB payload. Measured: protected header 175 bytes with the attestation media type (33 characters), two signature entries add about 110 bytes of framing and kids, giving about 4.6 KB for a 1 KB payload without a bundle (about 6.6 KB with the 1.97 KB bundle inline). An encrypted envelope adds about 1.2 KB (ML-KEM ciphertext, ephemeral key, kid, tag).
Proposed fix: say "about 350 bytes of headers and framing" and quote sizes with and without the inline bundle. Section 17's 4.7 KB encrypted telemetry figure is too low for the same reason.
Resolution: Resolved in Draft 02, section 5 (Size) and section 17 (Constrained hardware). Modified: measured framing is about 280 bytes (3,698 B envelope minus 51 B payload minus 3,373 B of signatures is 274), not the proposed 350, giving about 4.7 KB, 6.7 KB with bundle, and 5 KB for a small encrypted telemetry envelope.

## 15. Agent ID example length
Section 4 says the example `atep:k7h2mqv3...` is 52 characters. The base32 part is 52 characters; the full string is 57.
Proposed fix: say "52 base32 characters after the prefix".
Resolution: Resolved in Draft 02, section 4 (Agent ID). As proposed.

## 16. Appendix A label range
Appendix A says labels -70001 to -70006 were assigned, but section 5 also assigns -70007 (suite).
Proposed fix: change to "-70001 to -70007".
Resolution: Resolved in Draft 02, Appendix A row on header labels. As proposed.

## 17. Attestation `expires-at` and step 1
Section 5 makes `expires-at` REQUIRED for attestations but no verification step checks it before step 9.
Implementation: rejected at step 1 (`missing_expires_at`) when the content type is the attestation media type. Proposed fix: add to step 1.
Resolution: Resolved in Draft 02, section 7 and section 10 step 1 (value still compared at step 5). As proposed.

## Added in Draft 02
ATEP-R command class had no protected header label (section 17 said "tagged in the protected header"). Draft 02 assigns provisional label -70014 `command-class` (text, REQUIRED in ATEP-R envelopes, section 5 and 17, `atep.cddl`). The core verifier ignores unknown protected labels, so the Rust code needs no change until ATEP-R enforcement exists.

## Code follow-ups
No change is needed for the M1 vectors to keep passing: Draft 02 documents what the code and vectors do. Items for later milestones:

1. M2 (issue 4): when attestation, SRL and checkpoint parsing lands, schema-validate the payload of any envelope that is consumed as a trust document, and reject malformed ones. The current M1 `signed-*` and `trust-doc-*` vectors carry placeholder payloads under trust document content types, so M2 needs schema-valid payloads (new vectors, or keep these as core-verifier-only vectors).
2. M2: process the `-70009` inline attestations (already parsed by name only) and the `-70012` inclusion proof (no code reads it yet).
3. ATEP-R milestone: parse `-70014` command-class and enforce the section 17 claim table; reject ATEP-R envelopes that lack it.
4. Optional: the spec says implementations MAY bound CBOR nesting depth (the code uses 32). No change required.
5. Documentation only: `vectors/README.md` and `rust/atep-core/src/lib.rs` still say Draft 01 and list -70013 as an implementation choice and the inclusion label as open; refresh them when the code is next touched.

Status after M2: items 1, 2, 3 and 5 are done. Attestation, SRL and checkpoint payloads are schema-validated where they are consumed (`attestation.rs`, `srl.rs`, `log.rs`); the M1 `signed-*` and `trust-doc-*` vectors stay core-verifier-only vectors with placeholder payloads, and the M2 vectors use schema-valid payloads. `-70009` and `-70012` are processed at step 9 and `-70014` is parsed and enforced under `TrustPolicy::atep_r`. Item 4 needs no change.

## Entries from the second milestone (Draft 02)

Status: entries 18 to 31 are resolved in Draft 03 (Draft 03, ). Each entry ends with a Resolution line.

Found while implementing attestations, SRLs, the trust policy engine, inclusion proofs and ATEP-R. Each entry: section, problem, proposed fix, and what the Rust reference implementation does meanwhile. None of these changed an M1 vector. Numbering continues from the M1 list.

## 18. `issuer-authority` data layout and delegation scope
Section 7 says an `issuer-authority` attestation means "Subject may issue the listed claim types" but defines no `data` field, and does not say whether a delegate may be given more than the delegator holds.
Proposed fix: `data` is `{"claims": [claim URI, ...]}`; an issuer is authorized for claim C when it is a root, or holds an `issuer-authority` attestation listing C whose own issuer is authorized for `issuer-authority` and for C. To delegate further the list must contain the `issuer-authority` URI itself. Roots may issue any claim.
Implementation: exactly this (`Attestation::authority_claims`, `Ctx::authorize`).
Resolution: Resolved in Draft 03, section 7 (Data layouts of the core claims, Chains with pseudocode). As proposed.

## 19. Chain depth is not defined
Section 7 says chains MUST be bounded with a recommended maximum depth of 5 without saying what is counted.
Proposed fix: depth is the number of attestations in the chain, the claim attestation included (a claim issued directly by a root has depth 1). Default maximum 5.
Implementation: as proposed; `TrustPolicy::max_depth`, error `chain_depth_exceeded`. A chain may also not repeat an issuer (`chain_cycle`).
Resolution: Resolved in Draft 03, section 7 (Chains, rules 3 and 4) and section 10 (error table). As proposed.

## 20. What "chaining to root R" means
Section 7 and 9 speak of "a root issuer in its trust policy" and a rule form "from an issuer chaining to root R" but not whether R is optional or how roots relate to claims.
Proposed fix: the policy has a root set; a rule MAY name one root from that set, otherwise any root in the set is accepted. A root is trusted for every claim type. A rule that names a root outside the set is a policy error.
Implementation: as proposed (`Rule::root`, `policy_invalid`).
Resolution: Resolved in Draft 03, section 7 (Chains rule 1, Trust policy) and section 10 step 9 in detail. As proposed; the policy file format and its CDDL (`atep.cddl`, `trust-policy`) are now in the spec.

## 21. Audit-backed claims and the evidence requirement
Section 7 lists `audited`, `safety-certified` and "any claim that requires an evidence hash" as audit-backed (up to 400 days), and says `audited` needs an evidence hash, but the schema marks `evidence` optional and no rule says which claims require it. The 180 day default is a SHOULD, which a verifier cannot meaningfully enforce.
Proposed fix: `audited` and `robotics/safety-certified` REQUIRE `evidence`; an attestation carrying `evidence` is audit-backed; the 180 day default is enforced by issuers only and verifiers enforce only the 400 day maximum.
Implementation: issuance refuses more than 180 days for non audit-backed claims unless asked (`allow_long_default`, CLI `--allow-long`); the verifier enforces 400 days (`attestation_lifetime_exceeded`) and the evidence requirement (`attestation_schema_invalid`).
Resolution: Resolved in Draft 03, section 7 (Evidence requirement, lifetime tiers). As proposed.

## 22. SRL entry `id` has two meanings
Section 8 and the CDDL give `id` as an attestation id (16 bytes) or an Agent ID (32 bytes) but do not say how they are told apart or what `reason` means for identities.
Proposed fix: distinguish by length; every 32 byte entry is an identity revocation (reason `compromised`, or `retired`). Attestation entries apply only to attestations issued by the SRL's own issuer.
Implementation: as proposed. For step 8 every identity entry counts regardless of its reason text (fail safe). An attestation is checked only against the SRL whose `issuer` is the attestation's issuer. For identity entries any cached SRL counts, as section 10 step 8 says ("any cached SRL").
Resolution: Resolved in Draft 03, section 8 (SRL payload) and section 10 step 8. As proposed; stated explicitly that the reason text never affects step 8 and that attestation entries ignore `revoked-at`.

## 23. SRL freshness, missing lists and sequence handling
Section 8 says a cached copy "past next-update" triggers a local policy but gives no boundary, says nothing about an issuer whose SRL was never fetched, and gives `sequence` no semantics.
Proposed fix: stale when `now >= next-update` (fails safe, like step 8); a missing SRL is treated as unreachable and follows its own policy setting; `next-update` MUST be later than `issued-at`; a cache refuses a lower `sequence` than the one it holds (rollback) and a different list with the same sequence.
Implementation: `SrlPolicy {on_stale, on_missing}` with defaults fail-closed for stale and fail-open with a warning for missing, so a fresh verifier still works; errors `srl_stale`, `srl_unavailable`, `srl_rollback`, `srl_sequence_conflict`. Stale lists are still used for step 8 entries (a revocation is never forgotten).
Resolution: Resolved in Draft 03, section 8 (Loading an SRL, Freshness, Warnings). As proposed, with the warning strings now normative.

## 24. Step 8 on attestation issuers, and `retired` attestations
Step 8 checks "the signer". Step 9 recursion verifies attestations "as envelopes (steps 1 to 8)", so an issuer that was compromised before issuing an attestation invalidates it, but an attestation issued before `revoked-at` stays valid. Section 4 also says a `retired` self-attestation makes later envelopes rejectable, but step 8 only mentions SRLs.
Proposed fix: state both consequences. For `retired`, say whether step 8 consults self-signed `retired` attestations.
Implementation: recursion includes step 8 (error `attestation_invalid` with cause step 8). `retired` self-attestations are NOT consulted at step 8 in M2 (only SRL entries are).
Resolution: Resolved in Draft 03, section 10 step 8 and section 7 (Retirement and succession). Both consequences are stated. Modified: Draft 03 also specifies that step 8 consults valid `retired` self-attestations held in the verifier's local store (inline attestations of the envelope are not consulted). No vector covers this and neither the Rust nor the Python code implements it yet (section 12, gap 1; section 20, decision 16).

## 25. Merkle leaf definition and where the inclusion proof lives
Section 9 says each leaf is "the SHA-256 of a submitted envelope" and also "RFC 6962 / RFC 9162 style", which hashes leaves as `SHA-256(0x00 || leaf)`. It also says the proof is embedded in the attestation's unprotected header, so the attestation that was logged cannot contain its own proof.
Proposed fix: the leaf hash is `SHA-256(0x00 || submitted envelope)` and the submitted envelope is the attestation with its `-70012` entry removed, re-encoded deterministically. The inclusion proof is the map `{leaf-index, audit-path, checkpoint}` with text keys (as in the CDDL) and the checkpoint embedded as a CBOR value. Checkpoint payload keys are `tree-size`, `root-hash`, `timestamp`.
Implementation: as proposed (`log.rs`, `envelope::submitted_form`); `crosscheck.py` re-derives the leaf in Python.
Resolution: Resolved in Draft 03, section 9 (Log structure, Submitted form, Checkpoints, Submission and the inclusion proof). As proposed; the Draft 02 sentence that the leaf is the bare SHA-256 of the envelope is corrected.

## 26. Inclusion proofs: scope, checkpoint trust and freshness
Section 9 says a verifier MAY require a valid proof "against a checkpoint it trusts" for "any attestation it relies on".
Proposed fix: when required, every attestation in the chain (claim attestation and delegations) needs a proof; a checkpoint is trusted when signed by a log in the verifier's `trusted_logs`; the result reports the checkpoint with the latest timestamp. Checkpoint age limits are left to a later draft (the log service defines hourly cadence).
Implementation: as proposed; no maximum checkpoint age is enforced. The check is behind the `InclusionCheck` trait so the M3 log client can replace the offline checker.
Resolution: Resolved in Draft 03, section 9 (Checking an inclusion proof) and section 7 (Trust policy, `require_inclusion`). As proposed; no maximum checkpoint age is defined (section 14, open).

## 27. Where step 9 gets its attestations
Section 10 step 9 says "collect attestations for the signer" without saying from where, but only the unprotected `-70009` header is defined, which is unsigned.
Proposed fix: sources are the envelope's `-70009` array, attestations those attestations carry in their own `-70009`, and a verifier-local store. All of them are untrusted input: each is fully verified before use. Verifiers SHOULD bound the pool.
Implementation: pool of at most 256 envelopes, nesting up to 8 levels, deduplicated by SHA-256; candidates are selected by payload `subject` and `claim` and then fully validated, so a malformed candidate is reported rather than skipped. Replay (step 6) is not applied to attestations, which are meant to be reused.
Resolution: Resolved in Draft 03, section 7 (The attestation pool, Candidate selection). As proposed, with the order, bounds and deduplication written out.

## 28. ATEP-R: how an e-stop is recognized and what the exception covers
Section 17 says an e-stop "MUST be accepted from any fleet-member with safety-certified" and "honored even if the sender's other claims have expired", but the payload is opaque to ATEP and the header only carries the class `safety`. It also does not say which claims the exception covers.
Proposed fix: define the e-stop recognition (a `safety` payload that is a CBOR map with `command` equal to `"e-stop"`, or a separate command class, for example `safety-estop`), and say the exception covers claim expiry only, not revocation, signatures, chains or the envelope's own `expires-at`.
Implementation: payload convention above, anything unrecognized is an ordinary safety command needing `safety-authority`; expiry of attestations is ignored for the e-stop requirement, everything else is enforced (`atep_r::is_estop`).
Resolution: Resolved in Draft 03, section 17 (E-stop recognition). As proposed (the payload convention, not a separate class).

## 29. ATEP-R: `peer-motion` data and the receiver
Section 17 says `peer-motion` lists "the listed peers" without a layout, and a `fleet-member` with "peer-motion delegation" can send motion.
Proposed fix: `data.peers` is an array of Agent IDs (byte strings); the delegation counts when the receiving agent is listed.
Implementation: as proposed; the receiver is the verifier's recipient identity, and without one the peer-motion alternative is not offered.
Resolution: Resolved in Draft 03, section 7 (Data layouts) and section 17 (`peer-motion`). As proposed.

## 30. ATEP-R: which classes fail closed, and how a verifier knows it is ATEP-R
Section 17 says revocation lists past `next-update` cause "motion and actuation" to fail closed and telemetry MAY continue, which leaves sensor, coordination, safety and maintenance open. It also says the class header is REQUIRED in ATEP-R envelopes, but an attacker can simply omit a header, so the envelope cannot say whether it is ATEP-R.
Proposed fix: (a) fail closed, on a stale or missing SRL, for motion, actuation, maintenance and non e-stop safety; continue with a warning for telemetry, sensor, coordination and e-stop. (b) ATEP-R is a verifier policy setting for a channel; under it an envelope without a valid class, or without encryption, is rejected at step 1.
Implementation: as proposed (`TrustPolicy::atep_r`; step 1 codes `missing_command_class`, `unknown_command_class`, `atep_r_unencrypted`). The per-class SRL mode replaces the configured one.
Resolution: Resolved in Draft 03, section 17 (Enforcement, Fail-closed and fail-open classes). As proposed.

## 31. Vector categories for M2
Section 12 lists "Attestations and chains" and "SRL and log" without file layouts or result shapes.
Proposed fix: adopt the categories `attestation`, `chain-positive`, `chain-negative`, `srl`, `log`, `atep-r-positive` and `atep-r-negative` and the result shapes documented in `vectors/README.md`, including the step 9 error codes and the `cause` field for failures of steps 1 to 8 inside an attestation.
Implementation: as documented; the README is the format definition until the spec grows an appendix.
Resolution: Resolved in Draft 03, section 12 (Vector categories, Vector files). The spec now states the categories and result shapes; `vectors/README.md` remains the file format reference.

## Entries from the third milestone (Draft 02)

Status: entries 32 to 41 are resolved in Draft 03. Each entry ends with a Resolution line.

Found while building the registry (log, API, gossip) and the monitor. Same format as above; numbering continues. None of these changed an existing vector; the new vectors are the 13 `log` vectors listed in `vectors/README.md`.

## 32. Roadmap names Go for M3; the reference implementation is Rust
Section 13 says the M3 deliverable is a "Go service". The build machine has no Go toolchain and no C compiler, and a Go log would need its own hybrid (Ed25519 plus ML-DSA-65) envelope verifier for submission validation and for checking checkpoints, which risks divergence from the M1 and M2 code and vectors.
Proposed fix: say "a service" in the roadmap and make the language an implementation choice; the normative interface is the wire formats and the vectors. An independent Go log or monitor remains welcome and is exactly what the log vectors are for.
Implementation: M3 is Rust: `atep-log` (library, `atep-logd` server) and `atep-monitor`, reusing `atep-core` for every verification.
Resolution: Resolved in Draft 03, section 13 (M3 row). As proposed: the roadmap reports the Rust reference log and monitor honestly and keeps a Go log welcome.

## 33. The log policy has no envelope type
Section 9 says the log policy "is itself recorded in the log", and the log holds only envelopes (leaf = hash of a submitted envelope), but section 5 allows only attestations, SRLs and checkpoints to be signed without encryption, and none of them is a policy document.
Proposed fix: the policy is an attestation issued by the log to itself (subject and issuer are the log, a claim type in the operator's own namespace, the policy in `data`), so no new media type is needed. A changed policy is a new entry; the latest entry governs. The claim type must not be under `https://atep.dev/claims/` (the core vocabulary is closed, issue 36).
Implementation: claim `https://atep.dev/log/policy` (provisional), lifetime 365 days and re-issued before it lapses or when the configuration changes. The policy is entry 0 of a new log and is served at `GET /v1/policy` with its inclusion proof. Fields: `version`, `log`, `operator`, `admission`, `retention`, `availability`, `checkpoint-interval-seconds`, `checkpoint-media-type`, `max-envelope-bytes`, `key-custody`, `core-namespace`, `core-claims`, `commitments`.
Resolution: Resolved in Draft 03, section 9 (The log policy entry). As proposed, with the field list.

## 34. Consistency proofs, checkpoint pairs and split view evidence have no format
Section 9 requires logs to detect a log "that shows different trees to different viewers" and monitors to alert on "a gap in consistency proofs", but defines no consistency proof structure, no way to hold two checkpoints as evidence, and no rule for when a failed proof means a split view rather than an error.
Proposed fix: a consistency proof is the map `{from, to, path}` (tree sizes and an array of 32 byte hashes, RFC 9162 section 2.1.4). Evidence is the map `{a, b, proof?}` of two checkpoint envelopes of one log, or `{old, new, proof}` for a proof between them. Two valid signed checkpoints of one log are a split view when they have the same tree size and different roots, or different sizes and a failing consistency proof; both are transferable evidence that needs only the log's public key. A proof between checkpoints of different sizes that is missing is a gap, not a split view.
Implementation: as proposed (`atep_core::log::ConsistencyProof`, `ConsistencyEvidence`, `CheckpointPair`, `OfflineInclusion::check_consistency` and `check_split_view`), error codes `consistency_proof_invalid` and `split_view_detected`, and the 13 M3 `log` vectors.
Resolution: Resolved in Draft 03, section 9 (Consistency proofs, Split views). As proposed.

## 35. Checkpoint cadence, on-demand checkpoints and proof freshness
Section 9 says checkpoints are signed "at least hourly" and that a submission returns a Signed Inclusion Proof containing "the checkpoint", but a proof can only be verified against a checkpoint that already covers the new leaf, and the spec does not say whether an idle log must still sign hourly or what a verifier does with an old checkpoint (issue 26 left this open).
Proposed fix: a log signs a fresh checkpoint at least every interval even when the tree did not change (the timestamp is the freshness signal), signs on demand, and answers a submission with a checkpoint that covers the new entry, either by signing one per submission or by a published maximum merge delay. Checkpoint timestamps never decrease.
Implementation: the log signs a checkpoint for every new entry (so the proof is immediately verifiable), on demand (`POST /v1/checkpoint`) and whenever `--checkpoint-interval` (default 3600 s) has passed. Timestamps are `max(now, previous)`. A high volume operator would batch submissions and publish a merge delay in the policy.
Resolution: Resolved in Draft 03, section 9 (Cadence and freshness). As proposed.

## 36. What a log must check at admission, and what it must not
Section 9 says issuers "submit every attestation and SRL" and section 16 lists commitments, but not what the log checks. Draft 02 section 5 says any component that interprets a payload must validate it, and step 9 chain validation needs roots a log does not have.
Proposed fix: a log accepts an envelope only when it is signed-only with content type attestation or SRL (never encrypted, never a data type, never a checkpoint), passes steps 1 to 8 at the log's clock with the signer bundle inline or already logged, matches the payload schema (including the 400 day maximum and, for SRLs, an increasing `sequence` per issuer), and, for the reserved namespace `https://atep.dev/claims/`, names a claim of the core vocabulary. The log does not judge issuer authority (no mandatory root, section 16 point 3): monitors do. Resubmission is idempotent, keyed by the submitted form (the envelope without `-70012`, issue 25). A subject that is a natural person (section 16 point 1) cannot be detected from the payload; it is an operator policy enforced through the closed core vocabulary and review.
Implementation: as proposed. Step 8 uses the identity entries of the SRLs already in the log. Entries are re-validated at their original logging time when the log restarts. `logged-at` is stored for each entry but is not part of the leaf, so only checkpoint timestamps are committed.
Resolution: Resolved in Draft 03, section 9 (Admission). As proposed, with the refusal reasons.

## 37. `domain-control` data layout and the meaning of "watched domain"
Section 7 says `domain-control` binds a subject to a DNS name proven by a record, and section 9 has monitors alert on "a domain-control attestation for a domain the monitor owns but did not authorize", but no `data` field names the domain and nothing says whether subdomains count.
Proposed fix: `data` is `{"domain": "<lowercase DNS name>"}`. A monitor watching `example.com` also watches every name below it. Whether the issuer actually checked the DNS or well-known record cannot be decided from the log; it is the monitor owner's reason to alert.
Implementation: the log refuses `domain-control` without a canonical `data.domain`; the monitor matches the name or any subdomain and alerts when the subject is not among the Agent IDs it was configured to authorize.
Resolution: Resolved in Draft 03, section 7 (Data layouts) and section 9 (Monitors). As proposed.

## 38. Monitor alerts: "outside its delegated claim types" and "gap"
Section 9 lists three anomalies without defining them.
Proposed fix: an issuer is outside its authority when it issues claim C at time T and is neither a root of the monitor nor holds, at T, a live (not expired, not on a logged SRL) `issuer-authority` attestation that lists C and whose issuer is authorized for `issuer-authority` and for C (issue 18, depth at most 5). An `issuer-authority` attestation that lists claims its issuer does not hold is the same finding. An issuer with no delegation at all and no root status is outside the delegation system: it is reported only in a strict mode. A gap is a published checkpoint pair for which the log does not supply a consistency proof, entries the log does not return for a tree size it signed, or entries that do not hash to the signed root.
Implementation: as proposed; delegations count when they are in the log at the time the monitor analyzes the entry (a delegation logged later does not clear an earlier alert). Alert types: `unauthorized_domain_control`, `issuer_outside_authority`, `undelegated_issuer`, `inconsistent_checkpoint`, `checkpoint_gap`, `tree_shrank`, `entry_root_mismatch`, `entry_gap`, `entry_invalid`, `bad_checkpoint`, `split_view`, `source_unavailable`.
Resolution: Resolved in Draft 03, section 9 (Monitors). As proposed. Modified: the chain depth in monitors is counted like the verifier counts it (attestations including the judged one); the reference monitor allows one more delegation, a code follow-up (section 20, decision 19).

## 39. Registry services have no defined shape
Section 9 lists issuer directory, claim-type directory, lookup and gossip as "layered on the log" without content.
Proposed fix: the directories are derived data that anyone can recompute from the entries and the policy, and carry no authority. Issuer directory row: issuer, first entry, claim types issued, namespaces, claim types delegated to it and by whom, self-bound domains with the SRL location `https://<domain>/.well-known/atep-revocations.cbor`, latest logged SRL, inclusion status. Claim-type directory row: URI, core or open, counts, definition and `data` schema for the core vocabulary. Lookup returns attestations whose subject is the Agent ID. Because lookup is a query by subject, it MUST serve attestations and SRLs only (never agent traffic, section 16 point 5) and operators SHOULD rate limit it.
Implementation: `GET /v1/issuers`, `/v1/claims` and `/v1/lookup` as described in `rust/docs/log-api.md`. Definitions for the core vocabulary are built in; other claim types appear with no definition.
Resolution: Resolved in Draft 03, section 9 (Registry services). As proposed, with the directory rows listed.

## 40. Gossip has no protocol
Section 9 names checkpoint exchange between independent logs and verifiers' use of "multiple independent logs" but defines no exchange.
Proposed fix: any node (log or monitor) may hand any other node signed checkpoints, its own and third-party ones it has seen. The receiver verifies each one, compares it with every checkpoint it holds for the same signing log, keeps new ones, and produces split view evidence (issue 34) when it finds a contradiction. Relaying third-party checkpoints is what lets two viewers of one equivocating log find out, because neither sees both views directly. Proofs between sizes come from the log in question when the receiver can ask it, or travel with the message.
Implementation: `POST /v1/gossip` (checkpoints and optional proofs in, results plus the receiver's own and relayed checkpoints out, HTTP 409 when a split view is found), `GET /v1/gossip`, in-process `gossip::exchange` and `client::exchange_remote`, and `--peer` in `atep-logd`. Observed checkpoints and evidence are persisted.
Resolution: Resolved in Draft 03, section 9 (Gossip). As proposed.

## 41. Transport, log identity bootstrap and log key rotation
Section 9 says the log's data and APIs are published but gives no transport, and a verifier needs the log's Agent ID and bundle before trusting a checkpoint.
Proposed fix: the API is HTTP with JSON, plus CBOR responses (`Accept: application/cbor`, checkpoints as `application/atep-checkpoint+cbor`); TLS is an operational layer and carries no trust (all data is signed). A verifier learns a log's Agent ID out of band (published with the policy, root set or software), exactly like roots. A log key is rotated with a `successor` attestation issued by the old key and logged, and monitors treat more than one hop as an alert (section 11).
Implementation: plain HTTP/1.1 on `std::net` (no TLS; put a TLS terminating proxy in front), the log writes its bundle to `log.pub`, and rotation is not implemented.
Resolution: Resolved in Draft 03, section 9 (Log API and transport, Log identity and key rotation). As proposed; log key rotation is not implemented yet (section 13).

Entries 42 to 49 were found while implementing `retired` and `successor` (Draft 04) and are resolved in Draft 05.

## 42. Section 12 fixtures for `retired` and `successor` cannot hold for the retired issuer
The fixtures of the case tables say "fresh SRLs that name nothing are cached for every issuer involved" and name an SRL entry "for O" (SU11, SU12) or "of X" (RT10, RT28, RT29). Taken literally they conflict with RT24 and decision 36: an SRL issued after the retirement or compromise instant of its own issuer cannot be loaded (step 8), so a list of X at the usual fresh time (`issued-at` 1799996400) cannot be cached when R (1799990000) is in the store, and the same holds for O in SU9 to SU11 and SU24. An SRL entry that names O as compromised cannot be in O's own list for the same reason (its `revoked-at` is not after its `issued-at`).
Proposed fix: the fixture reads "SRLs that name nothing are cached for every issuer involved, issued before any instant from which that issuer is retired or revoked and not yet past `next-update`", and an entry that names O or X is in the list of another issuer (the root `i` in the vectors).
Implementation: the SRL of X is issued at 1799980000 and the SRL of O at 1799400000, both with `next-update` 1800082800 (still "fresh" at `now`); the SRLs of the other issuers are issued at 1799996400 as in the chain vectors; entries naming X or O are in the SRL of `i`.
Resolution: Resolved in Draft 05, section 12 (case tables, fixture of the SRLs; decision 45). The tables now state the fixture the vectors use.

## 43. SU21 and SU22: the fixture rule cannot be satisfied by a `fleet-member` attestation
The succession fixture has the rule `operator` from I. SU21 and SU22 add `atep_r` and give O a `fleet-member` attestation only, so with the fixture rule in place the verification would fail on the rule `operator` (`claim_missing`) before the class requirement is looked at, and SU21 could not accept.
Proposed fix: say that SU21 and SU22 use the fixture policy without the rule list (`rules` empty), so that the class requirement is the only thing evaluated.
Implementation: the policy of both vectors is `{roots: [I], rules: [], atep_r: true, follow_succession: true}` (and without `follow_succession` for SU22). The result has one claim, `fleet-member`, with the chain `A_O`, `SUC`.
Resolution: Resolved in Draft 05, section 12 (SU21, SU22; decision 46). The policy of both cases has no rule list.

## 44. RT31: the refusal of a `retired` attestation for another subject depends on its `issued-at`
RT31 submits "a `retired` attestation with `issuer` X and `subject` Y" after R and expects `schema_invalid`. A log applies steps 1 to 8 before the payload rules (section 9, admission order), and only a `retired` attestation whose subject and issuer are both X is exempt from step 8 (section 7). If that document is issued at or after R's `issued-at` and R is logged, it is refused as `verification_failed` at step 8 and never reaches the schema rule.
Proposed fix: RT31 says the second document is submitted to a log that does not hold R (or is issued before R's `issued-at`).
Implementation: vector `rt31b` submits it to a log that holds nothing, `rt31a` (R2 after R) holds R.
Resolution: Resolved in Draft 05, section 9 (Admission) and section 12 (RT31; decision 47). The second part is submitted to a log that does not hold R.

## 45. The section 12 tables have no vector form for the load, admission and monitor cases
RT24 and RT25 load an SRL in the verifier's context, RT30, RT31 and SU26 are log admission and SU25 is a monitor result. Section 12 gives the verification and the SRL vector formats, which have no input for a local attestation store at SRL load, no form for a log's state, and no monitor form. `vectors/README.md` describes only the formats of the first 140 vectors.
Proposed fix: add the three formats to section 12 (the vectors README is the reference until then).
Implementation: three new categories. `srl-context`: the inputs of the `srl` vectors plus the optional `attestations` (store) and `revocations`. `log-admission`: the submission, with `inputs` `now`, `log`, `max_envelope_bytes` and `logged` (hex of the submitted forms the log already holds); `expected` `{ok, document}` or `{ok: false, refusal, step?, error?}`. `monitor`: a map `{"entries": [envelope, ...]}`; `expected` `{alerts: [{alert, entry, issuer, subject}]}`, entry indices counted from the first entry of the vector. The Rust log and monitor run the same vectors in their own tests, and `atep-vectors check` runs them through `atep_core::admission` and `atep_core::succession`, which the log and the monitor call.
Resolution: Resolved in Draft 05, section 12 (Formats of the categories added in Draft 04 and 05; decision 48). `vectors/README.md` remains the file format reference.

## 46. `successor_chain`: "the later link" is ambiguous, and the fork stays open
Section 9 says the alert carries `entry` ("the later link"), `issuer` and `subject`. "Later" can mean later in the chain (the link whose issuer is the subject of the other) or later in the log. The two differ when the links were logged in the reverse order.
Proposed fix: say that `entry` is the link whose `issuer` is the `subject` of another logged `successor` attestation, whatever the log order, and that a link logged later raises the alert for an earlier entry too.
Implementation: `atep_core::succession::chain_links`: the links whose issuer is the subject of another link, in entry order; the monitor raises each once. A fork (one identity naming two successors) is not an alert: section 14 leaves the question open and no decision of Draft 04 adds it.
Resolution: Resolved in Draft 05, section 9 (Monitors, `successor_chain`; decision 49): `entry` is the link whose issuer is the subject of another logged `successor`, in either log order. The fork alert stays open (section 14, decision 62) and is not implemented.

## 47. RT25 does not exercise the reload rule of section 7
Section 7 says a list that names its own issuer from an instant at or before its own `issued-at` fails step 8 when it is loaded into a context that already holds it, and "a verifier SHOULD treat a failed reload of the bytes it has cached as no change". RT25 uses an entry later than the list's `issued-at`, so both loads pass whether or not an implementation has that rule.
Proposed fix: add a case: a list that names its own issuer from before its `issued-at`, loaded twice (the second load is no change), and then a newer list of the same issuer, which fails step 8.
Implementation: `srl::ingest_in` returns the cached list when the bytes are identical, before any verification; the case above is a unit test (`atep-core/tests/retired_successor.rs`), not a vector.
Resolution: Resolved in Draft 05, section 8 (Loading an SRL; decision 50): cached bytes are accepted first and are no change, a MUST. Case RT32 has no vector yet (section 12, known gap 1).

## 48. The exemption of step 8 is decided on the shape of the payload, not on its validity
Section 7 exempts "an envelope that is itself a `retired` attestation of X (content type attestation, payload with claim `retired` and `subject` and `issuer` both X)" from the retirement rule. It does not say whether such an envelope must pass the schema (a `data.reason` that is not text, say). The two readings differ for a malformed retirement of X issued after R: exempt at step 8 and then a schema failure at step 9 or at admission, or `signer_revoked` at step 8.
Proposed fix: say that the exemption looks only at the content type, the claim and the two Agent IDs, so that the error is the schema error a consumer reports for any malformed attestation.
Implementation: that reading (`verify::is_retirement_payload`). No vector covers it.
Resolution: Resolved in Draft 05, section 7 (`retired`: effect at step 8; decision 51): the exemption looks at the content type, the claim and the two Agent IDs only. Case RT33 has no vector yet.

## 49. The chain depth is not checked for the `successor` attestation when the claim issuer is a root
Section 7 counts the `successor` attestation as one attestation of the chain and calls `authorize(issuer, C, roots, empty path, 2)`, and the pseudocode accepts a root before the depth test. With `max_depth` 1 and a claim issued by a root, the chain through succession has two attestations (the claim attestation and `SUC`) and passes, although the rule "maximum attestations in a chain, claim attestation included" would reject it.
Proposed fix: either add a depth test for the successor attestation (`2 > max_depth` fails the pair) or state that `max_depth` limits delegations only.
Implementation: the pseudocode, as written (no test for a root issuer). SU19 and SU20 are unaffected: they have a non-root issuer.
Resolution: Resolved in Draft 05, section 7 (Path, depth and warnings under succession; decision 52): `max_depth` limits delegations, and the successor attestation is not depth-tested when the claim issuer is a root. Case SU27 has no vector yet.

Entries 50 to 56 were found while implementing the anchor and discovery vectors from Draft 05 and are resolved in Draft 06.

## 50. Checking a published anchor: the result names and the order of the checks are not defined
Section 9 says a verifier "takes an anchor record as published only when its envelope verifies, its signer is the log it asked about and its `checkpoint-hash` equals the hash of the checkpoint it is looking at", and section 5 says a component that reads the payload "MUST reject it if it does not parse". Neither section gives the rejection a name or a step, the error table of section 10 has no anchor code, and the order in which the content type, the schema, the signer and the hash are checked is not stated. A failure of steps 1 to 8 may be reported as it is or wrapped, as a checkpoint is (`inclusion_proof_invalid` with a `cause`).
Proposed fix: add four step 9 codes to the error table, `anchor_content_type_invalid`, `anchor_schema_invalid`, `anchor_log_mismatch` and `anchor_checkpoint_mismatch`, and say that the checks run in the order: steps 1 to 8 (a failure is reported as it is, with its own step and code), content type, schema, signer, hash.
Implementation: `atep_core::anchor::check_published_anchor` with exactly those names and that order. The `anchor-envelope` vectors fix them. No verifier is obliged to evaluate anchors (decision 61), so these names matter to a log, a monitor or a client that shows anchors, and they are provisional until section 10 lists them.
Resolution: Resolved in Draft 06, section 9 ("Checking a published anchor") and section 10 (error table; decision 63). The four codes are step 9 codes in the error table, and the order is steps 1 to 8 as they are (not wrapped), content type, schema, signer, hash. The `anchor-envelope` vectors (13) pin it.

## 51. A trust document label inside tag 96, and `expires-at` on an anchor record
Section 5 decides unencrypted use by the content type alone and lets a bare tag 98 envelope carry only the four trust document types, but it does not say what happens to an envelope of such a type that is wrapped in tag 96, and "no `expires-at`" in section 9 (anchor records and checkpoints) is a statement about what the log signs, not a rule a verifier applies. The verification algorithm accepts an encrypted envelope with an anchor content type (step 1 applies the label rule to bare envelopes only) and an anchor with an `expires-at` that is still in the future. Candidate validation rejects an encrypted attestation, so attestations are already unencrypted by construction; for anchors nothing says so.
Proposed fix: say that a component that takes an anchor record (or a checkpoint or an SRL) as published requires the envelope to be unencrypted, and either that an `expires-at` on an anchor record is ignored or that it makes the record invalid.
Implementation: `check_published_anchor` verifies the envelope with no recipient identity, so an encrypted anchor fails at step 2 (`no_recipient_key`); an `expires-at` is checked at step 5 as for any envelope and is otherwise ignored. No vector covers an encrypted anchor or an anchor with `expires-at`, because the text decides neither; the `anchor-media-type` vectors cover only what the text states (a bare anchor envelope is accepted at step 1, a look-alike media type is not).
Resolution: Resolved in Draft 06, section 5 (the label rule covers bare envelopes only) and section 9 (decision 64). An anchor is never encrypted: with no recipient identity a tag 96 anchor fails at step 2 (`no_recipient_key`, as Rust and npm do; Python reports `1/unexpected_encryption`, a code follow-up), and `expires-at` on an anchor is compared at step 5 like for any envelope and is otherwise ignored. No vector yet (known gap 25).

## 52. Limits of a TXT record: a record that breaks them is ignored or invalid?
Section 4 limits a TXT record to 1,024 octets of US-ASCII and says a reader MAY stop after the first 16 records. It does not say what a `v=atep1` record that is longer than that, or not ASCII, makes of the source: the record is ignored (the source may then not exist or may list nobody) or the source is invalid (it exists and breaks a rule). The state matters to the label of the source and to nothing else in the outcome, because an invalid source and an absent one both fail to list the Agent ID and neither contradicts a listing; a record that is read and does not list the Agent ID does contradict one.
Proposed fix: say that a record over the limit or with a non ASCII octet is ignored, like a record that does not begin with `v=atep1`.
Implementation: the record is ignored (`atep_core::domain`). The vectors `txt-record-of-1025-octets-is-ignored` and `txt-non-ascii-record-is-ignored` pin that reading; the first 16 records are read (`txt-sixteenth-record-is-read`), and no vector has the listing in a 17th record, which the text leaves to the reader.
Resolution: Resolved in Draft 06, section 4 (decision 65). A record over 1,024 octets or with a non ASCII octet is ignored, like one that does not begin with `v=atep1`; a reader MUST read at least the first 16 records and MAY ignore the rest. The listing in a 17th record stays unspecified because Rust ignores it and Python reads it (known gap 20).

## 53. Limits of the well-known document: more than 1,024 agents, and a `version` other than 1
Section 4 says `agents` has "at most 1,024 entries" and that a document of another `version` "is not read". It does not say whether a document with 1,025 entries is invalid, or read up to the limit, and whether a document that is not read is *invalid* or *absent* (the two differ in the label of the source only, see issue 52).
Proposed fix: say that entries past the 1,024th are not read and the document stays valid, and that a document of another version is invalid.
Implementation: the first 1,024 entries are read and a warning is recorded; a `version` other than the integer 1 is invalid (`wk-version-2-is-not-read`). The 1,025 entry case has no vector (the readings give different answers for an Agent ID in the 1,025th place). A document of exactly 1,024 entries with the Agent ID last and one of exactly 65,536 bytes are accepted and a body of 65,537 bytes is invalid (`wk-1024-entries-agent-last`, `wk-document-65536-bytes`, `wk-document-65537-bytes`).
Resolution: Resolved in Draft 06, section 4 (decision 66). The first 1,024 entries are read and the rest ignored with the document still valid; a `version` other than the integer 1 is invalid ("is not read" meant that). The 1,025th place has no vector (known gap 20).

## 54. Checking a domain binding: the refusal of a name, the option to require both sources, and the public suffix list
Section 7 step 1 refuses a name that is not canonical, but step 2 defines the state of a source only after reading, so a refused name has no source state. The text also lets an issuer "require both sources to list the Agent ID" (section 4) without saying what the result is when one source is unavailable, and step 1 says an issuer SHOULD refuse public suffixes, which needs a list the reference does not carry.
Proposed fix: say that a refused name is *not bound* and nothing is read; that with both sources required the result is *bound* when both list the Agent ID, *not bound* when any source is absent, invalid or does not list it, and *indeterminate* otherwise; and that the public suffix check is outside the language neutral cases.
Implementation: the vectors record a refused name as `not-read` for both sources with no name queried (`domain-uppercase-is-not-read` and three more) and the `require_both` cases as above (`require-both-*`). The public suffix check is not implemented and has no vector.
Resolution: Resolved in Draft 06, section 7 ("Checking a domain binding"; decisions 70, 71, 73). A refused name is *not read*, nothing is queried and the result is *not bound*; with both sources required the result is *bound* when both list, *not bound* when either is absent, invalid or not listing, *indeterminate* otherwise; the public suffix check stays a SHOULD outside the language neutral cases (no vector). The state of an answer refused for lack of DNSSEC stays open (decision 72).

## 55. `registry-endpoint`: the extension kind rule, "characters" and the scheme
Section 7 says `kind` may be "an extension name `x-` followed by lowercase letters, digits and `-`", which allows a hyphen at either end (`x--`, `x-a-`), whereas the `chain-id` extension rule of section 9 does not. It limits `url` to "2,048 characters", which could be characters or octets for a non ASCII URL, and says "an `https` URL" without saying whether `HTTPS://` is one (the scheme of a URL is case insensitive in RFC 3986).
Proposed fix: say that the two extension rules are meant to differ or make them one; say octets; say that the scheme is the lowercase text `https`.
Implementation: `atep_core::admission::check_registry_endpoint` accepts a hyphen anywhere after `x-` (as the CDDL `x-[a-z0-9-]+` does), counts characters, and compares the scheme exactly in lowercase. The vectors avoid the three edge cases (they contain no `x--`, no non ASCII URL and no uppercase scheme).
Resolution: Resolved in Draft 06, section 7 ("Registry endpoints"; decisions 74, 75). The extension `kind` allows a hyphen anywhere after `x-` (looser than `chain-id`, on purpose as written), the URL length is counted in characters and the scheme is lowercase `https` exactly. The URL grammar is the checked list and nothing more; non ASCII white space and an unclosed bracketed host stay open because Rust and Python differ (known gap 21).

## 56. A configuration error has no vector form, and a policy value can be a number CBOR cannot carry
Known gap 23 says the vector format has no place for a policy that does not parse (decision 54: `{ok: false, step: 9, error: policy_invalid}` for an API that has only results, the error channel for one that has two). The `require-anchor` vectors need one, and some invalid values (a non integer number such as 1.5, an integer above 64 bits) cannot be written in the deterministic CBOR the other vectors use.
Proposed fix: say that a policy parse vector has `inputs.policy` (the JSON) and `expected` either `{ok: true, ...}` or `{ok: false, error: "policy_invalid"}` with no step, and that a non integer or out of range number is the same error.
Implementation: category `require-anchor`: the `.cbor` file is the deterministic CBOR encoding of `inputs.policy`, the result is `{ok: true, require_anchor: [{log, chain, max_age_days | max_age_hours}]}` or `{ok: false, error: "policy_invalid"}` (no step). Only the `require_anchor` member is covered; the other members of the policy parser still have no vector (gap 23 stays open for them), and the non integer and out of range numbers are not in a vector because they cannot be encoded.
Resolution: Resolved in Draft 06, section 7 ("Where `policy_invalid` is raised") and section 12 (decision 77). A policy parse vector expects `{ok: false, error: "policy_invalid"}` with no step, and a number that is not an integer or is out of range is the same error. The other members of the policy parser still have no vector (known gap 23).

## 57. A policy rule with alternatives reports the wrong reason when a stale revocation list is the cause
Found while building the second certified member of the ATEP-R demo (Draft 07 sections 7, 8 and 10 step 9). A `motion` rule is satisfied either by `fleet-controller` or by `fleet-member` with a `peer-motion` naming the receiver. When the issuer's revocation list is stale and the verifier fails closed, every alternative fails. Section 10 says that the rejection reports the alternative that got furthest and that, on a tie, the first alternative is reported. The first alternative is `fleet-controller`, which the sender does not hold, so the rejection is `claim_missing` although the real cause is the stale list (`srl_stale`), which a single-alternative rule reports correctly. An operator reading the log is told the sender lacks a claim it was never meant to hold.
Proposed fix: say that when two or more alternatives fail and at least one failed because of a stale or missing revocation list under a fail-closed policy, the rejection reports `srl_stale` (or `srl_missing`) and names that list, because that cause applies to every alternative that otherwise matched; keep the furthest-alternative rule for all other failures. A vector would pin it: a `motion` command from a member holding a valid `peer-motion`, verified with a stale list under the fail-closed mode.
Implementation: not changed. The demo re-runs the verifier on the same envelope against a fresh list (it verifies) and says so in the log row; its self-test pins the current result (`claim_missing`).
Resolution: Open. For Draft 08 and a vector.
