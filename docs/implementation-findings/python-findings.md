# Implementation findings: the independent Python implementation

`python/atep_py` was written from the specification text, the CDDL and the test vectors only, without reading the Rust code, as an interoperability test: if two implementations that share nothing but the documents agree byte for byte, the documents are sufficient. This file lists every place where the spec text and the vectors did not determine the behavior, so a rule had to be guessed (and happens to match the vectors) or is undetermined by any vector. Each entry has a proposed fix and a resolution.

How to read the numbers:

* "Draft N" in this file refers to an internal working draft. Drafts 00 to 06 were not published. [Draft 07](../../spec/ATEP-Specification-Draft-07.md) is the first public draft and carries every resolution recorded here (its Appendix A explains the numbering).
* The entries are kept as they were written; only references to files that are not part of the public repository were removed.
* A companion file, [rust-findings.md](rust-findings.md), lists the findings from the Rust reference implementation.

## Entries

Status: all 20 entries are resolved in Draft 03 (Draft 03, ). Each entry ends with a Resolution line pointing at the Draft 03 section. Where Draft 03 chose a rule different from the one implemented here (entries 6, 12 and 13) the Resolution says so; none of these changes affects a vector.

Method: implemented from `Draft 02`, `spec/schemas/*` and `vectors/` (README, manifest, all vector files
except `crosscheck.py`) only. Result: all 140 vectors pass (byte-identical envelopes for identity,
signing, attestation and encryption; identical accept/reject, step and error code for all verification,
chain, ATEP-R, SRL and log vectors). Every item below is a place where spec plus vectors/README.md did not
determine the behaviour, so a value or rule had to be guessed (and happens to match the vectors) or is
undetermined by any vector. No generation vector (anything with exact `.cbor` bytes) needed a guess.

## A. Needed a guess to reproduce a vector

1. **Trust policy file format (vectors/README.md, "Trust policy evaluation")**: says `inputs.policy.trust` is
   "the same format as the policy file of the CLI, see `rust/README.md`", a file the implementer did not have.
   Had to infer the keys (`roots`, `rules[{claim, root?, max_age_days?}]`, `max_depth`, `require_inclusion`,
   `trusted_logs`, `srl{on_stale,on_missing}`, `atep_r`) from the vector inputs and the key list in the
   README. Short claim names ("`claim` may be a short name") have no stated expansion rule; I used the prefix
   `https://atep.dev/claims/` (so a robotics short name would have to be written `robotics/fleet-member`).
   Fix: put the policy schema (with CDDL) in the spec or in vectors/README.md, including the short name rule.
   Resolution: Resolved in Draft 03, section 7 (Trust policy: file format, defaults and unknown-member rule; Short claim names) and `spec/schemas/atep.cddl` (`trust-policy`). The expansion rule matches your reading, with robotics short names also accepted without the `robotics/` prefix.
2. **Warning strings (vectors/README.md, "Trust policy evaluation" and "SRL vectors")**: `warnings` are compared
   verbatim but no text is specified. The exact two templates
   `no SRL cached for issuer <atep id>; revocation status unknown` and
   `SRL of <atep id> is past next-update <n>; using the stale copy` could only be copied from vector
   expectations. Neither the dedup rule (one warning per distinct message) nor the order (order of first
   encounter while walking claim attestation then its authority chain, rules before ATEP-R class claims) is stated.
   Fix: specify the strings, or declare `warnings` non-normative and exclude it from comparison.
   Resolution: Resolved in Draft 03, section 8 (Warnings): the two strings are normative, a result lists each distinct warning once in order of first encounter, and the list is omitted when empty.
3. **Authority chain rule (README step 9.6)**: "whose issuer is in turn authorized for both `issuer-authority`
   and the claim" does not say how this recurses. I implemented: the delegator's own `issuer-authority`
   attestation must list the claim and (from the second hop upward) also `issuer-authority`; i.e. needed
   set = {claim} for the first hop and {issuer-authority, claim} for every later hop. The three-level
   chain vector passes with this, but other readings (for example requiring `issuer-authority` in the first hop's
   list) are not excluded by the text. Fix: state the recursion as pseudocode.
   Resolution: Resolved in Draft 03, section 7 (Chains): the recursion is given as pseudocode and matches your reading (first hop needs the claim, later hops need `issuer-authority` and the claim).
4. **Chain error mapping (README step 9 error table)**: the table lists `chain_broken`, `issuer_not_authorized`,
   `chain_cycle`, `chain_depth_exceeded` without conditions. Inferred: no `issuer-authority` attestation
   for a non-root issuer, or terminal root not allowed by the rule's `root`, is `chain_broken`; one exists but
   its `data.claims` lacks a needed claim is `issuer_not_authorized`; an issuer repeated in the chain is
   `chain_cycle`; more than `max_depth` attestations is `chain_depth_exceeded` (checked when the attestation is
   added). Also undefined: which error wins when several candidate attestations fail (I report the error of the
   first candidate, as README rule 7 says for the top level, and apply the same rule at each hop).
   Resolution: Resolved in Draft 03, section 7 (Chains rule 5) and section 10 (error table, Step 9 in detail): conditions for `chain_broken`, `issuer_not_authorized`, `chain_cycle` and `chain_depth_exceeded`, and the first-candidate error rule at every hop.
5. **Step 9 order of checks per candidate (README 9.2 to 9.5 versus spec section 10 step 9)**: spec lists
   schema, lifetime, SRL, chain, inclusion; README lists envelope, schema, issuer match, lifetime, SRL,
   inclusion, max age, authorization. Followed the README. `attestation_issuer_mismatch` versus
   `attestation_schema_invalid` precedence is only fixed by the README wording.
   Resolution: Resolved in Draft 03, section 10 (Candidate validation): the exact order of the checks per candidate, which is the README order.
6. **Candidate selection reads unverified payloads (README 9.1)**: candidates are chosen by `subject` and
   `claim` from the payload before the envelope is verified, so a payload that does not decode is silently
   not a candidate (leading to `claim_missing` rather than a schema error). Not stated; the vectors
   `attestation-schema-invalid` and `audited-without-evidence` only work because subject and claim still parse.
   Also unspecified: whether inline attestations nested inside inline attestations (`-70009` in an
   attestation) enter the pool (I pool them recursively, deduplicated, in breadth first order).
   Resolution: Resolved in Draft 03, section 7 (Candidate selection, The attestation pool): selection reads unvalidated payloads, a payload that does not decode is not a candidate, nested attestations are pooled depth first (your breadth first order is a code follow-up that only changes which candidate is tried first, section 20 decision 8).
7. **Inclusion proof failure of a checkpoint envelope (README "Log vectors")**: a checkpoint whose own
   signature fails is `inclusion_proof_invalid` with `cause {step, error}`, per the vector
   `checkpoint-bad-signature`; the README only lists the four error names without saying that an
   envelope failure maps to `inclusion_proof_invalid`. For `consistency` and `split-view` checks with a bad
   checkpoint signature the error is undefined by any vector (I use the same mapping).
   Resolution: Resolved in Draft 03, section 9 (Checkpoints: checking a checkpoint): an envelope failure of a checkpoint is `inclusion_proof_invalid` with `cause`, for inclusion, consistency and split view checks alike. No vector for the consistency and split view cases yet (section 12, gap 11).
8. **ATEP-R SRL handling (spec section 17 and README ATEP-R table)**: spec section 17 says "Revocation lists past
   `next-update` cause motion and actuation to fail closed; telemetry MAY continue", README adds a per class
   table. Not stated: that the class mode overrides the policy's `srl.on_stale`/`on_missing` for every chain
   issuer (I override both), nor whether the fail-closed mode for a class also covers a missing list (README says
   "stale or missing"). Also the order of claim results (user `rules` first, then the satisfied class
   alternative in its listed order) is unspecified.
   Resolution: Resolved in Draft 03, section 17 (Fail-closed and fail-open classes, Result order): the class mode replaces the configured mode for stale and missing lists of every issuer in the class requirement, and the rules of the policy keep the configured mode.
9. **ATEP-R step 1 ordering (README ATEP-R)**: `atep_r_unencrypted`, `missing_command_class`,
   `unknown_command_class` are listed without position in the step 1 sub-order. I apply them after all core
   step 1 checks, on the inner envelope for tag 96 (so a bare envelope with a data content type reports
   `unencrypted_non_trust_document` first). The vectors only contain one failure each.
   Resolution: Resolved in Draft 03, section 10 step 1 and section 17 (Enforcement): the ATEP-R checks come after every core step 1 check, on the inner envelope, in the order unencrypted, missing class, unknown class.
10. **Alternatives and "most rules satisfied" (README 9.7)**: "the error of the alternative that satisfied the
    most rules" leaves ties undefined (I take the first alternative) and does not say whether a requirement
    that fails on a `data` check (`claim_data_mismatch`) counts as satisfied. I count only fully satisfied
    requirements before the first failure.
   Resolution: Resolved in Draft 03, section 10 (Step 9 in detail): the alternative that satisfied the most rules, ties to the first, a failed rule (data mismatch included) never counted.
11. **E-stop recognition and expiry relaxation**: spec section 17 says an e-stop "MUST be accepted ... even if
    the sender's other claims have expired" without defining an e-stop; vectors/README.md defines it
    (payload map with `command: "e-stop"`). The spec text should reference that definition. Which checks the
    relaxation skips (only attestation `expires-at` at step 5) is README-only.

   Resolution: Resolved in Draft 03, section 17 (E-stop recognition): the definition is in the spec and the relaxation skips only the clock comparison of attestation `expires-at`.
## B. Underspecified, no vector decides (my choices recorded so they can be pinned down)

12. **Error codes outside the listed tables**: the spec says only the step is normative. Codes I chose for
    undefined situations: `missing_field`, `invalid_field`, `malformed_envelope`, `signature_shape_invalid`,
    `unsupported_content_algorithm`, `recipient_count_invalid`, `unsupported_recipient_algorithm`,
    `kem_failure`, `bundle_invalid`, `detached_payload_missing`, `not_signed_envelope`,
    `unexpected_encryption`, `policy_invalid`. Also: a missing `atep-version` or `suite` is reported as
    `missing_field` at step 1 (spec says "= 1"/"supported" but not what absence means), a kid mismatch inside a
    signature entry is `signer_id_mismatch` at step 3, and a signature pair of two EdDSA entries is
    `signature_count_invalid`.
   Resolution: Resolved in Draft 03, section 10 (Error codes: complete table) and section 20 decisions 1 to 3. Canonical names are the Rust names, with the mapping from your names; an absent `atep-version` or `suite` is `missing_header`, a `kid` mismatch is `kid_mismatch`, two EdDSA entries are `algorithm_suite_mismatch`.
13. **Step 1 for the outer COSE_Encrypt**: the spec checks version, suite, content algorithm and recipient
    count/algorithm but does not say where malformed `eph_key` or `kem_ct` (wrong sizes) is rejected, nor whether
    structural errors inside the recipient are step 1 or step 2. I treat them as step 2 `kem_failure`
    (spec: "Any KEM or AEAD failure is fatal").
   Resolution: Resolved in Draft 03, section 10 step 1 (tag 96) and section 20 decision 4. Differs from your choice: structural errors in the recipient, including wrong sizes of `eph_key` and `kem_ct`, are step 1 (`malformed_structure`). Code follow-up for the Python implementation; no vector.
14. **Ed25519 strict verification (section 5)**: "rejecting non-canonical S and small-order components" does not
    say whether non-canonical encodings of A and R (y >= p) must be rejected, nor whether the check is on A, R
    or both. I reject S >= L, small-order A and R, and any non-decodable A or R, and compare the re-encoded
    point to the R bytes. No vector exercises these.
   Resolution: Resolved in Draft 03, section 5 (Sig_structure and signing modes) and section 20 decision 6: exactly your reading (S canonical, A and R decodable and not small order, recomputed R equals the R bytes). No vector yet (section 12, gap 4).
15. **Step 8 and SRL reasons**: spec text says the signer must not appear as `retired` or `compromised`; the
    README says any 32 byte SRL entry is an identity revocation. I apply every 32 byte entry whatever its reason
    string; the `retired` self-attestation path of spec section 4 and section 8 is not specified algorithmically
    for step 8 and is not implemented (no vector).
   Resolution: Resolved in Draft 03, section 8 (SRL payload), section 10 step 8 and section 7 (Retirement and succession): every 32 byte entry counts whatever its reason; `retired` self-attestations are consulted at step 8 from the verifier's local store (text only, no vector, section 12 gap 1).
16. **Policy `srls` that fail to load** (bad signature, rollback, ...) and SRL staleness when loading them for
    step 8: undefined. I fail the whole verification with the SRL error at step 9 for load failures, and load
    policy SRLs without a staleness check, judging staleness per lookup (so a stale list still contributes its
    identity entries to step 8, which the spec's "any cached SRL" suggests).
   Resolution: Resolved in Draft 03, section 8 (Loading an SRL, Freshness) and section 20 decisions 13 and 14: staleness is judged per lookup and a stale list still feeds step 8; failing the verification with the load error at step 9 is the recommended behavior (your choice).
17. **Trust document payload checks on unencrypted envelopes without policy**: spec section 5 says the core
    verifier checks only the label; the README says a consumer MUST validate the payload. `verify()` with no
    trust policy therefore returns ok for a bare SRL/checkpoint/attestation envelope whose payload is garbage.
    Consistent with the spec, but worth an explicit sentence.
   Resolution: Resolved in Draft 03, section 5 (Encryption rule) and section 10 (closing paragraph): the core verifier checks the label only, so a bare trust document with a garbage payload verifies when there is no trust policy.
18. **Retired and successor claims** (spec sections 4, 7): the lifecycle describes rejecting envelopes of a
    retired identity and following one hop of succession, but no data layout (`data` fields) or step is given
    and no vector covers them.
   Resolution: Resolved in Draft 03, section 7 (Data layouts, Retirement and succession): `retired` and `successor` layouts, step 8 treatment and one-hop succession are specified as text and flagged as no vector yet (section 12, gaps 1 and 2).
19. **ML-KEM encapsulation and key generation inputs**: spec section 6 describes `Encaps` (random) and only the
    README fixes `Encaps_internal(ek, m)` and the seed layouts (`d || z`, ML-DSA `xi`). The spec itself gives
    no way to reproduce encryption vectors; the README is the only source. Not ambiguous, but the vector README
    should be referenced normatively from section 12.
   Resolution: Resolved in Draft 03, section 12 (Deterministic generation inputs): seed layouts, `KeyGen_internal`, `Encaps_internal(ek, m)` and the signing mode are stated in the spec.
20. **Merkle leaf for the log (spec section 9)**: spec says the leaf is "the SHA-256 of a submitted envelope"
    while the vectors use RFC 9162 `SHA-256(0x00 || submitted form)`, where the submitted form is the envelope
    without its `-70012` entry (README only). The spec text contradicts the vectors if read literally (it
    implies leaf = SHA-256(envelope) with no 0x00 prefix and no removal of the proof).
   Resolution: Resolved in Draft 03, section 9 (Log structure, Submitted form): the leaf is `SHA-256(0x00 || submitted form)`, the submitted form being the envelope without its `-70012` entry; the Draft 02 text was wrong.
Entries 21 to 31 were found in Draft 04 and are resolved in Draft 05.

21. **Valid retirement, bundle source (Draft 04 section 7, "Retirement and succession")**: the text lists how R is
    validated but the bundle of X is only defined by the notes file ("inline bundle of R, a cached bundle, or the
    bundle resolved for the envelope under verification"); Draft 04 itself says only "steps 1 to 7". I use: inline
    in R, else `known_bundles`, else the bundle resolved for the envelope being verified. Proposed fix: state this
    in section 7 or in step 8.
   Resolution: Resolved in Draft 05, section 7 (valid retirement, item 1; decision 53): inline in R, else `known_bundles`, else the bundle resolved for the envelope; the order is immaterial.
22. **Retirement scan, which entries are looked at (section 7, step 8)**: whether an entry of the store that is not
    a tag 98 envelope, is encrypted, or is signed by someone else is "ignored" or an error is not stated for step 8
    (only "an R that fails any of these is ignored"). I ignore every entry that fails any check, silently, and
    do not apply step 8, replay or the `expires-at` comparison to it, but I do apply the `issued-at` skew check.
    Proposed fix: add a sentence that malformed store entries are ignored.
   Resolution: Resolved in Draft 05, section 7 (entries of the store that are not retirements; decision 53): they are ignored, never an error, and the `issued-at` skew check still applies.
23. **Retirement exemption (section 7, step 8)**: "an envelope that is itself a `retired` attestation of X" does not
    say how much of the payload must be valid. I look only at content type, `claim`, and `subject` and `issuer`
    both equal to the signer, not at the rest of the schema. Proposed fix: state that the test is on those fields only.
   Resolution: Resolved in Draft 05, section 7 (`retired`: effect at step 8; decision 51): the test is on the content type, the claim and the two Agent IDs only.
24. **Several retirements (section 7)**: not said what happens when the store holds several valid retirements of X.
    I use the smallest `issued-at` (the earliest instant wins, consistent with the union rule). Proposed fix: say so.
   Resolution: Resolved in Draft 05, section 7 (decision 53): the smallest `issued-at` decides. Case RT34 has no vector yet.
25. **Unknown policy members and `follow_succession` type (section 7, trust policy)**: the text says an unknown member
    is an error and `follow_succession` is a boolean, but not which code a configuration error has at the API.
    I return step 9 `policy_invalid` for an unknown member and for a non-boolean `follow_succession`. Draft 03 python
    ignored unknown members; I now reject them, which also makes `require_anchor` an unknown member (rejected as
    `policy_invalid`, not evaluated and not `anchor_not_supported`). Proposed fix: define a distinct configuration
    error that is not a verification result and name it.
   Resolution: Resolved in Draft 05, section 7 (Trust policy) and section 10 (error table; decision 54): the configuration error is named `policy_invalid`, reported as a step 9 result by an API that has only results and on an error channel otherwise. `require_anchor` is a known member and fails closed with `anchor_not_supported`; rejecting it as unknown is a known gap of the Python implementation.
26. **Warnings order under succession (section 8 "Warnings", section 7)**: "claim attestation first, then its
    authority chain" does not say where the successor attestation's warning goes, nor whether warnings from a
    failed (successor, claim) pair are kept when a later pair succeeds. I record warnings in the order met: successor
    attestation validation first, then the claim attestation, then the authority chain, and keep those met in failed
    attempts of the same rule. No vector distinguishes this (SU17 has one warning). Proposed fix: state the order.
   Resolution: Resolved in Draft 05, section 7 and section 8 (Warnings; decision 55): order of first meeting, successor attestation first under succession, warnings of failed attempts kept. Your choice, as implemented.
27. **Depth and cycle accounting for the successor attestation (section 7)**: "`authorize(issuer, C, roots, empty
    path, 2)`" says depth 2 and an empty path, so the successor's issuer O is not on the path. I pass the claim
    issuer as the only path member and depth 2 (the two links, claim and successor attestation). Whether O or S
    should count as a path member for `chain_cycle` is not stated. Proposed fix: say which Agent IDs seed the path.
   Resolution: Resolved in Draft 05, section 7 (Path, depth and warnings under succession; decision 56): the path handed to `authorize` is empty, neither O nor S is seeded, depth 2; the walk pushes the claim attestation's issuer first, which is what you implemented.
28. **SRL reload of the same bytes (section 8)**: "the same bytes again are accepted and change nothing" conflicts
    in order with "steps 1 to 8 first" (RT25 would fail step 8 on the second load because the list names its own
    issuer from before its `issued-at`... only if `revoked-at` is at or before `issued-at`). I check cached bytes
    before any verification, as the SHOULD in section 7 suggests. Proposed fix: make the order normative.
   Resolution: Resolved in Draft 05, section 8 (Loading an SRL; decision 50): the check of cached bytes comes first, a MUST. Case RT32 has no vector yet.
29. **Candidate validation and SRL attestation entries for `retired`**: step 9 candidate validation of a `retired`
    attestation (RT6) applies the SRL lookup like any other, but step 8 ignores SRL entries naming R's id. I only
    implement the second as a store rule and the first as in the generic lookup. No vector separates them. Proposed
    fix: state that the lookup of candidate validation is unchanged.
   Resolution: Resolved in Draft 05, section 7 (`retired`: valid retirement and the scan; decision 57): the lookup of candidate validation is unchanged for a `retired` attestation.
30. **srl-context vectors (vectors/README.md)**: `revocations` and `attestations` are in `inputs`, not in
    `inputs.policy`, which the README states; `srl_policy.on_stale` applies to the final load only, and
    `cached_srl_hex` is loaded fail-open. I guessed the latter from the `srl` vectors. Proposed fix: say so.
   Resolution: Resolved in Draft 05, section 12 (Formats of the categories added in Draft 04 and 05; decision 48): `attestations` and `revocations` are at the top level of `inputs`, `cached_srl_hex` is loaded first without a staleness test, `srl_policy.on_stale` applies to the last load only.
31. **Skips**: `log-admission` and `monitor` vectors are not run by Python (no log, no monitor); the README split
    in `RETIRED-SUCCESSOR-NOTES.md` section 1 says a verifier need not. Python reports them as a named, counted skip.
   Resolution: Resolved in Draft 05, section 12 (decision 58): a verifier need not run `log-admission` and `monitor`, and reports them as skipped; 195 of the 200 vectors apply to it.

## C. Draft 05 anchoring and discovery (236 vectors, implemented from Draft 05, the notes and the vector README)

Entries 32 to 44 were found in the anchoring and discovery vectors of Draft 05 and are resolved in Draft 06.

All 236 new vectors pass. The vector files and `ANCHOR-DISCOVERY-NOTES.md` decided almost everything; the entries below
are places where Draft 05 plus the notes plus the README did not determine a behavior, so a choice was made (no vector
contradicts it). Resolution lines were added in Draft 06.

32. **Domain records, JSON parsing (section 4, well-known document)**: "a JSON object (RFC 8259)" does not say what to do
    with a duplicate member name, with the non-RFC constants `NaN` and `Infinity` (accepted by some parsers), or whether
    `1.0` and `1e0` count as the integer `1` for `version`. I treat `NaN` and `Infinity` as invalid JSON, let the last
    duplicate win (the Python `json` default), and require a JSON integer token for `version` (so `1.0` is `invalid`).
    Proposed fix: say that duplicate names make the document invalid and that `version` must be the token `1`.
   Resolution: Resolved in Draft 06, section 4 (How the checker applies these rules; decision 67): UTF-8 only, `NaN` and `Infinity` are not JSON, `version` must be the token `1`, and a member name that occurs twice takes its last value (as in Python and Rust; making it invalid is left to a later draft with a vector).
33. **Domain records, content type and redirect test (section 4; notes section 8)**: the media type `application/json`
    is compared after lowercasing and trimming the part before `;` (media types are case insensitive in RFC 9110, the
    text is silent). The redirect rule in the spec ("stay on https and on the host, default port") is turned by the notes
    into the prefix test `final_url` starts with `https://<domain>/`; a `final_url` with an uppercase host, a userinfo
    part, or `https://<domain>` with no path is therefore `invalid`. The limit of three redirects cannot be seen in the
    fixture and is not checked. Proposed fix: state the prefix test (or a URL parse) in section 4.
   Resolution: Resolved in Draft 06, section 4 (decision 68): the media type is the text before the first `;`, trimmed, compared case insensitively; `final_url` must begin with `https://<domain>/`, byte for byte. The three redirects are the fetcher's duty.
34. **Domain records, size and TXT counts (section 4; notes section 8)**: the size limit is applied to the UTF-8 bytes of
    the `body` text (and `body_filler` is expanded to exactly `total_bytes`), the limit of 1,024 octets of a TXT record is
    applied to the concatenated character-strings in characters after the US-ASCII test. The spec says a reader "MAY stop
    after the first 16 records" and the notes "at least the first 16"; I read every record given, so a seventeenth listing
    counts. The 1,025th agent entry is ignored (read the first 1,024); no vector has it. Proposed fix: make the record and
    entry limits exact (read at most N, ignore the rest) so two implementations agree on a long answer.
   Resolution: Resolved in Draft 06, section 4 (decisions 65, 66): the limits are exact (1,024 octets of concatenated text then the ASCII test, 65,536 octets of body, the first 1,024 entries). A reader MUST read at least 16 TXT records and MAY ignore the rest; the 17th record stays unspecified (Rust ignores it, Python reads it; known gap 20).
35. **Domain records, `require_dnssec` (section 7, security notes)**: "An issuer MAY refuse unvalidated TXT answers and
    then relies on the well-known document alone" does not say which state a refused answer has. When `options.require_dnssec`
    is true and `dnssec_validated` is false I report `unavailable` (fail closed, like a validation failure) rather than
    `absent` (which would let the well-known document alone bind). No vector sets the option. Proposed fix: name the state.
   Resolution: Open in Draft 06 with the behavior stated (section 7, security notes; decision 72): Rust labels a refused answer *invalid* (when a record counts), Python *unavailable*; both let the well-known document alone bind and neither issues otherwise. No vector sets `require_dnssec` (known gap 20).
36. **Domain records, Agent ID comparison (section 4, section 7)**: an entry or `id=` term "equals" the Agent ID asked
    about. I compare the decoded 32 bytes after the strict `atep:` or `did:atep:` parse, so a `did:atep:` entry matches an
    `atep:` question (the vectors `lists-the-agent-in-did-form` agree), and an uppercase or non canonical text is not an
    Agent ID and is ignored. If the Agent ID asked about is itself not an Agent ID nothing is listed. Not said.
   Resolution: Resolved in Draft 06, section 4 (Agent ID comparison; decision 69): by decoded bytes after the strict parse; a `did:atep:` entry lists an `atep:` question; a non canonical text is not an Agent ID and is ignored; an Agent ID asked about that does not parse is listed by nothing.
37. **`registry-endpoint` URL grammar (section 7; notes section 7)**: "an `https` URL with a host, no credentials and no
    whitespace" leaves open how the host is found and which characters count. I take the authority as the text between
    `https://` and the first of `/`, `?`, `#`; an `@` anywhere in it is credentials; the host is the authority up to the
    first `:` (or the bracketed IPv6 literal) and must be non empty. The port is not range checked, the host is not checked
    for valid characters, and `https://?x` has no host. "Whitespace or control character" is read as any Unicode
    character that is whitespace or of general category `Cc`, `Cf`, `Zs`, `Zl` or `Zp`. The scheme is matched in lowercase
    only and the 2,048 limit counts characters, as note 55 says. Proposed fix: give an RFC 3986 based grammar, or say that
    the check is the listed ones and nothing more.
   Resolution: Resolved in part in Draft 06, section 7 (Registry endpoints; decision 74): the grammar is the checked list (lowercase `https://`, 2,048 characters, no ASCII white space or control character, a non empty authority with no `@` and not beginning with `:`) and nothing more, and the length counts characters. Your reading of white space as every Unicode `Cc`, `Cf`, `Zs`, `Zl` and `Zp` character and of an unclosed bracketed host differs from Rust, so those two edges stay open (known gap 21).
38. **Admission order for a non attestation content type (section 9 "Admission")**: the table lists the content type rule
    before "passes steps 1 to 8", but a bare data envelope fails step 1 (`unencrypted_non_trust_document`) before the
    content type can be told apart from the result of the steps. I read the protected header content type when steps 1 to 8
    reject: a content type other than the attestation type is then `content_type_not_loggable` (checkpoint) or
    `data_envelope`, otherwise `verification_failed`. The registry-endpoint vectors do not exercise it. The admission code
    covers only the `registry-endpoint` claim (size, malformed, encrypted, steps 1 to 8, schema, issuer, lifetime, claim
    vocabulary, data); resubmission, SRL and retirement stores, `domain-control` and `retired` data, and the log policy rule
    are not implemented (no log). Proposed fix: say whether the content type refusal applies to the header or to the
    verified result.
   Resolution: Resolved in Draft 06, section 9 (Admission; decision 80): the content type refusal reads the protected header after the structural decode, before steps 1 to 8, so a bare data envelope is `data_envelope`. Your order (header read after steps 1 to 8 reject) gives the same refusals for every vector; the one case that separates them is known gap 27.
39. **Published anchor, encrypted envelope and replay (section 9 "Anchor records"; notes section 6)**: steps 1 to 8 "like a
    checkpoint" does not say what an encrypted (tag 96) anchor does, nor whether replay protection applies to a published
    document read many times. I reject tag 96 with `1/unexpected_encryption` as the checkpoint check does and switch the
    nonce replay check off (a monitor re-reads the same anchor). An `expires-at` on an anchor is accepted (notes 51 leave it
    open). A malformed `log` argument is `anchor_log_mismatch`. Proposed fix: state the three points.
   Resolution: Resolved in Draft 06, section 9 (Checking a published anchor; decision 64): an encrypted anchor is rejected and, with no recipient identity, the code is `2/no_recipient_key` (Rust, npm); your `1/unexpected_encryption` is a code follow-up (known gap 25). Replay checking is off for a published anchor, `expires-at` is compared at step 5 and otherwise ignored, and a `log` argument that is not an Agent ID is `anchor_log_mismatch`.
40. **`require_anchor` rule values (section 7; notes section 4)**: an age of `true` is not an integer (JSON booleans are
    not numbers, but Python treats `True` as `1`; I reject it), an age above 2^64-1 is refused though the grammar `uint`
    is unbounded in CDDL, and the same rule listed twice is accepted (a conjunction of identical rules). `log` is
    normalized to the `atep:` form in the parsed result as the notes say; the text of a `chain` is kept. Proposed fix: say
    the integer range of an age (64 bits) and that duplicates are allowed.
   Resolution: Resolved in Draft 06, section 7 (Values of an anchor rule; decision 76): an age is a JSON integer from 1 to 2^64-1, a boolean is not a number, the same rule may be listed twice, `log` is normalized to the `atep:` form and `chain` kept as written.
41. **Where `policy_invalid` is raised in `verify` (section 7 versus notes section 4)**: section 7 says an implementation
    refuses to verify with a policy that does not parse and releases no payload; vectors for a bad `require_anchor` member
    only appear as a policy parse (`{ok: false, error: policy_invalid}`, no step). In `verify()` the policy is still
    parsed inside step 9, after steps 1 to 8 (so an envelope that fails an earlier step reports that step, and a bad policy
    never releases a payload either way); the vector runner maps the step 9 result to the step-less expectation. No vector
    separates the two orders. Proposed fix: say whether the parse happens before step 1.
   Resolution: Resolved in Draft 06, section 7 (Where `policy_invalid` is raised; decision 77): both positions are allowed (before step 1 in Rust and npm, inside step 9 in Python), the payload is never released, and no vector separates them (known gap 23).
42. **`chain-id` text rules (section 9 registry, CDDL)**: section 9 says "a registered id is 1 to 64 bytes of lowercase
    letters, digits and hyphens, and never starts with `x-`" and also that any id not in the table is invalid, which
    makes the first sentence a description of the table and not a second accept rule. I accept exactly the five listed
    ids and the extension form (matched as whole text; a trailing newline does not pass), the 64 byte limit counts UTF-8
    bytes (non ASCII text is invalid anyway). The CDDL `chain-id = tstr .size (1..64)` accepts more than the text; this is
    already noted in `ANCHOR-DISCOVERY-NOTES.md`. Proposed fix: as the notes propose for the CDDL.
   Resolution: Resolved in Draft 06, section 9 (The `chain-id` registry; decision 78): a registered id is the table and nothing else, matched as whole text; the CDDL was already changed to the registered choice and `extension-chain-id`, and section 9 now shows it.
43. **Anchor record integers (section 9)**: `uint` for `block-height` and `anchored-at` is read as 0 to 2^64-1 (the largest
    CBOR head); a CBOR bignum tag is not an integer here (the strict decoder does not accept tags). The expected `block_height`
    of an absent key is `null`, and encoding never writes a null (README), which a reader of section 9 alone would also
    infer. Proposed fix: state the range.
   Resolution: Resolved in Draft 06, section 9 (Validity of a record; decision 79): the integers are 0 to 2^63-1, because section 5 limits ATEP CBOR integers to a signed 64-bit range and both strict decoders refuse a larger head (so 2^64-1 is never reached); a bignum tag is not an integer; an absent height is `null` in a JSON view only.
44. **Skips of Draft 05 (notes section 9 and section 1)**: nothing is skipped beyond `log-admission` (4) and `monitor`
    (1). `registry-endpoint` (26) is run through the `admit_registry_endpoint` function rather than a log (the check is a
    pure function of the attestation, notes section 7), `domain-binding` through `check_binding`, so the totals are 431 run
    and 5 skipped of 436.
   Resolution: Resolved in Draft 06, section 12 (decision 81): 431 run and 5 skipped of 436; `registry-endpoint` and `domain-binding` run as pure functions; 264 vectors are required of every verifier.
