# `retired` and `successor`: what an implementation has to match

For the Python and JavaScript implementations, and for anyone writing a fourth. Read it together with `README.md` in this directory (formats, including the addendum for the 60 new vectors) and the specification ([Draft 07](../spec/ATEP-Specification-Draft-07.md); the behavior was introduced in internal Draft 04, and the section numbers here are unchanged in Draft 07) (section 7 "Retirement and succession", section 8 "Loading an SRL", section 9 "Admission" and "Monitors", section 10 steps 8 and 9, section 12 "Cases for `retired` and `successor`", section 17 "E-stop recognition"). Nothing here needs the Rust code. Where the text was open in Draft 04 the Rust reference took a reading, listed at the end and recorded as entries 42 to 49 of [`../docs/implementation-findings/rust-findings.md`](../docs/implementation-findings/rust-findings.md); a vector decides before this note does.

The Rust reference implements all of it and passes the 200 vectors (`cargo run --release -p atep-core --bin atep-vectors -- check ../vectors`). The first 140 vectors are unchanged, same bytes and same order in `manifest.json`; the 60 new ones are appended.

## 1. Checklist

| What | New or changed | Where the vectors supply it |
| --- | --- | --- |
| Error codes | **None.** Every new rejection is an existing code: `signer_revoked` (step 8), `attestation_invalid` with `cause {8, signer_revoked}`, `attestation_schema_invalid`, `claim_missing`, `srl_stale`, `attestation_revoked`, `claim_too_old`, and for a log `verification_failed` and `schema_invalid` | `expected` |
| Trust policy member | **`follow_succession`**, boolean, default false. A value that is not a boolean, and every member the specification does not define, is a configuration error as before | `inputs.policy.trust.follow_succession` |
| Context input: the local attestation store | Existing field, **new use**: step 8 reads valid `retired` attestations from it (also when there is no trust policy), and the step 8 of every attestation verified at step 9 reads it too | `inputs.policy.attestations` (list of hex envelopes) |
| SRL loading context | An SRL is loaded with steps 1 to 8 in the verifier's own context: lists loaded before it, `revocations`, `attestations` | `inputs.policy.srls` (loaded in list order), `srl-context` vectors |
| Attestation layouts | `retired` and `successor` are checked by every consumer (step 9 candidate validation, log admission) | the schema cases (RT6b, RT8, SU14a, SU14b, RT31b, SU26) |
| Step 8 | Retirement, exemption, union with SRL entries and direct revocations, earliest instant | RT1 to RT23, RT26 to RT29 |
| Step 9 | Succession fallback with `follow_succession` | SU1 to SU24 |
| Log admission | The retired attestations the log holds are its local store; layouts refused as `schema_invalid` | `log-admission` |
| Monitor | Alert `successor_chain` | `monitor` |
| Fork alert | **Not implemented**: Draft 04 section 14 leaves it open | none |

Which categories apply to which implementation: a **verifier** (what the Python and npm implementations are) must pass `retired-positive`, `retired-negative`, `successor-positive`, `successor-negative` (verification vectors) and `srl-context` (SRL loading). `log-admission` and `monitor` apply to an implementation that has a log or a monitor; a verifier that has none can still run them cheaply if it exposes the attestation layout check and the step 8 call (admission is those two plus the rules of section 9), but the specification does not require it of a verifier. That split is this note's reading of section 12, which says a conformant log or monitor passes the log vectors.

## 2. Running the verification vectors

Unchanged from the `chain-*` vectors, with these points.

* `recipient_seeds` is present when the CBOR file is an encrypted data envelope (all of them except RT18, RT19 and RT20, where the file is the unencrypted `retired` attestation under test).
* Compare the **whole** result with `expected`: `ok`, `step`, `error`, `cause` when there is one (`{step, error}`), and for a positive result `claims` (with `chain` and `expires_at`), `warnings` when non-empty, `command_class` for ATEP-R, `encrypted`, `nonce_hex` and the rest. The new vectors rely on `claims[].chain` (SU1, SU5, SU19, SU21, RT21, RT23, RT29), on `expires_at` (SU1: 1830000000) and on the warning text (RT29, SU17).
* `srls` is a list of SRL envelopes loaded **one after the other, each in the context built from what was loaded before it**, the `revocations` and the `attestations` store (section 8, "Loading an SRL"). No vector supplies a list that fails to load; the first failing one would make the vector invalid.
* `trust` is the policy object: `roots`, `rules`, `max_depth`, `srl` and `atep_r` as before, and `follow_succession`.

## 3. Step 8 in full

Step 8 of an envelope E (any envelope: the data envelope, and each attestation verified at step 9, and an SRL being loaded) with signer X and `issued-at` t. The first rule that applies rejects with `signer_revoked`; the three sources are a **union**, so the earliest instant wins and the reason is never looked at.

1. A 32 byte identity entry naming X with `revoked-at <= t` in **any** cached SRL (whatever its reason: `retired`, `compromised`, anything).
2. A directly supplied revocation for X with `revoked_at <= t` (reason `retired` or `compromised`).
3. **New.** The local attestation store holds a *valid retirement* R of X with `R.issued-at <= t` (inclusive: an envelope issued in the same second as R is rejected), **unless E is itself a `retired` attestation of X**.

*Exemption.* E is exempt from rule 3 only (rules 1 and 2 still apply, RT20) when its content type is `application/atep-attestation+cbor` and its payload is a CBOR map with `claim` equal to `https://atep.dev/claims/retired` and `subject` and `issuer` both equal to X (32 byte strings). The Rust reference looks only at those fields; it does not require the rest of the payload to be valid (Rust finding 48).

*Valid retirement R of X*, for a store entry. Every failure below makes the entry **ignored**, never an error (RT7, RT8, RT9, RT6a):

1. R is a tag 98 envelope with an attached payload, signed by X (`signer` equals X), content type `application/atep-attestation+cbor`, not encrypted.
2. R passes steps 1 to 7 of section 10 at the verifier's `now`, **except that `expires-at` is not compared with `now` at step 5** (RT4: a retirement whose `expires-at` has passed still counts) and replay checking is off. The `issued-at` skew check of step 5 still applies. The bundle of X is the inline bundle of R, a cached bundle, **or the bundle that was resolved for the envelope E being verified** (they have the same signer). No recipient identity: an encrypted entry is simply not a valid retirement.
3. The payload passes the attestation schema and the claim rules, with claim `retired`, `subject` and `issuer` both X (the `retired` layout below).
4. `expires-at - issued-at <= 400 days` (RT9: 401 days is ignored).
5. Nothing else is required: step 8 is **not** applied to R (it would only compare X with itself), an SRL entry naming R's `id` is **ignored** (RT10), and no inclusion proof is needed.

The effect is at `R.issued-at`, not when the verifier learns of it. If the store holds several valid retirements the smallest `issued-at` decides. Retirements that arrive any other way do not count: **an inline attestation of the envelope under verification is never read at step 8** (RT5), only the store, an SRL entry or a direct revocation.

Candidate validation (step 9) runs steps 1 to 8 on each pool attestation with the same bundles, revocations, SRL cache, skew **and the same local store** (replay off, no recipient, no trust policy, so no recursion). The store is used there for step 8 only; its entries are not made part of any pool by that call. So an attestation issued by X at or after `R.issued-at` is `9/attestation_invalid` with `cause {8, signer_revoked}` (RT22), one issued before stays valid (RT21), and this covers delegations (RT23).

An SRL being loaded is an envelope like any other, so step 8 applies to it: a list issued by X at or after `R.issued-at`, or at or after the `revoked-at` of an identity entry for X in a list already in the cache, is rejected at load with `8/signer_revoked` (RT24). A list whose own entry names its issuer from an instant **after** its `issued-at` loads (RT25). See also section 6.

*ATEP-R.* Nothing changes in section 17 except what step 8 now rejects: an e-stop signed by a retired X at or after `R.issued-at` is `8/signer_revoked` (RT26); before it, it is accepted (RT27). A claim attestation issued by X before the retirement stays usable, and the SRL rules of the class apply to X's list as to any issuer's: a stale list of X fails a `motion` command with `9/srl_stale` (RT28) and lets an e-stop through with the warning `SRL of <X> is past next-update <n>; using the stale copy` (RT29).

## 4. Layouts (every consumer)

In addition to the generic attestation schema and the evidence rule. A violation is `attestation_schema_invalid` at step 9 and `schema_invalid` at a log.

| Claim | Rule |
| --- | --- |
| `https://atep.dev/claims/retired` | `subject` equals `issuer`. `data` has no `reason`, or `reason` is a text string. Other members of `data` are free and ignored |
| `https://atep.dev/claims/successor` | `subject` differs from `issuer`. Same rule for `reason` |

Candidate validation order is unchanged: steps 1 to 8 as an envelope, content type and not encrypted, schema **and claim rules**, `issuer` equals signer, 400 day lifetime, issuer's SRL (missing or stale per policy, then `attestation_revoked`), inclusion proof when required. A schema failure therefore comes before the SRL lookup.

## 5. Step 9 with `follow_succession`

For a rule (claim C) on signer S, **only when the policy sets `follow_succession` true**:

1. Run the ordinary evaluation (unchanged).
2. If, and only if, it failed with `claim_missing` (the pool has no entry with `subject` S and `claim` C: this is the only way `claim_missing` arises), try succession. Any other failure (`claim_too_old`, `attestation_revoked`, `attestation_invalid`, a chain error, ...) is final and returned as it is (SU6, SU7).
3. Successor candidates: pool entries with `subject` S and `claim` `https://atep.dev/claims/successor`, in pool order, each through **candidate validation**; a candidate that fails is skipped, whatever the reason (SU9, SU11, SU13, SU14, SU15, SU16). Candidate validation applies step 8 to the old identity O at the successor attestation's `issued-at` (retirement of O at or before it, a `compromised` entry at or before it: both reject, SU9, SU11; strictly after: accepted, SU10, SU12), the lifetime, the SRL of O (stale list under fail-closed fails the candidate, SU16; under fail-open it passes with the warning, SU17) and the id withdrawal (SU15).
4. For each valid successor candidate, with issuer O, in pool order: the claim candidates are the pool entries with `subject` **O** and `claim` C, in pool order, each validated, then checked as for any rule: `max_age_days` (SU18), the rule's `data` condition (ATEP-R `peer-motion`), and authorization of the **claim attestation's issuer** by `authorize(issuer, C, roots, empty path, 2)`: the depth argument is 2 instead of 1, because the successor attestation is one attestation of the chain (SU19 passes at `max_depth` 3, SU20 fails at 2).
5. The first pair (successor candidate, claim candidate) that passes everything satisfies the rule. The verified claim reports: `claim` C; `issuer` the claim attestation's issuer; `root` the root the authority walk ended at; `chain` = [claim attestation, successor attestation, then the `issuer-authority` links]; `expires_at` the earliest `expires_at` of all of them (SU1: 1830000000).
6. If no pair passes, the rule fails with **`claim_missing`**, the error it already had; never the error of the failed pair (SU18, SU20, SU16). A verifier that does not implement succession reports the same error.

**One hop.** The verifier never looks for a successor attestation that names O (SU8). Applies unchanged to ATEP-R class requirements (SU21, SU22): the class rules are rules of the same kind, evaluated with the same policy member. The e-stop relaxation of attestation expiry applies to the attestations involved, successor attestation included.

Everything else of step 9 is unchanged: warnings are listed once each in the order first met (a stale list met while validating a failed attempt is still recorded, which cannot show in a result because the rule then fails), and the pool is the inline attestations (depth first) followed by the local store, deduplicated, at most 256 (SU23: `SUC` in the store, `A_O` inline).

## 6. SRL loading (section 8)

Steps, in this order: steps 1 to 8 on the envelope **in the verifier's context**; content type `srl_wrong_content_type`; payload schema `srl_schema_invalid`; `issuer` equals signer `srl_issuer_mismatch`; then the sequence rule against the cache (`srl_rollback`, `srl_sequence_conflict`, same bytes accepted, higher replaces). What is new is only the context of the first step: the cached lists (their identity entries), the direct revocations and the local store.

The Rust reference adds one thing the specification asks for as a SHOULD: **if the cache already holds exactly these bytes, the load is accepted and changes nothing**, before any verification (a list that names its own issuer from an instant at or before its `issued-at` would otherwise fail step 8 on a reload, Rust finding 47). No vector depends on it.

`srl-context` vectors: `inputs.attestations` is the store, `inputs.revocations` the direct revocations, `cached_srl_hex` is loaded first in the same context, then the CBOR file. Result as for the `srl` vectors; RT24 is `{"ok": false, "step": 8, "error": "signer_revoked"}`.

## 7. Log admission and monitor (for implementations that have them)

*Admission* (section 9): the order of the refusals is that of the table of the specification: size, strict CBOR and tag, not encrypted, content type, steps 1 to 8 of the **submitted form** at the log's clock (`verification_failed` with the failing step and error; revocations = identity entries of the SRLs already logged; **local attestation store = the `retired` attestations already logged**), payload schema, `issuer` equals signer, the 400 day limit, the claim vocabulary and the layouts (`schema_invalid` for `retired` and `successor` as in section 4 above), SRL sequence. Consequences: a document from a retired identity issued at or after its retirement is `verification_failed` step 8 `signer_revoked` (RT30), a second `retired` attestation of the same identity is admitted by the exemption (RT31a), a `retired` attestation with another subject (when the log holds no retirement of its issuer that predates it, Rust finding 44) and a `successor` naming its own issuer are `schema_invalid` (RT31b, SU26). A log keeps the retired attestations it logs (submitted form) as its store, and rebuilds it when it restarts, re-validating each entry with the store as it was.

*Monitor* (section 9, `successor_chain`): over the logged `successor` attestations, `entry` is the index of every one whose `issuer` is the `subject` of another logged `successor` attestation (the later link of a chain, whatever the log order), with that attestation's `issuer` and `subject`; raised once per entry; a single hop and a fork raise nothing. In the `monitor` vector the entries are numbered from 0 in the list; a real log holds its policy entry first, so its indices are one higher.

## 8. Readings the Rust reference took where the text was open

| Reading | Entry | Vector |
| --- | --- | --- |
| The SRL fixtures of the case tables: lists of X and O are issued before the instant they are revoked from (X 1799980000, O 1799400000), and entries naming X or O are in the list of another issuer | 42 | all that cache them |
| SU21, SU22 are evaluated without the fixture's `operator` rule | 43 | su21, su22 |
| RT31's second part is submitted to a log that does not hold R | 44 | rt31b |
| Formats of the load, admission and monitor vectors | 45 | srl-context, log-admission, monitor |
| `successor_chain`: `entry` is the link whose issuer is a subject, in either log order; fork not implemented | 46 | su25 |
| Reload of cached SRL bytes is no change | 47 | none |
| Exemption decided on content type, claim and the two Agent IDs only | 48 | none |
| No depth test for the successor attestation when the claim attestation's issuer is a root (the pseudocode accepts a root first) | 49 | none |

## 9. What the Python and the JavaScript implementations have to change

Both are verifiers; neither has a log or monitor. The first three rows are needed for the verification and `srl-context` vectors.

| Item | Python (`python/atep_py`, from the spec and these vectors only) | JavaScript (`js/`, wraps `rust/atep-wasm`) |
| --- | --- | --- |
| Step 8 reads the store | Today `attestations` only feeds the step 9 pool. Add the valid retirement scan to step 8 (section 3), with the exemption, for the envelope and for every attestation verified at step 9 | Done in `atep-core`; rebuild `js/dist` (`npm run build`). `verify` already passes `policy.attestations` through |
| `follow_succession` | Accept the member in the policy parser (it must keep rejecting unknown members) and implement section 5 | The member is parsed by `TrustPolicy::from_json`, so a rebuild accepts it; add `follow_succession?: boolean` to the TypeScript policy type if one exists |
| SRL loading context | Load SRLs with steps 1 to 8 against the cache, revocations and store (section 6) | `rust/atep-wasm` `verify` now loads `policy.srls` in that context. `verifySrl(cbor, now, srlPolicy, cachedSrl)` has no parameter for the store or revocations, so the `srl-context` vectors need it extended (for example an optional fifth JSON argument `{attestations, revocations}`) and `js/` updated |
| Attestation layouts | `retired` and `successor` checks in the claim rules (section 4) | Done in `atep-core` |
| Vector runners | `atep_py.vectors` walks `manifest.json` and indexes `CHECKERS[category]`, so it **fails on the seven new category names until they are added** (the five verifier categories at least). Python's own error names (spec section 20 decision 1) already map to the codes used here | `js/test/vectors.test.mjs` walks the manifest too and fails with `no checker for category` until the five verifier categories are added (the verification ones reuse the `chain-*` checker); its count becomes 200 |
| Expected totals | `python3 -m atep_py.vectors check ../vectors` should report 200 when `log-admission` and `monitor` are included, 195 for a verifier-only runner | as left |

`crosscheck.py` does not cover the new categories.
