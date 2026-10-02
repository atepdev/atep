# Anchoring and discovery vectors: what an implementation has to match

For the Python and JavaScript implementations, and for anyone writing a fourth. Read it together with `README.md` in this directory (formats, including the addendum "Draft 05 addendum: anchoring and discovery vectors") and the specification ([Draft 07](../spec/ATEP-Specification-Draft-07.md); the behavior was introduced in internal Draft 05, and the section numbers here are unchanged in Draft 07) (section 4 "Domain records", section 5 "Encryption rule", section 7 "Registry endpoints", "Checking a domain binding" and "Trust policy", section 9 "Checkpoints", "Checkpoint hash", "Anchor records", "The `chain-id` registry", "Admission", section 10 steps 1 and 9 and the error table, section 12 "Known vector gaps" 16 to 21). Nothing here needs the Rust code. Where the text was open in Draft 05 the Rust reference took a reading, listed at the end and recorded as entries 50 to 56 of [`../docs/implementation-findings/rust-findings.md`](../docs/implementation-findings/rust-findings.md); a vector decides before this note does.

The Rust reference passes all 436 vectors (`cargo run --release -p atep-core --bin atep-vectors -- check ../vectors`). The first 200 vectors are unchanged, same bytes and same order in `manifest.json`; the 236 new ones are appended. Generation is deterministic: regenerating gives identical bytes.

## 1. Checklist

| Category | Vectors | Object under test (`.cbor`) | Result (`expected`) | Applies to |
| --- | --- | --- | --- | --- |
| `anchor-media-type` | 3 | envelope, verification format | as `verify-*` | every verifier |
| `require-anchor` | 27 | deterministic CBOR of the policy JSON | `{ok, require_anchor}` or `{ok: false, error: policy_invalid}` | every verifier |
| `anchor-not-supported` | 9 | encrypted data envelope, verification format | as `verify-*` | every verifier |
| `chain-id` | 30 | CBOR text string | `{ok, kind}` or `{ok: false}` | every verifier (the policy parser needs it) |
| `checkpoint-hash` | 9 | checkpoint envelope | checkpoint check plus `checkpoint_hash`, or a rejection | anything that reads checkpoints for anchors: log, monitor, a client that shows anchors |
| `anchor-record` | 36 | anchor record payload, or any bytes | `{ok, record}` or `{ok: false, error: anchor_record_invalid}` | the same |
| `anchor-envelope` | 13 | log-signed anchor envelope | `{ok, log, record}` or a rejection | the same |
| `registry-endpoint` | 26 | attestation envelope, `log-admission` format | `{ok, document}` or `{ok: false, refusal}` | a log; a verifier may skip |
| `domain-binding` | 83 | deterministic CBOR of the fixture JSON | the state of each source and the outcome | an issuer of `domain-control` (and a log that offers the check); a verifier may skip |

"Every verifier" is what Draft 05 section 12 requires of an implementation that claims Draft 05: accept the anchor media type, fail closed on `require_anchor` with `anchor_not_supported`, reject an unknown or malformed member as `policy_invalid`. That is 69 vectors (3 + 27 + 9 + 30). The three categories of the fifth row group (`checkpoint-hash`, `anchor-record`, `anchor-envelope`, 58 vectors) apply to an implementation that interprets those documents; a verifier that does not read anchors (the spec says ignoring them loses nothing) reports them as skipped and says so. `registry-endpoint` and `domain-binding` (109 vectors) are the work of a log and of an issuer; a verifier that has neither reports them as skipped, as it does `log-admission` and `monitor`. 195 of the first 200 vectors apply to a verifier, so a verifier that runs the required set runs 264 of the 436.

No new vector changes any of the first 200 and no existing error code changes. New error codes, all step 9: `anchor_content_type_invalid`, `anchor_schema_invalid`, `anchor_log_mismatch`, `anchor_checkpoint_mismatch` (section 6; proposed in Rust finding 50, not yet in the section 10 table). New names that are not verification results: `anchor_record_invalid` and, for a configuration error, `policy_invalid` without a step.

## 2. Conventions of the new categories

* **Vectors whose object under test is JSON** (`require-anchor`, `domain-binding`) and the text of a `chain-id`: the `.cbor` file is the deterministic CBOR encoding of the value that `inputs` carries (`inputs.policy`, `inputs.fixture`, `inputs.id`), so that the manifest hash pins it. The `.json` file is the same value. An implementation reads the value from `.expected.json` (`inputs`); it never has to decode the `.cbor` file of these categories. Only integers appear (no floats), so the two are the same value.
* **`anchor-record` rejection vectors** are sometimes not strict deterministic CBOR on purpose (unsorted keys, a duplicate key, an indefinite length map, a non shortest integer head, trailing bytes). Such a file has no JSON view; its `.json` is `{"not_strict_cbor": true, "hex": "<the bytes>"}`. The expected result is the same `{ok: false, error: anchor_record_invalid}`.
* **Verification categories** (`anchor-media-type`, `anchor-not-supported`) are exactly the `verify-*` format of `README.md`: `inputs.policy` is the verifier context, `expected` the result of section 10, compared whole. `now` is 1800000000. The `.cbor` of `anchor-not-supported` is an encrypted data envelope from alice to bob (`recipient_seeds` in the policy), with its attestations inline under `-70009` where a case needs them; the `.cbor` of `anchor-media-type` is the bare tag 98 envelope.
* **Identities** are the usual ones (`SHA-256("ATEP-vectors-v1/<name>/<field>")`): `log` signs checkpoints and anchors, `mallory` is another signer, `alice` signs the data envelopes of `anchor-not-supported` and issues the `registry-endpoint` attestations, `root` is the root issuer, `bob` and `carol` hold encryption keys. Key bundles travel inline, so a verifier needs no seeds except `recipient_seeds`. Agent IDs in `domain-binding` fixtures are `alice` (the one asked about) and `bob` (another one).
* `CT_ANCHOR` is `application/atep-anchor+cbor` (provisional).

## 3. `anchor-media-type` (3 vectors)

Verification vectors with the policy of a bare verifier (`now`, no recipient, no trust policy). They show what step 1 does with the anchor media type.

| Vector | Result |
| --- | --- |
| `bare-anchor-envelope-accepted` | **accepted.** A bare tag 98 envelope with content type `application/atep-anchor+cbor`, an anchor record as payload, no `expires-at`. Draft 03 rejected it as `1/unencrypted_non_trust_document`; Draft 05 lists it with the attestation, SRL and checkpoint types. No `expires-at` is required (that is for the attestation type only) |
| `bare-anchor-envelope-garbage-payload-accepted` | accepted although the payload is a text string: the core verifier checks the label only (section 5), whoever reads the payload validates it |
| `lookalike-media-type-rejected` | `1/unencrypted_non_trust_document` for `application/atep-anchor+json`: only the four listed media types, matched exactly, may travel unencrypted |

What an implementation changes: the set of trust document content types at step 1 gains the anchor type (Python: `TRUST_DOC_TYPES` in `atep_py/envelope.py`). Nothing else about step 1 moves. No vector has an encrypted envelope with the anchor label or an anchor with `expires-at`, because the text decides neither (Rust finding 51).

## 4. `require-anchor` and `anchor-not-supported` (27 + 9 vectors)

**`require-anchor`: the policy parse.** `inputs`: `{check: "require-anchor", policy: {...}}`. The policy is a JSON object parsed by the rules of section 7 ("Trust policy"); the vectors only exercise the member `require_anchor` (the other members behave as before). `expected`:

* `{ok: true, require_anchor: [{log, chain, max_age_days | max_age_hours}, ...]}`: the rules in array order. `log` is reported in the canonical `atep:` form (a `did:atep:` input is accepted and normalized), `chain` as given, exactly one of the two age members as an integer.
* `{ok: false, error: "policy_invalid"}`: a configuration error. It has **no step**: an API that can only return verification results reports `{ok: false, step: 9, error: policy_invalid}` for it (decision 54) and one with an error channel reports it there; either way the implementation maps it to this expectation. Nothing is evaluated.

The rules of one rule object: members `log` (an Agent ID text, `atep:` or `did:atep:`), `chain` (a valid `chain-id`, section 5 below) and exactly one of `max_age_days` and `max_age_hours`, an integer of at least 1. An unknown member, a missing member, both age members, a malformed `log`, a `chain` that is not text or not a valid `chain-id`, an age that is not an integer or is below 1, a rule that is not an object, an array that holds one bad rule among good ones (the whole policy is refused), `require_anchor` that is not an array (an object, null), and the spelling `require-anchor` (an unknown member) are all `policy_invalid`. `[]` and an absent member are the same: no rules. A number that is not an integer (1.5) or above 64 bits is also an error, but cannot be written in the CBOR of the other vectors and has no vector (Rust finding 56).

**`anchor-not-supported`: step 9.** Verification vectors. While the effective policy has at least one `require_anchor` rule, an implementation that cannot evaluate it rejects at step 9 with `anchor_not_supported`, after steps 1 to 8 have passed and applied once to the envelope itself:

| Vector | Result |
| --- | --- |
| `policy-with-only-require-anchor` | `9/anchor_not_supported` (no other rule; the envelope would otherwise be accepted) |
| `with-a-rule-that-would-pass` | `9/anchor_not_supported` (not accepted: roots `[root]`, rule `operator`, alice holds it) |
| `with-a-rule-that-would-fail` | `9/anchor_not_supported`, not `claim_missing`: the refusal is reported before the rules are looked at |
| `two-require-anchor-rules` | `9/anchor_not_supported` |
| `before-the-atep-r-class-requirement` | `9/anchor_not_supported` with `atep_r` on and a class requirement that would fail with `claim_missing` |
| `empty-array-is-no-rule` | accepted: `require_anchor: []` behaves as Draft 03 |
| `empty-array-and-a-failing-rule` | `9/claim_missing`: an empty array is not a rule |
| `step-8-failure-is-reported-first` | `8/signer_revoked` |
| `step-2-failure-is-reported-first` | `2/not_addressed_to_recipient` |

No `cause`; the message text is informative. The refusal is part of step 9 evaluation, so a policy-less verification (no `trust`) never produces it. An implementation that rejects the member `require_anchor` as unknown (the Python implementation today) fails closed too but reports `policy_invalid`, so it fails these vectors and the valid cases of `require-anchor`; the fix is to know the member (parse its rules as above, keep them in the policy) and to add the refusal at the start of step 9.

## 5. `chain-id` (30 vectors)

One vector per identifier. `inputs`: `{check: "chain-id", id: "<text>"}`; the `.cbor` file is that text as a CBOR text string. `expected`: `{ok: true, kind: "registered"}`, `{ok: true, kind: "extension"}` or `{ok: false}`.

* Registered: exactly one of `solana-mainnet`, `ethereum-mainnet`, `bitcoin-mainnet`, `opentimestamps`, `rekor` (matched exactly: no other case, no suffix, no trailing space; `solana`, `Solana-mainnet`, `rekor2`, `bitcoin-testnet` are invalid).
* Extension: `x-` followed by a name of one or more of `a` to `z`, `0` to `9` and `-`, **not beginning or ending with a hyphen**, the whole id at most 64 bytes (`x-` plus 62 characters is the longest; 63 is invalid). `x-`, `x--`, `x-acme-`, `x--acme`, `x-Acme`, `X-acme`, `x_acme`, `xacme`, `x-acme_ledger`, `x-acme.ledger`, a name with a space or a non ASCII letter, and the empty string are invalid.

The same function decides the `chain-id` of an anchor record and of a `require_anchor` rule (an invalid one makes the record invalid, a rule a configuration error). It is a pure function of the text; there is no registry lookup.

## 6. `checkpoint-hash`, `anchor-record` and `anchor-envelope` (9 + 36 + 13 vectors)

**`checkpoint-hash`.** The `.cbor` file is a checkpoint envelope. `inputs`: `{now, trusted_logs}`. Check it as a `log` vector with `check: checkpoint` (steps 1 to 8, the content type, a trusted signer, the payload schema; failures exactly as there: `9/inclusion_proof_invalid` with `cause` for a failed envelope, `9/checkpoint_untrusted`, `9/checkpoint_schema_invalid`). On success `expected` is

```
{"ok": true,
 "checkpoint": {log, tree_size, root_hash, timestamp},      as in the log vectors
 "checkpoint_hash": "<64 hex>",
 "payload_hex": "<the payload bytes>"}
```

`checkpoint_hash` is SHA-256 of the **payload bytes of the verified envelope** (the deterministic CBOR map `{tree-size, root-hash, timestamp}`, keys in the order `root-hash`, `timestamp`, `tree-size`), not of the envelope and not of a re-encoding of anything else. Two envelopes with one payload and different signatures have one hash (`hash-same-payload-envelope-a` and `-b`). The vectors include the empty tree (SHA-256 of the empty string as root, size 0) and a tree size that needs an eight byte integer head. A rejected checkpoint yields no hash (the untrusted, bad signature and two schema cases).

**`anchor-record`.** The `.cbor` file is the bytes of an anchor record payload (or anything else). `inputs`: `{check: "anchor-record"}`. `expected`: `{ok: true, record: {checkpoint_hash, chain_id, transaction_id, block_height, anchored_at}}` (`block_height` is null when the key is absent; `checkpoint_hash` is hex) or `{ok: false, error: "anchor_record_invalid"}`. Decoding and encoding both apply: for an accepted vector, building the record from `expected.record` and encoding it deterministically (no `block-height` key when it is null, never a null or a zero) gives the `.cbor` bytes. A record is valid when the bytes are one strict deterministic CBOR item (no trailing byte, no duplicate or unsorted key, shortest heads, definite lengths) that is a map with exactly the text keys `checkpoint-hash` (32 byte string), `chain-id` (valid, section 5), `transaction-id` (text of 1 to 512 bytes), optional `block-height` (unsigned integer, so not null, text or negative) and `anchored-at` (unsigned integer). Everything else is invalid: an unknown key, a missing required key, a wrong type or size, an integer key, a document that is not a map. The accepted vectors cover every registered chain, an extension chain, a missing height, a height of 0, and transaction ids of 1 and of 512 bytes.

**`anchor-envelope`.** The `.cbor` file is a log-signed anchor envelope. `inputs`: `{now, log, checkpoint_hash_hex}`: the log the verifier asked about (an Agent ID text) and the hash of the checkpoint it is looking at. This is the check of section 9 "Anchor records" ("takes an anchor record as published only when ..."), in this order, the first failure being the result:

1. Steps 1 to 8 of section 10 with no recipient, no trust policy and no revocations (the bundle is inline). A failure is reported **as it is**: `{ok: false, step, error}` (`4/eddsa_signature_invalid`, `4/mldsa_signature_invalid`, `5/issued_in_future`, ...), not wrapped.
2. The content type is `application/atep-anchor+cbor`, else `9/anchor_content_type_invalid`.
3. The payload is a valid anchor record (above), else `9/anchor_schema_invalid`.
4. The signer is the log asked about, else `9/anchor_log_mismatch`.
5. The record's `checkpoint-hash` equals the hash of the checkpoint looked at, else `9/anchor_checkpoint_mismatch`.

On success `expected` is `{ok: true, log: "<atep: text>", record: {...}}`. The vectors: three valid records (a registered chain with a height, `rekor` without, an extension chain), a flipped EdDSA signature, a flipped ML-DSA signature, an altered payload (all step 4), a record signed by another identity, a record for another checkpoint, a record under the checkpoint content type, a payload with an unknown key, one with an unregistered chain, one that is not a map, and an envelope issued in the future (step 5). Whether the witness really holds the hash is not checked and has no vector (milestone M5).

## 7. `registry-endpoint` (26 vectors)

Log admission vectors, in the format of `log-admission` (README, "Draft 04 addendum"): the `.cbor` file is the submitted attestation (alice issues it for herself; claim `https://atep.dev/claims/registry-endpoint`), `inputs` is `{now, log, max_envelope_bytes, logged: []}` and `expected` is `{ok: true, document: "attestation"}` or `{ok: false, refusal: "schema_invalid"}` (and `claim_vocabulary` for the look-alike claim). The claim is the seventh entry of the core list, so a log with the 14 core claim types admits it; the core verifier does not look at `data`.

The `data` rule (section 7): `url` is text, an `https` URL of at most 2,048 characters with a host, no credentials (`@` in the authority) and no whitespace or control character; `kind` is text, one of `registry`, `verifier`, `mcp`, `a2a` or `x-` followed by one or more lowercase letters, digits and hyphens. Other members are free. Accepted: the four kinds, an extension kind, a URL with port, path and query, a URL of exactly 2,048 characters, extra members, and an `a2a` attestation with `evidence` and `evidence-uri` (the agent card digest, which changes nothing in the layout). Refused (`schema_invalid`): `http` and `ftp` schemes, no scheme, credentials, whitespace, no host (`https:///v1`, `https://:8443/`), 2,049 characters, `url` or `kind` missing or not text, an unknown kind, `Registry`, an empty kind, `x-`, `x-Acme`, `x-acme_queue`. `reject-lookalike-claim-uri` (a claim URI ending in `registry-endpoints`) is `claim_vocabulary`: the reserved namespace stays closed.

A verifier-only implementation does not need this category. An implementation with a log runs it through its admission rules (after the `log-admission` ones, which already exist); the check is a pure function of the attestation `data`.

## 8. `domain-binding` (83 vectors)

Pure fixtures: nothing in a domain record is signed, so the object under test is what a fake fetcher answers, the Agent ID asked about and the options. No network is used. `inputs`: `{check: "domain-binding", fixture: {...}}`.

```
fixture = {
  "domain": "<DNS name to check>",
  "agent_id": "atep:...",
  "options": {"require_both": bool, "require_dnssec": false},
  "well_known": { "<host>": <answer>, ... },     the fetcher's answers by host name
  "txt":        { "<name>": <answer>, ... }      the fetcher's answers by TXT name
}
well-known answer = {"unavailable": "<reason>"}                          the fetch failed
                  | {"status": int, "final_url": text, "content_type": text or null,
                     "body": text}                                       an HTTP answer
                  | the same with "body_filler": {"prefix", "fill", "suffix", "total_bytes"}
                    instead of "body": the body is prefix, then the one character `fill`
                    repeated so that the whole is exactly total_bytes bytes, then suffix
txt answer        = {"unavailable": "<reason>"}                          SERVFAIL, DNSSEC failure, timeout
                  | {"records": [ text | [text, ...] ], "dnssec_validated": bool}
                    a record given as a list is its character-strings, concatenated with nothing between
```

A host or TXT name that has no key in the fixture is a fetch for which **the document or name does not exist** (the fetcher says "not found"); that is silent, like a 404 or empty TXT data. `final_url` is the URL the body came from after the redirects the fetcher followed; the checker only looks at it. The checker asks the fetcher for the well-known document of `domain` and for the TXT records of `_atep.<domain>`, and for nothing else.

`expected`:

```
{"well_known": <state>, "dns": <state>, "outcome": "bound" | "not-bound" | "indeterminate",
 "queried": {"well_known": [<hosts asked, in order>], "txt": [<names asked, in order>]}}
state = "listed" | "not-listed" | "absent" | "invalid" | "unavailable" | "not-read"
```

`queried` is normative: it shows that nothing else was read (no parent, no search up the tree, no subdomain). A `domain` that is not a canonical lowercase DNS name (`valid_domain`: labels of 1 to 63 characters from `a` to `z`, `0` to `9` and `-`, none beginning or ending with `-`, at most 253 characters, no trailing dot, no empty label, no underscore) is refused first: both states are `not-read`, nothing is queried, the outcome is `not-bound`.

**The well-known source** (section 4), state from the answer:

1. `{"unavailable"}`, status `429` or `5xx`: `unavailable`. `404` or `410`: `absent` (the same as a missing key). Any other status (3xx, 204, 403, ...): `invalid`.
2. Otherwise (status 200): `final_url` must start with `https://<domain>/`, so another host, a subdomain, plain `http`, another port, or a longer host that begins with the name are `invalid` (a redirect that stays on the host and on `https` is fine, whatever the path). The content type must be `application/json` with optional parameters (`; charset=utf-8`), else `invalid` (also when missing, `text/plain`, `application/ld+json`). The body must be at most 65,536 bytes (65,537 is `invalid`, and its content is not read), valid JSON, an object, with `version` the integer 1 (`2`, `"1"` or absent: `invalid`) and `agents` an array (absent or not an array: `invalid`); when `domain` is present it must equal the domain asked about exactly (`other.example`, `www.example.com`, `Example.com`, and a document of a subdomain naming its parent: `invalid`). Other members (`srl-url`, `updated`, unknown ones) are ignored.
3. A valid document is `listed` when an entry of `agents` is text that parses as an Agent ID (`atep:` or `did:atep:` followed by exactly 52 lowercase base32 characters of 32 bytes, nothing else) and equals the one asked about, else `not-listed`. Entries that are not Agent IDs (`"nope"`, 7) are ignored. At most 1,024 entries are read (the 1,024th counts; the 1,025th case has no vector).

**The DNS source** (section 4): `{"unavailable"}`: `unavailable`. Missing key, an empty list, or no usable record: `absent`. Otherwise each record is the text (strings concatenated); a record counts only if it is at most 1,024 octets, US-ASCII and **begins with the term `v=atep1`**: the text starts with `v=atep1` and the next character, if any, is a space (a leading space, `v=atep10`, and `v=atep1` as a second term all fail this). At least the first 16 records are read. The terms after it are separated by one or more spaces; `id=<agent id>` terms (`atep:` or `did:atep:`, canonical lowercase) list an identity, every other term (including an `id=` that is not an Agent ID, an `srl=` term, an unknown term) is ignored. The authorized set is the union of the `id=` terms of all counting records. With no counting record the state is `absent`; otherwise `listed` if the set contains the Agent ID and `not-listed` if not (a bare `v=atep1` authorizes nobody and is `not-listed`). `dnssec_validated` does not change the state while `require_dnssec` is false (an issuer MAY refuse unvalidated answers; no vector sets the option).

**The outcome** (section 7, "Checking a domain binding", step 3), with `a` the well-known state and `b` the DNS state:

* Default (`require_both` false): `bound` when one of them is `listed` and the other is not `not-listed`; `not-bound` when one is `listed` and the other `not-listed` (a valid source that omits the Agent ID contradicts one that lists it: the stale record case, either way round); otherwise `indeterminate` when either is `unavailable` and none is `listed` (including `not-listed` plus `unavailable`), otherwise `not-bound`. An `invalid` source never contradicts and never lists.
* `require_both` true: `bound` when both are `listed`; `not-bound` when either is `absent`, `invalid` or `not-listed`; otherwise (an `unavailable` side and no definite no) `indeterminate`.

The cases include the stale TXT record that the document withdrew and the reverse, an invalid document next to a listing TXT record (bound), an unavailable source next to a listing one (bound) and next to a valid source that omits the Agent ID (`indeterminate`), and the subdomain cases: records at `example.com` do not bind `a.example.com` and the reverse, and `queried` shows the exact names read.

## 9. Which implementation has to add what

**Python (`python/atep_py`)**, from the spec and these vectors only:

1. `anchor-media-type`: add `application/atep-anchor+cbor` to the trust document types at step 1.
2. `require-anchor` and `anchor-not-supported`: know the policy member `require_anchor`; parse it by the rules of section 4 above (`policy_invalid` on any violation, no rules for `[]`); at the start of step 9, when a rule exists, return `{ok: false, step: 9, error: anchor_not_supported}`.
3. `chain-id`: the registry and extension rule as a pure function.
4. If it reads checkpoints, anchors or documents with a hash: the checkpoint hash (`SHA-256` of the verified payload), the anchor record decode and encode, and `check_published_anchor` with its four codes (steps 1 to 8 as they are).
5. If it has a log or an issuer: `registry-endpoint` data check in admission, and the domain binding fixture runner (the two parsers and the outcome of section 8).

**JavaScript (`@atep/core`, the Rust core compiled to WebAssembly)**: `verify` already takes the Rust policy parser, the Rust step 1 and the Rust step 9, so `anchor-media-type`, `anchor-not-supported` and the verification half of `require-anchor` (a policy that does not parse throws) pass once the vector runner reads the new categories. The WebAssembly crate exports none of the other functions yet; to run the rest it needs exports for: the chain-id check (`atep_core::anchor::validate_chain_id`), the anchor record decode (`AnchorRecord::from_payload`), the checkpoint hash (the Rust `verify_checkpoint` result plus `sha256` of the payload), `check_published_anchor`, the `require_anchor` parse result (`TrustPolicy::from_json`), the registry-endpoint check (`atep_core::admission::check_registry_endpoint`) and the fixture runner of `atep_core::domain`. The runner in `js` then compares whole results as the existing categories do.

**Any implementation** reports the categories it does not run as skipped by name (`registry-endpoint`, `domain-binding`, `checkpoint-hash`, `anchor-record`, `anchor-envelope`) the way a verifier reports `log-admission` and `monitor`. `crosscheck.py` does not cover the new categories.

## 10. Readings the reference took where Draft 05 was open

| Question | Reading in the vectors | Rust finding |
| --- | --- | --- |
| Names and order of the checks of a published anchor; steps 1 to 8 wrapped or not | four new step 9 codes; content type, schema, signer, hash; steps 1 to 8 reported as they are | 50 |
| An encrypted anchor, or an anchor with `expires-at` | not decided by the text, no vector | 51 |
| A TXT record over 1,024 octets or not ASCII | ignored (the source is `absent` if nothing else counts) | 52 |
| More than 1,024 agents, a `version` other than 1 | first 1,024 read (no vector); version other than 1 is `invalid` | 53 |
| A refused name, `require_both` with an unavailable source, public suffixes | `not-read`; as section 8; not implemented | 54 |
| `kind` extension name, URL length unit, scheme case | hyphen anywhere after `x-`; characters; lowercase `https` exactly (no edge vectors) | 55 |
| A configuration error as a vector result | `{ok: false, error: policy_invalid}` with no step | 56 |

**CDDL (`../spec/schemas/atep.cddl`) points raised by these vectors** (raised against the CDDL file as it stood): `chain-id = tstr .size (1..64)` does not say which ids are valid: it could be `chain-id = registered-chain-id / extension-chain-id`, with the five registered ids as a choice of text constants and `extension-chain-id = tstr .size (3..64) .regexp "x-[a-z0-9]([a-z0-9-]*[a-z0-9])?"` (the extension name does not begin or end with a hyphen), as the comment above it already says in prose. `endpoint-kind` uses `x-[a-z0-9-]+`, which allows a hyphen at either end of the name, and that is how the reference checks it (Rust finding 55). `anchor-record` and `anchor-rule` already match the vectors. `registry-endpoint` is already in `core-claim`.
