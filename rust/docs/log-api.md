# ATEP log API (milestone M3, provisional)

HTTP/1.1, served by `atep-logd`. All data is signed, so TLS adds privacy but no trust; run the daemon behind a TLS terminating proxy for public use. Responses are JSON unless `Accept` contains `cbor`, which selects the CBOR form where one exists. Binary values in JSON are unpadded base64url (`envelope`, `checkpoint`, `proof`) or lowercase hex (`leaf-hash`, `root-hash`, `audit-path`). Agent IDs are `atep:` text. Errors are `{"error": "<code>", "detail": "..."}` with an HTTP status.

Layouts that were provisional are recorded in `../../docs/implementation-findings/rust-findings.md` (entries 33 to 41) and are now normative in the specification. The machine readable description of every endpoint below is `GET /openapi.json` (OpenAPI 3.1, a checked in copy is `docs/openapi.json`). `HEAD` is answered for every `GET` route. Every response carries `Access-Control-Allow-Origin: *`.

## Concepts

* **Leaf**: `SHA-256(0x00 || submitted envelope)`; the submitted envelope is the attestation or SRL without its `-70012` header (implementation finding 25). Tree: RFC 9162.
* **Checkpoint**: tag 98 envelope, content type `application/atep-checkpoint+cbor`, payload `{tree-size, root-hash, timestamp}`, signed by the log's hybrid identity, with the log's bundle inline.
* **Inclusion proof** (the `-70012` value): CBOR map `{leaf-index, audit-path, checkpoint}`. Verify with `atep_core::log::OfflineInclusion`.
* **Consistency proof**: CBOR map `{from, to, path}`.

## Endpoints

### `POST /v1/submit`
Body: the envelope (`Content-Type: application/cbor`), or JSON `{"envelope": "<base64url>"}`. Accepts attestations and SRLs only.

* `201` new entry, `200` duplicate (idempotent, the existing entry and a proof against the latest checkpoint).
* JSON reply: `{status: "accepted"|"duplicate", leaf-index, leaf-hash, audit-path, proof}`, where `proof` is the base64url CBOR inclusion proof ready for the attestation's `-70012` header. With `Accept: application/cbor` the body is that CBOR value.
* `400 malformed`, `413 too_large`, `422` with `error` one of `encrypted_envelope`, `data_envelope`, `content_type_not_loggable` (checkpoints), `verification_failed` (with `step` and `rejection`, steps 1 to 8; the `retired` attestations already logged are the local attestation store of step 8, so a document signed by a retired identity at or after its retirement is refused with step 8 `signer_revoked`, except a further `retired` attestation of that identity), `schema_invalid` (including a `retired` attestation whose subject differs from its issuer, a `successor` whose subject equals its issuer, and a non-text `data.reason` in either), `lifetime_exceeded`, `claim_vocabulary` (a claim under `https://atep.dev/claims/` that is not one of the 14 core claim types, or a forged log policy), `srl_rollback`.

Admission rules: see `GET /v1/policy`. Envelopes exchanged between agents are never logged (spec section 16 point 5).

### `GET /v1/checkpoint`, `POST /v1/checkpoint`
Latest signed checkpoint (a fresh one is signed first when the configured interval has passed). `POST` signs one on demand. JSON: `{log, tree-size, root-hash, timestamp, checkpoint, checkpoint-hash, anchors}`, where `checkpoint-hash` is the lowercase hex of `SHA-256(checkpoint payload)` and `anchors` is the list of anchor records of that checkpoint (empty unless the operator configured a witness; see below); `Accept: application/cbor` returns the envelope with content type `application/atep-checkpoint+cbor`.

### `GET /v1/checkpoints?from=<tree size>`
Every published checkpoint with tree size at least `from`, oldest first (at most 1000): `{log, checkpoints: [{tree-size, root-hash, timestamp, checkpoint, checkpoint-hash, anchors}]}`.

Each anchor is `{checkpoint-hash, chain-id, transaction-id, block-height (null when absent), anchored-at, anchor}` where `anchor` is the base64url log-signed envelope (`application/atep-anchor+cbor`) the other fields were read from. The log stores them in `anchors.rec` in the data directory; a directory without that file simply has no anchors. The operator attaches a witness with `Log::set_witness` (`atep_log::Witness`); the default is none and `atep-logd` ships no chain adapter.

### `GET /v1/proof/inclusion?leaf-hash=<hex>` (or `index=<n>`)
Inclusion proof against the latest checkpoint (one is signed first if none covers the leaf yet). JSON adds `tree-size` and `checkpoint`; `Accept: application/cbor` returns the proof value. `404` when the leaf is not in the log.

### `GET /v1/proof/consistency?from=<m>&to=<n>`
Proof that tree size `n` extends tree size `m` (`m <= n <= current tree size`). JSON: `{from, to, first-hash, second-hash, path, proof}`; `Accept: application/cbor` returns the proof value.

### `GET /v1/entries?from=<i>&to=<j>`
Entries `i..j` (exclusive, at most 1000 per call): `{from, to, tree-size, entries: [{index, leaf-hash, logged-at, kind, issuer, subject?, claim?, issued-at, expires-at, attestation-id?, srl-sequence?, envelope}]}`. `envelope` is the submitted form, so `SHA-256(0x00 || envelope)` is the leaf. `logged-at` is informational and not committed by the tree.

### `GET /v1/lookup?subject=<agent-id>[&claim=<uri or short name>]`
Attestations about a subject, same entry objects as `/v1/entries`. Serves logged attestations only.

### `GET /v1/issuers[?issuer=<agent-id>]`
Issuer directory, derived from the log: `{tree-size, issuers: [{issuer, first-index, entries, claims, namespaces, delegated-claims, delegated-by, domains, srl-urls, latest-srl, included}]}`. `srl-urls` come from `domain-control` attestations the issuer holds about itself.

### `GET /v1/claims`
Claim-type directory: the 14 core claim types (with definition and `data` schema, CDDL) plus every other claim type seen in the log: `{tree-size, core-namespace, claim-types: [{claim, core, namespace, entries, issuers, first-index, definition, data-schema, status, resolve}]}`. `status` is `core`, `proposed` (a proposal the log admits outside the core list; none today, `registry-endpoint` was one before Draft 05) or `open` (any other claim type seen in the log, which has no definition: `definition`, `data-schema` and `resolve` are `null`).

### `GET /v1/claims/<claim>`
Claim-type resolution: the human-readable definition and the CDDL schema of `data` of one claim type. `<claim>` is the claim URI percent-encoded (`/v1/claims/https%3A%2F%2Fatep.dev%2Fclaims%2Frobotics%2Ffleet-member`; the plain URI also works) or a short name (`audited`, `robotics/fleet-member`). JSON by default; `Accept: text/html` (or a `.html` suffix) returns a page, a `.json` suffix forces JSON. `404 claim_unknown` for anything without a definition: an unknown name, a claim of another namespace, a log policy URI.

The JSON document: `{claim, name, core, status, profile, definition, title, description[], issued-by, subject, data-schema, data-schema-format ("cddl"), attestation-schema, data-checked-by, evidence, lifetime, spec[], example-data, links}`. `definition` and `data-schema` are the strings the directory carries. Responses are cacheable for an hour (`Cache-Control: public, max-age=3600`, `Vary: Accept`).

The definitions come from the data file `atep-log/data/claims.json`: the 14 core claim types (spec section 7 and 17, schemas from `spec/schemas/atep.cddl`). A test checks that every claim `atep-core` knows is defined, that the CDDL rules shared with `atep.cddl` are identical, and that nothing else resolves.

### `GET /claims`, `GET /claims/<name>`, `GET /claims/robotics/<name>`
The same documents at the path of the claim URI, so a deployment mounted at `atep.dev` (a reverse proxy sending `atep.dev/claims/*`, `atep.dev/openapi.json` and `atep.dev/v1/*` to the daemon) serves `https://atep.dev/claims/audited` and `https://atep.dev/claims/robotics/peer-motion` itself. `<name>` may end in `.html` or `.json`; negotiation is as above. `GET /claims` is the index (`{namespace, claims: [...]}`, HTML on request). Only `/claims/robotics/<name>` serves robotics names: `/claims/fleet-member` is `404`.

### `GET /openapi.json`
The OpenAPI 3.1 description of every route in this document, with request bodies (CBOR and JSON), response schemas (JSON and the CBOR content types) and the error shapes. It is generated from the route table in `atep-log/src/routes.rs`, which is also what the server dispatches on, so a route cannot exist without a description. `docs/openapi.json` is a checked in copy; the test `openapi_is_served_and_matches_the_checked_in_copy` fails when it is stale (regenerate with `ATEP_UPDATE_OPENAPI=1 cargo test -p atep-log --test discovery`). Live responses of every endpoint are validated against the component schemas in `tests/discovery.rs`.

### `GET /v1/policy`
The log policy (admission rules, retention, availability, checkpoint cadence, key custody, commitments) with the entry that records it: `{log, claim, entry-index, first-entry, leaf-hash, issued-at, expires-at, policy, envelope, proof}`. The policy is a self-attestation of the log and the first entry of a new log.

### `GET /v1/gossip`, `POST /v1/gossip`
Checkpoint exchange. `GET` returns the log's latest checkpoint, the checkpoints of other logs it has observed and any split view evidence (`pair` is a base64url `{a, b, proof?}` document). `POST` takes `{"checkpoints": [<base64url envelope>...], "proofs": [<base64url consistency proof>...]}`, verifies and compares each checkpoint with what it holds for the same log, and answers `{log, split-view, results, checkpoints}` (its own latest and every checkpoint it relays). `409` when a split view was found; `results[].evidence` is then the evidence document, which anyone can confirm with the signing log's public key (`check_split_view`).

## Domain records (`domain-control`)

Not an HTTP endpoint: the check an issuer makes before it issues `domain-control` (spec section 4, "Domain records", and section 7, "Checking a domain binding"). The pure code is `atep_core::domain` and `atep_log::domain_binding` re-exports it (the domain binding vectors run it from `atep-vectors check`). `atep_log::domain_binding::check_domain_binding(domain, &agent_id, &fetcher)` reads `https://<domain>/.well-known/atep.json` and the TXT records at `_atep.<domain>` through a `DomainFetcher` trait (`fetch_well_known`, `fetch_txt`) and returns a `BindingReport` with an `Outcome` of `Bound`, `NotBound` or `Indeterminate`, the result of each source (`Listed`, `NotListed`, `Absent`, `Invalid`, `Unavailable`), warnings and the document's `srl-url` and `updated`. The library has no network code. The feature `net-fetch` adds `net::StdHttpFetcher`, a plain HTTP fetcher on `std::net` for a TLS terminating proxy (no TLS, no DNS client); production issuers supply an HTTPS and DNSSEC aware fetcher. `check_domain_binding_with` takes `BindingOptions { require_dnssec, require_both }`. `txt_record` and `well_known_document` render the two formats for a domain owner.

## The `registry-endpoint` claim (core claim type since Draft 05)

`https://atep.dev/claims/registry-endpoint` with `data` `{url, kind}` (`url` an https URL, `kind` one of `registry`, `verifier`, `mcp`, `a2a` or `x-<name>`) binds a service endpoint to an Agent ID. It is an ordinary attestation: the log admits it, validates `data` (`schema_invalid`) and changes nothing else. A signed A2A agent card is carried by putting the SHA-256 of the card bytes in the attestation's `evidence` and the card URL in `evidence-uri`. It is the seventh entry of `atep_core::attestation::claims::CORE` (with the seven robotics claims, 14 core claim types), so the log policy lists it in `core-claims` (14 entries; a log started from a data directory written by an earlier build appends a new policy entry on its first start) and the directory marks it `core`. The layout check (`atep_core::admission::check_registry_endpoint`) is part of the admission rules every log applies and has vectors (`vectors/registry-endpoint`); the core verifier does not check it.

## Running

```
atep-logd --data-dir ./log-data --listen 127.0.0.1:8480
atep-logd --data-dir ./log-data --check          # re-verify everything, print the log ID, exit
```

See `rust/README.md` for options and operations notes.
