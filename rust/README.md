# ATEP reference implementation, Rust

Workspace with five crates:

* `atep-core`: library. Key bundles, Agent IDs, hybrid signing, hybrid encryption, attestations (`attestation`), signed revocation lists and caches (`srl`), Merkle proofs and checkpoints (`log`), the trust policy engine and chain walking (`trust`), ATEP-R enforcement (`atep_r`), verification (spec section 10, all ten steps), JSON debug view, and the test vector generator and checker. Also builds the `atep-vectors` binary.
* `atep-cli`: the `atep` command line tool.
* `atep-log`: M3 transparency log library and the `atep-logd` server (Merkle log, checkpoints, proofs, submission validation, HTTP API, directories, gossip) and the discoverability layer (claim-type resolver, OpenAPI description, domain binding checker).
* `atep-monitor`: M3 monitor library and the `atep-monitor` command line tool.
* `atep-wasm`: the `atep-core` API compiled to WebAssembly for `js/` (not published as a crate).

The roadmap names Go for M3; it is Rust here so that every verification reuses `atep-core` ([`../docs/implementation-findings/rust-findings.md`](../docs/implementation-findings/rust-findings.md) entry 32).

Spec: [`../spec/ATEP-Specification-Draft-07.md`](../spec/ATEP-Specification-Draft-07.md). Test vectors and their format: [`../vectors/README.md`](../vectors/README.md). Spec ambiguities found while implementing: [`../docs/implementation-findings/rust-findings.md`](../docs/implementation-findings/rust-findings.md).

## Build and test

Needs a Rust toolchain (developed on rustc 1.98) and a working linker. M3 adds no dependencies beyond the ones already used (the HTTP server and client are on `std::net`).

```
cargo build --release
cargo test
cargo clippy --all-targets
```

The binaries are `target/release/atep`, `atep-logd` and `atep-monitor`. All crypto comes from RustCrypto crates (`ml-dsa`, `ml-kem`, `ed25519-dalek`, `x25519-dalek`, `aes-gcm`, `hkdf`, `sha2`); there is no custom cryptography. CBOR is a small in-crate encoder and strict decoder (`atep_core::cbor`) so that RFC 8949 section 4.2 determinism is exact and non-deterministic input is rejected.

## Registry: `atep-logd` and `atep-monitor` (M3)

API reference: `docs/log-api.md`. Spec section 9, provisional layouts in [`../docs/implementation-findings/rust-findings.md`](../docs/implementation-findings/rust-findings.md) entries 32 to 41 (resolved in the spec).

### Run a log

```
atep-logd --data-dir ./log-data --listen 127.0.0.1:8480
```

On first start the log generates its identity (`identity.key`, mode 0600), writes its public bundle to `log.pub`, records its policy as entry 0 and signs a first checkpoint. It prints its Agent ID, which verifiers pin in `trusted_logs` and monitors in `--log-id`. Options:

| Option | Meaning |
| --- | --- |
| `--data-dir DIR` | identity key, entries, checkpoints, gossip state (created if missing) |
| `--listen ADDR` | plain HTTP listen address, default `127.0.0.1:8480` |
| `--checkpoint-interval SECS` | sign a fresh checkpoint at least this often, default 3600 (checkpoints are also signed on every new entry and on `POST /v1/checkpoint`) |
| `--operator`, `--retention`, `--availability`, `--key-custody` | statements published in the policy (a change appends a new policy entry) |
| `--max-envelope-bytes N` | admission size limit, default 65536 |
| `--peer URL` (repeatable), `--gossip-interval SECS` | gossip with other logs, default every 300 s; a split view is printed to stderr |
| `--check` | open, fully re-verify, print the log ID and exit |

Storage is two append-only record files (`entries.rec`, `checkpoints.rec`) plus `peers.rec` and `evidence.rec` for gossip, each record length prefixed and checksummed and `fsync`ed on append, so a crash leaves at most a torn tail record, which is cut off at the next start. A `LOCK` file prevents two processes on one directory. At every start the log re-validates each entry as at its logging time, rebuilds the tree and checks that every stored checkpoint has a valid signature of this log and the root of the tree at its size; altered or rewritten files stop it from starting.

Submit with any HTTP client (`curl --data-binary @att.cbor -H 'Content-Type: application/cbor' -H 'Accept: application/cbor' http://127.0.0.1:8480/v1/submit -o proof.cbor`); the reply is the `-70012` value, which an issuer embeds in the attestation's unprotected header. The log accepts only valid attestations and SRLs: encrypted and data envelopes, checkpoints, unknown `https://atep.dev/claims/` types, expired or malformed documents are refused with a reason (see the API document).

### Discoverability

The registry describes itself, so an agent that is given only a URL can use it without an SDK. Details in `docs/log-api.md`; normative text in spec section 4 and section 9.

* **Claim-type resolution.** `GET /v1/claims/<claim-uri-encoded>` and the path style `GET /claims/<name>`, `GET /claims/robotics/<name>` (a deployment mounted at atep.dev serves `https://atep.dev/claims/<name>`) return the definition and the CDDL schema of `data` as JSON, or HTML for `Accept: text/html` or a `.html` suffix, for the 14 core claim types (`registry-endpoint` is one); anything else is `404`. The source of truth is `atep-log/data/claims.json`, tested against `atep-core`'s claim list and `../spec/schemas/atep.cddl`.
* **OpenAPI 3.1.** `GET /openapi.json` (copy in `docs/openapi.json`) covers every route, in JSON and CBOR, with error shapes. The route table (`atep-log/src/routes.rs`) is the one list the server dispatches on and the document is built from; tests check the document against the table, the checked in copy and live responses. Regenerate the copy with `ATEP_UPDATE_OPENAPI=1 cargo test -p atep-log --test discovery`. The document was validated with `@apidevtools/swagger-parser` 13 (`SwaggerParser.validate`, OpenAPI 3.1) and `@redocly/cli lint` from npm.
* **Domain records.** `atep_log::domain_binding::check_domain_binding(domain, agent_id, fetcher)` (the code is `atep_core::domain`, re-exported there, and has language neutral vectors in `../vectors/domain-binding`) checks `https://<domain>/.well-known/atep.json` and `_atep.<domain>` TXT records before an issuer signs `domain-control`. Trait based fetcher, no network code in the library; `cargo test -p atep-log --features net-fetch` also runs the `std::net` fetcher test.
* **`registry-endpoint`.** The seventh core claim type `{url, kind}` that binds a registry, verifier, MCP or A2A endpoint (and, through `evidence` and `evidence-uri`, a signed agent card) to an Agent ID. It is in `atep_core::attestation::claims::CORE`; admission checks `data` (`../vectors/registry-endpoint`); the core verifier does not.

### Run a monitor

```
atep-monitor --log http://127.0.0.1:8480 --log-id atep:... \
    --watch-domain example.com --authorized atep:<agent allowed to hold example.com> \
    --root atep:<root issuer> --interval 60
atep-monitor --log ./log-data --once --json ...      # read a log's data directory directly
```

`--once` polls once and exits 0 (no alerts) or 3 (alerts). Without `--once` it polls every `--interval` seconds and prints each alert once. `--state FILE` keeps the last verified checkpoint between runs, so a log rewritten while the monitor was down is still caught. `--strict-issuers` also reports issuers that hold no delegation. `--now` overrides the clock for replays.

Alerts (`--json` prints `{"alert": "<type>", ...}`): `unauthorized_domain_control` (a `domain-control` attestation for a watched domain, or a subdomain, whose subject is not in `--authorized`), `issuer_outside_authority` (a claim type outside the issuer's delegated `issuer-authority`, relative to the `--root` set), `undelegated_issuer`, `successor_chain` (a logged `successor` attestation whose issuer is itself the subject of another: succession spans two or more hops, which a verifier never follows; `entry` is the later link; one identity naming two successors, a fork, is not an alert, see spec section 14), `inconsistent_checkpoint` (failed consistency proof, with transferable evidence), `checkpoint_gap`, `tree_shrank`, `entry_root_mismatch` and `entry_gap` (served entries do not match what was signed), `entry_invalid`, `bad_checkpoint` (bad signature or wrong log), `split_view` (two checkpoints of one log that cannot share a history, with evidence) and `source_unavailable`. Monitors also verify that the entries they download hash to each signed root.

### Operations note: key custody

The log's signing key is the root of trust of every checkpoint and inclusion proof it ever issues. `identity.key` holds the secret seeds in a file readable only by the daemon user; anyone who can read it can sign checkpoints for forked histories, which monitors would then report as split views but cannot prevent. For a public log:

* keep the data directory on a dedicated host account, with the key file excluded from backups that others can read; back up `entries.rec` and `checkpoints.rec` (public data) freely;
* prefer an HSM or key service for signing (the `Identity` signing calls are the only users of the key; the seeds are never needed for verification);
* never copy `identity.key` to a second running log: two logs with one key and different histories are, by construction, a split view;
* publish the Agent ID and `log.pub` through channels independent of the log, and run monitors and gossip peers on other infrastructure;
* a compromised or retired log key is replaced by a new identity and a `successor` attestation signed by the old one (not implemented in M3, finding 41); until then start a new data directory and announce the new Agent ID.

### M3 acceptance tests

`atep-monitor/tests/acceptance.rs` starts a log over HTTP, logs a legitimate chain and an injected mis-issuance (an issuer outside its delegated claim types plus two unauthorized `domain-control` attestations), and checks that the monitor alerts on exactly the bad entries; the same monitor reads the data directory and the library directly; and rewritten, forked, shrunk and tampered histories are caught through consistency proof failure, split view detection and root mismatch. `atep-log/tests/log.rs` covers admission, proofs, restart, torn writes, tampering, directories, the HTTP API and gossip between a log that equivocates and honest logs.

## CLI

```
atep keygen --out alice.key            # writes alice.key (secret, mode 0600) and alice.key.pub, prints the Agent ID
atep keygen --out bob.key --no-enc     # signing keys only
atep id alice.key                      # atep:... ;  --did gives did:atep:...
atep sign -k alice.key -i payload.bin -o env.cbor --expires-in 3600
atep encrypt -i env.cbor --to bob.key.pub -o env.enc.cbor
atep verify -i env.enc.cbor -k bob.key --payload-out payload.out
atep decrypt -i env.enc.cbor -k bob.key -o env.cbor
atep verify -i env.cbor --bundle alice.key.pub --now 1800000000 --json
atep view env.enc.cbor                 # JSON debug view

# M2: attestations, revocation, policy
atep attest -k root.key --subject ca.key.pub --claim issuer-authority \
      --data '{"claims": ["https://atep.dev/claims/operator"]}' --days 90 -o root-ca.cbor   # prints the attestation id
atep attest -k ca.key --subject atep:... --claim operator --data '{"name": "Acme"}' -o ca-alice.cbor
atep sign -k alice.key -i payload.bin -o env.cbor --attach ca-alice.cbor --attach root-ca.cbor
atep verify -i env.enc.cbor -k bob.key --policy policy.json --root atep:<root id> --srl root.srl
atep chain -i ca-alice.cbor --attestation root-ca.cbor --root atep:<root id>             # print the chain
atep srl -k root.key --attestation root-ca.cbor -o root.srl                             # revoke (alias: atep revoke)
atep srl -k root.key --prev root.srl --identity atep:... -o root.srl2                   # next sequence, mark an identity compromised
```

Notes:

* `sign` defaults to content type `application/atep+cbor`, which MUST be encrypted for exchange. For public trust documents pass `--content-type application/atep-attestation+cbor` (requires `--expires-at` or `--expires-in`), `application/atep-srl+cbor` or `application/atep-checkpoint+cbor`.
* Other `sign` options: `--detached`, `--no-bundle`, `--issued-at`, `--nonce-hex`, `--deterministic` (deterministic ML-DSA).
* `verify` exits 0 and prints the signer and header summary on success. On failure it exits 1 and names the step, for example `REJECTED at step 3 (signer_id_mismatch): ...`. With `--json` it prints the same structured result used in the test vectors. Options for the inputs a verifier would otherwise cache: `--bundle` (known signer bundles), `--detached`, `--seen-nonce`, `--revoked <agent-id>:<retired|compromised>:<revoked-at>`, `--now`. Exit code 2 means a usage or I/O error.
* `sign` also takes `--attach <attestation file>` (repeatable, inline attestations under `-70009`) and `--command-class <class>` (ATEP-R header `-70014`).
* `attest` options: `--subject` (an Agent ID, or a key or bundle file), `--claim` (URI or short name such as `audited`, `fleet-member`, `robotics/peer-motion`), `--data` or `--data-file` (JSON, integers only, `{"$hex": "..."}` for byte strings), `--evidence-file` or `--evidence-hex`, `--evidence-uri`, `--days` (default 90), `--expires-in`, `--expires-at`, `--issued-at`, `--id-hex`, `--allow-long`, `--no-bundle`, `--deterministic`. It refuses more than 400 days, more than 180 days for claims that are not audit-backed unless `--allow-long`, and `audited` or `safety-certified` without evidence. It prints the attestation id (hex) on stdout.
* `srl` (alias `revoke`) options: `--attestation` (attestation file or 32 hex id, repeatable), `--identity` (Agent ID to list as compromised, repeatable), `--prev` (previous SRL: keeps its entries, sequence plus one), `--reason`, `--revoked-at`, `--issued-at`, `--valid-for` (seconds until `next-update`, default 86400), `--sequence`, `--no-bundle`.
* `verify` and `chain` share the trust options `--policy <file>`, `--root <agent-id>` (repeatable, added to the policy's roots), `--srl <file>` (repeatable), `--srl-dir <dir>` (file-backed SRL cache: loaded, re-verified and extended by `--srl`), `--attestation <file>` (repeatable) and `--atep-r`. `verify` evaluates step 9 when any of `--policy`, `--root` or `--atep-r` is given, prints each verified claim with its chain, the checkpoint used and any warnings, and on rejection prints the step and, for attestation failures, the inner cause. `chain -i <attestation>` prints the chain of that attestation's claim to a root; `chain -i <other envelope>` verifies it under the policy and prints the chains of the claims the rules required.
* `-` as a path means stdin or stdout where it makes sense.

### Policy file (JSON)

```json
{
  "roots": ["atep:..."],
  "max_depth": 5,
  "rules": [
    {"claim": "https://atep.dev/claims/operator"},
    {"claim": "audited", "root": "atep:...", "max_age_days": 120}
  ],
  "srl": {"on_stale": "fail-closed", "on_missing": "fail-open"},
  "require_inclusion": false,
  "trusted_logs": ["atep:..."],
  "atep_r": false,
  "require_anchor": []
}
```

Every key is optional and unknown keys are errors. `roots` is the trusted root set (there are no built-in roots). A rule requires the claim on the envelope's signer from an issuer chaining to a root (to `root` if given, which must be in `roots`), with the attestation issued at most `max_age_days` ago; `claim` accepts a URI or a short name. `max_depth` counts the attestations in a chain including the claim attestation (default 5). `srl.on_stale` and `srl.on_missing` are `fail-closed` or `fail-open` (defaults `fail-closed` and `fail-open`); fail-open adds a warning to the result. With `require_inclusion` every attestation in the chain needs a `-70012` inclusion proof against a checkpoint signed by a log in `trusted_logs`. `atep_r` enforces the ATEP-R command class table (encryption, `-70014` header, minimum claims per class, e-stop rule, fail-safe SRL handling) in addition to `rules`. `require_anchor` (spec section 7) is an array of `{"log": <agent id>, "chain": <chain-id>, "max_age_days" | "max_age_hours": n}`; it is parsed and validated, but this build cannot evaluate it, so a policy that contains one fails step 9 with `anchor_not_supported` (fail closed). An empty array or no key changes nothing.

### File formats

* Secret key file: CBOR map `{"atep-secret-key": 1, "ed25519": bstr32, "mldsa65": bstr32, "x25519": bstr32, "mlkem768": bstr64}`. The last two are absent for `--no-enc` identities. Values are seeds: the Ed25519 secret key, the FIPS 204 seed xi, the X25519 scalar, and the FIPS 203 seed d || z. The public bundle is derived from them. Protect this file.
* Public bundle file: the canonical CBOR bundle `[ed25519_key, mldsa65_key, [x25519_key, mlkem768_key]?]`; its SHA-256 is the Agent ID.
* Envelopes: CBOR, tag 98 (signed) or tag 96 (encrypted). See `../vectors/README.md`.

## Library

```rust
use atep_core::{keys::Identity, sign, verify, encrypt, decrypt, Policy, SignParams};
use atep_core::consts::CT_DATA;

let alice = Identity::generate(false)?;
let bob = Identity::generate(true)?;
let params = SignParams::new(b"payload", CT_DATA, nonce16, issued_at);
let signed = sign(&alice, &params)?;
let wire = atep_core::encrypt::encrypt_random(&signed, bob.public())?;
let policy = Policy { recipient: Some(&bob), ..Policy::default() };
let ok = verify(&wire, &policy, now)?;       // Err(Rejection { step, code, detail }) names the failing step
```

Deterministic modes for vectors: `SignMode::Deterministic` (FIPS 204 deterministic ML-DSA, Ed25519 is always deterministic), caller supplied nonce, `Seeds` for key generation, and `EncryptRandomness { x25519_ephemeral, mlkem_m, iv }` for encryption. Secret seeds are zeroized on drop (`Seeds`, `Identity`, `EncryptRandomness`, derived keys).

### Trust (M2)

```rust
use atep_core::{Policy, Rule, TrustPolicy};
use atep_core::attestation::{self, AttestationParams, claims};
use atep_core::srl::{self, MemorySrlCache};

// issue
let p = AttestationParams::new(subject_id, "operator", issued_at, expires_at)?;   // short names expand
let att = attestation::issue(&issuer, &p)?;                                      // checks lifetime tiers and claim rules

// verify with a policy: roots, rules, cached SRLs
let mut cache = MemorySrlCache::new();
srl::ingest(&mut cache, &srl_bytes, &[], now)?;                                  // verifies, schema, sequence rules
let policy = Policy {
    recipient: Some(&bob),
    trust: Some(TrustPolicy { roots: vec![root_id], rules: vec![Rule::new("operator")], ..TrustPolicy::default() }),
    srls: Some(&cache),
    ..Policy::default()
};
let ok = verify(&wire, &policy, now)?;   // ok.claims, ok.checkpoint, ok.warnings
```

`verify` runs all ten steps. Step 9 (`trust.rs`) pools the attestations inline in the envelope (`-70009`, nested ones included) and in `Policy::attestations`, and for each rule validates candidates and walks `issuer-authority` attestations to a root: every attestation is verified as an envelope through steps 1 to 8, schema-validated, lifetime-checked (400 day maximum), looked up in its issuer's SRL (an entry revokes it; stale or missing lists follow `SrlPolicy`) and, if required, checked with an `InclusionCheck`. Depth is bounded and cycles are detected. Step 8 also consults every cached SRL for identity entries (`compromised`). The result lists the verified claims with their chains, the checkpoint used (step 10) and warnings for tolerated fail-open conditions. Rejections name the step; step 9 rejections that wrap a failure of steps 1 to 8 on an attestation carry it in `Rejection::cause`.

Extension points: `srl::SrlCache` (`MemorySrlCache`, `FileSrlCache`), `log::InclusionCheck` (the M3 log client implements it; `log::OfflineInclusion` verifies a proof and checkpoint signature offline, with `merkle_root`, `audit_path` and `verify_inclusion` for RFC 9162 trees).

### ATEP-R

With `TrustPolicy::atep_r` set, `verify` requires encryption and a valid `command-class` header at step 1 and the minimum claims of the class at step 9 (table in `../vectors/README.md`). `atep_r::enforce` returns `Outcome::Honor(verified)` or `Outcome::Ignore(rejection)`: an envelope that cannot be verified is ignored and the robot continues its last safe behavior. Motion, actuation, maintenance and non e-stop safety fail closed on a stale or missing SRL; telemetry, sensor, coordination and e-stop continue with a warning. An e-stop is a `safety` payload that is a CBOR map with `command: "e-stop"` and is accepted from a `fleet-member` with `safety-certified` even if attestation expiry has passed (revocation and signatures are still enforced).

### Provisional identifiers

All private-use values awaiting IANA registration are documented in `atep-core/src/lib.rs` (`consts`): ML-DSA-65 COSE alg -49, ML-KEM-768 alg -70010, the ATEP-1 hybrid KEM recipient alg -70011, header labels -70008 (signer-bundle), -70009 (attestations), -70012 (inclusion-proof), -70013 (KEM ciphertext) and -70014 (command-class), kty 7 (AKP), and the SRL and checkpoint media types. Choices the spec leaves open for M2 (issuer-authority layout, e-stop recognition, Merkle leaf hash and others) are listed in [`../docs/implementation-findings/rust-findings.md`](../docs/implementation-findings/rust-findings.md) entries 18 to 31.

## Test vectors

```
cargo run -p atep-core --bin atep-vectors -- generate ../vectors   # regenerate (pure function of fixed seeds)
cargo run -p atep-core --bin atep-vectors -- check ../vectors      # verify every vector on disk
```

`cargo test` runs the same check against `../vectors`, asserts that regenerating produces exactly the files on disk, and runs the CLI end-to-end tests (M1 round trip, and issue, chain, verify, revoke for M2). `../vectors/crosscheck.py` re-checks parts of the vectors with an independent Python implementation.

## `retired` and `successor` (Draft 04)

Implemented as specified in spec section 7 ("Retirement and succession"), with 60 vectors (`../vectors/RETIRED-SUCCESSOR-NOTES.md`):

* **Step 8** (`atep_core::verify`): a valid retirement in the verifier's local attestation store (`Policy::attestations`) rejects every envelope of the identity issued at or after the retirement, unless the envelope is itself a `retired` attestation of the identity; it combines with SRL identity entries and direct revocations as a union (earliest instant wins). Candidate validation passes the store to the step 8 of every attestation it verifies.
* **Layouts** (`Attestation::validate_claim_data`): `retired` has `subject` equal to `issuer`, `successor` a different subject, and `data.reason`, when present, is text. The log refuses violations as `schema_invalid` (`atep_core::admission`, which `atep-log` runs with its own claim rules; the logged `retired` attestations are the log's store for step 8).
* **`follow_succession`** (trust policy, default false): after a rule failed with `claim_missing`, one hop of succession (`trust.rs`, `eval_succession`); the chain through succession is one attestation deeper, and a failed attempt reports `claim_missing` as before.
* **SRL loading** (`atep_core::srl::load`, `ingest_in`, `LoadContext`): steps 1 to 8 run in the verifier's own context (cached lists, direct revocations, local store), so a retired or revoked issuer cannot publish a list; the same bytes loaded again are no change.
* **Monitor**: alert `successor_chain` (`atep_core::succession::chain_links`).
