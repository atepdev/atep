# @atep/core

ATEP is a quantum-safe trust layer for robots and AI agents. Every signature and key exchange pairs a classical algorithm with a finalized NIST post-quantum standard (Ed25519 with ML-DSA-65, X25519 with ML-KEM-768), and both halves must hold. A robot or agent can identify and verify another offline, with no internet connection, registry or central server: an identity is a hash of public keys, and everything else is checked against cached keys, revocation lists and log checkpoints.

> **Experimental alpha. Do not rely on this to protect anything of value.** There has been no independent security audit. The wire format may change between releases (the COSE labels are private-use values and the media types are unregistered), and the post-quantum crates underneath are young. "Quantum-safe" means finalized NIST algorithms (FIPS 203 and FIPS 204) in a hybrid construction; it does not mean audited or proven.

`@atep/core` is the ATEP reference core (Draft 08, `ATEP-1` suite, including `retired`, `successor`, anchors and domain binding) for JavaScript: the Rust
`atep-core` crate compiled to WebAssembly, with a TypeScript API. One ESM
package for Node, Bun, Deno and browsers, no framework and no runtime
dependencies.

```
npm install @atep/core@alpha
```

Pre-releases are published under the `alpha` dist-tag, so a plain `npm install @atep/core` does not pick one until a stable release exists. Node 18 or later.

A complete example (generate keys, sign, encrypt, verify) is under "Usage" below.

Everything cryptographic and every protocol rule comes from the Rust crate
(RustCrypto: `ed25519-dalek`, `ml-dsa`, `x25519-dalek`, `ml-kem`, `aes-gcm`,
`hkdf`, `sha2`). The wrapper crate `rust/atep-wasm` only converts between JS
values and the core types.

## Build from the repository

The published package ships the built `dist/`. To build from a repository checkout (development, or to audit the build) use the steps below.
`js/dist/` is gitignored, so a fresh clone always needs `npm run build` before
the package can be imported.

```
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.129 --locked --no-default-features
npm ci               # in the repository root: npm workspaces (js, mcp, examples), one lockfile
cd js
npm run build        # cargo (wasm32, release) -> wasm-bindgen -> tsc -> dist/
npm test             # all vectors plus round trip tests, under Node
```

The wasm-bindgen CLI version must equal the `wasm-bindgen` crate version in
`rust/Cargo.lock` (0.2.129 at the time of writing). `npm run build` checks the
target and the CLI first, reads the required version from `rust/Cargo.lock`,
and prints the exact install commands if something is missing or mismatched.
`--no-default-features` is what CI uses: the default feature set pulls in
`ring`, which needs a C compiler, so without that flag the install fails on
machines that have none. The CLI is looked up on `PATH` (or `WASM_BINDGEN=/path`).
If `wasm-opt` is on `PATH` it is applied (saves about 6 percent). On a machine
without a C compiler also point `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER`
at a linker for the build scripts; the wasm32 target itself needs no C compiler
because all dependencies are pure Rust.

The build remaps the cargo, rustup and workspace paths (`--remap-path-prefix`),
turns debug info off, and drops the wasm name and producers sections, so the
binary contains no absolute local paths. `scripts/ci/no-local-paths.sh` checks this.

Output in `dist/`: `index.js`, `index.d.ts` (generated from `src/index.ts`) and
`wasm/` (`atep_wasm.js`, `atep_wasm_bg.wasm`, typings).

## Size

| File | Bytes |
| --- | --- |
| `dist/wasm/atep_wasm_bg.wasm` (release, LTO, opt-level 3, no wasm-opt) | 758,345 (741 KiB) |
| same, gzip -9 | 286,802 (280 KiB) |
| `wasm-opt -Oz` (optional) | not measured for this build (measured once, on an earlier 657,927 byte build: 613,961) |

The Draft 05 exports (log admission rules, domain binding, anchors) grew the binary by 85,964 bytes
over the Draft 04 build (673,191).

## Usage

```js
import { init, keygen, sign, encrypt, verify, hexToBytes } from "@atep/core";

await init();                       // loads the wasm once (Node: from disk, browser: fetch)

const alice = keygen(false);        // signing keys only
const bob   = keygen(true);         // plus X25519 + ML-KEM-768 to receive encrypted envelopes

const now = Math.floor(Date.now() / 1000);
const signed = sign(alice, new TextEncoder().encode("hello"), { issuedAt: now, expiresAt: now + 600 });
const sealed = encrypt(signed, bob.publicBundle);        // tag 96

const r = verify(sealed, {}, { recipient: bob, now });   // spec section 10, steps 1 to 10
if (r.ok) console.log(r.signer, new TextDecoder().decode(hexToBytes(r.payload_hex)));
else      console.log(`rejected at step ${r.step}: ${r.error}`);
```

A rejection is a returned value, `{ok: false, step, error, cause?}`. Exceptions
are for malformed arguments (bad hex, wrong seed length, bad JSON) and signing
or encryption failures.

Note the protocol rule that a data envelope (`application/atep+cbor`) must be
encrypted: a bare signed data envelope is refused at step 1. Trust documents
(attestations, SRLs, checkpoints) may travel signed only.

### Verification with a trust policy, attestations and SRLs

```js
const root = keygen(false), agent = keygen(false);
const att = root.issueAttestation({
  subject: agent.agentId, claim: "operator-of",
  issuedAt: now - 10, expiresAt: now + 86400, data: { operator: "Example Corp" },
});
const msg = encrypt(withAttestations(agent.sign(payload, { issuedAt: now }), [att]), bob.publicBundle);

const policy = {
  trust: { roots: [root.agentId], rules: [{ claim: "operator-of" }] },  // same format as the Rust CLI policy file
  known_bundles: [root.publicBundle],
  srls: [],                 // signed revocation lists (hex or bytes)
  attestations: [],         // extra attestations known out of band
  seen_nonces: [],          // replay set
};
const result = bob.verify(msg, policy, now);   // result.claims lists each satisfied rule with its chain

const srl = root.createSrl({ sequence: 1, issuedAt: now, nextUpdate: now + 3600,
  revoked: [{ attestationId: hexToBytes(result.claims[0].chain[0].id), reason: "withdrawn", revokedAt: now }] });
bob.verify(msg, { ...policy, srls: [srl] }, now);   // {ok: false, step: 9, ...}
```

`VerifyPolicy` is the exact `policy` object of the test vectors (`vectors/README.md`).

### Retirement and succession (Draft 04)

* `policy.attestations` is the local attestation store. Step 8 reads valid `retired`
  attestations from it, so an identity that retired is rejected (`8/signer_revoked`) for
  anything issued at or after its retirement, including attestations checked at step 9.
* `policy.trust.follow_succession` (boolean, default false): when a rule fails with
  `claim_missing`, a one-hop `successor` attestation is followed. Applies to ATEP-R rules too.
* `policy.revocations` and `policy.srls` work as before; `srls` are loaded in list order in the
  verifier's own context (earlier lists, `revocations`, `attestations`).
* `verifySrl(srl, {now, onStale, cached, context})`: `context` is
  `{known_bundles?, attestations?, revocations?, max_skew_secs?}`, the context in which `cached`
  and then `srl` are loaded (steps 1 to 8). A list signed by a retired identity at or after its
  retirement is rejected `8/signer_revoked`. Without `context` nothing is retired or revoked.
* Not provided: a stateful log (the `log-admission` vectors) and the monitor `successor_chain` alert
  (this package has no log or monitor). `checkAdmission` applies the admission rules to one submission
  (below), which is what the `registry-endpoint` vectors need.

### Anchors, chain ids, `require_anchor`, registry endpoints, domain binding (Draft 05)

All of these are pure functions of their input (no network, no clock unless `now` is passed) and return
the result shapes of `vectors/ANCHOR-DISCOVERY-NOTES.md`.

```js
chainIdKind("x-acme-ledger");                       // {ok: true, kind: "extension"}
parseAnchorRecord(payload);                         // {ok, record} or {ok: false, error: "anchor_record_invalid"}
encodeAnchorRecord(record);                         // deterministic CBOR, no block-height key when null
checkpointHash(checkpointEnvelope, [logId], now);   // verifyCheckpoint plus checkpoint_hash, payload_hex
checkPublishedAnchor(anchorEnvelope, logId, checkpointHashHex, now);   // {ok, log, record} or step 1 to 9 rejection
parseRequireAnchor(policy);                         // {ok, require_anchor} or {ok: false, error: "policy_invalid"}
checkAdmission(attestation, { now, log, maxEnvelopeBytes, logged });   // {ok, document} or {ok: false, refusal, ...}
checkDomainBinding(fixture);                        // {well_known, dns, outcome, queried}, fetcher answers come from the fixture
```

`verify` already knows the `application/atep-anchor+cbor` media type and the policy member `require_anchor`
(step 9 refuses with `anchor_not_supported` while a rule exists; a malformed rule makes `verify` throw,
`parseRequireAnchor` reports it as `policy_invalid`). `checkDomainBinding` takes the answers of a fake
fetcher; wiring it to real HTTPS and DNS is the caller's job.

### API summary

| Function | Purpose |
| --- | --- |
| `init(source?)`, `initSync(bytes)` | load the wasm; required once |
| `keygen(withEncryption)`, `Identity.generate`, `Identity.fromSeeds`, `fromSeedsHex`, `fromSecret` | create identities |
| `identity.agentId`, `.did`, `.publicBundle`, `.agentIdBytes`, `.hasEncryption`, `.exportSecret()`, `.free()` | identity access |
| `agentId(bundle)`, `parseAgentId(text)` | Agent ID derivation and parsing (`atep:` and `did:atep:`) |
| `sign(identity, payload, opts)` / `identity.sign` | hybrid Ed25519 + ML-DSA-65 signature, tag 98 |
| `encrypt(signedEnvelope, recipientBundle)` | hybrid X25519 + ML-KEM-768 with AES-256-GCM, tag 96 |
| `decrypt(identity, data)` | returns the inner signed envelope (unverified) |
| `verify(data, policy, {now, recipient})` / `identity.verify` | full verification, policy, chains, SRLs, inclusion proofs, ATEP-R |
| `view(data)` | JSON debug rendering of any ATEP CBOR object |
| `identity.issueAttestation(opts)` | issue an attestation |
| `identity.createSrl(opts)`, `verifySrl(srl, {now, onStale, cached, context})` | revocation lists |
| `identity.createCheckpoint(opts)`, `verifyCheckpoint`, `verifyInclusion`, `checkConsistency`, `checkSplitView` | transparency log documents |
| `merkleRoot`, `auditPath`, `submittedFormOf`, `withInclusionProof`, `withAttestations` | log and envelope helpers |
| `chainIdKind`, `parseAnchorRecord`, `encodeAnchorRecord`, `checkpointHash`, `checkPublishedAnchor` | chain ids, anchor records, checkpoint hash, published anchors |
| `parseRequireAnchor`, `checkAdmission`, `checkDomainBinding` | `require_anchor` parse, log admission rules for one submission, domain binding over a fixture |
| `sha256`, `hexToBytes`, `bytesToHex` | utilities |

Types are in `dist/index.d.ts`.

### Runtimes

What was run, on one Linux development machine (Ubuntu 20.04 under WSL) on 3 October 2026, against the built `dist/` with the same vector checks and the roundtrip tests:

| Runtime | How | Result |
| --- | --- | --- |
| Node 25 | `npm test` | 442 tests: 437 pass, 5 skipped by name (the 4 `log-admission` and 1 `monitor` vectors) |
| Deno 2.9.7 | `deno test -A test/` | all vector checks (432 pass, 5 skipped by name) and the 5 roundtrip tests pass |
| Bun 1.4.2 | `bun test test/` | 442 tests: 437 pass, 5 skipped by name, 0 fail |
| Chromium 131 (headless shell, Playwright) | `node scripts/browser-vectors.mjs` (needs `playwright-core`, see the header of the script) | the vector checks run in the page: 432 pass, 5 skipped by name, 0 fail |

These runs were made on the 437 vectors of that date. The suite now has 446; only Node was re-run on it (451 tests: 446 pass, 5 skipped by name).

Notes:

* Node: 18 or later is the intended range, and only Node 25 was run here. `init()` reads the wasm next to `index.js`.
* Browsers: `init()` fetches `new URL("./wasm/atep_wasm_bg.wasm", import.meta.url)`; serve `.wasm` as `application/wasm`. Or pass your own source: `await init(fetch("/path/atep.wasm"))`, a `URL`, or bytes. The fetch and streaming-instantiate path ran in the Chromium run above and in the hosted demo. Not run: Firefox, Safari, mobile browsers, or any other version of the runtimes above. The plain-JS page `examples/smoke.html` (`npm run smoke`) was not opened by hand; the Chromium run uses the same `init()` path.
* Bun and Deno: the package uses only standard ESM, `WebAssembly`, `fetch`, `crypto.getRandomValues` (through wasm-bindgen) and `node:fs/promises`.
* Not run anywhere: constrained devices, or any embedded or flight hardware.
* Bundlers: the wasm is referenced via `new URL(..., import.meta.url)`; the export `@atep/core/atep_core_bg.wasm` points at the binary.

## Secrets and their limits

* An `Identity` keeps its seeds only inside wasm linear memory. `atep-core`
  zeroizes them (`ZeroizeOnDrop`) when the object is freed: call `identity.free()`
  (or `using id = ...`). If you forget, they stay in wasm memory until the
  JS garbage collector finalizes the object.
* Seeds you pass in (`fromSeeds`, `fromSecret`) are zeroized on the wasm side
  after use, but the Uint8Array you passed is yours: `fill(0)` it.
* `exportSecret()` copies secret material to a JS Uint8Array, which is
  garbage collected memory. Only use it for persistence, wipe the array after.
* Signing keys are not held in JS strings or objects, but the guarantees stop
  at the platform: JS engines may copy or retain buffers (for example in
  `TextEncoder` or structured clones), wasm memory never shrinks and is not
  locked, swap and core dumps can capture it, and other code in the same
  realm can read the module's memory. This is an in-process software key, not
  an HSM.
* Passing `recipient_seeds` inside the policy JSON puts seed hex into JS
  strings; pass `recipient: identity` instead.
* `encryptDeterministic` takes explicit randomness for test vectors only.
* Randomness comes from `crypto.getRandomValues` (the `getrandom` crate with its
  `wasm_js` backend). The module has no clock: pass `now` explicitly or let the
  wrapper default to `Date.now()`.
* Verification is not constant time in the places the Rust crate is not; see the
  crates' documentation.

## Timings

Node 25 on the development machine (WSL2), average over 50 to 100 calls after warm-up, 256 byte payload:
`node scripts/bench.mjs`.

| Operation | Time |
| --- | --- |
| `init()` (compile and instantiate) | about 5 ms |
| `keygen(true)` | 1.7 ms |
| `sign` (Ed25519 + ML-DSA-65) | 4.5 ms |
| `encrypt` (X25519 + ML-KEM-768 + AES-GCM) | 0.64 ms |
| `verify`, signed trust document, steps 1 to 10 | 0.91 ms |
| `verify`, encrypted envelope (decrypt, then steps 1 to 10) | 1.4 ms |
| `verify`, encrypted, with one attestation chain and trust policy | 2.6 ms |

## Tests

`npm test` (node:test) runs, under Node, through the built package:

* `test/vectors.test.mjs`: every vector listed in `../vectors/manifest.json`: **441 passed + 5 skipped = 446**.
  The first 200 (identity, signing, encryption, verify-positive/negative, attestation, chain-positive/negative,
  srl, log, atep-r-positive/negative, retired-positive/negative, successor-positive/negative, srl-context,
  log-admission, monitor) and the 236 of Draft 05: checkpoint-hash 9, anchor-record 36, chain-id 30,
  anchor-envelope 13, anchor-media-type 3, require-anchor 27, anchor-not-supported 9, registry-endpoint 26,
  domain-binding 83. The 5 skipped are named and counted in the summary: `log-admission` (4) and `monitor` (1),
  because they need a stateful log or a monitor, which this package does not have. Each vector is checked for
  CBOR hash, JSON view equality with the vector's `.json` (a vector whose `.json` says `not_strict_cbor` has no
  view, and the runner only accepts a failing view for those), and by category: exact bytes for identity,
  signing, encryption and attestation (and for anchor records, decoded and re-encoded); the full expected JSON
  result for every other category. It is the same set of checks as `atep-vectors check` in `rust/`.
* `test/roundtrip.test.mjs`: two identities exchange an encrypted envelope, tampering, replay and wrong recipient,
  detached payloads, secret export and import, attestation and trust policy, SRL revocation, checkpoint and inclusion proof.

## Layout

```
js/
  package.json  tsconfig.json
  src/index.ts           TypeScript API (src/wasm/ is generated)
  scripts/build.mjs      cargo -> wasm-bindgen -> tsc
  scripts/bench.mjs      timings
  scripts/serve.mjs      static server for the smoke page
  scripts/browser-vectors.mjs  the vector checks in headless Chromium (needs playwright-core; not part of CI)
  examples/smoke.html    browser smoke page, plain JS
  test/                  node:test suites
rust/atep-wasm/          the wasm-bindgen wrapper crate (workspace member)
```
