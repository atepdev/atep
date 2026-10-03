<p align="center"><img src="site/atep.dev/assets/atep-wordmark.jpg" alt="ATEP" width="420"></p>

# ATEP: Autonomy Trust Envelope Protocol

ATEP is a quantum-safe trust layer for robots and AI agents. Every signature and key exchange pairs a classical algorithm with a finalized NIST post-quantum standard (Ed25519 with ML-DSA-65, X25519 with ML-KEM-768), and both halves must hold. A robot or agent can identify and verify another offline, with no internet connection, registry or central server, because an identity is a hash of public keys and everything else is checked against cached keys, revocation lists and log checkpoints.

"Quantum-safe" here means the algorithms are the finalized NIST standards (FIPS 203 and FIPS 204) in a hybrid construction. It does not mean audited: the reference code has had no independent security audit, and the post-quantum libraries it uses are young. ATEP rides on any carrier (MCP, A2A, MQTT, ROS 2, HTTP, files). It is a working draft, not an Internet-Draft or a standard.

* In practice, in plain language: https://atep.dev/in-practice.html (what ATEP changes for robot fleets and AI agents, and what it does not do)
* Specification: [`spec/ATEP-Specification-Draft-08.md`](spec/ATEP-Specification-Draft-08.md) (Draft 08, the second public draft; Draft 07, the first, stays in `spec/` unchanged)
* Test vectors: [`vectors/`](vectors/README.md), 443 vectors in 28 categories
* Live simulator: https://atep.dev/demo/ (runs in your browser, real cryptography with simulated robots), four simulated units exchanging real encrypted envelopes, one revoked mid-run, with certified members verifying each other directly while the fleet controller is offline. Source and notes: [`demo/`](demo/README.md). To run it on your own machine instead: `node demo/serve.mjs` (Node 18 or later, no install, then open http://127.0.0.1:8088/)
* Site: https://atep.dev (the site sources are in `site/`)

## Install (experimental alpha)

ATEP is quantum-safe (hybrid Ed25519 + ML-DSA-65 and X25519 + ML-KEM-768) and lets a robot or agent identify and verify another offline. The 0.1 releases are experimental: no independent audit, the wire format may change, and the post-quantum crates are young.

| Ecosystem | Install |
| --- | --- |
| Rust command line (`atep` binary) | `cargo install atep-cli --version 0.1.0-alpha.3` |
| Rust library | `cargo add atep-core@0.1.0-alpha.3` (or `atep`, the same library under a shorter name) |
| JavaScript and TypeScript | `npm install @atep/core@alpha` |
| MCP server (read-only) | `npx -y @atep/mcp@alpha` |
| Python | `pip install --pre atep` (import `atep_py`; the post-quantum code is pure Python and slow) |

The earlier 0.0.1 placeholders contain no code; use the versions above. The log and monitor crates are not published; build them from this repository (see "Try it in 60 seconds" below).

How releases are made: [`docs/RELEASING.md`](docs/RELEASING.md). Version policy: [`docs/VERSIONING.md`](docs/VERSIONING.md). Changes: [`CHANGELOG.md`](CHANGELOG.md).

## Try it in 60 seconds

Run all commands from the repository root. The examples below verify the same vector, `vectors/verify-positive/signed-trust-doc-inline-bundle.cbor`, at the reference time `now = 1800000000` that every vector uses.

### The live simulator (Node 18 or later, no build, no install)

```
node demo/serve.mjs          # then open http://127.0.0.1:8088/
node demo/selftest.mjs       # headless check, 80 assertions
```

Four simulated units exchange real ATEP-R envelopes; the operator revokes one, and its next command is refused at a named step. Two certified members keep verifying each other when you take the fleet controller offline, because they check each other against certificates saved earlier. The map, movement and clock are simulated; the envelopes, keys and verification are real. See [`demo/README.md`](demo/README.md).

### Python (standard library only, Python 3.8 or later)

```
cd python
python3 -c "
import json
from atep_py.verify import verify_json
n = '../vectors/verify-positive/signed-trust-doc-inline-bundle'
v = json.load(open(n + '.expected.json'))
print(verify_json(open(n + '.cbor', 'rb').read(), v['inputs']['policy']))"
python3 -m atep_py.vectors check ../vectors     # 438 pass, 5 skipped by name; about 30 seconds
```

The first command prints a dictionary starting `{'ok': True, 'signer': 'atep:...'`.

### Rust command line

```
cd rust
cargo build --release -p atep-cli        # needs a Rust toolchain and a C compiler or linker
./target/release/atep verify -i ../vectors/verify-positive/signed-trust-doc-inline-bundle.cbor --now 1800000000
./target/release/atep verify -i ../vectors/verify-negative/bad-eddsa-signature.cbor --now 1800000000
```

The first prints `OK`, the signer, content type and times, exit code 0. The second prints `REJECTED at step 4 (eddsa_signature_invalid): signature does not verify` and exits with 1. Every rejection names the step of the ten-step verification algorithm and a stable error code. Create your own identities with `atep keygen`, `atep sign`, `atep encrypt` and `atep verify` (see [`rust/README.md`](rust/README.md)).

### JavaScript (`@atep/core`, built from this repository)

The JavaScript package is the Rust core compiled to WebAssembly. A fresh clone has no `js/dist`, so it must be built, which needs the `wasm32-unknown-unknown` target and `wasm-bindgen-cli` 0.2.129 (exact commands and the C-compiler note are in [`js/README.md`](js/README.md)):

```
npm ci && npm run build -w js && npm test -w js     # npm workspaces: run in the repository root
```

## How it compares

ATEP is a layer that composes with these, not a replacement for any of them. The table gives the authors' reading of each project's public documentation; corrections are welcome (open a specification issue).

| Project | What it is for | How ATEP relates |
| --- | --- | --- |
| COSE ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052)) | A signing and encryption format for CBOR data | ATEP envelopes are COSE objects. ATEP adds the identity model, hybrid post-quantum algorithms (using private-use algorithm identifiers until registered), attestations, revocation and a log. |
| [SPIFFE](https://spiffe.io/) and SPIRE | Workload identity within and across trust domains, with X.509 or JWT identities | Solves workload identity, with federation between trust domains. ATEP identities are derived from keys, and certifier claims are separate signed attestations that verify offline. The two can coexist. |
| DIDs and Verifiable Credentials (W3C) | Decentralized identifiers and signed claims | Similar in spirit. ATEP fixes one concrete envelope, one cryptographic suite and a verification algorithm with test vectors, and defines a `did:atep:` alias for Agent IDs so DID tooling can refer to them. |
| [C2PA](https://c2pa.org/) | Provenance for media content (who made or edited an asset) | A different problem: C2PA is about content provenance; ATEP is about identity, authority and certification of the sender of a message or command. |
| MCP and A2A | How agents call tools and talk to each other | Carriers. ATEP does not replace them; it can be carried inside them so the receiving agent can verify who sent a message and which certifications the sender holds. See `examples/mcp` and `examples/a2a`. |

## Status

| Part | Where | State |
| --- | --- | --- |
| Rust core and CLI | `rust/atep-core`, `rust/atep-cli` | Passes all 443 vectors; 147 tests in the workspace. Keygen, sign, encrypt, verify (ten steps), attestations, revocation, ATEP-R command classes, retirement and succession, anchor and domain-binding checks. |
| Transparency log and monitor | `rust/atep-log`, `rust/atep-monitor` | Merkle log, checkpoints, proofs, gossip, HTTP API, monitor; acceptance-tested against injected mis-issuance and forked history. |
| npm package `@atep/core` | `js/` | Rust compiled to WASM with a TypeScript API; 448 tests, passing 438 of 443 vectors (5 need a log or monitor and are skipped by name). |
| Python implementation | `python/` | Standard library only, written from the spec and vectors without the Rust code; 477 tests, 438 of 443 vectors (5 skipped by name). |
| MCP server | `mcp/` | Read-only tools: verify, inspect, log lookups; 54 tests. |
| Carrier examples | `examples/` | MCP, A2A, files, HTTP (25 tests), MQTT (5 tests, in-process broker), ROS 2 (not run on a ROS 2 install). |
| Live simulator | `demo/` | Four simulated units, real envelopes, a controller-offline mode; 80 self-test assertions. |

Honest limits:

* No independent security audit. The RustCrypto post-quantum crates (`ml-dsa`, `ml-kem`) are young.
* One steward (AIRAD LABS): no implementation outside the project exists yet. The Python implementation is independent of the Rust code, not of the project.
* No Internet-Draft, no IANA registration; media types, CBOR tags and COSE labels are provisional.
* The Python implementation is slow, has no log or monitor, and fails closed on `require_anchor` without evaluating it. The reference log speaks plain HTTP, keeps keys in files and has no HSM support. No chain adapter exists for optional anchoring.
* Measured figures (for example verification in about a millisecond) come from one development machine (WSL2 Linux, Rust 1.98, Node 25, Python 3.8; CI also runs Python 3.12) and are not a guarantee elsewhere.
* No certification program operates and there are no customers.

## Repository layout

```
spec/                       the specification (Draft 08; Draft 07 is kept) and CDDL schemas (spec/schemas/)
vectors/                    443 test vectors: the executable form of the spec
docs/                       index, and implementation findings (docs/implementation-findings/)
rust/                       atep-core, atep-cli, atep-log (atep-logd), atep-monitor, atep-wasm
js/                         @atep/core (WASM + TypeScript)
python/                     atep_py, the independent implementation
mcp/                        @atep/mcp read-only MCP server
examples/                   mcp, a2a, files, http, mqtt, ros2, transport, common
demo/                       ATEP-R fleet demo (plain HTML and ES modules)
site/                       static site for atep.dev
scripts/ci/                 repository checks run in CI
```

## The specification and the vectors

The specification defines an identity model (Agent IDs), a COSE/CBOR envelope format, an attestation schema for third-party claims, signed revocation lists, a transparency log, a ten-step verification algorithm and a robotics profile (ATEP-R). The CDDL schemas in `spec/schemas/` are validated against all 443 vectors in CI.

The test vectors are authoritative: every vector is three files (`<name>.cbor` with the exact bytes, `<name>.json` as a debug view, and `<name>.expected.json` with inputs, policy and the required result including step and error code). An implementation is conformant when it reproduces every byte and every result that applies to it; where the spec text and a vector disagree, the vector wins and the text is amended. Format: [`vectors/README.md`](vectors/README.md). Ambiguities found while implementing, and how the spec resolved them: [`docs/implementation-findings/`](docs/implementation-findings/README.md). Draft numbers below 07 in those files name internal working drafts (Appendix A of the spec).

## Design commitments against misuse (spec section 16)

These are normative for the core specification and for any registry operated under the ATEP name.

1. Subjects are agents and organizations, not individuals. No claim type about a natural person in the core vocabulary.
2. No global score. No aggregate rating, ranking or trust number; claims are specific, independently issued and expire.
3. No mandatory root. Verifiers choose their roots, may run several, and may drop any issuer at any time.
4. Reputation stays out of the core. No mechanism to publish, exchange or aggregate track records across contexts.
5. Transparency watches issuers, not subjects. The log is not a surveillance feed; agent-to-agent envelopes are never submitted to it.
6. Minimal disclosure. Claims carry what a verifier needs; detail lives behind evidence hashes; Agent IDs are pseudonymous until bound.
7. Right to retire. Any identity can retire itself by a self-signed claim no issuer can block.

A registry that violates these forfeits use of the ATEP name and root. No envelope, attestation or key may require a blockchain, a token or an on-chain lookup.

## AI assistance

Much of the specification text and the code in this repository was written with AI assistance (Claude, by Anthropic), directed by the project owner. The check on that work is mechanical: shared test vectors that three implementations must reproduce, regeneration of the vectors from fixed seeds, and continuous integration. That is evidence of consistency, not of security. There has been no independent security audit; do not rely on this code to protect anything of value without your own review.

## Contributing and security

* Contributions: see [`CONTRIBUTING.md`](CONTRIBUTING.md) (how to build and test, the vector rule, how spec changes are proposed). Participation is covered by the [Code of Conduct](CODE_OF_CONDUCT.md).
* Vulnerabilities: do not open a public issue. Use GitHub private vulnerability reporting or email nathan@airadlabs.com, as described in [`SECURITY.md`](SECURITY.md).
* AI coding agents working in the repository: [`CLAUDE.md`](CLAUDE.md).

## License

Code: Apache-2.0 ([`LICENSE`](LICENSE)). Specification text and CDDL: CC BY 4.0 ([`LICENSE-SPEC.md`](LICENSE-SPEC.md)). Third-party software linked into the builds: [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md). Copyright AIRAD LABS, which stewards the project.

The ATEP name and logo are not covered by the Apache-2.0 or CC BY 4.0 licenses; use them to refer to the protocol and do not suggest endorsement.

MCP, A2A, ROS, SPIFFE, C2PA, COSE and other names are trademarks or names of their respective owners, used only to identify what ATEP works with; no affiliation or endorsement is implied.
