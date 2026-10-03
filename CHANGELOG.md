# Changelog

All notable changes to the packages of this repository are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning policy: [`docs/VERSIONING.md`](docs/VERSIONING.md). The specification has its own revision history (Appendix A of the spec); the vectors are versioned with the spec draft.

## [Unreleased]

## [0.1.0-alpha.1] - not yet released

First alpha. Experimental: no independent security audit, the wire format may change in any 0.x release (private-use COSE labels, unregistered media types) and the post-quantum crates it builds on (`ml-dsa`, `ml-kem`) are young. Versions: crates.io and npm `0.1.0-alpha.1`, PyPI `0.1.0a1`.

### Scope

* Implements ATEP Draft 07 (the first public draft), suite `ATEP-1`: quantum-safe hybrid signatures and key exchange (Ed25519 with ML-DSA-65, X25519 with ML-KEM-768, both halves must hold) and offline identification and verification against cached keys, revocation lists and log checkpoints.
* 436 test vectors in 28 categories. Rust passes all 436; `@atep/core` and the Python implementation pass the 431 that do not need a stateful log or monitor and report the other 5 as skipped by name.
* Three implementations: Rust (`atep-core`), JavaScript (`@atep/core`, the Rust core compiled to WebAssembly) and an independent pure Python implementation (`atep_py`).

### Added

* crates.io: `atep-core` (library, plus the `atep-vectors` checker binary), `atep-cli` (installs the `atep` binary: keygen, sign, encrypt, verify) and `atep` (re-exports `atep-core`). Minimum supported Rust version 1.89.
* npm: `@atep/core` (ESM, TypeScript types, WebAssembly; Node, Bun, Deno and browsers) and `@atep/mcp` (read-only MCP server, binary `atep-mcp`), published under the dist-tag `alpha`.
* PyPI: `atep` (import package `atep_py`, Python 3.8 or later, standard library only).
* A release workflow with trusted publishing, and a dry-run mode (`docs/RELEASING.md`).
* An npm workspace at the repository root (`js`, `mcp`, `examples`, `examples/mqtt`) with one lockfile, so that `@atep/mcp` and the examples are tested against the local `@atep/core` build.

### Not included

* `atep-log` (transparency log and `atep-logd` server), `atep-monitor` and `atep-wasm` are not published (`publish = false`); build them from the repository.
* The examples, the demo and the site are not packages.

### Known limitations

* No independent audit; one steward (AIRAD LABS) and no implementation outside the project yet.
* The wire format may change: COSE labels are private-use values, media types and the CBOR tag choice are unregistered, no Internet-Draft has been submitted.
* The Python implementation is slow (pure Python ML-DSA and ML-KEM; about 30 seconds for the vectors), has no log or monitor, and fails closed on `require_anchor` without evaluating it.
* The reference log speaks plain HTTP, keeps keys in files and has no HSM support. No chain adapter exists for optional anchoring.
* `@atep/core` is tested under Node only; Bun, Deno and browser use are not verified. The ROS 2 example has not been run on a ROS 2 install.
* See section 13 of the specification for the open items.

[Unreleased]: https://github.com/atepdev/atep/compare/v0.1.0-alpha.1...HEAD
[0.1.0-alpha.1]: https://github.com/atepdev/atep/releases/tag/v0.1.0-alpha.1
