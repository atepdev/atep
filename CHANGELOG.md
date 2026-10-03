# Changelog

All notable changes to the packages of this repository are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning policy: [`docs/VERSIONING.md`](docs/VERSIONING.md). The specification has its own revision history (Appendix A of the spec); the vectors are versioned with the spec draft.

## [Unreleased]

### Added

* Nine test vectors, the last nine of the manifest (446 vectors in 28 categories; the 437 earlier ones are unchanged), closing cases of spec section 12 that had none: `srl-context/rt32a-first-list-naming-its-issuer-from-before-its-issue`, `srl-context/rt32b-newer-list-after-reload`, `retired-negative/rt34a-earliest-retirement-decides-after`, `retired-positive/rt34b-earliest-retirement-decides-before`, `retired-negative/rt35-other-store-entries-do-not-stop-the-scan`, `successor-positive/su27-root-claim-inherited-at-max-depth-1` and, for known gaps 9 and 15, `chain-positive/depth-exactly-at-max-depth`, `chain-positive/direct-claim-at-max-depth-1` and `chain-positive/attestation-nonce-in-seen-nonces`. Rust passes all 446; `@atep/core` and the independent Python implementation pass 441 and skip 5 by name, with no code change and no new finding. The published Drafts 07 and 08 still list RT32, RT34, RT35 and SU27 (and parts of rows 9 and 15) as gaps; Draft 09 must say they are closed.

### Tested

* `@atep/core` was run against the vector suite under Deno 2.9.7, Bun 1.4.2 and headless Chromium 131 as well as Node 25 (432 pass and 5 skipped by name in each); `js/README.md` lists exactly what ran and what did not. New: `js/scripts/browser-vectors.mjs`, the browser runner (not part of `npm test` or CI, no new dependency).

## [0.1.0-alpha.3] - 2026-10-03

Implements Draft 08 of the specification (`spec/ATEP-Specification-Draft-08.md`, the second public draft; Draft 07 is unchanged). `0.1.0-alpha.1` and `0.1.0-alpha.2` implement Draft 07 and do not contain these changes. Section 13 of Draft 08 was written before this release and still says that no release has the Draft 08 rule; a published draft is not edited, so the next draft corrects it.

### Changed

* Step 9 of the verification algorithm: when every alternative of a requirement fails and any of them failed with `srl_stale` or `srl_unavailable`, that error is reported (from the first such alternative in listed order) instead of the error of the alternative that satisfied the most rules. In practice an ATEP-R `motion` command from a member holding a `peer-motion`, checked against a stale revocation list, is now rejected with `srl_stale` instead of `claim_missing`. What is accepted or rejected does not change, only which error is reported for a rejection (Rust finding 57, decision 83). Rust, `@atep/core` and the Python implementation all follow.

### Added

* One test vector, `atep-r-negative/motion-member-peer-motion-stale-srl`, the last of the manifest: 437 vectors in 28 categories. The 436 earlier vectors are unchanged. `@atep/core` and the Python implementation run 432 of 437 and skip the same 5 by name.

### Fixed

* The demo and its notes expected `claim_missing` for the peer motion probe under a stale list; they now expect `srl_stale`.

## [0.1.0-alpha.2] - 2026-10-03

The first alpha on npm. The code is identical to 0.1.0-alpha.1; this release exists because the alpha.1 release run could not publish to npm.

### Fixed

* Release workflow: the npm publish step passed the tarball as `tarballs/atep-core-<version>.tgz`. A relative path of that two-segment shape is read by npm as GitHub shorthand (`owner/repo`), so npm tried to reach `ssh://git@github.com/tarballs/...` and failed with exit code 128 before uploading anything. Both the dry run and the publish job now call one script, `scripts/release/npm-publish.sh`, which passes absolute paths, so the two cannot differ again.

### Notes

* `0.1.0-alpha.1` was published to crates.io (`atep-core`, `atep-cli`, `atep`) and PyPI (`atep`) only. It was never published to npm. It stays installable on those two registries and is functionally the same as alpha.2. npm users start at `0.1.0-alpha.2`.

## [0.1.0-alpha.1] - 2026-10-02 (crates.io and PyPI only)

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

[Unreleased]: https://github.com/atepdev/atep/compare/v0.1.0-alpha.2...HEAD
[0.1.0-alpha.2]: https://github.com/atepdev/atep/releases/tag/v0.1.0-alpha.2
[0.1.0-alpha.1]: https://github.com/atepdev/atep/releases/tag/v0.1.0-alpha.1
