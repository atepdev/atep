# CI workflows

Both workflows run with `permissions: contents: read`, use no secrets, set a timeout on every job, and cancel superseded runs on pull requests. Third-party actions are pinned to full commit SHAs with the version in a comment. Rust is installed with `rustup` on the runner (no third-party toolchain action).

## ci.yml (push to main, pull requests)

| Job | What it runs |
| --- | --- |
| `rust` | `cargo fmt --check`, `cargo clippy --all-targets -D warnings`, `cargo test --workspace` (includes the no chain or wallet dependency guard and the vector regeneration test), `atep-vectors check ../vectors`, then `scripts/ci/check-vector-regeneration.sh` (regenerate, `git diff --exit-code vectors/`, no new files) |
| `js` | wasm32 target, wasm-bindgen CLI at the version in `rust/Cargo.lock` (`scripts/ci/wasm-bindgen-version.sh`, installed with `--no-default-features`), `npm ci`, `npm run build`, `npm test` in `js/`, then `mcp/`, `examples/`, `examples/mqtt/` tests and `node demo/selftest.mjs` |
| `python` | Python 3.8 and 3.12: `python -m unittest`, `python -m atep_py.vectors check ../vectors`, and the ROS-free tests of `examples/ros2` |
| `site-and-docs` | `node site/check.mjs`, `scripts/ci/no-em-dashes.sh`, `node scripts/ci/vector-counts.mjs`, `node scripts/ci/check-md-links.mjs` |
| `cddl` | installs the Rust `cddl` crate at a pinned version (cached) and runs `node scripts/ci/validate-cddl.mjs`: every vector and the JSON documents against `spec/schemas/atep.cddl` as listed in `scripts/ci/cddl-map.json`, the mutation checks, expected-fail vectors asserted |
| `workflow-lint` | actionlint 1.7.12 (checksum verified) over the workflow files |

## security.yml (push to main, lockfile pull requests, weekly)

Informational, non-blocking (`continue-on-error`): `cargo audit` on `rust/Cargo.lock` and `npm audit --omit=dev` in `js`, `mcp`, `examples`, `examples/mqtt`.

## Helper scripts (`scripts/ci/`)

* `no-em-dashes.sh`: fails on U+2014 in any tracked text file (skips `node_modules`, `vendor`, `*.wasm`, binaries).
* `vector-counts.mjs`: manifest entries all have `.cbor`, `.json`, `.expected.json`, hashes match, no orphan files, and the counts documented in `js/README.md` and `python/README.md` agree with the manifest.
* `validate-cddl.mjs`, `cddl-map.json`, `cbor-mini.mjs`: the CDDL validation above (driver, table of rule and expected result per vector pattern, small CBOR reader and encoder).
* `check-md-links.mjs`: relative links and anchors in tracked Markdown files resolve (external links are not fetched).
* `no-local-paths.sh`: fails if a tracked file or a built artifact embeds an absolute local path.
* `check-vector-regeneration.sh`, `wasm-bindgen-version.sh`: see above.

`dependabot.yml` opens weekly updates for cargo (`rust/`), npm (`js`, `mcp`, `examples`, `examples/mqtt`) and GitHub Actions.
