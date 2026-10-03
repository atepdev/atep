# Releasing

How the packages of this repository are published, and exactly what the owner has to do. The current release is `0.1.0-alpha.3` (npm and crates.io) and `0.1.0a3` (PyPI, the PEP 440 spelling of the same version); `0.1.0-alpha.1` (crates.io and PyPI) and `0.1.0-alpha.2` (all three) came before it. Everything is experimental: there is no independent audit, the wire format may change, and the post-quantum crates are young. See [`VERSIONING.md`](VERSIONING.md).

| Registry | Package names | Version | Contents |
| --- | --- | --- | --- |
| crates.io | `atep-core`, `atep-cli` (binary `atep`), `atep` (re-exports `atep-core`) | `0.1.0-alpha.3` | `rust/atep-core`, `rust/atep-cli`, `rust/atep` |
| npm | `@atep/core`, `@atep/mcp` | `0.1.0-alpha.3`, dist-tag `alpha` | `js/`, `mcp/` |
| PyPI | `atep` (import package `atep_py`) | `0.1.0a3` | `python/` |

`atep-log`, `atep-monitor` and `atep-wasm` are `publish = false` and are not released yet. The unscoped npm name `atep` was refused by npm and is not used. The three crates, two npm packages and the PyPI project carry `0.0.1` placeholders that contain no code, and the `0.1.0-alpha` releases are published next to them.

Nothing here is published by hand. The workflow [`.github/workflows/release.yml`](../.github/workflows/release.yml) publishes with trusted publishing (OIDC): no registry token exists in the repository, in the Environment or in a secret.

## One-time setup

### 1. The GitHub Environment `release`

Repository Settings, Environments, New environment, name `release`. Add yourself (or a second person) under Required reviewers, and tick "Prevent self-review" only if there are two reviewers. Optionally restrict deployment to tags matching `v*`. Every publish job (`publish-crates`, `publish-npm`, `publish-pypi`) uses this environment, so each one waits for approval.

### 2. crates.io trusted publishers

For each of the three crates, `atep-core`, `atep-cli` and `atep`: crates.io, Account, the crate's Settings page, Trusted Publishing, Add (GitHub):

| Field | Value |
| --- | --- |
| Repository owner | `atepdev` |
| Repository name | `atep` |
| Workflow filename | `release.yml` |
| Environment | `release` |

The crates must be owned by your account (they are: the names are reserved). Optionally turn on "Enforce trusted publishing" afterwards so that tokens can no longer publish the crate. The workflow uses `rust-lang/crates-io-auth-action`, which exchanges the GitHub OIDC token for a short-lived crates.io token that is revoked when the job ends.

### 3. npm trusted publishers

For each of `@atep/core` and `@atep/mcp`: npmjs.com, the package, Settings, Trusted Publisher, GitHub Actions:

| Field | Value |
| --- | --- |
| Organization or user | `atepdev` |
| Repository | `atep` |
| Workflow filename | `release.yml` |
| Environment name | `release` |

Trusted publishing needs npm 11.5.1 or later; the publish job runs on Node 24, which ships it. Provenance statements are attached automatically (`--provenance`). After the first release you can set "Require two-factor authentication and disallow tokens" in each package's publishing access.

### 4. PyPI trusted publisher

PyPI, project `atep`, Manage, Publishing, Add a new publisher, GitHub:

| Field | Value |
| --- | --- |
| Owner | `atepdev` |
| Repository name | `atep` |
| Workflow name | `release.yml` |
| Environment name | `release` |

The publish step is `pypa/gh-action-pypi-publish`, which signs in with the OIDC token and uploads attestations.

### 5. Check the setup without publishing

Actions, Release, Run workflow on `main` with `dry-run` ticked (the default). It runs every verification, builds the crates, the npm tarballs and the Python distributions, smoke-tests the packed artifacts and runs `cargo publish --dry-run -p atep-core`, `npm publish --dry-run` and `twine check`. No publish job runs, so the registry settings above are first exercised by the real release.

## Release procedure

1. Pick the version. `rust/Cargo.toml` (`[workspace.package] version` and the `version = "..."` of the `atep-core` and `atep-log` dependencies in the member crates), `js/package.json`, `mcp/package.json` (its own version and the `@atep/core` range), `python/pyproject.toml` and `python/atep_py/__init__.py` must all name it. `scripts/release/check-versions.sh` checks that they agree (it also runs in CI).
2. Update `rust/Cargo.lock` (`cargo update -p atep-core --offline` or a build in `rust/`), `package-lock.json` (`npm install` at the root) and [`../CHANGELOG.md`](../CHANGELOG.md) (move Unreleased into a dated section).
3. Run the checks locally or in CI: `scripts/release/check-versions.sh v<version>` and the dry-run workflow (above). Read the file lists printed by `build-npm` and `build-crates`.
4. Commit and push to `main`; wait for CI.
5. Tag and push the tag: `git tag -a v0.1.0-alpha.3 -m "ATEP 0.1.0-alpha.3"` (`-s` needs a GPG key; an annotated tag is enough) and `git push origin v0.1.0-alpha.3`. The tag must equal `v` plus the Cargo version; the `versions` job fails otherwise.
6. Open the workflow run. After `publish-dry-run` passes, the three publish jobs wait for approval. Approve `publish-crates`, `publish-npm` and `publish-pypi` (in any order; they are independent). `publish-crates` publishes `atep-core`, waits for the sparse index to show it, then `atep-cli`, then `atep`; `publish-npm` publishes `@atep/core` and then `@atep/mcp`.
7. If a job fails part way, fix the cause and re-run the failed jobs (or run the workflow again from the tag with `dry-run` off). Each publish job skips a package version that already exists, so nothing is published twice.
8. Flip the README text (below), verify the release (below) and add the GitHub release notes (copy the changelog section).

The npm dist-tag comes from the version: `0.1.0-alpha.3` is published under `alpha`, a stable `1.2.3` under `latest`. A pre-release never takes `latest`.

## Ready-to-paste README text after the first publish

The root [`README.md`](../README.md) "Install (experimental alpha)" section and the supported-versions row in [`../SECURITY.md`](../SECURITY.md) were updated when the first alpha went out. For a later release, change the version strings in that README table. The package READMEs (`js/`, `mcp/`, `python/`, and the crate READMEs) ship inside the packages. The spec's section 13 ("Publication status") still says nothing functional is published: it is not edited, because Draft 07 is a published draft, and changes only in a new draft.

## Verify a release

In a clean directory, after the registries show the new version (the crates.io index can take a few minutes):

```
# crates.io
cargo install atep-cli --version 0.1.0-alpha.3 --root /tmp/atep-check
/tmp/atep-check/bin/atep --help
cargo info atep-core@0.1.0-alpha.3       # or: cargo search atep-core

# npm
npm view @atep/core@0.1.0-alpha.3 version dist-tags
npm view @atep/mcp@0.1.0-alpha.3 version dependencies
mkdir /tmp/npm-check && cd /tmp/npm-check && npm init -y && npm install @atep/core@alpha @atep/mcp@alpha
npm audit signatures                       # provenance and registry signatures

# PyPI
python3 -m venv /tmp/py-check && /tmp/py-check/bin/pip install --pre atep
/tmp/py-check/bin/python -c "import atep_py; print(atep_py.__version__)"
```

Then run the vector smoke tests against a checkout of the same tag (`git clone --branch v0.1.0-alpha.3 https://github.com/atepdev/atep`):

```
/tmp/atep-check/bin/atep verify -i atep/vectors/verify-positive/signed-trust-doc-inline-bundle.cbor --now 1800000000   # OK
/tmp/atep-check/bin/atep verify -i atep/vectors/verify-negative/bad-eddsa-signature.cbor --now 1800000000             # REJECTED at step 4
node atep/scripts/release/smoke-npm.mjs /tmp/npm-check atep/vectors
/tmp/py-check/bin/python -m atep_py.vectors check atep/vectors                                                        # 441 pass, 5 skipped
```

## After the first alpha

* **npm `latest` tag.** The workflow always publishes a pre-release under `--tag alpha`, so the dist-tag `latest` stays on whatever it points to today (the `0.0.1` placeholder, if that is how it was published; check with `npm view @atep/core dist-tags`). Decide whether to leave it there until a stable release (users then must ask for `@alpha`), or to move it with `npm dist-tag add @atep/core@0.1.0-alpha.3 latest`. Recommendation: leave it, so that a plain `npm install @atep/core` does not install an unaudited alpha, and update the placeholder README text on the next version.
* **Stray `0.0.0-stage` versions on npm.** Deprecate them (do not unpublish): `npm deprecate "@atep/core@0.0.0-stage" "Placeholder, no code. Use @atep/core@alpha."` and the same for `@atep/mcp`. Use the exact version strings shown by `npm view <name> versions`.
* **The 0.0.1 placeholders on crates.io and PyPI.** Do not yank them. They are harmless, yanking them gains nothing, and a yank on PyPI hides the version from resolvers in a way that confuses pinned installs. The first real versions replace them as the newest; the READMEs of the next versions say what the package is.
* Add the dependabot and security workflows' first results to your checks, and consider turning on "Enforce trusted publishing" (crates.io) and token-less publishing (npm) once a release has gone through.

## Rollback and mistakes

Registries do not let you take a release back, so plan for forward fixes:

* crates.io: `cargo yank --version 0.1.0-alpha.3 atep-core` stops new resolutions but existing lockfiles still work. A yank does not delete the code. Publish a fixed `0.1.0-alpha.3`.
* npm: `npm deprecate @atep/core@0.1.0-alpha.3 "reason, use 0.1.0-alpha.3"`. Do not rely on `npm unpublish`: it is limited to 72 hours or to packages nobody depends on, and the version number can never be reused. Move the `alpha` tag with `npm dist-tag add @atep/core@<good version> alpha`.
* PyPI: yank the release in the project's Manage page (a yanked release is skipped unless pinned exactly). Files cannot be replaced; publish `0.1.0a3`.
* A security problem in a published version: follow [`../SECURITY.md`](../SECURITY.md), yank or deprecate, publish a fixed version and say so in the changelog.
* A partial release (for example crates published but npm not): re-run the failed jobs; the skip-existing checks make that safe. Never move a tag that has already published something; cut a new version instead.
