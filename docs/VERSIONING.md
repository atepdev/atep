# Versioning

ATEP has three things that are versioned, and they move independently.

| What | How it is versioned | Where |
| --- | --- | --- |
| The specification | numbered public drafts (Draft 07 was the first, Draft 08 the second); a published draft is never edited, a change is a new file | [`../spec/`](../spec/ATEP-Specification-Draft-08.md) |
| The test vectors | with the spec draft: the vectors of a draft are fixed by regeneration from seeds, and a new draft may add or change vectors | [`../vectors/`](../vectors/README.md) |
| The packages (crates, npm, PyPI) | SemVer for crates.io and npm (`0.1.0-alpha.2`), the PEP 440 spelling for PyPI (`0.1.0a2`); one version number for all of them | `rust/`, `js/`, `mcp/`, `python/` |

## The 0.x policy

* **Anything may change in any 0.x release**: the wire format, the public API of every package, command line flags, error codes, the claim vocabulary. The package version does not promise compatibility between releases before 1.0.
* The wire format uses private-use COSE header labels, a provisional CBOR tag choice and unregistered media types until the IANA registrations exist. Envelopes produced by one 0.x release may be rejected by another.
* We still try not to break needlessly: a change that breaks compatibility is called out in [`../CHANGELOG.md`](../CHANGELOG.md) under "Changed" or "Removed", and a spec change that changes bytes ships as a new draft with new vectors.
* Every implementation in a release must pass the vectors of the draft that release names (the draft is stated in the changelog). That is the compatibility statement: "conforms to Draft N vectors", not "compatible with version X".

## What a breaking change means before 1.0

A change is breaking if a conforming implementation of the previous release would, on the same input, give a different accept or reject, a different step or error code, or different bytes for something the vectors pin; or if a documented API, flag or file format of a package stops working. Before 1.0 a breaking change bumps the minor number (`0.1.x` to `0.2.0`) when it is in the released packages, and is never made inside a patch release. Pre-release labels (`-alpha.N`, `-beta.N`, `-rc.N`) may break each other freely.

## What the alpha label means

`0.1.0-alpha.N` says: usable to try, to build interoperability tests against and to read, not to rely on. No independent audit has been done, the post-quantum libraries are young, the wire format may change. Alphas are published under the npm dist-tag `alpha` (never `latest`), and on PyPI and crates.io as pre-releases that installers skip unless asked (`pip install --pre atep`, `cargo add atep-core@0.1.0-alpha.2`, `npm install @atep/core@alpha`). A later beta would mean the wire format is frozen for that draft and the remaining work is review and fixes; a release candidate would mean nothing else is planned before 1.0.

## Conditions for 1.0

1.0 is not a date. It needs all of:

1. **IANA registration** of the provisional values (COSE header parameters and algorithm identifiers, the CBOR tag question, the media types) and an Internet-Draft submitted, so that the private-use labels disappear from the wire format.
2. At least one **independent security audit** of the specification and of the reference code, with the findings fixed or published.
3. At least one **independent implementation outside the project** that passes the vectors.
4. The vector gaps and open items of section 13 of the spec closed or explicitly accepted.

After 1.0, SemVer applies: a breaking change to the wire format or the API is a new major version, and a wire format change that old verifiers cannot read is a new suite or version identifier, not a silent change.

## Where the version lives

`scripts/release/check-versions.sh` reads: `[workspace.package] version` in `rust/Cargo.toml` (inherited by every crate; the internal dependencies carry the same version), `js/package.json`, `mcp/package.json` (and the `@atep/core` range it depends on), `python/pyproject.toml` and `__version__` in `python/atep_py/__init__.py`. CI runs it on every push, and the release workflow runs it against the tag.
