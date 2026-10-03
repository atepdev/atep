# Security policy

ATEP is a security protocol and its reference code is meant to guard physical systems, so reports of weaknesses are welcome and taken seriously.

## Reporting a vulnerability

Use either channel:

1. **GitHub private vulnerability reporting (preferred).** On the repository, open the Security tab and choose "Report a vulnerability": https://github.com/atepdev/atep/security/advisories/new
2. **Email** **nathan@airadlabs.com**.

Please include the affected component and version or commit, a description of the issue, steps or a test vector that reproduce it, and what you think the impact is. Please do not open a public issue for a vulnerability and do not test against systems you do not own.

Intended handling (a goal, not a service level agreement): acknowledge within 5 working days, assess and reply with a plan within 15 working days, coordinate disclosure with you, and credit you unless you prefer otherwise. No bug bounty exists.

## Supported versions

| Component | Version | Supported |
| --- | --- | --- |
| Specification | Draft 08, `spec/ATEP-Specification-Draft-08.md` (current, second public draft) | yes |
| Specification | Draft 07, `spec/ATEP-Specification-Draft-07.md` (first public draft, superseded) | no, see Draft 08 |
| Rust crates, `@atep/core`, `@atep/mcp`, `atep` on PyPI (`atep_py`) | this repository's main branch | yes, as pre-release software |
| The same packages, `0.1.0-alpha.x` (PyPI `0.1.0a2`) | published | yes, as an experimental alpha |

The earlier `0.0.1` versions on the registries are placeholders with no code and are not supported; use the `0.1.0-alpha` releases. There is no stable 1.0 release and no formal long term support.

## Scope

In scope: protocol flaws in the specification (a way to forge, replay, downgrade, strip or confuse envelopes, attestations, revocation lists or log proofs); bugs in the reference implementations that make verification accept something the specification or the test vectors say must be rejected, or reject something it must accept; memory or key handling flaws in `rust/`, `js/`, `python/`; flaws in the log and monitor (`atep-log`, `atep-monitor`) that let an attacker present a forked or rewritten history undetected.

Out of scope or known limits: the examples and the demo (they are illustrations; their key handling is deliberately simple); denial of service against the reference log daemon, which speaks plain HTTP and is meant to sit behind a TLS proxy; timing side channels beyond what the cryptographic crates guarantee; secrets held in JavaScript or Python process memory (see the `js/` README, "Secrets and their limits"); social engineering of issuers; vulnerabilities in third party dependencies (report those upstream, but tell us if ATEP is affected); and the cryptographic libraries themselves (the ML-DSA and ML-KEM crates are young and have not had an independent audit of this project).

The project has not had an external security audit. Do not assume it has.
