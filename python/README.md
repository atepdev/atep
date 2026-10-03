# atep (Python)

ATEP is a quantum-safe trust layer for robots and AI agents. Every signature and key exchange pairs a classical algorithm with a finalized NIST post-quantum standard (Ed25519 with ML-DSA-65, X25519 with ML-KEM-768), and both halves must hold. A robot or agent can identify and verify another offline, with no internet connection, registry or central server: an identity is a hash of public keys, and everything else is checked against cached keys, revocation lists and log checkpoints.

> **Experimental alpha. Do not rely on this to protect anything of value.** There has been no independent security audit. The wire format may change between releases (the COSE labels are private-use values and the media types are unregistered). "Quantum-safe" means finalized NIST algorithms (FIPS 203 and FIPS 204) in a hybrid construction; it does not mean audited or proven.

```
pip install --pre atep
```

The PyPI distribution is named `atep`; the import package is `atep_py` (`import atep_py`). The `--pre` flag is needed because the first releases are pre-releases (`0.1.0a1`). Python 3.8 or later, no dependencies.

**The post-quantum algorithms are pure Python and slow.** ML-DSA-65 and ML-KEM-768 are implemented here in plain Python so that the package has no native code and no third party dependencies; a full run over the 431 test vectors takes about 30 seconds. This package is meant for interoperability checks, tooling and reading the protocol, not for performance. For speed use the Rust crate or the `@atep/core` npm package.

`atep_py` is the independent Python implementation of ATEP Draft 07 (suite `ATEP-1`; the first 140 vectors are Draft 02/03, then 60 `retired` and `successor`, then 236 anchoring and discovery vectors; draft numbers are internal, see spec Appendix A), written for the M4
interoperability test from the specification and `vectors/` only. Pure Python 3.8, standard
library only: Ed25519, X25519, AES-256-GCM, HKDF, deterministic CBOR, ML-DSA-65 (FIPS 204) and
ML-KEM-768 (FIPS 203) are all implemented here. No native extensions, no third party packages.

## Layout

| Module | Contents |
| --- | --- |
| `atep_py/cbor.py` | strict deterministic CBOR codec (RFC 8949 4.2.1) |
| `atep_py/ed25519.py`, `x25519.py`, `aesgcm.py`, `hkdf.py` | classical primitives (Ed25519 verifies in strict mode) |
| `atep_py/mldsa.py`, `mlkem.py` | FIPS 204 and FIPS 203 |
| `atep_py/identity.py` | key bundle, Agent ID, `did:atep:` alias |
| `atep_py/envelope.py` | deterministic signing, hybrid encryption |
| `atep_py/core.py` | verification steps 1 to 8, decryption |
| `atep_py/srl.py`, `logs.py`, `policy.py` | SRLs, Merkle log proofs and checkpoints, step 9 (chains, ATEP-R) |
| `atep_py/anchors.py` | `chain-id`, checkpoint hash, anchor record decode and encode, published anchor check, `require_anchor` rules |
| `atep_py/admission.py` | admission of a `registry-endpoint` attestation (that claim only, no log state) |
| `atep_py/domain.py` | domain records and the domain binding check (pure functions, fixture based, no network) |
| `atep_py/verify.py` | `verify()` and `verify_json()` entry points |
| `atep_py/vectors.py` | vector runner |

## Usage

The test vectors are not part of the package; clone https://github.com/atepdev/atep to get the `vectors/` directory, then pass its path.

```
python3 -m atep_py.vectors check ../vectors            # all vectors, summary per category
python3 -m atep_py.vectors check ../vectors chain-negative -v   # one category, verbose
python3 -m unittest                                    # unit tests plus every vector (run from python/)
```

`ATEP_VECTORS=/path/to/vectors python3 -m unittest` points the tests at another vectors directory.

```python
from atep_py import identity, envelope
alice = identity.Identity({"ed25519": "...hex...", "mldsa65": "...hex..."})
env = envelope.sign(alice, payload, envelope.CT_ATTESTATION, nonce16, issued_at, expires_at,
                    include_bundle=True)            # deterministic ML-DSA (rnd = 32 zero bytes)
```

## Notes

* Signing always uses the deterministic ML-DSA variant; pass `rnd=` to `envelope.sign` for hedged signing.
* Pure Python is slow: a full vector run takes about 30 seconds.
* Implemented from Draft 04: step 8 retirement store (valid `retired` attestations in the local attestation
  store, with the exemption), the `retired` and `successor` layouts, the `follow_succession` policy member
  (one hop, section 7), and SRL loading in the verifier's own context (cache, revocations, store).
* Implemented from Draft 05: the anchor media type as a signed-only trust document at step 1, the `require_anchor`
  policy member (parsed and validated, `policy_invalid` on any violation, `anchor_not_supported` at the start of step 9,
  also with no claim rules), the `chain-id` rule, the checkpoint hash, anchor record decode and encode, the published
  anchor check with its four step 9 codes, the `registry-endpoint` data and admission check, and the domain binding check.
* `python3 -m atep_py.vectors check ../vectors` reports 431 passed + 5 skipped = 436. Per new category: `anchor-envelope`
  13, `anchor-media-type` 3, `anchor-not-supported` 9, `anchor-record` 36, `chain-id` 30, `checkpoint-hash` 9,
  `domain-binding` 83, `registry-endpoint` 26, `require-anchor` 27 (all passed). The 5 skipped are named and counted:
  `log-admission` (4) and `monitor` (1), because Python has no log and no monitor. `registry-endpoint` runs through
  `admission.admit_registry_endpoint`, a function of the submission only, not through a log.
* Known gaps: evaluation of `require_anchor` (it fails closed, as the spec requires; fetching and checking anchors
  against a witness is milestone M5), checking that a witness holds the hash, a network fetcher for domain records
  (the checker takes the fetcher's answers; no HTTPS or DNS code), public suffix refusal of the domain name, the rest of
  log admission (resubmission, SRL and retirement stores, `domain-control` data), claim-type resolution, hedged-signing
  test inputs.
* Divergences between the spec text and what was needed to reproduce the vectors are in [`docs/implementation-findings/python-findings.md`](https://github.com/atepdev/atep/blob/main/docs/implementation-findings/python-findings.md) (entries 32 to
  44 are from the anchoring and discovery vectors); all are resolved in the spec.
