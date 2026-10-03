# Call for review

ATEP (Autonomy Trust Envelope Protocol) is an open, quantum-safe trust layer for robots and AI agents: signed and encrypted envelopes in which every signature and key exchange pairs a classical algorithm with a NIST post-quantum standard (Ed25519 with ML-DSA-65, X25519 with ML-KEM-768), plus attestations, signed revocation lists and a transparency log. A robot or agent can identify and verify another with no network connection, from keys and lists it saved earlier.

It is a working draft with experimental alpha code, and **it has had no independent review of any kind**. We would like people who know cryptography, protocol design, robotics safety or space communications to try to break it, and to tell us in public when the text is unclear. This page says what we most want looked at, what we know is weak, and how to tell us.

## The short version, for posting

> ATEP is an open protocol draft (Draft 08) and experimental alpha code (Rust, JavaScript/WebAssembly, an independent Python implementation) for authenticating robots and AI agents offline, using hybrid classical and post-quantum signatures and key exchange. It has not been independently audited and the post-quantum libraries it uses are young. We are looking for reviewers of the specification and the reference code, and for a second implementer outside the project: 446 shared test vectors define the behavior. Start at https://atep.dev, read the draft at https://github.com/atepdev/atep, report ambiguities as public issues and vulnerabilities privately (SECURITY.md).

## What we most want reviewed

Section numbers are those of [Draft 08](../spec/ATEP-Specification-Draft-08.md).

1. **The hybrid construction (section 6).** Two signatures in one envelope (Ed25519 and ML-DSA-65, both must verify, no composite algorithm yet), and a hybrid key exchange whose shared secrets are combined by HKDF-SHA-256 with the public values and the KEM ciphertext bound into the context. Is the combiner sound, is binding the right inputs enough, and is level 3 the right choice? The COSE header labels, the CBOR tag and the media types are private-use and unregistered, so they will change.
2. **The verification algorithm and its error reporting (section 10).** Ten steps, first failure wins, each with a stable step and error code. Check the order, the freshness and skew rules at step 5, and the way step 9 picks which error to report when alternatives fail (decision 83 in section 20, new in Draft 08).
3. **Revocation freshness and the offline trade (sections 8 and 11).** A verifier that has not refreshed a revocation list does not know of a revocation published since. The draft chooses fail-closed or fail-open per context. Are the defaults and the 24 hour guidance defensible, and are there attacks that exploit the window?
4. **The transparency log, monitor and anchoring hooks (section 9).** Split-view and consistency checking, mis-issuance detection, and the optional anchor records. Anchoring is optional and no verifier needs a chain.
5. **The robotics profile ATEP-R (section 17).** The seven command classes, which fail closed and which continue with a warning, the e-stop exception for claim expiry, and the `peer-motion` delegation. This is where a wrong choice has physical consequences.
6. **The design commitments (section 16).** Subjects are agents and organizations, never individuals; no global score; no mandatory root or log; no reputation in the core. Tell us where a feature would erode them.
7. **The reference code.** Rust workspace under `rust/` (`atep-core` carries the verifier). It uses RustCrypto crates (at this writing `ml-dsa` 0.1.1, `ml-kem` 0.3.2, `ed25519-dalek` 3.0.0, `x25519-dalek` 3.0.0, `aes-gcm` 0.11.1) and an in-crate deterministic CBOR codec and COSE structures, so the strictness of that codec deserves particular scrutiny. Secrets are zeroized, but JavaScript and Python cannot guarantee it (see `js/README.md`).
8. **The design note on relayed space links** ([`space-links.md`](space-links.md)). Unreviewed by anyone who builds space systems. Its sections 2, 4 and 5 are the ones most likely to be wrong.

## What we know is weak or missing

* **No audit, no external review.** Everything above is the project's own work. The Python implementation is independent of the Rust code but not of the project, and it was built with the same specification.
* **Known gaps in the test vectors.** Section 12 of the specification has a table of behaviors no vector covers (for example hedged ML-DSA inputs, several Ed25519 edge cases, chain depth at the boundary, some candidate-ordering rules). An implementation can pass every vector and still be wrong there.
* **Young post-quantum libraries.** The ML-DSA and ML-KEM crates are recent and have not had an independent audit of this project's use of them.
* **Unregistered labels.** Header labels, the CBOR tag, media types and algorithm identifiers are provisional until an Internet-Draft is submitted and IANA registrations exist. Envelopes from one 0.x release may be rejected by another.
* **Untested environments.** The code has not run on constrained, embedded or flight hardware, the ROS 2 example has not been run on ROS 2, and the log daemon speaks plain HTTP and expects a TLS proxy in front. Timing figures for small processors are estimates, not measurements.
* **No external users.** Nobody outside the project is known to run it.

## A second implementation

The most useful single contribution is a second implementation by someone who does not share our assumptions. The 446 vectors in [`vectors/`](../vectors/README.md) are the contract: identical bytes for identity, signing, encryption and attestation vectors, and an identical accept or reject, step and error code for the rest. A verifier that passes the required set (265 of the 446, listed in section 12) is conformant to Draft 08. Where the text and a vector disagree, the vector wins, and we want to hear about every such place; the independent Python implementation produced 44 such reports, all resolved in the specification.

## How to tell us

* **Ambiguities, mistakes and inconsistencies in the specification:** a public issue using the "Specification issue" template. Name the draft and section. These are welcome at any level of detail.
* **Interoperability results from another implementation:** the "Interoperability report" issue template.
* **A vulnerability, or anything you would not want public yet:** do not open an issue. Use GitHub private vulnerability reporting on the repository, or email the address in [`SECURITY.md`](../SECURITY.md). We aim to acknowledge within 5 working days. There is no bug bounty. We credit reporters who want credit.
* **Contributions:** see [`CONTRIBUTING.md`](../CONTRIBUTING.md). There are a few firm rules: the vectors are authoritative, the implementations must agree, claims must be honest, and the design commitments bind contributions.

Reviews that find nothing are useful too, if they say what was looked at and what was not.
