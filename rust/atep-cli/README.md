# atep-cli

ATEP is a quantum-safe trust layer for robots and AI agents. Every signature and key exchange pairs a classical algorithm with a finalized NIST post-quantum standard (Ed25519 with ML-DSA-65, X25519 with ML-KEM-768), and both halves must hold. A robot or agent can identify and verify another offline, with no internet connection, registry or central server: an identity is a hash of public keys, and everything else is checked against cached keys, revocation lists and log checkpoints.

`atep-cli` installs the `atep` command line tool: `atep keygen`, `atep sign`, `atep encrypt`, `atep verify`. It is a thin front end over [`atep-core`](https://crates.io/crates/atep-core).

> **Experimental alpha. Do not rely on this to protect anything of value.** There has been no independent security audit. The wire format may change between releases (the COSE labels are private-use values and the media types are unregistered), and the post-quantum crates it builds on (`ml-dsa`, `ml-kem`) are young. "Quantum-safe" here means finalized NIST algorithms (FIPS 203 and FIPS 204) in a hybrid construction; it does not mean audited or proven.

## Install

```
cargo install atep-cli --version 0.1.0-alpha.3
```

The crate is named `atep-cli`; the binary it installs is named `atep`. Needs Rust 1.89 or later and a C compiler or linker.

## Use

```
atep keygen --out alice.key            # writes alice.key (secret) and alice.key.pub, prints the Agent ID
atep sign -k alice.key -i payload.bin -o env.cbor --expires-in 3600
atep encrypt -i env.cbor --to bob.key.pub -o env.enc.cbor
atep verify -i env.cbor --now 1800000000
```

`atep verify` prints `OK` and the signer, or `REJECTED at step N (error_code): reason` and exits with 1. Run `atep --help` for every option. To check the tool against the specification, clone the repository and run it on the test vectors in `vectors/`.

## Links

* Website: https://atep.dev
* Repository, specification and test vectors: https://github.com/atepdev/atep
* Full Rust documentation: https://github.com/atepdev/atep/blob/main/rust/README.md
* Security policy: https://github.com/atepdev/atep/blob/main/SECURITY.md

License: Apache-2.0.
