# atep

ATEP is a quantum-safe trust layer for robots and AI agents. Every signature and key exchange pairs a classical algorithm with a finalized NIST post-quantum standard (Ed25519 with ML-DSA-65, X25519 with ML-KEM-768), and both halves must hold. A robot or agent can identify and verify another offline, with no internet connection, registry or central server: an identity is a hash of public keys, and everything else is checked against cached keys, revocation lists and log checkpoints.

This crate is a thin alias: `pub use atep_core::*;`. Depend on `atep` if you want the shorter name; it is the same library as [`atep-core`](https://crates.io/crates/atep-core). The `atep` command line tool is installed by the crate [`atep-cli`](https://crates.io/crates/atep-cli), not by this one.

> **Experimental alpha. Do not rely on this to protect anything of value.** There has been no independent security audit. The wire format may change between releases (the COSE labels are private-use values and the media types are unregistered), and the post-quantum crates it builds on (`ml-dsa`, `ml-kem`) are young. "Quantum-safe" here means finalized NIST algorithms (FIPS 203 and FIPS 204) in a hybrid construction; it does not mean audited or proven.

## Install

```
cargo add atep@0.1.0-alpha.1       # the library
cargo install atep-cli --version 0.1.0-alpha.1   # the `atep` binary
```

Needs Rust 1.89 or later.

## Use

```rust,no_run
use atep::{verify, Policy};

let envelope = std::fs::read("envelope.cbor").unwrap();
match verify(&envelope, &Policy::default(), 1_800_000_000) {
    Ok(v) => println!("OK, signer {}", v.signer),
    Err(r) => println!("rejected: {r}"),
}
```

## Links

* Website: https://atep.dev
* Repository, specification and test vectors: https://github.com/atepdev/atep
* Security policy: https://github.com/atepdev/atep/blob/main/SECURITY.md

License: Apache-2.0.
