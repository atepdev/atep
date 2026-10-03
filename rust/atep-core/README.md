# atep-core

ATEP is a quantum-safe trust layer for robots and AI agents. Every signature and key exchange pairs a classical algorithm with a finalized NIST post-quantum standard (Ed25519 with ML-DSA-65, X25519 with ML-KEM-768), and both halves must hold. A robot or agent can identify and verify another offline, with no internet connection, registry or central server: an identity is a hash of public keys, and everything else is checked against cached keys, revocation lists and log checkpoints.

`atep-core` is the Rust reference library of ATEP (Draft 07): key bundles and Agent IDs, hybrid signing (COSE_Sign) and encryption (COSE_Encrypt), attestations, signed revocation lists, the trust policy engine, Merkle log proofs and the ten-step verification algorithm. It passes all 436 test vectors of the specification.

> **Experimental alpha. Do not rely on this to protect anything of value.** There has been no independent security audit. The wire format may change between releases (the COSE labels are private-use values and the media types are unregistered), and the post-quantum crates it builds on (`ml-dsa`, `ml-kem`) are young. "Quantum-safe" here means finalized NIST algorithms (FIPS 203 and FIPS 204) in a hybrid construction; it does not mean audited or proven.

## Install

```
cargo add atep-core@0.1.0-alpha.1
```

(Cargo does not select pre-releases on its own, so the version is spelled out.) Needs Rust 1.89 or later. The command line tool is the separate crate [`atep-cli`](https://crates.io/crates/atep-cli), which installs a binary named `atep`. The crate `atep` re-exports this library under the shorter name.

## Use

```rust,no_run
use atep_core::{verify, Policy};

let envelope = std::fs::read("envelope.cbor").unwrap();
let now = 1_800_000_000; // Unix seconds
match verify(&envelope, &Policy::default(), now) {
    Ok(v) => println!("OK, signer {}", v.signer),
    // every rejection names the step of the ten-step algorithm and a stable error code
    Err(r) => println!("rejected: {r}"),
}
```

The `atep-vectors` binary of this crate checks a directory of test vectors: `atep-vectors check <dir>`. The vectors live in the repository, not in the crate.

## Links

* Website: https://atep.dev
* Repository, specification and test vectors: https://github.com/atepdev/atep
* Security policy: https://github.com/atepdev/atep/blob/main/SECURITY.md

License: Apache-2.0.
