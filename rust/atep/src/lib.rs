//! ATEP: a quantum-safe trust layer for robots and AI agents.
//!
//! Every signature and key exchange pairs a classical algorithm with a
//! finalized NIST post-quantum standard (Ed25519 with ML-DSA-65, X25519 with
//! ML-KEM-768), and both halves must hold. A robot or agent can identify and
//! verify another offline, with no internet connection, registry or central
//! server.
//!
//! **Experimental alpha.** There has been no independent security audit, the
//! wire format may change between releases (private-use COSE labels,
//! unregistered media types) and the post-quantum crates underneath are young.
//!
//! This crate only re-exports [`atep_core`], so `atep::verify` is
//! `atep_core::verify`. The `atep` command line tool is installed by the crate
//! `atep-cli`.
//!
//! ```no_run
//! use atep::{verify, Policy};
//!
//! let envelope = std::fs::read("envelope.cbor").unwrap();
//! match verify(&envelope, &Policy::default(), 1_800_000_000) {
//!     Ok(v) => println!("OK, signer {}", v.signer),
//!     Err(r) => println!("rejected: {r}"),
//! }
//! ```
//!
//! More: <https://atep.dev> and <https://github.com/atepdev/atep>.

pub use atep_core::*;
