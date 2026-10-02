//! ATEP core library (Draft 02, milestones M1 and M2; M3 adds consistency proofs to `log`).
//!
//! Identity, canonical bundles and Agent IDs, hybrid signing (COSE_Sign,
//! Ed25519 plus ML-DSA-65), hybrid encryption (COSE_Encrypt, X25519 plus
//! ML-KEM-768), and the verification algorithm of spec section 10. M2 adds
//! attestations (section 7), signed revocation lists (section 8), the trust
//! policy engine with chain walking and inclusion proofs (sections 9 and 10
//! step 9) and the ATEP-R enforcement rules (section 17).

pub mod admission;
pub mod anchor;
pub mod atep_r;
pub mod attestation;
pub mod cbor;
pub mod domain;
pub mod encrypt;
pub mod envelope;
pub mod error;
pub mod json;
pub mod keys;
pub mod log;
pub mod srl;
pub mod succession;
pub mod trust;
pub mod vectors;
mod vectors_trust;
pub mod verify;

pub use encrypt::{decrypt, encrypt, EncryptRandomness};
pub use envelope::{sign, SignMode, SignParams};
pub use error::{AtepError, ErrorCode, Rejection};
pub use keys::{AgentId, Identity, PublicBundle, Seeds};
pub use trust::{Rule, TrustPolicy};
pub use verify::{verify, Policy, Revocation, RevocationReason, Verified};

/// Constants and provisional identifiers.
///
/// Everything marked PROVISIONAL is a private-use value chosen so that test
/// vectors can exist before IANA registration (spec section 5). A later draft
/// will map each one to its assigned value.
pub mod consts {
    /// CBOR tag for COSE_Sign (RFC 9052).
    pub const TAG_COSE_SIGN: u64 = 98;
    /// CBOR tag for COSE_Encrypt (RFC 9052).
    pub const TAG_COSE_ENCRYPT: u64 = 96;

    /// Suite name carried in the protected header.
    pub const SUITE_ATEP_1: &str = "ATEP-1";
    /// atep-version value for this draft.
    pub const ATEP_VERSION: i64 = 1;
    /// Allowed clock skew for `issued-at`, seconds (spec section 10 step 5).
    pub const DEFAULT_SKEW_SECS: i64 = 300;
    /// HKDF info context (spec section 6).
    pub const KEM_CONTEXT: &[u8] = b"ATEP-1-KEM";
    /// Attestation lifetime hard maximum in seconds (spec section 7).
    pub const MAX_ATTESTATION_LIFETIME_SECS: i64 = 400 * 24 * 3600;
    /// Default attestation lifetime ceiling for non audit-backed claims (SHOULD).
    pub const DEFAULT_ATTESTATION_LIFETIME_SECS: i64 = 180 * 24 * 3600;
    /// Recommended maximum chain depth (spec section 7), counted in attestations.
    pub const DEFAULT_MAX_CHAIN_DEPTH: usize = 5;

    // COSE header labels, standard.
    pub const HDR_ALG: i64 = 1;
    pub const HDR_CONTENT_TYPE: i64 = 3;
    pub const HDR_KID: i64 = 4;
    pub const HDR_IV: i64 = 5;
    /// RFC 9052 ephemeral key header parameter.
    pub const HDR_EPHEMERAL_KEY: i64 = -1;

    // ATEP protected header labels, PROVISIONAL (spec section 5).
    pub const HDR_ATEP_VERSION: i64 = -70001;
    pub const HDR_SIGNER: i64 = -70002;
    pub const HDR_ISSUED_AT: i64 = -70003;
    pub const HDR_EXPIRES_AT: i64 = -70004;
    pub const HDR_NONCE: i64 = -70005;
    pub const HDR_PAYLOAD_DIGEST: i64 = -70006;
    pub const HDR_SUITE: i64 = -70007;
    /// ATEP-R command class (spec section 5 and 17), PROVISIONAL.
    pub const HDR_COMMAND_CLASS: i64 = -70014;

    // Unprotected header labels, PROVISIONAL (spec section 5).
    pub const HDR_SIGNER_BUNDLE: i64 = -70008;
    pub const HDR_ATTESTATIONS: i64 = -70009;
    /// Signed inclusion proof (spec section 9), PROVISIONAL.
    pub const HDR_INCLUSION_PROOF: i64 = -70012;
    /// ML-KEM-768 ciphertext in the recipient unprotected header, PROVISIONAL (spec section 5).
    pub const HDR_KEM_CIPHERTEXT: i64 = -70013;

    // COSE algorithm identifiers.
    /// EdDSA, registered (RFC 9053).
    pub const ALG_EDDSA: i64 = -8;
    /// ML-DSA-65. PROVISIONAL: -49 follows draft-ietf-cose-dilithium and is
    /// not yet assigned by IANA.
    pub const ALG_MLDSA65: i64 = -49;
    /// AES-256-GCM, registered (RFC 9053).
    pub const ALG_A256GCM: i64 = 3;
    /// ECDH-ES + HKDF-256, registered (RFC 9053). Used as the `alg` of X25519 keys.
    pub const ALG_ECDH_ES_HKDF_256: i64 = -25;
    /// ML-KEM-768 key algorithm. PROVISIONAL private-use value.
    pub const ALG_MLKEM768: i64 = -70010;
    /// ATEP-1 hybrid KEM recipient algorithm (X25519 + ML-KEM-768 + HKDF-SHA-256).
    /// PROVISIONAL private-use value.
    pub const ALG_ATEP1_HYBRID_KEM: i64 = -70011;

    // COSE_Key parameters and values.
    pub const KEY_KTY: i64 = 1;
    pub const KEY_ALG: i64 = 3;
    /// Curve (OKP) or public key (AKP), label -1.
    pub const KEY_NEG1: i64 = -1;
    /// OKP public key x, label -2.
    pub const KEY_NEG2: i64 = -2;
    pub const KTY_OKP: i64 = 1;
    /// AKP key type from draft-ietf-cose-dilithium. PROVISIONAL.
    pub const KTY_AKP: i64 = 7;
    pub const CRV_X25519: i64 = 4;
    pub const CRV_ED25519: i64 = 6;

    // Content types.
    pub const CT_DATA: &str = "application/atep+cbor";
    pub const CT_ATTESTATION: &str = "application/atep-attestation+cbor";
    /// PROVISIONAL media types for the other two trust documents (spec section 5).
    pub const CT_SRL: &str = "application/atep-srl+cbor";
    pub const CT_CHECKPOINT: &str = "application/atep-checkpoint+cbor";
    /// PROVISIONAL media type of a log-signed anchor record (anchoring hooks, spec section 9).
    pub const CT_ANCHOR: &str = "application/atep-anchor+cbor";

    /// Content types that may travel unencrypted (spec section 5).
    pub fn is_trust_document(content_type: &str) -> bool {
        matches!(
            content_type,
            CT_ATTESTATION | CT_SRL | CT_CHECKPOINT | CT_ANCHOR
        )
    }
}
