use std::fmt;

/// Machine-readable rejection reasons. `as_str` is the stable name used in
/// the expected-result files of the test vectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    // Step 1: decode
    MalformedCbor,
    UnexpectedTag,
    MalformedStructure,
    MissingHeader,
    BadHeaderType,
    UnsupportedVersion,
    UnsupportedSuite,
    SignatureCountInvalid,
    AlgorithmSuiteMismatch,
    UnencryptedNonTrustDocument,
    MissingExpiresAt,
    MissingCommandClass,
    UnknownCommandClass,
    AtepRUnencrypted,
    // Step 2: decrypt
    NoRecipientKey,
    NotAddressedToRecipient,
    KemFailure,
    AeadFailure,
    // Step 3: resolve signer
    SignerBundleUnavailable,
    SignerBundleInvalid,
    SignerIdMismatch,
    KidMismatch,
    // Step 4: signatures
    DetachedPayloadMissing,
    EddsaSignatureInvalid,
    MldsaSignatureInvalid,
    // Step 5: time
    IssuedInFuture,
    Expired,
    // Step 6: replay
    NonceReplayed,
    // Step 7: digest
    PayloadDigestMismatch,
    // Step 8: signer status
    SignerRevoked,
    // Step 9: policy, attestations, chains, revocation lists, logs
    PolicyInvalid,
    ClaimMissing,
    ClaimTooOld,
    ClaimDataMismatch,
    AttestationInvalid,
    AttestationSchemaInvalid,
    AttestationIssuerMismatch,
    AttestationLifetimeExceeded,
    AttestationRevoked,
    IssuerNotAuthorized,
    ChainBroken,
    ChainCycle,
    ChainDepthExceeded,
    SrlWrongContentType,
    SrlSchemaInvalid,
    SrlIssuerMismatch,
    SrlRollback,
    SrlSequenceConflict,
    SrlUnavailable,
    SrlStale,
    InclusionProofMissing,
    InclusionProofInvalid,
    CheckpointSchemaInvalid,
    CheckpointUntrusted,
    // M3: log consistency and gossip
    ConsistencyProofInvalid,
    SplitViewDetected,
    // Anchoring hooks
    AnchorNotSupported,
    // Checking a published anchor record (spec section 9). These four names
    // are proposed in Rust finding 50; Draft 05 names none.
    AnchorContentTypeInvalid,
    AnchorSchemaInvalid,
    AnchorLogMismatch,
    AnchorCheckpointMismatch,
}

impl ErrorCode {
    pub fn as_str(&self) -> &'static str {
        use ErrorCode::*;
        match self {
            MalformedCbor => "malformed_cbor",
            UnexpectedTag => "unexpected_tag",
            MalformedStructure => "malformed_structure",
            MissingHeader => "missing_header",
            BadHeaderType => "bad_header_type",
            UnsupportedVersion => "unsupported_version",
            UnsupportedSuite => "unsupported_suite",
            SignatureCountInvalid => "signature_count_invalid",
            AlgorithmSuiteMismatch => "algorithm_suite_mismatch",
            UnencryptedNonTrustDocument => "unencrypted_non_trust_document",
            MissingExpiresAt => "missing_expires_at",
            MissingCommandClass => "missing_command_class",
            UnknownCommandClass => "unknown_command_class",
            AtepRUnencrypted => "atep_r_unencrypted",
            NoRecipientKey => "no_recipient_key",
            NotAddressedToRecipient => "not_addressed_to_recipient",
            KemFailure => "kem_failure",
            AeadFailure => "aead_failure",
            SignerBundleUnavailable => "signer_bundle_unavailable",
            SignerBundleInvalid => "signer_bundle_invalid",
            SignerIdMismatch => "signer_id_mismatch",
            KidMismatch => "kid_mismatch",
            DetachedPayloadMissing => "detached_payload_missing",
            EddsaSignatureInvalid => "eddsa_signature_invalid",
            MldsaSignatureInvalid => "mldsa_signature_invalid",
            IssuedInFuture => "issued_in_future",
            Expired => "expired",
            NonceReplayed => "nonce_replayed",
            PayloadDigestMismatch => "payload_digest_mismatch",
            SignerRevoked => "signer_revoked",
            PolicyInvalid => "policy_invalid",
            ClaimMissing => "claim_missing",
            ClaimTooOld => "claim_too_old",
            ClaimDataMismatch => "claim_data_mismatch",
            AttestationInvalid => "attestation_invalid",
            AttestationSchemaInvalid => "attestation_schema_invalid",
            AttestationIssuerMismatch => "attestation_issuer_mismatch",
            AttestationLifetimeExceeded => "attestation_lifetime_exceeded",
            AttestationRevoked => "attestation_revoked",
            IssuerNotAuthorized => "issuer_not_authorized",
            ChainBroken => "chain_broken",
            ChainCycle => "chain_cycle",
            ChainDepthExceeded => "chain_depth_exceeded",
            SrlWrongContentType => "srl_wrong_content_type",
            SrlSchemaInvalid => "srl_schema_invalid",
            SrlIssuerMismatch => "srl_issuer_mismatch",
            SrlRollback => "srl_rollback",
            SrlSequenceConflict => "srl_sequence_conflict",
            SrlUnavailable => "srl_unavailable",
            SrlStale => "srl_stale",
            InclusionProofMissing => "inclusion_proof_missing",
            InclusionProofInvalid => "inclusion_proof_invalid",
            CheckpointSchemaInvalid => "checkpoint_schema_invalid",
            CheckpointUntrusted => "checkpoint_untrusted",
            ConsistencyProofInvalid => "consistency_proof_invalid",
            SplitViewDetected => "split_view_detected",
            AnchorNotSupported => "anchor_not_supported",
            AnchorContentTypeInvalid => "anchor_content_type_invalid",
            AnchorSchemaInvalid => "anchor_schema_invalid",
            AnchorLogMismatch => "anchor_log_mismatch",
            AnchorCheckpointMismatch => "anchor_checkpoint_mismatch",
        }
    }
}

/// A verification failure naming the step of spec section 10 that failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    pub step: u8,
    pub code: ErrorCode,
    pub detail: String,
    /// For step 9 failures that wrap a failure of steps 1 to 8 on an
    /// attestation: the inner rejection.
    pub cause: Option<Box<Rejection>>,
}

impl Rejection {
    pub fn new(step: u8, code: ErrorCode, detail: impl Into<String>) -> Self {
        Rejection {
            step,
            code,
            detail: detail.into(),
            cause: None,
        }
    }

    pub fn with_cause(mut self, cause: Rejection) -> Self {
        self.cause = Some(Box::new(cause));
        self
    }
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "verification failed at step {} ({}): {}",
            self.step,
            self.code.as_str(),
            self.detail
        )?;
        if let Some(c) = &self.cause {
            write!(f, " [caused by step {} ({})]", c.step, c.code.as_str())?;
        }
        Ok(())
    }
}

impl std::error::Error for Rejection {}

/// General library error for key handling, signing and encryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtepError(pub String);

impl AtepError {
    pub fn new(msg: impl Into<String>) -> Self {
        AtepError(msg.into())
    }
}

impl fmt::Display for AtepError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AtepError {}

impl From<crate::cbor::CborError> for AtepError {
    fn from(e: crate::cbor::CborError) -> Self {
        AtepError(e.to_string())
    }
}
