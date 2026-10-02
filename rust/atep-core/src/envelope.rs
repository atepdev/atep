//! COSE_Sign envelope: construction, signing and parsing (spec section 5).

use std::convert::Infallible;

use ed25519_dalek::Signer as _;
use ml_dsa::{MlDsa65, SigningKey as MlDsaSigningKey};

use crate::cbor::Value;
use crate::consts::*;
use crate::error::{AtepError, ErrorCode, Rejection};
use crate::keys::{fill_random, sha256, AgentId, Identity, PublicBundle};

/// How ML-DSA signing randomness is chosen. Ed25519 is always deterministic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignMode {
    /// FIPS 204 deterministic variant (rnd = 32 zero bytes). Used for vectors.
    Deterministic,
    /// FIPS 204 hedged variant with 32 fresh random bytes.
    Hedged,
}

/// Protected header of the COSE_Sign body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Headers {
    pub content_type: String,
    pub version: i64,
    pub signer: [u8; 32],
    pub issued_at: i64,
    pub expires_at: Option<i64>,
    pub nonce: [u8; 16],
    pub payload_digest: [u8; 32],
    pub suite: String,
    /// ATEP-R command class (-70014), when present.
    pub command_class: Option<String>,
}

impl Headers {
    pub fn to_value(&self) -> Value {
        let mut m = vec![
            (
                Value::Int(HDR_CONTENT_TYPE),
                Value::text(&self.content_type),
            ),
            (Value::Int(HDR_ATEP_VERSION), Value::Int(self.version)),
            (Value::Int(HDR_SIGNER), Value::bytes(&self.signer)),
            (Value::Int(HDR_ISSUED_AT), Value::Int(self.issued_at)),
            (Value::Int(HDR_NONCE), Value::bytes(&self.nonce)),
            (
                Value::Int(HDR_PAYLOAD_DIGEST),
                Value::bytes(&self.payload_digest),
            ),
            (Value::Int(HDR_SUITE), Value::text(&self.suite)),
        ];
        if let Some(e) = self.expires_at {
            m.push((Value::Int(HDR_EXPIRES_AT), Value::Int(e)));
        }
        if let Some(c) = &self.command_class {
            m.push((Value::Int(HDR_COMMAND_CLASS), Value::text(c)));
        }
        Value::Map(m)
    }

    /// Serialized protected header (the content of the bstr wrapper).
    pub fn encode(&self) -> Vec<u8> {
        self.to_value().encode()
    }
}

fn rej(code: ErrorCode, detail: impl Into<String>) -> Rejection {
    Rejection::new(1, code, detail)
}

/// Parse a serialized protected header. Applies the step 1 checks that depend
/// only on the header: version, suite, presence and types of required fields.
pub fn parse_headers(bytes: &[u8]) -> Result<Headers, Rejection> {
    let v = Value::decode(bytes)
        .map_err(|e| rej(ErrorCode::MalformedCbor, format!("protected header: {e}")))?;
    if v.as_map().is_none() {
        return Err(rej(
            ErrorCode::MalformedStructure,
            "protected header is not a map",
        ));
    }
    let get = |label: i64| v.map_get_int(label);
    match get(HDR_ATEP_VERSION) {
        None => {
            return Err(rej(
                ErrorCode::MissingHeader,
                "atep-version (-70001) missing",
            ))
        }
        Some(Value::Int(ATEP_VERSION)) => {}
        Some(Value::Int(n)) => {
            return Err(rej(
                ErrorCode::UnsupportedVersion,
                format!("atep-version {n} is not supported"),
            ))
        }
        Some(_) => {
            return Err(rej(
                ErrorCode::BadHeaderType,
                "atep-version must be an integer",
            ))
        }
    }
    let suite = match get(HDR_SUITE) {
        None => return Err(rej(ErrorCode::MissingHeader, "suite (-70007) missing")),
        Some(Value::Text(s)) => s.clone(),
        Some(_) => return Err(rej(ErrorCode::BadHeaderType, "suite must be text")),
    };
    if suite != SUITE_ATEP_1 {
        return Err(rej(
            ErrorCode::UnsupportedSuite,
            format!("suite `{suite}` is not supported"),
        ));
    }
    let content_type = match get(HDR_CONTENT_TYPE) {
        None => return Err(rej(ErrorCode::MissingHeader, "content type (3) missing")),
        Some(Value::Text(s)) => s.clone(),
        Some(_) => return Err(rej(ErrorCode::BadHeaderType, "content type must be text")),
    };
    let fixed = |label: i64, name: &str, len: usize| -> Result<Vec<u8>, Rejection> {
        match get(label) {
            None => Err(rej(
                ErrorCode::MissingHeader,
                format!("{name} ({label}) missing"),
            )),
            Some(Value::Bytes(b)) if b.len() == len => Ok(b.clone()),
            Some(_) => Err(rej(
                ErrorCode::BadHeaderType,
                format!("{name} must be a byte string of {len} bytes"),
            )),
        }
    };
    let int = |label: i64, name: &str| -> Result<i64, Rejection> {
        match get(label) {
            None => Err(rej(
                ErrorCode::MissingHeader,
                format!("{name} ({label}) missing"),
            )),
            Some(Value::Int(i)) => Ok(*i),
            Some(_) => Err(rej(
                ErrorCode::BadHeaderType,
                format!("{name} must be an integer"),
            )),
        }
    };
    let signer: [u8; 32] = fixed(HDR_SIGNER, "signer", 32)?.try_into().unwrap();
    let issued_at = int(HDR_ISSUED_AT, "issued-at")?;
    let nonce: [u8; 16] = fixed(HDR_NONCE, "nonce", 16)?.try_into().unwrap();
    let payload_digest: [u8; 32] = fixed(HDR_PAYLOAD_DIGEST, "payload-digest", 32)?
        .try_into()
        .unwrap();
    let expires_at = match get(HDR_EXPIRES_AT) {
        None => None,
        Some(Value::Int(i)) => Some(*i),
        Some(_) => {
            return Err(rej(
                ErrorCode::BadHeaderType,
                "expires-at must be an integer",
            ))
        }
    };
    let command_class = match get(HDR_COMMAND_CLASS) {
        None => None,
        Some(Value::Text(c)) => Some(c.clone()),
        Some(_) => return Err(rej(ErrorCode::BadHeaderType, "command-class must be text")),
    };
    Ok(Headers {
        content_type,
        version: ATEP_VERSION,
        signer,
        issued_at,
        expires_at,
        nonce,
        payload_digest,
        suite,
        command_class,
    })
}

/// One parsed COSE_Signature.
#[derive(Clone, Debug)]
pub struct CoseSignature {
    pub protected_raw: Vec<u8>,
    pub alg: i64,
    pub kid: Vec<u8>,
    pub signature: Vec<u8>,
}

/// A parsed COSE_Sign (tag 98) envelope.
#[derive(Clone, Debug)]
pub struct SignedEnvelope {
    pub body_protected_raw: Vec<u8>,
    pub headers: Headers,
    pub signer_bundle: Option<Value>,
    /// Inline attestations (-70009), exactly as carried. Not signed.
    pub attestations: Option<Value>,
    /// Inclusion proof (-70012), exactly as carried. Not signed.
    pub inclusion_proof: Option<Value>,
    pub payload: Option<Vec<u8>>,
    pub signatures: Vec<CoseSignature>,
}

fn malformed(detail: &str) -> Rejection {
    rej(ErrorCode::MalformedStructure, detail)
}

impl SignedEnvelope {
    /// Parse a decoded CBOR value that must be `98([...])`.
    pub fn from_value(v: &Value) -> Result<SignedEnvelope, Rejection> {
        let inner = match v {
            Value::Tag(t, inner) if *t == TAG_COSE_SIGN => inner,
            Value::Tag(t, _) => {
                return Err(rej(
                    ErrorCode::UnexpectedTag,
                    format!("expected tag 98, found tag {t}"),
                ))
            }
            _ => return Err(rej(ErrorCode::UnexpectedTag, "expected CBOR tag 98")),
        };
        let a = inner
            .as_array()
            .filter(|a| a.len() == 4)
            .ok_or_else(|| malformed("COSE_Sign must be an array of 4 elements"))?;
        let body_protected_raw = a[0]
            .as_bytes()
            .ok_or_else(|| malformed("body protected header must be a bstr"))?
            .to_vec();
        let headers = parse_headers(&body_protected_raw)?;
        let unprot = a[1]
            .as_map()
            .ok_or_else(|| malformed("unprotected header must be a map"))?;
        let signer_bundle = unprot
            .iter()
            .find(|(k, _)| *k == Value::Int(HDR_SIGNER_BUNDLE))
            .map(|(_, v)| v.clone());
        let unprot_get = |label: i64| {
            unprot
                .iter()
                .find(|(k, _)| *k == Value::Int(label))
                .map(|(_, v)| v.clone())
        };
        let attestations = unprot_get(HDR_ATTESTATIONS);
        let inclusion_proof = unprot_get(HDR_INCLUSION_PROOF);
        let payload = match &a[2] {
            Value::Null => None,
            Value::Bytes(b) => Some(b.clone()),
            _ => return Err(malformed("payload must be a bstr or null")),
        };
        let sigs = a[3]
            .as_array()
            .ok_or_else(|| malformed("signatures must be an array"))?;
        let mut signatures = Vec::new();
        for s in sigs {
            let s = s
                .as_array()
                .filter(|s| s.len() == 3)
                .ok_or_else(|| malformed("COSE_Signature must be an array of 3 elements"))?;
            let protected_raw = s[0]
                .as_bytes()
                .ok_or_else(|| malformed("signature protected header must be a bstr"))?
                .to_vec();
            if s[1].as_map().is_none() {
                return Err(malformed("signature unprotected header must be a map"));
            }
            let sig = s[2]
                .as_bytes()
                .ok_or_else(|| malformed("signature must be a bstr"))?
                .to_vec();
            let ph = Value::decode(&protected_raw).map_err(|e| {
                rej(
                    ErrorCode::MalformedCbor,
                    format!("signature protected header: {e}"),
                )
            })?;
            let alg = ph
                .map_get_int(HDR_ALG)
                .and_then(|v| v.as_int())
                .ok_or_else(|| malformed("signature protected header lacks integer alg"))?;
            let kid = ph
                .map_get_int(HDR_KID)
                .and_then(|v| v.as_bytes())
                .ok_or_else(|| malformed("signature protected header lacks bstr kid"))?
                .to_vec();
            signatures.push(CoseSignature {
                protected_raw,
                alg,
                kid,
                signature: sig,
            });
        }
        Ok(SignedEnvelope {
            body_protected_raw,
            headers,
            signer_bundle,
            attestations,
            inclusion_proof,
            payload,
            signatures,
        })
    }

    /// Parse from raw bytes.
    pub fn decode(data: &[u8]) -> Result<SignedEnvelope, Rejection> {
        let v = Value::decode(data).map_err(|e| rej(ErrorCode::MalformedCbor, e.to_string()))?;
        SignedEnvelope::from_value(&v)
    }
}

/// RFC 9052 section 4.4 Sig_structure for a COSE_Signature, external_aad empty.
pub fn sig_structure(body_protected: &[u8], sign_protected: &[u8], payload: &[u8]) -> Vec<u8> {
    Value::Array(vec![
        Value::text("Signature"),
        Value::bytes(body_protected),
        Value::bytes(sign_protected),
        Value::bytes(&[]),
        Value::bytes(payload),
    ])
    .encode()
}

pub fn signature_protected(alg: i64, kid: &[u8]) -> Vec<u8> {
    Value::Map(vec![
        (Value::Int(HDR_ALG), Value::Int(alg)),
        (Value::Int(HDR_KID), Value::bytes(kid)),
    ])
    .encode()
}

/// Inputs for ordinary signing.
pub struct SignParams<'a> {
    pub payload: &'a [u8],
    pub content_type: &'a str,
    /// 16 bytes, caller supplied so signing can be reproduced.
    pub nonce: [u8; 16],
    pub issued_at: i64,
    pub expires_at: Option<i64>,
    /// Detached payload: the envelope carries nil and the digest binds the payload.
    pub detached: bool,
    /// Put the signer's public bundle in the unprotected header.
    pub include_bundle: bool,
    pub mode: SignMode,
    /// ATEP-R command class, written to the protected header (-70014).
    pub command_class: Option<&'a str>,
}

impl<'a> SignParams<'a> {
    pub fn new(payload: &'a [u8], content_type: &'a str, nonce: [u8; 16], issued_at: i64) -> Self {
        SignParams {
            payload,
            content_type,
            nonce,
            issued_at,
            expires_at: None,
            detached: false,
            include_bundle: true,
            mode: SignMode::Hedged,
            command_class: None,
        }
    }
}

/// Fully explicit signing description. Used by `sign` and by the vector
/// generator to build deliberately broken envelopes.
pub struct RawSpec<'a> {
    pub headers: Headers,
    /// Bytes covered by the signatures.
    pub payload: Vec<u8>,
    pub attach_payload: bool,
    pub bundle_in_header: Option<PublicBundle>,
    pub ed_signer: Option<&'a Identity>,
    pub pq_signer: Option<&'a Identity>,
    pub kid: [u8; 32],
    pub mode: SignMode,
}

struct OneShotRng([u8; 32]);

impl rand_core::TryRng for OneShotRng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        unreachable!("ml-dsa only calls try_fill_bytes")
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        unreachable!("ml-dsa only calls try_fill_bytes")
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        let n = dst.len().min(32);
        dst[..n].copy_from_slice(&self.0[..n]);
        Ok(())
    }
}

impl rand_core::TryCryptoRng for OneShotRng {}

pub fn mldsa_sign(id: &Identity, msg: &[u8], mode: SignMode) -> Result<Vec<u8>, AtepError> {
    let sk = MlDsaSigningKey::<MlDsa65>::from_seed(&id.seeds().mldsa65.into());
    let sig = match mode {
        SignMode::Deterministic => ml_dsa::Signer::sign(&sk, msg),
        SignMode::Hedged => {
            let mut rnd = [0u8; 32];
            fill_random(&mut rnd)?;
            sk.expanded_key()
                .sign_randomized(msg, &[], &mut OneShotRng(rnd))
                .map_err(|_| AtepError::new("ML-DSA signing failed"))?
        }
    };
    Ok(ml_dsa::SignatureEncoding::to_vec(&sig))
}

pub fn ed_sign(id: &Identity, msg: &[u8]) -> Vec<u8> {
    let sk = ed25519_dalek::SigningKey::from_bytes(&id.seeds().ed25519);
    sk.sign(msg).to_bytes().to_vec()
}

pub fn sign_raw(spec: &RawSpec) -> Result<Vec<u8>, AtepError> {
    let body_protected = spec.headers.encode();
    let mut sigs = Vec::new();
    if let Some(ed) = spec.ed_signer {
        let prot = signature_protected(ALG_EDDSA, &spec.kid);
        let msg = sig_structure(&body_protected, &prot, &spec.payload);
        sigs.push(Value::Array(vec![
            Value::Bytes(prot),
            Value::Map(vec![]),
            Value::Bytes(ed_sign(ed, &msg)),
        ]));
    }
    if let Some(pq) = spec.pq_signer {
        let prot = signature_protected(ALG_MLDSA65, &spec.kid);
        let msg = sig_structure(&body_protected, &prot, &spec.payload);
        sigs.push(Value::Array(vec![
            Value::Bytes(prot),
            Value::Map(vec![]),
            Value::Bytes(mldsa_sign(pq, &msg, spec.mode)?),
        ]));
    }
    let mut unprot = Vec::new();
    if let Some(b) = &spec.bundle_in_header {
        unprot.push((Value::Int(HDR_SIGNER_BUNDLE), b.to_value()));
    }
    let payload = if spec.attach_payload {
        Value::bytes(&spec.payload)
    } else {
        Value::Null
    };
    Ok(Value::Tag(
        TAG_COSE_SIGN,
        Box::new(Value::Array(vec![
            Value::Bytes(body_protected),
            Value::Map(unprot),
            payload,
            Value::Array(sigs),
        ])),
    )
    .encode())
}

/// Sign `params.payload` as `identity` and return the tag 98 envelope bytes.
pub fn sign(identity: &Identity, params: &SignParams) -> Result<Vec<u8>, AtepError> {
    if params.content_type == CT_ATTESTATION && params.expires_at.is_none() {
        return Err(AtepError::new(
            "expires-at is REQUIRED for attestations (spec section 5)",
        ));
    }
    if let Some(e) = params.expires_at {
        if e <= params.issued_at {
            return Err(AtepError::new("expires-at must be later than issued-at"));
        }
    }
    let id: AgentId = identity.agent_id();
    let headers = Headers {
        content_type: params.content_type.to_string(),
        version: ATEP_VERSION,
        signer: id.0,
        issued_at: params.issued_at,
        expires_at: params.expires_at,
        nonce: params.nonce,
        payload_digest: sha256(params.payload),
        suite: SUITE_ATEP_1.to_string(),
        command_class: params.command_class.map(str::to_string),
    };
    sign_raw(&RawSpec {
        headers,
        payload: params.payload.to_vec(),
        attach_payload: !params.detached,
        bundle_in_header: params.include_bundle.then(|| identity.public().clone()),
        ed_signer: Some(identity),
        pq_signer: Some(identity),
        kid: id.0,
        mode: params.mode,
    })
}

/// Set entries in the unprotected header of a tag 98 envelope and return the
/// re-encoded bytes. The unprotected header is not signed, so this does not
/// touch the signatures. An entry whose value is `None` is removed.
pub fn with_unprotected(
    envelope: &[u8],
    entries: Vec<(i64, Option<Value>)>,
) -> Result<Vec<u8>, AtepError> {
    let mut v = Value::decode(envelope)?;
    let Value::Tag(_, inner) = &mut v else {
        return Err(AtepError::new("not a tagged envelope"));
    };
    let Value::Array(a) = inner.as_mut() else {
        return Err(AtepError::new("envelope is not an array"));
    };
    let Value::Map(m) = &mut a[1] else {
        return Err(AtepError::new("unprotected header is not a map"));
    };
    for (label, val) in entries {
        m.retain(|(k, _)| *k != Value::Int(label));
        if let Some(val) = val {
            m.push((Value::Int(label), val));
        }
    }
    Ok(v.encode())
}

/// The envelope as it would have been submitted to a log: the unprotected
/// inclusion proof (-70012) removed, everything else unchanged.
pub fn submitted_form(envelope: &[u8]) -> Result<Vec<u8>, AtepError> {
    with_unprotected(envelope, vec![(HDR_INCLUSION_PROOF, None)])
}
