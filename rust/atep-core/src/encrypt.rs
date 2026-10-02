//! Hybrid encryption: COSE_Encrypt (tag 96) around a signed envelope
//! (spec sections 5 and 6, sign-then-encrypt).
//!
//! Construction:
//! * KEM: X25519 (ephemeral sender key) plus ML-KEM-768 encapsulation.
//! * KDF: HKDF-SHA-256, salt empty, ikm = ss_x25519 || ss_mlkem768,
//!   info = "ATEP-1-KEM" || eph_x25519_pub || recipient_x25519_pub || mlkem_ciphertext,
//!   output 32 bytes.
//! * AEAD: AES-256-GCM, 12 byte IV, AAD = COSE Enc_structure
//!   `["Encrypt", protected, h'']`.
//!
//! The recipient header is not in the AAD, but its contents (ephemeral key and
//! ML-KEM ciphertext) are bound into the derived key through the HKDF info.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use hkdf::Hkdf;
use ml_kem::kem::Decapsulate;
use ml_kem::MlKem768;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::cbor::Value;
use crate::consts::*;
use crate::error::{AtepError, ErrorCode, Rejection};
use crate::keys::{
    fill_random, mlkem_encapsulation_key, parse_okp, x25519_cose_key, Identity, PublicBundle,
    MLKEM768_CT_LEN,
};

/// Every random input of an encryption, so it can be reproduced exactly.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EncryptRandomness {
    /// Ephemeral X25519 secret scalar bytes.
    pub x25519_ephemeral: [u8; 32],
    /// ML-KEM-768 encapsulation randomness m (FIPS 203 Encaps_internal).
    pub mlkem_m: [u8; 32],
    /// AES-GCM IV.
    pub iv: [u8; 12],
}

impl EncryptRandomness {
    pub fn random() -> Result<Self, AtepError> {
        let mut r = EncryptRandomness {
            x25519_ephemeral: [0; 32],
            mlkem_m: [0; 32],
            iv: [0; 12],
        };
        fill_random(&mut r.x25519_ephemeral)?;
        fill_random(&mut r.mlkem_m)?;
        fill_random(&mut r.iv)?;
        Ok(r)
    }
}

pub fn outer_protected() -> Vec<u8> {
    Value::Map(vec![
        (Value::Int(HDR_ALG), Value::Int(ALG_A256GCM)),
        (Value::Int(HDR_ATEP_VERSION), Value::Int(ATEP_VERSION)),
        (Value::Int(HDR_SUITE), Value::text(SUITE_ATEP_1)),
    ])
    .encode()
}

fn enc_structure(protected: &[u8]) -> Vec<u8> {
    Value::Array(vec![
        Value::text("Encrypt"),
        Value::bytes(protected),
        Value::bytes(&[]),
    ])
    .encode()
}

fn kdf_info(eph_pub: &[u8; 32], recip_x_pub: &[u8; 32], mlkem_ct: &[u8]) -> Vec<u8> {
    let mut info = Vec::new();
    info.extend_from_slice(KEM_CONTEXT);
    info.extend_from_slice(eph_pub);
    info.extend_from_slice(recip_x_pub);
    info.extend_from_slice(mlkem_ct);
    info
}

fn derive_key(
    ss_x: &[u8; 32],
    ss_pq: &[u8],
    eph_pub: &[u8; 32],
    recip_x_pub: &[u8; 32],
    mlkem_ct: &[u8],
) -> Zeroizing<[u8; 32]> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(ss_x);
    ikm.extend_from_slice(ss_pq);
    let info = kdf_info(eph_pub, recip_x_pub, mlkem_ct);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(&info, key.as_mut())
        .expect("32 bytes is a valid HKDF-SHA-256 output length");
    key
}

fn aes(key: &[u8; 32]) -> Aes256Gcm {
    Aes256Gcm::new_from_slice(key).expect("32 byte key")
}

/// Intermediate KEM values, published in the encryption test vectors so an
/// independent implementation can locate a divergence. Secret-bearing; only
/// ever shown for fixed test keys.
#[derive(Clone, Debug)]
pub struct KemTrace {
    pub eph_x25519_public: [u8; 32],
    pub mlkem_ciphertext: Vec<u8>,
    pub ss_x25519: [u8; 32],
    pub ss_mlkem768: Vec<u8>,
    pub hkdf_info: Vec<u8>,
    pub aes_key: [u8; 32],
}

/// Wrap `signed_envelope` (tag 98 bytes) for `recipient`.
pub fn encrypt(
    signed_envelope: &[u8],
    recipient: &PublicBundle,
    rnd: &EncryptRandomness,
) -> Result<Vec<u8>, AtepError> {
    encrypt_traced(signed_envelope, recipient, rnd).map(|(c, _)| c)
}

/// Like `encrypt`, also returning the intermediate KEM values.
pub fn encrypt_traced(
    signed_envelope: &[u8],
    recipient: &PublicBundle,
    rnd: &EncryptRandomness,
) -> Result<(Vec<u8>, KemTrace), AtepError> {
    let enc = recipient
        .enc
        .as_ref()
        .ok_or_else(|| AtepError::new("recipient bundle has no encryption keys"))?;
    let eph_pub = x25519_dalek::x25519(rnd.x25519_ephemeral, x25519_dalek::X25519_BASEPOINT_BYTES);
    let ss_x = Zeroizing::new(x25519_dalek::x25519(rnd.x25519_ephemeral, enc.x25519));
    if ss_x.iter().all(|b| *b == 0) {
        return Err(AtepError::new(
            "recipient X25519 key produced an all-zero shared secret",
        ));
    }
    let ek = mlkem_encapsulation_key(&enc.mlkem768)?;
    let (ct, ss_pq) = ek.encapsulate_deterministic(&rnd.mlkem_m.into());
    let key = derive_key(
        &ss_x,
        ss_pq.as_slice(),
        &eph_pub,
        &enc.x25519,
        ct.as_slice(),
    );
    let trace = KemTrace {
        eph_x25519_public: eph_pub,
        mlkem_ciphertext: ct.as_slice().to_vec(),
        ss_x25519: *ss_x,
        ss_mlkem768: ss_pq.as_slice().to_vec(),
        hkdf_info: kdf_info(&eph_pub, &enc.x25519, ct.as_slice()),
        aes_key: *key,
    };

    let prot = outer_protected();
    let aad = enc_structure(&prot);
    let ciphertext = aes(&key)
        .encrypt(
            &rnd.iv.into(),
            Payload {
                msg: signed_envelope,
                aad: &aad,
            },
        )
        .map_err(|_| AtepError::new("AES-GCM encryption failed"))?;

    let recipient_prot = Value::Map(vec![(
        Value::Int(HDR_ALG),
        Value::Int(ALG_ATEP1_HYBRID_KEM),
    )])
    .encode();
    let recipient_unprot = Value::Map(vec![
        (Value::Int(HDR_EPHEMERAL_KEY), x25519_cose_key(&eph_pub)),
        (Value::Int(HDR_KID), Value::bytes(&recipient.agent_id().0)),
        (Value::Int(HDR_KEM_CIPHERTEXT), Value::bytes(ct.as_slice())),
    ]);
    let out = Value::Tag(
        TAG_COSE_ENCRYPT,
        Box::new(Value::Array(vec![
            Value::Bytes(prot),
            Value::Map(vec![(Value::Int(HDR_IV), Value::bytes(&rnd.iv))]),
            Value::Bytes(ciphertext),
            Value::Array(vec![Value::Array(vec![
                Value::Bytes(recipient_prot),
                recipient_unprot,
                Value::bytes(&[]),
            ])]),
        ])),
    )
    .encode();
    Ok((out, trace))
}

/// Encrypt with fresh system randomness.
pub fn encrypt_random(
    signed_envelope: &[u8],
    recipient: &PublicBundle,
) -> Result<Vec<u8>, AtepError> {
    encrypt(signed_envelope, recipient, &EncryptRandomness::random()?)
}

/// A parsed COSE_Encrypt with one ATEP-1 hybrid KEM recipient.
pub struct EncryptedEnvelope {
    pub protected_raw: Vec<u8>,
    pub iv: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub kid: [u8; 32],
    pub eph_x25519: [u8; 32],
    pub mlkem_ct: Vec<u8>,
}

fn r1(code: ErrorCode, d: &str) -> Rejection {
    Rejection::new(1, code, d)
}

impl EncryptedEnvelope {
    /// Step 1 checks for a tag 96 envelope.
    pub fn from_value(v: &Value) -> Result<EncryptedEnvelope, Rejection> {
        let inner = match v {
            Value::Tag(t, inner) if *t == TAG_COSE_ENCRYPT => inner,
            _ => return Err(r1(ErrorCode::UnexpectedTag, "expected CBOR tag 96")),
        };
        let m = |d: &str| r1(ErrorCode::MalformedStructure, d);
        let a = inner
            .as_array()
            .filter(|a| a.len() == 4)
            .ok_or_else(|| m("COSE_Encrypt must be an array of 4 elements"))?;
        let protected_raw = a[0]
            .as_bytes()
            .ok_or_else(|| m("protected header must be a bstr"))?
            .to_vec();
        let ph = Value::decode(&protected_raw)
            .map_err(|e| r1(ErrorCode::MalformedCbor, &format!("protected header: {e}")))?;
        match ph.map_get_int(HDR_ATEP_VERSION) {
            Some(Value::Int(ATEP_VERSION)) => {}
            Some(Value::Int(n)) => {
                return Err(Rejection::new(
                    1,
                    ErrorCode::UnsupportedVersion,
                    format!("atep-version {n} is not supported"),
                ))
            }
            _ => {
                return Err(r1(
                    ErrorCode::MissingHeader,
                    "atep-version missing in outer header",
                ))
            }
        }
        match ph.map_get_int(HDR_SUITE) {
            Some(Value::Text(s)) if s == SUITE_ATEP_1 => {}
            Some(Value::Text(s)) => {
                return Err(Rejection::new(
                    1,
                    ErrorCode::UnsupportedSuite,
                    format!("suite `{s}` is not supported"),
                ))
            }
            _ => {
                return Err(r1(
                    ErrorCode::MissingHeader,
                    "suite missing in outer header",
                ))
            }
        }
        if ph.map_get_int(HDR_ALG) != Some(&Value::Int(ALG_A256GCM)) {
            return Err(r1(
                ErrorCode::AlgorithmSuiteMismatch,
                "content algorithm is not A256GCM",
            ));
        }
        let unprot = a[1]
            .as_map()
            .ok_or_else(|| m("unprotected header must be a map"))?;
        let _ = unprot;
        let iv: [u8; 12] = a[1]
            .map_get_int(HDR_IV)
            .and_then(|v| v.as_bytes())
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| m("unprotected header needs a 12 byte iv"))?;
        let ciphertext = a[2]
            .as_bytes()
            .ok_or_else(|| m("ciphertext must be a bstr"))?
            .to_vec();
        let recips = a[3]
            .as_array()
            .filter(|r| r.len() == 1)
            .ok_or_else(|| m("exactly one recipient is required"))?;
        let r = recips[0]
            .as_array()
            .filter(|r| r.len() == 3)
            .ok_or_else(|| m("recipient must be an array of 3 elements"))?;
        let rp = r[0]
            .as_bytes()
            .ok_or_else(|| m("recipient protected header must be a bstr"))?;
        let rph = Value::decode(rp)
            .map_err(|e| r1(ErrorCode::MalformedCbor, &format!("recipient header: {e}")))?;
        if rph.map_get_int(HDR_ALG) != Some(&Value::Int(ALG_ATEP1_HYBRID_KEM)) {
            return Err(r1(
                ErrorCode::AlgorithmSuiteMismatch,
                "recipient algorithm is not the ATEP-1 hybrid KEM",
            ));
        }
        if r[1].as_map().is_none() {
            return Err(m("recipient unprotected header must be a map"));
        }
        let kid: [u8; 32] = r[1]
            .map_get_int(HDR_KID)
            .and_then(|v| v.as_bytes())
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| m("recipient kid must be 32 bytes"))?;
        let eph = r[1]
            .map_get_int(HDR_EPHEMERAL_KEY)
            .ok_or_else(|| m("recipient lacks ephemeral key"))?;
        let eph_x25519 = parse_okp(eph, CRV_X25519, ALG_ECDH_ES_HKDF_256)
            .map_err(|e| r1(ErrorCode::MalformedStructure, &e.0))?;
        let mlkem_ct = r[1]
            .map_get_int(HDR_KEM_CIPHERTEXT)
            .and_then(|v| v.as_bytes())
            .filter(|b| b.len() == MLKEM768_CT_LEN)
            .ok_or_else(|| m("recipient needs a 1088 byte ML-KEM-768 ciphertext"))?
            .to_vec();
        Ok(EncryptedEnvelope {
            protected_raw,
            iv,
            ciphertext,
            kid,
            eph_x25519,
            mlkem_ct,
        })
    }

    /// Step 2: hybrid decapsulation and AEAD decryption. Returns the inner
    /// signed envelope bytes.
    pub fn decrypt(&self, recipient: &Identity) -> Result<Vec<u8>, Rejection> {
        let r2 = |code, d: &str| Rejection::new(2, code, d);
        let (Some(x), Some(k)) = (&recipient.seeds().x25519, &recipient.seeds().mlkem768) else {
            return Err(r2(
                ErrorCode::NoRecipientKey,
                "recipient identity has no encryption keys",
            ));
        };
        if self.kid != recipient.agent_id().0 {
            return Err(r2(
                ErrorCode::NotAddressedToRecipient,
                "envelope is addressed to a different Agent ID",
            ));
        }
        let ss_x = Zeroizing::new(x25519_dalek::x25519(*x, self.eph_x25519));
        if ss_x.iter().all(|b| *b == 0) {
            return Err(r2(
                ErrorCode::KemFailure,
                "X25519 shared secret is all zero",
            ));
        }
        let dk = ml_kem::DecapsulationKey::<MlKem768>::from_seed((*k).into());
        let ct = self
            .mlkem_ct
            .as_slice()
            .try_into()
            .map_err(|_| r2(ErrorCode::KemFailure, "bad ML-KEM ciphertext length"))?;
        let ss_pq = dk.decapsulate(&ct);
        let recip_x_pub = recipient
            .public()
            .enc
            .as_ref()
            .expect("identity with seeds has enc keys")
            .x25519;
        let key = derive_key(
            &ss_x,
            ss_pq.as_slice(),
            &self.eph_x25519,
            &recip_x_pub,
            &self.mlkem_ct,
        );
        let aad = enc_structure(&self.protected_raw);
        aes(&key)
            .decrypt(
                &self.iv.into(),
                Payload {
                    msg: &self.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| r2(ErrorCode::AeadFailure, "AEAD authentication failed"))
    }
}

/// Decrypt a tag 96 envelope and return the inner signed envelope bytes.
pub fn decrypt(data: &[u8], recipient: &Identity) -> Result<Vec<u8>, Rejection> {
    let v = Value::decode(data).map_err(|e| r1(ErrorCode::MalformedCbor, &e.to_string()))?;
    EncryptedEnvelope::from_value(&v)?.decrypt(recipient)
}
