//! Key bundles, Agent IDs and secret key handling (spec section 4).

use std::fmt;
use std::str::FromStr;

use ed25519_dalek::SigningKey as EdSigningKey;
use ml_dsa::{MlDsa65, SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey};
use ml_kem::{kem::KeyExport, MlKem768};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::cbor::Value;
use crate::consts::*;
use crate::error::AtepError;

pub const ED25519_PUB_LEN: usize = 32;
pub const MLDSA65_PUB_LEN: usize = 1952;
pub const MLDSA65_SIG_LEN: usize = 3309;
pub const X25519_PUB_LEN: usize = 32;
pub const MLKEM768_PUB_LEN: usize = 1184;
pub const MLKEM768_CT_LEN: usize = 1088;

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// 32-byte Agent ID: SHA-256 of the canonical CBOR public bundle.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AgentId(pub [u8; 32]);

impl AgentId {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Unpadded lowercase base32 of the 32 bytes (52 characters).
    pub fn base32(&self) -> String {
        base32::RFC4648_LOWER_NOPAD.encode(&self.0)
    }

    /// Canonical text form, `atep:` plus base32.
    pub fn to_text(&self) -> String {
        format!("atep:{}", self.base32())
    }

    /// DID alias, `did:atep:` plus the identical base32 string.
    pub fn to_did(&self) -> String {
        format!("did:atep:{}", self.base32())
    }

    /// Parse either the `atep:` or the `did:atep:` form.
    pub fn parse(s: &str) -> Result<AgentId, AtepError> {
        let b32 = if let Some(r) = s.strip_prefix("did:atep:") {
            r
        } else if let Some(r) = s.strip_prefix("atep:") {
            r
        } else {
            return Err(AtepError::new(
                "agent id must start with `atep:` or `did:atep:`",
            ));
        };
        if b32.len() != 52 {
            return Err(AtepError::new("agent id base32 part must be 52 characters"));
        }
        let bytes = base32::RFC4648_LOWER_NOPAD.decode(b32).map_err(|e| {
            AtepError::new(format!("agent id is not valid lowercase base32: {e:?}"))
        })?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| AtepError::new("agent id must decode to 32 bytes"))?;
        let id = AgentId(arr);
        if id.base32() != b32 {
            return Err(AtepError::new("agent id is not in canonical base32 form"));
        }
        Ok(id)
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_text())
    }
}

impl fmt::Debug for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AgentId({})", self.to_text())
    }
}

impl FromStr for AgentId {
    type Err = AtepError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        AgentId::parse(s)
    }
}

/// Raw secret seeds. All fields are zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Seeds {
    /// Ed25519 secret key (RFC 8032 seed).
    pub ed25519: [u8; 32],
    /// ML-DSA-65 seed xi (FIPS 204 KeyGen_internal).
    pub mldsa65: [u8; 32],
    /// X25519 secret scalar bytes (clamped on use per RFC 7748).
    pub x25519: Option<[u8; 32]>,
    /// ML-KEM-768 seed d || z (FIPS 203 KeyGen_internal, 64 bytes).
    pub mlkem768: Option<[u8; 64]>,
}

impl Seeds {
    pub fn random(with_enc: bool) -> Result<Seeds, AtepError> {
        let mut s = Seeds {
            ed25519: [0; 32],
            mldsa65: [0; 32],
            x25519: None,
            mlkem768: None,
        };
        fill_random(&mut s.ed25519)?;
        fill_random(&mut s.mldsa65)?;
        if with_enc {
            let mut x = [0u8; 32];
            let mut k = [0u8; 64];
            fill_random(&mut x)?;
            fill_random(&mut k)?;
            s.x25519 = Some(x);
            s.mlkem768 = Some(k);
        }
        Ok(s)
    }
}

pub fn fill_random(buf: &mut [u8]) -> Result<(), AtepError> {
    getrandom::fill(buf).map_err(|e| AtepError::new(format!("system randomness failed: {e}")))
}

/// Public key bundle `[sig_classical_key, sig_pq_key, enc_keys?]`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublicBundle {
    pub ed25519: [u8; 32],
    pub mldsa65: Vec<u8>,
    pub enc: Option<EncPublic>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EncPublic {
    pub x25519: [u8; 32],
    pub mlkem768: Vec<u8>,
}

fn cose_key_okp(crv: i64, alg: i64, x: &[u8]) -> Value {
    Value::Map(vec![
        (Value::Int(KEY_KTY), Value::Int(KTY_OKP)),
        (Value::Int(KEY_ALG), Value::Int(alg)),
        (Value::Int(KEY_NEG1), Value::Int(crv)),
        (Value::Int(KEY_NEG2), Value::bytes(x)),
    ])
}

fn cose_key_akp(alg: i64, public: &[u8]) -> Value {
    Value::Map(vec![
        (Value::Int(KEY_KTY), Value::Int(KTY_AKP)),
        (Value::Int(KEY_ALG), Value::Int(alg)),
        (Value::Int(KEY_NEG1), Value::bytes(public)),
    ])
}

/// COSE_Key for an X25519 public key (also used for ephemeral keys).
pub fn x25519_cose_key(x: &[u8; 32]) -> Value {
    cose_key_okp(CRV_X25519, ALG_ECDH_ES_HKDF_256, x)
}

pub fn parse_okp(v: &Value, crv: i64, alg: i64) -> Result<[u8; 32], AtepError> {
    let m = v
        .as_map()
        .ok_or_else(|| AtepError::new("COSE_Key is not a map"))?;
    if m.len() != 4
        || v.map_get_int(KEY_KTY) != Some(&Value::Int(KTY_OKP))
        || v.map_get_int(KEY_ALG) != Some(&Value::Int(alg))
        || v.map_get_int(KEY_NEG1) != Some(&Value::Int(crv))
    {
        return Err(AtepError::new("COSE_Key is not the expected OKP key"));
    }
    let x = v
        .map_get_int(KEY_NEG2)
        .and_then(|x| x.as_bytes())
        .ok_or_else(|| AtepError::new("COSE_Key lacks x"))?;
    x.try_into()
        .map_err(|_| AtepError::new("OKP key must be 32 bytes"))
}

pub fn parse_akp(v: &Value, alg: i64, len: usize) -> Result<Vec<u8>, AtepError> {
    let m = v
        .as_map()
        .ok_or_else(|| AtepError::new("COSE_Key is not a map"))?;
    if m.len() != 3
        || v.map_get_int(KEY_KTY) != Some(&Value::Int(KTY_AKP))
        || v.map_get_int(KEY_ALG) != Some(&Value::Int(alg))
    {
        return Err(AtepError::new("COSE_Key is not the expected AKP key"));
    }
    let p = v
        .map_get_int(KEY_NEG1)
        .and_then(|x| x.as_bytes())
        .ok_or_else(|| AtepError::new("COSE_Key lacks public key"))?;
    if p.len() != len {
        return Err(AtepError::new(format!(
            "AKP public key must be {len} bytes, got {}",
            p.len()
        )));
    }
    Ok(p.to_vec())
}

impl PublicBundle {
    pub fn to_value(&self) -> Value {
        let mut a = vec![
            cose_key_okp(CRV_ED25519, ALG_EDDSA, &self.ed25519),
            cose_key_akp(ALG_MLDSA65, &self.mldsa65),
        ];
        if let Some(e) = &self.enc {
            a.push(Value::Array(vec![
                x25519_cose_key(&e.x25519),
                cose_key_akp(ALG_MLKEM768, &e.mlkem768),
            ]));
        }
        Value::Array(a)
    }

    /// Canonical deterministic CBOR encoding of the bundle.
    pub fn encode(&self) -> Vec<u8> {
        self.to_value().encode()
    }

    pub fn from_value(v: &Value) -> Result<PublicBundle, AtepError> {
        let a = v
            .as_array()
            .ok_or_else(|| AtepError::new("bundle is not an array"))?;
        if a.len() != 2 && a.len() != 3 {
            return Err(AtepError::new("bundle must have 2 or 3 elements"));
        }
        let ed = parse_okp(&a[0], CRV_ED25519, ALG_EDDSA)?;
        ed25519_dalek::VerifyingKey::from_bytes(&ed)
            .map_err(|_| AtepError::new("Ed25519 public key is not a valid point"))?;
        let pq = parse_akp(&a[1], ALG_MLDSA65, MLDSA65_PUB_LEN)?;
        let enc = if a.len() == 3 {
            let e = a[2]
                .as_array()
                .filter(|e| e.len() == 2)
                .ok_or_else(|| AtepError::new("enc_keys must be a 2 element array"))?;
            let x = parse_okp(&e[0], CRV_X25519, ALG_ECDH_ES_HKDF_256)?;
            let k = parse_akp(&e[1], ALG_MLKEM768, MLKEM768_PUB_LEN)?;
            mlkem_encapsulation_key(&k)?;
            Some(EncPublic {
                x25519: x,
                mlkem768: k,
            })
        } else {
            None
        };
        Ok(PublicBundle {
            ed25519: ed,
            mldsa65: pq,
            enc,
        })
    }

    pub fn decode(data: &[u8]) -> Result<PublicBundle, AtepError> {
        PublicBundle::from_value(&Value::decode(data)?)
    }

    pub fn agent_id(&self) -> AgentId {
        AgentId(sha256(&self.encode()))
    }

    pub fn verify_ed25519(&self, msg: &[u8], sig: &[u8]) -> bool {
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&self.ed25519) else {
            return false;
        };
        let Ok(sig) = ed25519_dalek::Signature::from_slice(sig) else {
            return false;
        };
        vk.verify_strict(msg, &sig).is_ok()
    }

    pub fn verify_mldsa65(&self, msg: &[u8], sig: &[u8]) -> bool {
        let Ok(pk) = self.mldsa65.as_slice().try_into() else {
            return false;
        };
        let vk = MlDsaVerifyingKey::<MlDsa65>::decode(&pk);
        let Ok(sig_arr) = sig.try_into() else {
            return false;
        };
        let Some(sig) = ml_dsa::Signature::<MlDsa65>::decode(&sig_arr) else {
            return false;
        };
        ml_dsa::Verifier::verify(&vk, msg, &sig).is_ok()
    }
}

pub fn mlkem_encapsulation_key(
    bytes: &[u8],
) -> Result<ml_kem::EncapsulationKey<MlKem768>, AtepError> {
    let arr = bytes
        .try_into()
        .map_err(|_| AtepError::new("ML-KEM-768 public key has wrong length"))?;
    ml_kem::EncapsulationKey::<MlKem768>::new(&arr)
        .map_err(|_| AtepError::new("ML-KEM-768 public key failed validation"))
}

/// An agent identity: secret seeds plus the derived public bundle.
pub struct Identity {
    seeds: Seeds,
    bundle: PublicBundle,
    id: AgentId,
}

impl Identity {
    pub fn from_seeds(seeds: Seeds) -> Result<Identity, AtepError> {
        if seeds.x25519.is_some() != seeds.mlkem768.is_some() {
            return Err(AtepError::new(
                "x25519 and mlkem768 seeds must be both present or both absent",
            ));
        }
        let ed = EdSigningKey::from_bytes(&seeds.ed25519)
            .verifying_key()
            .to_bytes();
        let mldsa = MlDsaSigningKey::<MlDsa65>::from_seed(&seeds.mldsa65.into());
        let mldsa_pub = ml_dsa::Keypair::verifying_key(&mldsa).encode().to_vec();
        let enc = match (&seeds.x25519, &seeds.mlkem768) {
            (Some(x), Some(k)) => {
                let xp = x25519_dalek::x25519(*x, x25519_dalek::X25519_BASEPOINT_BYTES);
                let dk = ml_kem::DecapsulationKey::<MlKem768>::from_seed((*k).into());
                let kp = dk.encapsulation_key().to_bytes().to_vec();
                Some(EncPublic {
                    x25519: xp,
                    mlkem768: kp,
                })
            }
            _ => None,
        };
        let bundle = PublicBundle {
            ed25519: ed,
            mldsa65: mldsa_pub,
            enc,
        };
        let id = bundle.agent_id();
        Ok(Identity { seeds, bundle, id })
    }

    pub fn generate(with_enc: bool) -> Result<Identity, AtepError> {
        Identity::from_seeds(Seeds::random(with_enc)?)
    }

    pub fn seeds(&self) -> &Seeds {
        &self.seeds
    }

    pub fn public(&self) -> &PublicBundle {
        &self.bundle
    }

    pub fn agent_id(&self) -> AgentId {
        self.id
    }

    /// Secret key file: CBOR map with text keys
    /// `{"atep-secret-key": 1, "ed25519": bstr, "mldsa65": bstr, "x25519"?: bstr, "mlkem768"?: bstr}`.
    pub fn to_secret_file(&self) -> Vec<u8> {
        let mut m = vec![
            (Value::text("atep-secret-key"), Value::Int(1)),
            (Value::text("ed25519"), Value::bytes(&self.seeds.ed25519)),
            (Value::text("mldsa65"), Value::bytes(&self.seeds.mldsa65)),
        ];
        if let (Some(x), Some(k)) = (&self.seeds.x25519, &self.seeds.mlkem768) {
            m.push((Value::text("x25519"), Value::bytes(x)));
            m.push((Value::text("mlkem768"), Value::bytes(k)));
        }
        Value::Map(m).encode()
    }

    pub fn from_secret_file(data: &[u8]) -> Result<Identity, AtepError> {
        let v = Value::decode(data)?;
        let m = v
            .as_map()
            .ok_or_else(|| AtepError::new("secret key file is not a CBOR map"))?;
        let get = |name: &str| {
            m.iter()
                .find(|(k, _)| k.as_text() == Some(name))
                .map(|(_, v)| v)
        };
        if get("atep-secret-key") != Some(&Value::Int(1)) {
            return Err(AtepError::new(
                "not an ATEP secret key file (missing `atep-secret-key: 1`)",
            ));
        }
        let fixed = |name: &str, len: usize| -> Result<Option<Vec<u8>>, AtepError> {
            match get(name) {
                None => Ok(None),
                Some(v) => {
                    let b = v
                        .as_bytes()
                        .filter(|b| b.len() == len)
                        .ok_or_else(|| AtepError::new(format!("`{name}` must be {len} bytes")))?;
                    Ok(Some(b.to_vec()))
                }
            }
        };
        let ed = fixed("ed25519", 32)?.ok_or_else(|| AtepError::new("missing `ed25519`"))?;
        let ml = fixed("mldsa65", 32)?.ok_or_else(|| AtepError::new("missing `mldsa65`"))?;
        let x = fixed("x25519", 32)?;
        let k = fixed("mlkem768", 64)?;
        let seeds = Seeds {
            ed25519: ed.try_into().unwrap(),
            mldsa65: ml.try_into().unwrap(),
            x25519: x.map(|v| v.try_into().unwrap()),
            mlkem768: k.map(|v| v.try_into().unwrap()),
        };
        Identity::from_seeds(seeds)
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Identity({})", self.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_seeds(enc: bool) -> Seeds {
        Seeds {
            ed25519: [1; 32],
            mldsa65: [2; 32],
            x25519: enc.then_some([3; 32]),
            mlkem768: enc.then_some([4; 64]),
        }
    }

    #[test]
    fn id_text_forms() {
        let id = Identity::from_seeds(fixed_seeds(true)).unwrap();
        let t = id.agent_id().to_text();
        assert!(t.starts_with("atep:"));
        assert_eq!(t.len(), 5 + 52);
        assert_eq!(AgentId::parse(&t).unwrap(), id.agent_id());
        let d = id.agent_id().to_did();
        assert_eq!(d, format!("did:{t}"));
        assert_eq!(AgentId::parse(&d).unwrap(), id.agent_id());
        assert!(AgentId::parse(&t.to_uppercase()).is_err());
        assert!(AgentId::parse("atep:abc").is_err());
    }

    #[test]
    fn bundle_round_trip_and_commitment() {
        let a = Identity::from_seeds(fixed_seeds(false)).unwrap();
        let b = Identity::from_seeds(fixed_seeds(true)).unwrap();
        assert_ne!(a.agent_id(), b.agent_id());
        let enc = b.public().encode();
        let back = PublicBundle::decode(&enc).unwrap();
        assert_eq!(&back, b.public());
        assert_eq!(back.agent_id(), b.agent_id());
        assert_eq!(a.public().mldsa65.len(), MLDSA65_PUB_LEN);
    }

    #[test]
    fn secret_file_round_trip() {
        let a = Identity::from_seeds(fixed_seeds(true)).unwrap();
        let back = Identity::from_secret_file(&a.to_secret_file()).unwrap();
        assert_eq!(back.agent_id(), a.agent_id());
    }
}
