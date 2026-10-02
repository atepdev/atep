//! JSON debug rendering of ATEP envelopes (spec section 5): CBOR maps become
//! objects, byte strings become unpadded base64url, labels become names.
//! The view is informational only.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Map, Number, Value as J};

use crate::cbor::Value;
use crate::consts::*;
use crate::error::Rejection;
use crate::verify::Verified;

pub fn b64(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

pub fn alg_name(alg: i64) -> Option<&'static str> {
    Some(match alg {
        ALG_EDDSA => "EdDSA",
        ALG_MLDSA65 => "ML-DSA-65",
        ALG_A256GCM => "A256GCM",
        ALG_ECDH_ES_HKDF_256 => "ECDH-ES+HKDF-256",
        ALG_MLKEM768 => "ML-KEM-768",
        ALG_ATEP1_HYBRID_KEM => "ATEP-1-HYBRID-KEM",
        _ => return None,
    })
}

fn header_label(l: i64) -> Option<&'static str> {
    Some(match l {
        HDR_ALG => "alg",
        HDR_CONTENT_TYPE => "content-type",
        HDR_KID => "kid",
        HDR_IV => "iv",
        HDR_EPHEMERAL_KEY => "ephemeral-key",
        HDR_ATEP_VERSION => "atep-version",
        HDR_SIGNER => "signer",
        HDR_ISSUED_AT => "issued-at",
        HDR_EXPIRES_AT => "expires-at",
        HDR_NONCE => "nonce",
        HDR_PAYLOAD_DIGEST => "payload-digest",
        HDR_SUITE => "suite",
        HDR_SIGNER_BUNDLE => "signer-bundle",
        HDR_ATTESTATIONS => "attestations",
        HDR_INCLUSION_PROOF => "inclusion-proof",
        HDR_COMMAND_CLASS => "command-class",
        HDR_KEM_CIPHERTEXT => "kem-ciphertext",
        _ => return None,
    })
}

fn key_label(l: i64, kty: Option<i64>) -> Option<&'static str> {
    Some(match (l, kty) {
        (KEY_KTY, _) => "kty",
        (KEY_ALG, _) => "alg",
        (KEY_NEG1, Some(KTY_OKP)) => "crv",
        (KEY_NEG1, Some(KTY_AKP)) => "pub",
        (KEY_NEG2, Some(KTY_OKP)) => "x",
        _ => return None,
    })
}

fn num(i: i64) -> J {
    J::Number(Number::from(i))
}

/// Generic CBOR to JSON: text keys stay, integer keys become decimal strings.
pub fn generic(v: &Value) -> J {
    match v {
        Value::Int(i) => num(*i),
        Value::Bytes(b) => J::String(b64(b)),
        Value::Text(s) => J::String(s.clone()),
        Value::Array(a) => J::Array(a.iter().map(generic).collect()),
        Value::Map(m) => {
            let mut o = Map::new();
            for (k, v) in m {
                let key = match k {
                    Value::Text(s) => s.clone(),
                    Value::Int(i) => i.to_string(),
                    other => format!("{other:?}"),
                };
                o.insert(key, generic(v));
            }
            J::Object(o)
        }
        Value::Tag(t, inner) => json!({ "tag": t, "value": generic(inner) }),
        Value::Bool(b) => J::Bool(*b),
        Value::Null => J::Null,
    }
}

pub fn cose_key_view(v: &Value) -> J {
    let kty = v.map_get_int(KEY_KTY).and_then(|k| k.as_int());
    let Some(m) = v.as_map() else {
        return generic(v);
    };
    let mut o = Map::new();
    for (k, val) in m {
        let name = match k {
            Value::Int(l) => key_label(*l, kty)
                .map(str::to_string)
                .unwrap_or_else(|| l.to_string()),
            _ => continue,
        };
        let rendered = match (k, val) {
            (Value::Int(KEY_KTY), Value::Int(t)) => match *t {
                KTY_OKP => J::String("OKP".into()),
                KTY_AKP => J::String("AKP".into()),
                other => num(other),
            },
            (Value::Int(KEY_ALG), Value::Int(a)) => {
                alg_name(*a).map(|n| J::String(n.into())).unwrap_or(num(*a))
            }
            (Value::Int(KEY_NEG1), Value::Int(c)) if kty == Some(KTY_OKP) => match *c {
                CRV_ED25519 => J::String("Ed25519".into()),
                CRV_X25519 => J::String("X25519".into()),
                other => num(other),
            },
            _ => generic(val),
        };
        o.insert(name, rendered);
    }
    J::Object(o)
}

pub fn bundle_view(v: &Value) -> J {
    match v.as_array() {
        Some(a) if a.len() == 2 || a.len() == 3 => {
            let mut o = Map::new();
            o.insert("sig-classical".into(), cose_key_view(&a[0]));
            o.insert("sig-pq".into(), cose_key_view(&a[1]));
            if a.len() == 3 {
                if let Some(e) = a[2].as_array().filter(|e| e.len() == 2) {
                    o.insert(
                        "enc".into(),
                        json!({ "classical": cose_key_view(&e[0]), "pq": cose_key_view(&e[1]) }),
                    );
                } else {
                    o.insert("enc".into(), generic(&a[2]));
                }
            }
            J::Object(o)
        }
        _ => generic(v),
    }
}

fn header_view(v: &Value) -> J {
    let Some(m) = v.as_map() else {
        return generic(v);
    };
    let mut o = Map::new();
    for (k, val) in m {
        let (name, label) = match k {
            Value::Int(l) => (
                header_label(*l)
                    .map(str::to_string)
                    .unwrap_or_else(|| l.to_string()),
                Some(*l),
            ),
            Value::Text(s) => (s.clone(), None),
            _ => continue,
        };
        let rendered = match label {
            Some(HDR_ALG) => val
                .as_int()
                .and_then(alg_name)
                .map(|n| J::String(n.into()))
                .unwrap_or_else(|| generic(val)),
            Some(HDR_EPHEMERAL_KEY) => cose_key_view(val),
            Some(HDR_SIGNER_BUNDLE) => bundle_view(val),
            Some(HDR_ATTESTATIONS) => match val.as_array() {
                Some(a) => J::Array(a.iter().map(view_value).collect()),
                None => generic(val),
            },
            Some(HDR_INCLUSION_PROOF) => match val.as_map() {
                Some(m) => {
                    let mut o = Map::new();
                    for (k, v) in m {
                        let name = k.as_text().unwrap_or("?").to_string();
                        let r = if name == "checkpoint" {
                            view_value(v)
                        } else {
                            generic(v)
                        };
                        o.insert(name, r);
                    }
                    J::Object(o)
                }
                None => generic(val),
            },
            _ => generic(val),
        };
        o.insert(name, rendered);
    }
    J::Object(o)
}

/// A bstr-wrapped protected header: show the decoded map, falling back to base64url.
fn protected_view(raw: &Value) -> J {
    match raw.as_bytes() {
        Some(b) => match Value::decode(b) {
            Ok(v) => header_view(&v),
            Err(_) => J::String(b64(b)),
        },
        None => generic(raw),
    }
}

fn sign_view(inner: &[Value]) -> J {
    let content_type = Value::decode(inner[0].as_bytes().unwrap_or(&[]))
        .ok()
        .and_then(|h| h.map_get_int(HDR_CONTENT_TYPE).cloned())
        .and_then(|c| c.as_text().map(str::to_string));
    let mut o = Map::new();
    o.insert("type".into(), "COSE_Sign".into());
    o.insert("tag".into(), num(TAG_COSE_SIGN as i64));
    o.insert("protected".into(), protected_view(&inner[0]));
    o.insert("unprotected".into(), header_view(&inner[1]));
    o.insert("payload".into(), generic(&inner[2]));
    if let (Some(ct), Value::Bytes(p)) = (&content_type, &inner[2]) {
        if ct.ends_with("cbor") {
            if let Ok(d) = Value::decode(p) {
                o.insert("payload-decoded".into(), generic(&d));
            }
        }
    }
    let sigs = inner[3]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|s| match s.as_array() {
                    Some(s) if s.len() == 3 => json!({
                        "protected": protected_view(&s[0]),
                        "unprotected": header_view(&s[1]),
                        "signature": generic(&s[2]),
                    }),
                    _ => generic(s),
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    o.insert("signatures".into(), J::Array(sigs));
    J::Object(o)
}

fn encrypt_view(inner: &[Value]) -> J {
    let recips = inner[3]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|r| match r.as_array() {
                    Some(r) if r.len() == 3 => json!({
                        "protected": protected_view(&r[0]),
                        "unprotected": header_view(&r[1]),
                        "ciphertext": generic(&r[2]),
                    }),
                    _ => generic(r),
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    json!({
        "type": "COSE_Encrypt",
        "tag": TAG_COSE_ENCRYPT,
        "protected": protected_view(&inner[0]),
        "unprotected": header_view(&inner[1]),
        "ciphertext": generic(&inner[2]),
        "recipients": recips,
    })
}

/// JSON view of any ATEP CBOR object: envelope (tag 98 or 96), bundle, or generic.
pub fn view(data: &[u8]) -> Result<J, crate::cbor::CborError> {
    Ok(view_value(&Value::decode(data)?))
}

/// JSON view of an already decoded value.
pub fn view_value(v: &Value) -> J {
    match v {
        Value::Tag(t, inner) => match (t, inner.as_array()) {
            (&TAG_COSE_SIGN, Some(a)) if a.len() == 4 => sign_view(a),
            (&TAG_COSE_ENCRYPT, Some(a)) if a.len() == 4 => encrypt_view(a),
            _ => generic(v),
        },
        Value::Array(a) if a.len() == 2 || a.len() == 3 => bundle_view(v),
        _ => generic(v),
    }
}

/// Structured JSON form of a verification result, as used in the test vectors.
pub fn verify_result(r: &Result<Verified, Rejection>) -> J {
    match r {
        Ok(v) => {
            let mut o = Map::new();
            o.insert("ok".into(), true.into());
            o.insert("signer".into(), v.signer.to_text().into());
            o.insert("content_type".into(), v.content_type.clone().into());
            o.insert("issued_at".into(), v.issued_at.into());
            o.insert("expires_at".into(), v.expires_at.into());
            o.insert("nonce_hex".into(), hex::encode(v.nonce).into());
            o.insert("encrypted".into(), v.encrypted.into());
            o.insert(
                "claims".into(),
                J::Array(v.claims.iter().map(claim_json).collect()),
            );
            o.insert(
                "checkpoint".into(),
                v.checkpoint
                    .as_ref()
                    .map(checkpoint_json)
                    .unwrap_or(J::Null),
            );
            if let Some(c) = &v.command_class {
                o.insert("command_class".into(), c.clone().into());
            }
            if !v.warnings.is_empty() {
                o.insert("warnings".into(), json!(v.warnings));
            }
            o.insert("payload_hex".into(), hex::encode(&v.payload).into());
            J::Object(o)
        }
        Err(x) => rejection_json(x),
    }
}

pub fn rejection_json(x: &Rejection) -> J {
    let mut o = Map::new();
    o.insert("ok".into(), false.into());
    o.insert("step".into(), x.step.into());
    o.insert("error".into(), x.code.as_str().into());
    if let Some(c) = &x.cause {
        o.insert(
            "cause".into(),
            json!({ "step": c.step, "error": c.code.as_str() }),
        );
    }
    J::Object(o)
}

pub fn checkpoint_json(c: &crate::log::CheckpointUsed) -> J {
    json!({
        "log": c.log.to_text(),
        "tree_size": c.tree_size,
        "root_hash": hex::encode(c.root_hash),
        "timestamp": c.timestamp,
    })
}

pub fn claim_json(c: &crate::trust::VerifiedClaim) -> J {
    json!({
        "claim": c.claim,
        "issuer": c.issuer.to_text(),
        "root": c.root.to_text(),
        "expires_at": c.expires_at,
        "chain": c.chain.iter().map(|l| json!({
            "id": hex::encode(l.id),
            "claim": l.claim,
            "subject": l.subject.to_text(),
            "issuer": l.issuer.to_text(),
            "issued_at": l.issued_at,
            "expires_at": l.expires_at,
        })).collect::<Vec<_>>(),
    })
}
