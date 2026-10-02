//! Anchoring hooks (anchoring hooks, spec section 9): the data formats only.
//!
//! Anchoring is an optional feature of a transparency log. A log may write the
//! hash of a checkpoint to an external witness and publish an [`AnchorRecord`]
//! for it. Nothing here talks to a chain and nothing here depends on one: this
//! module defines the record, the `chain-id` registry stub and the
//! `require-anchor` policy rule. Producing anchors lives in `atep-log` behind
//! the `Witness` trait; evaluating the rule is "not supported in this build".

use crate::attestation::{fixed_bytes, schema, text_entries, uint, SchemaError};
use crate::cbor::Value;
use crate::consts::CT_ANCHOR;
use crate::error::{AtepError, ErrorCode, Rejection};
use crate::keys::AgentId;
use crate::verify::{verify, Policy};

/// Registered `chain-id` values (registry stub, spec amendment). Each entry is
/// `(id, description)`. Adding a registered chain is a one line change here.
pub const CHAIN_IDS: &[(&str, &str)] = &[
    ("solana-mainnet", "Solana mainnet-beta"),
    ("ethereum-mainnet", "Ethereum mainnet"),
    ("bitcoin-mainnet", "Bitcoin mainnet, direct transaction"),
    (
        "opentimestamps",
        "Bitcoin via an OpenTimestamps calendar (aggregated)",
    ),
    (
        "rekor",
        "Sigstore Rekor public append-only log (not a chain)",
    ),
];

/// Prefix of the extension namespace for unregistered witnesses.
pub const CHAIN_EXTENSION_PREFIX: &str = "x-";

/// Longest accepted `chain-id`, bytes.
pub const MAX_CHAIN_ID_LEN: usize = 64;

/// Is `id` in the registry table.
pub fn is_registered_chain(id: &str) -> bool {
    CHAIN_IDS.iter().any(|(i, _)| *i == id)
}

/// Is `id` a well formed extension id: `x-` followed by a lowercase name of
/// letters, digits and inner hyphens, at most [`MAX_CHAIN_ID_LEN`] bytes total.
pub fn is_extension_chain(id: &str) -> bool {
    let Some(name) = id.strip_prefix(CHAIN_EXTENSION_PREFIX) else {
        return false;
    };
    let b = name.as_bytes();
    !b.is_empty()
        && id.len() <= MAX_CHAIN_ID_LEN
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && b[0] != b'-'
        && b[b.len() - 1] != b'-'
}

/// A `chain-id` must be registered or a well formed extension id.
pub fn validate_chain_id(id: &str) -> Result<(), AtepError> {
    if is_registered_chain(id) || is_extension_chain(id) {
        Ok(())
    } else {
        Err(AtepError::new(format!(
            "unknown chain-id `{id}`: use a registered id or an extension id of the form `x-<name>`"
        )))
    }
}

/// An anchor record (unsigned body): evidence that `checkpoint_hash` was
/// written to the witness `chain_id`. The log signs it, see
/// `atep_log::anchor`. Payload of `application/atep-anchor+cbor`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorRecord {
    /// `SHA-256` of the checkpoint payload (`log::checkpoint_hash`).
    pub checkpoint_hash: [u8; 32],
    pub chain_id: String,
    /// Transaction (or proof) identifier on that chain, as the chain prints it.
    pub transaction_id: String,
    /// Block height; omitted for witnesses that have none (`rekor`).
    pub block_height: Option<i64>,
    /// Unix seconds: the witness's time for the anchor.
    pub anchored_at: i64,
}

impl AnchorRecord {
    pub fn to_value(&self) -> Value {
        let mut m = vec![
            (
                Value::text("checkpoint-hash"),
                Value::bytes(&self.checkpoint_hash),
            ),
            (Value::text("chain-id"), Value::text(&self.chain_id)),
            (
                Value::text("transaction-id"),
                Value::text(&self.transaction_id),
            ),
            (Value::text("anchored-at"), Value::Int(self.anchored_at)),
        ];
        if let Some(h) = self.block_height {
            m.push((Value::text("block-height"), Value::Int(h)));
        }
        Value::Map(m)
    }

    pub fn encode(&self) -> Vec<u8> {
        self.to_value().encode()
    }

    pub fn from_value(v: &Value) -> Result<AnchorRecord, SchemaError> {
        let (mut hash, mut chain, mut tx, mut height, mut at) = (None, None, None, None, None);
        for (k, val) in text_entries(v)? {
            match k {
                "checkpoint-hash" => hash = Some(fixed_bytes::<32>(val, k)?),
                "chain-id" => {
                    let Some(s) = val.as_text() else {
                        return schema("`chain-id` must be text");
                    };
                    validate_chain_id(s).map_err(|e| SchemaError(e.0))?;
                    chain = Some(s.to_string());
                }
                "transaction-id" => match val.as_text() {
                    Some(s) if !s.is_empty() && s.len() <= 512 => tx = Some(s.to_string()),
                    _ => {
                        return schema(
                            "`transaction-id` must be non-empty text of at most 512 bytes",
                        )
                    }
                },
                "block-height" => height = Some(uint(val, k)?),
                "anchored-at" => at = Some(uint(val, k)?),
                other => return schema(format!("unknown field `{other}`")),
            }
        }
        let need = |n: &str| SchemaError(format!("missing field `{n}`"));
        Ok(AnchorRecord {
            checkpoint_hash: hash.ok_or_else(|| need("checkpoint-hash"))?,
            chain_id: chain.ok_or_else(|| need("chain-id"))?,
            transaction_id: tx.ok_or_else(|| need("transaction-id"))?,
            block_height: height,
            anchored_at: at.ok_or_else(|| need("anchored-at"))?,
        })
    }

    pub fn from_payload(payload: &[u8]) -> Result<AnchorRecord, SchemaError> {
        let v = Value::decode(payload).map_err(|e| SchemaError(e.to_string()))?;
        AnchorRecord::from_value(&v)
    }
}

/// Verify a log-signed anchor envelope: steps 1 to 8 of spec section 10 (a
/// failure is returned as it is), then the content type
/// (`anchor_content_type_invalid`) and the record schema
/// (`anchor_schema_invalid`), both at step 9. Returns the signing identity and
/// the record. Trust in the signer is the caller's decision, see
/// [`check_published_anchor`].
pub fn parse_anchor_envelope(raw: &[u8], now: i64) -> Result<(AgentId, AnchorRecord), Rejection> {
    let v = verify(raw, &Policy::default(), now)?;
    if v.content_type != CT_ANCHOR {
        return Err(Rejection::new(
            9,
            ErrorCode::AnchorContentTypeInvalid,
            format!("content type `{}` is not an anchor record", v.content_type),
        ));
    }
    let rec = AnchorRecord::from_payload(&v.payload)
        .map_err(|e| Rejection::new(9, ErrorCode::AnchorSchemaInvalid, e.0))?;
    Ok((v.signer, rec))
}

/// Take an anchor record as published (spec section 9, "Anchor records"):
/// the envelope verifies and carries a valid record, its signer is `log`, the
/// log the caller asked about, and its `checkpoint-hash` equals
/// `checkpoint_hash`, the hash of the checkpoint the caller is looking at.
/// The checks run in that order; `anchor_log_mismatch` and
/// `anchor_checkpoint_mismatch` are step 9 rejections. Whether the witness
/// really holds the hash is not checked (milestone M5).
pub fn check_published_anchor(
    raw: &[u8],
    log: &AgentId,
    checkpoint_hash: &[u8; 32],
    now: i64,
) -> Result<AnchorRecord, Rejection> {
    let (signer, rec) = parse_anchor_envelope(raw, now)?;
    if signer != *log {
        return Err(Rejection::new(
            9,
            ErrorCode::AnchorLogMismatch,
            format!("anchor record is signed by {signer}, not by the log {log}"),
        ));
    }
    if rec.checkpoint_hash != *checkpoint_hash {
        return Err(Rejection::new(
            9,
            ErrorCode::AnchorCheckpointMismatch,
            "anchor record is for another checkpoint",
        ));
    }
    Ok(rec)
}

/// Maximum age of an anchor accepted by a `require-anchor` rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorMaxAge {
    Hours(u64),
    Days(u64),
}

impl AnchorMaxAge {
    pub fn as_secs(&self) -> u64 {
        match self {
            AnchorMaxAge::Hours(h) => h.saturating_mul(3600),
            AnchorMaxAge::Days(d) => d.saturating_mul(86_400),
        }
    }
}

/// `require-anchor { log, chain, max_age_days | max_age_hours }`: accept
/// checkpoints of `log` only if anchored on `chain` within the maximum age.
/// Parsed and validated here; evaluation is not supported in this build.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorRule {
    pub log: crate::keys::AgentId,
    pub chain: String,
    pub max_age: AnchorMaxAge,
}

fn perr(msg: impl Into<String>) -> AtepError {
    AtepError::new(format!("policy: require_anchor: {}", msg.into()))
}

impl AnchorRule {
    /// Parse one JSON rule object. Unknown keys are errors.
    pub fn from_json(j: &serde_json::Value) -> Result<AnchorRule, AtepError> {
        let o = j
            .as_object()
            .ok_or_else(|| perr("a rule must be an object"))?;
        let (mut log, mut chain, mut days, mut hours) = (None, None, None, None);
        for (k, v) in o {
            match k.as_str() {
                "log" => {
                    log = Some(crate::keys::AgentId::parse(
                        v.as_str().ok_or_else(|| perr("`log` must be a string"))?,
                    )?)
                }
                "chain" => {
                    let s = v.as_str().ok_or_else(|| perr("`chain` must be a string"))?;
                    validate_chain_id(s).map_err(|e| perr(e.0))?;
                    chain = Some(s.to_string());
                }
                "max_age_days" => {
                    days =
                        Some(v.as_u64().filter(|n| *n >= 1).ok_or_else(|| {
                            perr("`max_age_days` must be an integer of at least 1")
                        })?)
                }
                "max_age_hours" => {
                    hours =
                        Some(v.as_u64().filter(|n| *n >= 1).ok_or_else(|| {
                            perr("`max_age_hours` must be an integer of at least 1")
                        })?)
                }
                other => return Err(perr(format!("unknown key `{other}`"))),
            }
        }
        let max_age = match (days, hours) {
            (Some(d), None) => AnchorMaxAge::Days(d),
            (None, Some(h)) => AnchorMaxAge::Hours(h),
            _ => {
                return Err(perr(
                    "give exactly one of `max_age_days` and `max_age_hours`",
                ))
            }
        };
        Ok(AnchorRule {
            log: log.ok_or_else(|| perr("a rule needs a `log`"))?,
            chain: chain.ok_or_else(|| perr("a rule needs a `chain`"))?,
            max_age,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec() -> AnchorRecord {
        AnchorRecord {
            checkpoint_hash: [7; 32],
            chain_id: "solana-mainnet".into(),
            transaction_id: "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnb".into(),
            block_height: Some(280_000_000),
            anchored_at: 1_800_000_000,
        }
    }

    #[test]
    fn record_roundtrip_and_determinism() {
        let r = rec();
        let enc = r.encode();
        assert_eq!(AnchorRecord::from_payload(&enc).unwrap(), r);
        assert_eq!(r.to_value().encode(), enc);
        let mut no_height = r.clone();
        no_height.block_height = None;
        assert_eq!(
            AnchorRecord::from_payload(&no_height.encode()).unwrap(),
            no_height
        );
    }

    #[test]
    fn record_schema_errors() {
        let mut r = rec();
        r.chain_id = "dogecoin".into();
        assert!(AnchorRecord::from_payload(&r.encode()).is_err());
        let mut v = rec().to_value();
        if let Value::Map(m) = &mut v {
            m.push((Value::text("extra"), Value::Int(1)));
        }
        assert!(AnchorRecord::from_value(&v).is_err());
        let mut v = rec().to_value();
        if let Value::Map(m) = &mut v {
            m.retain(|(k, _)| k.as_text() != Some("anchored-at"));
        }
        assert!(AnchorRecord::from_value(&v).is_err());
    }

    #[test]
    fn chain_id_registry() {
        for (id, _) in CHAIN_IDS {
            assert!(validate_chain_id(id).is_ok());
            assert!(!id.starts_with(CHAIN_EXTENSION_PREFIX));
        }
        for ok in ["x-acme", "x-acme-chain-2", "x-1"] {
            assert!(validate_chain_id(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "x-",
            "x--",
            "x-Acme",
            "x-acme-",
            "x-a_b",
            "solana",
            "Solana-mainnet",
            "x-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert!(validate_chain_id(bad).is_err(), "{bad}");
        }
    }
}
