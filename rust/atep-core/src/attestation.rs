//! Attestations (spec section 7): payload type with strict schema validation,
//! issuance helper, lifetime tiers and the claim-type vocabulary.

use std::fmt;

use crate::cbor::Value;
use crate::consts::*;
use crate::envelope::{sign, SignMode, SignParams};
use crate::error::AtepError;
use crate::keys::{fill_random, AgentId, Identity};

/// Claim type URIs. The core set lives under `https://atep.dev/claims/`, the
/// robotics set (ATEP-R, spec section 17) under `.../robotics/`.
pub mod claims {
    pub const NS: &str = "https://atep.dev/claims/";
    pub const DOMAIN_CONTROL: &str = "https://atep.dev/claims/domain-control";
    pub const OPERATOR: &str = "https://atep.dev/claims/operator";
    pub const SUCCESSOR: &str = "https://atep.dev/claims/successor";
    pub const RETIRED: &str = "https://atep.dev/claims/retired";
    pub const ISSUER_AUTHORITY: &str = "https://atep.dev/claims/issuer-authority";
    pub const AUDITED: &str = "https://atep.dev/claims/audited";
    pub const REGISTRY_ENDPOINT: &str = "https://atep.dev/claims/registry-endpoint";

    /// The seven core claim types (spec section 7). With the seven robotics
    /// claims of section 17 (`operator` is shared) they make the 14 types of
    /// the closed core vocabulary.
    pub const CORE: [&str; 7] = [
        DOMAIN_CONTROL,
        OPERATOR,
        SUCCESSOR,
        RETIRED,
        ISSUER_AUTHORITY,
        AUDITED,
        REGISTRY_ENDPOINT,
    ];

    /// ATEP-R claim vocabulary (spec section 17). `operator` is the core claim.
    pub mod robotics {
        pub const NS: &str = "https://atep.dev/claims/robotics/";
        pub const FLEET_MEMBER: &str = "https://atep.dev/claims/robotics/fleet-member";
        pub const FLEET_CONTROLLER: &str = "https://atep.dev/claims/robotics/fleet-controller";
        pub const SAFETY_CERTIFIED: &str = "https://atep.dev/claims/robotics/safety-certified";
        pub const SENSOR_SOURCE: &str = "https://atep.dev/claims/robotics/sensor-source";
        pub const SAFETY_AUTHORITY: &str = "https://atep.dev/claims/robotics/safety-authority";
        pub const MAINTENANCE_AUTHORITY: &str =
            "https://atep.dev/claims/robotics/maintenance-authority";
        pub const PEER_MOTION: &str = "https://atep.dev/claims/robotics/peer-motion";
        pub const OPERATOR: &str = super::OPERATOR;

        /// The eight ATEP-R claim types.
        pub const ALL: [&str; 8] = [
            FLEET_MEMBER,
            FLEET_CONTROLLER,
            SAFETY_CERTIFIED,
            SENSOR_SOURCE,
            SAFETY_AUTHORITY,
            MAINTENANCE_AUTHORITY,
            PEER_MOTION,
            OPERATOR,
        ];
    }

    /// Expand a short name (`audited`, `fleet-member`, `robotics/peer-motion`)
    /// to its URI. Anything that already looks like a URI is returned as is.
    pub fn expand(name: &str) -> String {
        if name.contains(':') {
            return name.to_string();
        }
        let core = format!("{NS}{name}");
        if CORE.contains(&core.as_str()) || name.starts_with("robotics/") {
            return core;
        }
        let robo = format!("{}{name}", robotics::NS);
        if robotics::ALL.contains(&robo.as_str()) {
            return robo;
        }
        core
    }

    /// Claims whose definition requires an evidence hash (spec sections 7, 17).
    pub fn requires_evidence(claim: &str) -> bool {
        matches!(claim, AUDITED | robotics::SAFETY_CERTIFIED)
    }
}

/// Lifetime class of an attestation (spec section 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifetimeTier {
    /// 30 to 180 days, SHOULD.
    Default,
    /// Up to 400 days: `audited`, `safety-certified` and any claim carrying an
    /// evidence hash.
    AuditBacked,
}

impl LifetimeTier {
    pub fn of(claim: &str, has_evidence: bool) -> LifetimeTier {
        if claims::requires_evidence(claim) || has_evidence {
            LifetimeTier::AuditBacked
        } else {
            LifetimeTier::Default
        }
    }

    /// Longest lifetime this tier allows, seconds.
    pub fn max_secs(self) -> i64 {
        match self {
            LifetimeTier::Default => DEFAULT_ATTESTATION_LIFETIME_SECS,
            LifetimeTier::AuditBacked => MAX_ATTESTATION_LIFETIME_SECS,
        }
    }
}

/// Schema violation in a trust document payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchemaError(pub String);

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SchemaError {}

pub(crate) fn schema<T>(msg: impl Into<String>) -> Result<T, SchemaError> {
    Err(SchemaError(msg.into()))
}

/// Entries of a map whose keys are all text. Rejects other key types.
pub(crate) fn text_entries(v: &Value) -> Result<Vec<(&str, &Value)>, SchemaError> {
    let Some(m) = v.as_map() else {
        return schema("not a map");
    };
    let mut out = Vec::with_capacity(m.len());
    for (k, val) in m {
        match k.as_text() {
            Some(t) => out.push((t, val)),
            None => return schema("map key is not text"),
        }
    }
    Ok(out)
}

pub(crate) fn fixed_bytes<const N: usize>(v: &Value, name: &str) -> Result<[u8; N], SchemaError> {
    match v.as_bytes() {
        Some(b) if b.len() == N => Ok(b.try_into().unwrap()),
        _ => schema(format!("`{name}` must be a byte string of {N} bytes")),
    }
}

pub(crate) fn uint(v: &Value, name: &str) -> Result<i64, SchemaError> {
    match v.as_int() {
        Some(i) if i >= 0 => Ok(i),
        _ => schema(format!("`{name}` must be an unsigned integer")),
    }
}

/// A URI here is any text with a scheme and something after it.
pub(crate) fn uri(v: &Value, name: &str) -> Result<String, SchemaError> {
    let Some(s) = v.as_text() else {
        return schema(format!("`{name}` must be text"));
    };
    let ok = match s.split_once(':') {
        Some((scheme, rest)) => {
            !rest.is_empty()
                && scheme.starts_with(|c: char| c.is_ascii_alphabetic())
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "+.-".contains(c))
        }
        None => false,
    };
    if !ok {
        return schema(format!("`{name}` is not a URI"));
    }
    Ok(s.to_string())
}

/// Attestation payload (spec section 7, `application/atep-attestation+cbor`).
/// CBOR map with text keys `subject`, `issuer`, `claim`, `data`, `evidence`,
/// `evidence-uri`, `id`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attestation {
    pub subject: AgentId,
    pub issuer: AgentId,
    pub claim: String,
    /// Claim-type-specific fields: a CBOR map with text keys.
    pub data: Value,
    pub evidence: Option<[u8; 32]>,
    pub evidence_uri: Option<String>,
    pub id: [u8; 16],
}

impl Attestation {
    pub fn to_value(&self) -> Value {
        let mut m = vec![
            (Value::text("subject"), Value::bytes(&self.subject.0)),
            (Value::text("issuer"), Value::bytes(&self.issuer.0)),
            (Value::text("claim"), Value::text(&self.claim)),
            (Value::text("data"), self.data.clone()),
            (Value::text("id"), Value::bytes(&self.id)),
        ];
        if let Some(e) = &self.evidence {
            m.push((Value::text("evidence"), Value::bytes(e)));
        }
        if let Some(u) = &self.evidence_uri {
            m.push((Value::text("evidence-uri"), Value::text(u)));
        }
        Value::Map(m)
    }

    pub fn encode(&self) -> Vec<u8> {
        self.to_value().encode()
    }

    /// Strict schema validation of a decoded payload. Unknown fields,
    /// missing fields and wrong types are all errors.
    pub fn from_value(v: &Value) -> Result<Attestation, SchemaError> {
        let entries = text_entries(v)?;
        let mut subject = None;
        let mut issuer = None;
        let mut claim = None;
        let mut data = None;
        let mut evidence = None;
        let mut evidence_uri = None;
        let mut id = None;
        for (k, val) in entries {
            match k {
                "subject" => subject = Some(AgentId(fixed_bytes::<32>(val, "subject")?)),
                "issuer" => issuer = Some(AgentId(fixed_bytes::<32>(val, "issuer")?)),
                "claim" => claim = Some(uri(val, "claim")?),
                "data" => {
                    text_entries(val).map_err(|e| SchemaError(format!("`data`: {}", e.0)))?;
                    data = Some(val.clone());
                }
                "evidence" => evidence = Some(fixed_bytes::<32>(val, "evidence")?),
                "evidence-uri" => evidence_uri = Some(uri(val, "evidence-uri")?),
                "id" => id = Some(fixed_bytes::<16>(val, "id")?),
                other => return schema(format!("unknown field `{other}`")),
            }
        }
        let need = |name: &str| SchemaError(format!("missing field `{name}`"));
        Ok(Attestation {
            subject: subject.ok_or_else(|| need("subject"))?,
            issuer: issuer.ok_or_else(|| need("issuer"))?,
            claim: claim.ok_or_else(|| need("claim"))?,
            data: data.ok_or_else(|| need("data"))?,
            evidence,
            evidence_uri,
            id: id.ok_or_else(|| need("id"))?,
        })
    }

    /// Decode (strictly) and validate a payload.
    pub fn from_payload(payload: &[u8]) -> Result<Attestation, SchemaError> {
        let v = Value::decode(payload).map_err(|e| SchemaError(e.to_string()))?;
        Attestation::from_value(&v)
    }

    /// Value of a `data` field.
    pub fn data_get(&self, key: &str) -> Option<&Value> {
        self.data
            .as_map()?
            .iter()
            .find(|(k, _)| k.as_text() == Some(key))
            .map(|(_, v)| v)
    }

    /// Claim-type rules checked on top of the generic schema: `audited` and
    /// `safety-certified` need an evidence hash, `issuer-authority` needs
    /// `data.claims` as an array of URIs, `retired` has `subject` equal to
    /// `issuer` and `successor` a `subject` that differs from it, and in both
    /// `data.reason`, when present, is text (spec section 7).
    pub fn validate_claim_data(&self) -> Result<(), SchemaError> {
        if claims::requires_evidence(&self.claim) && self.evidence.is_none() {
            return schema(format!("claim `{}` requires an evidence hash", self.claim));
        }
        if self.claim == claims::ISSUER_AUTHORITY {
            self.authority_claims()?;
        }
        if self.claim == claims::RETIRED {
            // Only an identity can retire itself (spec section 7).
            if self.subject != self.issuer {
                return schema("`retired` needs `subject` equal to `issuer`");
            }
            self.check_reason()?;
        }
        if self.claim == claims::SUCCESSOR {
            // The old identity (issuer) names a different new identity (subject).
            if self.subject == self.issuer {
                return schema("`successor` needs `subject` different from `issuer`");
            }
            self.check_reason()?;
        }
        Ok(())
    }

    /// `retired` and `successor`: `data` is `{}` or has a `reason` that is text;
    /// other members are free and ignored.
    fn check_reason(&self) -> Result<(), SchemaError> {
        match self.data_get("reason") {
            None => Ok(()),
            Some(v) if v.as_text().is_some() => Ok(()),
            Some(_) => schema("`data.reason` must be text"),
        }
    }

    /// For `issuer-authority`: the claim types the subject may issue
    /// (`data.claims`, provisional layout).
    pub fn authority_claims(&self) -> Result<Vec<String>, SchemaError> {
        let Some(list) = self.data_get("claims").and_then(|v| v.as_array()) else {
            return schema("issuer-authority data needs `claims`, an array of URIs");
        };
        list.iter().map(|v| uri(v, "claims entry")).collect()
    }
}

/// `data` for an `issuer-authority` attestation.
pub fn authority_data(claim_types: &[&str]) -> Value {
    Value::Map(vec![(
        Value::text("claims"),
        Value::Array(claim_types.iter().map(|c| Value::text(c)).collect()),
    )])
}

/// Check the lifetime of an attestation against the tiers of section 7.
/// More than 400 days is always an error (MUST NOT). More than 180 days for a
/// claim that is not audit-backed is an error only when `strict_default`.
pub fn check_lifetime(
    claim: &str,
    has_evidence: bool,
    lifetime_secs: i64,
    strict_default: bool,
) -> Result<(), String> {
    if lifetime_secs > MAX_ATTESTATION_LIFETIME_SECS {
        return Err(format!(
            "lifetime of {} days exceeds the 400 day maximum",
            lifetime_secs / 86_400
        ));
    }
    if strict_default
        && LifetimeTier::of(claim, has_evidence) == LifetimeTier::Default
        && lifetime_secs > DEFAULT_ATTESTATION_LIFETIME_SECS
    {
        return Err(format!(
            "lifetime of {} days exceeds the 180 day default tier; only audit-backed claims may run up to 400 days",
            lifetime_secs / 86_400
        ));
    }
    Ok(())
}

/// Everything needed to issue an attestation.
pub struct AttestationParams {
    pub subject: AgentId,
    pub claim: String,
    /// Map with text keys.
    pub data: Value,
    pub evidence: Option<[u8; 32]>,
    pub evidence_uri: Option<String>,
    /// Attestation id, the handle used in revocation lists.
    pub id: [u8; 16],
    pub issued_at: i64,
    /// REQUIRED for attestations.
    pub expires_at: i64,
    pub nonce: [u8; 16],
    pub mode: SignMode,
    pub include_bundle: bool,
    /// Allow more than 180 days for a claim that is not audit-backed
    /// (SHOULD in the spec; the hard limit of 400 days always applies).
    pub allow_long_default: bool,
}

impl AttestationParams {
    /// Random id and nonce, hedged signing, bundle inline, empty `data`.
    pub fn new(
        subject: AgentId,
        claim: &str,
        issued_at: i64,
        expires_at: i64,
    ) -> Result<AttestationParams, AtepError> {
        let mut id = [0u8; 16];
        let mut nonce = [0u8; 16];
        fill_random(&mut id)?;
        fill_random(&mut nonce)?;
        Ok(AttestationParams {
            subject,
            claim: claims::expand(claim),
            data: Value::Map(vec![]),
            evidence: None,
            evidence_uri: None,
            id,
            issued_at,
            expires_at,
            nonce,
            mode: SignMode::Hedged,
            include_bundle: true,
            allow_long_default: false,
        })
    }
}

/// Build the payload an issuer would sign, without signing it.
pub fn build(issuer: &Identity, p: &AttestationParams) -> Result<Attestation, AtepError> {
    let a = Attestation {
        subject: p.subject,
        issuer: issuer.agent_id(),
        claim: p.claim.clone(),
        data: p.data.clone(),
        evidence: p.evidence,
        evidence_uri: p.evidence_uri.clone(),
        id: p.id,
    };
    // Round trip through the strict schema so issuance and validation agree.
    let a = Attestation::from_value(&a.to_value()).map_err(|e| AtepError::new(e.0))?;
    a.validate_claim_data().map_err(|e| AtepError::new(e.0))?;
    if p.expires_at <= p.issued_at {
        return Err(AtepError::new("expires-at must be later than issued-at"));
    }
    check_lifetime(
        &a.claim,
        a.evidence.is_some(),
        p.expires_at - p.issued_at,
        !p.allow_long_default,
    )
    .map_err(AtepError)?;
    Ok(a)
}

/// Issue an attestation: the issuer signs a tag 98 envelope with content type
/// `application/atep-attestation+cbor` and an `expires-at`.
pub fn issue(issuer: &Identity, p: &AttestationParams) -> Result<Vec<u8>, AtepError> {
    let a = build(issuer, p)?;
    let payload = a.encode();
    let mut sp = SignParams::new(&payload, CT_ATTESTATION, p.nonce, p.issued_at);
    sp.expires_at = Some(p.expires_at);
    sp.include_bundle = p.include_bundle;
    sp.mode = p.mode;
    sign(issuer, &sp)
}

/// Convert JSON to CBOR for claim `data`. Objects become maps with text keys,
/// integers stay integers, `{"$hex": "..."}` becomes a byte string. Floats are
/// refused because ATEP uses none.
pub fn json_to_cbor(j: &serde_json::Value) -> Result<Value, AtepError> {
    use serde_json::Value as J;
    Ok(match j {
        J::Null => Value::Null,
        J::Bool(b) => Value::Bool(*b),
        J::Number(n) => Value::Int(
            n.as_i64()
                .ok_or_else(|| AtepError::new("only integers are allowed in claim data"))?,
        ),
        J::String(s) => Value::Text(s.clone()),
        J::Array(a) => Value::Array(a.iter().map(json_to_cbor).collect::<Result<_, _>>()?),
        J::Object(o) => {
            if o.len() == 1 {
                if let Some(h) = o.get("$hex").and_then(|h| h.as_str()) {
                    return Ok(Value::Bytes(
                        hex::decode(h).map_err(|e| AtepError::new(format!("bad $hex: {e}")))?,
                    ));
                }
            }
            Value::Map(
                o.iter()
                    .map(|(k, v)| Ok((Value::Text(k.clone()), json_to_cbor(v)?)))
                    .collect::<Result<_, AtepError>>()?,
            )
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Seeds;

    fn ident(n: u8) -> Identity {
        Identity::from_seeds(Seeds {
            ed25519: [n; 32],
            mldsa65: [n + 1; 32],
            x25519: None,
            mlkem768: None,
        })
        .unwrap()
    }

    fn params(subject: AgentId, claim: &str, days: i64) -> AttestationParams {
        let mut p = AttestationParams::new(subject, claim, 1_000, 1_000 + days * 86_400).unwrap();
        p.mode = SignMode::Deterministic;
        p
    }

    #[test]
    fn core_vocabulary_has_fourteen_claim_types() {
        let all: std::collections::BTreeSet<&str> = claims::CORE
            .iter()
            .chain(claims::robotics::ALL.iter())
            .copied()
            .collect();
        // Seven core types, seven robotics types, `operator` shared.
        assert_eq!(claims::CORE.len(), 7);
        assert_eq!(all.len(), 14);
        assert!(all.contains(claims::REGISTRY_ENDPOINT));
    }

    #[test]
    fn expand_names() {
        assert_eq!(claims::expand("audited"), claims::AUDITED);
        assert_eq!(
            claims::expand("fleet-member"),
            claims::robotics::FLEET_MEMBER
        );
        assert_eq!(
            claims::expand("robotics/peer-motion"),
            claims::robotics::PEER_MOTION
        );
        assert_eq!(claims::expand("operator"), claims::OPERATOR);
        assert_eq!(
            claims::expand("registry-endpoint"),
            claims::REGISTRY_ENDPOINT
        );
        assert_eq!(claims::expand("https://x.example/c"), "https://x.example/c");
    }

    #[test]
    fn payload_round_trip_and_strictness() {
        let a = Attestation {
            subject: ident(5).agent_id(),
            issuer: ident(1).agent_id(),
            claim: claims::OPERATOR.into(),
            data: Value::Map(vec![(Value::text("name"), Value::text("Acme"))]),
            evidence: None,
            evidence_uri: None,
            id: [9; 16],
        };
        assert_eq!(Attestation::from_payload(&a.encode()).unwrap(), a);
        // unknown field
        let mut v = a.to_value();
        if let Value::Map(m) = &mut v {
            m.push((Value::text("extra"), Value::Int(1)));
        }
        assert!(Attestation::from_payload(&v.encode()).is_err());
        // missing id
        let mut v = a.to_value();
        if let Value::Map(m) = &mut v {
            m.retain(|(k, _)| k.as_text() != Some("id"));
        }
        assert!(Attestation::from_payload(&v.encode()).is_err());
        // short subject
        let mut v = a.to_value();
        if let Value::Map(m) = &mut v {
            for (k, val) in m.iter_mut() {
                if k.as_text() == Some("subject") {
                    *val = Value::bytes(&[1; 31]);
                }
            }
        }
        assert!(Attestation::from_payload(&v.encode()).is_err());
        // claim must be a URI
        let mut b = a.clone();
        b.claim = "not a uri".into();
        assert!(Attestation::from_payload(&b.encode()).is_err());
        // not a map
        assert!(Attestation::from_payload(&Value::Int(1).encode()).is_err());
    }

    #[test]
    fn lifetime_tiers() {
        let i = ident(1);
        let s = ident(2).agent_id();
        // 180 days default is fine, 181 is refused unless allowed
        assert!(issue(&i, &params(s, "operator", 180)).is_ok());
        assert!(issue(&i, &params(s, "operator", 181)).is_err());
        let mut p = params(s, "operator", 300);
        p.allow_long_default = true;
        assert!(issue(&i, &p).is_ok());
        // 400 days is the hard maximum, 401 is refused even when allowed
        let mut p = params(s, "operator", 401);
        p.allow_long_default = true;
        assert!(issue(&i, &p).is_err());
        // audit-backed claims need evidence and may run 400 days
        let mut p = params(s, "audited", 400);
        assert!(issue(&i, &p).is_err());
        p.evidence = Some([3; 32]);
        assert!(issue(&i, &p).is_ok());
        let mut p = params(s, "operator", 400);
        p.evidence = Some([3; 32]);
        assert!(issue(&i, &p).is_ok());
    }

    #[test]
    fn issuance_sets_issuer_and_expiry() {
        let i = ident(1);
        let s = ident(2).agent_id();
        let env = issue(&i, &params(s, "operator", 90)).unwrap();
        let v = crate::verify(&env, &crate::Policy::default(), 2_000).unwrap();
        assert_eq!(v.content_type, CT_ATTESTATION);
        let a = Attestation::from_payload(&v.payload).unwrap();
        assert_eq!(a.issuer, i.agent_id());
        assert_eq!(a.subject, s);
        assert!(v.expires_at.is_some());
    }

    #[test]
    fn authority_data_layout() {
        let a = Attestation {
            subject: ident(2).agent_id(),
            issuer: ident(1).agent_id(),
            claim: claims::ISSUER_AUTHORITY.into(),
            data: authority_data(&[claims::AUDITED]),
            evidence: None,
            evidence_uri: None,
            id: [1; 16],
        };
        assert_eq!(a.authority_claims().unwrap(), vec![claims::AUDITED]);
        let mut b = a.clone();
        b.data = Value::Map(vec![]);
        assert!(b.validate_claim_data().is_err());
    }

    #[test]
    fn json_data_conversion() {
        let j: serde_json::Value =
            serde_json::from_str(r#"{"a": 1, "b": ["x", {"$hex": "0a0b"}], "c": null}"#).unwrap();
        let v = json_to_cbor(&j).unwrap();
        let again = Value::decode(&v.encode()).unwrap();
        assert_eq!(again.as_map().unwrap().len(), 3);
        assert!(json_to_cbor(&serde_json::json!(1.5)).is_err());
    }
}
