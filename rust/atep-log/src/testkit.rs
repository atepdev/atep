//! Helpers for tests and examples: temporary directories, deterministic
//! identities and quick attestation and SRL builders.

use std::path::{Path, PathBuf};

use atep_core::attestation::{self, authority_data, AttestationParams};
use atep_core::cbor::Value;
use atep_core::envelope::SignMode;
use atep_core::keys::{AgentId, Identity, Seeds};
use atep_core::srl::{self, RevocationEntry, Srl};

pub const DAY: i64 = 86_400;

/// A directory removed on drop.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(label: &str) -> TempDir {
        let mut n = [0u8; 8];
        atep_core::keys::fill_random(&mut n).expect("random");
        let p = std::env::temp_dir().join(format!(
            "atep-{label}-{}-{}",
            std::process::id(),
            hex::encode(n)
        ));
        std::fs::create_dir_all(&p).expect("create temp dir");
        TempDir(p)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A deterministic signing-only identity: `ident(7)` is always the same.
pub fn ident(n: u8) -> Identity {
    Identity::from_seeds(Seeds {
        ed25519: [n; 32],
        mldsa65: [n.wrapping_add(100); 32],
        x25519: None,
        mlkem768: None,
    })
    .expect("identity")
}

/// Issue an attestation with the claim data given as CBOR.
pub fn attest(
    issuer: &Identity,
    subject: AgentId,
    claim: &str,
    data: Value,
    issued_at: i64,
    days: i64,
) -> Vec<u8> {
    let mut p =
        AttestationParams::new(subject, claim, issued_at, issued_at + days * DAY).expect("params");
    p.data = data;
    p.mode = SignMode::Deterministic;
    attestation::issue(issuer, &p).expect("issue")
}

pub fn text_map(pairs: &[(&str, &str)]) -> Value {
    Value::Map(
        pairs
            .iter()
            .map(|(k, v)| (Value::text(k), Value::text(v)))
            .collect(),
    )
}

/// `issuer-authority` attestation listing `claims`.
pub fn delegate(issuer: &Identity, subject: AgentId, claims: &[&str], issued_at: i64) -> Vec<u8> {
    attest(
        issuer,
        subject,
        attestation::claims::ISSUER_AUTHORITY,
        authority_data(claims),
        issued_at,
        90,
    )
}

/// `domain-control` attestation naming `domain`.
pub fn domain_control(
    issuer: &Identity,
    subject: AgentId,
    domain: &str,
    issued_at: i64,
) -> Vec<u8> {
    attest(
        issuer,
        subject,
        attestation::claims::DOMAIN_CONTROL,
        text_map(&[("domain", domain)]),
        issued_at,
        90,
    )
}

pub fn srl(
    issuer: &Identity,
    sequence: i64,
    issued_at: i64,
    revoked: Vec<RevocationEntry>,
) -> Vec<u8> {
    let s = Srl {
        issuer: issuer.agent_id(),
        sequence,
        issued_at,
        next_update: issued_at + DAY,
        revoked,
    };
    srl::create(
        issuer,
        &s,
        [sequence as u8; 16],
        SignMode::Deterministic,
        true,
    )
    .expect("srl")
}
