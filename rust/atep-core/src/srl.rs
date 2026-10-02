//! Signed revocation lists (spec section 8): payload type, schema validation,
//! signing, sequence handling and cache abstractions with the stale policy.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::attestation::{fixed_bytes, schema, text_entries, uint, SchemaError};
use crate::cbor::Value;
use crate::consts::*;
use crate::envelope::{sign, SignMode, SignParams};
use crate::error::{AtepError, ErrorCode, Rejection};
use crate::keys::{AgentId, Identity, PublicBundle};
use crate::verify::{verify, Policy, Revocation};

/// What a revocation entry names: an attestation id (16 bytes) or an Agent ID
/// (32 bytes, an identity revocation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevokedId {
    Attestation([u8; 16]),
    Identity(AgentId),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationEntry {
    pub id: RevokedId,
    /// `superseded`, `withdrawn`, `compromised` or any other text.
    pub reason: String,
    pub revoked_at: i64,
}

/// SRL payload (`application/atep-srl+cbor`): text keys `issuer`, `sequence`,
/// `issued-at`, `next-update`, `revoked`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Srl {
    pub issuer: AgentId,
    pub sequence: i64,
    pub issued_at: i64,
    pub next_update: i64,
    pub revoked: Vec<RevocationEntry>,
}

impl Srl {
    pub fn to_value(&self) -> Value {
        let revoked = self
            .revoked
            .iter()
            .map(|e| {
                let id = match &e.id {
                    RevokedId::Attestation(a) => Value::bytes(a),
                    RevokedId::Identity(i) => Value::bytes(&i.0),
                };
                Value::Map(vec![
                    (Value::text("id"), id),
                    (Value::text("reason"), Value::text(&e.reason)),
                    (Value::text("revoked-at"), Value::Int(e.revoked_at)),
                ])
            })
            .collect();
        Value::Map(vec![
            (Value::text("issuer"), Value::bytes(&self.issuer.0)),
            (Value::text("sequence"), Value::Int(self.sequence)),
            (Value::text("issued-at"), Value::Int(self.issued_at)),
            (Value::text("next-update"), Value::Int(self.next_update)),
            (Value::text("revoked"), Value::Array(revoked)),
        ])
    }

    pub fn encode(&self) -> Vec<u8> {
        self.to_value().encode()
    }

    /// Strict schema validation of a decoded payload.
    pub fn from_value(v: &Value) -> Result<Srl, SchemaError> {
        let mut issuer = None;
        let mut sequence = None;
        let mut issued_at = None;
        let mut next_update = None;
        let mut revoked = None;
        for (k, val) in text_entries(v)? {
            match k {
                "issuer" => issuer = Some(AgentId(fixed_bytes::<32>(val, "issuer")?)),
                "sequence" => sequence = Some(uint(val, "sequence")?),
                "issued-at" => issued_at = Some(uint(val, "issued-at")?),
                "next-update" => next_update = Some(uint(val, "next-update")?),
                "revoked" => {
                    let Some(list) = val.as_array() else {
                        return schema("`revoked` must be an array");
                    };
                    revoked = Some(
                        list.iter()
                            .map(parse_entry)
                            .collect::<Result<Vec<_>, _>>()?,
                    );
                }
                other => return schema(format!("unknown field `{other}`")),
            }
        }
        let need = |n: &str| SchemaError(format!("missing field `{n}`"));
        let srl = Srl {
            issuer: issuer.ok_or_else(|| need("issuer"))?,
            sequence: sequence.ok_or_else(|| need("sequence"))?,
            issued_at: issued_at.ok_or_else(|| need("issued-at"))?,
            next_update: next_update.ok_or_else(|| need("next-update"))?,
            revoked: revoked.ok_or_else(|| need("revoked"))?,
        };
        if srl.next_update <= srl.issued_at {
            return schema("`next-update` must be later than `issued-at`");
        }
        Ok(srl)
    }

    pub fn from_payload(payload: &[u8]) -> Result<Srl, SchemaError> {
        let v = Value::decode(payload).map_err(|e| SchemaError(e.to_string()))?;
        Srl::from_value(&v)
    }

    /// Past `next-update`. Fails safe: the boundary counts as stale.
    pub fn is_stale(&self, now: i64) -> bool {
        now >= self.next_update
    }

    /// The entry revoking this attestation id, if any.
    pub fn revokes_attestation(&self, id: &[u8; 16]) -> Option<&RevocationEntry> {
        self.revoked
            .iter()
            .find(|e| e.id == RevokedId::Attestation(*id))
    }

    /// Identity entry for `who`, if any (compromised or retired).
    pub fn revokes_identity(&self, who: &AgentId) -> Option<&RevocationEntry> {
        self.revoked
            .iter()
            .find(|e| e.id == RevokedId::Identity(*who))
    }
}

fn parse_entry(v: &Value) -> Result<RevocationEntry, SchemaError> {
    let mut id = None;
    let mut reason = None;
    let mut at = None;
    for (k, val) in text_entries(v)? {
        match k {
            "id" => {
                id = Some(match val.as_bytes() {
                    Some(b) if b.len() == 16 => RevokedId::Attestation(b.try_into().unwrap()),
                    Some(b) if b.len() == 32 => RevokedId::Identity(AgentId(b.try_into().unwrap())),
                    _ => return schema("entry `id` must be 16 or 32 bytes"),
                })
            }
            "reason" => match val.as_text() {
                Some(t) => reason = Some(t.to_string()),
                None => return schema("entry `reason` must be text"),
            },
            "revoked-at" => at = Some(uint(val, "revoked-at")?),
            other => return schema(format!("unknown entry field `{other}`")),
        }
    }
    let need = |n: &str| SchemaError(format!("entry lacks `{n}`"));
    Ok(RevocationEntry {
        id: id.ok_or_else(|| need("id"))?,
        reason: reason.ok_or_else(|| need("reason"))?,
        revoked_at: at.ok_or_else(|| need("revoked-at"))?,
    })
}

/// Sign an SRL: tag 98 envelope with content type `application/atep-srl+cbor`,
/// `issued-at` equal to the payload's.
pub fn create(
    issuer: &Identity,
    srl: &Srl,
    nonce: [u8; 16],
    mode: SignMode,
    include_bundle: bool,
) -> Result<Vec<u8>, AtepError> {
    if srl.issuer != issuer.agent_id() {
        return Err(AtepError::new("SRL issuer must be the signing identity"));
    }
    // Same checks a consumer applies.
    Srl::from_value(&srl.to_value()).map_err(|e| AtepError::new(e.0))?;
    let payload = srl.encode();
    let mut p = SignParams::new(&payload, CT_SRL, nonce, srl.issued_at);
    p.mode = mode;
    p.include_bundle = include_bundle;
    sign(issuer, &p)
}

/// The verifier context an SRL is loaded in (spec section 8, "Loading an
/// SRL"): steps 1 to 8 run against the verifier's own cached SRLs, directly
/// supplied revocations and local attestation store, so that an issuer that is
/// revoked or retired as of the list's `issued-at` cannot publish it.
#[derive(Clone, Copy)]
pub struct LoadContext<'a> {
    pub known_bundles: &'a [PublicBundle],
    /// Directly supplied identity revocations (step 8).
    pub revocations: &'a [Revocation],
    /// The local attestation store (step 8 reads retirements from it).
    pub attestations: &'a [Vec<u8>],
    /// Cached SRLs (step 8 reads their identity entries).
    pub srls: Option<&'a dyn SrlCache>,
    pub max_skew_secs: i64,
}

impl<'a> LoadContext<'a> {
    /// A context that holds only signer bundles: nothing is revoked, retired
    /// or cached. For callers that have no verifier state.
    pub fn bundles(known_bundles: &'a [PublicBundle]) -> LoadContext<'a> {
        LoadContext {
            known_bundles,
            revocations: &[],
            attestations: &[],
            srls: None,
            max_skew_secs: DEFAULT_SKEW_SECS,
        }
    }

    /// The same context with `cache` as the SRL cache.
    pub fn with_cache(self, cache: &'a dyn SrlCache) -> LoadContext<'a> {
        LoadContext {
            srls: Some(cache),
            ..self
        }
    }
}

/// Verify an SRL envelope (steps 1 to 8, in the verifier context `cx`) and
/// validate its payload: content type, schema, and that `issuer` equals the
/// envelope signer.
pub fn load(raw: &[u8], cx: &LoadContext, now: i64) -> Result<Srl, Rejection> {
    let policy = Policy {
        known_bundles: cx.known_bundles.to_vec(),
        revocations: cx.revocations.to_vec(),
        attestations: cx.attestations.to_vec(),
        srls: cx.srls,
        max_skew_secs: cx.max_skew_secs,
        ..Policy::default()
    };
    let v = verify(raw, &policy, now)?;
    if v.content_type != CT_SRL {
        return Err(Rejection::new(
            9,
            ErrorCode::SrlWrongContentType,
            format!("content type `{}` is not an SRL", v.content_type),
        ));
    }
    let srl = Srl::from_payload(&v.payload)
        .map_err(|e| Rejection::new(9, ErrorCode::SrlSchemaInvalid, e.0))?;
    if srl.issuer != v.signer {
        return Err(Rejection::new(
            9,
            ErrorCode::SrlIssuerMismatch,
            "SRL issuer does not equal the envelope signer",
        ));
    }
    Ok(srl)
}

/// A verified SRL together with the envelope it came from.
#[derive(Clone, Debug)]
pub struct CachedSrl {
    pub raw: Vec<u8>,
    pub srl: Srl,
}

/// Where a verifier keeps SRLs. One entry per issuer.
pub trait SrlCache {
    fn get(&self, issuer: &AgentId) -> Option<CachedSrl>;
    fn issuers(&self) -> Vec<AgentId>;
    /// Unconditional write. Use [`ingest`] to apply the sequence rules.
    fn store(&mut self, entry: CachedSrl) -> Result<(), AtepError>;
}

/// Verify `raw` and put it in the cache. A lower `sequence` than the cached
/// one is a rollback and is refused; the same sequence with different bytes is
/// refused too; the same bytes again are accepted and change nothing. The
/// cache itself is part of the context the list is verified in (step 8 reads
/// the identity entries of the cached lists).
pub fn ingest(
    cache: &mut dyn SrlCache,
    raw: &[u8],
    known_bundles: &[PublicBundle],
    now: i64,
) -> Result<Srl, Rejection> {
    ingest_in(cache, raw, &LoadContext::bundles(known_bundles), now)
}

/// [`ingest`] in a fuller verifier context: `cx.srls` is ignored, the cache
/// being filled is used instead.
pub fn ingest_in(
    cache: &mut dyn SrlCache,
    raw: &[u8],
    cx: &LoadContext,
    now: i64,
) -> Result<Srl, Rejection> {
    // The bytes the cache already holds are no change, even when a reload
    // would now fail step 8 (a list that names its own issuer, spec section 7).
    for issuer in cache.issuers() {
        if let Some(c) = cache.get(&issuer) {
            if c.raw == raw {
                return Ok(c.srl);
            }
        }
    }
    let srl = load(raw, &cx.with_cache(&*cache), now)?;
    if let Some(old) = cache.get(&srl.issuer) {
        if srl.sequence < old.srl.sequence {
            return Err(Rejection::new(
                9,
                ErrorCode::SrlRollback,
                format!(
                    "sequence {} is lower than the cached sequence {}",
                    srl.sequence, old.srl.sequence
                ),
            ));
        }
        if srl.sequence == old.srl.sequence {
            return Err(Rejection::new(
                9,
                ErrorCode::SrlSequenceConflict,
                format!(
                    "a different SRL with sequence {} is already cached",
                    srl.sequence
                ),
            ));
        }
    }
    cache
        .store(CachedSrl {
            raw: raw.to_vec(),
            srl: srl.clone(),
        })
        .map_err(|e| Rejection::new(9, ErrorCode::SrlUnavailable, e.0))?;
    Ok(srl)
}

#[derive(Default, Clone)]
pub struct MemorySrlCache {
    map: HashMap<AgentId, CachedSrl>,
}

impl MemorySrlCache {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SrlCache for MemorySrlCache {
    fn get(&self, issuer: &AgentId) -> Option<CachedSrl> {
        self.map.get(issuer).cloned()
    }
    fn issuers(&self) -> Vec<AgentId> {
        let mut v: Vec<AgentId> = self.map.keys().copied().collect();
        v.sort();
        v
    }
    fn store(&mut self, entry: CachedSrl) -> Result<(), AtepError> {
        self.map.insert(entry.srl.issuer, entry);
        Ok(())
    }
}

/// Memory cache that also writes every stored SRL to `<dir>/<issuer>.srl.cbor`
/// and reloads (re-verifying) the directory on open.
pub struct FileSrlCache {
    dir: PathBuf,
    mem: MemorySrlCache,
}

impl FileSrlCache {
    /// Open `dir` (created if missing). Files that fail verification are
    /// skipped and reported in the second return value.
    pub fn open(
        dir: &Path,
        known_bundles: &[PublicBundle],
        now: i64,
    ) -> Result<(FileSrlCache, Vec<String>), AtepError> {
        fs::create_dir_all(dir).map_err(|e| AtepError::new(format!("{}: {e}", dir.display())))?;
        let mut mem = MemorySrlCache::new();
        let mut skipped = Vec::new();
        let mut paths: Vec<PathBuf> = fs::read_dir(dir)
            .map_err(|e| AtepError::new(format!("{}: {e}", dir.display())))?
            .filter_map(|r| r.ok().map(|d| d.path()))
            .filter(|p| p.to_string_lossy().ends_with(".srl.cbor"))
            .collect();
        paths.sort();
        for p in paths {
            let loaded = fs::read(&p).map_err(|e| e.to_string()).and_then(|raw| {
                load(&raw, &LoadContext::bundles(known_bundles), now)
                    .map(|srl| CachedSrl { raw, srl })
                    .map_err(|e| e.to_string())
            });
            match loaded {
                Ok(c) => {
                    let keep = mem
                        .get(&c.srl.issuer)
                        .map(|o| o.srl.sequence < c.srl.sequence)
                        .unwrap_or(true);
                    if keep {
                        mem.store(c)?;
                    }
                }
                Err(e) => skipped.push(format!("{}: {e}", p.display())),
            }
        }
        Ok((
            FileSrlCache {
                dir: dir.to_path_buf(),
                mem,
            },
            skipped,
        ))
    }

    pub fn path_for(&self, issuer: &AgentId) -> PathBuf {
        self.dir.join(format!("{}.srl.cbor", issuer.base32()))
    }
}

impl SrlCache for FileSrlCache {
    fn get(&self, issuer: &AgentId) -> Option<CachedSrl> {
        self.mem.get(issuer)
    }
    fn issuers(&self) -> Vec<AgentId> {
        self.mem.issuers()
    }
    fn store(&mut self, entry: CachedSrl) -> Result<(), AtepError> {
        let path = self.path_for(&entry.srl.issuer);
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, &entry.raw)
            .and_then(|_| fs::rename(&tmp, &path))
            .map_err(|e| AtepError::new(format!("{}: {e}", path.display())))?;
        self.mem.store(entry)
    }
}

/// What to do when an issuer's SRL is past `next-update` or absent
/// (spec section 8: the protocol does not force one choice).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StaleMode {
    FailClosed,
    FailOpenWithWarning,
}

impl StaleMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            StaleMode::FailClosed => "fail-closed",
            StaleMode::FailOpenWithWarning => "fail-open",
        }
    }

    pub fn parse(s: &str) -> Option<StaleMode> {
        match s {
            "fail-closed" => Some(StaleMode::FailClosed),
            "fail-open" | "fail-open-with-warning" => Some(StaleMode::FailOpenWithWarning),
            _ => None,
        }
    }
}

/// The verifier's revocation freshness policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SrlPolicy {
    /// Cached SRL is past `next-update`. Default fail-closed.
    pub on_stale: StaleMode,
    /// No SRL cached for an issuer. Default fail-open with a warning, so a
    /// verifier that has not fetched any list yet can still work.
    pub on_missing: StaleMode,
}

impl Default for SrlPolicy {
    fn default() -> Self {
        SrlPolicy {
            on_stale: StaleMode::FailClosed,
            on_missing: StaleMode::FailOpenWithWarning,
        }
    }
}

impl SrlPolicy {
    pub const STRICT: SrlPolicy = SrlPolicy {
        on_stale: StaleMode::FailClosed,
        on_missing: StaleMode::FailClosed,
    };
    pub const LENIENT: SrlPolicy = SrlPolicy {
        on_stale: StaleMode::FailOpenWithWarning,
        on_missing: StaleMode::FailOpenWithWarning,
    };
}

/// The SRL to consult for `issuer`, applying the freshness policy. Returns the
/// list (even when stale) and an optional warning, or a step 9 rejection.
pub fn current_for(
    cache: Option<&dyn SrlCache>,
    issuer: &AgentId,
    now: i64,
    pol: &SrlPolicy,
) -> Result<(Option<Srl>, Option<String>), Rejection> {
    match cache.and_then(|c| c.get(issuer)) {
        None => match pol.on_missing {
            StaleMode::FailClosed => Err(Rejection::new(
                9,
                ErrorCode::SrlUnavailable,
                format!("no SRL cached for issuer {issuer}"),
            )),
            StaleMode::FailOpenWithWarning => Ok((
                None,
                Some(format!(
                    "no SRL cached for issuer {issuer}; revocation status unknown"
                )),
            )),
        },
        Some(c) if c.srl.is_stale(now) => match pol.on_stale {
            StaleMode::FailClosed => Err(Rejection::new(
                9,
                ErrorCode::SrlStale,
                format!(
                    "SRL of {issuer} is past next-update {} (now {now})",
                    c.srl.next_update
                ),
            )),
            StaleMode::FailOpenWithWarning => {
                let w = format!(
                    "SRL of {issuer} is past next-update {}; using the stale copy",
                    c.srl.next_update
                );
                Ok((Some(c.srl), Some(w)))
            }
        },
        Some(c) => Ok((Some(c.srl), None)),
    }
}

/// Step 8 helper: the first identity entry in any cached SRL naming `signer`
/// whose `revoked-at` is at or before `issued_at`.
pub fn identity_revoked(
    cache: &dyn SrlCache,
    signer: &AgentId,
    issued_at: i64,
) -> Option<(AgentId, RevocationEntry)> {
    for issuer in cache.issuers() {
        if let Some(c) = cache.get(&issuer) {
            if let Some(e) = c
                .srl
                .revoked
                .iter()
                .find(|e| e.id == RevokedId::Identity(*signer) && e.revoked_at <= issued_at)
            {
                return Some((issuer, e.clone()));
            }
        }
    }
    None
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

    fn srl_for(i: &Identity, seq: i64, issued: i64, next: i64) -> Srl {
        Srl {
            issuer: i.agent_id(),
            sequence: seq,
            issued_at: issued,
            next_update: next,
            revoked: vec![
                RevocationEntry {
                    id: RevokedId::Attestation([7; 16]),
                    reason: "withdrawn".into(),
                    revoked_at: issued - 10,
                },
                RevocationEntry {
                    id: RevokedId::Identity(ident(9).agent_id()),
                    reason: "compromised".into(),
                    revoked_at: issued - 5,
                },
            ],
        }
    }

    fn signed(i: &Identity, s: &Srl) -> Vec<u8> {
        create(i, s, [1; 16], SignMode::Deterministic, true).unwrap()
    }

    #[test]
    fn payload_round_trip_and_strictness() {
        let i = ident(1);
        let s = srl_for(&i, 3, 1_000, 2_000);
        assert_eq!(Srl::from_payload(&s.encode()).unwrap(), s);
        let mut bad = s.clone();
        bad.next_update = bad.issued_at;
        assert!(Srl::from_payload(&bad.encode()).is_err());
        let mut v = s.to_value();
        if let Value::Map(m) = &mut v {
            m.push((Value::text("x"), Value::Int(0)));
        }
        assert!(Srl::from_payload(&v.encode()).is_err());
        assert!(Srl::from_payload(&Value::Array(vec![]).encode()).is_err());
    }

    #[test]
    fn load_checks_issuer_and_signature() {
        let i = ident(1);
        let s = srl_for(&i, 1, 1_000, 2_000);
        let raw = signed(&i, &s);
        assert_eq!(load(&raw, &LoadContext::bundles(&[]), 1_500).unwrap(), s);
        // issuer field names someone else
        let other = ident(3);
        let mut forged = s.clone();
        forged.issuer = other.agent_id();
        let payload = forged.encode();
        let mut p = SignParams::new(&payload, CT_SRL, [2; 16], 1_000);
        p.mode = SignMode::Deterministic;
        let raw2 = sign(&i, &p).unwrap();
        let e = load(&raw2, &LoadContext::bundles(&[]), 1_500).unwrap_err();
        assert_eq!((e.step, e.code), (9, ErrorCode::SrlIssuerMismatch));
        // a data envelope is not an SRL
        let mut p = SignParams::new(&payload, CT_ATTESTATION, [2; 16], 1_000);
        p.expires_at = Some(5_000);
        let raw3 = sign(&i, &p).unwrap();
        let e = load(&raw3, &LoadContext::bundles(&[]), 1_500).unwrap_err();
        assert_eq!(e.code, ErrorCode::SrlWrongContentType);
        // tampered signature
        let mut bad = raw.clone();
        let n = bad.len();
        bad[n - 1] ^= 1;
        assert_eq!(
            load(&bad, &LoadContext::bundles(&[]), 1_500)
                .unwrap_err()
                .step,
            4
        );
    }

    #[test]
    fn sequence_rules() {
        let i = ident(1);
        let mut cache = MemorySrlCache::new();
        let r2 = signed(&i, &srl_for(&i, 2, 1_000, 2_000));
        ingest(&mut cache, &r2, &[], 1_500).unwrap();
        ingest(&mut cache, &r2, &[], 1_500).unwrap();
        let r1 = signed(&i, &srl_for(&i, 1, 1_000, 2_000));
        assert_eq!(
            ingest(&mut cache, &r1, &[], 1_500).unwrap_err().code,
            ErrorCode::SrlRollback
        );
        let mut other = srl_for(&i, 2, 1_000, 2_000);
        other.revoked.clear();
        let r2b = signed(&i, &other);
        assert_eq!(
            ingest(&mut cache, &r2b, &[], 1_500).unwrap_err().code,
            ErrorCode::SrlSequenceConflict
        );
        let r3 = signed(&i, &srl_for(&i, 3, 1_100, 2_100));
        assert_eq!(ingest(&mut cache, &r3, &[], 1_500).unwrap().sequence, 3);
        assert_eq!(cache.get(&i.agent_id()).unwrap().srl.sequence, 3);
    }

    #[test]
    fn stale_policy_knob() {
        let i = ident(1);
        let mut cache = MemorySrlCache::new();
        ingest(
            &mut cache,
            &signed(&i, &srl_for(&i, 1, 1_000, 2_000)),
            &[],
            1_500,
        )
        .unwrap();
        let id = i.agent_id();
        let c: &dyn SrlCache = &cache;
        // fresh
        let (s, w) = current_for(Some(c), &id, 1_999, &SrlPolicy::STRICT).unwrap();
        assert!(s.is_some() && w.is_none());
        // stale at the boundary
        let e = current_for(Some(c), &id, 2_000, &SrlPolicy::STRICT).unwrap_err();
        assert_eq!((e.step, e.code), (9, ErrorCode::SrlStale));
        let (s, w) = current_for(Some(c), &id, 2_000, &SrlPolicy::LENIENT).unwrap();
        assert!(s.is_some() && w.is_some());
        // missing
        let nobody = ident(8).agent_id();
        assert_eq!(
            current_for(Some(c), &nobody, 1_500, &SrlPolicy::STRICT)
                .unwrap_err()
                .code,
            ErrorCode::SrlUnavailable
        );
        let (s, w) = current_for(None, &nobody, 1_500, &SrlPolicy::default()).unwrap();
        assert!(s.is_none() && w.is_some());
    }

    #[test]
    fn identity_entries_feed_step_8() {
        let i = ident(1);
        let mut cache = MemorySrlCache::new();
        ingest(
            &mut cache,
            &signed(&i, &srl_for(&i, 1, 1_000, 2_000)),
            &[],
            1_500,
        )
        .unwrap();
        let victim = ident(9).agent_id();
        // revoked-at is 995; issued at or after is rejected, before is not
        assert!(identity_revoked(&cache, &victim, 995).is_some());
        assert!(identity_revoked(&cache, &victim, 1_200).is_some());
        assert!(identity_revoked(&cache, &victim, 994).is_none());
        assert!(identity_revoked(&cache, &ident(4).agent_id(), 1_200).is_none());
    }

    #[test]
    fn file_cache_round_trip() {
        let dir = std::env::temp_dir().join(format!("atep-srl-cache-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let i = ident(1);
        let (mut c, skipped) = FileSrlCache::open(&dir, &[], 1_500).unwrap();
        assert!(skipped.is_empty());
        let raw = signed(&i, &srl_for(&i, 4, 1_000, 2_000));
        ingest(&mut c, &raw, &[], 1_500).unwrap();
        assert!(c.path_for(&i.agent_id()).exists());
        // garbage in the directory is skipped, the good file reloads
        fs::write(dir.join("junk.srl.cbor"), b"nope").unwrap();
        let (c2, skipped) = FileSrlCache::open(&dir, &[], 1_500).unwrap();
        assert_eq!(skipped.len(), 1);
        assert_eq!(c2.get(&i.agent_id()).unwrap().srl.sequence, 4);
        let _ = fs::remove_dir_all(&dir);
    }
}
