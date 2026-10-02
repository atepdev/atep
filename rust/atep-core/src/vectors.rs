//! Test vector generation and checking (spec section 12).
//!
//! Everything is derived from fixed seeds so that `generate` is a pure
//! function: running it twice yields identical bytes. `check_dir` re-reads a
//! vectors directory from disk and verifies every vector using only the public
//! API and the inputs recorded in each `.expected.json`, so it doubles as the
//! reference conformance runner. The format is documented in `vectors/README.md`.

use std::fs;
use std::path::Path;

use serde_json::{json, Map, Value as J};

use crate::cbor::Value;
use crate::consts::*;
use crate::encrypt::{decrypt, encrypt_traced, EncryptRandomness};
use crate::envelope::{sign, sign_raw, Headers, RawSpec, SignMode, SignParams};
use crate::error::AtepError;
use crate::json::view;
use crate::keys::{sha256, AgentId, Identity, PublicBundle, Seeds};
use crate::srl::MemorySrlCache;
use crate::trust::TrustPolicy;
use crate::vectors_trust;
use crate::verify::{verify, Policy, Revocation, RevocationReason};

/// Reference "now" used by every verification vector (2027-01-15T08:00:00Z).
pub const NOW: i64 = 1_800_000_000;

pub const CATEGORIES: [&str; 28] = [
    "identity",
    "signing",
    "verify-positive",
    "verify-negative",
    "encryption",
    "attestation",
    "chain-positive",
    "chain-negative",
    "srl",
    "log",
    "atep-r-positive",
    "atep-r-negative",
    "retired-positive",
    "retired-negative",
    "successor-positive",
    "successor-negative",
    "srl-context",
    "log-admission",
    "monitor",
    "checkpoint-hash",
    "anchor-record",
    "chain-id",
    "anchor-envelope",
    "anchor-media-type",
    "require-anchor",
    "anchor-not-supported",
    "registry-endpoint",
    "domain-binding",
];

pub(crate) type R<T> = Result<T, AtepError>;

/// The JSON view of a vector file. A file that is not strict deterministic
/// CBOR (some `anchor-record` rejection vectors are built that way) has no
/// view; its stand-in is `{"not_strict_cbor": true, "hex": ...}`.
pub(crate) fn view_or_raw(cbor: &[u8]) -> J {
    match view(cbor) {
        Ok(j) => j,
        Err(_) => json!({ "not_strict_cbor": true, "hex": hx(cbor) }),
    }
}

pub(crate) fn e(msg: impl Into<String>) -> AtepError {
    AtepError::new(msg)
}

pub(crate) fn hx(b: &[u8]) -> String {
    hex::encode(b)
}

pub(crate) fn unhex(s: &str) -> R<Vec<u8>> {
    hex::decode(s).map_err(|x| e(format!("bad hex: {x}")))
}

pub(crate) fn label_hash(label: &str) -> [u8; 32] {
    sha256(format!("ATEP-vectors-v1/{label}").as_bytes())
}

/// Deterministic seeds for a named test identity. Documented in the README.
pub fn vector_seeds(name: &str, with_enc: bool) -> Seeds {
    let mut mlkem = [0u8; 64];
    mlkem[..32].copy_from_slice(&label_hash(&format!("{name}/mlkem768/d")));
    mlkem[32..].copy_from_slice(&label_hash(&format!("{name}/mlkem768/z")));
    Seeds {
        ed25519: label_hash(&format!("{name}/ed25519")),
        mldsa65: label_hash(&format!("{name}/mldsa65")),
        x25519: with_enc.then(|| label_hash(&format!("{name}/x25519"))),
        mlkem768: with_enc.then_some(mlkem),
    }
}

pub(crate) fn nonce(label: &str) -> [u8; 16] {
    label_hash(&format!("nonce/{label}"))[..16]
        .try_into()
        .unwrap()
}

pub(crate) fn seeds_json(s: &Seeds) -> J {
    let mut m = Map::new();
    m.insert("ed25519".into(), hx(&s.ed25519).into());
    m.insert("mldsa65".into(), hx(&s.mldsa65).into());
    if let Some(x) = &s.x25519 {
        m.insert("x25519".into(), hx(x).into());
    }
    if let Some(k) = &s.mlkem768 {
        m.insert("mlkem768".into(), hx(k).into());
    }
    J::Object(m)
}

pub(crate) fn jget<'a>(j: &'a J, k: &str) -> R<&'a J> {
    j.get(k).ok_or_else(|| e(format!("missing field `{k}`")))
}

pub(crate) fn jstr<'a>(j: &'a J, k: &str) -> R<&'a str> {
    jget(j, k)?
        .as_str()
        .ok_or_else(|| e(format!("field `{k}` is not a string")))
}

pub(crate) fn jint(j: &J, k: &str) -> R<i64> {
    jget(j, k)?
        .as_i64()
        .ok_or_else(|| e(format!("field `{k}` is not an integer")))
}

pub(crate) fn jhex<const N: usize>(j: &J, k: &str) -> R<[u8; N]> {
    unhex(jstr(j, k)?)?
        .try_into()
        .map_err(|_| e(format!("field `{k}` must be {N} bytes")))
}

pub(crate) fn seeds_from_json(j: &J) -> R<Seeds> {
    let opt = |k: &str| -> R<Option<Vec<u8>>> {
        match j.get(k) {
            None => Ok(None),
            Some(v) => Ok(Some(unhex(
                v.as_str().ok_or_else(|| e("seed is not a string"))?,
            )?)),
        }
    };
    let fix = |v: Vec<u8>, n: usize| -> R<Vec<u8>> {
        if v.len() == n {
            Ok(v)
        } else {
            Err(e(format!("seed must be {n} bytes")))
        }
    };
    let ed = fix(unhex(jstr(j, "ed25519")?)?, 32)?;
    let ml = fix(unhex(jstr(j, "mldsa65")?)?, 32)?;
    let x = opt("x25519")?.map(|v| fix(v, 32)).transpose()?;
    let k = opt("mlkem768")?.map(|v| fix(v, 64)).transpose()?;
    Ok(Seeds {
        ed25519: ed.try_into().unwrap(),
        mldsa65: ml.try_into().unwrap(),
        x25519: x.map(|v| v.try_into().unwrap()),
        mlkem768: k.map(|v| v.try_into().unwrap()),
    })
}

pub(crate) fn payload_for(label: &str) -> Vec<u8> {
    Value::Map(vec![
        (Value::text("vector"), Value::text(label)),
        (Value::text("note"), Value::text("ATEP test payload")),
    ])
    .encode()
}

pub(crate) struct Vector {
    pub category: &'static str,
    pub name: String,
    pub description: String,
    pub cbor: Vec<u8>,
    pub inputs: J,
    pub expected: J,
}

// ---------------------------------------------------------------------------
// Policy handling shared by generator and checker

#[derive(Default)]
pub(crate) struct PolicySpec {
    pub now: i64,
    pub recipient: Option<Seeds>,
    pub known_bundles: Vec<PublicBundle>,
    pub seen_nonces: Vec<[u8; 16]>,
    pub revocations: Vec<Revocation>,
    pub detached_payload: Option<Vec<u8>>,
    /// M2: trust policy in the policy file format.
    pub trust: Option<J>,
    /// M2: attestations known out of band.
    pub attestations: Vec<Vec<u8>>,
    /// M2: cached SRL envelopes.
    pub srls: Vec<Vec<u8>>,
}

impl PolicySpec {
    pub(crate) fn to_json(&self) -> J {
        let mut m = Map::new();
        m.insert("now".into(), self.now.into());
        m.insert("max_skew_secs".into(), DEFAULT_SKEW_SECS.into());
        if let Some(s) = &self.recipient {
            m.insert("recipient_seeds".into(), seeds_json(s));
        }
        m.insert(
            "known_bundles".into(),
            self.known_bundles
                .iter()
                .map(|b| J::String(hx(&b.encode())))
                .collect::<Vec<_>>()
                .into(),
        );
        m.insert(
            "seen_nonces".into(),
            self.seen_nonces
                .iter()
                .map(|n| J::String(hx(n)))
                .collect::<Vec<_>>()
                .into(),
        );
        m.insert(
            "revocations".into(),
            self.revocations
                .iter()
                .map(|r| {
                    json!({
                        "id": r.id.to_text(),
                        "reason": r.reason.as_str(),
                        "revoked_at": r.revoked_at,
                    })
                })
                .collect::<Vec<_>>()
                .into(),
        );
        if let Some(p) = &self.detached_payload {
            m.insert("detached_payload_hex".into(), hx(p).into());
        }
        if let Some(t) = &self.trust {
            m.insert("trust".into(), t.clone());
        }
        if !self.attestations.is_empty() {
            m.insert(
                "attestations".into(),
                self.attestations
                    .iter()
                    .map(|a| J::String(hx(a)))
                    .collect::<Vec<_>>()
                    .into(),
            );
        }
        if !self.srls.is_empty() {
            m.insert(
                "srls".into(),
                self.srls
                    .iter()
                    .map(|a| J::String(hx(a)))
                    .collect::<Vec<_>>()
                    .into(),
            );
        }
        J::Object(m)
    }
}

/// Directly supplied identity revocations: `[{id, reason, revoked_at}]`.
pub(crate) fn parse_revocations(j: &J) -> R<Vec<Revocation>> {
    let mut out = Vec::new();
    for r in j.as_array().ok_or_else(|| e("revocations"))? {
        out.push(Revocation {
            id: AgentId::parse(jstr(r, "id")?)?,
            reason: match jstr(r, "reason")? {
                "retired" => RevocationReason::Retired,
                "compromised" => RevocationReason::Compromised,
                other => return Err(e(format!("unknown revocation reason {other}"))),
            },
            revoked_at: jint(r, "revoked_at")?,
        });
    }
    Ok(out)
}

/// Run `verify` using the policy object recorded in a vector.
pub(crate) fn run_verify(cbor: &[u8], p: &J) -> R<J> {
    let now = jint(p, "now")?;
    let recipient = match p.get("recipient_seeds") {
        Some(s) => Some(Identity::from_seeds(seeds_from_json(s)?)?),
        None => None,
    };
    let mut cache = MemorySrlCache::new();
    let mut pol = Policy {
        recipient: recipient.as_ref(),
        max_skew_secs: jint(p, "max_skew_secs")?,
        ..Policy::default()
    };
    for b in jget(p, "known_bundles")?
        .as_array()
        .ok_or_else(|| e("known_bundles"))?
    {
        pol.known_bundles.push(PublicBundle::decode(&unhex(
            b.as_str().ok_or_else(|| e("known_bundles entry"))?,
        )?)?);
    }
    for n in jget(p, "seen_nonces")?
        .as_array()
        .ok_or_else(|| e("seen_nonces"))?
    {
        let v = unhex(n.as_str().ok_or_else(|| e("seen_nonces entry"))?)?;
        pol.seen_nonces
            .push(v.try_into().map_err(|_| e("nonce must be 16 bytes"))?);
    }
    pol.revocations = parse_revocations(jget(p, "revocations")?)?;
    if let Some(d) = p.get("detached_payload_hex") {
        pol.detached_payload = Some(unhex(d.as_str().ok_or_else(|| e("detached_payload_hex"))?)?);
    }
    if let Some(t) = p.get("trust") {
        pol.trust = Some(TrustPolicy::from_json(t)?);
    }
    for a in p
        .get("attestations")
        .and_then(|a| a.as_array())
        .into_iter()
        .flatten()
    {
        pol.attestations
            .push(unhex(a.as_str().ok_or_else(|| e("attestations entry"))?)?);
    }
    if let Some(list) = p.get("srls").and_then(|a| a.as_array()) {
        for r in list {
            let raw = unhex(r.as_str().ok_or_else(|| e("srls entry"))?)?;
            // Loaded in the verifier's own context: the cache so far, the
            // directly supplied revocations and the local attestation store.
            let cx = crate::srl::LoadContext {
                known_bundles: &pol.known_bundles,
                revocations: &pol.revocations,
                attestations: &pol.attestations,
                srls: None,
                max_skew_secs: pol.max_skew_secs,
            };
            crate::srl::ingest_in(&mut cache, &raw, &cx, now)
                .map_err(|x| e(format!("srl in policy: {x}")))?;
        }
        pol.srls = Some(&cache);
    }
    Ok(crate::json::verify_result(&verify(cbor, &pol, now)))
}

// ---------------------------------------------------------------------------
// Generation

struct Cast {
    alice: Identity,
    bob: Identity,
    carol: Identity,
    mallory: Identity,
}

fn cast() -> R<Cast> {
    Ok(Cast {
        alice: Identity::from_seeds(vector_seeds("alice", false))?,
        bob: Identity::from_seeds(vector_seeds("bob", true))?,
        carol: Identity::from_seeds(vector_seeds("carol", true))?,
        mallory: Identity::from_seeds(vector_seeds("mallory", false))?,
    })
}

fn headers(
    id: &Identity,
    ct: &str,
    issued: i64,
    expires: Option<i64>,
    label: &str,
    payload: &[u8],
) -> Headers {
    Headers {
        content_type: ct.to_string(),
        version: ATEP_VERSION,
        signer: id.agent_id().0,
        issued_at: issued,
        expires_at: expires,
        nonce: nonce(label),
        payload_digest: sha256(payload),
        suite: SUITE_ATEP_1.to_string(),
        command_class: None,
    }
}

fn raw<'a>(id: &'a Identity, h: Headers, payload: &[u8]) -> RawSpec<'a> {
    RawSpec {
        headers: h,
        payload: payload.to_vec(),
        attach_payload: true,
        bundle_in_header: Some(id.public().clone()),
        ed_signer: Some(id),
        pq_signer: Some(id),
        kid: id.agent_id().0,
        mode: SignMode::Deterministic,
    }
}

fn signed_doc<'a>(
    label: &str,
    id: &'a Identity,
    ct: &str,
    issued: i64,
    expires: Option<i64>,
    tweak: impl FnOnce(&mut RawSpec<'a>),
) -> R<Vec<u8>> {
    let payload = payload_for(label);
    let h = headers(id, ct, issued, expires, label, &payload);
    let mut spec = raw(id, h, &payload);
    tweak(&mut spec);
    sign_raw(&spec)
}

pub(crate) fn mutate(env: &[u8], f: impl FnOnce(&mut Vec<Value>)) -> R<Vec<u8>> {
    let mut v = Value::decode(env)?;
    if let Value::Tag(_, inner) = &mut v {
        if let Value::Array(a) = inner.as_mut() {
            f(a);
            return Ok(v.encode());
        }
    }
    Err(e("mutate: not a tagged array"))
}

pub(crate) fn flip_last(v: &mut Value) {
    if let Value::Bytes(b) = v {
        let n = b.len();
        b[n - 1] ^= 0x01;
    }
}

pub(crate) fn sig_slot(a: &mut [Value], idx: usize) -> &mut Value {
    match &mut a[3] {
        Value::Array(sigs) => match &mut sigs[idx] {
            Value::Array(s) => &mut s[2],
            _ => panic!("bad signature entry"),
        },
        _ => panic!("bad signatures"),
    }
}

pub(crate) fn pol(now: i64) -> PolicySpec {
    PolicySpec {
        now,
        ..PolicySpec::default()
    }
}

struct NegSpec {
    name: &'static str,
    description: &'static str,
    cbor: Vec<u8>,
    policy: PolicySpec,
}

fn generate_vectors() -> R<Vec<Vector>> {
    let c = cast()?;
    let mut out: Vec<Vector> = Vec::new();

    // Identity vectors.
    for (name, with_enc) in [
        ("alice", false),
        ("bob", true),
        ("carol", true),
        ("mallory", false),
    ] {
        let seeds = vector_seeds(name, with_enc);
        let id = Identity::from_seeds(seeds.clone())?;
        let bundle = id.public().encode();
        out.push(Vector {
            category: "identity",
            name: name.to_string(),
            description: format!(
                "Key bundle and Agent ID for `{name}` ({} keys).",
                if with_enc {
                    "signing and encryption"
                } else {
                    "signing only"
                }
            ),
            cbor: bundle.clone(),
            inputs: json!({ "seeds": seeds_json(&seeds) }),
            expected: json!({
                "agent_id": id.agent_id().to_text(),
                "did": id.agent_id().to_did(),
                "agent_id_hex": hx(&id.agent_id().0),
                "bundle_len": bundle.len(),
                "ed25519_public_hex": hx(&id.public().ed25519),
                "mldsa65_public_sha256": hx(&sha256(&id.public().mldsa65)),
            }),
        });
    }

    // Signing vectors.
    struct SignCase {
        name: &'static str,
        description: &'static str,
        ct: &'static str,
        expires: Option<i64>,
        detached: bool,
        bundle: bool,
    }
    let sign_cases = [
        SignCase {
            name: "trust-doc-inline-bundle",
            description: "Attestation-typed document, attached payload, public bundle in the unprotected header.",
            ct: CT_ATTESTATION,
            expires: Some(NOW + 86_400 * 90),
            detached: false,
            bundle: true,
        },
        SignCase {
            name: "trust-doc-no-bundle",
            description: "Same as above but without the inline bundle.",
            ct: CT_ATTESTATION,
            expires: Some(NOW + 86_400 * 90),
            detached: false,
            bundle: false,
        },
        SignCase {
            name: "trust-doc-detached-payload",
            description: "Detached payload: the payload slot is nil and the digest binds the payload.",
            ct: CT_ATTESTATION,
            expires: Some(NOW + 86_400 * 90),
            detached: true,
            bundle: true,
        },
        SignCase {
            name: "data-no-expiry",
            description: "Data envelope without expires-at (signed only; exchanged envelopes are then encrypted).",
            ct: CT_DATA,
            expires: None,
            detached: false,
            bundle: true,
        },
        SignCase {
            name: "data-with-expiry",
            description: "Data envelope with expires-at.",
            ct: CT_DATA,
            expires: Some(NOW + 3_600),
            detached: false,
            bundle: true,
        },
    ];
    for sc in &sign_cases {
        let payload = payload_for(sc.name);
        let n = nonce(sc.name);
        let issued = NOW - 60;
        let mut p = SignParams::new(&payload, sc.ct, n, issued);
        p.expires_at = sc.expires;
        p.detached = sc.detached;
        p.include_bundle = sc.bundle;
        p.mode = SignMode::Deterministic;
        let env = sign(&c.alice, &p)?;
        out.push(Vector {
            category: "signing",
            name: sc.name.to_string(),
            description: sc.description.to_string(),
            cbor: env.clone(),
            inputs: json!({
                "signer_seeds": seeds_json(c.alice.seeds()),
                "payload_hex": hx(&payload),
                "content_type": sc.ct,
                "nonce_hex": hx(&n),
                "issued_at": issued,
                "expires_at": sc.expires,
                "detached": sc.detached,
                "include_bundle": sc.bundle,
                "mode": "deterministic",
            }),
            expected: json!({
                "signer": c.alice.agent_id().to_text(),
                "payload_digest_hex": hx(&sha256(&payload)),
                "envelope_len": env.len(),
                "envelope_sha256": hx(&sha256(&env)),
            }),
        });
    }

    // Verification vectors.
    let mut positives: Vec<NegSpec> = Vec::new();
    let mut negatives: Vec<NegSpec> = Vec::new();
    let att_window = (NOW - 3_600, Some(NOW + 86_400 * 30));

    // Positives.
    positives.push(NegSpec {
        name: "signed-trust-doc-inline-bundle",
        description: "Signed-only attestation-typed document with the signer bundle inline.",
        cbor: signed_doc(
            "p1",
            &c.alice,
            CT_ATTESTATION,
            att_window.0,
            att_window.1,
            |_| {},
        )?,
        policy: pol(NOW),
    });
    let mut p = pol(NOW);
    p.known_bundles = vec![c.alice.public().clone()];
    positives.push(NegSpec {
        name: "signed-trust-doc-cached-bundle",
        description: "No inline bundle; the verifier resolves the signer from its cache.",
        cbor: signed_doc(
            "p2",
            &c.alice,
            CT_ATTESTATION,
            att_window.0,
            att_window.1,
            |s| s.bundle_in_header = None,
        )?,
        policy: p,
    });
    let detached_payload = payload_for("p3");
    let mut p = pol(NOW);
    p.detached_payload = Some(detached_payload);
    positives.push(NegSpec {
        name: "signed-trust-doc-detached-payload",
        description: "Detached payload supplied by the caller.",
        cbor: signed_doc(
            "p3",
            &c.alice,
            CT_ATTESTATION,
            att_window.0,
            att_window.1,
            |s| s.attach_payload = false,
        )?,
        policy: p,
    });
    positives.push(NegSpec {
        name: "signed-srl-no-expiry",
        description: "SRL-typed trust document without expires-at (optional outside attestations).",
        cbor: signed_doc("p4", &c.alice, CT_SRL, NOW - 10, None, |_| {})?,
        policy: pol(NOW),
    });
    positives.push(NegSpec {
        name: "issued-at-skew-boundary",
        description: "issued-at exactly 300 s in the future is accepted.",
        cbor: signed_doc("p5", &c.alice, CT_CHECKPOINT, NOW + 300, None, |_| {})?,
        policy: pol(NOW),
    });
    positives.push(NegSpec {
        name: "revocation-after-issuance-ignored",
        description: "Signer is revoked, but only after the envelope was issued (revoked-at later than issued-at).",
        cbor: signed_doc("p6", &c.alice, CT_SRL, NOW - 10, None, |_| {})?,
        policy: {
            let mut p = pol(NOW);
            p.revocations = vec![Revocation {
                id: c.alice.agent_id(),
                reason: RevocationReason::Compromised,
                revoked_at: NOW,
            }];
            p
        },
    });

    // Encryption cases double as verification positives.
    let mut enc_vectors: Vec<Vector> = Vec::new();
    struct EncCase {
        name: &'static str,
        description: &'static str,
        expires: Option<i64>,
    }
    let enc_cases = [
        EncCase {
            name: "alice-to-bob",
            description: "alice signs a data envelope and encrypts it to bob.",
            expires: None,
        },
        EncCase {
            name: "alice-to-bob-with-expiry",
            description: "As above with expires-at set in the inner envelope.",
            expires: Some(NOW + 3_600),
        },
    ];
    let mut enc_built: Vec<(String, Vec<u8>)> = Vec::new();
    for ec in &enc_cases {
        let label = format!("enc-{}", ec.name);
        let payload = payload_for(&label);
        let mut sp = SignParams::new(&payload, CT_DATA, nonce(&label), NOW - 30);
        sp.expires_at = ec.expires;
        sp.mode = SignMode::Deterministic;
        let inner = sign(&c.alice, &sp)?;
        let rnd = EncryptRandomness {
            x25519_ephemeral: label_hash(&format!("{label}/x25519-ephemeral")),
            mlkem_m: label_hash(&format!("{label}/mlkem-m")),
            iv: label_hash(&format!("{label}/iv"))[..12].try_into().unwrap(),
        };
        let (ct, trace) = encrypt_traced(&inner, c.bob.public(), &rnd)?;
        enc_built.push((ec.name.to_string(), ct.clone()));
        enc_vectors.push(Vector {
            category: "encryption",
            name: ec.name.to_string(),
            description: ec.description.to_string(),
            cbor: ct.clone(),
            inputs: json!({
                "recipient_seeds": seeds_json(c.bob.seeds()),
                "inner_envelope_hex": hx(&inner),
                "randomness": {
                    "x25519_ephemeral_hex": hx(&rnd.x25519_ephemeral),
                    "mlkem_m_hex": hx(&rnd.mlkem_m),
                    "iv_hex": hx(&rnd.iv),
                },
            }),
            expected: json!({
                "recipient": c.bob.agent_id().to_text(),
                "ciphertext_len": ct.len(),
                "ciphertext_sha256": hx(&sha256(&ct)),
                "intermediate": {
                    "eph_x25519_public_hex": hx(&trace.eph_x25519_public),
                    "mlkem_ciphertext_sha256": hx(&sha256(&trace.mlkem_ciphertext)),
                    "ss_x25519_hex": hx(&trace.ss_x25519),
                    "ss_mlkem768_hex": hx(&trace.ss_mlkem768),
                    "hkdf_info_hex": hx(&trace.hkdf_info),
                    "aes_key_hex": hx(&trace.aes_key),
                },
            }),
        });
        let mut p = pol(NOW);
        p.recipient = Some(c.bob.seeds().clone());
        positives.push(NegSpec {
            name: if ec.name == "alice-to-bob" {
                "encrypted-data-envelope"
            } else {
                "encrypted-data-envelope-with-expiry"
            },
            description: "Encrypted data envelope opened by the recipient and verified.",
            cbor: ct,
            policy: p,
        });
    }

    // Negatives.
    let bob_policy = || {
        let mut p = pol(NOW);
        p.recipient = Some(c.bob.seeds().clone());
        p
    };
    negatives.push(NegSpec {
        name: "missing-pq-signature",
        description:
            "Only the EdDSA signature is present; the ML-DSA-65 entry is absent. Expect step 1.",
        cbor: signed_doc(
            "n-missing-pq",
            &c.alice,
            CT_ATTESTATION,
            att_window.0,
            att_window.1,
            |s| s.pq_signer = None,
        )?,
        policy: pol(NOW),
    });
    negatives.push(NegSpec {
        name: "missing-classical-signature",
        description: "Only the ML-DSA-65 signature is present. Expect step 1.",
        cbor: signed_doc(
            "n-missing-ed",
            &c.alice,
            CT_ATTESTATION,
            att_window.0,
            att_window.1,
            |s| s.ed_signer = None,
        )?,
        policy: pol(NOW),
    });
    negatives.push(NegSpec {
        name: "swapped-key",
        description: "signer header is alice, but the inline bundle replaces alice's ML-DSA key with mallory's and the PQ signature is mallory's. Expect step 3 (bundle hash differs from signer).",
        cbor: signed_doc("n-swapped", &c.alice, CT_ATTESTATION, att_window.0, att_window.1, |s| {
            let mut b = c.alice.public().clone();
            b.mldsa65 = c.mallory.public().mldsa65.clone();
            s.bundle_in_header = Some(b);
            s.pq_signer = Some(&c.mallory);
        })?,
        policy: pol(NOW),
    });
    negatives.push(NegSpec {
        name: "expired",
        description: "expires-at is before now. Signatures are valid. Expect step 5.",
        cbor: signed_doc(
            "n-expired",
            &c.alice,
            CT_ATTESTATION,
            NOW - 2_000,
            Some(NOW - 1_000),
            |_| {},
        )?,
        policy: pol(NOW),
    });
    negatives.push(NegSpec {
        name: "expires-exactly-now",
        description: "expires-at equals now; it MUST be later than now. Expect step 5.",
        cbor: signed_doc(
            "n-expires-now",
            &c.alice,
            CT_ATTESTATION,
            NOW - 2_000,
            Some(NOW),
            |_| {},
        )?,
        policy: pol(NOW),
    });
    negatives.push(NegSpec {
        name: "future-dated",
        description: "issued-at is 3600 s after now, beyond the 300 s skew. Expect step 5.",
        cbor: signed_doc(
            "n-future",
            &c.alice,
            CT_ATTESTATION,
            NOW + 3_600,
            Some(NOW + 7_200),
            |_| {},
        )?,
        policy: pol(NOW),
    });
    negatives.push(NegSpec {
        name: "future-dated-just-over-skew",
        description: "issued-at is now + 301 s. Expect step 5.",
        cbor: signed_doc("n-future-301", &c.alice, CT_SRL, NOW + 301, None, |_| {})?,
        policy: pol(NOW),
    });
    negatives.push(NegSpec {
        name: "bad-digest",
        description: "Signed correctly, but payload-digest is the SHA-256 of different bytes. Expect step 7.",
        cbor: signed_doc("n-digest", &c.alice, CT_ATTESTATION, att_window.0, att_window.1, |s| {
            s.headers.payload_digest = sha256(b"some other payload")
        })?,
        policy: pol(NOW),
    });
    negatives.push(NegSpec {
        name: "unknown-suite",
        description: "suite is `ATEP-9`; otherwise valid and signed. Expect step 1.",
        cbor: signed_doc(
            "n-suite",
            &c.alice,
            CT_ATTESTATION,
            att_window.0,
            att_window.1,
            |s| s.headers.suite = "ATEP-9".into(),
        )?,
        policy: pol(NOW),
    });
    negatives.push(NegSpec {
        name: "unsupported-version",
        description: "atep-version is 2. Expect step 1.",
        cbor: signed_doc(
            "n-version",
            &c.alice,
            CT_ATTESTATION,
            att_window.0,
            att_window.1,
            |s| s.headers.version = 2,
        )?,
        policy: pol(NOW),
    });
    negatives.push(NegSpec {
        name: "signer-mismatch",
        description: "signer header names bob, but the inline bundle and the signatures are alice's. Expect step 3.",
        cbor: signed_doc("n-signer", &c.alice, CT_ATTESTATION, att_window.0, att_window.1, |s| {
            s.headers.signer = c.bob.agent_id().0;
            s.kid = c.bob.agent_id().0;
        })?,
        policy: pol(NOW),
    });
    negatives.push(NegSpec {
        name: "signer-bundle-unavailable",
        description: "No inline bundle and no cached bundle for the signer. Expect step 3.",
        cbor: signed_doc(
            "n-nobundle",
            &c.alice,
            CT_ATTESTATION,
            att_window.0,
            att_window.1,
            |s| s.bundle_in_header = None,
        )?,
        policy: pol(NOW),
    });
    negatives.push(NegSpec {
        name: "unencrypted-non-trust-doc",
        description: "A tag 98 envelope with content type application/atep+cbor and no COSE_Encrypt wrapper. Expect step 1.",
        cbor: signed_doc("n-unenc", &c.alice, CT_DATA, att_window.0, att_window.1, |_| {})?,
        policy: pol(NOW),
    });
    negatives.push(NegSpec {
        name: "attestation-without-expires-at",
        description:
            "Attestation content type but no expires-at, which is REQUIRED. Expect step 1.",
        cbor: signed_doc(
            "n-noexp",
            &c.alice,
            CT_ATTESTATION,
            att_window.0,
            None,
            |_| {},
        )?,
        policy: pol(NOW),
    });
    let base = signed_doc(
        "n-tamper",
        &c.alice,
        CT_ATTESTATION,
        att_window.0,
        att_window.1,
        |_| {},
    )?;
    negatives.push(NegSpec {
        name: "tampered-payload",
        description: "A valid envelope whose attached payload has its last byte flipped after signing. Expect step 4 (EdDSA fails first).",
        cbor: mutate(&base, |a| flip_last(&mut a[2]))?,
        policy: pol(NOW),
    });
    negatives.push(NegSpec {
        name: "bad-eddsa-signature",
        description: "Last byte of the EdDSA signature flipped. Expect step 4.",
        cbor: mutate(&base, |a| flip_last(sig_slot(a, 0)))?,
        policy: pol(NOW),
    });
    negatives.push(NegSpec {
        name: "bad-mldsa-signature",
        description: "Last byte of the ML-DSA-65 signature flipped, EdDSA intact. Expect step 4.",
        cbor: mutate(&base, |a| flip_last(sig_slot(a, 1)))?,
        policy: pol(NOW),
    });
    let mut p = pol(NOW);
    p.seen_nonces = vec![nonce("n-replay")];
    negatives.push(NegSpec {
        name: "replayed-nonce",
        description: "The verifier has already seen this nonce. Expect step 6.",
        cbor: signed_doc(
            "n-replay",
            &c.alice,
            CT_ATTESTATION,
            att_window.0,
            att_window.1,
            |_| {},
        )?,
        policy: p,
    });
    let mut p = pol(NOW);
    p.revocations = vec![Revocation {
        id: c.alice.agent_id(),
        reason: RevocationReason::Compromised,
        revoked_at: NOW - 7_200,
    }];
    negatives.push(NegSpec {
        name: "revoked-signer",
        description: "alice is listed as compromised since before issued-at. Expect step 8.",
        cbor: signed_doc(
            "n-revoked",
            &c.alice,
            CT_ATTESTATION,
            att_window.0,
            att_window.1,
            |_| {},
        )?,
        policy: p,
    });
    let bob_ct = enc_built[0].1.clone();
    negatives.push(NegSpec {
        name: "aead-tampered-ciphertext",
        description: "Last byte of the AES-GCM ciphertext flipped. Expect step 2.",
        cbor: mutate(&bob_ct, |a| flip_last(&mut a[2]))?,
        policy: bob_policy(),
    });
    let mut p = pol(NOW);
    p.recipient = Some(c.carol.seeds().clone());
    negatives.push(NegSpec {
        name: "wrong-recipient",
        description: "Encrypted to bob but opened with carol's keys. Expect step 2.",
        cbor: bob_ct.clone(),
        policy: p,
    });
    negatives.push(NegSpec {
        name: "encrypted-without-recipient-key",
        description:
            "Encrypted envelope and the verifier has no recipient identity. Expect step 2.",
        cbor: bob_ct,
        policy: pol(NOW),
    });

    for (cat, specs) in [
        ("verify-positive", positives),
        ("verify-negative", negatives),
    ] {
        for s in specs {
            let policy_json = s.policy.to_json();
            let expected = run_verify(&s.cbor, &policy_json)?;
            let ok = expected["ok"].as_bool().unwrap_or(false);
            if ok != (cat == "verify-positive") {
                return Err(e(format!(
                    "generator bug: vector {}/{} produced {}",
                    cat, s.name, expected
                )));
            }
            out.push(Vector {
                category: if cat == "verify-positive" {
                    "verify-positive"
                } else {
                    "verify-negative"
                },
                name: s.name.to_string(),
                description: s.description.to_string(),
                cbor: s.cbor,
                inputs: json!({ "policy": policy_json }),
                expected,
            });
        }
    }
    out.extend(enc_vectors);
    vectors_trust::generate(&mut out)?;
    Ok(out)
}

/// Produce every vector file as (relative path, bytes), sorted by path.
pub fn generate() -> R<Vec<(String, Vec<u8>)>> {
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    let mut manifest = Vec::new();
    for v in generate_vectors()? {
        let base = format!("{}/{}", v.category, v.name);
        let view_json = view_or_raw(&v.cbor);
        let meta = json!({
            "name": v.name,
            "category": v.category,
            "description": v.description,
            "cbor_file": format!("{}.cbor", v.name),
            "cbor_sha256": hx(&sha256(&v.cbor)),
            "inputs": v.inputs,
            "expected": v.expected,
        });
        manifest.push(json!({
            "category": v.category,
            "name": v.name,
            "cbor_sha256": hx(&sha256(&v.cbor)),
        }));
        files.push((format!("{base}.cbor"), v.cbor));
        files.push((format!("{base}.json"), pretty(&view_json)));
        files.push((format!("{base}.expected.json"), pretty(&meta)));
    }
    files.push((
        "manifest.json".to_string(),
        pretty(&json!({ "now": NOW, "vectors": manifest })),
    ));
    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(files)
}

pub(crate) fn pretty(j: &J) -> Vec<u8> {
    let mut s = serde_json::to_string_pretty(j).expect("json serializes");
    s.push('\n');
    s.into_bytes()
}

/// Write all vectors under `dir` (created if needed).
pub fn write_dir(dir: &Path) -> R<usize> {
    let files = generate()?;
    for (rel, bytes) in &files {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).map_err(|x| e(format!("{}: {x}", parent.display())))?;
        }
        fs::write(&p, bytes).map_err(|x| e(format!("{}: {x}", p.display())))?;
    }
    Ok(files.len())
}

// ---------------------------------------------------------------------------
// Checking

fn check_one(dir: &Path, category: &str, meta_path: &Path) -> R<()> {
    let meta: J = serde_json::from_slice(
        &fs::read(meta_path).map_err(|x| e(format!("{}: {x}", meta_path.display())))?,
    )
    .map_err(|x| e(format!("{}: {x}", meta_path.display())))?;
    let name = jstr(&meta, "name")?;
    let cbor_path = dir.join(category).join(jstr(&meta, "cbor_file")?);
    let cbor = fs::read(&cbor_path).map_err(|x| e(format!("{}: {x}", cbor_path.display())))?;
    if hx(&sha256(&cbor)) != jstr(&meta, "cbor_sha256")? {
        return Err(e("cbor_sha256 mismatch"));
    }
    let view_path = dir.join(category).join(format!("{name}.json"));
    let on_disk: J = serde_json::from_slice(
        &fs::read(&view_path).map_err(|x| e(format!("{}: {x}", view_path.display())))?,
    )
    .map_err(|x| e(format!("json view: {x}")))?;
    if on_disk != view_or_raw(&cbor) {
        return Err(e("JSON view does not match the CBOR file"));
    }
    let inputs = jget(&meta, "inputs")?;
    let expected = jget(&meta, "expected")?;
    match category {
        "identity" => {
            let id = Identity::from_seeds(seeds_from_json(jget(inputs, "seeds")?)?)?;
            if id.public().encode() != cbor {
                return Err(e("bundle bytes differ"));
            }
            let b = PublicBundle::decode(&cbor)?;
            if b.agent_id() != id.agent_id()
                || b.agent_id().to_text() != jstr(expected, "agent_id")?
            {
                return Err(e("agent id mismatch"));
            }
            if b.agent_id().to_did() != jstr(expected, "did")?
                || AgentId::parse(jstr(expected, "did")?)? != b.agent_id()
            {
                return Err(e("did alias mismatch"));
            }
            if hx(&b.agent_id().0) != jstr(expected, "agent_id_hex")? {
                return Err(e("agent_id_hex mismatch"));
            }
        }
        "signing" => {
            let id = Identity::from_seeds(seeds_from_json(jget(inputs, "signer_seeds")?)?)?;
            let payload = unhex(jstr(inputs, "payload_hex")?)?;
            let ct = jstr(inputs, "content_type")?;
            let mut p = SignParams::new(
                &payload,
                ct,
                jhex::<16>(inputs, "nonce_hex")?,
                jint(inputs, "issued_at")?,
            );
            p.expires_at = jget(inputs, "expires_at")?.as_i64();
            p.detached = jget(inputs, "detached")?.as_bool().unwrap_or(false);
            p.include_bundle = jget(inputs, "include_bundle")?.as_bool().unwrap_or(true);
            p.mode = SignMode::Deterministic;
            if sign(&id, &p)? != cbor {
                return Err(e("signed envelope bytes differ"));
            }
            if hx(&sha256(&cbor)) != jstr(expected, "envelope_sha256")? {
                return Err(e("envelope_sha256 mismatch"));
            }
        }
        "verify-positive"
        | "verify-negative"
        | "chain-positive"
        | "chain-negative"
        | "atep-r-positive"
        | "atep-r-negative"
        | "retired-positive"
        | "retired-negative"
        | "successor-positive"
        | "successor-negative"
        | "anchor-media-type"
        | "anchor-not-supported" => {
            let got = run_verify(&cbor, jget(inputs, "policy")?)?;
            if &got != expected {
                return Err(e(format!("result {got} != expected {expected}")));
            }
        }
        "encryption" => {
            let rec = Identity::from_seeds(seeds_from_json(jget(inputs, "recipient_seeds")?)?)?;
            let inner = unhex(jstr(inputs, "inner_envelope_hex")?)?;
            let r = jget(inputs, "randomness")?;
            let rnd = EncryptRandomness {
                x25519_ephemeral: jhex(r, "x25519_ephemeral_hex")?,
                mlkem_m: jhex(r, "mlkem_m_hex")?,
                iv: jhex(r, "iv_hex")?,
            };
            let (ct, trace) = encrypt_traced(&inner, rec.public(), &rnd)?;
            if ct != cbor {
                return Err(e("ciphertext bytes differ"));
            }
            let inter = jget(expected, "intermediate")?;
            if hx(&trace.aes_key) != jstr(inter, "aes_key_hex")?
                || hx(&trace.ss_x25519) != jstr(inter, "ss_x25519_hex")?
                || hx(&trace.ss_mlkem768) != jstr(inter, "ss_mlkem768_hex")?
                || hx(&trace.hkdf_info) != jstr(inter, "hkdf_info_hex")?
            {
                return Err(e("intermediate KEM values differ"));
            }
            let opened = decrypt(&cbor, &rec).map_err(|x| e(x.to_string()))?;
            if opened != inner {
                return Err(e("decrypted envelope differs from the inner envelope"));
            }
        }
        "attestation" | "srl" | "log" | "srl-context" | "log-admission" | "monitor"
        | "checkpoint-hash" | "anchor-record" | "chain-id" | "anchor-envelope"
        | "require-anchor" | "registry-endpoint" | "domain-binding" => {
            vectors_trust::check(category, &cbor, inputs, expected)?
        }
        other => return Err(e(format!("unknown category {other}"))),
    }
    Ok(())
}

/// Check every vector below `dir`. Returns the number checked, or the list of failures.
pub fn check_dir(dir: &Path) -> Result<usize, Vec<String>> {
    let mut failures = Vec::new();
    let mut count = 0usize;
    for cat in CATEGORIES {
        let cat_dir = dir.join(cat);
        let rd = match fs::read_dir(&cat_dir) {
            Ok(r) => r,
            Err(x) => {
                failures.push(format!("{}: {x}", cat_dir.display()));
                continue;
            }
        };
        let mut paths: Vec<_> = rd
            .filter_map(|r| r.ok().map(|d| d.path()))
            .filter(|p| p.to_string_lossy().ends_with(".expected.json"))
            .collect();
        paths.sort();
        for p in paths {
            count += 1;
            if let Err(x) = check_one(dir, cat, &p) {
                failures.push(format!(
                    "{cat}/{}: {x}",
                    p.file_name().unwrap().to_string_lossy()
                ));
            }
        }
    }
    if failures.is_empty() {
        Ok(count)
    } else {
        Err(failures)
    }
}
