//! WebAssembly bindings for `atep-core`. This crate is a thin layer: every
//! behavior comes from `atep-core`; here we only convert between JS values
//! (Uint8Array, JSON text) and the core types.
//!
//! Conventions
//! * Bytes are `Uint8Array`, structured inputs and outputs are JSON text (the
//!   TypeScript layer in `js/src` parses and types them).
//! * Verification outcomes (accept or reject) are returned as JSON, never
//!   thrown. Malformed arguments and signing failures throw an `Error`.
//! * The wasm module has no clock: all times are passed in as Unix seconds.
//! * An `Identity` keeps its secret seeds inside wasm linear memory only
//!   (zeroized by atep-core when the object is freed). Secret bytes are only
//!   copied out by `exportSecret`.

use atep_core::admission::{AdmissionState, CoreClaimRules, Doc};
use atep_core::anchor::{self, AnchorMaxAge, AnchorRecord};
use atep_core::attestation::{self, AttestationParams};
use atep_core::cbor::Value;
use atep_core::domain::{
    self, BindingOptions, DomainFetcher, FetchError, Outcome, SourceResult, TxtAnswer,
    WellKnownResponse,
};
use atep_core::encrypt::{self, EncryptRandomness};
use atep_core::envelope::{self, SignMode, SignParams, SignedEnvelope};
use atep_core::error::{AtepError, Rejection};
use atep_core::json::{checkpoint_json, rejection_json, verify_result};
use atep_core::keys::{fill_random, AgentId, Identity as CoreIdentity, PublicBundle, Seeds};
use atep_core::log::{
    self, Checkpoint, CheckpointPair, ConsistencyEvidence, InclusionCheck, InclusionProof,
    OfflineInclusion,
};
use atep_core::srl::{self, MemorySrlCache, RevocationEntry, RevokedId, Srl, SrlPolicy, StaleMode};
use atep_core::trust::TrustPolicy;
use atep_core::verify::{Policy, Revocation, RevocationReason};
use serde_json::{json, Map, Value as J};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

type R<T> = Result<T, JsError>;

fn err(msg: impl Into<String>) -> JsError {
    JsError::new(&msg.into())
}

fn ae(e: AtepError) -> JsError {
    err(e.0)
}

fn rj(e: Rejection) -> JsError {
    err(e.to_string())
}

fn hexd(s: &str) -> R<Vec<u8>> {
    hex::decode(s).map_err(|x| err(format!("bad hex: {x}")))
}

fn jget<'a>(j: &'a J, k: &str) -> R<&'a J> {
    j.get(k).ok_or_else(|| err(format!("missing field `{k}`")))
}

fn jstr<'a>(j: &'a J, k: &str) -> R<&'a str> {
    jget(j, k)?
        .as_str()
        .ok_or_else(|| err(format!("field `{k}` is not a string")))
}

fn jint(j: &J, k: &str) -> R<i64> {
    jget(j, k)?
        .as_i64()
        .ok_or_else(|| err(format!("field `{k}` is not an integer")))
}

fn jhex<const N: usize>(j: &J, k: &str) -> R<[u8; N]> {
    hexd(jstr(j, k)?)?
        .try_into()
        .map_err(|_| err(format!("field `{k}` must be {N} bytes")))
}

fn opt_hex<const N: usize>(j: &J, k: &str) -> R<Option<[u8; N]>> {
    match j.get(k) {
        None | Some(J::Null) => Ok(None),
        Some(_) => Ok(Some(jhex::<N>(j, k)?)),
    }
}

fn parse_json(s: &str) -> R<J> {
    serde_json::from_str(s).map_err(|x| err(format!("bad JSON: {x}")))
}

fn out(j: J) -> String {
    j.to_string()
}

fn random<const N: usize>() -> R<[u8; N]> {
    let mut b = [0u8; N];
    fill_random(&mut b).map_err(ae)?;
    Ok(b)
}

fn mode_of(j: &J) -> R<SignMode> {
    match j.get("mode").and_then(|m| m.as_str()) {
        None | Some("hedged") => Ok(SignMode::Hedged),
        Some("deterministic") => Ok(SignMode::Deterministic),
        Some(o) => Err(err(format!("unknown signing mode `{o}`"))),
    }
}

fn bundle(b: &[u8]) -> R<PublicBundle> {
    PublicBundle::decode(b).map_err(ae)
}

fn seeds_from_json(j: &J) -> R<Seeds> {
    let fix = |k: &str, n: usize| -> R<Option<Vec<u8>>> {
        match j.get(k) {
            None | Some(J::Null) => Ok(None),
            Some(v) => {
                let b = hexd(v.as_str().ok_or_else(|| err("seed is not a string"))?)?;
                if b.len() != n {
                    return Err(err(format!("seed `{k}` must be {n} bytes")));
                }
                Ok(Some(b))
            }
        }
    };
    let ed = fix("ed25519", 32)?.ok_or_else(|| err("missing seed `ed25519`"))?;
    let ml = fix("mldsa65", 32)?.ok_or_else(|| err("missing seed `mldsa65`"))?;
    Ok(Seeds {
        ed25519: ed.try_into().unwrap(),
        mldsa65: ml.try_into().unwrap(),
        x25519: fix("x25519", 32)?.map(|v| v.try_into().unwrap()),
        mlkem768: fix("mlkem768", 64)?.map(|v| v.try_into().unwrap()),
    })
}

// ---------------------------------------------------------------------------
// Identity

/// An agent identity. The secret seeds stay inside wasm memory.
#[wasm_bindgen(js_name = Identity)]
pub struct WasmIdentity {
    inner: CoreIdentity,
}

#[wasm_bindgen(js_class = Identity)]
impl WasmIdentity {
    /// New identity from system randomness (`crypto.getRandomValues`).
    pub fn generate(with_encryption: bool) -> R<WasmIdentity> {
        Ok(WasmIdentity {
            inner: CoreIdentity::generate(with_encryption).map_err(ae)?,
        })
    }

    /// From raw seeds. `x25519` and `mlkem768` are both given or both empty.
    #[wasm_bindgen(js_name = fromSeeds)]
    pub fn from_seeds(
        ed25519: Vec<u8>,
        mldsa65: Vec<u8>,
        x25519: Option<Vec<u8>>,
        mlkem768: Option<Vec<u8>>,
    ) -> R<WasmIdentity> {
        let ed = Zeroizing::new(ed25519);
        let ml = Zeroizing::new(mldsa65);
        let x = x25519.map(Zeroizing::new);
        let k = mlkem768.map(Zeroizing::new);
        let fixed = |v: &[u8], n: usize, name: &str| -> R<()> {
            if v.len() == n {
                Ok(())
            } else {
                Err(err(format!("{name} seed must be {n} bytes")))
            }
        };
        fixed(&ed, 32, "ed25519")?;
        fixed(&ml, 32, "mldsa65")?;
        if let Some(x) = &x {
            fixed(x, 32, "x25519")?;
        }
        if let Some(k) = &k {
            fixed(k, 64, "mlkem768")?;
        }
        let seeds = Seeds {
            ed25519: ed[..].try_into().unwrap(),
            mldsa65: ml[..].try_into().unwrap(),
            x25519: x.as_ref().map(|v| v[..].try_into().unwrap()),
            mlkem768: k.as_ref().map(|v| v[..].try_into().unwrap()),
        };
        Ok(WasmIdentity {
            inner: CoreIdentity::from_seeds(seeds).map_err(ae)?,
        })
    }

    /// From the CBOR secret key file written by `exportSecret` (and by the Rust CLI).
    #[wasm_bindgen(js_name = fromSecret)]
    pub fn from_secret(secret_file: Vec<u8>) -> R<WasmIdentity> {
        let b = Zeroizing::new(secret_file);
        Ok(WasmIdentity {
            inner: CoreIdentity::from_secret_file(&b).map_err(ae)?,
        })
    }

    /// The CBOR secret key file. This copies secret material into a JS
    /// Uint8Array: the caller owns it and should `.fill(0)` it after use.
    #[wasm_bindgen(js_name = exportSecret)]
    pub fn export_secret(&self) -> Vec<u8> {
        self.inner.to_secret_file()
    }

    /// Agent ID in text form (`atep:...`).
    #[wasm_bindgen(js_name = agentId)]
    pub fn agent_id(&self) -> String {
        self.inner.agent_id().to_text()
    }

    #[wasm_bindgen(js_name = agentIdBytes)]
    pub fn agent_id_bytes(&self) -> Vec<u8> {
        self.inner.agent_id().0.to_vec()
    }

    pub fn did(&self) -> String {
        self.inner.agent_id().to_did()
    }

    /// Canonical public key bundle (CBOR).
    #[wasm_bindgen(js_name = publicBundle)]
    pub fn public_bundle(&self) -> Vec<u8> {
        self.inner.public().encode()
    }

    #[wasm_bindgen(js_name = hasEncryption)]
    pub fn has_encryption(&self) -> bool {
        self.inner.public().enc.is_some()
    }

    /// Sign a payload into a tag 98 envelope. `options` is JSON:
    /// `{content_type?, issued_at, expires_at?, detached?, include_bundle?,
    /// nonce_hex?, mode?: "hedged"|"deterministic", command_class?}`.
    pub fn sign(&self, payload: &[u8], options: &str) -> R<Vec<u8>> {
        let o = parse_json(options)?;
        let ct = o
            .get("content_type")
            .and_then(|c| c.as_str())
            .unwrap_or(atep_core::consts::CT_DATA);
        let nonce = match opt_hex::<16>(&o, "nonce_hex")? {
            Some(n) => n,
            None => random::<16>()?,
        };
        let mut p = SignParams::new(payload, ct, nonce, jint(&o, "issued_at")?);
        p.expires_at = o.get("expires_at").and_then(|v| v.as_i64());
        p.detached = o.get("detached").and_then(|v| v.as_bool()).unwrap_or(false);
        p.include_bundle = o
            .get("include_bundle")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        p.mode = mode_of(&o)?;
        p.command_class = o.get("command_class").and_then(|v| v.as_str());
        envelope::sign(&self.inner, &p).map_err(ae)
    }

    /// Open a tag 96 envelope addressed to this identity; returns the inner
    /// tag 98 envelope (not verified, run `verify` on it or use `verify`
    /// directly with this identity as recipient).
    pub fn decrypt(&self, data: &[u8]) -> R<Vec<u8>> {
        encrypt::decrypt(data, &self.inner).map_err(rj)
    }

    /// Issue an attestation (spec section 7). `options` is JSON:
    /// `{subject, claim, issued_at, expires_at, data?: JSON object (or data_hex: CBOR),
    /// evidence_hex?, evidence_uri?, id_hex?, nonce_hex?, mode?, include_bundle?,
    /// allow_long_default?}`. In `data`, `{"$hex": "..."}` becomes a byte string.
    #[wasm_bindgen(js_name = issueAttestation)]
    pub fn issue_attestation(&self, options: &str) -> R<Vec<u8>> {
        let o = parse_json(options)?;
        let subject = AgentId::parse(jstr(&o, "subject")?).map_err(ae)?;
        let mut p = AttestationParams::new(
            subject,
            jstr(&o, "claim")?,
            jint(&o, "issued_at")?,
            jint(&o, "expires_at")?,
        )
        .map_err(ae)?;
        if let Some(h) = o.get("data_hex").and_then(|v| v.as_str()) {
            p.data = Value::decode(&hexd(h)?).map_err(|x| err(x.to_string()))?;
        } else if let Some(d) = o.get("data") {
            p.data = attestation::json_to_cbor(d).map_err(ae)?;
        }
        p.evidence = opt_hex::<32>(&o, "evidence_hex")?;
        p.evidence_uri = o
            .get("evidence_uri")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        if let Some(id) = opt_hex::<16>(&o, "id_hex")? {
            p.id = id;
        }
        if let Some(n) = opt_hex::<16>(&o, "nonce_hex")? {
            p.nonce = n;
        }
        p.mode = mode_of(&o)?;
        if let Some(b) = o.get("include_bundle").and_then(|v| v.as_bool()) {
            p.include_bundle = b;
        }
        if let Some(b) = o.get("allow_long_default").and_then(|v| v.as_bool()) {
            p.allow_long_default = b;
        }
        attestation::issue(&self.inner, &p).map_err(ae)
    }

    /// Create a signed revocation list (spec section 8). `options` JSON:
    /// `{sequence, issued_at, next_update, revoked: [{id_hex (16 bytes, an
    /// attestation) | id (an Agent ID), reason, revoked_at}], nonce_hex?,
    /// mode?, include_bundle?}`. The issuer is this identity.
    #[wasm_bindgen(js_name = createSrl)]
    pub fn create_srl(&self, options: &str) -> R<Vec<u8>> {
        let o = parse_json(options)?;
        let mut revoked = Vec::new();
        for e in jget(&o, "revoked")?
            .as_array()
            .ok_or_else(|| err("`revoked` must be an array"))?
        {
            let id = if e.get("id_hex").is_some() {
                RevokedId::Attestation(jhex::<16>(e, "id_hex")?)
            } else {
                RevokedId::Identity(AgentId::parse(jstr(e, "id")?).map_err(ae)?)
            };
            revoked.push(RevocationEntry {
                id,
                reason: jstr(e, "reason")?.to_string(),
                revoked_at: jint(e, "revoked_at")?,
            });
        }
        let s = Srl {
            issuer: self.inner.agent_id(),
            sequence: jint(&o, "sequence")?,
            issued_at: jint(&o, "issued_at")?,
            next_update: jint(&o, "next_update")?,
            revoked,
        };
        let nonce = match opt_hex::<16>(&o, "nonce_hex")? {
            Some(n) => n,
            None => random::<16>()?,
        };
        let inc = o
            .get("include_bundle")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        srl::create(&self.inner, &s, nonce, mode_of(&o)?, inc).map_err(ae)
    }

    /// Sign a log checkpoint (this identity is the log). `options` JSON:
    /// `{tree_size, root_hash_hex, timestamp, nonce_hex?, mode?}`.
    #[wasm_bindgen(js_name = createCheckpoint)]
    pub fn create_checkpoint(&self, options: &str) -> R<Vec<u8>> {
        let o = parse_json(options)?;
        let cp = Checkpoint {
            tree_size: jint(&o, "tree_size")?,
            root_hash: jhex::<32>(&o, "root_hash_hex")?,
            timestamp: jint(&o, "timestamp")?,
        };
        let nonce = match opt_hex::<16>(&o, "nonce_hex")? {
            Some(n) => n,
            None => random::<16>()?,
        };
        log::create_checkpoint(&self.inner, &cp, nonce, mode_of(&o)?).map_err(ae)
    }
}

// ---------------------------------------------------------------------------
// Stateless helpers

/// Agent ID (text form) of a public bundle.
#[wasm_bindgen(js_name = agentIdOfBundle)]
pub fn agent_id_of_bundle(bundle_bytes: &[u8]) -> R<String> {
    Ok(bundle(bundle_bytes)?.agent_id().to_text())
}

/// Parse any accepted Agent ID spelling (`atep:` text or `did:atep:`) and
/// return `{text, did, hex}` as JSON.
#[wasm_bindgen(js_name = parseAgentId)]
pub fn parse_agent_id(s: &str) -> R<String> {
    let id = AgentId::parse(s).map_err(ae)?;
    Ok(out(
        json!({"text": id.to_text(), "did": id.to_did(), "hex": hex::encode(id.0)}),
    ))
}

/// SHA-256.
#[wasm_bindgen]
pub fn sha256(data: &[u8]) -> Vec<u8> {
    atep_core::keys::sha256(data).to_vec()
}

/// Encrypt a signed envelope to a recipient bundle with fresh randomness.
#[wasm_bindgen]
pub fn encrypt(signed_envelope: &[u8], recipient_bundle: &[u8]) -> R<Vec<u8>> {
    encrypt::encrypt_random(signed_envelope, &bundle(recipient_bundle)?).map_err(ae)
}

/// Encrypt with caller supplied randomness (for reproducing test vectors; do
/// not use in production). Sizes: 32, 32 and 12 bytes.
#[wasm_bindgen(js_name = encryptWithRandomness)]
pub fn encrypt_with_randomness(
    signed_envelope: &[u8],
    recipient_bundle: &[u8],
    x25519_ephemeral: Vec<u8>,
    mlkem_m: Vec<u8>,
    iv: Vec<u8>,
) -> R<Vec<u8>> {
    let x = Zeroizing::new(x25519_ephemeral);
    let m = Zeroizing::new(mlkem_m);
    let rnd = EncryptRandomness {
        x25519_ephemeral: x[..]
            .try_into()
            .map_err(|_| err("x25519_ephemeral must be 32 bytes"))?,
        mlkem_m: m[..]
            .try_into()
            .map_err(|_| err("mlkem_m must be 32 bytes"))?,
        iv: iv[..].try_into().map_err(|_| err("iv must be 12 bytes"))?,
    };
    encrypt::encrypt(signed_envelope, &bundle(recipient_bundle)?, &rnd).map_err(ae)
}

/// JSON debug view of any ATEP CBOR object.
#[wasm_bindgen]
pub fn view(data: &[u8]) -> R<String> {
    atep_core::json::view(data)
        .map(out)
        .map_err(|x| err(x.to_string()))
}

/// The form of an attestation that is submitted to a log (the `-70012` header removed).
#[wasm_bindgen(js_name = submittedForm)]
pub fn submitted_form(envelope_bytes: &[u8]) -> R<Vec<u8>> {
    envelope::submitted_form(envelope_bytes).map_err(ae)
}

/// Put inline attestations (`-70009`) into the unprotected header of an
/// envelope. `attestations` is a JSON array of hex strings.
#[wasm_bindgen(js_name = withAttestations)]
pub fn with_attestations(envelope_bytes: &[u8], attestations: &str) -> R<Vec<u8>> {
    let a = parse_json(attestations)?;
    let mut vals = Vec::new();
    for h in a.as_array().ok_or_else(|| err("expected an array"))? {
        let raw = hexd(h.as_str().ok_or_else(|| err("expected hex strings"))?)?;
        vals.push(Value::decode(&raw).map_err(|x| err(x.to_string()))?);
    }
    envelope::with_unprotected(
        envelope_bytes,
        vec![(
            atep_core::consts::HDR_ATTESTATIONS,
            Some(Value::Array(vals)),
        )],
    )
    .map_err(ae)
}

/// Attach an inclusion proof (`-70012`) to an attestation. `audit_path` is a
/// JSON array of 32 byte hex hashes, `checkpoint` the signed checkpoint envelope.
#[wasm_bindgen(js_name = withInclusionProof)]
pub fn with_inclusion_proof(
    attestation_bytes: &[u8],
    leaf_index: f64,
    audit_path: &str,
    checkpoint: &[u8],
) -> R<Vec<u8>> {
    let mut path = Vec::new();
    for h in parse_json(audit_path)?
        .as_array()
        .ok_or_else(|| err("expected an array"))?
    {
        let b: [u8; 32] = hexd(h.as_str().ok_or_else(|| err("expected hex strings"))?)?
            .try_into()
            .map_err(|_| err("audit path hashes are 32 bytes"))?;
        path.push(b);
    }
    let proof = InclusionProof {
        leaf_index: leaf_index as i64,
        audit_path: path,
        checkpoint: Value::decode(checkpoint).map_err(|x| err(x.to_string()))?,
    };
    envelope::with_unprotected(
        attestation_bytes,
        vec![(
            atep_core::consts::HDR_INCLUSION_PROOF,
            Some(proof.to_value()),
        )],
    )
    .map_err(ae)
}

/// RFC 9162 Merkle tree root over leaves given as a JSON array of hex strings.
#[wasm_bindgen(js_name = merkleRoot)]
pub fn merkle_root(leaves: &str) -> R<String> {
    let l = leaf_list(leaves)?;
    Ok(hex::encode(log::merkle_root(&l)))
}

/// Audit path for `index` (JSON array of hex hashes) over the leaves.
#[wasm_bindgen(js_name = auditPath)]
pub fn audit_path(index: u32, leaves: &str) -> R<String> {
    let l = leaf_list(leaves)?;
    if index as usize >= l.len() {
        return Err(err("leaf index out of range"));
    }
    Ok(out(log::audit_path(index as usize, &l)
        .iter()
        .map(|h| J::String(hex::encode(h)))
        .collect::<Vec<_>>()
        .into()))
}

fn leaf_list(s: &str) -> R<Vec<Vec<u8>>> {
    parse_json(s)?
        .as_array()
        .ok_or_else(|| err("expected an array"))?
        .iter()
        .map(|h| hexd(h.as_str().ok_or_else(|| err("expected hex strings"))?))
        .collect()
}

// ---------------------------------------------------------------------------
// Verification

/// Verify an envelope (spec section 10, all ten steps). `policy` is JSON in the
/// format of the test vectors: `{max_skew_secs?, known_bundles: [hex],
/// seen_nonces: [hex], revocations: [{id, reason, revoked_at}],
/// detached_payload_hex?, trust?: {...policy file...}, attestations?: [hex],
/// srls?: [hex], recipient_seeds?: {...}}`. A recipient `Identity` object can
/// be passed instead of `recipient_seeds` (preferred: the seeds then never
/// enter JSON). Returns JSON: `{ok: true, signer, ..., payload_hex}` or
/// `{ok: false, step, error, cause?}`.
#[wasm_bindgen]
pub fn verify(data: &[u8], policy: &str, now: f64) -> R<String> {
    verify_impl(data, policy, now, None)
}

/// `verify` with a recipient `Identity` object that opens tag 96 envelopes.
#[wasm_bindgen(js_name = verifyAs)]
pub fn verify_as(recipient: &WasmIdentity, data: &[u8], policy: &str, now: f64) -> R<String> {
    verify_impl(data, policy, now, Some(&recipient.inner))
}

fn verify_impl(data: &[u8], policy: &str, now: f64, recipient: Option<&CoreIdentity>) -> R<String> {
    let p = parse_json(policy)?;
    let now = now as i64;
    let from_seeds = match (recipient, p.get("recipient_seeds")) {
        (None, Some(s)) => Some(CoreIdentity::from_seeds(seeds_from_json(s)?).map_err(ae)?),
        _ => None,
    };
    let recipient_ref: Option<&CoreIdentity> = recipient.or(from_seeds.as_ref());
    let mut cache = MemorySrlCache::new();
    let mut pol = Policy {
        recipient: recipient_ref,
        max_skew_secs: p
            .get("max_skew_secs")
            .and_then(|v| v.as_i64())
            .unwrap_or(atep_core::consts::DEFAULT_SKEW_SECS),
        ..Policy::default()
    };
    for b in list(&p, "known_bundles") {
        pol.known_bundles.push(bundle(&hexd(
            b.as_str().ok_or_else(|| err("known_bundles entry"))?,
        )?)?);
    }
    for n in list(&p, "seen_nonces") {
        let v = hexd(n.as_str().ok_or_else(|| err("seen_nonces entry"))?)?;
        pol.seen_nonces
            .push(v.try_into().map_err(|_| err("nonce must be 16 bytes"))?);
    }
    for r in list(&p, "revocations") {
        pol.revocations.push(revocation_of(r)?);
    }
    if let Some(d) = p.get("detached_payload_hex") {
        pol.detached_payload = Some(hexd(
            d.as_str().ok_or_else(|| err("detached_payload_hex"))?,
        )?);
    }
    if let Some(t) = p.get("trust") {
        pol.trust = Some(TrustPolicy::from_json(t).map_err(ae)?);
    }
    for a in list(&p, "attestations") {
        pol.attestations
            .push(hexd(a.as_str().ok_or_else(|| err("attestations entry"))?)?);
    }
    if let Some(l) = p.get("srls").and_then(|a| a.as_array()) {
        for r in l {
            let raw = hexd(r.as_str().ok_or_else(|| err("srls entry"))?)?;
            // Loaded in the verifier's own context (spec section 8): the lists
            // loaded before, the direct revocations and the local store.
            let cx = srl::LoadContext {
                known_bundles: &pol.known_bundles,
                revocations: &pol.revocations,
                attestations: &pol.attestations,
                srls: None,
                max_skew_secs: pol.max_skew_secs,
            };
            srl::ingest_in(&mut cache, &raw, &cx, now)
                .map_err(|x| err(format!("srl in policy: {x}")))?;
        }
        pol.srls = Some(&cache);
    }
    Ok(out(verify_result(&atep_core::verify::verify(
        data, &pol, now,
    ))))
}

fn revocation_of(r: &J) -> R<Revocation> {
    Ok(Revocation {
        id: AgentId::parse(jstr(r, "id")?).map_err(ae)?,
        reason: match jstr(r, "reason")? {
            "retired" => RevocationReason::Retired,
            "compromised" => RevocationReason::Compromised,
            other => return Err(err(format!("unknown revocation reason {other}"))),
        },
        revoked_at: jint(r, "revoked_at")?,
    })
}

fn list<'a>(p: &'a J, k: &str) -> impl Iterator<Item = &'a J> {
    p.get(k).and_then(|a| a.as_array()).into_iter().flatten()
}

fn offline(trusted: &str) -> R<OfflineInclusion> {
    let t = parse_json(trusted)?;
    let ids = t
        .as_array()
        .ok_or_else(|| err("trusted_logs must be an array"))?
        .iter()
        .map(|t| AgentId::parse(t.as_str().unwrap_or("")).map_err(ae))
        .collect::<R<Vec<_>>>()?;
    Ok(OfflineInclusion {
        trusted_logs: ids,
        known_bundles: vec![],
    })
}

fn checkpoint_result(r: Result<atep_core::log::CheckpointUsed, Rejection>) -> J {
    match r {
        Ok(cp) => json!({"ok": true, "checkpoint": checkpoint_json(&cp)}),
        Err(x) => rejection_json(&x),
    }
}

/// Verify a checkpoint envelope against trusted logs (JSON array of Agent IDs).
#[wasm_bindgen(js_name = verifyCheckpoint)]
pub fn verify_checkpoint(cbor: &[u8], trusted_logs: &str, now: f64) -> R<String> {
    let c = offline(trusted_logs)?;
    Ok(out(checkpoint_result(c.load_checkpoint(cbor, now as i64))))
}

/// Verify the inclusion proof carried by an attestation.
#[wasm_bindgen(js_name = verifyInclusion)]
pub fn verify_inclusion(attestation_bytes: &[u8], trusted_logs: &str, now: f64) -> R<String> {
    let c = offline(trusted_logs)?;
    let env = match SignedEnvelope::decode(attestation_bytes) {
        Ok(e) => e,
        Err(x) => return Ok(out(rejection_json(&x))),
    };
    let submitted = envelope::submitted_form(attestation_bytes).map_err(ae)?;
    Ok(out(checkpoint_result(InclusionCheck::check(
        &c,
        &submitted,
        env.inclusion_proof.as_ref(),
        now as i64,
    ))))
}

fn pair_result(
    r: Result<
        (
            atep_core::log::CheckpointUsed,
            atep_core::log::CheckpointUsed,
        ),
        Rejection,
    >,
    ka: &str,
    kb: &str,
) -> J {
    match r {
        Ok((a, b)) => {
            let mut m = Map::new();
            m.insert("ok".into(), true.into());
            m.insert(ka.into(), checkpoint_json(&a));
            m.insert(kb.into(), checkpoint_json(&b));
            J::Object(m)
        }
        Err(x) => rejection_json(&x),
    }
}

/// Check a consistency proof document `{old, new, proof}` (CBOR).
#[wasm_bindgen(js_name = checkConsistency)]
pub fn check_consistency(cbor: &[u8], trusted_logs: &str, now: f64) -> R<String> {
    let c = offline(trusted_logs)?;
    let doc = Value::decode(cbor).map_err(|x| err(x.to_string()))?;
    let ev = ConsistencyEvidence::from_value(&doc).map_err(|x| err(x.0))?;
    Ok(out(pair_result(
        c.check_consistency(&ev, now as i64),
        "old",
        "new",
    )))
}

/// Check a split view document `{a, b, proof?}` (CBOR).
#[wasm_bindgen(js_name = checkSplitView)]
pub fn check_split_view(cbor: &[u8], trusted_logs: &str, now: f64) -> R<String> {
    let c = offline(trusted_logs)?;
    let doc = Value::decode(cbor).map_err(|x| err(x.to_string()))?;
    let pair = CheckpointPair::from_value(&doc).map_err(|x| err(x.0))?;
    Ok(out(pair_result(
        c.check_split_view(&pair, now as i64),
        "a",
        "b",
    )))
}

/// Verify an SRL envelope and apply the freshness policy. `srl_policy` JSON:
/// `{on_stale: "fail-closed"|"fail-open", on_missing?}`; `cached_srl` is an
/// optional previously accepted SRL envelope (rollback rules apply).
/// `context` is optional JSON `{known_bundles?: [hex], attestations?: [hex],
/// revocations?: [{id, reason, revoked_at}], max_skew_secs?}`: the verifier's
/// own context in which the cached list and the list are loaded (steps 1 to 8,
/// spec section 8). Without it only the inline bundles are known.
#[wasm_bindgen(js_name = verifySrl)]
pub fn verify_srl(
    cbor: &[u8],
    now: f64,
    srl_policy: &str,
    cached_srl: Option<Vec<u8>>,
    context: Option<String>,
) -> R<String> {
    let now = now as i64;
    let sp = parse_json(srl_policy)?;
    let cj = match context {
        Some(c) => parse_json(&c)?,
        None => J::Null,
    };
    let mut known: Vec<PublicBundle> = Vec::new();
    for b in list(&cj, "known_bundles") {
        known.push(bundle(&hexd(
            b.as_str().ok_or_else(|| err("known_bundles entry"))?,
        )?)?);
    }
    let mut revs: Vec<Revocation> = Vec::new();
    for r in list(&cj, "revocations") {
        revs.push(revocation_of(r)?);
    }
    let mut store: Vec<Vec<u8>> = Vec::new();
    for a in list(&cj, "attestations") {
        store.push(hexd(a.as_str().ok_or_else(|| err("attestations entry"))?)?);
    }
    let cx = srl::LoadContext {
        known_bundles: &known,
        revocations: &revs,
        attestations: &store,
        srls: None,
        max_skew_secs: cj
            .get("max_skew_secs")
            .and_then(|v| v.as_i64())
            .unwrap_or(atep_core::consts::DEFAULT_SKEW_SECS),
    };
    let on_stale = StaleMode::parse(jstr(&sp, "on_stale")?).ok_or_else(|| err("bad on_stale"))?;
    let mut cache = MemorySrlCache::new();
    if let Some(c) = cached_srl {
        srl::ingest_in(&mut cache, &c, &cx, now).map_err(|x| err(format!("cached srl: {x}")))?;
    }
    match srl::ingest_in(&mut cache, cbor, &cx, now) {
        Err(x) => Ok(out(rejection_json(&x))),
        Ok(s) => {
            let policy = SrlPolicy {
                on_stale,
                on_missing: StaleMode::FailOpenWithWarning,
            };
            match srl::current_for(Some(&cache), &s.issuer, now, &policy) {
                Err(x) => Ok(out(rejection_json(&x))),
                Ok((_, w)) => Ok(out(srl_json(&s, now, w))),
            }
        }
    }
}

fn srl_json(s: &Srl, now: i64, warning: Option<String>) -> J {
    let mut o = Map::new();
    o.insert("ok".into(), true.into());
    o.insert("issuer".into(), s.issuer.to_text().into());
    o.insert("sequence".into(), s.sequence.into());
    o.insert("issued_at".into(), s.issued_at.into());
    o.insert("next_update".into(), s.next_update.into());
    o.insert("stale".into(), s.is_stale(now).into());
    o.insert(
        "revoked".into(),
        s.revoked
            .iter()
            .map(|e| match &e.id {
                RevokedId::Attestation(id) => json!({
                    "kind": "attestation", "id_hex": hex::encode(id), "reason": e.reason, "revoked_at": e.revoked_at
                }),
                RevokedId::Identity(id) => json!({
                    "kind": "identity", "id": id.to_text(), "reason": e.reason, "revoked_at": e.revoked_at
                }),
            })
            .collect::<Vec<_>>()
            .into(),
    );
    if let Some(w) = warning {
        o.insert("warnings".into(), json!([w]));
    }
    J::Object(o)
}

// ---------------------------------------------------------------------------
// Draft 05: anchors, chain ids, require_anchor, registry-endpoint admission,
// domain binding. Every function returns JSON text in the shapes of
// `vectors/ANCHOR-DISCOVERY-NOTES.md`.

/// Check a `chain-id` (spec section 9, "The `chain-id` registry"): returns
/// `{ok: true, kind: "registered" | "extension"}` or `{ok: false}`.
#[wasm_bindgen(js_name = chainIdKind)]
pub fn chain_id_kind(id: &str) -> String {
    out(if anchor::is_registered_chain(id) {
        json!({"ok": true, "kind": "registered"})
    } else if anchor::is_extension_chain(id) {
        json!({"ok": true, "kind": "extension"})
    } else {
        json!({"ok": false})
    })
}

fn record_json(r: &AnchorRecord) -> J {
    json!({
        "checkpoint_hash": hex::encode(r.checkpoint_hash),
        "chain_id": r.chain_id,
        "transaction_id": r.transaction_id,
        "block_height": r.block_height,
        "anchored_at": r.anchored_at,
    })
}

/// Decode an anchor record payload (strict deterministic CBOR, schema of
/// section 9). Returns `{ok: true, record}` or
/// `{ok: false, error: "anchor_record_invalid"}`. An accepted record must
/// re-encode to the same bytes, else this throws (an internal inconsistency).
#[wasm_bindgen(js_name = parseAnchorRecord)]
pub fn parse_anchor_record(payload: &[u8]) -> R<String> {
    Ok(out(match AnchorRecord::from_payload(payload) {
        Ok(r) => {
            if r.encode() != payload {
                return Err(err(
                    "a decoded anchor record does not re-encode to its bytes",
                ));
            }
            json!({"ok": true, "record": record_json(&r)})
        }
        Err(_) => json!({"ok": false, "error": "anchor_record_invalid"}),
    }))
}

/// Encode an anchor record (deterministic CBOR). `record` is JSON
/// `{checkpoint_hash, chain_id, transaction_id, block_height?, anchored_at}`
/// (the shape `parseAnchorRecord` returns). Throws when the chain id is invalid.
#[wasm_bindgen(js_name = encodeAnchorRecord)]
pub fn encode_anchor_record(record: &str) -> R<Vec<u8>> {
    let j = parse_json(record)?;
    let chain_id = jstr(&j, "chain_id")?.to_string();
    anchor::validate_chain_id(&chain_id).map_err(ae)?;
    let r = AnchorRecord {
        checkpoint_hash: jhex::<32>(&j, "checkpoint_hash")?,
        chain_id,
        transaction_id: jstr(&j, "transaction_id")?.to_string(),
        block_height: match j.get("block_height") {
            None | Some(J::Null) => None,
            Some(_) => Some(jint(&j, "block_height")?),
        },
        anchored_at: jint(&j, "anchored_at")?,
    };
    Ok(r.encode())
}

/// Verify a checkpoint envelope (as `verifyCheckpoint`) and add its checkpoint
/// hash, SHA-256 of the verified payload bytes. Returns
/// `{ok: true, checkpoint, checkpoint_hash, payload_hex}` or a rejection.
#[wasm_bindgen(js_name = checkpointHash)]
pub fn checkpoint_hash(cbor: &[u8], trusted_logs: &str, now: f64) -> R<String> {
    let c = offline(trusted_logs)?;
    let now = now as i64;
    Ok(out(match c.load_checkpoint(cbor, now) {
        Ok(cp) => {
            let v = atep_core::verify::verify(cbor, &Policy::default(), now).map_err(rj)?;
            let hash = log::checkpoint_hash(&v.payload);
            let parsed = Checkpoint::from_payload(&v.payload).map_err(|x| err(x.0))?;
            if parsed.hash() != hash {
                return Err(err("checkpoint hash differs from the hash of the payload"));
            }
            json!({
                "ok": true,
                "checkpoint": checkpoint_json(&cp),
                "checkpoint_hash": hex::encode(hash),
                "payload_hex": hex::encode(&v.payload),
            })
        }
        Err(x) => rejection_json(&x),
    }))
}

/// Take a log-signed anchor envelope as published (spec section 9, "Anchor
/// records"): steps 1 to 8, content type, record schema, signer is `log`,
/// record is for `checkpoint_hash_hex`. Returns `{ok: true, log, record}` or
/// `{ok: false, step, error}`.
#[wasm_bindgen(js_name = checkPublishedAnchor)]
pub fn check_published_anchor(
    cbor: &[u8],
    log_id: &str,
    checkpoint_hash_hex: &str,
    now: f64,
) -> R<String> {
    let log = AgentId::parse(log_id).map_err(ae)?;
    let hash: [u8; 32] = hexd(checkpoint_hash_hex)?
        .try_into()
        .map_err(|_| err("checkpoint hash must be 32 bytes"))?;
    Ok(out(
        match anchor::check_published_anchor(cbor, &log, &hash, now as i64) {
            Ok(rec) => json!({"ok": true, "log": log.to_text(), "record": record_json(&rec)}),
            Err(x) => rejection_json(&x),
        },
    ))
}

/// Parse the `require_anchor` rules of a trust policy (a JSON object, the
/// policy file format). Returns `{ok: true, require_anchor: [...]}` or
/// `{ok: false, error: "policy_invalid"}` (a configuration error, no step).
#[wasm_bindgen(js_name = parseRequireAnchor)]
pub fn parse_require_anchor(policy: &str) -> R<String> {
    let p = parse_json(policy)?;
    Ok(out(match TrustPolicy::from_json(&p) {
        Ok(tp) => {
            let rules: Vec<J> = tp
                .require_anchor
                .iter()
                .map(|r| {
                    let mut m = Map::new();
                    m.insert("log".into(), r.log.to_text().into());
                    m.insert("chain".into(), r.chain.clone().into());
                    match r.max_age {
                        AnchorMaxAge::Days(d) => m.insert("max_age_days".into(), d.into()),
                        AnchorMaxAge::Hours(h) => m.insert("max_age_hours".into(), h.into()),
                    };
                    J::Object(m)
                })
                .collect();
            json!({"ok": true, "require_anchor": rules})
        }
        Err(_) => json!({"ok": false, "error": "policy_invalid"}),
    }))
}

/// Run the admission rules of a log (spec section 9, "Admission", the 14 core
/// claim types, `registry-endpoint` and `domain-control` data rules) on a
/// submission. `options` JSON: `{now, log, max_envelope_bytes, logged?: [hex]}`
/// where `logged` are documents admitted first, in order. Returns
/// `{ok: true, document}` or `{ok: false, refusal, step?, error?}`.
#[wasm_bindgen(js_name = checkAdmission)]
pub fn check_admission(cbor: &[u8], options: &str) -> R<String> {
    let o = parse_json(options)?;
    let now = jint(&o, "now")?;
    let max = jint(&o, "max_envelope_bytes")? as usize;
    let log = AgentId::parse(jstr(&o, "log")?).map_err(ae)?;
    let mut state = AdmissionState::default();
    for l in list(&o, "logged") {
        let raw = hexd(l.as_str().ok_or_else(|| err("logged entry"))?)?;
        state
            .submit(&raw, log, &CoreClaimRules, max, now)
            .map_err(|x| err(format!("logged entry was refused: {x}")))?;
    }
    Ok(out(
        match state.submit(cbor, log, &CoreClaimRules, max, now) {
            Ok(adm) => json!({
                "ok": true,
                "document": match adm.doc { Doc::Attestation(_) => "attestation", Doc::Srl(_) => "srl" },
            }),
            Err(x) => {
                let mut o = Map::new();
                o.insert("ok".into(), false.into());
                o.insert("refusal".into(), x.code.into());
                if let Some(r) = &x.rejection {
                    o.insert("step".into(), r.step.into());
                    o.insert("error".into(), r.code.as_str().into());
                }
                J::Object(o)
            }
        },
    ))
}

// Domain binding: a fetcher that answers from a fixture and records what was asked.

type WkAnswer = Result<WellKnownResponse, FetchError>;
type TxtResult = Result<TxtAnswer, FetchError>;

struct Fake {
    wk: std::collections::HashMap<String, WkAnswer>,
    txt: std::collections::HashMap<String, TxtResult>,
    asked_wk: std::cell::RefCell<Vec<String>>,
    asked_txt: std::cell::RefCell<Vec<String>>,
}

impl DomainFetcher for Fake {
    fn fetch_well_known(&self, d: &str) -> WkAnswer {
        self.asked_wk.borrow_mut().push(d.to_string());
        self.wk.get(d).cloned().unwrap_or(Err(FetchError::NotFound))
    }
    fn fetch_txt(&self, name: &str) -> TxtResult {
        self.asked_txt.borrow_mut().push(name.to_string());
        self.txt
            .get(name)
            .cloned()
            .unwrap_or(Err(FetchError::NotFound))
    }
}

fn fixture_body(r: &J) -> R<Vec<u8>> {
    if let Some(b) = r.get("body") {
        return Ok(b
            .as_str()
            .ok_or_else(|| err("`body` is not text"))?
            .as_bytes()
            .to_vec());
    }
    let f = jget(r, "body_filler")?;
    let (prefix, fill, suffix) = (jstr(f, "prefix")?, jstr(f, "fill")?, jstr(f, "suffix")?);
    let total = jint(f, "total_bytes")? as usize;
    if fill.len() != 1 || prefix.len() + suffix.len() > total {
        return Err(err("bad body_filler"));
    }
    let mut b = prefix.as_bytes().to_vec();
    b.extend(std::iter::repeat_n(
        fill.as_bytes()[0],
        total - prefix.len() - suffix.len(),
    ));
    b.extend(suffix.as_bytes());
    Ok(b)
}

fn source_label(s: &SourceResult, read: bool) -> &'static str {
    if !read {
        return "not-read";
    }
    match s {
        SourceResult::Listed => "listed",
        SourceResult::NotListed => "not-listed",
        SourceResult::Absent => "absent",
        SourceResult::Invalid(_) => "invalid",
        SourceResult::Unavailable(_) => "unavailable",
    }
}

/// Run the domain binding check (spec section 7, "Checking a domain binding")
/// on a fixture: `{domain, agent_id, options: {require_both, require_dnssec},
/// well_known: {host: answer}, txt: {name: answer}}`, the fetcher's answers
/// by name (a name with no key does not exist). No network is used. Returns
/// `{well_known, dns, outcome, queried: {well_known, txt}}`.
#[wasm_bindgen(js_name = checkDomainBinding)]
pub fn check_domain_binding(fixture: &str) -> R<String> {
    let f = parse_json(fixture)?;
    let mut fake = Fake {
        wk: Default::default(),
        txt: Default::default(),
        asked_wk: Default::default(),
        asked_txt: Default::default(),
    };
    let obj = |k: &str| -> R<&Map<String, J>> {
        jget(&f, k)?
            .as_object()
            .ok_or_else(|| err(format!("`{k}` is not an object")))
    };
    for (host, r) in obj("well_known")? {
        let v = if let Some(m) = r.get("unavailable") {
            Err(FetchError::Unavailable(
                m.as_str().unwrap_or("").to_string(),
            ))
        } else {
            Ok(WellKnownResponse {
                status: jint(r, "status")? as u16,
                final_url: r
                    .get("final_url")
                    .and_then(|u| u.as_str())
                    .map(str::to_string)
                    .unwrap_or_else(|| domain::well_known_url(host)),
                content_type: r
                    .get("content_type")
                    .and_then(|c| c.as_str())
                    .map(str::to_string),
                body: fixture_body(r)?,
            })
        };
        fake.wk.insert(host.clone(), v);
    }
    for (name, r) in obj("txt")? {
        let v = if let Some(m) = r.get("unavailable") {
            Err(FetchError::Unavailable(
                m.as_str().unwrap_or("").to_string(),
            ))
        } else {
            let mut records = Vec::new();
            for rec in jget(r, "records")?
                .as_array()
                .ok_or_else(|| err("records"))?
            {
                records.push(match rec {
                    J::String(s) => s.clone(),
                    J::Array(parts) => parts
                        .iter()
                        .map(|p| p.as_str().unwrap_or(""))
                        .collect::<String>(),
                    _ => return Err(err("record is neither text nor a list of text")),
                });
            }
            Ok(TxtAnswer {
                records,
                dnssec_validated: r
                    .get("dnssec_validated")
                    .and_then(|b| b.as_bool())
                    .unwrap_or(false),
            })
        };
        fake.txt.insert(name.clone(), v);
    }
    let agent = AgentId::parse(jstr(&f, "agent_id")?).map_err(ae)?;
    let o = f.get("options").cloned().unwrap_or(J::Null);
    let flag = |k: &str| o.get(k).and_then(|b| b.as_bool()).unwrap_or(false);
    let opts = BindingOptions {
        require_dnssec: flag("require_dnssec"),
        require_both: flag("require_both"),
    };
    let r = domain::check_domain_binding_with(jstr(&f, "domain")?, &agent, &fake, opts);
    let (wk, txt) = (fake.asked_wk.borrow(), fake.asked_txt.borrow());
    Ok(out(json!({
        "well_known": source_label(&r.well_known, !wk.is_empty()),
        "dns": source_label(&r.dns, !txt.is_empty()),
        "outcome": match r.outcome {
            Outcome::Bound => "bound",
            Outcome::NotBound => "not-bound",
            Outcome::Indeterminate => "indeterminate",
        },
        "queried": {"well_known": *wk, "txt": *txt},
    })))
}
