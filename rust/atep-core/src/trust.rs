//! Trust policy engine: verification step 9 (spec sections 7, 8, 9 and 10).
//!
//! A rule asks for a claim type on the signer from an issuer chaining to a
//! configured root, optionally not older than N days. Chains are walked through
//! `issuer-authority` attestations. Every attestation on the way is verified
//! as an envelope (steps 1 to 8 through [`crate::verify::verify_core`]),
//! schema-validated, lifetime-checked, looked up in its issuer's SRL and, if
//! the policy requires it, checked against a log inclusion proof.

use std::cell::RefCell;
use std::collections::HashMap;

use crate::anchor::AnchorRule;
use crate::attestation::{claims, Attestation};
use crate::cbor::Value;
use crate::consts::*;
use crate::envelope::{submitted_form, SignedEnvelope};
use crate::error::{AtepError, ErrorCode, Rejection};
use crate::keys::{sha256, AgentId};
use crate::log::{CheckpointUsed, InclusionCheck, OfflineInclusion};
use crate::srl::{current_for, SrlPolicy, StaleMode};
use crate::verify::{verify_core, Policy};

/// One policy rule: require `claim` on the signer from an issuer chaining to
/// `root` (any configured root when `None`), not older than `max_age_days`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    /// Claim type URI.
    pub claim: String,
    /// Restrict the chain to this root. It must be in the configured root set.
    pub root: Option<AgentId>,
    /// The attestation's `issued-at` must be at most this many days before now.
    pub max_age_days: Option<i64>,
    /// The attestation's `data[key]` must be an array containing the value.
    /// Used for `peer-motion` (`peers`).
    pub data_contains: Option<(String, Value)>,
}

impl Rule {
    pub fn new(claim: &str) -> Rule {
        Rule {
            claim: claims::expand(claim),
            root: None,
            max_age_days: None,
            data_contains: None,
        }
    }
}

/// The verifier's trust configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustPolicy {
    /// Trusted root issuers. ATEP ships with none (spec section 9).
    pub roots: Vec<AgentId>,
    /// Every rule must be satisfied.
    pub rules: Vec<Rule>,
    /// Maximum number of attestations in a chain, claim attestation included.
    pub max_depth: usize,
    /// Require a valid inclusion proof on every attestation relied on.
    pub require_inclusion: bool,
    /// Logs whose checkpoints are trusted (used by the built-in offline checker).
    pub trusted_logs: Vec<AgentId>,
    /// Behavior for stale or missing SRLs.
    pub srl: SrlPolicy,
    /// Enforce the ATEP-R command class table (section 17).
    pub atep_r: bool,
    /// `require-anchor` rules (anchoring hooks, spec section 9). Parsed and validated, but
    /// evaluation is not supported in this build: while any rule is present,
    /// step 9 fails closed with `anchor_not_supported`.
    pub require_anchor: Vec<AnchorRule>,
    /// Follow one hop of succession for a rule that failed with
    /// `claim_missing` (spec section 7, "`successor`: following succession").
    /// Default false.
    pub follow_succession: bool,
}

impl Default for TrustPolicy {
    fn default() -> Self {
        TrustPolicy {
            roots: Vec::new(),
            rules: Vec::new(),
            max_depth: DEFAULT_MAX_CHAIN_DEPTH,
            require_inclusion: false,
            trusted_logs: Vec::new(),
            srl: SrlPolicy::default(),
            atep_r: false,
            require_anchor: Vec::new(),
            follow_succession: false,
        }
    }
}

fn perr(msg: impl Into<String>) -> AtepError {
    AtepError::new(format!("policy: {}", msg.into()))
}

fn parse_ids(j: &serde_json::Value, what: &str) -> Result<Vec<AgentId>, AtepError> {
    let a = j
        .as_array()
        .ok_or_else(|| perr(format!("`{what}` must be an array")))?;
    a.iter()
        .map(|x| {
            AgentId::parse(
                x.as_str()
                    .ok_or_else(|| perr(format!("`{what}` entries must be strings")))?,
            )
        })
        .collect()
}

impl TrustPolicy {
    /// Fail closed while a `require-anchor` rule is present: this build cannot
    /// evaluate anchors, so it must not accept what the rule would have judged.
    pub fn check_anchor_rules(&self) -> Result<(), Rejection> {
        match self.require_anchor.first() {
            None => Ok(()),
            Some(r) => Err(r9(
                ErrorCode::AnchorNotSupported,
                format!(
                    "require-anchor (log {}, chain {}) is not supported in this build",
                    r.log, r.chain
                ),
            )),
        }
    }

    /// Parse the policy file format documented in `rust/README.md`. Unknown
    /// keys are errors so that typos cannot silently weaken a policy.
    pub fn from_json(j: &serde_json::Value) -> Result<TrustPolicy, AtepError> {
        let o = j
            .as_object()
            .ok_or_else(|| perr("policy must be a JSON object"))?;
        let mut p = TrustPolicy::default();
        for (k, v) in o {
            match k.as_str() {
                "roots" => p.roots = parse_ids(v, "roots")?,
                "trusted_logs" => p.trusted_logs = parse_ids(v, "trusted_logs")?,
                "max_depth" => {
                    p.max_depth = v
                        .as_u64()
                        .filter(|n| *n >= 1)
                        .ok_or_else(|| perr("`max_depth` must be an integer of at least 1"))?
                        as usize
                }
                "require_inclusion" => {
                    p.require_inclusion = v
                        .as_bool()
                        .ok_or_else(|| perr("`require_inclusion` must be a boolean"))?
                }
                "atep_r" => {
                    p.atep_r = v
                        .as_bool()
                        .ok_or_else(|| perr("`atep_r` must be a boolean"))?
                }
                "follow_succession" => {
                    p.follow_succession = v
                        .as_bool()
                        .ok_or_else(|| perr("`follow_succession` must be a boolean"))?
                }
                "srl" => {
                    let so = v
                        .as_object()
                        .ok_or_else(|| perr("`srl` must be an object"))?;
                    for (sk, sv) in so {
                        let mode = sv.as_str().and_then(StaleMode::parse).ok_or_else(|| {
                            perr(format!("`srl.{sk}` must be `fail-closed` or `fail-open`"))
                        })?;
                        match sk.as_str() {
                            "on_stale" => p.srl.on_stale = mode,
                            "on_missing" => p.srl.on_missing = mode,
                            other => return Err(perr(format!("unknown key `srl.{other}`"))),
                        }
                    }
                }
                "require_anchor" => {
                    let a = v
                        .as_array()
                        .ok_or_else(|| perr("`require_anchor` must be an array"))?;
                    for r in a {
                        p.require_anchor.push(AnchorRule::from_json(r)?);
                    }
                }
                "rules" => {
                    let a = v
                        .as_array()
                        .ok_or_else(|| perr("`rules` must be an array"))?;
                    for r in a {
                        p.rules.push(parse_rule(r)?);
                    }
                }
                other => return Err(perr(format!("unknown key `{other}`"))),
            }
        }
        Ok(p)
    }
}

fn parse_rule(j: &serde_json::Value) -> Result<Rule, AtepError> {
    let o = j
        .as_object()
        .ok_or_else(|| perr("a rule must be an object"))?;
    let mut claim = None;
    let mut rule_root = None;
    let mut max_age = None;
    for (k, v) in o {
        match k.as_str() {
            "claim" => {
                claim = Some(claims::expand(
                    v.as_str().ok_or_else(|| perr("`claim` must be a string"))?,
                ))
            }
            "root" => {
                rule_root = Some(AgentId::parse(
                    v.as_str().ok_or_else(|| perr("`root` must be a string"))?,
                )?)
            }
            "max_age_days" => {
                max_age = Some(
                    v.as_i64()
                        .filter(|n| *n >= 0)
                        .ok_or_else(|| perr("`max_age_days` must be a non-negative integer"))?,
                )
            }
            other => return Err(perr(format!("unknown rule key `{other}`"))),
        }
    }
    let mut r = Rule::new(&claim.ok_or_else(|| perr("a rule needs a `claim`"))?);
    r.root = rule_root;
    r.max_age_days = max_age;
    Ok(r)
}

/// A link of a verified chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainLink {
    pub id: [u8; 16],
    pub subject: AgentId,
    pub issuer: AgentId,
    pub claim: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

/// A claim verified in step 9.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedClaim {
    pub claim: String,
    /// Issuer of the claim attestation itself.
    pub issuer: AgentId,
    /// The root the chain ends at.
    pub root: AgentId,
    /// Earliest `expires-at` over the whole chain: the claim is good until then.
    pub expires_at: i64,
    /// Chain from the claim attestation (first) up to the root's delegation (last).
    pub chain: Vec<ChainLink>,
}

/// What step 9 needs to know about the envelope being verified.
pub struct Step9Input {
    pub signer: AgentId,
    /// Inline attestations (`-70009`) of the envelope, as encoded envelopes.
    pub inline: Vec<Vec<u8>>,
    /// Every requirement must hold; a requirement is a list of alternatives,
    /// each alternative a list of rules that must all hold.
    pub requirements: Vec<Vec<Vec<Rule>>>,
    /// Ignore the expiry of attestations (ATEP-R e-stop only).
    pub relax_expiry: bool,
    pub srl: SrlPolicy,
}

#[derive(Debug, Default)]
pub struct Step9Output {
    pub claims: Vec<VerifiedClaim>,
    pub checkpoint: Option<CheckpointUsed>,
    pub warnings: Vec<String>,
}

fn r9(code: ErrorCode, msg: impl Into<String>) -> Rejection {
    Rejection::new(9, code, msg)
}

struct PoolEntry {
    raw: Vec<u8>,
    hash: [u8; 32],
    subject: Option<AgentId>,
    claim: Option<String>,
}

/// Loose look at an attestation: subject and claim, without validating
/// anything. Candidates are selected on this so that a malformed candidate is
/// reported by full validation instead of being skipped.
fn loose_parse(raw: &[u8]) -> (Option<AgentId>, Option<String>, Vec<Vec<u8>>) {
    let Ok(env) = SignedEnvelope::decode(raw) else {
        return (None, None, Vec::new());
    };
    let nested = match &env.attestations {
        Some(Value::Array(a)) => a.iter().map(|v| v.encode()).collect(),
        _ => Vec::new(),
    };
    let Some(Ok(p)) = env.payload.as_deref().map(Value::decode) else {
        return (None, None, nested);
    };
    let subject = p
        .as_map()
        .and_then(|m| m.iter().find(|(k, _)| k.as_text() == Some("subject")))
        .and_then(|(_, v)| v.as_bytes())
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .map(AgentId);
    let claim = p
        .as_map()
        .and_then(|m| m.iter().find(|(k, _)| k.as_text() == Some("claim")))
        .and_then(|(_, v)| v.as_text())
        .map(str::to_string);
    (subject, claim, nested)
}

#[derive(Clone)]
struct Valid {
    att: Attestation,
    issued_at: i64,
    expires_at: i64,
    checkpoint: Option<CheckpointUsed>,
}

struct Auth {
    links: Vec<ChainLink>,
    root: AgentId,
    cps: Vec<CheckpointUsed>,
}

const MAX_POOL: usize = 256;

struct Ctx<'p, 'a> {
    policy: &'p Policy<'a>,
    trust: &'p TrustPolicy,
    now: i64,
    relax: bool,
    srl: SrlPolicy,
    pool: Vec<PoolEntry>,
    memo: RefCell<HashMap<[u8; 32], Result<Valid, Rejection>>>,
    warnings: RefCell<Vec<String>>,
}

impl Ctx<'_, '_> {
    fn add_to_pool(&mut self, raw: Vec<u8>, level: usize) {
        let hash = sha256(&raw);
        if self.pool.len() >= MAX_POOL || self.pool.iter().any(|e| e.hash == hash) {
            return;
        }
        let (subject, claim, nested) = loose_parse(&raw);
        self.pool.push(PoolEntry {
            raw,
            hash,
            subject,
            claim,
        });
        if level < 8 {
            for n in nested {
                self.add_to_pool(n, level + 1);
            }
        }
    }

    fn warn(&self, w: Option<String>) {
        if let Some(w) = w {
            let mut ws = self.warnings.borrow_mut();
            if !ws.contains(&w) {
                ws.push(w);
            }
        }
    }

    fn candidates(&self, subject: &AgentId, claim: &str) -> Vec<&PoolEntry> {
        self.pool
            .iter()
            .filter(|e| e.subject.as_ref() == Some(subject) && e.claim.as_deref() == Some(claim))
            .collect()
    }

    /// Verify one pooled attestation completely. Memoized.
    fn validate(&self, e: &PoolEntry) -> Result<Valid, Rejection> {
        if let Some(r) = self.memo.borrow().get(&e.hash) {
            return r.clone();
        }
        let r = self.validate_uncached(e);
        self.memo.borrow_mut().insert(e.hash, r.clone());
        r
    }

    fn validate_uncached(&self, e: &PoolEntry) -> Result<Valid, Rejection> {
        let sub = Policy {
            known_bundles: self.policy.known_bundles.clone(),
            revocations: self.policy.revocations.clone(),
            srls: self.policy.srls,
            max_skew_secs: self.policy.max_skew_secs,
            // Step 8 of a candidate reads the local store for retirements and
            // for nothing else (no policy, so no pool is built from it).
            attestations: self.policy.attestations.clone(),
            ..Policy::default()
        };
        // Steps 1 to 8, reused for the nested envelope.
        let v = verify_core(&e.raw, &sub, self.now, self.relax).map_err(|inner| {
            r9(
                ErrorCode::AttestationInvalid,
                "attestation envelope failed verification",
            )
            .with_cause(inner)
        })?;
        if v.encrypted || v.content_type != CT_ATTESTATION {
            return Err(r9(
                ErrorCode::AttestationSchemaInvalid,
                format!("content type `{}` is not an attestation", v.content_type),
            ));
        }
        let att = Attestation::from_payload(&v.payload)
            .map_err(|x| r9(ErrorCode::AttestationSchemaInvalid, x.0))?;
        att.validate_claim_data()
            .map_err(|x| r9(ErrorCode::AttestationSchemaInvalid, x.0))?;
        if att.issuer != v.signer {
            return Err(r9(
                ErrorCode::AttestationIssuerMismatch,
                "attestation `issuer` does not equal the envelope signer",
            ));
        }
        let expires_at = v.expires_at.ok_or_else(|| {
            r9(
                ErrorCode::AttestationSchemaInvalid,
                "attestation has no expires-at",
            )
        })?;
        let lifetime = expires_at - v.issued_at;
        if lifetime > MAX_ATTESTATION_LIFETIME_SECS {
            return Err(r9(
                ErrorCode::AttestationLifetimeExceeded,
                format!(
                    "lifetime of {} days exceeds the 400 day maximum",
                    lifetime / 86_400
                ),
            ));
        }
        // The issuer's SRL.
        let (srl, w) = current_for(self.policy.srls, &att.issuer, self.now, &self.srl)?;
        self.warn(w);
        if let Some(entry) = srl.as_ref().and_then(|s| s.revokes_attestation(&att.id)) {
            return Err(r9(
                ErrorCode::AttestationRevoked,
                format!(
                    "attestation {} is on the SRL of {} ({}, since {})",
                    hex::encode(att.id),
                    att.issuer,
                    entry.reason,
                    entry.revoked_at
                ),
            ));
        }
        // Inclusion proof.
        let mut checkpoint = None;
        if self.trust.require_inclusion {
            let submitted =
                submitted_form(&e.raw).map_err(|x| r9(ErrorCode::InclusionProofInvalid, x.0))?;
            let proof = SignedEnvelope::decode(&e.raw)
                .ok()
                .and_then(|env| env.inclusion_proof);
            let default;
            let checker: &dyn InclusionCheck = match self.policy.inclusion {
                Some(c) => c,
                None => {
                    default = OfflineInclusion {
                        trusted_logs: self.trust.trusted_logs.clone(),
                        known_bundles: self.policy.known_bundles.clone(),
                    };
                    &default
                }
            };
            checkpoint = Some(checker.check(&submitted, proof.as_ref(), self.now)?);
        }
        Ok(Valid {
            att,
            issued_at: v.issued_at,
            expires_at,
            checkpoint,
        })
    }

    fn link(v: &Valid) -> ChainLink {
        ChainLink {
            id: v.att.id,
            subject: v.att.subject,
            issuer: v.att.issuer,
            claim: v.att.claim.clone(),
            issued_at: v.issued_at,
            expires_at: v.expires_at,
        }
    }

    /// Is `issuer` allowed to issue `claim`: a root, or holder of an
    /// `issuer-authority` attestation listing the claim whose own issuer is in
    /// turn allowed to issue both `issuer-authority` and the claim.
    /// `depth` counts the attestations in the chain so far.
    fn authorize(
        &self,
        issuer: &AgentId,
        claim: &str,
        roots: &[AgentId],
        path: &mut Vec<AgentId>,
        depth: usize,
    ) -> Result<Auth, Rejection> {
        if roots.contains(issuer) {
            return Ok(Auth {
                links: Vec::new(),
                root: *issuer,
                cps: Vec::new(),
            });
        }
        if path.contains(issuer) {
            return Err(r9(
                ErrorCode::ChainCycle,
                format!("issuer {issuer} appears twice in the chain"),
            ));
        }
        if depth + 1 > self.trust.max_depth {
            return Err(r9(
                ErrorCode::ChainDepthExceeded,
                format!(
                    "chain needs more than {} attestations to reach a root",
                    self.trust.max_depth
                ),
            ));
        }
        path.push(*issuer);
        let r = self.authorize_via_attestations(issuer, claim, roots, path, depth);
        path.pop();
        r
    }

    fn authorize_via_attestations(
        &self,
        issuer: &AgentId,
        claim: &str,
        roots: &[AgentId],
        path: &mut Vec<AgentId>,
        depth: usize,
    ) -> Result<Auth, Rejection> {
        let cands = self.candidates(issuer, claims::ISSUER_AUTHORITY);
        if cands.is_empty() {
            return Err(r9(
                ErrorCode::ChainBroken,
                format!("no issuer-authority attestation for {issuer}, which is not a root"),
            ));
        }
        let mut first_err: Option<Rejection> = None;
        for c in cands {
            let outcome = (|| {
                let valid = self.validate(c)?;
                let listed = valid
                    .att
                    .authority_claims()
                    .map_err(|x| r9(ErrorCode::AttestationSchemaInvalid, x.0))?;
                if !listed.iter().any(|l| l == claim) {
                    return Err(r9(
                        ErrorCode::IssuerNotAuthorized,
                        format!("authority of {issuer} does not list the claim {claim}"),
                    ));
                }
                let parent = valid.att.issuer;
                let up =
                    self.authorize(&parent, claims::ISSUER_AUTHORITY, roots, path, depth + 1)?;
                if claim != claims::ISSUER_AUTHORITY {
                    // The delegator can only hand on what it holds itself.
                    self.authorize(&parent, claim, roots, path, depth + 1)?;
                }
                let mut links = vec![Self::link(&valid)];
                links.extend(up.links);
                let mut cps: Vec<CheckpointUsed> = valid.checkpoint.clone().into_iter().collect();
                cps.extend(up.cps);
                Ok(Auth {
                    links,
                    root: up.root,
                    cps,
                })
            })();
            match outcome {
                Ok(a) => return Ok(a),
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }
        Err(first_err.expect("at least one candidate"))
    }

    /// Apply a rule to an already validated claim attestation: `max_age_days`,
    /// the `data` condition, then the authorization of its issuer, with the
    /// chain starting at `depth` attestations (1 for a claim attestation of the
    /// signer, 2 when the `successor` attestation is part of the chain).
    fn apply_rule(
        &self,
        valid: &Valid,
        rule: &Rule,
        roots: &[AgentId],
        depth: usize,
    ) -> Result<Auth, Rejection> {
        if let Some(days) = rule.max_age_days {
            let age = self.now - valid.issued_at;
            if age > days * 86_400 {
                return Err(r9(
                    ErrorCode::ClaimTooOld,
                    format!(
                        "attestation was issued {} days ago, the rule allows {days}",
                        age / 86_400
                    ),
                ));
            }
        }
        if let Some((key, want)) = &rule.data_contains {
            let ok = valid
                .att
                .data_get(key)
                .and_then(|v| v.as_array())
                .is_some_and(|a| a.contains(want));
            if !ok {
                return Err(r9(
                    ErrorCode::ClaimDataMismatch,
                    format!("attestation data `{key}` does not list the required value"),
                ));
            }
        }
        self.authorize(
            &valid.att.issuer,
            &rule.claim,
            roots,
            &mut Vec::new(),
            depth,
        )
    }

    /// Assemble the verified claim from the validated attestations of the
    /// chain (claim attestation first, then the `successor` attestation when
    /// succession was followed) and the authority links above them.
    fn assemble(
        rule: &Rule,
        first: &Valid,
        via: Option<&Valid>,
        auth: Auth,
    ) -> (VerifiedClaim, Vec<CheckpointUsed>) {
        let mut chain = vec![Self::link(first)];
        let mut cps: Vec<CheckpointUsed> = first.checkpoint.clone().into_iter().collect();
        if let Some(v) = via {
            chain.push(Self::link(v));
            cps.extend(v.checkpoint.clone());
        }
        chain.extend(auth.links);
        cps.extend(auth.cps);
        let expires_at = chain.iter().map(|l| l.expires_at).min().unwrap();
        (
            VerifiedClaim {
                claim: rule.claim.clone(),
                issuer: first.att.issuer,
                root: auth.root,
                expires_at,
                chain,
            },
            cps,
        )
    }

    fn eval_rule(
        &self,
        subject: &AgentId,
        rule: &Rule,
    ) -> Result<(VerifiedClaim, Vec<CheckpointUsed>), Rejection> {
        let roots: Vec<AgentId> = match &rule.root {
            Some(r) => {
                if !self.trust.roots.contains(r) {
                    return Err(r9(
                        ErrorCode::PolicyInvalid,
                        format!("rule root {r} is not in the configured root set"),
                    ));
                }
                vec![*r]
            }
            None => self.trust.roots.clone(),
        };
        let cands = self.candidates(subject, &rule.claim);
        if cands.is_empty() {
            let missing = r9(
                ErrorCode::ClaimMissing,
                format!("no attestation of {} for {subject}", rule.claim),
            );
            // Succession can only turn a `claim_missing` into a success, and
            // a failed attempt reports the error the rule already had.
            if self.trust.follow_succession {
                if let Some(found) = self.eval_succession(subject, rule, &roots) {
                    return Ok(found);
                }
            }
            return Err(missing);
        }
        let mut first_err: Option<Rejection> = None;
        for c in cands {
            let outcome = (|| {
                let valid = self.validate(c)?;
                let auth = self.apply_rule(&valid, rule, &roots, 1)?;
                Ok(Self::assemble(rule, &valid, None, auth))
            })();
            match outcome {
                Ok(x) => return Ok(x),
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }
        Err(first_err.expect("at least one candidate"))
    }

    /// One hop of succession (spec section 7): for each valid `successor`
    /// attestation naming `subject`, in pool order, the claim attestations
    /// whose subject is its issuer, validated and checked like those of any
    /// rule. The first pair that passes everything satisfies the rule. A
    /// successor attestation naming the old identity is never looked for.
    fn eval_succession(
        &self,
        subject: &AgentId,
        rule: &Rule,
        roots: &[AgentId],
    ) -> Option<(VerifiedClaim, Vec<CheckpointUsed>)> {
        for sc in self.candidates(subject, claims::SUCCESSOR) {
            let Ok(suc) = self.validate(sc) else {
                continue;
            };
            let old = suc.att.issuer;
            for cc in self.candidates(&old, &rule.claim) {
                let outcome = (|| {
                    let valid = self.validate(cc)?;
                    let auth = self.apply_rule(&valid, rule, roots, 2)?;
                    Ok::<_, Rejection>(Self::assemble(rule, &valid, Some(&suc), auth))
                })();
                if let Ok(found) = outcome {
                    return Some(found);
                }
            }
        }
        None
    }
}

/// Evaluate step 9 for `input.signer`. Every requirement must hold.
pub fn evaluate(
    policy: &Policy,
    trust: &TrustPolicy,
    input: Step9Input,
    now: i64,
) -> Result<Step9Output, Rejection> {
    trust.check_anchor_rules()?;
    let mut ctx = Ctx {
        policy,
        trust,
        now,
        relax: input.relax_expiry,
        srl: input.srl,
        pool: Vec::new(),
        memo: RefCell::new(HashMap::new()),
        warnings: RefCell::new(Vec::new()),
    };
    for raw in input.inline.iter().chain(policy.attestations.iter()) {
        ctx.add_to_pool(raw.clone(), 0);
    }
    let mut out = Step9Output::default();
    let mut cps: Vec<CheckpointUsed> = Vec::new();
    for req in &input.requirements {
        // Among alternatives that all fail, report the one that got furthest,
        // except that a stale or unavailable revocation list in any alternative
        // is reported first: that cause applies to every alternative that would
        // otherwise match (Draft 08, section 10 step 9).
        let mut best: Option<(usize, Rejection)> = None;
        let mut srl_cause: Option<Rejection> = None;
        let mut satisfied = false;
        for group in req {
            let mut got = Vec::new();
            let mut group_err = None;
            for rule in group {
                match ctx.eval_rule(&input.signer, rule) {
                    Ok(x) => got.push(x),
                    Err(e) => {
                        group_err = Some(e);
                        break;
                    }
                }
            }
            match group_err {
                None => {
                    for (c, cp) in got {
                        out.claims.push(c);
                        cps.extend(cp);
                    }
                    satisfied = true;
                    break;
                }
                Some(e) => {
                    if srl_cause.is_none()
                        && matches!(e.code, ErrorCode::SrlStale | ErrorCode::SrlUnavailable)
                    {
                        srl_cause = Some(e.clone());
                    }
                    if best.as_ref().is_none_or(|(n, _)| got.len() > *n) {
                        best = Some((got.len(), e));
                    }
                }
            }
        }
        if !satisfied {
            return Err(srl_cause.or(best.map(|b| b.1)).unwrap_or_else(|| {
                r9(ErrorCode::PolicyInvalid, "requirement has no alternatives")
            }));
        }
    }
    out.checkpoint = cps.into_iter().max_by_key(|c| (c.timestamp, c.tree_size));
    out.warnings = ctx.warnings.into_inner();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG: &str = "atep:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn require_anchor_parses_and_fails_closed() {
        let ok = |s: &str| {
            let j: serde_json::Value = serde_json::from_str(s).unwrap();
            TrustPolicy::from_json(&j)
        };
        let p = ok(&format!(
            r#"{{"require_anchor": [{{"log": "{LOG}", "chain": "solana-mainnet", "max_age_hours": 6}},
                {{"log": "{LOG}", "chain": "x-acme", "max_age_days": 2}}]}}"#
        ))
        .unwrap();
        assert_eq!(p.require_anchor.len(), 2);
        assert_eq!(p.require_anchor[0].max_age.as_secs(), 6 * 3600);
        assert_eq!(p.require_anchor[1].max_age.as_secs(), 2 * 86_400);
        let e = p.check_anchor_rules().unwrap_err();
        assert_eq!(e.code, ErrorCode::AnchorNotSupported);
        assert_eq!(e.step, 9);
        assert!(e.detail.contains("not supported in this build"));
        // No rule: unchanged.
        assert!(ok("{}").unwrap().check_anchor_rules().is_ok());
        assert!(ok(r#"{"require_anchor": []}"#)
            .unwrap()
            .require_anchor
            .is_empty());
        for bad in [
            r#"{"require_anchor": [{"chain": "solana-mainnet", "max_age_days": 1}]}"#.to_string(),
            format!(r#"{{"require_anchor": [{{"log": "{LOG}", "max_age_days": 1}}]}}"#),
            format!(r#"{{"require_anchor": [{{"log": "{LOG}", "chain": "solana-mainnet"}}]}}"#),
            format!(
                r#"{{"require_anchor": [{{"log": "{LOG}", "chain": "dogecoin", "max_age_days": 1}}]}}"#
            ),
            format!(
                r#"{{"require_anchor": [{{"log": "{LOG}", "chain": "rekor", "max_age_days": 1, "max_age_hours": 1}}]}}"#
            ),
            format!(
                r#"{{"require_anchor": [{{"log": "{LOG}", "chain": "rekor", "max_age_hours": 0}}]}}"#
            ),
            format!(
                r#"{{"require_anchor": [{{"log": "{LOG}", "chain": "rekor", "max_age_days": 1, "x": 1}}]}}"#
            ),
            r#"{"require_anchor": {}}"#.to_string(),
            r#"{"require_anchor": [{"log": "nope", "chain": "rekor", "max_age_days": 1}]}"#
                .to_string(),
        ] {
            assert!(ok(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn policy_json() {
        let j: serde_json::Value = serde_json::from_str(
            r#"{"roots": [], "max_depth": 3, "require_inclusion": true,
                "srl": {"on_stale": "fail-open", "on_missing": "fail-closed"},
                "rules": [{"claim": "audited", "max_age_days": 30}]}"#,
        )
        .unwrap();
        let p = TrustPolicy::from_json(&j).unwrap();
        assert_eq!(p.max_depth, 3);
        assert!(p.require_inclusion);
        assert_eq!(p.srl.on_stale, StaleMode::FailOpenWithWarning);
        assert_eq!(p.srl.on_missing, StaleMode::FailClosed);
        assert_eq!(p.rules[0].claim, claims::AUDITED);
        assert_eq!(p.rules[0].max_age_days, Some(30));
        for bad in [
            r#"{"rootz": []}"#,
            r#"{"max_depth": 0}"#,
            r#"{"rules": [{"claim": "audited", "x": 1}]}"#,
            r#"{"rules": [{}]}"#,
            r#"{"srl": {"on_stale": "maybe"}}"#,
            r#"{"roots": ["nope"]}"#,
            r#"[]"#,
        ] {
            let j: serde_json::Value = serde_json::from_str(bad).unwrap();
            assert!(TrustPolicy::from_json(&j).is_err(), "{bad}");
        }
    }
}
