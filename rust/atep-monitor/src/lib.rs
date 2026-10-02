//! ATEP log monitor (spec section 9, "Monitors", milestone M3).
//!
//! A monitor follows a log, checks that every new checkpoint extends the
//! previous one (RFC 9162 consistency proofs), that the entries the log serves
//! reproduce the checkpoint root, and reads every new attestation for the
//! anomalies the spec names: a `domain-control` attestation for a watched
//! domain that the monitor did not authorize, an issuer issuing claim types
//! outside its delegated `issuer-authority`, a chain of two or more `successor`
//! hops, a gap or inconsistency in the
//! checkpoint history, and a split view. Findings are typed [`Alert`]s.

pub mod alert;
pub mod source;

use std::collections::{HashMap, HashSet};

use atep_core::attestation::{claims, Attestation};
use atep_core::consts::{CT_ATTESTATION, CT_SRL};
use atep_core::envelope::SignedEnvelope;
use atep_core::keys::{AgentId, PublicBundle};
use atep_core::log::{hash_leaf, root_of_hashes, verify_consistency};
use atep_core::srl::{RevokedId, Srl};
use atep_core::succession::{chain_links, SuccessorLink};
use atep_core::verify::{verify, Policy};
use atep_log::gossip::{
    parse_checkpoint, GossipState, NoProofs, Observation, ProofSource, Seen, SplitEvidence,
};

pub use alert::Alert;
pub use atep_log::anchor::CheckpointAnchors;
pub use source::{DirSource, HttpSource, LibrarySource, LogSource, SourceError};

const CHUNK: u64 = 500;
const MAX_PROOFS: usize = 64;

#[derive(Clone, Debug, Default)]
pub struct MonitorConfig {
    /// Pin the log's Agent ID. When `None` the first checkpoint's signer is
    /// trusted (trust on first use) and pinned from then on.
    pub log_id: Option<AgentId>,
    /// DNS names whose `domain-control` attestations are watched (a name also
    /// covers its subdomains).
    pub watch_domains: Vec<String>,
    /// Agent IDs the monitor operator authorizes for the watched domains.
    pub authorized: Vec<AgentId>,
    /// Root issuers for delegation checks. Without roots the monitor does not
    /// judge issuer authority.
    pub roots: Vec<AgentId>,
    /// Also alert on issuers that hold no delegation at all (not a root).
    pub strict_issuers: bool,
    /// Maximum chain length in attestations (spec section 7, default 5).
    pub max_depth: usize,
}

impl MonitorConfig {
    pub fn new() -> MonitorConfig {
        MonitorConfig {
            max_depth: atep_core::consts::DEFAULT_MAX_CHAIN_DEPTH,
            ..MonitorConfig::default()
        }
    }
}

struct AttRec {
    index: u64,
    att: Attestation,
    issued_at: i64,
    expires_at: i64,
}

/// Adapter so the gossip comparison can ask the followed log for proofs.
struct SourceProofs<'a>(&'a dyn LogSource);

impl ProofSource for SourceProofs<'_> {
    fn consistency_proof(&self, from: u64, to: u64) -> Option<atep_core::log::ConsistencyProof> {
        self.0.consistency(from, to).ok()
    }
}

pub struct Monitor<S: LogSource> {
    cfg: MonitorConfig,
    source: S,
    /// The last checkpoint this monitor accepted.
    last: Option<Seen>,
    /// Leaf hashes of the entries verified against `last`.
    leaves: Vec<[u8; 32]>,
    atts: Vec<AttRec>,
    bundles: HashMap<AgentId, PublicBundle>,
    /// (issuer, attestation id) to `revoked-at`, from logged SRLs.
    revoked: HashMap<(AgentId, [u8; 16]), i64>,
    gossip: GossipState,
    emitted: HashSet<String>,
    history: Vec<Alert>,
}

fn domain_matches(domain: &str, watched: &str) -> bool {
    let d = domain.trim_end_matches('.').to_ascii_lowercase();
    let w = watched.trim_end_matches('.').to_ascii_lowercase();
    d == w || d.ends_with(&format!(".{w}"))
}

impl<S: LogSource> Monitor<S> {
    pub fn new(cfg: MonitorConfig, source: S) -> Monitor<S> {
        let mut cfg = cfg;
        if cfg.max_depth == 0 {
            cfg.max_depth = atep_core::consts::DEFAULT_MAX_CHAIN_DEPTH;
        }
        Monitor {
            cfg,
            source,
            last: None,
            leaves: Vec::new(),
            atts: Vec::new(),
            bundles: HashMap::new(),
            revoked: HashMap::new(),
            gossip: GossipState::new(),
            emitted: HashSet::new(),
            history: Vec::new(),
        }
    }

    /// Start from a checkpoint saved by an earlier run, so a log that was
    /// rewritten while the monitor was down is still caught.
    pub fn trust_checkpoint(&mut self, raw: &[u8], now: i64) -> Result<(), String> {
        let s = parse_checkpoint(raw, now).map_err(|e| e.to_string())?;
        if let Some(id) = self.cfg.log_id {
            if s.log != id {
                return Err("saved checkpoint is from a different log".into());
            }
        }
        self.cfg.log_id = Some(s.log);
        let _ = self.gossip.observe(raw, now, &SourceProofs(&self.source));
        self.last = Some(s);
        Ok(())
    }

    /// Published checkpoints with tree size at least `from`, each with its
    /// anchor records (anchoring hooks, spec section 9). The list of anchors is empty for a log
    /// that does not anchor, so a monitor written against this call shows
    /// anchors as soon as a log starts to publish them. The monitor does not
    /// check the chain; it checks that every record is for the checkpoint it
    /// is listed under.
    pub fn checkpoint_anchors(&self, from: u64) -> Result<Vec<CheckpointAnchors>, SourceError> {
        let list = self.source.anchors(from)?;
        for c in &list {
            if c.anchors
                .iter()
                .any(|a| a.checkpoint_hash != c.checkpoint_hash)
            {
                return Err(SourceError(format!(
                    "an anchor listed under the checkpoint of tree size {} is for another checkpoint",
                    c.tree_size
                )));
            }
        }
        Ok(list)
    }

    pub fn last_checkpoint(&self) -> Option<&Seen> {
        self.last.as_ref()
    }

    pub fn log_id(&self) -> Option<AgentId> {
        self.cfg.log_id
    }

    /// Every alert raised so far.
    pub fn alerts(&self) -> &[Alert] {
        &self.history
    }

    pub fn entries_seen(&self) -> u64 {
        self.leaves.len() as u64
    }

    fn raise(&mut self, out: &mut Vec<Alert>, a: Alert) {
        if self.emitted.insert(a.key()) {
            self.history.push(a.clone());
            out.push(a);
        }
    }

    /// Feed a checkpoint received from elsewhere (another monitor, a gossip
    /// peer). A second signed checkpoint of the followed log that cannot
    /// belong to the same history is a split view.
    pub fn observe_checkpoint(&mut self, raw: &[u8], now: i64) -> Vec<Alert> {
        let mut out = Vec::new();
        match self.gossip.observe(raw, now, &SourceProofs(&self.source)) {
            Ok(Observation::Split(ev)) => self.raise(&mut out, Alert::split(&ev)),
            Ok(_) => {}
            Err(r) => self.raise(
                &mut out,
                Alert::BadCheckpoint {
                    detail: r.to_string(),
                },
            ),
        }
        out
    }

    /// One round: fetch, verify and analyze. Returns the alerts that are new
    /// in this round.
    pub fn poll(&mut self, now: i64) -> Vec<Alert> {
        let mut out = Vec::new();
        let raw = match self.source.latest_checkpoint() {
            Ok(r) => r,
            Err(e) => {
                self.raise(
                    &mut out,
                    Alert::SourceUnavailable {
                        detail: e.to_string(),
                    },
                );
                return out;
            }
        };
        let new = match parse_checkpoint(&raw, now) {
            Ok(s) => s,
            Err(r) => {
                self.raise(
                    &mut out,
                    Alert::BadCheckpoint {
                        detail: r.to_string(),
                    },
                );
                return out;
            }
        };
        match self.cfg.log_id {
            Some(id) if id != new.log => {
                self.raise(
                    &mut out,
                    Alert::BadCheckpoint {
                        detail: format!(
                            "checkpoint is signed by {} but the followed log is {id}",
                            new.log
                        ),
                    },
                );
                return out;
            }
            None => self.cfg.log_id = Some(new.log),
            _ => {}
        }
        // Split view: another signed checkpoint of this log with the same
        // size and a different root (proofs are checked in `check_history`).
        if let Ok(Observation::Split(ev)) = self.gossip.observe(&raw, now, &NoProofs) {
            self.raise(&mut out, Alert::split(&ev));
            return out;
        }
        if !self.check_history(&new, now, &mut out) {
            return out;
        }
        if !self.sync_entries(&new, &mut out) {
            return out;
        }
        self.last = Some(new);
        out
    }

    /// Verify the chain of checkpoints from the last accepted one (or, on the
    /// first poll, from the start of the log) to `new`. Returns false when the
    /// history is not consistent.
    fn check_history(&mut self, new: &Seen, now: i64, out: &mut Vec<Alert>) -> bool {
        let from = self.last.as_ref().map_or(0, |l| l.size.max(0) as u64);
        // Every checkpoint the log published since, oldest first, plus the new one.
        let mut chain: Vec<Seen> = Vec::new();
        if let Some(l) = &self.last {
            chain.push(l.clone());
        }
        match self.source.checkpoints_since(from) {
            Ok(list) => {
                for raw in list {
                    match parse_checkpoint(&raw, now) {
                        Ok(s) if Some(s.log) == self.cfg.log_id => chain.push(s),
                        Ok(s) => self.raise(
                            out,
                            Alert::BadCheckpoint {
                                detail: format!("published checkpoint is signed by {}", s.log),
                            },
                        ),
                        Err(r) => self.raise(
                            out,
                            Alert::BadCheckpoint {
                                detail: r.to_string(),
                            },
                        ),
                    }
                }
            }
            Err(e) => self.raise(
                out,
                Alert::CheckpointGap {
                    from,
                    to: new.size as u64,
                    detail: format!("cannot list the published checkpoints: {e}"),
                },
            ),
        }
        chain.push(new.clone());
        let mut ok = true;
        // Local checks on every consecutive pair.
        for w in chain.windows(2) {
            let (a, b) = (&w[0], &w[1]);
            if a.raw == b.raw {
                continue;
            }
            if b.size < a.size {
                self.raise(
                    out,
                    Alert::TreeShrank {
                        from: a.size as u64,
                        to: b.size as u64,
                    },
                );
                ok = false;
            } else if b.size == a.size && a.root != b.root {
                let ev = SplitEvidence {
                    log: a.log,
                    a: a.raw.clone(),
                    b: b.raw.clone(),
                    proof: None,
                    reason: format!(
                        "two signed checkpoints of tree size {} carry different roots",
                        a.size
                    ),
                };
                self.raise(out, Alert::split(&ev));
                ok = false;
            }
        }
        if !ok {
            return false;
        }
        // Consistency proofs between successive distinct sizes. A long
        // published history is thinned to MAX_PROOFS steps (the proofs chain,
        // so the first and last checkpoints are always covered).
        let mut sized: Vec<&Seen> = Vec::new();
        for c in &chain {
            if sized.last().is_none_or(|l| l.size != c.size) {
                sized.push(c);
            }
        }
        let step = sized.len().div_ceil(MAX_PROOFS + 1).max(1);
        let mut picks: Vec<&Seen> = sized.iter().step_by(step).copied().collect();
        if let (Some(l), Some(p)) = (sized.last(), picks.last()) {
            if !std::ptr::eq(*l, *p) {
                picks.push(l);
            }
        }
        for w in picks.windows(2) {
            let (a, b) = (w[0], w[1]);
            let (from, to) = (a.size as u64, b.size as u64);
            match self.source.consistency(from, to) {
                Err(e) => {
                    self.raise(
                        out,
                        Alert::CheckpointGap {
                            from,
                            to,
                            detail: format!("no consistency proof: {e}"),
                        },
                    );
                    ok = false;
                }
                Ok(p) => {
                    if p.from != a.size
                        || p.to != b.size
                        || !verify_consistency(from, to, &a.root, &b.root, &p.path)
                    {
                        self.raise(
                            out,
                            Alert::InconsistentCheckpoint {
                                from,
                                to,
                                detail: "the consistency proof does not lead from the older root to the newer one; the log's history was altered or forked".into(),
                                evidence: SplitEvidence {
                                    log: a.log,
                                    a: a.raw.clone(),
                                    b: b.raw.clone(),
                                    proof: Some(p),
                                    reason: String::new(),
                                }
                                .to_pair_cbor(),
                            },
                        );
                        ok = false;
                    }
                }
            }
        }
        ok
    }

    /// Fetch the entries up to `new.size`, check that they reproduce the
    /// checkpoint root, then analyze the new ones.
    fn sync_entries(&mut self, new: &Seen, out: &mut Vec<Alert>) -> bool {
        let target = new.size as u64;
        let have = self.leaves.len() as u64;
        if target < have {
            self.raise(
                out,
                Alert::TreeShrank {
                    from: have,
                    to: target,
                },
            );
            return false;
        }
        let mut fetched: Vec<Vec<u8>> = Vec::new();
        let mut at = have;
        while at < target {
            let to = (at + CHUNK).min(target);
            match self.source.entries(at, to) {
                Ok(v) if v.len() as u64 == to - at => {
                    fetched.extend(v);
                    at = to;
                }
                Ok(v) => {
                    self.raise(
                        out,
                        Alert::EntryGap {
                            from: at,
                            to,
                            detail: format!(
                                "asked for {} entries, the log returned {}",
                                to - at,
                                v.len()
                            ),
                        },
                    );
                    return false;
                }
                Err(e) => {
                    self.raise(
                        out,
                        Alert::EntryGap {
                            from: at,
                            to,
                            detail: e.to_string(),
                        },
                    );
                    return false;
                }
            }
        }
        let mut leaves = self.leaves.clone();
        leaves.extend(fetched.iter().map(|r| hash_leaf(r)));
        if root_of_hashes(&leaves) != new.root {
            self.raise(
                out,
                Alert::EntryRootMismatch {
                    tree_size: target,
                    detail: "the entries served by the log do not hash to the signed root".into(),
                },
            );
            return false;
        }
        self.leaves = leaves;
        self.analyze(have, fetched, out);
        true
    }

    fn analyze(&mut self, first_index: u64, raws: Vec<Vec<u8>>, out: &mut Vec<Alert>) {
        let start = self.atts.len();
        for (i, raw) in raws.iter().enumerate() {
            let index = first_index + i as u64;
            if let Err(detail) = self.ingest(index, raw) {
                self.raise(
                    out,
                    Alert::EntryInvalid {
                        entry: index,
                        detail,
                    },
                );
            }
        }
        // Judge the new attestations with everything known now.
        let judged: Vec<(u64, Attestation, i64)> = self.atts[start..]
            .iter()
            .map(|a| (a.index, a.att.clone(), a.issued_at))
            .collect();
        for (index, att, at) in judged {
            self.judge(index, &att, at, out);
        }
        self.judge_successions(out);
    }

    /// `successor_chain`: a logged `successor` attestation whose issuer is the
    /// subject of another logged one. Judged over everything logged so far, so
    /// that a link logged later raises the alert for the earlier chain too;
    /// each finding is reported once.
    fn judge_successions(&mut self, out: &mut Vec<Alert>) {
        let links: Vec<SuccessorLink> = self
            .atts
            .iter()
            .filter(|a| a.att.claim == claims::SUCCESSOR)
            .map(|a| SuccessorLink {
                entry: a.index,
                issuer: a.att.issuer,
                subject: a.att.subject,
            })
            .collect();
        for l in chain_links(&links) {
            self.raise(
                out,
                Alert::SuccessorChain {
                    entry: l.entry,
                    issuer: l.issuer,
                    subject: l.subject,
                },
            );
        }
    }

    fn ingest(&mut self, index: u64, raw: &[u8]) -> Result<(), String> {
        let env = SignedEnvelope::decode(raw).map_err(|e| e.to_string())?;
        if let Some(b) = &env.signer_bundle {
            if let Ok(b) = PublicBundle::from_value(b) {
                self.bundles.entry(b.agent_id()).or_insert(b);
            }
        }
        let policy = Policy {
            known_bundles: self.bundles.values().cloned().collect(),
            ..Policy::default()
        };
        // Verified as of its own issuance time.
        let v = verify(raw, &policy, env.headers.issued_at).map_err(|e| e.to_string())?;
        match v.content_type.as_str() {
            CT_ATTESTATION => {
                let att = Attestation::from_payload(&v.payload).map_err(|e| e.0)?;
                if att.issuer != v.signer {
                    return Err("attestation issuer differs from the signer".into());
                }
                self.atts.push(AttRec {
                    index,
                    att,
                    issued_at: v.issued_at,
                    expires_at: v.expires_at.unwrap_or(i64::MAX),
                });
            }
            CT_SRL => {
                let srl = Srl::from_payload(&v.payload).map_err(|e| e.0)?;
                for e in srl.revoked {
                    if let RevokedId::Attestation(id) = e.id {
                        self.revoked.insert((srl.issuer, id), e.revoked_at);
                    }
                }
            }
            other => return Err(format!("entry has content type `{other}`")),
        }
        Ok(())
    }

    fn judge(&mut self, index: u64, att: &Attestation, at: i64, out: &mut Vec<Alert>) {
        if att.claim == claims::DOMAIN_CONTROL {
            if let Some(domain) = att.data_get("domain").and_then(|d| d.as_text()) {
                for w in self.cfg.watch_domains.clone() {
                    if domain_matches(domain, &w) && !self.cfg.authorized.contains(&att.subject) {
                        self.raise(
                            out,
                            Alert::UnauthorizedDomainControl {
                                entry: index,
                                domain: domain.to_string(),
                                watched: w,
                                subject: att.subject,
                                issuer: att.issuer,
                            },
                        );
                    }
                }
            }
        }
        if self.cfg.roots.is_empty() || Some(att.issuer) == self.cfg.log_id {
            return;
        }
        if !self.cfg.roots.contains(&att.issuer) && !self.holds_delegation(&att.issuer) {
            if self.cfg.strict_issuers {
                self.raise(
                    out,
                    Alert::UndelegatedIssuer {
                        entry: index,
                        issuer: att.issuer,
                        claim: att.claim.clone(),
                    },
                );
            }
            return;
        }
        let mut wanted = vec![att.claim.clone()];
        if att.claim == claims::ISSUER_AUTHORITY {
            // A delegator can hand on only what it holds itself.
            wanted.push(claims::ISSUER_AUTHORITY.to_string());
            wanted.extend(att.authority_claims().unwrap_or_default());
        }
        wanted.dedup();
        let mut failures = Vec::new();
        for c in &wanted {
            if let Err(why) = self.authorized(&att.issuer, c, at, 1, &mut Vec::new()) {
                failures.push((c.clone(), why));
            }
        }
        if let Some((claim, reason)) = failures.into_iter().next() {
            self.raise(
                out,
                Alert::IssuerOutsideAuthority {
                    entry: index,
                    issuer: att.issuer,
                    claim,
                    subject: att.subject,
                    reason,
                },
            );
        }
    }

    fn delegation_live(&self, a: &AttRec, at: i64) -> bool {
        a.issued_at <= at
            && at < a.expires_at
            && !self
                .revoked
                .get(&(a.att.issuer, a.att.id))
                .is_some_and(|r| *r <= at)
    }

    /// Has the issuer ever been delegated authority (live or not)? Issuers
    /// that never were are outside the delegation system and not judged.
    fn holds_delegation(&self, who: &AgentId) -> bool {
        self.atts
            .iter()
            .any(|a| a.att.subject == *who && a.att.claim == claims::ISSUER_AUTHORITY)
    }

    /// Is `issuer` allowed to issue `claim` at time `at`: a root, or the
    /// subject of a live `issuer-authority` attestation listing the claim
    /// whose own issuer is authorized for `issuer-authority` and for the claim
    /// (Rust finding 18). `depth` counts the attestations in the chain so far,
    /// the judged claim attestation included (1 at the first call), and the
    /// depth test is the verifier's rule (spec section 7, "Chains", rule 3
    /// and the `authorize` pseudocode): authorizing a non-root issuer needs
    /// one more attestation, so it fails when `depth + 1` exceeds `max_depth`.
    fn authorized(
        &self,
        issuer: &AgentId,
        claim: &str,
        at: i64,
        depth: usize,
        path: &mut Vec<AgentId>,
    ) -> Result<(), String> {
        if self.cfg.roots.contains(issuer) {
            return Ok(());
        }
        if path.contains(issuer) {
            return Err(format!("delegation cycle through {issuer}"));
        }
        if depth + 1 > self.cfg.max_depth {
            return Err(format!(
                "delegation chain is longer than {} attestations",
                self.cfg.max_depth
            ));
        }
        path.push(*issuer);
        let mut why = format!("{issuer} holds no live issuer-authority attestation");
        let mut result = Err(why.clone());
        for a in self.atts.iter().filter(|a| {
            a.att.subject == *issuer
                && a.att.claim == claims::ISSUER_AUTHORITY
                && self.delegation_live(a, at)
        }) {
            let listed = a.att.authority_claims().unwrap_or_default();
            if !listed.iter().any(|l| l == claim) {
                why = format!("the authority of {issuer} lists {listed:?}, not {claim}");
                result = Err(why.clone());
                continue;
            }
            let parent = a.att.issuer;
            let up = self
                .authorized(&parent, claims::ISSUER_AUTHORITY, at, depth + 1, path)
                .and_then(|_| {
                    if claim == claims::ISSUER_AUTHORITY {
                        Ok(())
                    } else {
                        self.authorized(&parent, claim, at, depth + 1, path)
                    }
                });
            match up {
                Ok(()) => {
                    result = Ok(());
                    break;
                }
                Err(e) => {
                    why = format!("delegator {parent} is not authorized: {e}");
                    result = Err(why.clone());
                }
            }
        }
        path.pop();
        result
    }
}
