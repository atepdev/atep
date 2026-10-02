//! Domain records and the binding check: what a `domain-control` issuer
//! verifies before it issues the attestation (spec section 4, "Domain
//! records" and "Bind"; section 7, "Checking a domain binding"). The pure
//! parts live here, with no network code, so that the language neutral
//! domain binding vectors (`vectors/domain-binding`) run from `atep-vectors`;
//! `atep_log::domain_binding` re-exports this module and adds a small
//! network fetcher.
//!
//! A domain publishes the Agent IDs it authorizes in a JSON document at
//! `https://<domain>/.well-known/atep.json`, in TXT records at
//! `_atep.<domain>`, or both. [`check_domain_binding`] reads them through a
//! [`DomainFetcher`] (this module has no network code of its own; a real
//! fetcher is plugged in, and `net` has a small `std::net` one behind the
//! `net-fetch` feature) and reports whether `agent_id` is listed.
//!
//! The result is evidence for the issuer, not for a verifier: the log cannot
//! see DNS, so a verifier still trusts the issuer's `domain-control`
//! attestation, and monitors watch for mis-issuance (spec section 9).

use serde_json::Value as J;

use crate::admission::{valid_domain, valid_https_url};
use crate::keys::AgentId;

/// Largest well-known document read (bytes).
pub const MAX_DOC_BYTES: usize = 64 * 1024;
/// Most Agent IDs read from one source.
pub const MAX_AGENTS: usize = 1024;
/// Most TXT records read at `_atep.<domain>`.
pub const MAX_TXT_RECORDS: usize = 16;
/// Longest TXT record read (the character-strings of one record, joined).
pub const MAX_TXT_BYTES: usize = 1024;
/// Version of the record formats.
pub const VERSION: i64 = 1;
/// First term of every `_atep.<domain>` record.
pub const TXT_VERSION_TERM: &str = "v=atep1";

/// Why a fetch gave nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
    /// The document or the name does not exist (HTTP 404 or 410, NXDOMAIN, no TXT data).
    NotFound,
    /// Timeouts, connection failures, server errors: worth retrying.
    Unavailable(String),
}

/// An HTTP answer for the well-known document.
#[derive(Debug, Clone)]
pub struct WellKnownResponse {
    pub status: u16,
    /// The URL the body came from after any redirects the fetcher followed.
    pub final_url: String,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

/// A DNS TXT answer.
#[derive(Debug, Clone, Default)]
pub struct TxtAnswer {
    /// One entry per TXT record, its character-strings concatenated.
    pub records: Vec<String>,
    /// True when the resolver validated the answer with DNSSEC (the AD bit
    /// from a validating resolver you trust, or validation done locally).
    pub dnssec_validated: bool,
}

/// How the checker reads the outside world. Implementations MUST use HTTPS
/// with full certificate validation for the well-known document and follow at
/// most three redirects that stay on `https` and the host `<domain>` (the
/// checker rejects a `final_url` that is not `https://<domain>/...`).
pub trait DomainFetcher {
    /// `GET https://<domain>/.well-known/atep.json`.
    fn fetch_well_known(&self, domain: &str) -> Result<WellKnownResponse, FetchError>;
    /// TXT records of `name` (for example `_atep.example.com`).
    fn fetch_txt(&self, name: &str) -> Result<TxtAnswer, FetchError>;
}

/// Outcome of one source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceResult {
    /// The source is valid and lists the Agent ID.
    Listed,
    /// The source is valid and does not list it.
    NotListed,
    /// The source does not exist.
    Absent,
    /// The source exists but breaks the format or the transport rules; the reason is attached.
    Invalid(String),
    /// The source could not be read; retry later.
    Unavailable(String),
}

impl SourceResult {
    fn definite_no(&self) -> bool {
        matches!(
            self,
            SourceResult::NotListed | SourceResult::Absent | SourceResult::Invalid(_)
        )
    }
}

/// The verdict for the issuer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The domain authorizes the Agent ID: the issuer may issue `domain-control`.
    Bound,
    /// It does not (not listed, no records, invalid records, or the sources disagree).
    NotBound,
    /// No source lists it and at least one could not be read: do not issue, retry.
    Indeterminate,
}

/// Options of the check.
#[derive(Debug, Clone, Copy, Default)]
pub struct BindingOptions {
    /// Treat a TXT answer that is not DNSSEC validated as invalid.
    pub require_dnssec: bool,
    /// Require both the well-known document and the TXT record to list the Agent ID.
    pub require_both: bool,
}

/// Everything the check learned.
#[derive(Debug, Clone)]
pub struct BindingReport {
    pub domain: String,
    pub agent_id: AgentId,
    pub well_known: SourceResult,
    pub dns: SourceResult,
    pub outcome: Outcome,
    /// Both sources are valid and one lists the Agent ID while the other does not.
    pub conflict: bool,
    /// `updated` of the well-known document, when present.
    pub updated: Option<i64>,
    /// `srl-url` of the well-known document (or an `srl=` TXT term), when present.
    pub srl_url: Option<String>,
    pub warnings: Vec<String>,
}

/// Check whether `domain` authorizes `agent_id`. `domain` must be a canonical
/// lowercase DNS name (the form of `domain-control` `data.domain`). Only that
/// exact name is read: a record at `example.com` says nothing about
/// `a.example.com`, and the reverse.
pub fn check_domain_binding(
    domain: &str,
    agent_id: &AgentId,
    fetcher: &dyn DomainFetcher,
) -> BindingReport {
    check_domain_binding_with(domain, agent_id, fetcher, BindingOptions::default())
}

pub fn check_domain_binding_with(
    domain: &str,
    agent_id: &AgentId,
    fetcher: &dyn DomainFetcher,
    opts: BindingOptions,
) -> BindingReport {
    let mut report = BindingReport {
        domain: domain.to_string(),
        agent_id: *agent_id,
        well_known: SourceResult::Absent,
        dns: SourceResult::Absent,
        outcome: Outcome::NotBound,
        conflict: false,
        updated: None,
        srl_url: None,
        warnings: Vec::new(),
    };
    if !valid_domain(domain) {
        let why = "domain is not a canonical lowercase DNS name".to_string();
        report.well_known = SourceResult::Invalid(why.clone());
        report.dns = SourceResult::Invalid(why);
        return report;
    }

    // Well-known document.
    let mut wk_present = false;
    report.well_known = match fetcher.fetch_well_known(domain) {
        Err(FetchError::NotFound) => SourceResult::Absent,
        Err(FetchError::Unavailable(m)) => SourceResult::Unavailable(m),
        Ok(resp) => match parse_well_known(domain, &resp) {
            Ok(doc) => {
                wk_present = true;
                report.updated = doc.updated;
                report.srl_url = doc.srl_url;
                report.warnings.extend(doc.warnings);
                if doc.agents.contains(agent_id) {
                    SourceResult::Listed
                } else {
                    SourceResult::NotListed
                }
            }
            Err(SourceResult::Absent) => SourceResult::Absent,
            Err(e) => e,
        },
    };

    // TXT records.
    let mut dns_present = false;
    report.dns = match fetcher.fetch_txt(&txt_name(domain)) {
        Err(FetchError::NotFound) => SourceResult::Absent,
        Err(FetchError::Unavailable(m)) => SourceResult::Unavailable(m),
        Ok(answer) => {
            let parsed = parse_txt(&answer.records);
            if parsed.records == 0 {
                SourceResult::Absent
            } else if opts.require_dnssec && !answer.dnssec_validated {
                SourceResult::Invalid("TXT answer is not DNSSEC validated".into())
            } else {
                dns_present = true;
                if !answer.dnssec_validated {
                    report
                        .warnings
                        .push("TXT answer is not DNSSEC validated".into());
                }
                if report.srl_url.is_none() {
                    report.srl_url = parsed.srl_url;
                }
                if parsed.agents.contains(agent_id) {
                    SourceResult::Listed
                } else {
                    SourceResult::NotListed
                }
            }
        }
    };

    report.conflict = wk_present
        && dns_present
        && report.well_known != report.dns
        && (report.well_known == SourceResult::Listed || report.dns == SourceResult::Listed);

    let (a, b) = (&report.well_known, &report.dns);
    report.outcome = if opts.require_both {
        if *a == SourceResult::Listed && *b == SourceResult::Listed {
            Outcome::Bound
        } else if a.definite_no() || b.definite_no() {
            Outcome::NotBound
        } else {
            Outcome::Indeterminate
        }
    } else if report.conflict {
        Outcome::NotBound
    } else if *a == SourceResult::Listed || *b == SourceResult::Listed {
        Outcome::Bound
    } else if matches!(a, SourceResult::Unavailable(_)) || matches!(b, SourceResult::Unavailable(_))
    {
        Outcome::Indeterminate
    } else {
        Outcome::NotBound
    };
    report
}

/// `_atep.<domain>`.
pub fn txt_name(domain: &str) -> String {
    format!("_atep.{domain}")
}

/// The well-known URL of a domain.
pub fn well_known_url(domain: &str) -> String {
    format!("https://{domain}/.well-known/atep.json")
}

struct WellKnownDoc {
    agents: Vec<AgentId>,
    updated: Option<i64>,
    srl_url: Option<String>,
    warnings: Vec<String>,
}

fn invalid(m: impl Into<String>) -> SourceResult {
    SourceResult::Invalid(m.into())
}

fn parse_well_known(domain: &str, r: &WellKnownResponse) -> Result<WellKnownDoc, SourceResult> {
    match r.status {
        200 => {}
        404 | 410 => return Err(SourceResult::Absent),
        429 | 500..=599 => {
            return Err(SourceResult::Unavailable(format!(
                "HTTP status {}",
                r.status
            )))
        }
        s => return Err(invalid(format!("HTTP status {s}"))),
    }
    let expect = format!("https://{domain}/");
    if !r.final_url.starts_with(&expect) {
        return Err(invalid(format!(
            "document was served from {}, not {expect}",
            r.final_url
        )));
    }
    let ct = r.content_type.as_deref().unwrap_or("");
    let media = ct
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if media != "application/json" {
        return Err(invalid(format!(
            "content type is `{ct}`, expected application/json"
        )));
    }
    if r.body.len() > MAX_DOC_BYTES {
        return Err(invalid(format!(
            "document is larger than {MAX_DOC_BYTES} bytes"
        )));
    }
    let j: J = serde_json::from_slice(&r.body).map_err(|_| invalid("body is not JSON"))?;
    let obj = j
        .as_object()
        .ok_or_else(|| invalid("document is not an object"))?;
    if obj.get("version").and_then(|v| v.as_i64()) != Some(VERSION) {
        return Err(invalid("`version` must be the integer 1"));
    }
    if let Some(d) = obj.get("domain") {
        if d.as_str() != Some(domain) {
            return Err(invalid(
                "`domain` does not equal the domain it was served for",
            ));
        }
    }
    let list = obj
        .get("agents")
        .and_then(|a| a.as_array())
        .ok_or_else(|| invalid("`agents` must be an array of Agent IDs"))?;
    let mut warnings = Vec::new();
    let mut agents = Vec::new();
    let mut ignored = 0;
    for a in list.iter().take(MAX_AGENTS) {
        match a.as_str().and_then(|s| AgentId::parse(s).ok()) {
            Some(id) => agents.push(id),
            None => ignored += 1,
        }
    }
    if list.len() > MAX_AGENTS {
        warnings.push(format!("only the first {MAX_AGENTS} agents were read"));
    }
    if ignored > 0 {
        warnings.push(format!(
            "{ignored} entries of `agents` are not Agent IDs and were ignored"
        ));
    }
    let srl_url = match obj.get("srl-url") {
        None => None,
        Some(v) => match v.as_str() {
            Some(u) if valid_https_url(u) => Some(u.to_string()),
            _ => {
                warnings.push("`srl-url` is not an https URL and was ignored".into());
                None
            }
        },
    };
    Ok(WellKnownDoc {
        agents,
        updated: obj.get("updated").and_then(|u| u.as_i64()),
        srl_url,
        warnings,
    })
}

struct TxtParse {
    /// Records that start with `v=atep1`.
    records: usize,
    agents: Vec<AgentId>,
    srl_url: Option<String>,
}

/// Parse the records at `_atep.<domain>`. A record is ASCII terms separated
/// by spaces; the first is `v=atep1`; `id=<agent id>` terms list an identity
/// and an `srl=<https url>` term gives the SRL location. Records that do not
/// start with `v=atep1`, over-long records, records past the sixteenth and
/// unknown terms are ignored.
fn parse_txt(records: &[String]) -> TxtParse {
    let mut out = TxtParse {
        records: 0,
        agents: Vec::new(),
        srl_url: None,
    };
    for rec in records.iter().take(MAX_TXT_RECORDS) {
        if rec.len() > MAX_TXT_BYTES || !rec.is_ascii() {
            continue;
        }
        // The record begins with the term `v=atep1`: no leading space, and
        // the term ends there or at a space (spec section 4, "DNS record").
        let Some(rest) = rec.strip_prefix(TXT_VERSION_TERM) else {
            continue;
        };
        if !(rest.is_empty() || rest.starts_with(' ')) {
            continue;
        }
        out.records += 1;
        for t in rest.split(' ').filter(|t| !t.is_empty()) {
            if let Some(id) = t.strip_prefix("id=") {
                if let Ok(a) = AgentId::parse(id) {
                    out.agents.push(a);
                }
            } else if let Some(u) = t.strip_prefix("srl=") {
                if valid_https_url(u) && out.srl_url.is_none() {
                    out.srl_url = Some(u.to_string());
                }
            }
        }
    }
    out
}

/// Render the TXT record text for a list of Agent IDs: one record per call,
/// at most three IDs fit in the 255 byte limit of a single character-string.
pub fn txt_record(agents: &[AgentId]) -> String {
    let mut s = TXT_VERSION_TERM.to_string();
    for a in agents {
        s.push_str(" id=");
        s.push_str(&a.to_text());
    }
    s
}

/// Render the well-known document.
pub fn well_known_document(agents: &[AgentId], srl_url: Option<&str>, updated: i64) -> J {
    let mut j = serde_json::json!({
        "version": VERSION,
        "agents": agents.iter().map(|a| a.to_text()).collect::<Vec<_>>(),
        "updated": updated,
    });
    if let Some(u) = srl_url {
        j["srl-url"] = J::String(u.to_string());
    }
    j
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> AgentId {
        AgentId([n; 32])
    }

    #[test]
    fn a_txt_record_begins_with_the_version_term() {
        let good = txt_record(&[id(1)]);
        assert_eq!(parse_txt(std::slice::from_ref(&good)).agents, vec![id(1)]);
        // A leading space, a longer first term and another case of the name are not `v=atep1`.
        for bad in [
            format!(" {good}"),
            good.replacen("v=atep1", "v=atep10", 1),
            good.replacen("v=atep1", "v=atep", 1),
        ] {
            let p = parse_txt(std::slice::from_ref(&bad));
            assert_eq!(p.records, 0, "{bad}");
            assert!(p.agents.is_empty());
        }
        // Several spaces between terms are fine; a bare version term authorizes nobody.
        let spaced = format!("v=atep1   id={}", id(2).to_text());
        assert_eq!(parse_txt(&[spaced]).agents, vec![id(2)]);
        let bare = parse_txt(&["v=atep1".to_string()]);
        assert_eq!(bare.records, 1);
        assert!(bare.agents.is_empty());
    }
}
