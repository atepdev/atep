//! Registry services layered on the log (spec section 9): the issuer
//! directory and the claim-type directory, both derived from log content and
//! the published log policy. Nothing here is authoritative: every number can
//! be recomputed from the entries.

use std::collections::{BTreeMap, BTreeSet};

use atep_core::attestation::claims;
use serde_json::{json, Value as J};

use crate::admit::is_core_claim;
use crate::claimdefs;
use crate::log::{EntryKind, EntryMeta, Log};

fn namespace_of(claim: &str) -> String {
    match claim.rfind('/') {
        Some(i) => claim[..=i].to_string(),
        None => claim.to_string(),
    }
}

/// Issuer directory: every identity that issued a logged attestation or SRL.
pub fn issuers(log: &Log) -> J {
    #[derive(Default)]
    struct Row {
        first: Option<u64>,
        entries: u64,
        claims: BTreeSet<String>,
        srl: Option<(u64, i64, i64)>,
    }
    let mut rows: BTreeMap<String, Row> = BTreeMap::new();
    let mut delegated: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut delegated_by: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut domains: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for m in log.entries_meta() {
        let row = rows.entry(m.issuer.to_text()).or_default();
        row.first.get_or_insert(m.index);
        row.entries += 1;
        match m.kind {
            EntryKind::Attestation => {
                if let Some(c) = &m.claim {
                    row.claims.insert(c.clone());
                }
                if let Some(s) = &m.subject {
                    if !m.delegated.is_empty() {
                        delegated
                            .entry(s.to_text())
                            .or_default()
                            .extend(m.delegated.iter().cloned());
                        delegated_by
                            .entry(s.to_text())
                            .or_default()
                            .insert(m.issuer.to_text());
                    }
                    if let Some(d) = &m.domain {
                        if *s == m.issuer {
                            domains.entry(s.to_text()).or_default().insert(d.clone());
                        }
                    }
                }
            }
            EntryKind::Srl => {
                row.srl = Some((m.index, m.srl_sequence.unwrap_or(0), m.issued_at));
            }
        }
    }
    // Domains for an issuer may be bound by someone else's domain-control
    // attestation; only self-bound domains give an SRL location.
    let list: Vec<J> = rows
        .into_iter()
        .map(|(id, row)| {
            let doms: Vec<String> = domains
                .get(&id)
                .map(|d| d.iter().cloned().collect())
                .unwrap_or_default();
            let urls: Vec<String> = doms
                .iter()
                .map(|d| format!("https://{d}/.well-known/atep-revocations.cbor"))
                .collect();
            let namespaces: BTreeSet<String> = row.claims.iter().map(|c| namespace_of(c)).collect();
            json!({
                "issuer": id,
                "first-index": row.first,
                "entries": row.entries,
                "claims": row.claims,
                "namespaces": namespaces,
                "delegated-claims": delegated.get(&id).cloned().unwrap_or_default(),
                "delegated-by": delegated_by.get(&id).cloned().unwrap_or_default(),
                "domains": doms,
                "srl-urls": urls,
                "latest-srl": row.srl.map(|(i, seq, at)| json!({
                    "entry": i, "sequence": seq, "issued-at": at,
                })),
                "included": true,
            })
        })
        .collect();
    json!({ "tree-size": log.tree_size(), "issuers": list })
}

/// Claim-type directory: the core vocabulary named by the log policy, plus
/// every other claim type that appears in the log.
pub fn claim_types(log: &Log) -> J {
    #[derive(Default)]
    struct Row {
        first: Option<u64>,
        entries: u64,
        issuers: BTreeSet<String>,
    }
    let mut rows: BTreeMap<String, Row> = BTreeMap::new();
    for d in claimdefs::all() {
        rows.entry(d.uri.clone()).or_default();
    }
    for m in log.entries_meta() {
        let (EntryKind::Attestation, Some(c)) = (m.kind, &m.claim) else {
            continue;
        };
        if m.is_policy {
            continue;
        }
        let row = rows.entry(c.clone()).or_default();
        row.first.get_or_insert(m.index);
        row.entries += 1;
        row.issuers.insert(m.issuer.to_text());
    }
    let list: Vec<J> = rows
        .into_iter()
        .map(|(uri, row)| {
            let def = claimdefs::find_uri(&uri);
            let row = json!({
                "claim": uri,
                "core": is_core_claim(&uri),
                "namespace": namespace_of(&uri),
                "entries": row.entries,
                "issuers": row.issuers.len(),
                "first-index": row.first,
                "definition": def.map(|d| d.summary.as_str()),
                "data-schema": def.map(|d| d.data_schema.as_str()),
                "status": def.map_or("open", |d| d.status.as_str()),
                "resolve": def.map(|d| format!("/v1/claims/{}", claimdefs::pct(&d.uri))),
            });
            row
        })
        .collect();
    json!({ "tree-size": log.tree_size(), "core-namespace": claims::NS, "claim-types": list })
}

/// JSON view of an entry's metadata.
pub fn entry_json(m: &EntryMeta, envelope: Option<&[u8]>) -> J {
    let mut o = json!({
        "index": m.index,
        "leaf-hash": hex::encode(m.leaf),
        "logged-at": m.logged_at,
        "kind": match m.kind { EntryKind::Attestation => "attestation", EntryKind::Srl => "srl" },
        "issuer": m.issuer.to_text(),
        "issued-at": m.issued_at,
        "expires-at": m.expires_at,
    });
    let map = o.as_object_mut().expect("object");
    if let Some(s) = &m.subject {
        map.insert("subject".into(), json!(s.to_text()));
    }
    if let Some(c) = &m.claim {
        map.insert("claim".into(), json!(c));
    }
    if let Some(id) = &m.att_id {
        map.insert("attestation-id".into(), json!(hex::encode(id)));
    }
    if let Some(q) = m.srl_sequence {
        map.insert("srl-sequence".into(), json!(q));
    }
    if m.is_policy {
        map.insert("policy".into(), json!(true));
    }
    if let Some(e) = envelope {
        map.insert("envelope".into(), json!(crate::b64(e)));
    }
    o
}
