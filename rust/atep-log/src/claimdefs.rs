//! Claim-type definitions: the human readable definition and the CDDL schema
//! of `data` for every claim type of the closed core vocabulary (spec
//! section 7, `https://atep.dev/claims/`) and for the Draft 04 proposal
//! `registry-endpoint`.
//!
//! The source of truth is the data file `data/claims.json`, compiled into the
//! crate. Tests check it against `atep-core`'s list of known claims and
//! against `spec/schemas/atep.cddl`. Everything served by the resolver
//! (`GET /v1/claims/<claim>`, `GET /claims/<name>`) and the claim-type
//! directory comes from here.

use std::sync::OnceLock;

use atep_core::attestation::claims;
use serde_json::{json, Value as J};

const DATA: &str = include_str!("../data/claims.json");

/// The `registry-endpoint` claim type, the seventh core claim type of spec
/// section 7 (it was a Draft 04 proposal carried as an extension claim before
/// Draft 05).
pub const REGISTRY_ENDPOINT: &str = claims::REGISTRY_ENDPOINT;

pub use atep_core::admission::{
    check_registry_endpoint, valid_https_url, valid_kind, ENDPOINT_KINDS,
};

/// One claim type definition.
#[derive(Debug, Clone)]
pub struct ClaimDef {
    /// Path under the namespace: `audited`, `robotics/fleet-member`.
    pub name: String,
    pub uri: String,
    /// `core`, `robotics` or `draft-04`.
    pub profile: String,
    /// `core` or `proposed`.
    pub status: String,
    pub title: String,
    pub summary: String,
    pub description: Vec<String>,
    pub issued_by: String,
    pub subject: String,
    /// CDDL for the `data` map (RFC 8610), self-contained.
    pub data_schema: String,
    pub data_checked_by: String,
    pub evidence: String,
    pub lifetime: String,
    pub spec: Vec<String>,
    pub example_data: J,
}

pub struct Catalog {
    pub namespace: String,
    pub attestation_schema: String,
    pub claims: Vec<ClaimDef>,
}

fn s(v: &J, k: &str) -> String {
    v.get(k)
        .and_then(|x| x.as_str())
        .unwrap_or_else(|| panic!("claims.json: missing text `{k}`"))
        .to_string()
}

fn list(v: &J, k: &str) -> Vec<String> {
    v.get(k)
        .and_then(|x| x.as_array())
        .unwrap_or_else(|| panic!("claims.json: missing list `{k}`"))
        .iter()
        .map(|x| x.as_str().expect("text").to_string())
        .collect()
}

/// The parsed data file. Panics on a malformed file (a test covers it).
pub fn catalog() -> &'static Catalog {
    static CAT: OnceLock<Catalog> = OnceLock::new();
    CAT.get_or_init(|| {
        let root: J = serde_json::from_str(DATA).expect("claims.json is valid JSON");
        let namespace = s(&root, "namespace");
        let claims = root["claims"]
            .as_array()
            .expect("claims list")
            .iter()
            .map(|c| {
                let name = s(c, "name");
                ClaimDef {
                    uri: format!("{namespace}{name}"),
                    name,
                    profile: s(c, "profile"),
                    status: s(c, "status"),
                    title: s(c, "title"),
                    summary: s(c, "summary"),
                    description: list(c, "description"),
                    issued_by: s(c, "issued-by"),
                    subject: s(c, "subject"),
                    data_schema: s(c, "data-schema"),
                    data_checked_by: s(c, "data-checked-by"),
                    evidence: s(c, "evidence"),
                    lifetime: s(c, "lifetime"),
                    spec: list(c, "spec"),
                    example_data: c["example-data"].clone(),
                }
            })
            .collect();
        Catalog {
            attestation_schema: s(&root, "attestation-schema"),
            namespace,
            claims,
        }
    })
}

/// Every definition, in file order (core, robotics, then proposals).
pub fn all() -> &'static [ClaimDef] {
    &catalog().claims
}

/// The definition of a full claim URI.
pub fn find_uri(uri: &str) -> Option<&'static ClaimDef> {
    all().iter().find(|d| d.uri == uri)
}

/// Resolve what a client wrote after `/v1/claims/`: a full URI, or a short
/// name with the expansion rules of spec section 7.
pub fn resolve(input: &str) -> Option<&'static ClaimDef> {
    find_uri(&claims::expand(input))
}

/// Directory fields shared by `GET /v1/claims` rows and the resolver.
fn base_json(d: &ClaimDef) -> serde_json::Map<String, J> {
    let mut m = serde_json::Map::new();
    m.insert("claim".into(), json!(d.uri));
    m.insert("name".into(), json!(d.name));
    m.insert("core".into(), json!(d.status == "core"));
    m.insert("status".into(), json!(d.status));
    m.insert("profile".into(), json!(d.profile));
    m.insert("definition".into(), json!(d.summary));
    m.insert("data-schema".into(), json!(d.data_schema));
    m
}

/// The resolver document for one claim type.
pub fn definition_json(d: &ClaimDef) -> J {
    let mut m = base_json(d);
    m.insert("title".into(), json!(d.title));
    m.insert("description".into(), json!(d.description));
    m.insert("issued-by".into(), json!(d.issued_by));
    m.insert("subject".into(), json!(d.subject));
    m.insert("data-schema-format".into(), json!("cddl"));
    m.insert(
        "attestation-schema".into(),
        json!(catalog().attestation_schema),
    );
    m.insert("data-checked-by".into(), json!(d.data_checked_by));
    m.insert("evidence".into(), json!(d.evidence));
    m.insert("lifetime".into(), json!(d.lifetime));
    m.insert("spec".into(), json!(d.spec));
    m.insert("example-data".into(), d.example_data.clone());
    m.insert(
        "links".into(),
        json!({
            "self": format!("/claims/{}", d.name),
            "html": format!("/claims/{}.html", d.name),
            "api": format!("/v1/claims/{}", pct(&d.uri)),
            "directory": "/v1/claims",
        }),
    );
    J::Object(m)
}

/// Percent-encode everything except unreserved characters.
pub fn pct(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The index document of `GET /claims`.
pub fn index_json() -> J {
    let list: Vec<J> = all()
        .iter()
        .map(|d| {
            let mut m = base_json(d);
            m.remove("data-schema");
            m.insert("title".into(), json!(d.title));
            m.insert("url".into(), json!(d.uri));
            J::Object(m)
        })
        .collect();
    json!({ "namespace": catalog().namespace, "claims": list })
}

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

const STYLE: &str = "<style>:root{color-scheme:light dark;--bg:#fff;--fg:#1b1f24;--mut:#59636e;--line:#d1d9e0;--code:#f3f5f7}\
@media(prefers-color-scheme:dark){:root{--bg:#0f1318;--fg:#e6e9ed;--mut:#9aa5b1;--line:#2d343c;--code:#171c22}}\
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 system-ui,sans-serif}\
main{max-width:56rem;margin:0 auto;padding:2rem 16px}h1{font-size:1.6rem;margin:0 0 .25rem}\
.uri,pre,code{font-family:ui-monospace,monospace}.uri{color:var(--mut);word-break:break-all}\
pre{background:var(--code);border:1px solid var(--line);padding:1rem;overflow-x:auto;border-radius:6px}\
dl{display:grid;grid-template-columns:max-content 1fr;gap:.35rem 1.25rem}dt{color:var(--mut)}dd{margin:0}\
a{color:inherit}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid var(--line);padding:.4rem .5rem;text-align:left;vertical-align:top}\
@media(max-width:600px){dl{grid-template-columns:1fr}}</style>";

fn page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{}</title>{STYLE}</head><body><main>{body}</main></body></html>\n",
        esc(title)
    )
}

/// HTML page of one claim type.
pub fn definition_html(d: &ClaimDef) -> String {
    let mut b = String::new();
    b.push_str(&format!(
        "<h1>{}</h1><p class=\"uri\">{}</p><p>{}</p>",
        esc(&d.title),
        esc(&d.uri),
        esc(&d.summary)
    ));
    for p in &d.description {
        b.push_str(&format!("<p>{}</p>", esc(p)));
    }
    b.push_str("<dl>");
    let rows: [(&str, &str); 7] = [
        ("Status", &d.status),
        ("Profile", &d.profile),
        ("Issued by", &d.issued_by),
        ("Subject", &d.subject),
        ("Evidence", &d.evidence),
        ("Lifetime", &d.lifetime),
        ("Data checked by", &d.data_checked_by),
    ];
    for (k, v) in rows {
        b.push_str(&format!("<dt>{k}</dt><dd>{}</dd>", esc(v)));
    }
    b.push_str(&format!(
        "<dt>Specification</dt><dd>{}</dd></dl>",
        esc(&d.spec.join("; "))
    ));
    b.push_str("<h2>Schema of <code>data</code> (CDDL, RFC 8610)</h2>");
    b.push_str(&format!("<pre>{}</pre>", esc(&d.data_schema)));
    b.push_str("<h2>Attestation payload (CDDL)</h2>");
    b.push_str(&format!(
        "<pre>{}</pre>",
        esc(&catalog().attestation_schema)
    ));
    b.push_str("<h2>Example <code>data</code> (JSON form)</h2>");
    b.push_str(&format!(
        "<pre>{}</pre>",
        esc(&serde_json::to_string_pretty(&d.example_data).unwrap_or_default())
    ));
    b.push_str("<p><a href=\"/claims\">All claim types</a></p>");
    page(&format!("{} (ATEP claim type)", d.title), &b)
}

/// HTML index of all claim types.
pub fn index_html() -> String {
    let mut b = String::from("<h1>ATEP claim types</h1><p class=\"uri\">");
    b.push_str(&esc(&catalog().namespace));
    b.push_str("</p><p>The closed core vocabulary of Draft 03 and the Draft 04 proposals. Each page has the definition and the CDDL schema of <code>data</code>.</p><table><tr><th>Claim</th><th>Status</th><th>Definition</th></tr>");
    for d in all() {
        b.push_str(&format!(
            "<tr><td><a href=\"/claims/{n}\">{n}</a></td><td>{}</td><td>{}</td></tr>",
            esc(&d.status),
            esc(&d.summary),
            n = esc(&d.name)
        ));
    }
    b.push_str("</table>");
    page("ATEP claim types", &b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_rules() {
        assert!(valid_https_url("https://registry.example.com/v1"));
        assert!(valid_https_url("https://example.com:8443"));
        assert!(!valid_https_url("http://example.com"));
        assert!(!valid_https_url("https://"));
        assert!(!valid_https_url("https://user@example.com/"));
        assert!(!valid_https_url("https://exa mple.com"));
        assert!(!valid_https_url("https:///path"));
    }

    #[test]
    fn kinds() {
        assert!(valid_kind("mcp") && valid_kind("x-foo-1"));
        assert!(!valid_kind("x-") && !valid_kind("other") && !valid_kind("x-Foo"));
    }

    #[test]
    fn html_escapes() {
        assert_eq!(esc("<a&\"'>"), "&lt;a&amp;&quot;&#39;&gt;");
    }
}
