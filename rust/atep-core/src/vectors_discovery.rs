//! Vectors for the discovery formats of Draft 05 (spec sections 4, 7 and 9,
//! known gaps 20 and 21): the `registry-endpoint` attestation data, and the
//! domain records with the binding check. A child of `vectors_trust`. The
//! formats are documented in `vectors/README.md` and
//! `vectors/ANCHOR-DISCOVERY-NOTES.md`.
//!
//! `registry-endpoint` vectors are log admission vectors (the CBOR file is the
//! submitted attestation, the result is the refusal or the acceptance of the
//! admission rules of section 9). `domain-binding` vectors are pure fixtures:
//! nothing in a domain record is signed, so the object under test is the
//! answers a fake fetcher gives for the names the checker asks for, the Agent
//! ID asked about and the options, and the result is the state of each source
//! and the outcome of the check. No network is involved.

use std::cell::RefCell;
use std::collections::HashMap;

use super::*;
use crate::attestation::json_to_cbor;
use crate::domain::{
    check_domain_binding_with, BindingOptions, DomainFetcher, FetchError, Outcome, SourceResult,
    TxtAnswer, WellKnownResponse, MAX_DOC_BYTES, MAX_TXT_BYTES, MAX_TXT_RECORDS,
};

const D: &str = "example.com";

pub(super) fn generate(out: &mut Vec<Vector>, n: &Net) -> R<()> {
    registry_endpoint_vectors(out, n)?;
    domain_binding_vectors(out, n)?;
    Ok(())
}

pub(super) fn check(category: &str, cbor: &[u8], inputs: &J, expected: &J) -> R<()> {
    let got = match category {
        "registry-endpoint" => retired::run_admission(cbor, inputs)?,
        "domain-binding" => run_domain_binding(cbor, inputs)?,
        other => return Err(e(format!("unknown category {other}"))),
    };
    if &got != expected {
        return Err(e(format!("result {got} != expected {expected}")));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// registry-endpoint (admission)

fn registry_endpoint_vectors(out: &mut Vec<Vector>, n: &Net) -> R<()> {
    let inputs = json!({
        "now": NOW,
        "log": n.log.agent_id().to_text(),
        "max_envelope_bytes": 65_536,
        "logged": [],
    });
    let push = |out: &mut Vec<Vector>,
                name: &str,
                desc: &str,
                cbor: Vec<u8>,
                want: Result<(), &str>|
     -> R<()> {
        let expected = retired::run_admission(&cbor, &inputs)?;
        let ok = match want {
            Ok(()) => expected == json!({ "ok": true, "document": "attestation" }),
            Err(r) => expected == json!({ "ok": false, "refusal": r }),
        };
        if !ok {
            return Err(e(format!(
                "generator bug: registry-endpoint/{name}: {expected}"
            )));
        }
        out.push(Vector {
            category: "registry-endpoint",
            name: name.to_string(),
            description: desc.to_string(),
            cbor,
            inputs: inputs.clone(),
            expected,
        });
        Ok(())
    };
    let att = |label: &str, data: Vec<(&str, Value)>| -> R<Vec<u8>> {
        issue_att(
            &A::std(
                &n.alice,
                n.alice.agent_id(),
                claims::REGISTRY_ENDPOINT,
                label,
            )
            .data(text_map(data)),
        )
    };
    let url = |u: &str| Value::text(u);
    let kind = |k: &str| Value::text(k);
    let ok_url = "https://registry.example.com/v1";

    // Accepted.
    push(
        out,
        "valid-registry",
        "A registry-endpoint attestation (a core claim type) for kind `registry` with an https URL. A log admits it like any attestation: no new document type or endpoint.",
        att("re/registry", vec![("url", url(ok_url)), ("kind", kind("registry"))])?,
        Ok(()),
    )?;
    push(
        out,
        "valid-verifier-with-port-path-and-query",
        "Kind `verifier`; the URL has a port, a path and a query.",
        att(
            "re/verifier",
            vec![
                (
                    "url",
                    url("https://verify.example.com:8443/atep/verify?v=1"),
                ),
                ("kind", kind("verifier")),
            ],
        )?,
        Ok(()),
    )?;
    push(
        out,
        "valid-mcp",
        "Kind `mcp`.",
        att(
            "re/mcp",
            vec![
                ("url", url("https://mcp.example.com/sse")),
                ("kind", kind("mcp")),
            ],
        )?,
        Ok(()),
    )?;
    push(
        out,
        "valid-a2a-with-agent-card-digest",
        "Kind `a2a` carrying the digest of the agent card as `evidence` and the https URL it is fetched from as `evidence-uri`. Evidence makes the attestation audit-backed for the lifetime tiers; the layout of `data` is unchanged and admission accepts it.",
        {
            let a = A::std(
                &n.alice,
                n.alice.agent_id(),
                claims::REGISTRY_ENDPOINT,
                "re/a2a",
            )
            .data(text_map(vec![
                ("url", url("https://agent.example.com/a2a")),
                ("kind", kind("a2a")),
            ]))
            .evidence();
            forge_att(&a, |m| {
                m.push((
                    Value::text("evidence-uri"),
                    Value::text("https://agent.example.com/.well-known/agent.json"),
                ))
            })?
        },
        Ok(()),
    )?;
    push(
        out,
        "valid-extension-kind",
        "Kind `x-acme-queue`: an extension name is `x-` followed by lowercase letters, digits and hyphens.",
        att(
            "re/ext",
            vec![("url", url("https://q.example.com/")), ("kind", kind("x-acme-queue"))],
        )?,
        Ok(()),
    )?;
    push(
        out,
        "valid-other-members-are-free",
        "`data` has members beyond `url` and `kind`; they are free and ignored.",
        att(
            "re/free",
            vec![
                ("url", url(ok_url)),
                ("kind", kind("registry")),
                ("region", Value::text("eu")),
                ("note", Value::Int(7)),
            ],
        )?,
        Ok(()),
    )?;
    let long_ok = format!(
        "https://example.com/{}",
        "a".repeat(2048 - "https://example.com/".len())
    );
    assert_eq!(long_ok.len(), 2048);
    push(
        out,
        "valid-url-2048-characters",
        "A URL of exactly 2048 characters: the longest allowed.",
        att(
            "re/url2048",
            vec![("url", url(&long_ok)), ("kind", kind("registry"))],
        )?,
        Ok(()),
    )?;

    // Refused: schema_invalid.
    let long_bad = format!(
        "https://example.com/{}",
        "a".repeat(2049 - "https://example.com/".len())
    );
    type Case<'a> = (&'a str, &'a str, Vec<(&'a str, Value)>);
    let cases: Vec<Case> = vec![
        (
            "reject-url-scheme-http",
            "`url` is an `http` URL: only `https` is allowed.",
            vec![
                ("url", url("http://registry.example.com/v1")),
                ("kind", kind("registry")),
            ],
        ),
        (
            "reject-url-scheme-ftp",
            "`url` has the scheme `ftp`.",
            vec![
                ("url", url("ftp://registry.example.com/v1")),
                ("kind", kind("registry")),
            ],
        ),
        (
            "reject-url-without-scheme",
            "`url` is a bare host name.",
            vec![
                ("url", url("registry.example.com")),
                ("kind", kind("registry")),
            ],
        ),
        (
            "reject-url-with-credentials",
            "`url` carries credentials (`user:password@`).",
            vec![
                ("url", url("https://user:secret@registry.example.com/v1")),
                ("kind", kind("registry")),
            ],
        ),
        (
            "reject-url-with-whitespace",
            "`url` contains a space.",
            vec![
                ("url", url("https://registry.example.com/a b")),
                ("kind", kind("registry")),
            ],
        ),
        (
            "reject-url-without-host",
            "`url` is `https:///v1`: no host.",
            vec![("url", url("https:///v1")), ("kind", kind("registry"))],
        ),
        (
            "reject-url-with-port-and-no-host",
            "`url` is `https://:8443/`: a port and no host.",
            vec![("url", url("https://:8443/")), ("kind", kind("registry"))],
        ),
        (
            "reject-url-2049-characters",
            "A URL of 2049 characters: one over the limit.",
            vec![("url", url(&long_bad)), ("kind", kind("registry"))],
        ),
        (
            "reject-url-not-text",
            "`url` is the integer 7.",
            vec![("url", Value::Int(7)), ("kind", kind("registry"))],
        ),
        (
            "reject-url-missing",
            "`data` has no `url`.",
            vec![("kind", kind("registry"))],
        ),
        (
            "reject-kind-unknown",
            "`kind` is `ftp`: not a defined kind and not an `x-` extension.",
            vec![("url", url(ok_url)), ("kind", kind("ftp"))],
        ),
        (
            "reject-kind-wrong-case",
            "`kind` is `Registry`: kinds are lowercase.",
            vec![("url", url(ok_url)), ("kind", kind("Registry"))],
        ),
        (
            "reject-kind-empty",
            "`kind` is the empty string.",
            vec![("url", url(ok_url)), ("kind", kind(""))],
        ),
        (
            "reject-kind-extension-without-name",
            "`kind` is `x-`: an extension needs a name.",
            vec![("url", url(ok_url)), ("kind", kind("x-"))],
        ),
        (
            "reject-kind-extension-uppercase",
            "`kind` is `x-Acme`: the extension name is lowercase.",
            vec![("url", url(ok_url)), ("kind", kind("x-Acme"))],
        ),
        (
            "reject-kind-extension-underscore",
            "`kind` is `x-acme_queue`: an underscore is not allowed.",
            vec![("url", url(ok_url)), ("kind", kind("x-acme_queue"))],
        ),
        (
            "reject-kind-not-text",
            "`kind` is the integer 3.",
            vec![("url", url(ok_url)), ("kind", Value::Int(3))],
        ),
        (
            "reject-kind-missing",
            "`data` has no `kind`.",
            vec![("url", url(ok_url))],
        ),
    ];
    for (name, desc, data) in cases {
        push(
            out,
            name,
            desc,
            att(&format!("re/{name}"), data)?,
            Err("schema_invalid"),
        )?;
    }
    // The vocabulary stays closed: a look-alike claim URI under the reserved namespace.
    let lookalike = issue_att(
        &A::std(
            &n.alice,
            n.alice.agent_id(),
            "https://atep.dev/claims/registry-endpoints",
            "re/lookalike",
        )
        .data(text_map(vec![
            ("url", url(ok_url)),
            ("kind", kind("registry")),
        ])),
    )?;
    push(
        out,
        "reject-lookalike-claim-uri",
        "The claim URI is https://atep.dev/claims/registry-endpoints (plural), not a core claim type: the reserved namespace is closed to the 14 core types. Expect claim_vocabulary.",
        lookalike,
        Err("claim_vocabulary"),
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// domain-binding (fixtures)

struct Fake {
    wk: HashMap<String, Result<WellKnownResponse, FetchError>>,
    txt: HashMap<String, Result<TxtAnswer, FetchError>>,
    asked_wk: RefCell<Vec<String>>,
    asked_txt: RefCell<Vec<String>>,
}

impl DomainFetcher for Fake {
    fn fetch_well_known(&self, domain: &str) -> Result<WellKnownResponse, FetchError> {
        self.asked_wk.borrow_mut().push(domain.to_string());
        self.wk
            .get(domain)
            .cloned()
            .unwrap_or(Err(FetchError::NotFound))
    }
    fn fetch_txt(&self, name: &str) -> Result<TxtAnswer, FetchError> {
        self.asked_txt.borrow_mut().push(name.to_string());
        self.txt
            .get(name)
            .cloned()
            .unwrap_or(Err(FetchError::NotFound))
    }
}

fn well_known_url_of(domain: &str) -> String {
    format!("https://{domain}/.well-known/atep.json")
}

fn parse_body(r: &J) -> R<Vec<u8>> {
    if let Some(b) = r.get("body") {
        return Ok(b
            .as_str()
            .ok_or_else(|| e("`body` is not text"))?
            .as_bytes()
            .to_vec());
    }
    let f = jget(r, "body_filler")?;
    let (prefix, fill, suffix) = (jstr(f, "prefix")?, jstr(f, "fill")?, jstr(f, "suffix")?);
    let total = jint(f, "total_bytes")? as usize;
    if fill.len() != 1 || prefix.len() + suffix.len() > total {
        return Err(e("bad body_filler"));
    }
    let mut b = prefix.as_bytes().to_vec();
    b.extend(std::iter::repeat_n(
        fill.as_bytes()[0],
        total - prefix.len() - suffix.len(),
    ));
    b.extend(suffix.as_bytes());
    Ok(b)
}

fn parse_fake(f: &J) -> R<Fake> {
    let mut fake = Fake {
        wk: HashMap::new(),
        txt: HashMap::new(),
        asked_wk: RefCell::new(Vec::new()),
        asked_txt: RefCell::new(Vec::new()),
    };
    for (domain, r) in jget(f, "well_known")?
        .as_object()
        .ok_or_else(|| e("well_known"))?
    {
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
                    .unwrap_or_else(|| well_known_url_of(domain)),
                content_type: r
                    .get("content_type")
                    .and_then(|c| c.as_str())
                    .map(str::to_string),
                body: parse_body(r)?,
            })
        };
        fake.wk.insert(domain.clone(), v);
    }
    for (name, r) in jget(f, "txt")?.as_object().ok_or_else(|| e("txt"))? {
        let v = if let Some(m) = r.get("unavailable") {
            Err(FetchError::Unavailable(
                m.as_str().unwrap_or("").to_string(),
            ))
        } else {
            let mut records = Vec::new();
            for rec in jget(r, "records")?.as_array().ok_or_else(|| e("records"))? {
                records.push(match rec {
                    J::String(s) => s.clone(),
                    J::Array(parts) => parts
                        .iter()
                        .map(|p| p.as_str().unwrap_or(""))
                        .collect::<String>(),
                    _ => return Err(e("record is neither text nor a list of text")),
                });
            }
            Ok(TxtAnswer {
                records,
                dnssec_validated: jget(r, "dnssec_validated")?.as_bool().unwrap_or(false),
            })
        };
        fake.txt.insert(name.clone(), v);
    }
    Ok(fake)
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

fn run_domain_binding(cbor: &[u8], inputs: &J) -> R<J> {
    let fixture = jget(inputs, "fixture")?;
    super::anchor::json_cbor_agree(cbor, fixture)?;
    let fake = parse_fake(fixture)?;
    let domain = jstr(fixture, "domain")?;
    let agent = AgentId::parse(jstr(fixture, "agent_id")?)?;
    let o = jget(fixture, "options")?;
    let opts = BindingOptions {
        require_dnssec: jget(o, "require_dnssec")?.as_bool().unwrap_or(false),
        require_both: jget(o, "require_both")?.as_bool().unwrap_or(false),
    };
    let r = check_domain_binding_with(domain, &agent, &fake, opts);
    let (wk, txt) = (fake.asked_wk.borrow(), fake.asked_txt.borrow());
    Ok(json!({
        "well_known": source_label(&r.well_known, !wk.is_empty()),
        "dns": source_label(&r.dns, !txt.is_empty()),
        "outcome": match r.outcome {
            Outcome::Bound => "bound",
            Outcome::NotBound => "not-bound",
            Outcome::Indeterminate => "indeterminate",
        },
        "queried": { "well_known": *wk, "txt": *txt },
    }))
}

/// Builder of a fixture.
struct Fx {
    domain: String,
    agent: String,
    wk: Map<String, J>,
    txt: Map<String, J>,
    require_both: bool,
}

impl Fx {
    fn new(domain: &str, agent: &AgentId) -> Fx {
        Fx {
            domain: domain.to_string(),
            agent: agent.to_text(),
            wk: Map::new(),
            txt: Map::new(),
            require_both: false,
        }
    }
    /// A 200 `application/json` answer for the well-known document of `host`.
    fn doc(self, host: &str, body: &J) -> Fx {
        let text = serde_json::to_string(body).expect("json");
        self.wk_raw(host, 200, None, Some("application/json"), &text)
    }
    fn wk_raw(
        mut self,
        host: &str,
        status: u16,
        final_url: Option<&str>,
        content_type: Option<&str>,
        body: &str,
    ) -> Fx {
        let mut m = Map::new();
        m.insert("status".into(), status.into());
        m.insert(
            "final_url".into(),
            final_url
                .map(str::to_string)
                .unwrap_or_else(|| well_known_url_of(host))
                .into(),
        );
        m.insert(
            "content_type".into(),
            content_type.map(|c| J::String(c.into())).unwrap_or(J::Null),
        );
        m.insert("body".into(), body.into());
        self.wk.insert(host.into(), J::Object(m));
        self
    }
    fn wk_filler(mut self, host: &str, prefix: &str, suffix: &str, total: usize) -> Fx {
        let mut m = Map::new();
        m.insert("status".into(), 200.into());
        m.insert("final_url".into(), well_known_url_of(host).into());
        m.insert("content_type".into(), "application/json".into());
        m.insert(
            "body_filler".into(),
            json!({ "prefix": prefix, "fill": "a", "suffix": suffix, "total_bytes": total }),
        );
        self.wk.insert(host.into(), J::Object(m));
        self
    }
    fn wk_unavailable(mut self, host: &str, why: &str) -> Fx {
        self.wk.insert(host.into(), json!({ "unavailable": why }));
        self
    }
    fn txt(mut self, name: &str, records: Vec<J>, dnssec: bool) -> Fx {
        self.txt.insert(
            name.into(),
            json!({ "records": records, "dnssec_validated": dnssec }),
        );
        self
    }
    fn txt_unavailable(mut self, name: &str, why: &str) -> Fx {
        self.txt.insert(name.into(), json!({ "unavailable": why }));
        self
    }
    fn both(mut self) -> Fx {
        self.require_both = true;
        self
    }
    fn build(self) -> J {
        json!({
            "domain": self.domain,
            "agent_id": self.agent,
            "options": { "require_both": self.require_both, "require_dnssec": false },
            "well_known": self.wk,
            "txt": self.txt,
        })
    }
}

fn doc_of(agents: &[String]) -> J {
    json!({ "version": 1, "agents": agents })
}

type Want = (&'static str, &'static str, &'static str);

fn domain_binding_vectors(out: &mut Vec<Vector>, n: &Net) -> R<()> {
    let s = n.alice.agent_id();
    let t = n.bob.agent_id();
    let (st, tt) = (s.to_text(), t.to_text());
    let s_did = st.replacen("atep:", "did:atep:", 1);
    let txt_name = format!("_atep.{D}");
    let rec = |ids: &[&str]| -> J {
        let mut r = "v=atep1".to_string();
        for i in ids {
            r.push_str(" id=");
            r.push_str(i);
        }
        J::String(r)
    };
    let mut case = |name: &str, desc: &str, fx: Fx, want: Want| -> R<()> {
        let fixture = fx.build();
        let cbor = json_to_cbor(&fixture)?.encode();
        let inputs = json!({ "check": "domain-binding", "fixture": fixture });
        let expected = run_domain_binding(&cbor, &inputs)?;
        let got = (
            expected["well_known"].as_str().unwrap_or(""),
            expected["dns"].as_str().unwrap_or(""),
            expected["outcome"].as_str().unwrap_or(""),
        );
        if got != want {
            return Err(e(format!(
                "generator bug: domain-binding/{name}: wanted {want:?}, got {expected}"
            )));
        }
        out.push(Vector {
            category: "domain-binding",
            name: name.to_string(),
            description: desc.to_string(),
            cbor,
            inputs,
            expected,
        });
        Ok(())
    };
    let new = || Fx::new(D, &s);
    let doc_s = doc_of(std::slice::from_ref(&st));
    let doc_t = doc_of(std::slice::from_ref(&tt));

    // The well-known document alone.
    case(
        "wk-lists-the-agent",
        "Only the well-known document exists (the TXT name has no data) and it lists the Agent ID: the source is listed, the DNS source absent, the result bound. The checker reads exactly https://example.com/.well-known/atep.json and `_atep.example.com`.",
        new().doc(D, &doc_s),
        ("listed", "absent", "bound"),
    )?;
    case(
        "wk-lists-another-agent",
        "The document is valid and lists another Agent ID only: not listed, not bound.",
        new().doc(D, &doc_t),
        ("not-listed", "absent", "not-bound"),
    )?;
    case(
        "wk-lists-the-agent-in-did-form",
        "The document lists the Agent ID as `did:atep:...`: an exact alias of the `atep:` form.",
        new().doc(D, &doc_of(std::slice::from_ref(&s_did))),
        ("listed", "absent", "bound"),
    )?;
    case(
        "wk-junk-entries-are-ignored",
        "`agents` holds `nope`, the integer 7 and the Agent ID: an entry that is not an Agent ID is ignored, the others count.",
        new().doc(D, &json!({ "version": 1, "agents": ["nope", 7, st.clone()] })),
        ("listed", "absent", "bound"),
    )?;
    case(
        "wk-only-junk-entries",
        "`agents` holds only entries that are not Agent IDs: a valid document that names nobody.",
        new().doc(
            D,
            &json!({ "version": 1, "agents": ["nope", 7, "atep:short"] }),
        ),
        ("not-listed", "absent", "not-bound"),
    )?;
    case(
        "wk-unknown-members-are-ignored",
        "Members that are not listed (`srl-url`, `updated`, `future-member`) are ignored; the document still lists the Agent ID.",
        new().doc(
            D,
            &json!({ "version": 1, "domain": D, "agents": [st.clone()],
                     "srl-url": "https://example.com/.well-known/atep-revocations.cbor",
                     "updated": 1_790_000_000, "future-member": { "x": 1 } }),
        ),
        ("listed", "absent", "bound"),
    )?;
    let agents_1024: Vec<String> = (0..1023u32)
        .map(|i| AgentId(label_hash(&format!("domain/agent/{i}"))).to_text())
        .chain(std::iter::once(st.clone()))
        .collect();
    case(
        "wk-1024-entries-agent-last",
        "`agents` has exactly 1024 entries and the Agent ID is the last: the limit is on the number of entries and 1024 are all read.",
        new().doc(D, &doc_of(&agents_1024)),
        ("listed", "absent", "bound"),
    )?;
    let pad_prefix = format!("{{\"version\":1,\"agents\":[\"{st}\"],\"pad\":\"");
    case(
        "wk-document-65536-bytes",
        "A document of exactly 65536 bytes (the maximum) that lists the Agent ID: accepted. The body is built from `body_filler`: prefix, then the fill character repeated so that the whole is `total_bytes` bytes, then suffix.",
        new().wk_filler(D, &pad_prefix, "\"}", MAX_DOC_BYTES),
        ("listed", "absent", "bound"),
    )?;
    case(
        "wk-document-65537-bytes",
        "The same document one byte longer: over the limit, so the source is invalid and the Agent ID is not bound although the (unread) body lists it.",
        new().wk_filler(D, &pad_prefix, "\"}", MAX_DOC_BYTES + 1),
        ("invalid", "absent", "not-bound"),
    )?;
    // Document format rules.
    let bad_docs: Vec<(&str, &str, J)> = vec![
        (
            "wk-version-2-is-not-read",
            "`version` is 2: a document of another version is not read.",
            json!({ "version": 2, "agents": [st.clone()] }),
        ),
        (
            "wk-version-missing",
            "`version` is absent.",
            json!({ "agents": [st.clone()] }),
        ),
        (
            "wk-version-as-text",
            "`version` is the text `1`, not the integer 1.",
            json!({ "version": "1", "agents": [st.clone()] }),
        ),
        (
            "wk-agents-missing",
            "`agents` is absent.",
            json!({ "version": 1 }),
        ),
        (
            "wk-agents-not-an-array",
            "`agents` is a text string.",
            json!({ "version": 1, "agents": st.clone() }),
        ),
        (
            "wk-domain-member-names-another-host",
            "`domain` is `other.example`: a document copied from another host does not bind this name.",
            json!({ "version": 1, "domain": "other.example", "agents": [st.clone()] }),
        ),
        (
            "wk-domain-member-names-a-subdomain",
            "`domain` is `www.example.com` in the document fetched for `example.com`: the member must equal the name it was fetched for, so the document is invalid.",
            json!({ "version": 1, "domain": "www.example.com", "agents": [st.clone()] }),
        ),
        (
            "wk-domain-member-differs-in-case",
            "`domain` is `Example.com`: the name must be equal as written (canonical names are lowercase).",
            json!({ "version": 1, "domain": "Example.com", "agents": [st.clone()] }),
        ),
        (
            "wk-body-is-an-array",
            "The body is a JSON array, not an object.",
            json!([{ "version": 1, "agents": [st.clone()] }]),
        ),
    ];
    for (name, desc, body) in bad_docs {
        case(
            name,
            desc,
            new().doc(D, &body),
            ("invalid", "absent", "not-bound"),
        )?;
    }
    case(
        "wk-body-is-not-json",
        "The body is not JSON.",
        new().wk_raw(D, 200, None, Some("application/json"), "agents: nobody"),
        ("invalid", "absent", "not-bound"),
    )?;
    case(
        "wk-domain-member-matches",
        "`domain` equals the name the document was fetched for.",
        new().doc(
            D,
            &json!({ "version": 1, "domain": D, "agents": [st.clone()] }),
        ),
        ("listed", "absent", "bound"),
    )?;
    // Transport rules.
    let ok_body = serde_json::to_string(&doc_s).expect("json");
    for (name, status, want, desc) in [
        ("wk-status-404", 404u16, ("absent", "absent", "not-bound"), "HTTP 404: the document does not exist, which is silent, not contradictory."),
        ("wk-status-410", 410, ("absent", "absent", "not-bound"), "HTTP 410: the document does not exist."),
        ("wk-status-429", 429, ("unavailable", "absent", "indeterminate"), "HTTP 429: the document could not be read; with nothing else listing the Agent ID the result is indeterminate."),
        ("wk-status-500", 500, ("unavailable", "absent", "indeterminate"), "HTTP 500: could not be read."),
        ("wk-status-503", 503, ("unavailable", "absent", "indeterminate"), "HTTP 503: could not be read."),
        ("wk-status-301-not-followed", 301, ("invalid", "absent", "not-bound"), "HTTP 301 reaching the checker (the fetcher follows the redirects it may follow): any other status makes the document invalid."),
        ("wk-status-403", 403, ("invalid", "absent", "not-bound"), "HTTP 403: any other status makes the document invalid."),
        ("wk-status-204", 204, ("invalid", "absent", "not-bound"), "HTTP 204 with the right body: only 200 is read."),
    ] {
        case(
            name,
            desc,
            new().wk_raw(D, status, None, Some("application/json"), &ok_body),
            want,
        )?;
    }
    for (name, ct, want, desc) in [
        (
            "wk-content-type-with-charset",
            Some("application/json; charset=utf-8"),
            ("listed", "absent", "bound"),
            "`application/json; charset=utf-8`: parameters are allowed.",
        ),
        (
            "wk-content-type-text-plain",
            Some("text/plain"),
            ("invalid", "absent", "not-bound"),
            "`text/plain`: the content type must be application/json.",
        ),
        (
            "wk-content-type-text-html",
            Some("text/html"),
            ("invalid", "absent", "not-bound"),
            "`text/html`.",
        ),
        (
            "wk-content-type-ld-json",
            Some("application/ld+json"),
            ("invalid", "absent", "not-bound"),
            "`application/ld+json` is not application/json.",
        ),
        (
            "wk-content-type-missing",
            None,
            ("invalid", "absent", "not-bound"),
            "No content type.",
        ),
    ] {
        case(name, desc, new().wk_raw(D, 200, None, ct, &ok_body), want)?;
    }
    for (name, final_url, want, desc) in [
        ("wk-redirect-same-host-other-path", "https://example.com/other/atep.json", ("listed", "absent", "bound"), "The fetcher followed a redirect that stayed on https and on the host: the document is read."),
        ("wk-redirect-to-another-host", "https://evil.example.net/.well-known/atep.json", ("invalid", "absent", "not-bound"), "The document came from another host."),
        ("wk-redirect-to-a-subdomain", "https://www.example.com/.well-known/atep.json", ("invalid", "absent", "not-bound"), "The document came from `www.example.com`, not from the host `example.com`."),
        ("wk-redirect-to-http", "http://example.com/.well-known/atep.json", ("invalid", "absent", "not-bound"), "The document came over plain http."),
        ("wk-redirect-to-another-port", "https://example.com:8443/.well-known/atep.json", ("invalid", "absent", "not-bound"), "The document came from a non default port."),
        ("wk-redirect-to-a-host-that-starts-with-the-name", "https://example.com.evil.example/.well-known/atep.json", ("invalid", "absent", "not-bound"), "The document came from `example.com.evil.example`: a longer host name that begins with the domain."),
    ] {
        case(
            name,
            desc,
            new().wk_raw(D, 200, Some(final_url), Some("application/json"), &ok_body),
            want,
        )?;
    }
    case(
        "wk-unavailable",
        "The fetch failed (timeout, TLS failure): unavailable, and with nothing else listing the Agent ID the result is indeterminate, never bound and never plain not bound.",
        new().wk_unavailable(D, "timeout"),
        ("unavailable", "absent", "indeterminate"),
    )?;

    // DNS TXT records alone.
    case(
        "txt-lists-the-agent",
        "Only the TXT record exists and it lists the Agent ID.",
        new().txt(&txt_name, vec![rec(&[&st])], true),
        ("absent", "listed", "bound"),
    )?;
    case(
        "txt-lists-the-agent-in-did-form",
        "`id=did:atep:...` is an alias of the `atep:` form.",
        new().txt(&txt_name, vec![rec(&[&s_did])], true),
        ("absent", "listed", "bound"),
    )?;
    case(
        "txt-lists-another-agent",
        "A valid record that names another Agent ID only.",
        new().txt(&txt_name, vec![rec(&[&tt])], true),
        ("absent", "not-listed", "not-bound"),
    )?;
    case(
        "txt-union-of-records-and-terms",
        "Three records: one with two `id=` terms that do not include the Agent ID, an unrelated one, and one that lists it. The authorized set is the union of the `id=` terms of all `v=atep1` records.",
        new().txt(
            &txt_name,
            vec![rec(&[&tt, &tt]), "v=spf1 -all".into(), rec(&[&st])],
            true,
        ),
        ("absent", "listed", "bound"),
    )?;
    case(
        "txt-only-unrelated-records",
        "The name carries other uses only (an SPF record and a site verification record): no `v=atep1` record, so no `_atep` TXT data, which is silent.",
        new().txt(
            &txt_name,
            vec!["v=spf1 -all".into(), "google-site-verification=abc".into()],
            true,
        ),
        ("absent", "absent", "not-bound"),
    )?;
    case(
        "txt-empty-answer",
        "An answer with no records.",
        new().txt(&txt_name, vec![], true),
        ("absent", "absent", "not-bound"),
    )?;
    case(
        "txt-version-term-only",
        "`v=atep1` with no `id=` term authorizes nobody: a valid record that does not list the Agent ID.",
        new().txt(&txt_name, vec!["v=atep1".into()], true),
        ("absent", "not-listed", "not-bound"),
    )?;
    case(
        "txt-unknown-terms-are-ignored",
        "Terms the reader does not understand (`foo=bar`, `x-ext=1`, an `srl=` term) are ignored; the `id=` term counts.",
        new().txt(
            &txt_name,
            vec![format!(
                "v=atep1 foo=bar x-ext=1 id={st} srl=https://example.com/.well-known/atep-revocations.cbor"
            )
            .into()],
            true,
        ),
        ("absent", "listed", "bound"),
    )?;
    case(
        "txt-several-spaces-between-terms",
        "Terms are separated by one or more spaces.",
        new().txt(
            &txt_name,
            vec![format!("v=atep1   id={tt}    id={st}").into()],
            true,
        ),
        ("absent", "listed", "bound"),
    )?;
    case(
        "txt-malformed-id-term-is-ignored",
        "`id=atep:notanid` is not an Agent ID: the term is ignored and the next one counts.",
        new().txt(
            &txt_name,
            vec![format!("v=atep1 id=atep:notanid id={st}").into()],
            true,
        ),
        ("absent", "listed", "bound"),
    )?;
    case(
        "txt-uppercase-agent-id-is-not-an-agent-id",
        "The Agent ID is written in uppercase: only the canonical lowercase text is an Agent ID, so the term names nobody.",
        new().txt(
            &txt_name,
            vec![format!("v=atep1 id={}", st.to_uppercase()).into()],
            true,
        ),
        ("absent", "not-listed", "not-bound"),
    )?;
    case(
        "txt-leading-space-is-not-the-version-term",
        "The record starts with a space: it does not begin with the term `v=atep1`, so it is ignored.",
        new().txt(&txt_name, vec![format!(" v=atep1 id={st}").into()], true),
        ("absent", "absent", "not-bound"),
    )?;
    case(
        "txt-version-term-must-be-exact",
        "The first term is `v=atep10`: not the term `v=atep1`, so the record is ignored.",
        new().txt(&txt_name, vec![format!("v=atep10 id={st}").into()], true),
        ("absent", "absent", "not-bound"),
    )?;
    case(
        "txt-version-term-not-first",
        "`v=atep1` is the second term: the record does not begin with it, so it is ignored.",
        new().txt(&txt_name, vec![format!("id={st} v=atep1").into()], true),
        ("absent", "absent", "not-bound"),
    )?;
    let (a, b) = st.split_at(30);
    case(
        "txt-character-strings-are-concatenated",
        "One record given as two character-strings that split the Agent ID in the middle: the text of a record is its character-strings concatenated, with nothing between them.",
        new().txt(
            &txt_name,
            vec![json!([format!("v=atep1 id={a}"), b.to_string()])],
            true,
        ),
        ("absent", "listed", "bound"),
    )?;
    let filler = |len: usize| -> J {
        let head = format!("v=atep1 id={st} x=");
        J::String(format!("{head}{}", "a".repeat(len - head.len())))
    };
    case(
        "txt-record-of-1024-octets",
        "A record of exactly 1024 octets (the maximum) that lists the Agent ID: accepted.",
        new().txt(&txt_name, vec![filler(MAX_TXT_BYTES)], true),
        ("absent", "listed", "bound"),
    )?;
    case(
        "txt-record-of-1025-octets-is-ignored",
        "The same record one octet longer: the reader ignores a record over the limit, so it contributes nothing and the name has no usable `_atep` data (spec-issues 51 records that the text does not say whether such a record is ignored or invalid).",
        new().txt(&txt_name, vec![filler(MAX_TXT_BYTES + 1)], true),
        ("absent", "absent", "not-bound"),
    )?;
    case(
        "txt-non-ascii-record-is-ignored",
        "A record that lists the Agent ID but contains a non ASCII character in an unknown term: records are US-ASCII, so it is ignored (spec-issues 51).",
        new().txt(&txt_name, vec![format!("v=atep1 id={st} note=caf\u{e9}").into()], true),
        ("absent", "absent", "not-bound"),
    )?;
    let mut sixteen: Vec<J> = (0..MAX_TXT_RECORDS - 1)
        .map(|i| J::String(format!("unrelated-record-{i}")))
        .collect();
    sixteen.push(rec(&[&st]));
    case(
        "txt-sixteenth-record-is-read",
        "Fifteen unrelated records and, sixteenth, the record that lists the Agent ID: a reader reads at least the first 16 records.",
        new().txt(&txt_name, sixteen, true),
        ("absent", "listed", "bound"),
    )?;
    case(
        "txt-not-dnssec-validated-still-counts",
        "The answer was not DNSSEC validated: by default it still counts (an issuer MAY refuse unvalidated answers; the options of this vector do not).",
        new().txt(&txt_name, vec![rec(&[&st])], false),
        ("absent", "listed", "bound"),
    )?;
    case(
        "txt-unavailable",
        "The DNS lookup failed (SERVFAIL, DNSSEC validation failure, timeout): unavailable, with nothing listing the Agent ID the result is indeterminate.",
        new().txt_unavailable(&txt_name, "SERVFAIL"),
        ("absent", "unavailable", "indeterminate"),
    )?;

    // Both sources.
    case(
        "both-list-the-agent",
        "Both sources list the Agent ID.",
        new().doc(D, &doc_s).txt(&txt_name, vec![rec(&[&st])], true),
        ("listed", "listed", "bound"),
    )?;
    case(
        "stale-txt-contradicted-by-the-document",
        "The document no longer lists the Agent ID (the owner withdrew it) but a stale TXT record still does: a valid source that does not list the Agent ID contradicts the one that does, so the Agent ID is not bound.",
        new().doc(D, &doc_t).txt(&txt_name, vec![rec(&[&st])], true),
        ("not-listed", "listed", "not-bound"),
    )?;
    case(
        "stale-document-contradicted-by-txt",
        "The TXT record was cleared (a `v=atep1` record with no `id=`) but the document still lists the Agent ID: contradiction, not bound.",
        new().doc(D, &doc_s).txt(&txt_name, vec!["v=atep1".into()], true),
        ("listed", "not-listed", "not-bound"),
    )?;
    case(
        "document-lists-txt-names-another-agent",
        "The document lists the Agent ID and the TXT record names only another one: contradiction, not bound.",
        new().doc(D, &doc_s).txt(&txt_name, vec![rec(&[&tt])], true),
        ("listed", "not-listed", "not-bound"),
    )?;
    case(
        "either-source-is-enough",
        "The document lists the Agent ID and the TXT name has only unrelated records (no `_atep` data): a source that does not exist is silent, so one listing is enough.",
        new().doc(D, &doc_s).txt(&txt_name, vec!["v=spf1 -all".into()], true),
        ("listed", "absent", "bound"),
    )?;
    case(
        "invalid-source-does-not-contradict",
        "The document is invalid (version 2) and the TXT record lists the Agent ID: an invalid source is not a valid source that omits the Agent ID, so it does not contradict; bound.",
        new()
            .doc(D, &json!({ "version": 2, "agents": [tt.clone()] }))
            .txt(&txt_name, vec![rec(&[&st])], true),
        ("invalid", "listed", "bound"),
    )?;
    case(
        "unavailable-source-does-not-block-a-listing",
        "The document lists the Agent ID and the DNS lookup failed: a listed source and no valid source that omits it, so bound.",
        new().doc(D, &doc_s).txt_unavailable(&txt_name, "SERVFAIL"),
        ("listed", "unavailable", "bound"),
    )?;
    case(
        "unavailable-source-and-a-valid-source-that-omits",
        "The DNS lookup failed and the document is valid but does not list the Agent ID: indeterminate (do not issue now, retry), not a plain not bound.",
        new()
            .doc(D, &doc_t)
            .txt_unavailable(&txt_name, "SERVFAIL"),
        ("not-listed", "unavailable", "indeterminate"),
    )?;
    case(
        "neither-lists-the-agent",
        "Both sources are valid and name only another Agent ID.",
        new().doc(D, &doc_t).txt(&txt_name, vec![rec(&[&tt])], true),
        ("not-listed", "not-listed", "not-bound"),
    )?;
    case(
        "unavailable-and-absent",
        "One source could not be read and the other does not exist: no source lists the Agent ID and one is unavailable, so indeterminate.",
        new().wk_unavailable(D, "TLS handshake failed"),
        ("unavailable", "absent", "indeterminate"),
    )?;
    // The option "require both".
    case(
        "require-both-both-list",
        "Option `require_both` (an issuer MAY require both sources to list the Agent ID): both list it, bound.",
        new().both().doc(D, &doc_s).txt(&txt_name, vec![rec(&[&st])], true),
        ("listed", "listed", "bound"),
    )?;
    case(
        "require-both-only-the-document-lists",
        "`require_both`; the document lists the Agent ID and the TXT name has no data: not bound (the one listing that is enough without the option is not enough with it).",
        new().both().doc(D, &doc_s),
        ("listed", "absent", "not-bound"),
    )?;
    case(
        "require-both-the-other-source-unavailable",
        "`require_both`; the document lists the Agent ID and the DNS lookup failed: not decided, indeterminate.",
        new().both().doc(D, &doc_s).txt_unavailable(&txt_name, "SERVFAIL"),
        ("listed", "unavailable", "indeterminate"),
    )?;
    case(
        "require-both-the-sources-disagree",
        "`require_both`; the sources contradict each other: not bound.",
        new()
            .both()
            .doc(D, &doc_s)
            .txt(&txt_name, vec![rec(&[&tt])], true),
        ("listed", "not-listed", "not-bound"),
    )?;

    // Names: no inheritance, no search up the tree, canonical names only.
    let sub = "a.example.com";
    let sub_txt = format!("_atep.{sub}");
    case(
        "subdomain-gets-no-record-from-its-parent",
        "The domain asked about is `a.example.com`; only `example.com` publishes records, and they list the Agent ID. A record at example.com says nothing about a.example.com and the checker does not search up the tree: it reads exactly the well-known document of a.example.com and `_atep.a.example.com`, finds nothing, and does not bind.",
        Fx::new(sub, &s).doc(D, &doc_s).txt(&txt_name, vec![rec(&[&st])], true),
        ("absent", "absent", "not-bound"),
    )?;
    case(
        "parent-gets-no-record-from-a-subdomain",
        "The domain asked about is `example.com`; only `a.example.com` publishes records. A record at a.example.com says nothing about example.com.",
        new().doc(sub, &doc_s).txt(&sub_txt, vec![rec(&[&st])], true),
        ("absent", "absent", "not-bound"),
    )?;
    case(
        "subdomain-with-its-own-records",
        "`a.example.com` publishes its own records: bound by them, reading its own names.",
        Fx::new(sub, &s)
            .doc(sub, &doc_s)
            .txt(&sub_txt, vec![rec(&[&st])], true),
        ("listed", "listed", "bound"),
    )?;
    case(
        "document-of-a-subdomain-names-the-parent",
        "The document fetched for `a.example.com` has `domain` `example.com`: it does not equal the name it was fetched for, so it is invalid.",
        Fx::new(sub, &s).doc(
            sub,
            &json!({ "version": 1, "domain": D, "agents": [st.clone()] }),
        ),
        ("invalid", "absent", "not-bound"),
    )?;
    for (name, dom, desc) in [
        ("domain-uppercase-is-not-read", "Example.com", "The domain is `Example.com`: not a canonical lowercase DNS name, so nothing is read (the sources are `not-read`, no name is queried) and the result is not bound even though records for the lowercase name list the Agent ID."),
        ("domain-trailing-dot-is-not-read", "example.com.", "The domain has a trailing dot: not canonical, nothing is read."),
        ("domain-with-underscore-is-not-read", "_atep.example.com", "The domain begins with an underscore label: not a canonical name, nothing is read."),
        ("domain-empty-label-is-not-read", "a..example.com", "The domain has an empty label: nothing is read."),
    ] {
        case(
            name,
            desc,
            Fx::new(dom, &s).doc(D, &doc_s).txt(&txt_name, vec![rec(&[&st])], true),
            ("not-read", "not-read", "not-bound"),
        )?;
    }
    Ok(())
}
