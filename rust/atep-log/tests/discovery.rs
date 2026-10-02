//! Discoverability (spec sections 4 and 9): claim-type resolution, the OpenAPI
//! description and its agreement with the server, and the `registry-endpoint`
//! claim.

use std::collections::BTreeSet;
use std::sync::Mutex;

use atep_core::attestation::{self, claims, AttestationParams};
use atep_core::cbor::Value;
use atep_core::envelope::SignMode;
use atep_core::keys::sha256;
use atep_log::claimdefs;
use atep_log::http::{handle, prefers_html, Request, Response};
use atep_log::openapi;
use atep_log::routes::{resolve, sample_path, ROUTES};
use atep_log::testkit::*;
use atep_log::{Log, LogConfig, SubmitErr};
use serde_json::{json, Value as J};

const NOW: i64 = 1_800_000_000;
const NS: &str = "https://atep.dev/claims/";

fn open(dir: &TempDir) -> Log {
    Log::open_with(dir.path(), Some(ident(1)), LogConfig::default(), NOW).unwrap()
}

fn get(m: &Mutex<Log>, target: &str, accept: Option<&str>) -> Response {
    let mut req = Request::new("GET", target, vec![]);
    if let Some(a) = accept {
        req = req.with_header("accept", a);
    }
    handle(m, &req, NOW)
}

/// The 14 core claim URIs as `atep-core` knows them.
fn core_uris() -> BTreeSet<String> {
    claims::CORE
        .iter()
        .chain(claims::robotics::ALL.iter())
        .map(|s| s.to_string())
        .collect()
}

#[test]
fn every_core_claim_has_a_definition_and_a_schema() {
    let core = core_uris();
    assert_eq!(core.len(), 14);
    for uri in &core {
        let d = claimdefs::find_uri(uri).unwrap_or_else(|| panic!("no definition for {uri}"));
        assert!(d.status == "core" && d.profile != "draft-04", "{uri}");
        assert!(d.summary.len() > 20, "{uri} summary");
        assert!(!d.description.is_empty(), "{uri} description");
        assert!(d.data_schema.contains("-data = "), "{uri} schema");
        assert!(!d.spec.is_empty());
        assert!(!d.issued_by.is_empty() && !d.subject.is_empty());
        // Evidence rule agrees with atep-core.
        assert_eq!(
            d.evidence == "required",
            claims::requires_evidence(uri),
            "{uri} evidence"
        );
    }
    // The data file holds the 14 core types, nothing else.
    let defined: BTreeSet<String> = claimdefs::all().iter().map(|d| d.uri.clone()).collect();
    assert_eq!(defined, core);
    assert_eq!(
        claimdefs::all().len(),
        defined.len(),
        "duplicate definitions"
    );
    // Every claim `atep-core` lists is under the namespace and its name matches the path.
    for d in claimdefs::all() {
        assert_eq!(d.uri, format!("{NS}{}", d.name));
        // CDDL sanity: balanced brackets, a rule named after the claim.
        let rule = format!("{}-data = ", d.name.rsplit('/').next().unwrap());
        assert!(d.data_schema.starts_with(&rule), "{} rule name", d.uri);
        for (o, c) in [('{', '}'), ('[', ']'), ('(', ')')] {
            assert_eq!(
                d.data_schema.matches(o).count(),
                d.data_schema.matches(c).count(),
                "{} brackets {o}{c}",
                d.uri
            );
        }
        assert!(d.example_data.is_object());
    }
}

#[test]
fn layouts_agree_with_the_spec_cddl() {
    // Rules that spec/schemas/atep.cddl also defines must be identical (modulo comments).
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/schemas/atep.cddl");
    let Ok(cddl) = std::fs::read_to_string(&path) else {
        eprintln!("skipping: {} not found", path.display());
        return;
    };
    let strip = |l: &str| l.split(';').next().unwrap().trim().to_string();
    let spec_rules: Vec<String> = cddl.lines().map(strip).collect();
    let mut checked = 0;
    for d in claimdefs::all() {
        let first = strip(d.data_schema.lines().next().unwrap());
        let head = first.split(" = ").next().unwrap();
        if let Some(spec) = spec_rules
            .iter()
            .find(|l| l.starts_with(&format!("{head} = ")))
        {
            assert_eq!(&first, spec, "{} differs from atep.cddl", d.uri);
            checked += 1;
        }
    }
    assert!(checked >= 4, "only {checked} rules compared");
    // The core-claim choice in atep.cddl lists the 14 URIs.
    for uri in core_uris() {
        assert!(
            cddl.contains(&format!("\"{uri}\"")),
            "{uri} missing in atep.cddl"
        );
    }
}

#[test]
fn resolver_serves_every_claim_in_every_form() {
    let dir = TempDir::new("resolve");
    let m = Mutex::new(open(&dir));
    for d in claimdefs::all() {
        let enc = claimdefs::pct(&d.uri);
        let r = get(&m, &format!("/v1/claims/{enc}"), None);
        assert_eq!(r.status, 200, "{}", d.uri);
        assert!(r.content_type.starts_with("application/json"));
        let j = r.json_body().unwrap();
        assert_eq!(j["claim"], d.uri.as_str());
        assert_eq!(j["data-schema"], d.data_schema.as_str());
        assert_eq!(j["data-schema-format"], "cddl");
        assert!(j["definition"].as_str().unwrap().len() > 10);
        assert_eq!(j["core"], d.status == "core");
        // Plain (unencoded) URI and short name give the same document.
        let plain = get(&m, &format!("/v1/claims/{}", d.uri), None)
            .json_body()
            .unwrap();
        assert_eq!(plain, j);
        let short = get(&m, &format!("/v1/claims/{}", d.name), None)
            .json_body()
            .unwrap();
        assert_eq!(short, j);
        // Path style: https://atep.dev/claims/<name>, with .html and Accept negotiation.
        let p = get(&m, &format!("/claims/{}", d.name), None);
        assert_eq!(p.status, 200);
        assert_eq!(p.json_body().unwrap(), j);
        let h = get(&m, &format!("/claims/{}.html", d.name), None);
        assert_eq!(h.status, 200);
        assert!(h.content_type.starts_with("text/html"));
        let page = String::from_utf8(h.body).unwrap();
        assert!(page.contains(&d.uri) && page.contains("CDDL") && page.contains("<pre>"));
        let nego = get(
            &m,
            &format!("/claims/{}", d.name),
            Some("text/html,application/xhtml+xml,*/*;q=0.8"),
        );
        assert!(nego.content_type.starts_with("text/html"));
        let jsuffix = get(&m, &format!("/claims/{}.json", d.name), Some("text/html"));
        assert!(jsuffix.content_type.starts_with("application/json"));
        let api_html = get(&m, &format!("/v1/claims/{enc}"), Some("text/html"));
        assert!(api_html.content_type.starts_with("text/html"));
    }
    // The index lists every definition, as JSON and HTML.
    let idx = get(&m, "/claims", None).json_body().unwrap();
    assert_eq!(
        idx["claims"].as_array().unwrap().len(),
        claimdefs::all().len()
    );
    assert_eq!(idx["namespace"], NS);
    let idx_html = get(&m, "/claims/", Some("text/html"));
    assert!(String::from_utf8(idx_html.body)
        .unwrap()
        .contains("robotics/peer-motion"));
    // The directory carries the same definition and schema.
    let dir_rows = get(&m, "/v1/claims", None).json_body().unwrap();
    let row = dir_rows["claim-types"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["claim"] == claims::AUDITED)
        .unwrap();
    assert_eq!(
        row["data-schema"],
        claimdefs::find_uri(claims::AUDITED)
            .unwrap()
            .data_schema
            .as_str()
    );
    assert_eq!(row["status"], "core");
}

#[test]
fn unknown_claims_are_404() {
    let dir = TempDir::new("unknown");
    let m = Mutex::new(open(&dir));
    for path in [
        "/v1/claims/https%3A%2F%2Fatep.dev%2Fclaims%2Fnot-a-claim",
        "/v1/claims/https%3A%2F%2Fexample.com%2Fclaims%2Faudited",
        "/v1/claims/nonsense",
        "/v1/claims/https%3A%2F%2Fatep.dev%2Flog%2Fpolicy",
        "/claims/not-a-claim",
        "/claims/robotics/operator",
        "/claims/robotics/audited",
        "/claims/audited/extra",
        "/claims/not-a-claim.html",
        "/claims/robotics/nope.html",
        "/claims/.html",
    ] {
        let r = get(&m, path, None);
        assert_eq!(r.status, 404, "{path}");
        let j = r.json_body().unwrap();
        assert!(
            j["error"] == "claim_unknown" || j["error"] == "not_found",
            "{path}: {j}"
        );
    }
    // A claim that only exists in a log (another namespace) is in the directory but does not resolve.
    assert_eq!(
        get(
            &m,
            "/v1/claims/https%3A%2F%2Fexample.com%2Fclaims%2Fx",
            None
        )
        .status,
        404
    );
    // HEAD works like GET, other methods do not exist.
    let head = handle(&m, &Request::new("HEAD", "/claims/audited", vec![]), NOW);
    assert_eq!(head.status, 200);
    assert_eq!(
        handle(&m, &Request::new("POST", "/claims/audited", vec![]), NOW).status,
        404
    );
}

#[test]
fn accept_negotiation() {
    assert!(!prefers_html(None));
    assert!(!prefers_html(Some("*/*")));
    assert!(!prefers_html(Some("application/json")));
    assert!(prefers_html(Some("text/html")));
    assert!(prefers_html(Some(
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    )));
    assert!(!prefers_html(Some("text/html;q=0.5, application/json")));
    assert!(!prefers_html(Some("application/json, text/html")));
}

// ---------------------------------------------------------------------------
// OpenAPI

fn doc() -> J {
    openapi::document()
}

#[test]
fn openapi_is_served_and_matches_the_checked_in_copy() {
    let dir = TempDir::new("openapi");
    let m = Mutex::new(open(&dir));
    let r = get(&m, "/openapi.json", None);
    assert_eq!(r.status, 200);
    assert_eq!(r.json_body().unwrap(), doc());
    assert_eq!(doc()["openapi"], "3.1.0");
    let file = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/openapi.json");
    let text = openapi::document_text();
    if std::env::var("ATEP_UPDATE_OPENAPI").is_ok() {
        std::fs::write(&file, &text).unwrap();
    }
    let on_disk = std::fs::read_to_string(&file).expect("rust/docs/openapi.json exists");
    assert_eq!(
        on_disk, text,
        "rust/docs/openapi.json is out of date; run with ATEP_UPDATE_OPENAPI=1 to regenerate it"
    );
}

#[test]
fn every_route_is_documented_and_every_documented_path_is_a_route() {
    let d = doc();
    let mut documented: BTreeSet<(String, String)> = BTreeSet::new();
    for (path, item) in d["paths"].as_object().unwrap() {
        for (method, op) in item.as_object().unwrap() {
            assert!(
                ["get", "post", "put", "delete", "patch", "head", "options"]
                    .contains(&method.as_str()),
                "{method}"
            );
            assert!(
                op["operationId"].is_string() && op["responses"].is_object(),
                "{method} {path}"
            );
            documented.insert((method.to_ascii_uppercase(), path.clone()));
        }
    }
    let table: BTreeSet<(String, String)> = ROUTES
        .iter()
        .map(|r| (r.method.to_string(), r.path.to_string()))
        .collect();
    assert_eq!(documented, table);
    assert_eq!(documented.len(), 19);
    // Operation ids are unique.
    let ids: BTreeSet<&str> = d["paths"]
        .as_object()
        .unwrap()
        .values()
        .flat_map(|i| i.as_object().unwrap().values())
        .map(|op| op["operationId"].as_str().unwrap())
        .collect();
    assert_eq!(ids.len(), 19);
}

#[test]
fn the_server_implements_exactly_the_routes_of_the_table() {
    let dir = TempDir::new("routes");
    let m = Mutex::new(open(&dir));
    for route in ROUTES.iter() {
        let p = sample_path(route);
        // The path resolves to this very route ...
        let (id, _) = resolve(route.method, &p).unwrap_or_else(|| panic!("{} {p}", route.method));
        assert_eq!(id, route.id);
        // ... and the handler answers it as a route (not the "no such endpoint" 404).
        let mut req = Request::new(route.method, &p, b"{}".to_vec());
        if route.method == "POST" {
            req = req.with_header("content-type", "application/json");
        }
        let r = handle(&m, &req, NOW);
        let msg = r
            .json_body()
            .map(|j| j["detail"].to_string())
            .unwrap_or_default();
        assert!(
            !msg.contains("no such endpoint") && !msg.contains("unknown path"),
            "{} {p} is not routed: {msg}",
            route.method
        );
    }
    // Paths and methods outside the table are 404 or unrouted.
    for (method, p) in [
        ("GET", "/v1/nothing"),
        ("DELETE", "/v1/entries"),
        ("PUT", "/v1/submit"),
        ("GET", "/v1/submit"),
        ("POST", "/v1/policy"),
        ("GET", "/v2/entries"),
        ("GET", "/openapi.yaml"),
        ("POST", "/openapi.json"),
    ] {
        assert!(resolve(method, p).is_none(), "{method} {p}");
        assert_eq!(
            handle(&m, &Request::new(method, p, vec![]), NOW).status,
            404
        );
    }
    // The index lists the table.
    let idx = get(&m, "/", None).json_body().unwrap();
    assert_eq!(idx["endpoints"].as_array().unwrap().len(), ROUTES.len());
    assert_eq!(idx["openapi"], "/openapi.json");
}

/// Resolve a `$ref` of the document.
fn deref<'a>(d: &'a J, v: &'a J) -> &'a J {
    match v.get("$ref").and_then(|r| r.as_str()) {
        Some(r) => {
            let p = r.strip_prefix('#').unwrap();
            d.pointer(p).unwrap_or_else(|| panic!("dangling $ref {r}"))
        }
        None => v,
    }
}

/// A small JSON Schema checker for the subset the document uses: `type`
/// (string or list), `properties`, `required`, `items`, `enum`, `pattern`
/// for the three simple patterns, `oneOf`, `$ref`. Unknown object members
/// not listed in `properties` are errors, which keeps the document honest.
fn conforms(d: &J, schema: &J, v: &J, at: &str) -> Result<(), String> {
    let schema = deref(d, schema);
    if let Some(alts) = schema.get("oneOf").and_then(|a| a.as_array()) {
        let ok = alts.iter().any(|a| conforms(d, a, v, at).is_ok());
        return if ok {
            Ok(())
        } else {
            Err(format!("{at}: no oneOf alternative matches {v}"))
        };
    }
    if let Some(t) = schema.get("type") {
        let types: Vec<&str> = match t {
            J::String(s) => vec![s.as_str()],
            J::Array(a) => a.iter().map(|x| x.as_str().unwrap()).collect(),
            _ => panic!("bad type"),
        };
        let ok = types.iter().any(|t| match *t {
            "string" => v.is_string(),
            "integer" => v.is_i64() || v.is_u64(),
            "boolean" => v.is_boolean(),
            "null" => v.is_null(),
            "object" => v.is_object(),
            "array" => v.is_array(),
            other => panic!("type {other}"),
        });
        if !ok {
            return Err(format!("{at}: expected {types:?}, got {v}"));
        }
    }
    if let (Some(en), true) = (schema.get("enum").and_then(|e| e.as_array()), !v.is_null()) {
        if !en.contains(v) {
            return Err(format!("{at}: {v} not in {en:?}"));
        }
    }
    if let (Some(pat), Some(s)) = (schema.get("pattern").and_then(|p| p.as_str()), v.as_str()) {
        let ok = match pat {
            "^[0-9a-f]{64}$" => {
                s.len() == 64
                    && s.bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            }
            "^[0-9a-f]{32}$" => {
                s.len() == 32
                    && s.bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            }
            "^[A-Za-z0-9_-]*$" => s
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-'),
            "^(did:)?atep:[a-z2-7]{52}$" => {
                let r = s.strip_prefix("did:").unwrap_or(s);
                r.strip_prefix("atep:").is_some_and(|b| {
                    b.len() == 52
                        && b.bytes()
                            .all(|c| c.is_ascii_lowercase() || (b'2'..=b'7').contains(&c))
                })
            }
            other => panic!("pattern {other} not supported by the test"),
        };
        if !ok {
            return Err(format!("{at}: {s:?} does not match {pat}"));
        }
    }
    if let Some(obj) = v.as_object() {
        let props = schema.get("properties").and_then(|p| p.as_object());
        for req in schema
            .get("required")
            .and_then(|r| r.as_array())
            .into_iter()
            .flatten()
        {
            let k = req.as_str().unwrap();
            if !obj.contains_key(k) {
                return Err(format!("{at}: missing required member `{k}`"));
            }
        }
        if let Some(props) = props {
            for (k, val) in obj {
                let Some(ps) = props.get(k) else {
                    return Err(format!("{at}: member `{k}` is not in the schema"));
                };
                conforms(d, ps, val, &format!("{at}.{k}"))?;
            }
        }
    }
    if let (Some(items), Some(arr)) = (schema.get("items"), v.as_array()) {
        for (i, x) in arr.iter().enumerate() {
            conforms(d, items, x, &format!("{at}[{i}]"))?;
        }
    }
    Ok(())
}

/// Check a live response against the schema the document names for its status.
fn check_response(d: &J, route_path: &str, method: &str, resp: &Response) {
    let op = &d["paths"][route_path][method.to_ascii_lowercase()];
    let responses = &op["responses"];
    let entry = responses.get(resp.status.to_string()).unwrap_or_else(|| {
        panic!(
            "{method} {route_path}: status {} is not documented",
            resp.status
        )
    });
    let entry = deref(d, entry);
    let ct = resp.content_type.split(';').next().unwrap();
    let content = entry["content"].get(ct).unwrap_or_else(|| {
        panic!(
            "{method} {route_path}: {ct} is not documented for {}",
            resp.status
        )
    });
    if ct == "application/json" {
        let body: J = serde_json::from_slice(&resp.body).unwrap();
        conforms(
            d,
            &content["schema"],
            &body,
            &format!("{method} {route_path} {}", resp.status),
        )
        .unwrap_or_else(|e| panic!("{e}\n{body}"));
    }
}

/// A log with a bit of everything in it.
fn busy_log(dir: &TempDir) -> (Mutex<Log>, Vec<u8>) {
    let mut log = open(dir);
    let (root, ca, alice) = (ident(10), ident(11), ident(12));
    let subs = [
        delegate(
            &root,
            ca.agent_id(),
            &[
                claims::OPERATOR,
                claims::DOMAIN_CONTROL,
                claimdefs::REGISTRY_ENDPOINT,
            ],
            NOW - 100,
        ),
        attest(
            &ca,
            alice.agent_id(),
            claims::OPERATOR,
            text_map(&[("name", "Acme")]),
            NOW - 90,
            90,
        ),
        domain_control(&ca, ca.agent_id(), "ca.example.com", NOW - 80),
        attest(
            &ca,
            alice.agent_id(),
            "https://example.com/claims/x",
            text_map(&[("a", "b")]),
            NOW - 70,
            90,
        ),
        srl(&ca, 1, NOW - 60, vec![]),
        attest(
            &ca,
            alice.agent_id(),
            claimdefs::REGISTRY_ENDPOINT,
            text_map(&[
                ("url", "https://registry.example.com/v1"),
                ("kind", "registry"),
            ]),
            NOW - 50,
            90,
        ),
    ];
    let mut first = Vec::new();
    for s in &subs {
        let out = log.submit(s, NOW).unwrap_or_else(|e| match e {
            SubmitErr::Rejected(e) => panic!("{e}"),
            SubmitErr::Log(e) => panic!("{e}"),
        });
        if first.is_empty() {
            first = out.leaf.to_vec();
        }
    }
    (Mutex::new(log), first)
}

#[test]
fn live_responses_conform_to_the_documented_schemas() {
    let d = doc();
    let dir = TempDir::new("conform");
    let (m, leaf) = busy_log(&dir);
    let leaf_hex = hex::encode(&leaf);
    let alice = ident(12).agent_id().to_text();
    let cases: Vec<(&str, String)> = vec![
        ("GET", "/".into()),
        ("GET", "/v1/checkpoint".into()),
        ("GET", "/v1/checkpoints?from=0".into()),
        ("GET", format!("/v1/proof/inclusion?leaf-hash={leaf_hex}")),
        ("GET", "/v1/proof/inclusion?index=1".into()),
        ("GET", "/v1/proof/consistency?from=1&to=3".into()),
        ("GET", "/v1/entries?from=0&to=10".into()),
        ("GET", format!("/v1/lookup?subject={alice}")),
        ("GET", format!("/v1/lookup?subject={alice}&claim=operator")),
        ("GET", "/v1/issuers".into()),
        ("GET", "/v1/claims".into()),
        ("GET", "/v1/claims/audited".into()),
        ("GET", "/v1/policy".into()),
        ("GET", "/v1/gossip".into()),
        ("GET", "/claims".into()),
        ("GET", "/claims/audited".into()),
        ("GET", "/claims/robotics/fleet-member".into()),
        ("GET", "/openapi.json".into()),
        // Errors.
        ("GET", "/v1/lookup?subject=nope".into()),
        ("GET", "/v1/entries?from=x".into()),
        ("GET", "/v1/proof/inclusion".into()),
        ("GET", "/v1/proof/inclusion?index=999".into()),
        ("GET", "/v1/proof/consistency?from=3&to=1".into()),
        ("GET", "/claims/nope".into()),
    ];
    let path_of = |p: &str| -> String {
        let bare = p.split('?').next().unwrap();
        if bare.starts_with("/v1/claims/") {
            "/v1/claims/{claim}".into()
        } else if bare.starts_with("/claims/robotics/") {
            "/claims/robotics/{name}".into()
        } else if bare.starts_with("/claims/") {
            "/claims/{name}".into()
        } else {
            bare.to_string()
        }
    };
    for (method, target) in &cases {
        let r = get(&m, target, None);
        check_response(&d, &path_of(target), method, &r);
    }
    // POST /v1/checkpoint and a gossip exchange.
    let r = handle(&m, &Request::new("POST", "/v1/checkpoint", vec![]), NOW);
    check_response(&d, "/v1/checkpoint", "POST", &r);
    let cp = get(&m, "/v1/checkpoint", None).json_body().unwrap()["checkpoint"].clone();
    let r = handle(
        &m,
        &Request::new(
            "POST",
            "/v1/gossip",
            serde_json::to_vec(&json!({ "checkpoints": [cp] })).unwrap(),
        ),
        NOW,
    );
    check_response(&d, "/v1/gossip", "POST", &r);
    let r = handle(&m, &Request::new("POST", "/v1/gossip", b"{}".to_vec()), NOW);
    assert_eq!(r.status, 400);
    check_response(&d, "/v1/gossip", "POST", &r);
    // Submit: accepted, duplicate, and refusals.
    let fresh = attest(
        &ident(11),
        ident(13).agent_id(),
        claims::OPERATOR,
        text_map(&[("name", "B")]),
        NOW - 5,
        90,
    );
    let post = |body: Vec<u8>, ct: &str| {
        handle(
            &m,
            &Request::new("POST", "/v1/submit", body).with_header("content-type", ct),
            NOW,
        )
    };
    let r = post(fresh.clone(), "application/cbor");
    assert_eq!(r.status, 201);
    check_response(&d, "/v1/submit", "POST", &r);
    let r = post(fresh, "application/cbor");
    assert_eq!(r.status, 200);
    check_response(&d, "/v1/submit", "POST", &r);
    let r = post(b"junk".to_vec(), "application/cbor");
    assert_eq!(r.status, 400);
    check_response(&d, "/v1/submit", "POST", &r);
    let unknown = attest(
        &ident(11),
        ident(13).agent_id(),
        "https://atep.dev/claims/invented",
        text_map(&[]),
        NOW - 5,
        90,
    );
    let r = post(unknown, "application/cbor");
    assert_eq!(r.status, 422);
    check_response(&d, "/v1/submit", "POST", &r);
    // CBOR content types are documented where they are served.
    let cbor = handle(
        &m,
        &Request::new("GET", "/v1/checkpoint", vec![]).with_header("accept", "application/cbor"),
        NOW,
    );
    check_response(&d, "/v1/checkpoint", "GET", &cbor);
}

#[test]
fn the_validator_rejects_a_wrong_schema() {
    // Guard the guard: a response with an undocumented member or a wrong type fails.
    let d = doc();
    let schema = json!({ "$ref": "#/components/schemas/Checkpoint" });
    assert!(conforms(&d, &schema, &json!({ "tree-size": "x" }), "t").is_err());
    let bad = json!({ "error": "x", "detail": "y", "extra": 1 });
    assert!(conforms(
        &d,
        &json!({ "$ref": "#/components/schemas/Error" }),
        &bad,
        "t"
    )
    .is_err());
    assert!(conforms(
        &d,
        &json!({ "$ref": "#/components/schemas/Error" }),
        &json!({ "error": "x", "detail": "y" }),
        "t"
    )
    .is_ok());
}

#[test]
fn all_refs_resolve_and_are_used() {
    let d = doc();
    let text = serde_json::to_string(&d).unwrap();
    let mut refs = BTreeSet::new();
    let mut rest = text.as_str();
    while let Some(i) = rest.find("\"$ref\":\"") {
        rest = &rest[i + 8..];
        let end = rest.find('"').unwrap();
        refs.insert(rest[..end].to_string());
    }
    for r in &refs {
        assert!(
            d.pointer(r.strip_prefix('#').unwrap()).is_some(),
            "dangling {r}"
        );
    }
    for (kind, items) in [
        ("schemas", &d["components"]["schemas"]),
        ("responses", &d["components"]["responses"]),
    ] {
        for name in items.as_object().unwrap().keys() {
            let r = format!("#/components/{kind}/{name}");
            assert!(refs.contains(&r), "{r} is defined but never used");
        }
    }
}

// ---------------------------------------------------------------------------
// registry-endpoint

fn endpoint_attestation(
    kind: &str,
    url: &str,
    evidence: Option<([u8; 32], &str)>,
    claim: &str,
) -> Vec<u8> {
    let mut p =
        AttestationParams::new(ident(3).agent_id(), claim, NOW - 10, NOW - 10 + 90 * DAY).unwrap();
    p.data = text_map(&[("url", url), ("kind", kind)]);
    if let Some((digest, uri)) = evidence {
        p.evidence = Some(digest);
        p.evidence_uri = Some(uri.to_string());
    }
    p.mode = SignMode::Deterministic;
    attestation::issue(&ident(2), &p).unwrap()
}

#[test]
fn registry_endpoint_is_admitted_with_checked_data() {
    let dir = TempDir::new("endpoint");
    let mut log = open(&dir);
    let ok =
        |kind: &str, url: &str| endpoint_attestation(kind, url, None, claimdefs::REGISTRY_ENDPOINT);
    for kind in ["registry", "verifier", "mcp", "a2a", "x-custom"] {
        log.submit(&ok(kind, &format!("https://{kind}.example.com/")), NOW)
            .unwrap();
    }
    for (kind, url) in [
        ("registry", "http://insecure.example.com"),
        ("registry", "ftp://x.example.com"),
        ("registry", "https://user:pw@x.example.com/"),
        ("registry", "https://"),
        ("other", "https://x.example.com"),
        ("X-Caps", "https://x.example.com"),
    ] {
        match log.submit(&ok(kind, url), NOW) {
            Err(SubmitErr::Rejected(e)) => assert_eq!(e.code, "schema_invalid", "{kind} {url}"),
            other => panic!("{kind} {url}: {other:?}"),
        }
    }
    // Missing members.
    let mut p = AttestationParams::new(
        ident(3).agent_id(),
        claimdefs::REGISTRY_ENDPOINT,
        NOW - 10,
        NOW + DAY,
    )
    .unwrap();
    p.data = Value::Map(vec![]);
    p.mode = SignMode::Deterministic;
    let raw = attestation::issue(&ident(2), &p).unwrap();
    assert!(
        matches!(log.submit(&raw, NOW), Err(SubmitErr::Rejected(e)) if e.code == "schema_invalid")
    );
    // The rest of the closed namespace stays closed.
    let invented = endpoint_attestation(
        "registry",
        "https://x.example.com",
        None,
        "https://atep.dev/claims/invented",
    );
    assert!(
        matches!(log.submit(&invented, NOW), Err(SubmitErr::Rejected(e)) if e.code == "claim_vocabulary")
    );
}

#[test]
fn an_a2a_card_is_carried_as_evidence() {
    // The card JSON is hashed into `evidence`, `evidence-uri` points at the card.
    let card = br#"{"name":"Registry","url":"https://atep.dev/","skills":[]}"#;
    let digest = sha256(card);
    let raw = endpoint_attestation(
        "a2a",
        "https://atep.dev/",
        Some((digest, "https://atep.dev/.well-known/agent.json")),
        claimdefs::REGISTRY_ENDPOINT,
    );
    let dir = TempDir::new("card");
    let mut log = open(&dir);
    let out = log.submit(&raw, NOW).unwrap();
    let env =
        atep_core::envelope::SignedEnvelope::decode(&log.read_entry(out.index as u64).unwrap())
            .unwrap();
    let att = attestation::Attestation::from_payload(&env.payload.unwrap()).unwrap();
    assert_eq!(att.evidence, Some(digest));
    assert_eq!(
        att.evidence_uri.as_deref(),
        Some("https://atep.dev/.well-known/agent.json")
    );
    // Evidence makes it audit-backed: a 400 day lifetime is allowed, as for any attestation with evidence.
    // (Lifetime tiers are unchanged by the new claim.)
}

#[test]
fn registry_endpoint_is_a_core_claim() {
    // atep-core knows 14 core claims and registry-endpoint is one of them.
    assert!(core_uris().contains(claimdefs::REGISTRY_ENDPOINT));
    assert!(atep_log::admit::is_core_claim(claimdefs::REGISTRY_ENDPOINT));
    assert_eq!(core_uris().len(), 14);
    // The log policy lists the 14 in core-claims and has no extension list.
    let dir = TempDir::new("policy-ext");
    let m = Mutex::new(open(&dir));
    let p = get(&m, "/v1/policy", None).json_body().unwrap();
    let core = p["policy"]["core-claims"].as_array().unwrap();
    assert_eq!(core.len(), 14);
    assert!(core.iter().any(|c| c == claimdefs::REGISTRY_ENDPOINT));
    assert!(p["policy"].get("extension-claims").is_none());
    // The directory marks it core.
    let rows = get(&m, "/v1/claims", None).json_body().unwrap();
    let row = rows["claim-types"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["claim"] == claimdefs::REGISTRY_ENDPOINT)
        .unwrap();
    assert_eq!(row["core"], true);
    assert_eq!(row["status"], "core");
}

#[test]
fn a_data_directory_with_the_draft_04_policy_gets_a_new_policy_entry_on_restart() {
    // An operator that ran the extension transition has a policy with the 13
    // claim types of Draft 03 in `core-claims` and `registry-endpoint` under
    // `extension-claims`. Starting the Draft 05 log appends the new policy.
    let dir = TempDir::new("policy-upgrade");
    let (old_index, size_before) = {
        let mut log = open(&dir);
        let mut data = atep_log::policy::policy_data(log.config(), &log.log_id());
        let Value::Map(m) = &mut data else {
            panic!("policy data is a map")
        };
        for (k, v) in m.iter_mut() {
            if k.as_text() == Some("core-claims") {
                let Value::Array(a) = v else { panic!() };
                a.retain(|c| c.as_text() != Some(claimdefs::REGISTRY_ENDPOINT));
                assert_eq!(a.len(), 13);
            }
        }
        m.push((
            Value::text("extension-claims"),
            Value::Array(vec![Value::text(claimdefs::REGISTRY_ENDPOINT)]),
        ));
        let mut p = AttestationParams::new(
            log.log_id(),
            atep_log::POLICY_CLAIM,
            NOW + 1,
            NOW + 1 + 365 * DAY,
        )
        .unwrap();
        p.data = data;
        p.allow_long_default = true;
        let raw = attestation::issue(log.identity(), &p).unwrap();
        let idx = log.submit(&raw, NOW + 1).unwrap().index;
        assert_eq!(log.policy_entry().unwrap().index, idx);
        (idx, log.tree_size())
    };
    let log = Log::open_with(dir.path(), Some(ident(1)), LogConfig::default(), NOW + 2).unwrap();
    let latest = log.policy_entry().unwrap();
    assert!(latest.index > old_index);
    assert_eq!(log.tree_size(), size_before + 1);
    let raw = log.read_entry(latest.index).unwrap();
    let env = atep_core::envelope::SignedEnvelope::decode(&raw).unwrap();
    let att = attestation::Attestation::from_payload(&env.payload.unwrap()).unwrap();
    let core = att.data_get("core-claims").unwrap().as_array().unwrap();
    assert_eq!(core.len(), 14);
    assert!(att.data_get("extension-claims").is_none());
}

/// The `registry-endpoint` vectors (the admission of kinds and URLs, spec
/// sections 7 and 9) run against the real log: each submission is made to
/// `Log::submit` and accepted or refused with the reason the vector names.
#[test]
fn registry_endpoint_vectors_agree_with_the_log() {
    let dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/registry-endpoint");
    let mut seen = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let Some(base) = name.strip_suffix(".expected.json") else {
            continue;
        };
        let meta: J = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let cbor = std::fs::read(dir.join(format!("{base}.cbor"))).unwrap();
        let tmp = TempDir::new("registry-endpoint-vectors");
        let mut log = open(&tmp);
        let want = &meta["expected"];
        match (log.submit(&cbor, NOW), want["ok"].as_bool().unwrap()) {
            (Ok(out), true) => assert!(!out.duplicate, "{base}"),
            (Err(SubmitErr::Rejected(e)), false) => {
                assert_eq!(e.code, want["refusal"].as_str().unwrap(), "{base}")
            }
            (other, _) => panic!("{base}: log answered {other:?}, vector expects {want}"),
        }
        seen += 1;
    }
    assert!(seen >= 20, "only {seen} registry-endpoint vectors");
}
