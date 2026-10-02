//! The OpenAPI 3.1 description of the log HTTP API, served at
//! `GET /openapi.json` and checked in as `docs/openapi.json`.
//!
//! Paths and methods come from [`crate::routes::ROUTES`]; [`operation`]
//! matches exhaustively on [`RouteId`], so adding a route without describing
//! it does not compile. The component schemas below are checked against live
//! responses in `tests/discovery.rs`.

use serde_json::{json, Map, Value as J};

use crate::routes::{RouteId, ROUTES};

/// Version of the API description (not of the protocol).
pub const API_VERSION: &str = "0.2.0";

fn r(name: &str) -> J {
    json!({ "$ref": format!("#/components/schemas/{name}") })
}

fn resp_ref(name: &str) -> J {
    json!({ "$ref": format!("#/components/responses/{name}") })
}

fn json_content(schema: J) -> J {
    json!({ "application/json": { "schema": schema } })
}

fn binary(desc: &str) -> J {
    json!({ "type": "string", "format": "binary", "description": desc })
}

fn query(name: &str, desc: &str, schema: J, required: bool) -> J {
    json!({ "name": name, "in": "query", "required": required, "description": desc, "schema": schema })
}

fn path_param(name: &str, desc: &str) -> J {
    json!({ "name": name, "in": "path", "required": true, "description": desc, "schema": { "type": "string" } })
}

fn accept_cbor_note() -> &'static str {
    "Send `Accept: application/cbor` for the CBOR form."
}

/// The operation object of a route.
pub fn operation(id: RouteId) -> J {
    match id {
        RouteId::Index => json!({
            "operationId": "getIndex", "tags": ["meta"],
            "summary": "Service index",
            "description": "The log's Agent ID, the list of routes and the location of this description.",
            "responses": { "200": { "description": "Service index", "content": json_content(r("ApiIndex")) } },
        }),
        RouteId::OpenApi => json!({
            "operationId": "getOpenApi", "tags": ["meta"],
            "summary": "This OpenAPI 3.1 description",
            "responses": { "200": { "description": "The OpenAPI document", "content": json_content(json!({ "type": "object" })) } },
        }),
        RouteId::Submit => json!({
            "operationId": "submit", "tags": ["log"],
            "summary": "Submit an attestation or an SRL",
            "description": "Accepts attestations (`application/atep-attestation+cbor`) and signed revocation lists (`application/atep-srl+cbor`) only. Encrypted envelopes, data envelopes and checkpoints are refused; envelopes exchanged between agents are never logged (spec section 16 point 5). A resubmission is idempotent. The reply's `proof` is the value of the `-70012` inclusion-proof header. Admission rules: GET /v1/policy.",
            "requestBody": { "required": true, "content": {
                "application/cbor": { "schema": binary("The signed envelope (COSE tag 98), deterministic CBOR.") },
                "application/json": { "schema": r("SubmitRequest") },
            } },
            "responses": {
                "200": { "description": "Duplicate: the existing entry and a proof against the latest checkpoint. With `Accept: application/cbor` the body is the inclusion-proof CBOR value.",
                    "content": { "application/json": { "schema": r("SubmitReply") }, "application/cbor": { "schema": binary("CBOR inclusion-proof map {leaf-index, audit-path, checkpoint}.") } } },
                "201": { "description": "New entry. With `Accept: application/cbor` the body is the inclusion-proof CBOR value.",
                    "content": { "application/json": { "schema": r("SubmitReply") }, "application/cbor": { "schema": binary("CBOR inclusion-proof map {leaf-index, audit-path, checkpoint}.") } } },
                "400": resp_ref("BadRequest"),
                "413": resp_ref("TooLarge"),
                "422": resp_ref("Rejected"),
                "500": resp_ref("ServerError"),
            },
        }),
        RouteId::CheckpointGet => json!({
            "operationId": "getCheckpoint", "tags": ["log"],
            "summary": "Latest signed checkpoint",
            "description": format!("A fresh checkpoint is signed first when the configured interval has passed. {}", accept_cbor_note()),
            "responses": {
                "200": { "description": "The latest checkpoint", "content": {
                    "application/json": { "schema": r("Checkpoint") },
                    "application/atep-checkpoint+cbor": { "schema": binary("Signed checkpoint envelope (tag 98), payload {tree-size, root-hash, timestamp}.") } } },
                "500": resp_ref("ServerError"),
                "503": resp_ref("Unavailable"),
            },
        }),
        RouteId::CheckpointPost => json!({
            "operationId": "signCheckpoint", "tags": ["log"],
            "summary": "Sign a checkpoint now",
            "responses": {
                "201": { "description": "The new checkpoint", "content": {
                    "application/json": { "schema": r("Checkpoint") },
                    "application/atep-checkpoint+cbor": { "schema": binary("Signed checkpoint envelope (tag 98).") } } },
                "500": resp_ref("ServerError"),
            },
        }),
        RouteId::Checkpoints => json!({
            "operationId": "listCheckpoints", "tags": ["log"],
            "summary": "Published checkpoints",
            "description": "Every published checkpoint with tree size at least `from`, oldest first, at most 1000.",
            "parameters": [ query("from", "Smallest tree size to return (default 0).", json!({ "type": "integer", "minimum": 0 }), false) ],
            "responses": {
                "200": { "description": "Checkpoints", "content": json_content(r("CheckpointList")) },
                "400": resp_ref("BadRequest"),
            },
        }),
        RouteId::ProofInclusion => json!({
            "operationId": "getInclusionProof", "tags": ["log"],
            "summary": "Inclusion proof of a leaf",
            "description": format!("Proof against the latest checkpoint (one is signed first if none covers the leaf yet). Give `leaf-hash` or `index`. {}", accept_cbor_note()),
            "parameters": [
                query("leaf-hash", "Leaf hash, 64 lowercase hex characters: SHA-256(0x00 || submitted envelope).", r("Hex32"), false),
                query("index", "Leaf index, alternative to `leaf-hash`.", json!({ "type": "integer", "minimum": 0 }), false),
            ],
            "responses": {
                "200": { "description": "The proof", "content": {
                    "application/json": { "schema": r("InclusionProof") },
                    "application/cbor": { "schema": binary("CBOR inclusion-proof map {leaf-index, audit-path, checkpoint}.") } } },
                "400": resp_ref("BadRequest"),
                "404": resp_ref("NotFound"),
                "500": resp_ref("ServerError"),
            },
        }),
        RouteId::ProofConsistency => json!({
            "operationId": "getConsistencyProof", "tags": ["log"],
            "summary": "Consistency proof between two tree sizes",
            "description": format!("Proof that tree size `to` extends tree size `from` (`from <= to <= current tree size`). {}", accept_cbor_note()),
            "parameters": [
                query("from", "Older tree size.", json!({ "type": "integer", "minimum": 0 }), true),
                query("to", "Newer tree size.", json!({ "type": "integer", "minimum": 0 }), true),
            ],
            "responses": {
                "200": { "description": "The proof", "content": {
                    "application/json": { "schema": r("ConsistencyProof") },
                    "application/cbor": { "schema": binary("CBOR consistency-proof map {from, to, path}.") } } },
                "400": resp_ref("BadRequest"),
            },
        }),
        RouteId::Entries => json!({
            "operationId": "listEntries", "tags": ["log"],
            "summary": "Log entries",
            "description": "Entries `from` to `to` (exclusive), at most 1000 per call. `envelope` is the submitted form, so SHA-256(0x00 || envelope) is the leaf hash.",
            "parameters": [
                query("from", "First index (default 0).", json!({ "type": "integer", "minimum": 0 }), false),
                query("to", "End index, exclusive (default the tree size).", json!({ "type": "integer", "minimum": 0 }), false),
            ],
            "responses": {
                "200": { "description": "Entries", "content": json_content(r("EntryList")) },
                "400": resp_ref("BadRequest"),
                "500": resp_ref("ServerError"),
            },
        }),
        RouteId::Lookup => json!({
            "operationId": "lookupSubject", "tags": ["registry"],
            "summary": "Attestations about a subject",
            "description": "Logged attestations whose subject is the given Agent ID, optionally filtered by claim type. Serves attestations only, never agent traffic (spec section 16 point 5). Operators SHOULD rate limit it.",
            "parameters": [
                query("subject", "Agent ID (`atep:` text, percent-encoded).", r("AgentId"), true),
                query("claim", "Claim URI or short name (`audited`, `robotics/fleet-member`).", json!({ "type": "string" }), false),
            ],
            "responses": {
                "200": { "description": "Matching entries", "content": json_content(r("LookupReply")) },
                "400": resp_ref("BadRequest"),
                "500": resp_ref("ServerError"),
            },
        }),
        RouteId::Issuers => json!({
            "operationId": "listIssuers", "tags": ["registry"],
            "summary": "Issuer directory",
            "description": "Derived from the log: every identity that issued a logged document, the claim types it issued, its delegations, bound domains and SRL locations.",
            "parameters": [ query("issuer", "Return only this issuer.", r("AgentId"), false) ],
            "responses": { "200": { "description": "Issuer directory", "content": json_content(r("IssuerDirectory")) } },
        }),
        RouteId::ClaimsDirectory => json!({
            "operationId": "listClaimTypes", "tags": ["registry", "claims"],
            "summary": "Claim-type directory",
            "description": "The core vocabulary and Draft 04 proposals (with definition and CDDL schema of `data`) plus every other claim type seen in the log. Resolve one with GET /v1/claims/{claim}.",
            "responses": { "200": { "description": "Claim-type directory", "content": json_content(r("ClaimDirectory")) } },
        }),
        RouteId::ClaimResolve => json!({
            "operationId": "resolveClaimType", "tags": ["claims"],
            "summary": "Resolve a claim type",
            "description": "Human-readable definition and CDDL schema of `data` for a claim type. `claim` is the full claim URI (percent-encode it: `https%3A%2F%2Fatep.dev%2Fclaims%2Faudited`; the plain form also works) or a short name (`audited`, `robotics/fleet-member`). A trailing `.html` or `.json` selects the format, otherwise `Accept: text/html` selects HTML and anything else JSON. Unknown claims, including claim types of other namespaces, are 404.",
            "parameters": [ path_param("claim", "Claim URI (percent-encoded) or short name.") ],
            "responses": {
                "200": { "description": "The definition", "content": {
                    "application/json": { "schema": r("ClaimDefinition") },
                    "text/html": { "schema": { "type": "string" } } } },
                "404": resp_ref("NotFound"),
            },
        }),
        RouteId::Policy => json!({
            "operationId": "getPolicy", "tags": ["log"],
            "summary": "Log policy",
            "description": "The log policy with the entry that records it. The policy is a self-attestation of the log and the first entry of a new log.",
            "responses": {
                "200": { "description": "Policy", "content": json_content(r("PolicyReply")) },
                "404": resp_ref("NotFound"),
                "500": resp_ref("ServerError"),
            },
        }),
        RouteId::GossipGet => json!({
            "operationId": "getGossip", "tags": ["gossip"],
            "summary": "Checkpoints and split view evidence held by this node",
            "responses": { "200": { "description": "Gossip state", "content": json_content(r("GossipState")) } },
        }),
        RouteId::GossipPost => json!({
            "operationId": "postGossip", "tags": ["gossip"],
            "summary": "Exchange checkpoints",
            "description": "Verifies and compares each checkpoint with what the log holds for the same signing log. `409` when a split view was found; `results[].evidence` is then the evidence document, confirmable with the signing log's public key.",
            "requestBody": { "required": true, "content": json_content(r("GossipRequest")) },
            "responses": {
                "200": { "description": "No split view", "content": json_content(r("GossipReply")) },
                "400": resp_ref("BadRequest"),
                "409": { "description": "Split view found", "content": json_content(r("GossipReply")) },
            },
        }),
        RouteId::ClaimsIndex => json!({
            "operationId": "getClaimsIndex", "tags": ["claims"],
            "summary": "Claim-type index (path style)",
            "description": "Index of the claim types the registry defines. JSON by default, HTML with `Accept: text/html`. A deployment mounted at atep.dev serves `https://atep.dev/claims`.",
            "responses": { "200": { "description": "Index", "content": {
                "application/json": { "schema": r("ClaimsIndex") },
                "text/html": { "schema": { "type": "string" } } } } },
        }),
        RouteId::ClaimRobotics => json!({
            "operationId": "getRoboticsClaim", "tags": ["claims"],
            "summary": "Resolve a robotics claim type (path style)",
            "description": "`https://atep.dev/claims/robotics/<name>`. JSON by default, HTML with `Accept: text/html` or a `.html` suffix.",
            "parameters": [ path_param("name", "Claim name below robotics/, for example `fleet-member`; may end in `.html` or `.json`.") ],
            "responses": {
                "200": { "description": "The definition", "content": {
                    "application/json": { "schema": r("ClaimDefinition") },
                    "text/html": { "schema": { "type": "string" } } } },
                "404": resp_ref("NotFound"),
            },
        }),
        RouteId::ClaimCore => json!({
            "operationId": "getClaim", "tags": ["claims"],
            "summary": "Resolve a core claim type (path style)",
            "description": "`https://atep.dev/claims/<name>`. JSON by default, HTML with `Accept: text/html` or a `.html` suffix.",
            "parameters": [ path_param("name", "Claim name, for example `audited`; may end in `.html` or `.json`.") ],
            "responses": {
                "200": { "description": "The definition", "content": {
                    "application/json": { "schema": r("ClaimDefinition") },
                    "text/html": { "schema": { "type": "string" } } } },
                "404": resp_ref("NotFound"),
            },
        }),
    }
}

fn s_str() -> J {
    json!({ "type": "string" })
}
fn s_int() -> J {
    json!({ "type": "integer" })
}
fn s_str_list() -> J {
    json!({ "type": "array", "items": { "type": "string" } })
}
fn nullable(ty: &str) -> J {
    json!({ "type": [ty, "null"] })
}

/// An object schema with the given required and optional members.
fn obj(required: &[(&str, J)], optional: &[(&str, J)]) -> J {
    let mut props = Map::new();
    for (k, v) in required.iter().chain(optional.iter()) {
        props.insert((*k).to_string(), v.clone());
    }
    json!({
        "type": "object",
        "properties": props,
        "required": required.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
    })
}

fn schemas() -> J {
    let log = r("AgentId");
    let hex = r("Hex32");
    let b64 = r("Base64Url");
    let hexlist = json!({ "type": "array", "items": hex });
    json!({
        "AgentId": { "type": "string", "pattern": "^(did:)?atep:[a-z2-7]{52}$", "description": "Agent ID: `atep:` (canonical) or `did:atep:` plus 52 lowercase base32 characters." },
        "Hex32": { "type": "string", "pattern": "^[0-9a-f]{64}$", "description": "32 bytes as lowercase hex." },
        "Base64Url": { "type": "string", "pattern": "^[A-Za-z0-9_-]*$", "description": "Unpadded base64url." },
        "Error": obj(&[("error", s_str()), ("detail", s_str())], &[]),
        "Rejection": {
            "description": "A refused submission: the admission reason, with the failing verification step when the reason is `verification_failed`.",
            "type": "object",
            "properties": {
                "error": { "type": "string", "enum": ["encrypted_envelope", "data_envelope", "content_type_not_loggable", "verification_failed", "schema_invalid", "lifetime_exceeded", "claim_vocabulary", "srl_rollback"] },
                "detail": s_str(),
                "step": { "type": "integer", "minimum": 1, "maximum": 9 },
                "rejection": { "type": "string", "description": "Stable rejection code of spec section 10." },
            },
            "required": ["error", "detail"],
        },
        "ApiIndex": obj(&[("service", s_str()), ("log", log.clone()), ("openapi", s_str()), ("endpoints", s_str_list())], &[]),
        "SubmitRequest": obj(&[("envelope", b64.clone())], &[]),
        "SubmitReply": obj(&[
            ("status", json!({ "type": "string", "enum": ["accepted", "duplicate"] })),
            ("leaf-index", s_int()), ("leaf-hash", hex.clone()),
            ("audit-path", hexlist.clone()),
            ("proof", b64.clone()),
        ], &[]),
        "Anchor": obj(&[
            ("checkpoint-hash", hex.clone()), ("chain-id", s_str()), ("transaction-id", s_str()),
            ("block-height", nullable("integer")), ("anchored-at", s_int()), ("anchor", b64.clone()),
        ], &[]),
        "Checkpoint": obj(&[
            ("log", log.clone()), ("tree-size", s_int()), ("root-hash", hex.clone()), ("timestamp", s_int()),
            ("checkpoint", b64.clone()), ("checkpoint-hash", hex.clone()),
            ("anchors", json!({ "type": "array", "items": r("Anchor") })),
        ], &[]),
        "CheckpointList": obj(&[("log", log.clone()), ("checkpoints", json!({ "type": "array", "items": r("Checkpoint") }))], &[]),
        "InclusionProof": obj(&[
            ("leaf-index", s_int()), ("leaf-hash", hex.clone()), ("audit-path", hexlist.clone()), ("proof", b64.clone()),
        ], &[("tree-size", s_int()), ("checkpoint", b64.clone())]),
        "ConsistencyProof": obj(&[
            ("from", s_int()), ("to", s_int()), ("first-hash", hex.clone()), ("second-hash", hex.clone()),
            ("path", hexlist.clone()), ("proof", b64.clone()),
        ], &[]),
        "Entry": obj(&[
            ("index", s_int()), ("leaf-hash", hex.clone()), ("logged-at", s_int()),
            ("kind", json!({ "type": "string", "enum": ["attestation", "srl"] })),
            ("issuer", log.clone()), ("issued-at", s_int()), ("expires-at", nullable("integer")),
        ], &[
            ("subject", log.clone()), ("claim", s_str()),
            ("attestation-id", json!({ "type": "string", "pattern": "^[0-9a-f]{32}$" })),
            ("srl-sequence", s_int()), ("policy", json!({ "type": "boolean" })), ("envelope", b64.clone()),
        ]),
        "EntryList": obj(&[
            ("from", s_int()), ("to", s_int()), ("tree-size", s_int()),
            ("entries", json!({ "type": "array", "items": r("Entry") })),
        ], &[]),
        "LookupReply": obj(&[
            ("subject", log.clone()), ("tree-size", s_int()),
            ("entries", json!({ "type": "array", "items": r("Entry") })),
        ], &[]),
        "Issuer": obj(&[
            ("issuer", log.clone()), ("first-index", nullable("integer")), ("entries", s_int()),
            ("claims", s_str_list()), ("namespaces", s_str_list()), ("delegated-claims", s_str_list()),
            ("delegated-by", s_str_list()), ("domains", s_str_list()), ("srl-urls", s_str_list()),
            ("latest-srl", json!({ "oneOf": [ { "type": "null" }, obj(&[("entry", s_int()), ("sequence", s_int()), ("issued-at", s_int())], &[]) ] })),
            ("included", json!({ "type": "boolean" })),
        ], &[]),
        "IssuerDirectory": obj(&[("tree-size", s_int()), ("issuers", json!({ "type": "array", "items": r("Issuer") }))], &[]),
        "ClaimRow": obj(&[
            ("claim", s_str()), ("core", json!({ "type": "boolean" })), ("namespace", s_str()),
            ("entries", s_int()), ("issuers", s_int()), ("first-index", nullable("integer")),
            ("definition", nullable("string")), ("data-schema", nullable("string")),
            ("status", json!({ "type": "string", "enum": ["core", "proposed", "open"], "description": "`core`: Draft 03 vocabulary; `proposed`: a Draft 04 proposal the log admits; `open`: any other claim type seen in the log." })),
            ("resolve", nullable("string")),
        ], &[]),
        "ClaimDirectory": obj(&[
            ("tree-size", s_int()), ("core-namespace", s_str()),
            ("claim-types", json!({ "type": "array", "items": r("ClaimRow") })),
        ], &[]),
        "ClaimDefinition": obj(&[
            ("claim", s_str()), ("name", s_str()), ("core", json!({ "type": "boolean" })),
            ("status", json!({ "type": "string", "enum": ["core", "proposed"] })),
            ("profile", json!({ "type": "string", "enum": ["core", "robotics", "draft-04"] })),
            ("definition", s_str()), ("title", s_str()), ("description", s_str_list()),
            ("issued-by", s_str()), ("subject", s_str()),
            ("data-schema", json!({ "type": "string", "description": "CDDL (RFC 8610) of the attestation `data` map." })),
            ("data-schema-format", json!({ "type": "string", "enum": ["cddl"] })),
            ("attestation-schema", json!({ "type": "string", "description": "CDDL of the whole attestation payload." })),
            ("data-checked-by", s_str()), ("evidence", s_str()), ("lifetime", s_str()),
            ("spec", s_str_list()), ("example-data", json!({ "type": "object" })),
            ("links", obj(&[("self", s_str()), ("html", s_str()), ("api", s_str()), ("directory", s_str())], &[])),
        ], &[]),
        "ClaimsIndex": obj(&[
            ("namespace", s_str()),
            ("claims", json!({ "type": "array", "items": obj(&[
                ("claim", s_str()), ("name", s_str()), ("core", json!({ "type": "boolean" })),
                ("status", s_str()), ("profile", s_str()), ("definition", s_str()),
                ("title", s_str()), ("url", s_str()),
            ], &[]) })),
        ], &[]),
        "PolicyReply": obj(&[
            ("log", log.clone()), ("claim", s_str()), ("entry-index", s_int()), ("first-entry", json!({ "type": "boolean" })),
            ("leaf-hash", hex.clone()), ("issued-at", s_int()), ("expires-at", s_int()),
            ("policy", json!({ "type": "object", "description": "The `data` of the policy attestation (spec section 9, log policy entry)." })),
            ("envelope", b64.clone()), ("proof", json!({ "oneOf": [ { "type": "null" }, b64.clone() ] })),
        ], &[]),
        "Observed": obj(&[
            ("log", log.clone()), ("tree-size", s_int()), ("root-hash", hex.clone()), ("timestamp", s_int()), ("checkpoint", b64.clone()),
        ], &[]),
        "GossipState": obj(&[
            ("log", log.clone()),
            ("latest", json!({ "oneOf": [ { "type": "null" }, r("Checkpoint") ] })),
            ("observed", json!({ "type": "array", "items": r("Observed") })),
            ("evidence", json!({ "type": "array", "items": obj(&[("log", log.clone()), ("reason", s_str()), ("pair", b64.clone())], &[]) })),
        ], &[]),
        "GossipRequest": {
            "type": "object",
            "properties": {
                "checkpoints": { "type": "array", "items": b64.clone() },
                "checkpoint": b64.clone(),
                "proofs": { "type": "array", "items": b64.clone(), "description": "Consistency proofs (CBOR, base64url) that may help to compare checkpoints." },
            },
        },
        "GossipResult": obj(&[
            ("result", json!({ "type": "string", "enum": ["new", "known", "split-view", "rejected"] })),
        ], &[
            ("log", json!({ "oneOf": [ { "type": "null" }, log.clone() ] })),
            ("tree-size", nullable("integer")),
            ("reason", s_str()), ("evidence", b64.clone()), ("error", s_str()), ("detail", s_str()),
        ]),
        "GossipReply": obj(&[
            ("log", log.clone()), ("split-view", json!({ "type": "boolean" })),
            ("results", json!({ "type": "array", "items": r("GossipResult") })),
            ("checkpoints", json!({ "type": "array", "items": b64.clone() })),
        ], &[]),
    })
}

fn responses() -> J {
    let err = |desc: &str| json!({ "description": desc, "content": json_content(r("Error")) });
    json!({
        "BadRequest": err("Malformed request or parameter (`malformed`, `bad_parameter`, `bad_request`)."),
        "NotFound": err("Nothing there (`not_found`, `claim_unknown`)."),
        "TooLarge": err("The body is larger than the admission limit (`too_large`)."),
        "Rejected": { "description": "The submission was refused; `error` is the admission reason.", "content": json_content(r("Rejection")) },
        "ServerError": err("Storage or crypto failure of the log (`log_error`)."),
        "Unavailable": err("The log has no checkpoint yet (`no_checkpoint`)."),
    })
}

/// Build the whole document.
pub fn document() -> J {
    let mut paths = Map::new();
    for route in ROUTES.iter() {
        let item = paths
            .entry(route.path.to_string())
            .or_insert_with(|| json!({}));
        item[route.method.to_ascii_lowercase()] = operation(route.id);
    }
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "ATEP log and registry API",
            "version": API_VERSION,
            "summary": "Transparency log, directories and claim-type resolver of an ATEP registry.",
            "description": "HTTP/1.1 API of an ATEP transparency log (atep-logd), ATEP Draft 07 section 9 plus the discovery additions of Draft 04. All data is signed, so TLS adds privacy and no trust. Responses are JSON unless `Accept` contains `cbor`, which selects the CBOR form where one exists. Binary values in JSON are unpadded base64url (`envelope`, `checkpoint`, `proof`) or lowercase hex (`leaf-hash`, `root-hash`, `audit-path`). Agent IDs are `atep:` text. Errors are `{\"error\": \"<code>\", \"detail\": \"...\"}`. `HEAD` is answered for every `GET` route. Every response allows any origin (CORS `*`). Layouts marked provisional are described in docs/implementation-findings/rust-findings.md, findings 33 to 41.",
            "license": { "name": "Apache-2.0", "identifier": "Apache-2.0" },
        },
        "servers": [
            { "url": "/", "description": "This log" },
            { "url": "https://atep.dev", "description": "Hosted registry when deployed there; also serves https://atep.dev/claims/<name>" },
        ],
        "tags": [
            { "name": "log", "description": "Merkle log: submission, checkpoints, proofs, entries, policy" },
            { "name": "registry", "description": "Directories derived from the log" },
            { "name": "claims", "description": "Claim-type resolution: definition plus CDDL schema" },
            { "name": "gossip", "description": "Checkpoint exchange and split view detection" },
            { "name": "meta", "description": "Service index and this description" },
        ],
        "security": [],
        "paths": paths,
        "components": { "schemas": schemas(), "responses": responses() },
    })
}

/// The document as pretty JSON with a trailing newline (the form of `docs/openapi.json`).
pub fn document_text() -> String {
    let mut s = serde_json::to_string_pretty(&document()).unwrap_or_default();
    s.push('\n');
    s
}
