//! HTTP/1.1 API of the log, on `std::net` only (no TLS: terminate TLS in a
//! reverse proxy). One thread per connection, `Connection: close`, bounded
//! headers and bodies, read timeouts. The router ([`handle`]) is a pure
//! function over a parsed request so it can be tested without sockets.
//!
//! See `docs/log-api.md` for the endpoint reference.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use atep_core::attestation::claims;
use atep_core::keys::AgentId;
use atep_core::log::{ConsistencyProof, InclusionProof};
use serde_json::{json, Value as J};

use crate::admit::SubmitError;
use crate::claimdefs;
use crate::directory::{claim_types, entry_json, issuers};
use crate::gossip::{Observation, ProofList};
use crate::log::{CheckpointRec, Log, SubmitErr, SubmitOutcome};
use crate::routes::{self, RouteId};
use crate::{b64, unb64, LogError};

const MAX_HEADER: usize = 16 * 1024;
const MAX_BODY: usize = 1024 * 1024;
const MAX_ENTRIES_PER_REQUEST: u64 = 1000;

pub struct Request {
    pub method: String,
    pub path: String,
    pub query: Vec<(String, String)>,
    /// Header names in lowercase.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn new(method: &str, target: &str, body: Vec<u8>) -> Request {
        let (path, q) = target.split_once('?').unwrap_or((target, ""));
        Request {
            method: method.to_string(),
            path: path.to_string(),
            query: q
                .split('&')
                .filter(|s| !s.is_empty())
                .map(|kv| {
                    let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                    (percent_decode(k), percent_decode(v))
                })
                .collect(),
            headers: Vec::new(),
            body,
        }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Request {
        self.headers
            .push((name.to_ascii_lowercase(), value.to_string()));
        self
    }

    fn param(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn wants_cbor(&self) -> bool {
        self.header("accept").is_some_and(|a| a.contains("cbor"))
    }

    fn wants_html(&self) -> bool {
        prefers_html(self.header("accept"))
    }
}

/// Content negotiation between `application/json` and `text/html`: HTML only
/// when the client asks for it with a higher quality than JSON (a browser
/// sends `text/html` at 1 and `*/*` at 0.8). No `Accept`, `*/*` and ties give JSON.
pub fn prefers_html(accept: Option<&str>) -> bool {
    let Some(accept) = accept else {
        return false;
    };
    let (mut html, mut json) = (0.0f32, 0.0f32);
    for item in accept.split(',') {
        let mut parts = item.split(';');
        let ty = parts.next().unwrap_or("").trim().to_ascii_lowercase();
        let q = parts
            .filter_map(|p| p.trim().strip_prefix("q="))
            .find_map(|v| v.trim().parse::<f32>().ok())
            .unwrap_or(1.0);
        match ty.as_str() {
            "text/html" | "text/*" => html = html.max(q),
            "application/json" | "application/*" | "*/*" => json = json.max(q),
            _ => {}
        }
    }
    html > json
}

pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).ok();
                if let Some(v) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    out.push(v);
                    i += 3;
                    continue;
                }
                out.push(b'%');
            }
            b'+' => out.push(b' '),
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub struct Response {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
    /// Extra response headers. A `Cache-Control` entry replaces the default `no-store`.
    pub headers: Vec<(String, String)>,
}

impl Response {
    fn json(status: u16, v: J) -> Response {
        Response {
            status,
            content_type: "application/json".into(),
            body: serde_json::to_vec_pretty(&v).unwrap_or_default(),
            headers: Vec::new(),
        }
    }

    fn cbor(status: u16, ct: &str, body: Vec<u8>) -> Response {
        Response {
            status,
            content_type: ct.into(),
            body,
            headers: Vec::new(),
        }
    }

    fn error(status: u16, code: &str, detail: impl Into<String>) -> Response {
        Response::json(status, json!({ "error": code, "detail": detail.into() }))
    }

    fn html(status: u16, body: String) -> Response {
        Response {
            status,
            content_type: "text/html; charset=utf-8".into(),
            body: body.into_bytes(),
            headers: Vec::new(),
        }
    }

    fn with_header(mut self, name: &str, value: &str) -> Response {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn json_body(&self) -> Option<J> {
        serde_json::from_slice(&self.body).ok()
    }
}

/// Anchor records of a checkpoint (anchoring hooks, spec section 9): empty unless the log has a witness.
fn anchors_json(log: &Log, hash: &[u8; 32]) -> Vec<J> {
    log.anchors_for(hash)
        .iter()
        .map(|a| {
            json!({
                "checkpoint-hash": hex::encode(a.record.checkpoint_hash),
                "chain-id": a.record.chain_id,
                "transaction-id": a.record.transaction_id,
                "block-height": a.record.block_height,
                "anchored-at": a.record.anchored_at,
                "anchor": b64(&a.raw),
            })
        })
        .collect()
}

fn checkpoint_json(c: &CheckpointRec, log: &AgentId, anchors: Vec<J>) -> J {
    json!({
        "log": log.to_text(),
        "tree-size": c.size,
        "root-hash": hex::encode(c.root),
        "timestamp": c.timestamp,
        "checkpoint": b64(&c.raw),
        "checkpoint-hash": hex::encode(c.hash),
        "anchors": anchors,
    })
}

fn proof_json(index: u64, leaf: &[u8; 32], p: &InclusionProof) -> J {
    json!({
        "leaf-index": index,
        "leaf-hash": hex::encode(leaf),
        "audit-path": p.audit_path.iter().map(hex::encode).collect::<Vec<_>>(),
        "proof": b64(&p.to_value().encode()),
    })
}

fn log_err(e: LogError) -> Response {
    Response::error(500, "log_error", e.to_string())
}

fn submit_err(e: SubmitError) -> Response {
    let status = match e.code {
        "too_large" => 413,
        "malformed" => 400,
        _ => 422,
    };
    let mut body = json!({ "error": e.code, "detail": e.detail });
    if let Some(r) = &e.rejection {
        body["step"] = json!(r.step);
        body["rejection"] = json!(r.code.as_str());
    }
    Response::json(status, body)
}

fn parse_u64(req: &Request, name: &str) -> Result<Option<u64>, Response> {
    match req.param(name) {
        None => Ok(None),
        Some(v) => v.parse::<u64>().map(Some).map_err(|_| {
            Response::error(
                400,
                "bad_parameter",
                format!("`{name}` must be a non-negative integer"),
            )
        }),
    }
}

fn parse_leaf(s: &str) -> Option<[u8; 32]> {
    hex::decode(s).ok()?.try_into().ok()
}

fn submit_response(req: &Request, out: &SubmitOutcome) -> Response {
    let status = if out.duplicate { 200 } else { 201 };
    if req.wants_cbor() {
        return Response::cbor(status, "application/cbor", out.proof_cbor());
    }
    let mut j = proof_json(out.index, &out.leaf, &out.proof);
    j["status"] = json!(if out.duplicate {
        "duplicate"
    } else {
        "accepted"
    });
    Response::json(status, j)
}

/// Route one request. `now` is Unix seconds.
pub fn handle(log: &Mutex<Log>, req: &Request, now: i64) -> Response {
    let mut log = match log.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    route(&mut log, req, now)
}

fn route(log: &mut Log, req: &Request, now: i64) -> Response {
    let id = log.log_id();
    let Some((rid, params)) = routes::resolve(&req.method, &req.path) else {
        let p = req.path.as_str();
        return if p.starts_with("/v1/") || p == "/" {
            Response::error(
                404,
                "not_found",
                format!("no such endpoint: {} {p}", req.method),
            )
        } else {
            Response::error(404, "not_found", "unknown path")
        };
    };
    let param = |name: &str| {
        params
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.as_str())
            .unwrap_or("")
    };
    match rid {
        RouteId::Index => Response::json(
            200,
            json!({
                "service": "atep-logd",
                "log": id.to_text(),
                "openapi": "/openapi.json",
                "endpoints": routes::ROUTES
                    .iter()
                    .map(|r| format!("{} {}", r.method, r.path))
                    .collect::<Vec<_>>(),
            }),
        ),
        RouteId::OpenApi => Response::json(200, crate::openapi::document()),
        RouteId::ClaimResolve => claim_response(req, param("claim"), true),
        RouteId::ClaimsIndex => claims_index_response(req),
        RouteId::ClaimCore => {
            claim_response(req, &format!("{}{}", claims::NS, param("name")), false)
        }
        RouteId::ClaimRobotics => claim_response(
            req,
            &format!("{}{}", claims::robotics::NS, param("name")),
            false,
        ),
        RouteId::Submit => {
            let raw = if req
                .header("content-type")
                .is_some_and(|c| c.contains("json"))
            {
                let Ok(j) = serde_json::from_slice::<J>(&req.body) else {
                    return Response::error(400, "malformed", "body is not JSON");
                };
                match j.get("envelope").and_then(|e| e.as_str()).and_then(unb64) {
                    Some(r) => r,
                    None => {
                        return Response::error(
                            400,
                            "malformed",
                            "JSON body needs `envelope`, the base64url envelope",
                        )
                    }
                }
            } else {
                req.body.clone()
            };
            match log.submit(&raw, now) {
                Ok(out) => submit_response(req, &out),
                Err(SubmitErr::Rejected(e)) => submit_err(e),
                Err(SubmitErr::Log(e)) => log_err(e),
            }
        }
        RouteId::CheckpointGet => {
            if log.checkpoint_due(now) {
                if let Err(e) = log.checkpoint(now) {
                    return log_err(e);
                }
            }
            let Some(c) = log.latest_checkpoint() else {
                return Response::error(503, "no_checkpoint", "no checkpoint yet");
            };
            if req.wants_cbor() {
                return Response::cbor(200, "application/atep-checkpoint+cbor", c.raw.clone());
            }
            let c = c.clone();
            Response::json(200, checkpoint_json(&c, &id, anchors_json(log, &c.hash)))
        }
        RouteId::CheckpointPost => match log.checkpoint(now) {
            Ok(c) => {
                let c = c.clone();
                if req.wants_cbor() {
                    Response::cbor(201, "application/atep-checkpoint+cbor", c.raw.clone())
                } else {
                    Response::json(201, checkpoint_json(&c, &id, anchors_json(log, &c.hash)))
                }
            }
            Err(e) => log_err(e),
        },
        RouteId::Checkpoints => {
            let from = match parse_u64(req, "from") {
                Ok(v) => v.unwrap_or(0),
                Err(r) => return r,
            };
            let list: Vec<J> = log
                .checkpoints()
                .iter()
                .filter(|c| c.size >= from)
                .take(MAX_ENTRIES_PER_REQUEST as usize)
                .map(|c| checkpoint_json(c, &id, anchors_json(log, &c.hash)))
                .collect();
            Response::json(200, json!({ "log": id.to_text(), "checkpoints": list }))
        }
        RouteId::ProofInclusion => {
            let leaf = match (req.param("leaf-hash"), req.param("index")) {
                (Some(h), _) => match parse_leaf(h) {
                    Some(l) => l,
                    None => {
                        return Response::error(
                            400,
                            "bad_parameter",
                            "`leaf-hash` must be 64 hex characters",
                        )
                    }
                },
                (None, Some(i)) => match i
                    .parse::<usize>()
                    .ok()
                    .and_then(|i| log.entries_meta().get(i))
                {
                    Some(m) => m.leaf,
                    None => return Response::error(404, "not_found", "no such entry"),
                },
                _ => {
                    return Response::error(400, "bad_parameter", "`leaf-hash` or `index` required")
                }
            };
            match log.inclusion_proof(&leaf, now) {
                Ok(Some((index, p))) => {
                    if req.wants_cbor() {
                        return Response::cbor(200, "application/cbor", p.to_value().encode());
                    }
                    let mut j = proof_json(index, &leaf, &p);
                    if let Some(c) = log.latest_checkpoint() {
                        j["tree-size"] = json!(c.size);
                        j["checkpoint"] = json!(b64(&c.raw));
                    }
                    Response::json(200, j)
                }
                Ok(None) => Response::error(404, "not_found", "leaf hash is not in the log"),
                Err(e) => log_err(e),
            }
        }
        RouteId::ProofConsistency => {
            let (from, to) = match (parse_u64(req, "from"), parse_u64(req, "to")) {
                (Ok(Some(f)), Ok(Some(t))) => (f, t),
                (Err(r), _) | (_, Err(r)) => return r,
                _ => return Response::error(400, "bad_parameter", "`from` and `to` required"),
            };
            match log.consistency(from, to) {
                Ok(p) => consistency_response(req, log, p),
                Err(m) => Response::error(400, "bad_parameter", m),
            }
        }
        RouteId::Entries => {
            let from = match parse_u64(req, "from") {
                Ok(v) => v.unwrap_or(0),
                Err(r) => return r,
            };
            let size = log.tree_size();
            let to = match parse_u64(req, "to") {
                Ok(v) => v.unwrap_or(size).min(size),
                Err(r) => return r,
            };
            if from > to {
                return Response::error(400, "bad_parameter", "`from` is greater than `to`");
            }
            let to = to.min(from + MAX_ENTRIES_PER_REQUEST);
            let mut list = Vec::new();
            for i in from..to {
                let m = log.entries_meta()[i as usize].clone();
                match log.read_entry(i) {
                    Ok(raw) => list.push(entry_json(&m, Some(&raw))),
                    Err(e) => return log_err(e),
                }
            }
            Response::json(
                200,
                json!({ "from": from, "to": to, "tree-size": size, "entries": list }),
            )
        }
        RouteId::Lookup => {
            let Some(s) = req.param("subject") else {
                return Response::error(400, "bad_parameter", "`subject` (an Agent ID) required");
            };
            let Ok(subject) = AgentId::parse(s) else {
                return Response::error(400, "bad_parameter", "`subject` is not an Agent ID");
            };
            let claim = req
                .param("claim")
                .map(atep_core::attestation::claims::expand);
            let metas: Vec<_> = log
                .entries_by_subject(&subject)
                .into_iter()
                .filter(|m| claim.as_ref().is_none_or(|c| m.claim.as_ref() == Some(c)))
                .cloned()
                .collect();
            let mut list = Vec::new();
            for m in metas {
                match log.read_entry(m.index) {
                    Ok(raw) => list.push(entry_json(&m, Some(&raw))),
                    Err(e) => return log_err(e),
                }
            }
            Response::json(
                200,
                json!({ "subject": subject.to_text(), "tree-size": log.tree_size(), "entries": list }),
            )
        }
        RouteId::Issuers => {
            let mut j = issuers(log);
            if let Some(f) = req.param("issuer") {
                if let Some(a) = j["issuers"].as_array_mut() {
                    a.retain(|r| r["issuer"] == f);
                }
            }
            Response::json(200, j)
        }
        RouteId::ClaimsDirectory => Response::json(200, claim_types(log)),
        RouteId::Policy => policy_response(log, now),
        RouteId::GossipGet => {
            let observed: Vec<J> = log
                .gossip_state()
                .all()
                .iter()
                .map(|s| {
                    json!({
                        "log": s.log.to_text(), "tree-size": s.size,
                        "root-hash": hex::encode(s.root), "timestamp": s.timestamp,
                        "checkpoint": b64(&s.raw),
                    })
                })
                .collect();
            let evidence: Vec<J> = log
                .gossip_state()
                .evidence()
                .iter()
                .map(|e| json!({ "log": e.log.to_text(), "reason": e.reason, "pair": b64(&e.to_pair_cbor()) }))
                .collect();
            let own = log
                .latest_checkpoint()
                .map(|c| checkpoint_json(c, &id, anchors_json(log, &c.hash)));
            Response::json(
                200,
                json!({ "log": id.to_text(), "latest": own, "observed": observed, "evidence": evidence }),
            )
        }
        RouteId::GossipPost => gossip_post(log, req, now),
    }
}

/// Resolve one claim type. `input` is a full URI or, for the `/v1/claims/`
/// route (`short`), a short name. A trailing `.html` or `.json` selects the
/// format; otherwise the `Accept` header does.
fn claim_response(req: &Request, input: &str, short: bool) -> Response {
    let lookup = |x: &str| {
        if short {
            claimdefs::resolve(x)
        } else {
            claimdefs::find_uri(x)
        }
    };
    let mut forced: Option<bool> = None;
    let mut def = lookup(input);
    if def.is_none() {
        for (suffix, html) in [(".html", true), (".json", false)] {
            if let Some(stripped) = input.strip_suffix(suffix) {
                def = lookup(stripped);
                forced = Some(html);
                break;
            }
        }
    }
    let Some(def) = def else {
        return Response::error(
            404,
            "claim_unknown",
            format!(
                "no definition for `{input}`; the registry defines the 14 core claim types of {}, see GET /claims",
                claims::NS
            ),
        );
    };
    let html = forced.unwrap_or_else(|| req.wants_html());
    let r = if html {
        Response::html(200, claimdefs::definition_html(def))
    } else {
        Response::json(200, claimdefs::definition_json(def))
    };
    r.with_header("Vary", "Accept")
        .with_header("Cache-Control", "public, max-age=3600")
}

fn claims_index_response(req: &Request) -> Response {
    let r = if req.wants_html() {
        Response::html(200, claimdefs::index_html())
    } else {
        Response::json(200, claimdefs::index_json())
    };
    r.with_header("Vary", "Accept")
        .with_header("Cache-Control", "public, max-age=3600")
}

fn consistency_response(req: &Request, log: &Log, p: ConsistencyProof) -> Response {
    if req.wants_cbor() {
        return Response::cbor(200, "application/cbor", p.to_value().encode());
    }
    Response::json(
        200,
        json!({
            "from": p.from,
            "to": p.to,
            "first-hash": hex::encode(log.root_at(p.from as u64)),
            "second-hash": hex::encode(log.root_at(p.to as u64)),
            "path": p.path.iter().map(hex::encode).collect::<Vec<_>>(),
            "proof": b64(&p.to_value().encode()),
        }),
    )
}

fn policy_response(log: &mut Log, now: i64) -> Response {
    let Some(m) = log.policy_entry().cloned() else {
        return Response::error(404, "not_found", "no policy recorded");
    };
    let raw = match log.read_entry(m.index) {
        Ok(r) => r,
        Err(e) => return log_err(e),
    };
    let proof = match log.inclusion_proof(&m.leaf, now) {
        Ok(Some((_, p))) => Some(p),
        _ => None,
    };
    let data = atep_core::envelope::SignedEnvelope::decode(&raw)
        .ok()
        .and_then(|e| e.payload)
        .and_then(|p| atep_core::attestation::Attestation::from_payload(&p).ok())
        .map(|a| atep_core::json::generic(&a.data))
        .unwrap_or(J::Null);
    let first = log.entries_meta().first().is_some_and(|f| f.leaf == m.leaf);
    Response::json(
        200,
        json!({
            "log": log.log_id().to_text(),
            "claim": crate::admit::POLICY_CLAIM,
            "entry-index": m.index,
            "first-entry": first,
            "leaf-hash": hex::encode(m.leaf),
            "issued-at": m.issued_at,
            "expires-at": m.expires_at,
            "policy": data,
            "envelope": b64(&raw),
            "proof": proof.map(|p| b64(&p.to_value().encode())),
        }),
    )
}

fn gossip_post(log: &mut Log, req: &Request, now: i64) -> Response {
    let Ok(j) = serde_json::from_slice::<J>(&req.body) else {
        return Response::error(400, "malformed", "body is not JSON");
    };
    let mut raws: Vec<Vec<u8>> = Vec::new();
    if let Some(a) = j.get("checkpoints").and_then(|c| c.as_array()) {
        raws.extend(a.iter().filter_map(|c| c.as_str().and_then(unb64)));
    }
    if let Some(c) = j.get("checkpoint").and_then(|c| c.as_str()).and_then(unb64) {
        raws.push(c);
    }
    if raws.is_empty() {
        return Response::error(
            400,
            "malformed",
            "`checkpoints` (base64url envelopes) required",
        );
    }
    let proofs = ProofList(
        j.get("proofs")
            .and_then(|p| p.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|p| p.as_str().and_then(unb64))
                    .filter_map(|b| atep_core::cbor::Value::decode(&b).ok())
                    .filter_map(|v| ConsistencyProof::from_value(&v).ok())
                    .collect()
            })
            .unwrap_or_default(),
    );
    let mut results = Vec::new();
    let mut split = false;
    for raw in raws {
        match log.observe_checkpoint(&raw, now, &proofs) {
            Ok(obs) => {
                let seen = crate::gossip::parse_checkpoint(&raw, now).ok();
                let mut r = json!({
                    "log": seen.as_ref().map(|s| s.log.to_text()),
                    "tree-size": seen.as_ref().map(|s| s.size),
                });
                match obs {
                    Observation::New => r["result"] = json!("new"),
                    Observation::Known => r["result"] = json!("known"),
                    Observation::Split(ev) => {
                        split = true;
                        r["result"] = json!("split-view");
                        r["reason"] = json!(ev.reason);
                        r["evidence"] = json!(b64(&ev.to_pair_cbor()));
                    }
                }
                results.push(r);
            }
            Err(rej) => results.push(json!({
                "result": "rejected", "error": rej.code.as_str(), "detail": rej.to_string(),
            })),
        }
    }
    let mut ours: Vec<J> = Vec::new();
    let id = log.log_id();
    if let Some(c) = log.latest_checkpoint() {
        ours.push(json!(b64(&c.raw)));
    }
    ours.extend(log.gossip_state().all().iter().map(|s| json!(b64(&s.raw))));
    Response::json(
        if split { 409 } else { 200 },
        json!({ "log": id.to_text(), "split-view": split, "results": results, "checkpoints": ours }),
    )
}

// ---------------------------------------------------------------------------
// Sockets

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        404 => "Not Found",
        409 => "Conflict",
        411 => "Length Required",
        413 => "Payload Too Large",
        422 => "Unprocessable Entity",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

fn read_request(stream: &mut TcpStream) -> Result<Request, Response> {
    let bad = |c: u16, m: &str| Response::error(c, "bad_request", m);
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p;
        }
        if buf.len() > MAX_HEADER {
            return Err(bad(413, "headers too large"));
        }
        let n = stream
            .read(&mut chunk)
            .map_err(|_| bad(400, "read error"))?;
        if n == 0 {
            return Err(bad(
                400,
                "connection closed before the request was complete",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let first = lines.next().unwrap_or("");
    let mut parts = first.split(' ');
    let (Some(method), Some(target), Some(ver)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(bad(400, "malformed request line"));
    };
    if !ver.starts_with("HTTP/1.") {
        return Err(bad(400, "only HTTP/1.x is supported"));
    }
    let mut req = Request::new(method, target, Vec::new());
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            req.headers
                .push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    if req.header("transfer-encoding").is_some() {
        return Err(bad(
            501,
            "chunked bodies are not supported, send Content-Length",
        ));
    }
    let len = match req.header("content-length") {
        Some(v) => v
            .parse::<usize>()
            .map_err(|_| bad(400, "bad Content-Length"))?,
        None if req.method == "POST" => return Err(bad(411, "POST needs Content-Length")),
        None => 0,
    };
    if len > MAX_BODY {
        return Err(bad(413, "body too large"));
    }
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < len {
        let n = stream
            .read(&mut chunk)
            .map_err(|_| bad(400, "read error"))?;
        if n == 0 {
            return Err(bad(400, "body shorter than Content-Length"));
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(len);
    req.body = body;
    Ok(req)
}

fn write_response(stream: &mut TcpStream, head_only: bool, r: &Response) {
    let mut extra = String::new();
    let mut cache = "Cache-Control: no-store\r\n".to_string();
    for (k, v) in &r.headers {
        // Header values never come from requests; strip line breaks anyway.
        let line = format!("{k}: {}\r\n", v.replace(['\r', '\n'], " "));
        if k.eq_ignore_ascii_case("cache-control") {
            cache = line;
        } else {
            extra.push_str(&line);
        }
    }
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\n{cache}{extra}\r\n",
        r.status,
        reason(r.status),
        r.content_type,
        r.body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    if !head_only {
        let _ = stream.write_all(&r.body);
    }
    let _ = stream.flush();
}

pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// A running server. Dropping it (or calling [`ServerHandle::stop`]) stops
/// the accept loop and the periodic checkpoint thread.
pub struct ServerHandle {
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl ServerHandle {
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the accept loop.
        let _ = TcpStream::connect(self.addr);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Bind `addr` and serve `log` on background threads. Also runs the periodic
/// checkpoint task: a fresh checkpoint whenever the configured interval has
/// passed (and on demand through the API).
pub fn spawn(log: Arc<Mutex<Log>>, addr: &str, clock: Clock) -> std::io::Result<ServerHandle> {
    let listener = TcpListener::bind(addr)?;
    let local = listener.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let mut threads = Vec::new();

    let (s, l, c) = (stop.clone(), log.clone(), clock.clone());
    threads.push(thread::spawn(move || {
        for incoming in listener.incoming() {
            if s.load(Ordering::SeqCst) {
                break;
            }
            let Ok(mut stream) = incoming else { continue };
            let (l, c) = (l.clone(), c.clone());
            thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(15)));
                let head_only;
                let resp = match read_request(&mut stream) {
                    Ok(req) => {
                        head_only = req.method == "HEAD";
                        handle(&l, &req, c())
                    }
                    Err(r) => {
                        head_only = false;
                        r
                    }
                };
                write_response(&mut stream, head_only, &resp);
            });
        }
    }));

    let (s, l, c) = (stop.clone(), log, clock);
    threads.push(thread::spawn(move || {
        let mut tick = 0u32;
        while !s.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(100));
            tick += 1;
            if !tick.is_multiple_of(10) {
                continue;
            }
            let now = c();
            let mut g = match l.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            if g.checkpoint_due(now) {
                if let Err(e) = g.checkpoint(now) {
                    eprintln!("atep-logd: periodic checkpoint failed: {e}");
                } else if let Err(e) = g.witness_latest(now) {
                    eprintln!("atep-logd: witness failed: {e}");
                }
            }
        }
    }));
    Ok(ServerHandle {
        addr: local,
        stop,
        threads,
    })
}
