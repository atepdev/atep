//! A minimal HTTP/1.1 client for the log API, on `std::net` (plain `http://`
//! only; put a local TLS-terminating proxy in front of an https log).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::Duration;

use atep_core::cbor::Value;
use atep_core::error::{ErrorCode, Rejection};
use atep_core::keys::{AgentId, PublicBundle};
use atep_core::log::{
    hash_leaf, CheckpointUsed, ConsistencyProof, InclusionCheck, InclusionProof, OfflineInclusion,
};
use serde_json::{json, Value as J};

use crate::gossip::{NoProofs, Observation, ProofSource};
use crate::log::Log;
use crate::{b64, unb64};

#[derive(Debug, Clone)]
pub struct ClientError(pub String);

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ClientError {}

type R<T> = Result<T, ClientError>;

fn err<T>(m: impl Into<String>) -> R<T> {
    Err(ClientError(m.into()))
}

#[derive(Clone, Debug)]
pub struct LogClient {
    host: String,
    prefix: String,
}

pub struct HttpReply {
    pub status: u16,
    pub body: Vec<u8>,
}

impl HttpReply {
    pub fn json(&self) -> R<J> {
        serde_json::from_slice(&self.body)
            .map_err(|e| ClientError(format!("reply is not JSON: {e}")))
    }
}

impl LogClient {
    /// `url` is `http://host:port` with an optional path prefix.
    pub fn new(url: &str) -> R<LogClient> {
        let Some(rest) = url.strip_prefix("http://") else {
            return err("only http:// URLs are supported (terminate TLS in a local proxy)");
        };
        let (host, prefix) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].trim_end_matches('/')),
            None => (rest, ""),
        };
        let host = if host.contains(':') {
            host.to_string()
        } else {
            format!("{host}:80")
        };
        Ok(LogClient {
            host,
            prefix: prefix.to_string(),
        })
    }

    pub fn request(
        &self,
        method: &str,
        path: &str,
        ct: Option<&str>,
        accept: Option<&str>,
        body: &[u8],
    ) -> R<HttpReply> {
        let mut s = TcpStream::connect(&self.host)
            .map_err(|e| ClientError(format!("connect {}: {e}", self.host)))?;
        let _ = s.set_read_timeout(Some(Duration::from_secs(30)));
        let mut head = format!(
            "{method} {}{path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
            self.prefix, self.host
        );
        if let Some(a) = accept {
            head.push_str(&format!("Accept: {a}\r\n"));
        }
        if method == "POST" {
            head.push_str(&format!(
                "Content-Type: {}\r\nContent-Length: {}\r\n",
                ct.unwrap_or("application/octet-stream"),
                body.len()
            ));
        }
        head.push_str("\r\n");
        s.write_all(head.as_bytes())
            .and_then(|_| s.write_all(body))
            .map_err(|e| ClientError(format!("write: {e}")))?;
        let mut data = Vec::new();
        s.read_to_end(&mut data)
            .map_err(|e| ClientError(format!("read: {e}")))?;
        let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") else {
            return err("malformed HTTP reply");
        };
        let head = String::from_utf8_lossy(&data[..end]);
        let status = head
            .split(' ')
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .ok_or_else(|| ClientError("malformed status line".into()))?;
        Ok(HttpReply {
            status,
            body: data[end + 4..].to_vec(),
        })
    }

    pub fn get(&self, path: &str) -> R<HttpReply> {
        self.request("GET", path, None, None, &[])
    }

    fn get_cbor(&self, path: &str) -> R<Vec<u8>> {
        let r = self.request("GET", path, None, Some("application/cbor"), &[])?;
        if r.status != 200 {
            return err(format!("GET {path}: HTTP {}", r.status));
        }
        Ok(r.body)
    }

    pub fn get_json(&self, path: &str) -> R<J> {
        let r = self.get(path)?;
        if r.status != 200 {
            return err(format!(
                "GET {path}: HTTP {}: {}",
                r.status,
                String::from_utf8_lossy(&r.body)
            ));
        }
        r.json()
    }

    /// Latest signed checkpoint envelope.
    pub fn checkpoint(&self) -> R<Vec<u8>> {
        self.get_cbor("/v1/checkpoint")
    }

    /// Signed checkpoints with tree size at least `from`, oldest first.
    pub fn checkpoints_since(&self, from: u64) -> R<Vec<Vec<u8>>> {
        let j = self.get_json(&format!("/v1/checkpoints?from={from}"))?;
        Ok(j["checkpoints"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|c| c["checkpoint"].as_str().and_then(unb64))
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Checkpoints with tree size at least `from` and their anchor records
    /// (empty lists for a log that does not anchor). Anchor envelopes are
    /// verified; a malformed or badly signed one is an error.
    pub fn checkpoint_anchors_since(&self, from: u64) -> R<Vec<crate::anchor::CheckpointAnchors>> {
        let j = self.get_json(&format!("/v1/checkpoints?from={from}"))?;
        let mut out = Vec::new();
        for c in j["checkpoints"].as_array().into_iter().flatten() {
            let hash = c["checkpoint-hash"]
                .as_str()
                .and_then(|h| hex::decode(h).ok())
                .and_then(|h| <[u8; 32]>::try_from(h).ok());
            let (Some(size), Some(hash)) = (c["tree-size"].as_u64(), hash) else {
                return err("checkpoint without tree-size or checkpoint-hash in reply");
            };
            let mut anchors = Vec::new();
            for a in c["anchors"].as_array().into_iter().flatten() {
                let Some(raw) = a["anchor"].as_str().and_then(unb64) else {
                    return err("anchor without envelope in reply");
                };
                let (_, rec) = crate::anchor::parse_anchor_envelope(&raw, i64::MAX / 2)
                    .map_err(|e| ClientError(e.to_string()))?;
                anchors.push(rec);
            }
            out.push(crate::anchor::CheckpointAnchors {
                tree_size: size,
                checkpoint_hash: hash,
                anchors,
            });
        }
        Ok(out)
    }

    pub fn consistency(&self, from: u64, to: u64) -> R<ConsistencyProof> {
        let b = self.get_cbor(&format!("/v1/proof/consistency?from={from}&to={to}"))?;
        let v = Value::decode(&b).map_err(|e| ClientError(e.to_string()))?;
        ConsistencyProof::from_value(&v).map_err(|e| ClientError(e.0))
    }

    /// Entries `from..to` as (index, submitted envelope bytes), at most 1000 per call.
    pub fn entries(&self, from: u64, to: u64) -> R<Vec<(u64, Vec<u8>)>> {
        let j = self.get_json(&format!("/v1/entries?from={from}&to={to}"))?;
        let mut out = Vec::new();
        for e in j["entries"].as_array().into_iter().flatten() {
            let (Some(i), Some(raw)) =
                (e["index"].as_u64(), e["envelope"].as_str().and_then(unb64))
            else {
                return err("malformed entry in reply");
            };
            out.push((i, raw));
        }
        Ok(out)
    }

    pub fn tree_size(&self) -> R<u64> {
        let j = self.get_json("/v1/checkpoint")?;
        j["tree-size"]
            .as_u64()
            .ok_or_else(|| ClientError("no tree-size".into()))
    }

    /// Submit an envelope. Returns the CBOR inclusion proof value and whether
    /// the entry already existed.
    pub fn submit(&self, envelope: &[u8]) -> R<(InclusionProof, bool)> {
        let r = self.request(
            "POST",
            "/v1/submit",
            Some("application/cbor"),
            Some("application/cbor"),
            envelope,
        )?;
        match r.status {
            200 | 201 => {
                let v = Value::decode(&r.body).map_err(|e| ClientError(e.to_string()))?;
                let p = InclusionProof::from_value(&v).map_err(|e| ClientError(e.0))?;
                Ok((p, r.status == 200))
            }
            s => err(format!(
                "submit refused (HTTP {s}): {}",
                String::from_utf8_lossy(&r.body)
            )),
        }
    }

    pub fn inclusion_proof(&self, leaf: &[u8; 32]) -> R<InclusionProof> {
        let b = self.get_cbor(&format!(
            "/v1/proof/inclusion?leaf-hash={}",
            hex::encode(leaf)
        ))?;
        let v = Value::decode(&b).map_err(|e| ClientError(e.to_string()))?;
        InclusionProof::from_value(&v).map_err(|e| ClientError(e.0))
    }
}

impl ProofSource for LogClient {
    fn consistency_proof(&self, from: u64, to: u64) -> Option<ConsistencyProof> {
        self.consistency(from, to).ok()
    }
}

/// Online inclusion check against a remote log: fetches the proof for the
/// submitted envelope and verifies it offline against `trusted_logs`.
pub struct RemoteInclusion {
    pub client: LogClient,
    pub trusted_logs: Vec<AgentId>,
    pub known_bundles: Vec<PublicBundle>,
}

impl InclusionCheck for RemoteInclusion {
    fn check(
        &self,
        submitted: &[u8],
        _proof: Option<&Value>,
        now: i64,
    ) -> Result<CheckpointUsed, Rejection> {
        let p = self
            .client
            .inclusion_proof(&hash_leaf(submitted))
            .map_err(|e| Rejection::new(9, ErrorCode::InclusionProofMissing, e.to_string()))?;
        OfflineInclusion {
            trusted_logs: self.trusted_logs.clone(),
            known_bundles: self.known_bundles.clone(),
        }
        .check(submitted, Some(&p.to_value()), now)
    }
}

/// Exchange checkpoints with a remote log over HTTP: ask what it has seen of
/// us, send our latest checkpoint with the consistency proofs it needs, then
/// check every checkpoint it returns against what we know.
pub fn exchange_remote(
    local: &Mutex<Log>,
    peer: &LogClient,
    now: i64,
) -> Result<crate::gossip::ExchangeReport, ClientError> {
    let mut report = crate::gossip::ExchangeReport::default();
    let (own_raw, proofs) = {
        let l = local.lock().unwrap_or_else(|p| p.into_inner());
        let Some(c) = l.latest_checkpoint() else {
            return err("local log has no checkpoint");
        };
        let id = l.log_id().to_text();
        let theirs = peer.get_json("/v1/gossip")?;
        let mut proofs = Vec::new();
        for o in theirs["observed"].as_array().into_iter().flatten() {
            if o["log"] == id {
                if let Some(s) = o["tree-size"].as_u64() {
                    if let Ok(p) = l.consistency(s.min(c.size), s.max(c.size)) {
                        proofs.push(b64(&p.to_value().encode()));
                    }
                }
            }
        }
        (c.raw.clone(), proofs)
    };
    let mut cps = vec![b64(&own_raw)];
    {
        let l = local.lock().unwrap_or_else(|p| p.into_inner());
        cps.extend(l.gossip_state().all().iter().map(|s| b64(&s.raw)));
    }
    let body = json!({ "checkpoints": cps, "proofs": proofs }).to_string();
    let r = peer.request(
        "POST",
        "/v1/gossip",
        Some("application/json"),
        None,
        body.as_bytes(),
    )?;
    if r.status != 200 && r.status != 409 {
        return err(format!("gossip POST: HTTP {}", r.status));
    }
    let reply = r.json()?;
    if reply["split-view"] == true {
        // The peer saw a split view among what we sent; evidence is in its reply.
        for res in reply["results"].as_array().into_iter().flatten() {
            if let Some(ev) = res["evidence"].as_str().and_then(unb64) {
                let log = res["log"].as_str().and_then(|s| AgentId::parse(s).ok());
                if let Some(log) = log {
                    if let Some(e) = crate::gossip::SplitEvidence::from_pair_cbor(log, &ev) {
                        report.splits.push(e);
                    }
                }
            }
        }
    }
    let peer_id = reply["log"].as_str().unwrap_or("").to_string();
    for c in reply["checkpoints"].as_array().into_iter().flatten() {
        let Some(raw) = c.as_str().and_then(unb64) else {
            continue;
        };
        let is_peer_own = crate::gossip::parse_checkpoint(&raw, now)
            .map(|s| s.log.to_text() == peer_id)
            .unwrap_or(false);
        let mut l = local.lock().unwrap_or_else(|p| p.into_inner());
        let src: &dyn ProofSource = if is_peer_own { peer } else { &NoProofs };
        match l.observe_checkpoint(&raw, now, src) {
            Ok(Observation::New) => report.new_checkpoints += 1,
            Ok(Observation::Known) => {}
            Ok(Observation::Split(ev)) => report.splits.push(*ev),
            Err(_) => report.rejected += 1,
        }
    }
    Ok(report)
}
