//! Where a monitor reads the log from: the HTTP API, a log data directory
//! (read-only, no log identity needed) or an in-process [`Log`].

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use atep_core::log::{consistency_proof, hash_leaf, ConsistencyProof};
use atep_log::anchor::{parse_anchor_envelope, CheckpointAnchors};
use atep_log::client::LogClient;
use atep_log::store::RecordFile;
use atep_log::Log;

#[derive(Debug, Clone)]
pub struct SourceError(pub String);

impl std::fmt::Display for SourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for SourceError {}

pub trait LogSource {
    /// Latest signed checkpoint envelope.
    fn latest_checkpoint(&self) -> Result<Vec<u8>, SourceError>;
    /// Published checkpoint envelopes with tree size at least `from`, oldest first.
    fn checkpoints_since(&self, from: u64) -> Result<Vec<Vec<u8>>, SourceError>;
    fn consistency(&self, from: u64, to: u64) -> Result<ConsistencyProof, SourceError>;
    /// Entries `from..to` as submitted envelope bytes.
    fn entries(&self, from: u64, to: u64) -> Result<Vec<Vec<u8>>, SourceError>;
    /// Published checkpoints with tree size at least `from`, with their
    /// anchor records (anchoring hooks, spec section 9). Anchor lists are empty for a log that
    /// does not anchor, which is every log today.
    ///
    /// The default reports none, so existing implementations keep working.
    fn anchors(&self, _from: u64) -> Result<Vec<CheckpointAnchors>, SourceError> {
        Ok(Vec::new())
    }
}

fn se(e: impl std::fmt::Display) -> SourceError {
    SourceError(e.to_string())
}

pub struct HttpSource(pub LogClient);

impl HttpSource {
    pub fn new(url: &str) -> Result<HttpSource, SourceError> {
        Ok(HttpSource(LogClient::new(url).map_err(se)?))
    }
}

impl LogSource for HttpSource {
    fn latest_checkpoint(&self) -> Result<Vec<u8>, SourceError> {
        self.0.checkpoint().map_err(se)
    }

    fn checkpoints_since(&self, from: u64) -> Result<Vec<Vec<u8>>, SourceError> {
        self.0.checkpoints_since(from).map_err(se)
    }

    fn consistency(&self, from: u64, to: u64) -> Result<ConsistencyProof, SourceError> {
        self.0.consistency(from, to).map_err(se)
    }

    fn entries(&self, from: u64, to: u64) -> Result<Vec<Vec<u8>>, SourceError> {
        let list = self.0.entries(from, to).map_err(se)?;
        for (n, (i, _)) in list.iter().enumerate() {
            if *i != from + n as u64 {
                return Err(SourceError("entries are not contiguous".into()));
            }
        }
        Ok(list.into_iter().map(|(_, r)| r).collect())
    }

    fn anchors(&self, from: u64) -> Result<Vec<CheckpointAnchors>, SourceError> {
        self.0.checkpoint_anchors_since(from).map_err(se)
    }
}

/// Reads the files of a log data directory without opening the log.
pub struct DirSource(pub PathBuf);

impl DirSource {
    fn entries_raw(&self) -> Result<Vec<Vec<u8>>, SourceError> {
        let recs = RecordFile::read_all(&self.0.join("entries.rec")).map_err(se)?;
        Ok(recs
            .into_iter()
            .filter(|r| r.payload.len() >= 8)
            .map(|r| r.payload[8..].to_vec())
            .collect())
    }

    fn checkpoints_raw(&self) -> Result<Vec<Vec<u8>>, SourceError> {
        Ok(RecordFile::read_all(&self.0.join("checkpoints.rec"))
            .map_err(se)?
            .into_iter()
            .map(|r| r.payload)
            .collect())
    }
}

impl LogSource for DirSource {
    fn latest_checkpoint(&self) -> Result<Vec<u8>, SourceError> {
        self.checkpoints_raw()?
            .pop()
            .ok_or_else(|| SourceError("no checkpoints in the data directory".into()))
    }

    fn checkpoints_since(&self, from: u64) -> Result<Vec<Vec<u8>>, SourceError> {
        Ok(self
            .checkpoints_raw()?
            .into_iter()
            .filter(|raw| {
                atep_log::gossip::parse_checkpoint(raw, i64::MAX / 2)
                    .map(|s| s.size as u64 >= from)
                    .unwrap_or(true)
            })
            .collect())
    }

    fn consistency(&self, from: u64, to: u64) -> Result<ConsistencyProof, SourceError> {
        let leaves: Vec<[u8; 32]> = self.entries_raw()?.iter().map(|e| hash_leaf(e)).collect();
        if from > to || to as usize > leaves.len() {
            return Err(SourceError("range outside the log".into()));
        }
        Ok(ConsistencyProof {
            from: from as i64,
            to: to as i64,
            path: consistency_proof(from as usize, &leaves[..to as usize]),
        })
    }

    fn entries(&self, from: u64, to: u64) -> Result<Vec<Vec<u8>>, SourceError> {
        let all = self.entries_raw()?;
        let to = (to as usize).min(all.len());
        let from = (from as usize).min(to);
        Ok(all[from..to].to_vec())
    }

    fn anchors(&self, from: u64) -> Result<Vec<CheckpointAnchors>, SourceError> {
        let mut out: Vec<CheckpointAnchors> = Vec::new();
        for raw in self.checkpoints_raw()? {
            let s = atep_log::gossip::parse_checkpoint(&raw, i64::MAX / 2).map_err(se)?;
            if s.size as u64 >= from {
                out.push(CheckpointAnchors {
                    tree_size: s.size as u64,
                    checkpoint_hash: s.hash,
                    anchors: Vec::new(),
                });
            }
        }
        // Old data directories have no anchors file: that means no anchors.
        let path = self.0.join("anchors.rec");
        if path.exists() {
            for rec in RecordFile::read_all(&path).map_err(se)? {
                let (_, a) = parse_anchor_envelope(&rec.payload, i64::MAX / 2).map_err(se)?;
                if let Some(c) = out
                    .iter_mut()
                    .find(|c| c.checkpoint_hash == a.checkpoint_hash)
                {
                    c.anchors.push(a);
                }
            }
        }
        Ok(out)
    }
}

/// Direct library access to a log in the same process.
pub struct LibrarySource(pub Arc<Mutex<Log>>);

impl LibrarySource {
    fn log(&self) -> std::sync::MutexGuard<'_, Log> {
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl LogSource for LibrarySource {
    fn latest_checkpoint(&self) -> Result<Vec<u8>, SourceError> {
        self.log()
            .latest_checkpoint()
            .map(|c| c.raw.clone())
            .ok_or_else(|| SourceError("no checkpoint".into()))
    }

    fn checkpoints_since(&self, from: u64) -> Result<Vec<Vec<u8>>, SourceError> {
        Ok(self
            .log()
            .checkpoints()
            .iter()
            .filter(|c| c.size >= from)
            .map(|c| c.raw.clone())
            .collect())
    }

    fn consistency(&self, from: u64, to: u64) -> Result<ConsistencyProof, SourceError> {
        self.log().consistency(from, to).map_err(SourceError)
    }

    fn entries(&self, from: u64, to: u64) -> Result<Vec<Vec<u8>>, SourceError> {
        let log = self.log();
        let to = to.min(log.tree_size());
        (from..to).map(|i| log.read_entry(i).map_err(se)).collect()
    }

    fn anchors(&self, from: u64) -> Result<Vec<CheckpointAnchors>, SourceError> {
        let log = self.log();
        Ok(log
            .checkpoints()
            .iter()
            .filter(|c| c.size >= from)
            .map(|c| CheckpointAnchors {
                tree_size: c.size,
                checkpoint_hash: c.hash,
                anchors: log
                    .anchors_for(&c.hash)
                    .iter()
                    .map(|a| a.record.clone())
                    .collect(),
            })
            .collect())
    }
}
