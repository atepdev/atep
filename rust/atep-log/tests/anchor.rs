//! Anchoring hooks in the log: canonical checkpoint hash on the API,
//! anchor records (stored, served, log-signed, additive on disk), the
//! `Witness` interface and its no-op default.

use std::sync::{Arc, Mutex};

use atep_core::anchor::AnchorRecord;
use atep_core::consts::CT_CHECKPOINT;
use atep_core::log::checkpoint_hash;
use atep_core::verify::{verify, Policy};
use atep_log::anchor::parse_anchor_envelope;
use atep_log::http::{handle, Request};
use atep_log::store::RecordFile;
use atep_log::testkit::*;
use atep_log::{Log, LogConfig, NoopWitness, Witness, WitnessError};

const NOW: i64 = 1_800_000_000;

fn open(dir: &TempDir, now: i64) -> Log {
    Log::open_with(dir.path(), Some(ident(1)), LogConfig::default(), now).unwrap()
}

/// A witness that "anchors" on an invented chain, for tests only.
struct Fake {
    chain: &'static str,
    fail: bool,
    wrong_hash: bool,
}

impl Witness for Fake {
    fn anchor(&self, h: &[u8; 32]) -> Result<AnchorRecord, WitnessError> {
        if self.fail {
            return Err(WitnessError::Failed("chain unreachable".into()));
        }
        let mut hash = *h;
        if self.wrong_hash {
            hash[0] ^= 1;
        }
        Ok(AnchorRecord {
            checkpoint_hash: hash,
            chain_id: self.chain.into(),
            transaction_id: format!("tx-{}", hex::encode(&h[..4])),
            block_height: Some(42),
            anchored_at: NOW + 1,
        })
    }
}

fn get(log: &Arc<Mutex<Log>>, path: &str) -> serde_json::Value {
    let r = handle(log, &Request::new("GET", path, vec![]), NOW);
    assert_eq!(r.status, 200, "{path}");
    r.json_body().unwrap()
}

#[test]
fn checkpoint_responses_carry_the_hash_and_an_empty_anchor_list() {
    let dir = TempDir::new("anchor-hash");
    let log = Arc::new(Mutex::new(open(&dir, NOW)));
    for path in ["/v1/checkpoint", "/v1/checkpoints?from=0", "/v1/gossip"] {
        let j = get(&log, path);
        let c = match path {
            "/v1/checkpoint" => j.clone(),
            "/v1/checkpoints?from=0" => j["checkpoints"][0].clone(),
            _ => j["latest"].clone(),
        };
        // Existing fields are all still there (additive change only).
        for k in ["log", "tree-size", "root-hash", "timestamp", "checkpoint"] {
            assert!(c.get(k).is_some(), "{path} lost {k}");
        }
        assert_eq!(c["anchors"], serde_json::json!([]), "{path}");
        // The hash is SHA-256 of the signed payload.
        let raw = atep_log_b64(c["checkpoint"].as_str().unwrap());
        let v = verify(&raw, &Policy::default(), i64::MAX / 2).unwrap();
        assert_eq!(v.content_type, CT_CHECKPOINT);
        assert_eq!(
            c["checkpoint-hash"].as_str().unwrap(),
            hex::encode(checkpoint_hash(&v.payload))
        );
    }
    // POST /v1/checkpoint too.
    let r = handle(
        &log,
        &Request::new("POST", "/v1/checkpoint", vec![]),
        NOW + 5,
    );
    assert_eq!(r.status, 201);
    let j = r.json_body().unwrap();
    assert_eq!(j["checkpoint-hash"].as_str().unwrap().len(), 64);
    assert_eq!(j["anchors"], serde_json::json!([]));
}

fn atep_log_b64(s: &str) -> Vec<u8> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.decode(s).unwrap()
}

#[test]
fn log_without_a_witness_has_no_anchors_and_old_directories_load() {
    let dir = TempDir::new("anchor-old");
    {
        let mut log = open(&dir, NOW);
        assert!(!log.has_witness());
        assert_eq!(log.witness_latest(NOW).unwrap().map(|_| ()), None);
        assert!(log.anchors().is_empty());
    }
    // A directory written before the hooks has no anchors.rec.
    std::fs::remove_file(dir.path().join("anchors.rec")).unwrap();
    let log = open(&dir, NOW + 10);
    assert!(log.anchors().is_empty());
    let h = log.latest_checkpoint().unwrap().hash;
    assert!(log.anchors_for(&h).is_empty());
}

#[test]
fn noop_witness_changes_nothing() {
    let dir = TempDir::new("anchor-noop");
    let mut log = open(&dir, NOW);
    log.set_witness(Some(Box::new(NoopWitness)));
    assert!(log.has_witness());
    assert!(log.witness_latest(NOW).unwrap().is_none());
    assert!(log.anchors().is_empty());
    assert_eq!(
        NoopWitness.anchor(&[0; 32]).unwrap_err(),
        WitnessError::Disabled
    );
}

#[test]
fn witness_anchors_are_signed_stored_served_and_survive_restart() {
    let dir = TempDir::new("anchor-real");
    let hash;
    {
        let mut log = open(&dir, NOW);
        log.set_witness(Some(Box::new(Fake {
            chain: "x-test",
            fail: false,
            wrong_hash: false,
        })));
        hash = log.latest_checkpoint().unwrap().hash;
        let e = log.witness_latest(NOW + 2).unwrap().expect("anchored");
        assert_eq!(e.record.checkpoint_hash, hash);
        // Signed by the log, media type application/atep-anchor+cbor.
        let (signer, rec) = parse_anchor_envelope(&e.raw, NOW + 2).unwrap();
        assert_eq!(signer, log.log_id());
        assert_eq!(rec, e.record);
        // Already anchored: nothing pending.
        assert!(log.witness_latest(NOW + 3).unwrap().is_none());
        assert_eq!(log.anchors_for(&hash).len(), 1);
        let shared = Arc::new(Mutex::new(log));
        let j = get(&shared, "/v1/checkpoint");
        let a = &j["anchors"][0];
        assert_eq!(a["chain-id"], "x-test");
        assert_eq!(a["block-height"], 42);
        assert_eq!(a["checkpoint-hash"], hex::encode(hash));
        let raw = atep_log_b64(a["anchor"].as_str().unwrap());
        assert_eq!(parse_anchor_envelope(&raw, NOW + 2).unwrap().1, e.record);
        drop(shared);
    }
    let log = open(&dir, NOW + 100);
    assert_eq!(log.anchors_for(&hash).len(), 1);
}

#[test]
fn bad_anchors_are_refused() {
    let dir = TempDir::new("anchor-bad");
    let mut log = open(&dir, NOW);
    let hash = log.latest_checkpoint().unwrap().hash;
    let good = AnchorRecord {
        checkpoint_hash: hash,
        chain_id: "solana-mainnet".into(),
        transaction_id: "sig".into(),
        block_height: None,
        anchored_at: NOW,
    };
    let mut unknown_cp = good.clone();
    unknown_cp.checkpoint_hash = [9; 32];
    assert!(log.record_anchor(unknown_cp, NOW).is_err());
    let mut bad_chain = good.clone();
    bad_chain.chain_id = "dogecoin".into();
    assert!(log.record_anchor(bad_chain, NOW).is_err());
    log.record_anchor(good.clone(), NOW).unwrap();
    assert!(log.record_anchor(good, NOW).is_err(), "duplicate");
    // A witness that answers for another hash is rejected, a failing one is an error.
    let dir2 = TempDir::new("anchor-bad2");
    let mut l2 = open(&dir2, NOW);
    l2.set_witness(Some(Box::new(Fake {
        chain: "rekor",
        fail: false,
        wrong_hash: true,
    })));
    assert!(matches!(
        l2.witness_latest(NOW),
        Err(WitnessError::Failed(_))
    ));
    l2.set_witness(Some(Box::new(Fake {
        chain: "rekor",
        fail: true,
        wrong_hash: false,
    })));
    assert!(matches!(
        l2.witness_latest(NOW),
        Err(WitnessError::Failed(_))
    ));
    assert!(l2.anchors().is_empty());
    // The failure did not touch the log: a good witness works afterwards.
    l2.set_witness(Some(Box::new(Fake {
        chain: "rekor",
        fail: false,
        wrong_hash: false,
    })));
    assert!(l2.witness_latest(NOW).unwrap().is_some());
}

#[test]
fn forged_anchor_files_stop_the_log_from_opening() {
    // An anchor signed by someone else.
    let dir = TempDir::new("anchor-forged");
    let hash = open(&dir, NOW).latest_checkpoint().unwrap().hash;
    let rec = AnchorRecord {
        checkpoint_hash: hash,
        chain_id: "rekor".into(),
        transaction_id: "t".into(),
        block_height: None,
        anchored_at: NOW,
    };
    let payload = rec.encode();
    let params =
        atep_core::envelope::SignParams::new(&payload, atep_core::consts::CT_ANCHOR, [1; 16], NOW);
    let forged = atep_core::envelope::sign(&ident(2), &params).unwrap();
    let (mut f, _, _) = RecordFile::open(&dir.path().join("anchors.rec")).unwrap();
    f.append(&forged).unwrap();
    drop(f);
    let e = Log::open_with(dir.path(), Some(ident(1)), LogConfig::default(), NOW + 1);
    assert!(e.is_err());

    // An anchor of a checkpoint the log never signed.
    let dir = TempDir::new("anchor-orphan");
    drop(open(&dir, NOW));
    let mut orphan = rec.clone();
    orphan.checkpoint_hash = [5; 32];
    let payload = orphan.encode();
    let params =
        atep_core::envelope::SignParams::new(&payload, atep_core::consts::CT_ANCHOR, [1; 16], NOW);
    let signed = atep_core::envelope::sign(&ident(1), &params).unwrap();
    let (mut f, _, _) = RecordFile::open(&dir.path().join("anchors.rec")).unwrap();
    f.append(&signed).unwrap();
    drop(f);
    assert!(Log::open_with(dir.path(), Some(ident(1)), LogConfig::default(), NOW + 1).is_err());
}
