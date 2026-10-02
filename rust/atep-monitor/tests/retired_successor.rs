//! The `monitor` vector for `successor_chain` (spec section 9, case SU25) run
//! against the real monitor: the entries of the vector are submitted to a log
//! and the monitor follows it. `atep-vectors check` runs the same vector
//! against the finder in `atep-core`.

use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use atep_core::cbor::Value;
use atep_log::testkit::*;
use atep_log::{Log, LogConfig};
use atep_monitor::{LibrarySource, Monitor, MonitorConfig};
use serde_json::Value as J;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors")
}

#[test]
fn successor_chain_vector_agrees_with_the_monitor() {
    let dir = vectors_dir().join("monitor");
    let mut seen = 0;
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let Some(base) = name.strip_suffix(".expected.json") else {
            continue;
        };
        let meta: J = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let now = meta["inputs"]["now"].as_i64().unwrap();
        let doc = Value::decode(&fs::read(dir.join(format!("{base}.cbor"))).unwrap()).unwrap();
        let entries = doc.as_map().unwrap()[0].1.as_array().unwrap().to_vec();
        let tmp = TempDir::new("monitor-vectors");
        let mut log =
            Log::open_with(tmp.path(), Some(ident(1)), LogConfig::default(), now).unwrap();
        for e in &entries {
            log.submit(&e.encode(), now).unwrap();
        }
        let mut mon = Monitor::new(
            MonitorConfig::new(),
            LibrarySource(Arc::new(Mutex::new(log))),
        );
        let got: Vec<J> = mon
            .poll(now + 10)
            .iter()
            .filter(|a| a.kind() == "successor_chain")
            .map(|a| a.to_json())
            .collect();
        // The log holds its policy entry first: the vector counts from its own
        // first entry.
        let want: Vec<J> = meta["expected"]["alerts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| {
                let mut a = a.clone();
                a["entry"] = (a["entry"].as_u64().unwrap() + 1).into();
                a
            })
            .collect();
        assert_eq!(got, want, "{base}");
        // Nothing else is raised for a log of valid successor attestations.
        assert_eq!(mon.alerts().len(), want.len(), "{:?}", mon.alerts());
        seen += 1;
    }
    assert_eq!(seen, 1);
}

/// A chain is found whatever the order in which its links were logged, and a
/// fork (one identity naming two successors) is not a chain.
#[test]
fn chains_forks_and_order() {
    use atep_core::attestation::claims;
    let now = 1_800_000_000;
    let (a, b, c, d) = (ident(50), ident(51), ident(52), ident(53));
    let link = |from: &atep_core::keys::Identity, to: &atep_core::keys::Identity, t: i64| {
        attest(from, to.agent_id(), claims::SUCCESSOR, text_map(&[]), t, 90)
    };
    let run = |links: Vec<Vec<u8>>| -> Vec<(String, Option<u64>)> {
        let tmp = TempDir::new("monitor-chain");
        let mut log =
            Log::open_with(tmp.path(), Some(ident(1)), LogConfig::default(), now).unwrap();
        for l in &links {
            log.submit(l, now).unwrap();
        }
        let mut mon = Monitor::new(
            MonitorConfig::new(),
            LibrarySource(Arc::new(Mutex::new(log))),
        );
        mon.poll(now + 10)
            .iter()
            .map(|x| (x.kind().to_string(), x.entry()))
            .collect()
    };
    let t = now - 1_000;
    // a to b, then b to c: alert for the later link (entry 2 of the log).
    assert_eq!(
        run(vec![link(&a, &b, t), link(&b, &c, t + 1)]),
        vec![("successor_chain".to_string(), Some(2))]
    );
    // The same chain logged in the other order: still the link b to c (entry 1).
    assert_eq!(
        run(vec![link(&b, &c, t + 1), link(&a, &b, t)]),
        vec![("successor_chain".to_string(), Some(1))]
    );
    // A single hop and a fork raise nothing.
    assert!(run(vec![link(&a, &b, t)]).is_empty());
    assert!(run(vec![link(&a, &b, t), link(&a, &d, t + 1)]).is_empty());
    // Three hops: the second and third links.
    assert_eq!(
        run(vec![
            link(&a, &b, t),
            link(&b, &c, t + 1),
            link(&c, &d, t + 2)
        ])
        .len(),
        2
    );
}
