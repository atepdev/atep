//! M3 acceptance: a monitor that follows a log by its public interfaces
//! detects an injected mis-issuance, and only that; and a tampered or
//! rewritten history is detected by consistency proof failure.

use std::sync::{Arc, Mutex};

use atep_core::attestation::claims;
use atep_core::keys::AgentId;
use atep_log::client::LogClient;
use atep_log::http::spawn;
use atep_log::store::RecordFile;
use atep_log::testkit::*;
use atep_log::{Log, LogConfig};
use atep_monitor::source::SourceError;
use atep_monitor::{
    Alert, DirSource, HttpSource, LibrarySource, LogSource, Monitor, MonitorConfig,
};

const NOW: i64 = 1_800_000_000;

struct World {
    root: atep_core::keys::Identity,
    ca1: atep_core::keys::Identity,
    ca2: atep_core::keys::Identity,
    alice: atep_core::keys::Identity,
    eve: atep_core::keys::Identity,
    mallory: atep_core::keys::Identity,
    randomco: atep_core::keys::Identity,
}

fn world() -> World {
    World {
        root: ident(11),
        ca1: ident(12),
        ca2: ident(13),
        alice: ident(14),
        eve: ident(15),
        mallory: ident(16),
        randomco: ident(17),
    }
}

fn cfg(w: &World) -> MonitorConfig {
    let mut c = MonitorConfig::new();
    c.watch_domains = vec!["example.com".into()];
    c.authorized = vec![w.alice.agent_id()];
    c.roots = vec![w.root.agent_id()];
    c
}

fn open_log(dir: &TempDir) -> Log {
    Log::open_with(dir.path(), Some(ident(1)), LogConfig::default(), NOW).unwrap()
}

/// The legitimate issuance: root delegates to ca1, ca1 to ca2, ca2 vouches
/// for alice, ca1 binds alice to a domain, root audits alice.
fn legit(w: &World) -> Vec<Vec<u8>> {
    let t = NOW - 1000;
    vec![
        delegate(
            &w.root,
            w.ca1.agent_id(),
            &[
                claims::OPERATOR,
                claims::ISSUER_AUTHORITY,
                claims::DOMAIN_CONTROL,
            ],
            t,
        ),
        delegate(&w.ca1, w.ca2.agent_id(), &[claims::OPERATOR], t + 1),
        attest(
            &w.ca2,
            w.alice.agent_id(),
            claims::OPERATOR,
            text_map(&[("name", "Alice Robotics")]),
            t + 2,
            90,
        ),
        domain_control(&w.ca1, w.alice.agent_id(), "alice.example.com", t + 3),
        {
            let mut p = atep_core::attestation::AttestationParams::new(
                w.alice.agent_id(),
                claims::AUDITED,
                t + 4,
                t + 4 + 200 * DAY,
            )
            .unwrap();
            p.evidence = Some([7; 32]);
            p.data = text_map(&[("audit", "2026")]);
            atep_core::attestation::issue(&w.root, &p).unwrap()
        },
        // Unwatched domain and an issuer nobody delegated: neither is a finding.
        domain_control(&w.mallory, w.mallory.agent_id(), "unwatched.org", t + 5),
        attest(
            &w.randomco,
            w.alice.agent_id(),
            "https://randomco.example/claims/seen",
            text_map(&[]),
            t + 6,
            90,
        ),
    ]
}

struct Injected {
    outside_authority: u64,
    rogue_domain: u64,
    eve_domain: u64,
}

fn inject(log: &mut Log, w: &World) -> Injected {
    let t = NOW - 500;
    // ca2 holds only `operator` but issues `audited`.
    let mut p = atep_core::attestation::AttestationParams::new(
        w.alice.agent_id(),
        claims::AUDITED,
        t,
        t + 100 * DAY,
    )
    .unwrap();
    p.evidence = Some([9; 32]);
    p.data = text_map(&[("audit", "bogus")]);
    let a = atep_core::attestation::issue(&w.ca2, &p).unwrap();
    let outside_authority = log.submit(&a, NOW).unwrap().index;
    // mallory binds herself to a watched domain.
    let b = domain_control(&w.mallory, w.mallory.agent_id(), "shop.example.com", t + 1);
    let rogue_domain = log.submit(&b, NOW).unwrap().index;
    // ca1 is entitled to issue domain-control but names a subject the owner did not authorize.
    let c = domain_control(&w.ca1, w.eve.agent_id(), "example.com", t + 2);
    let eve_domain = log.submit(&c, NOW).unwrap().index;
    Injected {
        outside_authority,
        rogue_domain,
        eve_domain,
    }
}

fn kinds(alerts: &[Alert]) -> Vec<(&'static str, Option<u64>)> {
    let mut v: Vec<_> = alerts.iter().map(|a| (a.kind(), a.entry())).collect();
    v.sort();
    v
}

#[test]
fn monitor_detects_injected_misissuance_over_http() {
    let w = world();
    let dir = TempDir::new("acc-http");
    let log = Arc::new(Mutex::new(open_log(&dir)));
    let server = spawn(log.clone(), "127.0.0.1:0", Arc::new(|| NOW + 5)).unwrap();
    let client = LogClient::new(&format!("http://{}", server.addr)).unwrap();
    for a in legit(&w) {
        client.submit(&a).unwrap();
    }
    let mut mon = Monitor::new(
        cfg(&w),
        HttpSource::new(&format!("http://{}", server.addr)).unwrap(),
    );
    let first = mon.poll(NOW + 10);
    assert!(
        first.is_empty(),
        "no alerts on a legitimate log, got {first:?}"
    );
    assert_eq!(mon.entries_seen(), 8); // policy + 7

    let inj = inject(&mut log.lock().unwrap(), &w);
    let alerts = mon.poll(NOW + 20);
    assert_eq!(
        kinds(&alerts),
        vec![
            ("issuer_outside_authority", Some(inj.outside_authority)),
            ("unauthorized_domain_control", Some(inj.rogue_domain)),
            ("unauthorized_domain_control", Some(inj.eve_domain)),
        ],
        "{alerts:#?}"
    );
    match alerts
        .iter()
        .find(|a| a.kind() == "issuer_outside_authority")
        .unwrap()
    {
        Alert::IssuerOutsideAuthority { issuer, claim, .. } => {
            assert_eq!(*issuer, w.ca2.agent_id());
            assert_eq!(claim, claims::AUDITED);
        }
        _ => unreachable!(),
    }
    // Reported once; a later round with nothing new is quiet.
    assert!(mon.poll(NOW + 30).is_empty());
    assert_eq!(mon.alerts().len(), 3);
}

#[test]
fn same_findings_through_the_data_directory_and_library_access() {
    let w = world();
    let dir = TempDir::new("acc-dir");
    let log = Arc::new(Mutex::new(open_log(&dir)));
    for a in legit(&w) {
        log.lock().unwrap().submit(&a, NOW).unwrap();
    }
    let inj = inject(&mut log.lock().unwrap(), &w);
    let want = vec![
        ("issuer_outside_authority", Some(inj.outside_authority)),
        ("unauthorized_domain_control", Some(inj.rogue_domain)),
        ("unauthorized_domain_control", Some(inj.eve_domain)),
    ];
    let mut by_lib = Monitor::new(cfg(&w), LibrarySource(log.clone()));
    assert_eq!(kinds(&by_lib.poll(NOW + 10)), want);
    // Read the directory of the live log without opening it.
    let mut by_dir = Monitor::new(cfg(&w), DirSource(dir.path().to_path_buf()));
    assert_eq!(kinds(&by_dir.poll(NOW + 10)), want);
    // Strict mode additionally flags the issuers nobody delegated to.
    let mut strict_cfg = cfg(&w);
    strict_cfg.strict_issuers = true;
    let mut strict = Monitor::new(strict_cfg, LibrarySource(log));
    let alerts = strict.poll(NOW + 10);
    let undelegated: Vec<_> = alerts
        .iter()
        .filter(|a| a.kind() == "undelegated_issuer")
        .collect();
    assert!(undelegated.len() >= 3, "{alerts:#?}"); // randomco, mallory (twice), and the unwatched one
}

#[test]
fn over_delegation_and_revoked_delegation_are_flagged() {
    let w = world();
    let dir = TempDir::new("acc-deleg");
    let mut log = open_log(&dir);
    let t = NOW - 1000;
    log.submit(
        &delegate(
            &w.root,
            w.ca1.agent_id(),
            &[claims::OPERATOR, claims::ISSUER_AUTHORITY],
            t,
        ),
        NOW,
    )
    .unwrap();
    // ca1 hands ca2 an authority it does not hold itself (audited).
    let over = delegate(
        &w.ca1,
        w.ca2.agent_id(),
        &[claims::OPERATOR, claims::AUDITED],
        t + 1,
    );
    let over_idx = log.submit(&over, NOW).unwrap().index;
    // A delegation chain that is too deep: ca2 -> alice -> eve ... five levels.
    let m = Mutex::new(log);
    let log = Arc::new(m);
    let mut mon = Monitor::new(cfg(&w), LibrarySource(log.clone()));
    let alerts = mon.poll(NOW + 10);
    assert_eq!(
        kinds(&alerts),
        vec![("issuer_outside_authority", Some(over_idx))],
        "{alerts:#?}"
    );
    // The delegation expires: later issuance under it is out of authority.
    let late = attest(
        &w.ca1,
        w.alice.agent_id(),
        claims::OPERATOR,
        text_map(&[("name", "late")]),
        t + 91 * DAY,
        30,
    );
    let mut l = log.lock().unwrap();
    let idx = l.submit(&late, t + 91 * DAY).unwrap().index;
    drop(l);
    let alerts = mon.poll(t + 92 * DAY);
    assert_eq!(
        kinds(&alerts),
        vec![("issuer_outside_authority", Some(idx))],
        "{alerts:#?}"
    );
}

/// Fork a log at `keep` entries: a new directory with the same identity and
/// the first `keep` entries of `from`, then different history.
fn fork_at(from: &TempDir, keep: usize, label: &str) -> (TempDir, Log) {
    let dir = TempDir::new(label);
    std::fs::copy(
        from.path().join("identity.key"),
        dir.path().join("identity.key"),
    )
    .unwrap();
    let recs = RecordFile::read_all(&from.path().join("entries.rec")).unwrap();
    let (mut f, _, _) = RecordFile::open(&dir.path().join("entries.rec")).unwrap();
    for r in recs.iter().take(keep) {
        f.append(&r.payload).unwrap();
    }
    drop(f);
    let log = Log::open(dir.path(), LogConfig::default(), NOW + 50).unwrap();
    (dir, log)
}

/// A source whose log can be replaced under the monitor.
struct Swap {
    inner: Arc<Mutex<LibrarySource>>,
    /// Publish only the latest checkpoint, as a log hiding its history would.
    hide_history: bool,
}

impl LogSource for Swap {
    fn latest_checkpoint(&self) -> Result<Vec<u8>, SourceError> {
        self.inner.lock().unwrap().latest_checkpoint()
    }
    fn checkpoints_since(&self, from: u64) -> Result<Vec<Vec<u8>>, SourceError> {
        let mut v = self.inner.lock().unwrap().checkpoints_since(from)?;
        if self.hide_history {
            v = v.split_off(v.len().saturating_sub(1));
        }
        Ok(v)
    }
    fn consistency(
        &self,
        from: u64,
        to: u64,
    ) -> Result<atep_core::log::ConsistencyProof, SourceError> {
        self.inner.lock().unwrap().consistency(from, to)
    }
    fn entries(&self, from: u64, to: u64) -> Result<Vec<Vec<u8>>, SourceError> {
        self.inner.lock().unwrap().entries(from, to)
    }
}

fn grow(log: &mut Log, n: usize, tag: &str, at: i64) {
    for i in 0..n {
        let a = attest(
            &ident(30),
            ident(40 + i as u8).agent_id(),
            claims::OPERATOR,
            text_map(&[("name", tag)]),
            NOW - 100,
            90,
        );
        log.submit(&a, at + i as i64).unwrap();
    }
}

#[test]
fn rewritten_history_fails_the_consistency_proof() {
    let w = world();
    let dir = TempDir::new("rw-honest");
    let mut honest = open_log(&dir);
    grow(&mut honest, 6, "honest", NOW + 1);
    let honest = Arc::new(Mutex::new(honest));
    let swap = Arc::new(Mutex::new(LibrarySource(honest.clone())));
    let mut mon = Monitor::new(
        cfg(&w),
        Swap {
            inner: swap.clone(),
            hide_history: true,
        },
    );
    assert!(mon.poll(NOW + 10).is_empty());
    assert_eq!(mon.entries_seen(), 7);

    // The operator rewrites history from entry 3 on, signs a bigger tree and
    // publishes only the newest checkpoint.
    let (_d2, mut forked) = fork_at(&dir, 3, "rw-forked");
    grow(&mut forked, 7, "rewritten", NOW + 100);
    assert!(forked.tree_size() > 7);
    let forked = Arc::new(Mutex::new(forked));
    *swap.lock().unwrap() = LibrarySource(forked.clone());
    // A monitor that follows the same log but sees its full checkpoint history
    // also notices: the fork has its own size 7 checkpoint with another root.
    let mut full = Monitor::new(cfg(&w), LibrarySource(honest.clone()));
    assert!(full.poll(NOW + 10).is_empty());
    let alerts = mon.poll(NOW + 200);
    assert!(
        alerts
            .iter()
            .any(|a| matches!(a, Alert::InconsistentCheckpoint { from: 7, .. })),
        "{alerts:#?}"
    );
    // Nothing from the rewritten history was accepted.
    assert_eq!(mon.entries_seen(), 7);
    assert_eq!(mon.last_checkpoint().unwrap().size, 7);
    // The alert carries evidence that anyone can confirm without the monitor.
    if let Some(Alert::InconsistentCheckpoint { evidence, .. }) = alerts
        .iter()
        .find(|a| a.kind() == "inconsistent_checkpoint")
    {
        let ev = atep_log::gossip::SplitEvidence::from_pair_cbor(mon.log_id().unwrap(), evidence)
            .unwrap();
        assert!(ev.confirm(NOW + 200));
    }
    let mut full = Monitor::new(cfg(&w), LibrarySource(forked));
    full.trust_checkpoint(&mon.last_checkpoint().unwrap().raw, NOW + 200)
        .unwrap();
    let alerts = full.poll(NOW + 200);
    assert!(
        alerts
            .iter()
            .any(|a| a.kind() == "split_view" || a.kind() == "inconsistent_checkpoint"),
        "{alerts:#?}"
    );
}

#[test]
fn equal_size_fork_is_a_split_view_and_shrinking_is_reported() {
    let w = world();
    let dir = TempDir::new("sv-honest");
    let mut honest = open_log(&dir);
    grow(&mut honest, 5, "honest", NOW + 1);
    let size = honest.tree_size();
    let honest = Arc::new(Mutex::new(honest));
    let swap = Arc::new(Mutex::new(LibrarySource(honest)));
    let mut mon = Monitor::new(
        cfg(&w),
        Swap {
            inner: swap.clone(),
            hide_history: false,
        },
    );
    assert!(mon.poll(NOW + 10).is_empty());

    // Same key, same size, different content.
    let (_d2, mut fork) = fork_at(&dir, 2, "sv-fork");
    let missing = (size - fork.tree_size()) as usize;
    grow(&mut fork, missing, "other", NOW + 100);
    assert_eq!(fork.tree_size(), size);
    *swap.lock().unwrap() = LibrarySource(Arc::new(Mutex::new(fork)));
    let alerts = mon.poll(NOW + 200);
    let split = alerts
        .iter()
        .find(|a| a.kind() == "split_view")
        .expect("split view");
    // The alert carries evidence anyone can confirm.
    if let Alert::SplitView { log, evidence, .. } = split {
        let ev = atep_log::gossip::SplitEvidence::from_pair_cbor(*log, evidence).unwrap();
        assert!(ev.confirm(NOW + 200));
    }

    // A log that goes back to a smaller tree.
    let (_d3, small) = fork_at(&dir, 2, "sv-small");
    *swap.lock().unwrap() = LibrarySource(Arc::new(Mutex::new(small)));
    let alerts = mon.poll(NOW + 300);
    assert!(
        alerts.iter().any(|a| a.kind() == "tree_shrank"),
        "{alerts:#?}"
    );
}

struct Flaky {
    inner: LibrarySource,
    no_proofs: bool,
    short_entries: bool,
}

impl LogSource for Flaky {
    fn latest_checkpoint(&self) -> Result<Vec<u8>, SourceError> {
        self.inner.latest_checkpoint()
    }
    fn checkpoints_since(&self, from: u64) -> Result<Vec<Vec<u8>>, SourceError> {
        self.inner.checkpoints_since(from)
    }
    fn consistency(
        &self,
        from: u64,
        to: u64,
    ) -> Result<atep_core::log::ConsistencyProof, SourceError> {
        if self.no_proofs {
            return Err(SourceError("404 not found".into()));
        }
        self.inner.consistency(from, to)
    }
    fn entries(&self, from: u64, to: u64) -> Result<Vec<Vec<u8>>, SourceError> {
        let mut v = self.inner.entries(from, to)?;
        if self.short_entries {
            v.pop();
        }
        Ok(v)
    }
}

#[test]
fn gaps_in_proofs_and_entries_are_alerts() {
    let w = world();
    let dir = TempDir::new("gaps");
    let mut log = open_log(&dir);
    grow(&mut log, 4, "x", NOW + 1);
    let log = Arc::new(Mutex::new(log));
    let mut m1 = Monitor::new(
        cfg(&w),
        Flaky {
            inner: LibrarySource(log.clone()),
            no_proofs: true,
            short_entries: false,
        },
    );
    let alerts = m1.poll(NOW + 10);
    assert!(
        alerts.iter().any(|a| a.kind() == "checkpoint_gap"),
        "{alerts:#?}"
    );
    let mut m2 = Monitor::new(
        cfg(&w),
        Flaky {
            inner: LibrarySource(log.clone()),
            no_proofs: false,
            short_entries: true,
        },
    );
    let alerts = m2.poll(NOW + 10);
    assert!(
        alerts.iter().any(|a| a.kind() == "entry_gap"),
        "{alerts:#?}"
    );
    let mut m3 = Monitor::new(
        cfg(&w),
        Flaky {
            inner: LibrarySource(log),
            no_proofs: false,
            short_entries: false,
        },
    );
    assert!(m3.poll(NOW + 10).is_empty());
}

#[test]
fn entries_that_do_not_match_the_signed_root_are_detected() {
    let w = world();
    let dir = TempDir::new("tamper-entry");
    {
        let mut log = open_log(&dir);
        grow(&mut log, 4, "x", NOW + 1);
    }
    // Replace entry 2 with another valid document in the data directory.
    let path = dir.path().join("entries.rec");
    let recs = RecordFile::read_all(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    {
        let (mut f, _, _) = RecordFile::open(&path).unwrap();
        for (i, r) in recs.iter().enumerate() {
            if i == 2 {
                let evil = attest(
                    &ident(30),
                    ident(99).agent_id(),
                    claims::OPERATOR,
                    text_map(&[("name", "evil")]),
                    NOW - 100,
                    90,
                );
                let mut rec = (NOW + 3).to_be_bytes().to_vec();
                rec.extend_from_slice(&atep_core::envelope::submitted_form(&evil).unwrap());
                f.append(&rec).unwrap();
            } else {
                f.append(&r.payload).unwrap();
            }
        }
    }
    let mut mon = Monitor::new(cfg(&w), DirSource(dir.path().to_path_buf()));
    let alerts = mon.poll(NOW + 10);
    assert!(
        alerts
            .iter()
            .any(|a| a.kind() == "entry_root_mismatch" || a.kind() == "inconsistent_checkpoint"),
        "{alerts:#?}"
    );
    // And the log itself refuses to start on that directory.
    assert!(Log::open(dir.path(), LogConfig::default(), NOW + 20).is_err());
}

#[test]
fn saved_checkpoint_catches_a_rewrite_between_runs() {
    let w = world();
    let dir = TempDir::new("state");
    let mut log = open_log(&dir);
    grow(&mut log, 5, "honest", NOW + 1);
    let mut first = Monitor::new(cfg(&w), LibrarySource(Arc::new(Mutex::new(log))));
    assert!(first.poll(NOW + 10).is_empty());
    let saved = first.last_checkpoint().unwrap().raw.clone();
    let (_d, mut forked) = fork_at(&dir, 2, "state-fork");
    grow(&mut forked, 8, "rewritten", NOW + 100);
    let hidden = Swap {
        inner: Arc::new(Mutex::new(LibrarySource(Arc::new(Mutex::new(forked))))),
        hide_history: true,
    };
    let mut second = Monitor::new(cfg(&w), hidden);
    second.trust_checkpoint(&saved, NOW + 150).unwrap();
    let alerts = second.poll(NOW + 200);
    assert!(
        alerts.iter().any(|a| a.kind() == "inconsistent_checkpoint"),
        "{alerts:#?}"
    );
}

#[test]
fn pinned_log_identity_is_enforced() {
    let w = world();
    let dir = TempDir::new("pin");
    let log = open_log(&dir);
    let mut c = cfg(&w);
    c.log_id = Some(AgentId([9; 32]));
    let mut mon = Monitor::new(c, LibrarySource(Arc::new(Mutex::new(log))));
    let alerts = mon.poll(NOW + 10);
    assert_eq!(alerts[0].kind(), "bad_checkpoint");
}

#[test]
fn cli_reports_alerts_with_exit_code_3() {
    let w = world();
    let dir = TempDir::new("cli");
    {
        let mut log = open_log(&dir);
        for a in legit(&w) {
            log.submit(&a, NOW).unwrap();
        }
        inject(&mut log, &w);
    }
    let bin = env!("CARGO_BIN_EXE_atep-monitor");
    let out = std::process::Command::new(bin)
        .args([
            "--log",
            dir.path().to_str().unwrap(),
            "--once",
            "--json",
            "--now",
            "1800000100",
        ])
        .args([
            "--watch-domain",
            "example.com",
            "--authorized",
            &w.alice.agent_id().to_text(),
        ])
        .args(["--root", &w.root.agent_id().to_text()])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let lines: Vec<serde_json::Value> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 3);
    assert!(lines
        .iter()
        .any(|l| l["alert"] == "issuer_outside_authority"));
    assert_eq!(
        lines
            .iter()
            .filter(|l| l["alert"] == "unauthorized_domain_control")
            .count(),
        2
    );
    // A clean log exits 0.
    let clean = TempDir::new("cli-clean");
    {
        let mut log =
            Log::open_with(clean.path(), Some(ident(1)), LogConfig::default(), NOW).unwrap();
        for a in legit(&w) {
            log.submit(&a, NOW).unwrap();
        }
    }
    let out = std::process::Command::new(bin)
        .args([
            "--log",
            clean.path().to_str().unwrap(),
            "--once",
            "--now",
            "1800000100",
        ])
        .args([
            "--watch-domain",
            "example.com",
            "--authorized",
            &w.alice.agent_id().to_text(),
        ])
        .args(["--root", &w.root.agent_id().to_text()])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    // Usage error.
    let out = std::process::Command::new(bin)
        .args(["--log", "x", "--root", "bogus", "--once"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

// ---- anchoring hooks: monitors see anchor records (empty today) ----

#[test]
fn monitor_api_exposes_anchor_records_through_every_source() {
    use atep_core::anchor::AnchorRecord;
    use atep_log::{Witness, WitnessError};

    struct W;
    impl Witness for W {
        fn anchor(&self, h: &[u8; 32]) -> Result<AnchorRecord, WitnessError> {
            Ok(AnchorRecord {
                checkpoint_hash: *h,
                chain_id: "bitcoin-mainnet".into(),
                transaction_id: "abc".into(),
                block_height: Some(900_000),
                anchored_at: NOW,
            })
        }
    }

    let w = world();
    let dir = TempDir::new("mon-anchors");
    let log = Arc::new(Mutex::new(
        Log::open_with(dir.path(), Some(ident(1)), LogConfig::default(), NOW).unwrap(),
    ));
    let m = Monitor::new(cfg(&w), LibrarySource(log.clone()));
    // Without a witness: every checkpoint is listed with an empty anchor list.
    let list = m.checkpoint_anchors(0).unwrap();
    assert!(!list.is_empty());
    assert!(list.iter().all(|c| c.anchors.is_empty()));
    let dm = Monitor::new(cfg(&w), DirSource(dir.path().to_path_buf()));
    let dl = dm.checkpoint_anchors(0).unwrap();
    assert_eq!(dl.len(), list.len());
    assert_eq!(dl[0].checkpoint_hash, list[0].checkpoint_hash);
    // An old data directory without anchors.rec reads as no anchors.
    let _ = std::fs::remove_file(dir.path().join("anchors.rec"));
    assert!(dm
        .checkpoint_anchors(0)
        .unwrap()
        .iter()
        .all(|c| c.anchors.is_empty()));

    // With a witness the same calls show the anchors, over HTTP too.
    {
        let mut l = log.lock().unwrap();
        l.set_witness(Some(Box::new(W)));
        l.witness_latest(NOW + 1).unwrap().unwrap();
    }
    let with = m.checkpoint_anchors(0).unwrap();
    assert_eq!(with.last().unwrap().anchors.len(), 1);
    assert_eq!(with.last().unwrap().anchors[0].chain_id, "bitcoin-mainnet");
    let h = spawn(log.clone(), "127.0.0.1:0", Arc::new(|| NOW + 2)).unwrap();
    let hm = Monitor::new(
        cfg(&w),
        HttpSource::new(&format!("http://{}", h.addr)).unwrap(),
    );
    let over_http = hm.checkpoint_anchors(0).unwrap();
    assert_eq!(
        over_http.last().unwrap().anchors,
        with.last().unwrap().anchors
    );
    // Other sources keep the default: no anchors, no error.
    let flaky = Flaky {
        inner: LibrarySource(log.clone()),
        no_proofs: false,
        short_entries: false,
    };
    assert!(Monitor::new(cfg(&w), flaky)
        .checkpoint_anchors(0)
        .unwrap()
        .is_empty());
}
