//! The monitor counts chain depth exactly as the verifier does (spec
//! section 7, "Chains" rule 3, and decision 19): the number of attestations in
//! the chain, the judged claim attestation included. A claim attestation by an
//! issuer that holds `k` delegations in a row below a root is a chain of
//! `k + 1` attestations and is within `max_depth` exactly when `k + 1 <=
//! max_depth`. (Before this was aligned the monitor counted delegations only
//! and accepted one delegation more than the verifier.)

use std::sync::{Arc, Mutex};

use atep_core::attestation::claims;
use atep_core::keys::Identity;
use atep_log::testkit::*;
use atep_log::{Log, LogConfig};
use atep_monitor::{LibrarySource, Monitor, MonitorConfig};

const NOW: i64 = 1_800_000_000;

/// A log holding root -> a -> b -> e (three delegations) and one `operator`
/// attestation issued by e: a chain of four attestations. Returns the log
/// and the index of the claim attestation.
fn world(dir: &TempDir) -> (Arc<Mutex<Log>>, u64, Identity) {
    let (root, a, b, e, subject) = (ident(31), ident(32), ident(33), ident(34), ident(35));
    let mut log = Log::open_with(dir.path(), Some(ident(1)), LogConfig::default(), NOW).unwrap();
    let t = NOW - 1000;
    let both = [claims::OPERATOR, claims::ISSUER_AUTHORITY];
    for (i, (from, to)) in [(&root, &a), (&a, &b), (&b, &e)].into_iter().enumerate() {
        log.submit(&delegate(from, to.agent_id(), &both, t + i as i64), NOW)
            .unwrap();
    }
    let claim = attest(
        &e,
        subject.agent_id(),
        claims::OPERATOR,
        text_map(&[("name", "Subject")]),
        t + 10,
        90,
    );
    let idx = log.submit(&claim, NOW).unwrap().index;
    (Arc::new(Mutex::new(log)), idx, root)
}

fn alerts_at(max_depth: usize) -> Vec<(&'static str, Option<u64>)> {
    let dir = TempDir::new("monitor-depth");
    let (log, _idx, root) = world(&dir);
    let mut cfg = MonitorConfig::new();
    cfg.roots = vec![root.agent_id()];
    cfg.max_depth = max_depth;
    let mut mon = Monitor::new(cfg, LibrarySource(log));
    mon.poll(NOW + 10)
        .iter()
        .map(|a| (a.kind(), a.entry()))
        .collect()
}

#[test]
fn a_chain_of_exactly_max_depth_attestations_is_not_an_alert() {
    assert_eq!(alerts_at(4), vec![]);
    assert_eq!(alerts_at(5), vec![]);
}

#[test]
fn one_attestation_over_max_depth_is_an_alert_as_the_verifier_would_reject_it() {
    let dir = TempDir::new("monitor-depth-idx");
    let (_log, idx, _root) = world(&dir);
    assert_eq!(
        alerts_at(3),
        vec![("issuer_outside_authority", Some(idx))],
        "the claim attestation heads a chain of four attestations"
    );
    // With max_depth 2 the delegation entries that sit too deep are findings too,
    // and the claim attestation is still one of them.
    let a2 = alerts_at(2);
    assert!(
        a2.contains(&("issuer_outside_authority", Some(idx))),
        "{a2:?}"
    );
}

#[test]
fn the_monitor_agrees_with_the_verifier_on_the_same_chain() {
    // The verifier side: the same four attestations, claim first, under
    // max_depth 3 and 4, through atep-core's step 9.
    use atep_core::attestation::{authority_data, AttestationParams};
    use atep_core::envelope::{sign, SignMode, SignParams};
    use atep_core::trust::TrustPolicy;
    use atep_core::verify::{verify, Policy};
    let (root, a, b, e, subject) = (ident(31), ident(32), ident(33), ident(34), ident(35));
    let t = NOW - 1000;
    let both = [claims::OPERATOR, claims::ISSUER_AUTHORITY];
    let del = |from: &Identity, to: &Identity, at: i64| {
        let mut p =
            AttestationParams::new(to.agent_id(), claims::ISSUER_AUTHORITY, at, at + 90 * DAY)
                .unwrap();
        p.data = authority_data(&both);
        p.mode = SignMode::Deterministic;
        atep_core::attestation::issue(from, &p).unwrap()
    };
    let claim = attest(
        &e,
        subject.agent_id(),
        claims::OPERATOR,
        text_map(&[("name", "Subject")]),
        t + 10,
        90,
    );
    let atts = vec![
        claim,
        del(&b, &e, t + 2),
        del(&a, &b, t + 1),
        del(&root, &a, t),
    ];
    let env = sign(
        &subject,
        &SignParams::new(b"x", atep_core::consts::CT_CHECKPOINT, [1; 16], NOW - 5),
    )
    .unwrap();
    let run = |max_depth: usize| {
        let trust = TrustPolicy::from_json(&serde_json::json!({
            "roots": [root.agent_id().to_text()],
            "max_depth": max_depth,
            "rules": [{"claim": "operator"}],
        }))
        .unwrap();
        let pol = Policy {
            trust: Some(trust),
            attestations: atts.clone(),
            srls: None,
            ..Policy::default()
        };
        verify(&env, &pol, NOW).map(|_| ()).map_err(|r| r.code)
    };
    assert!(run(4).is_ok());
    assert_eq!(
        run(3).unwrap_err(),
        atep_core::error::ErrorCode::ChainDepthExceeded
    );
}
