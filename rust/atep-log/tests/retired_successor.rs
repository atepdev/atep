//! The `log-admission` vectors for `retired` and `successor` (spec section 9,
//! "Admission"; cases RT30, RT31 and SU26) run against the real log: the
//! submissions are made to `Log::submit` and refused or accepted with the
//! reasons the vectors name. `atep-vectors check` runs the same vectors
//! against the admission engine in `atep-core`.

use std::fs;
use std::path::PathBuf;

use atep_log::testkit::*;
use atep_log::{Log, LogConfig, SubmitErr};
use serde_json::Value as J;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors")
}

fn hexdec(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

#[test]
fn admission_vectors_agree_with_the_log() {
    let dir = vectors_dir().join("log-admission");
    let mut seen = 0;
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let Some(base) = name.strip_suffix(".expected.json") else {
            continue;
        };
        let meta: J = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let cbor = fs::read(dir.join(format!("{base}.cbor"))).unwrap();
        let now = meta["inputs"]["now"].as_i64().unwrap();
        let tmp = TempDir::new("admission-vectors");
        let mut log =
            Log::open_with(tmp.path(), Some(ident(1)), LogConfig::default(), now).unwrap();
        for l in meta["inputs"]["logged"].as_array().unwrap() {
            log.submit(&hexdec(l.as_str().unwrap()), now)
                .unwrap_or_else(|e| panic!("{base}: a logged entry was refused: {e:?}"));
        }
        let want = &meta["expected"];
        match (log.submit(&cbor, now), want["ok"].as_bool().unwrap()) {
            (Ok(out), true) => assert!(!out.duplicate, "{base}"),
            (Err(SubmitErr::Rejected(e)), false) => {
                assert_eq!(e.code, want["refusal"].as_str().unwrap(), "{base}");
                match &e.rejection {
                    Some(r) => {
                        assert_eq!(r.step as i64, want["step"].as_i64().unwrap(), "{base}");
                        assert_eq!(r.code.as_str(), want["error"].as_str().unwrap(), "{base}");
                    }
                    None => assert!(want.get("step").is_none(), "{base}"),
                }
            }
            (other, _) => panic!("{base}: log answered {other:?}, vector expects {want}"),
        }
        seen += 1;
    }
    assert_eq!(seen, 4);
}

/// The retirement store of a log survives a restart: entries are re-validated
/// in order, with the retirements logged before them.
#[test]
fn the_retirement_store_is_rebuilt_when_the_log_reopens() {
    use atep_core::attestation::claims;
    let tmp = TempDir::new("retire-reopen");
    let now = 1_800_000_000;
    let x = ident(40);
    let y = ident(41);
    let mut log = Log::open_with(tmp.path(), Some(ident(1)), LogConfig::default(), now).unwrap();
    let retire = attest(
        &x,
        x.agent_id(),
        claims::RETIRED,
        text_map(&[]),
        now - 1_000,
        60,
    );
    log.submit(&retire, now).unwrap();
    let late = attest(
        &x,
        y.agent_id(),
        claims::OPERATOR,
        text_map(&[]),
        now - 10,
        60,
    );
    match log.submit(&late, now) {
        Err(SubmitErr::Rejected(e)) => {
            assert_eq!(e.code, "verification_failed");
            assert_eq!(e.rejection.unwrap().step, 8);
        }
        other => panic!("{other:?}"),
    }
    drop(log);
    let mut again = Log::open_with(tmp.path(), Some(ident(1)), LogConfig::default(), now).unwrap();
    assert!(matches!(
        again.submit(&late, now),
        Err(SubmitErr::Rejected(_))
    ));
    // A second retirement is still admitted after the reopen.
    let renew = attest(
        &x,
        x.agent_id(),
        claims::RETIRED,
        text_map(&[]),
        now - 500,
        60,
    );
    assert!(again.submit(&renew, now).is_ok());
}
