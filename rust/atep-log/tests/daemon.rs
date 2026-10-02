//! The `atep-logd` binary: start, serve, restart on the same data directory.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};

use atep_core::attestation::claims;
use atep_log::client::LogClient;
use atep_log::testkit::*;
use atep_log::unix_now;

struct Daemon {
    child: Child,
    url: String,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start(dir: &std::path::Path) -> Daemon {
    let mut child = Command::new(env!("CARGO_BIN_EXE_atep-logd"))
        .args([
            "--data-dir",
            dir.to_str().unwrap(),
            "--listen",
            "127.0.0.1:0",
        ])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let out = child.stdout.take().unwrap();
    let mut url = None;
    for line in BufReader::new(out).lines() {
        let line = line.unwrap();
        if let Some(u) = line.strip_prefix("listening on ") {
            url = Some(u.to_string());
            break;
        }
    }
    Daemon {
        child,
        url: url.expect("daemon printed its address"),
    }
}

#[test]
fn daemon_serves_and_survives_a_restart() {
    let dir = TempDir::new("daemon");
    let now = unix_now();
    let att = attest(
        &ident(2),
        ident(3).agent_id(),
        claims::OPERATOR,
        text_map(&[("name", "A")]),
        now - 10,
        90,
    );
    let first_root;
    {
        let d = start(dir.path());
        let c = LogClient::new(&d.url).unwrap();
        let (proof, dup) = c.submit(&att).unwrap();
        assert!(!dup);
        assert_eq!(proof.leaf_index, 1);
        let j = c.get_json("/v1/policy").unwrap();
        assert_eq!(j["first-entry"], true);
        first_root = c.get_json("/v1/checkpoint").unwrap()["root-hash"].clone();
    }
    // The key file is private and the public bundle is published.
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(dir.path().join("identity.key"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0);
    assert!(dir.path().join("log.pub").exists());
    {
        let d = start(dir.path());
        let c = LogClient::new(&d.url).unwrap();
        let (_, dup) = c.submit(&att).unwrap();
        assert!(dup, "entry survived the restart");
        let cp = c.get_json("/v1/checkpoint").unwrap();
        assert_eq!(cp["tree-size"], 2);
        assert_eq!(cp["root-hash"], first_root);
    }
    // --check verifies without serving.
    let out = Command::new(env!("CARGO_BIN_EXE_atep-logd"))
        .args(["--data-dir", dir.path().to_str().unwrap(), "--check"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("verified"));
}
