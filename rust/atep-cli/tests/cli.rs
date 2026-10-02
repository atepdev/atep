use std::path::Path;
use std::process::{Command, Output};

fn atep(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_atep"))
        .args(args)
        .output()
        .expect("run atep")
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn ok(o: &Output) -> String {
    assert!(
        o.status.success(),
        "failed: stdout={} stderr={}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).to_string()
}

#[test]
fn full_round_trip() {
    let d = std::env::temp_dir().join(format!("atep-cli-test-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let alice = d.join("alice.key");
    let bob = d.join("bob.key");
    let alice_pub = d.join("alice.key.pub");
    let bob_pub = d.join("bob.key.pub");
    let payload = d.join("payload.bin");
    let signed = d.join("signed.cbor");
    let enc = d.join("enc.cbor");
    let opened = d.join("opened.cbor");
    let out = d.join("out.bin");
    std::fs::write(&payload, b"drive to waypoint 7").unwrap();

    let alice_id = ok(&atep(&["keygen", "--out", s(&alice)]))
        .trim()
        .to_string();
    let bob_id = ok(&atep(&["keygen", "-k", s(&bob)])).trim().to_string();
    assert!(alice_id.starts_with("atep:") && alice_id.len() == 57);
    assert_eq!(ok(&atep(&["id", s(&alice)])).trim(), alice_id);
    assert_eq!(ok(&atep(&["id", s(&bob_pub)])).trim(), bob_id);
    assert_eq!(
        ok(&atep(&["id", "--did", s(&alice_pub)])).trim(),
        format!("did:{alice_id}")
    );

    // refuse to overwrite a key
    assert!(!atep(&["keygen", "-k", s(&alice)]).status.success());

    ok(&atep(&[
        "sign",
        "-k",
        s(&alice),
        "-i",
        s(&payload),
        "-o",
        s(&signed),
        "--expires-in",
        "3600",
    ]));
    // unencrypted data envelope is rejected at step 1
    let r = atep(&["verify", "-i", s(&signed)]);
    assert_eq!(r.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&r.stderr).contains("step 1"));

    ok(&atep(&[
        "encrypt",
        "-i",
        s(&signed),
        "--to",
        s(&bob_pub),
        "-o",
        s(&enc),
    ]));
    let v = ok(&atep(&[
        "verify",
        "-i",
        s(&enc),
        "-k",
        s(&bob),
        "--payload-out",
        s(&out),
    ]));
    assert!(v.contains(&alice_id));
    assert_eq!(std::fs::read(&out).unwrap(), b"drive to waypoint 7");

    // wrong recipient key fails at step 2
    let r = atep(&["verify", "-i", s(&enc), "-k", s(&alice)]);
    assert_eq!(r.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&r.stderr).contains("step 2"));

    ok(&atep(&[
        "decrypt",
        "-i",
        s(&enc),
        "-k",
        s(&bob),
        "-o",
        s(&opened),
    ]));
    assert_eq!(
        std::fs::read(&opened).unwrap(),
        std::fs::read(&signed).unwrap()
    );

    // JSON output names the failing step
    let r = atep(&["verify", "-i", s(&enc), "--json"]);
    assert_eq!(r.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&r.stdout).contains("\"step\": 2"));

    // detached trust document verified with a cached bundle
    let doc = d.join("doc.cbor");
    ok(&atep(&[
        "sign",
        "-k",
        s(&alice),
        "-i",
        s(&payload),
        "-o",
        s(&doc),
        "--content-type",
        "application/atep-srl+cbor",
        "--detached",
        "--no-bundle",
    ]));
    let r = atep(&["verify", "-i", s(&doc), "--bundle", s(&alice_pub)]);
    assert_eq!(r.status.code(), Some(1));
    ok(&atep(&[
        "verify",
        "-i",
        s(&doc),
        "--bundle",
        s(&alice_pub),
        "--detached",
        s(&payload),
    ]));

    let view = ok(&atep(&["view", s(&doc)]));
    assert!(view.contains("COSE_Sign"));
    let _ = std::fs::remove_dir_all(&d);
}

fn fail_with(o: &Output, step: &str, code: &str) {
    assert_eq!(
        o.status.code(),
        Some(1),
        "stdout={}",
        String::from_utf8_lossy(&o.stdout)
    );
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains(&format!("step {step}")) && err.contains(code),
        "wanted step {step} {code}, got: {err}"
    );
}

#[test]
fn trust_end_to_end() {
    let d = std::env::temp_dir().join(format!("atep-cli-trust-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let p = |n: &str| d.join(n);
    let (root, ca, alice, bob) = (p("root.key"), p("ca.key"), p("alice.key"), p("bob.key"));
    let root_id = ok(&atep(&["keygen", "-k", s(&root), "--no-enc"]))
        .trim()
        .to_string();
    ok(&atep(&["keygen", "-k", s(&ca), "--no-enc"]));
    let alice_id = ok(&atep(&["keygen", "-k", s(&alice), "--no-enc"]))
        .trim()
        .to_string();
    ok(&atep(&["keygen", "-k", s(&bob)]));

    // root delegates to ca, ca vouches for alice
    let root_ca = p("root-ca.cbor");
    let ca_alice = p("ca-alice.cbor");
    // delegation data must hold claim URIs; short names are refused
    let r = atep(&[
        "attest",
        "-k",
        s(&root),
        "--subject",
        s(&p("ca.key.pub")),
        "--claim",
        "issuer-authority",
        "--data",
        r#"{"claims": ["operator"]}"#,
        "-o",
        s(&root_ca),
    ]);
    assert_eq!(r.status.code(), Some(2));
    let delegation = r#"{"claims": ["https://atep.dev/claims/operator"]}"#;
    let id_root_ca = ok(&atep(&[
        "attest",
        "-k",
        s(&root),
        "--subject",
        s(&p("ca.key.pub")),
        "--claim",
        "issuer-authority",
        "--data",
        delegation,
        "-o",
        s(&root_ca),
    ]))
    .trim()
    .to_string();
    assert_eq!(id_root_ca.len(), 32);
    ok(&atep(&[
        "attest",
        "-k",
        s(&ca),
        "--subject",
        &alice_id,
        "--claim",
        "operator",
        "--data",
        r#"{"name": "Acme Robotics Ltd"}"#,
        "-o",
        s(&ca_alice),
    ]));
    // lifetime rules: audited needs evidence, 401 days is refused
    let r = atep(&[
        "attest",
        "-k",
        s(&ca),
        "--subject",
        &alice_id,
        "--claim",
        "audited",
        "-o",
        s(&p("y.cbor")),
    ]);
    assert_eq!(r.status.code(), Some(2));
    let r = atep(&[
        "attest",
        "-k",
        s(&ca),
        "--subject",
        &alice_id,
        "--claim",
        "operator",
        "--days",
        "401",
        "--allow-long",
        "-o",
        s(&p("y.cbor")),
    ]);
    assert_eq!(r.status.code(), Some(2));

    // alice signs, carrying the chain inline, and encrypts to bob
    let payload = p("payload.bin");
    std::fs::write(&payload, b"hello").unwrap();
    let (signed, enc) = (p("signed.cbor"), p("enc.cbor"));
    ok(&atep(&[
        "sign",
        "-k",
        s(&alice),
        "-i",
        s(&payload),
        "-o",
        s(&signed),
        "--expires-in",
        "3600",
        "--attach",
        s(&ca_alice),
        "--attach",
        s(&root_ca),
    ]));
    ok(&atep(&[
        "encrypt",
        "-i",
        s(&signed),
        "--to",
        s(&p("bob.key.pub")),
        "-o",
        s(&enc),
    ]));

    let policy = p("policy.json");
    std::fs::write(&policy, r#"{"rules": [{"claim": "operator"}]}"#).unwrap();
    let out = ok(&atep(&[
        "verify",
        "-i",
        s(&enc),
        "-k",
        s(&bob),
        "--policy",
        s(&policy),
        "--root",
        &root_id,
    ]));
    assert!(
        out.contains("claim:") && out.contains("operator") && out.contains(&root_id),
        "{out}"
    );
    assert!(out.contains("2. issuer-authority"), "{out}");

    // without the root nothing chains
    fail_with(
        &atep(&[
            "verify",
            "-i",
            s(&enc),
            "-k",
            s(&bob),
            "--policy",
            s(&policy),
        ]),
        "9",
        "chain_broken",
    );
    // the chain command prints the same chain
    let out = ok(&atep(&[
        "chain",
        "-i",
        s(&ca_alice),
        "--attestation",
        s(&root_ca),
        "--root",
        &root_id,
    ]));
    assert!(
        out.contains("1. operator") && out.contains("2. issuer-authority"),
        "{out}"
    );
    let r = atep(&["chain", "-i", s(&ca_alice)]);
    assert_eq!(r.status.code(), Some(1));

    // revoke the delegation: the root publishes an SRL naming the attestation
    let srl1 = p("root1.srl");
    // by id (hex), then again by file with the `srl` spelling
    ok(&atep(&[
        "revoke",
        "-k",
        s(&root),
        "--attestation",
        &id_root_ca,
        "-o",
        s(&srl1),
    ]));
    let srl1b = p("root1b.srl");
    ok(&atep(&[
        "srl",
        "-k",
        s(&root),
        "--attestation",
        s(&root_ca),
        "-o",
        s(&srl1b),
    ]));
    let verify_with = |extra: &[&str]| {
        let mut args = vec![
            "verify",
            "-i",
            s(&enc),
            "-k",
            s(&bob),
            "--policy",
            s(&policy),
            "--root",
            &root_id,
        ];
        args.extend_from_slice(extra);
        atep(&args)
    };
    fail_with(
        &verify_with(&["--srl", s(&srl1)]),
        "9",
        "attestation_revoked",
    );

    // the SRL cache directory persists the list between runs
    let cache = p("cache");
    ok(&atep(&[
        "verify",
        "-i",
        s(&enc),
        "-k",
        s(&bob),
        "--srl",
        s(&srl1),
        "--srl-dir",
        s(&cache),
    ]));
    assert!(cache.exists());
    fail_with(
        &verify_with(&["--srl-dir", s(&cache)]),
        "9",
        "attestation_revoked",
    );

    // an identity entry feeds step 8: root lists alice as compromised
    let srl2 = p("root2.srl");
    ok(&atep(&[
        "srl",
        "-k",
        s(&root),
        "--identity",
        &alice_id,
        "--revoked-at",
        "0",
        "-o",
        s(&srl2),
    ]));
    fail_with(&verify_with(&["--srl", s(&srl2)]), "8", "signer_revoked");
    // --prev keeps old entries and increments the sequence
    let srl3 = p("root3.srl");
    ok(&atep(&[
        "srl",
        "-k",
        s(&root),
        "--prev",
        s(&srl1),
        "--identity",
        &alice_id,
        "--revoked-at",
        "0",
        "-o",
        s(&srl3),
    ]));
    let view = ok(&atep(&["view", s(&srl3)]));
    assert!(
        view.contains("COSE_Sign") && view.contains("sequence"),
        "{view}"
    );

    // a stale list fails closed by default and continues with a warning when fail-open
    let stale = p("stale.srl");
    let past = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 10_000)
        .to_string();
    ok(&atep(&[
        "srl",
        "-k",
        s(&root),
        "--issued-at",
        &past,
        "--valid-for",
        "60",
        "-o",
        s(&stale),
    ]));
    fail_with(&verify_with(&["--srl", s(&stale)]), "9", "srl_stale");
    let open = p("policy-open.json");
    std::fs::write(
        &open,
        r#"{"rules": [{"claim": "operator"}], "srl": {"on_stale": "fail-open"}}"#,
    )
    .unwrap();
    let out = ok(&atep(&[
        "verify",
        "-i",
        s(&enc),
        "-k",
        s(&bob),
        "--policy",
        s(&open),
        "--root",
        &root_id,
        "--srl",
        s(&stale),
    ]));
    assert!(out.contains("warning:") && out.contains("stale"), "{out}");

    // a rule that is not met
    let want_audit = p("policy-audit.json");
    std::fs::write(&want_audit, r#"{"rules": [{"claim": "audited"}]}"#).unwrap();
    fail_with(
        &atep(&[
            "verify",
            "-i",
            s(&enc),
            "-k",
            s(&bob),
            "--policy",
            s(&want_audit),
            "--root",
            &root_id,
        ]),
        "9",
        "claim_missing",
    );
    // a bad policy file is a usage error
    std::fs::write(&want_audit, r#"{"rulez": []}"#).unwrap();
    let r = atep(&[
        "verify",
        "-i",
        s(&enc),
        "-k",
        s(&bob),
        "--policy",
        s(&want_audit),
    ]);
    assert_eq!(r.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&d);
}
