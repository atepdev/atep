//! Anchoring hooks that belong to the core: the canonical checkpoint
//! hash, the `require-anchor` policy rule failing closed, and the guard that
//! no chain dependency ever enters the workspace, the npm package or the
//! Python package.

use std::path::Path;

use atep_core::consts::*;
use atep_core::envelope::{sign, SignMode, SignParams};
use atep_core::keys::{Identity, Seeds};
use atep_core::log::{checkpoint_hash, Checkpoint};
use atep_core::{verify, ErrorCode, Policy, TrustPolicy};

fn ident(n: u8) -> Identity {
    Identity::from_seeds(Seeds {
        ed25519: [n; 32],
        mldsa65: [n + 1; 32],
        x25519: None,
        mlkem768: None,
    })
    .unwrap()
}

#[test]
fn checkpoint_hash_is_sha256_of_deterministic_payload() {
    let cp = Checkpoint {
        tree_size: 5,
        root_hash: [0xab; 32],
        timestamp: 1_800_000_000,
    };
    // Hand-built deterministic CBOR (keys sorted bytewise), hashed independently
    // with Python's hashlib when this test was written.
    let expected_bytes = "a369726f6f742d686173685820abababababababababababababababababababababababababababababababab6974696d657374616d701a6b49d20069747265652d73697a6505";
    assert_eq!(hex::encode(cp.encode()), expected_bytes);
    let expected = "a4c6fa1c60d4a52276084e63f8a77c5c2e04fb0d71e26bbdf1261606ef157313";
    assert_eq!(hex::encode(cp.hash()), expected);
    assert_eq!(hex::encode(checkpoint_hash(&cp.encode())), expected);
}

#[test]
fn checkpoint_hash_of_a_signed_checkpoint_payload() {
    let log = ident(60);
    let cp = Checkpoint {
        tree_size: 9,
        root_hash: [3; 32],
        timestamp: 1_000,
    };
    let env =
        atep_core::log::create_checkpoint(&log, &cp, [1; 16], SignMode::Deterministic).unwrap();
    let v = verify(&env, &Policy::default(), 1_000).unwrap();
    assert_eq!(v.content_type, CT_CHECKPOINT);
    assert_eq!(checkpoint_hash(&v.payload), cp.hash());
}

#[test]
fn require_anchor_fails_closed_in_verify_and_absent_rule_is_unchanged() {
    let a = ident(1);
    let mut p = SignParams::new(b"x", CT_ATTESTATION, [7; 16], 1_000);
    p.expires_at = Some(2_000);
    p.mode = SignMode::Deterministic;
    let env = sign(&a, &p).unwrap();
    let log = ident(70).agent_id();
    let rule = serde_json::json!({
        "require_anchor": [{"log": log.to_text(), "chain": "rekor", "max_age_hours": 24}]
    });
    let with = TrustPolicy::from_json(&rule).unwrap();
    let pol = Policy {
        trust: Some(with),
        ..Policy::default()
    };
    let e = verify(&env, &pol, 1_500).unwrap_err();
    assert_eq!(e.step, 9);
    assert_eq!(e.code, ErrorCode::AnchorNotSupported);
    assert_eq!(e.code.as_str(), "anchor_not_supported");
    assert!(e.detail.contains("not supported in this build"));
    // The same policy without the rule behaves as before.
    let pol = Policy {
        trust: Some(TrustPolicy::from_json(&serde_json::json!({})).unwrap()),
        ..Policy::default()
    };
    verify(&env, &pol, 1_500).unwrap();
}

/// Names (or name prefixes) of blockchain, wallet and chain-witness packages.
const CHAIN_NAMES: &[&str] = &[
    "solana",
    "spl-",
    "anchor-lang",
    "ethers",
    "alloy",
    "web3",
    "ethereum",
    "ethabi",
    "revm",
    "bitcoin",
    "bdk",
    "rust-bitcoin",
    "secp256k1",
    "opentimestamps",
    "sigstore",
    "rekor",
    "near-",
    "cosmos",
    "cosmwasm",
    "substrate",
    "sp-core",
    "polkadot",
    "aptos",
    "sui-",
    "tezos",
    "ton-",
    "starknet",
    "ethereumjs",
    "viem",
    "wagmi",
    "bitcoinjs",
    "algosdk",
    "xrpl",
];

fn is_chain_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.trim_start_matches('@')
        .split('/')
        .any(|part| CHAIN_NAMES.iter().any(|c| part.starts_with(c)))
}

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn cargo_lock_has_no_chain_crates() {
    let lock = std::fs::read_to_string(root().join("../Cargo.lock")).unwrap();
    let mut seen = 0;
    for l in lock.lines() {
        if let Some(n) = l.strip_prefix("name = \"") {
            seen += 1;
            let n = n.trim_end_matches('"');
            assert!(!is_chain_name(n), "chain dependency `{n}` in Cargo.lock");
        }
    }
    assert!(seen > 20, "Cargo.lock looks empty");
}

#[test]
fn manifests_have_no_chain_dependencies() {
    let repo = root().join("../..");
    let mut manifests = vec![];
    for member in [
        "atep-core",
        "atep-cli",
        "atep-log",
        "atep-monitor",
        "atep-wasm",
    ] {
        manifests.push(root().join("..").join(member).join("Cargo.toml"));
    }
    manifests.push(root().join("../Cargo.toml"));
    for m in &manifests {
        let t = std::fs::read_to_string(m).unwrap();
        let mut in_deps = false;
        for l in t.lines() {
            let l = l.trim();
            if l.starts_with('[') {
                in_deps = l.contains("dependencies");
                continue;
            }
            if in_deps {
                if let Some((name, _)) = l.split_once('=') {
                    let name = name.trim();
                    assert!(
                        !is_chain_name(name),
                        "chain dependency `{name}` in {}",
                        m.display()
                    );
                }
            }
        }
    }
    // npm package: dependencies and the lock file.
    let pkg = repo.join("js/package.json");
    if let Ok(t) = std::fs::read_to_string(&pkg) {
        let j: serde_json::Value = serde_json::from_str(&t).unwrap();
        for section in [
            "dependencies",
            "devDependencies",
            "peerDependencies",
            "optionalDependencies",
        ] {
            if let Some(o) = j[section].as_object() {
                for name in o.keys() {
                    assert!(
                        !is_chain_name(name),
                        "chain dependency `{name}` in js/package.json"
                    );
                }
            }
        }
    }
    if let Ok(t) = std::fs::read_to_string(repo.join("js/package-lock.json")) {
        let j: serde_json::Value = serde_json::from_str(&t).unwrap();
        if let Some(o) = j["packages"].as_object() {
            for key in o.keys() {
                let name = key.rsplit("node_modules/").next().unwrap_or(key);
                assert!(
                    !is_chain_name(name),
                    "chain dependency `{name}` in js/package-lock.json"
                );
            }
        }
    }
    // Python package: any requirement file or pyproject.
    for f in [
        "pyproject.toml",
        "requirements.txt",
        "setup.py",
        "setup.cfg",
    ] {
        if let Ok(t) = std::fs::read_to_string(repo.join("python").join(f)) {
            for l in t.lines() {
                let l = l.trim().trim_matches(|c| c == '"' || c == ',' || c == '\'');
                let name: String = l
                    .chars()
                    .take_while(|c| {
                        c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.'
                    })
                    .collect();
                if !name.is_empty() {
                    assert!(
                        !is_chain_name(&name),
                        "chain dependency `{name}` in python/{f}"
                    );
                }
            }
        }
    }
}

#[test]
fn python_sources_import_no_chain_modules() {
    let dir = root().join("../../python/atep_py");
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return;
    };
    for f in rd.flatten() {
        if f.path().extension().and_then(|e| e.to_str()) != Some("py") {
            continue;
        }
        for l in std::fs::read_to_string(f.path()).unwrap().lines() {
            let l = l.trim();
            let module = l
                .strip_prefix("import ")
                .or_else(|| l.strip_prefix("from "))
                .and_then(|r| r.split_whitespace().next());
            if let Some(m) = module {
                assert!(
                    !is_chain_name(m),
                    "chain import `{m}` in {}",
                    f.path().display()
                );
            }
        }
    }
}

#[test]
fn the_guard_itself_recognizes_chain_crates() {
    for n in [
        "solana-sdk",
        "ethers-core",
        "alloy-primitives",
        "bitcoin",
        "secp256k1",
        "@solana/web3.js",
        "web3",
    ] {
        assert!(is_chain_name(n), "{n}");
    }
    for n in ["sha2", "ed25519-dalek", "tonic", "serde_json", "base64"] {
        assert!(!is_chain_name(n), "{n}");
    }
}
