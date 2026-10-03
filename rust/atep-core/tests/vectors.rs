use std::fs;
use std::path::PathBuf;

use atep_core::vectors;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors")
}

#[test]
fn every_vector_on_disk_passes() {
    match vectors::check_dir(&vectors_dir()) {
        Ok(n) => assert!(n >= 120, "expected at least 120 vectors, found {n}"),
        Err(f) => panic!("vector failures:\n{}", f.join("\n")),
    }
}

#[test]
fn every_negative_reason_is_present() {
    let dir = vectors_dir().join("verify-negative");
    let names: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    for want in [
        "missing-pq-signature",
        "swapped-key",
        "expired",
        "bad-digest",
        "future-dated",
        "unknown-suite",
        "signer-mismatch",
        "unencrypted-non-trust-doc",
    ] {
        assert!(
            names.iter().any(|n| n == &format!("{want}.cbor")),
            "missing negative vector {want}"
        );
    }
}

#[test]
fn generation_is_deterministic_and_matches_disk() {
    let a = vectors::generate().unwrap();
    let b = vectors::generate().unwrap();
    assert_eq!(a, b);
    for (rel, bytes) in &a {
        let on_disk = fs::read(vectors_dir().join(rel))
            .unwrap_or_else(|e| panic!("{rel} missing on disk: {e}; run `atep-vectors generate`"));
        assert_eq!(
            &on_disk, bytes,
            "{rel} is stale; run `atep-vectors generate`"
        );
    }
}

fn names(cat: &str) -> Vec<String> {
    fs::read_dir(vectors_dir().join(cat))
        .unwrap_or_else(|e| panic!("{cat}: {e}"))
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            e.file_name()
                .to_string_lossy()
                .strip_suffix(".cbor")
                .map(str::to_string)
        })
        .collect()
}

#[test]
fn m2_vector_categories_cover_section_12() {
    let want: [(&str, &[&str]); 7] = [
        (
            "chain-positive",
            &[
                "three-level-chain",
                "valid-inclusion-proof",
                "claim-age-boundary",
            ],
        ),
        (
            "chain-negative",
            &[
                "broken-chain",
                "unauthorized-issuer",
                "expired-attestation",
                "attestation-lifetime-over-400-days",
                "attestation-on-issuer-srl",
                "issuer-compromised-on-srl",
                "subject-compromised-on-srl",
                "depth-exceeded",
                "chain-cycle",
                "rule-claim-missing",
                "claim-too-old",
                "bad-inclusion-proof",
            ],
        ),
        (
            "srl",
            &[
                "srl-valid",
                "srl-stale-fail-closed",
                "srl-bad-signature",
                "srl-issuer-mismatch",
            ],
        ),
        (
            "log",
            &[
                "checkpoint-valid",
                "inclusion-valid",
                "inclusion-wrong-audit-path",
            ],
        ),
        (
            "attestation",
            &["operator-90-days", "audited-400-days-with-evidence"],
        ),
        (
            "atep-r-positive",
            &[
                "telemetry-fleet-member",
                "sensor-fleet-member-and-sensor-source",
                "coordination-fleet-member",
                "motion-from-fleet-controller",
                "actuation-controller-and-safety-certified",
                "safety-geofence-from-safety-authority",
                "estop-with-expired-claims",
                "maintenance-from-maintenance-authority",
            ],
        ),
        (
            "atep-r-negative",
            &[
                "telemetry-no-fleet-member",
                "sensor-missing-sensor-source",
                "motion-member-without-peer-motion",
                "actuation-without-safety-certified",
                "safety-geofence-from-certified-member",
                "maintenance-from-fleet-member",
                "motion-stale-srl-fails-closed",
                "missing-command-class",
            ],
        ),
    ];
    for (cat, wanted) in want {
        let have = names(cat);
        for w in wanted {
            assert!(have.iter().any(|h| h == w), "missing {cat}/{w}");
        }
    }
}

/// Every vector's expected result names the rejection the description promises.
#[test]
fn negative_vectors_reject_for_their_stated_reason() {
    for cat in ["chain-negative", "atep-r-negative"] {
        for name in names(cat) {
            let meta: serde_json::Value = serde_json::from_slice(
                &fs::read(
                    vectors_dir()
                        .join(cat)
                        .join(format!("{name}.expected.json")),
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(meta["expected"]["ok"], false, "{cat}/{name}");
            assert!(
                meta["expected"]["step"].as_i64().unwrap() >= 1,
                "{cat}/{name}"
            );
            assert!(meta["expected"]["error"].is_string(), "{cat}/{name}");
        }
    }
}

/// The 140 vectors of Draft 03 never change (their order and bytes are pinned
/// by the digest of their manifest entries), nor do the 60 of Draft 04 that
/// follow them; the anchoring and discovery vectors are appended after those.
#[test]
fn the_first_200_vectors_are_unchanged_and_the_new_ones_are_appended() {
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(vectors_dir().join("manifest.json")).unwrap()).unwrap();
    let list = manifest["vectors"].as_array().unwrap();
    assert_eq!(list.len(), 437);
    let digest_of = |r: std::ops::Range<usize>| -> String {
        let s: String = list[r]
            .iter()
            .map(|v| v["cbor_sha256"].as_str().unwrap())
            .collect();
        digest_hex(s.as_bytes())
    };
    assert_eq!(
        digest_of(0..140),
        "4a4f85e047499f9bc187c0ca3da4f3e35681f09c1a92cb89db6efffa94f979fc"
    );
    assert_eq!(
        digest_of(0..200),
        "508b2aa685d032ca7d8d9b02d431e09526b9074008da993a76411bf4f87e26f3"
    );
    // Vectors 140 to 199 are exactly the retired and successor categories.
    let retired_cats = [
        "retired-positive",
        "retired-negative",
        "successor-positive",
        "successor-negative",
        "srl-context",
        "log-admission",
        "monitor",
    ];
    assert!(list[..140]
        .iter()
        .all(|v| !retired_cats.contains(&v["category"].as_str().unwrap())));
    assert!(list[140..200]
        .iter()
        .all(|v| retired_cats.contains(&v["category"].as_str().unwrap())));
    // Vectors 200 to 435 are the anchoring and discovery categories.
    let new_cats = [
        "checkpoint-hash",
        "anchor-record",
        "chain-id",
        "anchor-envelope",
        "anchor-media-type",
        "require-anchor",
        "anchor-not-supported",
        "registry-endpoint",
        "domain-binding",
    ];
    assert!(list[200..436]
        .iter()
        .all(|v| new_cats.contains(&v["category"].as_str().unwrap())));
    for c in new_cats {
        assert!(
            list[200..436].iter().any(|v| v["category"] == c),
            "no vector in {c}"
        );
    }
    // Draft 08 appends one vector after those: rust finding 57, an ATEP-R
    // `motion` rejection whose cause is a stale list.
    assert_eq!(list[436]["category"], "atep-r-negative");
    assert_eq!(list[436]["name"], "motion-member-peer-motion-stale-srl");
}

fn digest_hex(data: &[u8]) -> String {
    atep_core::keys::sha256(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Every case of the section 12 tables (RT1 to RT31, SU1 to SU26) has a vector
/// whose name begins with its number.
#[test]
fn every_retired_and_successor_case_has_a_vector() {
    let mut all: Vec<String> = Vec::new();
    for cat in [
        "retired-positive",
        "retired-negative",
        "successor-positive",
        "successor-negative",
        "srl-context",
        "log-admission",
        "monitor",
    ] {
        all.extend(names(cat));
    }
    for k in 1..=31 {
        let p = format!("rt{k:02}");
        assert!(all.iter().any(|n| n.starts_with(&p)), "no vector for RT{k}");
    }
    for k in 1..=26 {
        let p = format!("su{k:02}");
        assert!(all.iter().any(|n| n.starts_with(&p)), "no vector for SU{k}");
    }
    assert_eq!(all.len(), 60);
}
