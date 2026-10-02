//! Vectors for the anchoring formats of Draft 05 (spec sections 5, 7, 9, 10
//! and 12, known gaps 16 to 19): the checkpoint hash, the anchor record, the
//! `chain-id` table, the log-signed anchor envelope, the anchor media type as
//! a trust document, the `require_anchor` policy member and the
//! `anchor_not_supported` result. A child of `vectors_trust`, which supplies
//! the builders. The formats are documented in `vectors/README.md` and
//! `vectors/ANCHOR-DISCOVERY-NOTES.md`.
//!
//! Identities are the usual ones (`SHA-256("ATEP-vectors-v1/<name>/<field>")`):
//! `log` signs checkpoints and anchors, `mallory` is another signer, `alice`
//! signs the data envelopes of the `anchor-not-supported` vectors, `root`
//! is a root issuer and `bob` the recipient.

use super::*;
use crate::anchor::{
    check_published_anchor, is_extension_chain, is_registered_chain, AnchorRecord,
};
use crate::json::generic;
use crate::trust::TrustPolicy;
use crate::verify::{verify, Policy, Revocation, RevocationReason};

/// A checkpoint timestamp used by the vectors: an hour before `NOW`.
const T_CP: i64 = NOW - 3_600;

pub(super) fn generate(out: &mut Vec<Vector>, n: &Net) -> R<()> {
    checkpoint_hash_vectors(out, n)?;
    anchor_record_vectors(out)?;
    chain_id_vectors(out)?;
    anchor_envelope_vectors(out, n)?;
    anchor_media_type_vectors(out, n)?;
    require_anchor_vectors(out)?;
    anchor_not_supported_vectors(out, n)?;
    Ok(())
}

pub(super) fn check(category: &str, cbor: &[u8], inputs: &J, expected: &J) -> R<()> {
    let got = match category {
        "checkpoint-hash" => run_checkpoint_hash(cbor, inputs)?,
        "anchor-record" => run_anchor_record(cbor)?,
        "chain-id" => run_chain_id(cbor, inputs)?,
        "anchor-envelope" => run_anchor_envelope(cbor, inputs)?,
        "require-anchor" => run_require_anchor(cbor, inputs)?,
        other => return Err(e(format!("unknown category {other}"))),
    };
    if &got != expected {
        return Err(e(format!("result {got} != expected {expected}")));
    }
    Ok(())
}

/// For the vectors whose object under test is a JSON value (a policy, an
/// identifier): the `.cbor` file is the deterministic CBOR encoding of the
/// value in `inputs`, and the two must agree.
pub(super) fn json_cbor_agree(cbor: &[u8], j: &J) -> R<()> {
    if &generic(&Value::decode(cbor)?) != j {
        return Err(e(
            "the CBOR file is not the encoding of the JSON in `inputs`",
        ));
    }
    Ok(())
}

fn vec_of(
    category: &'static str,
    name: &str,
    description: &str,
    cbor: Vec<u8>,
    inputs: J,
    expected: J,
) -> Vector {
    Vector {
        category,
        name: name.to_string(),
        description: description.to_string(),
        cbor,
        inputs,
        expected,
    }
}

fn trusted_json(log: &Identity) -> J {
    json!([log.agent_id().to_text()])
}

// ---------------------------------------------------------------------------
// checkpoint-hash

fn run_checkpoint_hash(cbor: &[u8], inputs: &J) -> R<J> {
    let now = jint(inputs, "now")?;
    let trusted = jget(inputs, "trusted_logs")?
        .as_array()
        .ok_or_else(|| e("trusted_logs"))?
        .iter()
        .map(|t| AgentId::parse(t.as_str().unwrap_or("")))
        .collect::<Result<Vec<_>, _>>()?;
    let checker = OfflineInclusion {
        trusted_logs: trusted,
        known_bundles: vec![],
    };
    Ok(match checker.load_checkpoint(cbor, now) {
        Ok(cp) => {
            // The hash is over the payload bytes exactly as the verified
            // envelope carries them.
            let v = verify(cbor, &Policy::default(), now).map_err(|x| e(x.to_string()))?;
            let hash = sha256(&v.payload);
            let parsed = Checkpoint::from_payload(&v.payload).map_err(|x| e(x.0))?;
            if parsed.hash() != hash {
                return Err(e("checkpoint hash differs from the hash of the payload"));
            }
            json!({
                "ok": true,
                "checkpoint": checkpoint_json(&cp),
                "checkpoint_hash": hx(&hash),
                "payload_hex": hx(&v.payload),
            })
        }
        Err(x) => rejection_json(&x),
    })
}

fn checkpoint_hash_vectors(out: &mut Vec<Vector>, n: &Net) -> R<()> {
    let log = &n.log;
    let root = |label: &str| label_hash(&format!("anchor/{label}/root"));
    let cp_env = |size: i64, rh: [u8; 32], ts: i64, nonce_label: &str| -> R<Vec<u8>> {
        let cp = Checkpoint {
            tree_size: size,
            root_hash: rh,
            timestamp: ts,
        };
        create_checkpoint(log, &cp, nonce(nonce_label), SignMode::Deterministic)
    };
    let inputs = |l: &Identity| json!({ "now": NOW, "trusted_logs": trusted_json(l) });
    let push_ok = |out: &mut Vec<Vector>, name: &str, desc: &str, cbor: Vec<u8>| -> R<J> {
        let inp = inputs(log);
        let expected = run_checkpoint_hash(&cbor, &inp)?;
        if expected["ok"] != true {
            return Err(e(format!(
                "generator bug: checkpoint-hash/{name}: {expected}"
            )));
        }
        out.push(vec_of(
            "checkpoint-hash",
            name,
            desc,
            cbor,
            inp,
            expected.clone(),
        ));
        Ok(expected)
    };
    let c1 = cp_env(5, root("size5"), T_CP, "cph/size5")?;
    let a = push_ok(
        out,
        "hash-of-checkpoint",
        "A valid checkpoint of tree size 5. The checkpoint hash is SHA-256 of the payload bytes, the deterministic CBOR map {tree-size, root-hash, timestamp}, not of the envelope.",
        c1,
    )?;
    let empty = sha256(b"");
    let c = cp_env(0, empty, T_CP, "cph/empty")?;
    push_ok(
        out,
        "hash-of-empty-tree",
        "Tree size 0 with the root of the empty tree, SHA-256 of the empty string. One byte integer head for tree-size.",
        c,
    )?;
    let c = cp_env(4_294_967_296, root("large"), T_CP, "cph/large")?;
    push_ok(
        out,
        "hash-large-tree-size",
        "Tree size 4294967296: the integer needs an eight byte head, which the payload bytes (and so the hash) carry.",
        c,
    )?;
    // Same payload, different envelope: the nonce differs, so the signatures differ.
    let c2a = cp_env(9, root("twin"), T_CP, "cph/twin-a")?;
    let c2b = cp_env(9, root("twin"), T_CP, "cph/twin-b")?;
    if c2a == c2b {
        return Err(e("generator bug: twin checkpoints are identical"));
    }
    let ta = push_ok(
        out,
        "hash-same-payload-envelope-a",
        "Checkpoint of tree size 9, first of two envelopes with one payload. The other differs in nonce and so in both signatures.",
        c2a,
    )?;
    let tb = push_ok(
        out,
        "hash-same-payload-envelope-b",
        "Second envelope with the payload of hash-same-payload-envelope-a: a different envelope and the same checkpoint hash.",
        c2b,
    )?;
    if ta["checkpoint_hash"] != tb["checkpoint_hash"]
        || ta["checkpoint_hash"] == a["checkpoint_hash"]
    {
        return Err(e("generator bug: checkpoint hashes of the twin envelopes"));
    }

    // Rejections: no hash is produced for a checkpoint that does not check.
    let push_bad = |out: &mut Vec<Vector>,
                    name: &str,
                    desc: &str,
                    cbor: Vec<u8>,
                    trusted: &Identity,
                    want: (u8, &str)|
     -> R<()> {
        let inp = inputs(trusted);
        let expected = run_checkpoint_hash(&cbor, &inp)?;
        if expected["ok"] != false || expected["step"] != want.0 || expected["error"] != want.1 {
            return Err(e(format!(
                "generator bug: checkpoint-hash/{name}: {expected}"
            )));
        }
        out.push(vec_of("checkpoint-hash", name, desc, cbor, inp, expected));
        Ok(())
    };
    let c = cp_env(5, root("size5"), T_CP, "cph/untrusted")?;
    push_bad(
        out,
        "reject-untrusted-log",
        "A well formed checkpoint signed by the log, but the verifier trusts another log (mallory). Expect step 9 checkpoint_untrusted: no hash is taken from a checkpoint that does not check.",
        c,
        &n.mallory,
        (9, "checkpoint_untrusted"),
    )?;
    let good = cp_env(5, root("size5"), T_CP, "cph/badsig")?;
    let c = mutate(&good, |a| flip_last(sig_slot(a, 1)))?;
    push_bad(
        out,
        "reject-bad-signature",
        "The ML-DSA-65 signature of the checkpoint envelope has its last byte flipped. Expect step 9 inclusion_proof_invalid with cause step 4 mldsa_signature_invalid.",
        c,
        log,
        (9, "inclusion_proof_invalid"),
    )?;
    // Payload schema failures, validly signed.
    type SchemaCase<'a> = (&'a str, &'a str, Vec<(Value, Value)>);
    let schema_cases: [SchemaCase; 2] = [
        (
            "reject-missing-root-hash",
            "The payload lacks `root-hash`. Expect step 9 checkpoint_schema_invalid.",
            vec![
                (Value::text("tree-size"), Value::Int(5)),
                (Value::text("timestamp"), Value::Int(T_CP)),
            ],
        ),
        (
            "reject-unknown-payload-key",
            "The payload has a fourth key, `note`. Expect step 9 checkpoint_schema_invalid.",
            vec![
                (Value::text("tree-size"), Value::Int(5)),
                (Value::text("root-hash"), Value::bytes(&root("size5"))),
                (Value::text("timestamp"), Value::Int(T_CP)),
                (Value::text("note"), Value::text("x")),
            ],
        ),
    ];
    for (name, desc, entries) in schema_cases {
        let payload = Value::Map(entries).encode();
        let mut sp = SignParams::new(&payload, CT_CHECKPOINT, nonce(&format!("cph/{name}")), T_CP);
        sp.mode = SignMode::Deterministic;
        let c = sign(log, &sp)?;
        push_bad(out, name, desc, c, log, (9, "checkpoint_schema_invalid"))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// anchor-record

fn record_json(r: &AnchorRecord) -> J {
    json!({
        "checkpoint_hash": hx(&r.checkpoint_hash),
        "chain_id": r.chain_id,
        "transaction_id": r.transaction_id,
        "block_height": r.block_height,
        "anchored_at": r.anchored_at,
    })
}

fn run_anchor_record(cbor: &[u8]) -> R<J> {
    Ok(match AnchorRecord::from_payload(cbor) {
        Ok(r) => {
            if r.encode() != cbor {
                return Err(e("a decoded anchor record does not re-encode to its bytes"));
            }
            json!({ "ok": true, "record": record_json(&r) })
        }
        Err(_) => json!({ "ok": false, "error": "anchor_record_invalid" }),
    })
}

/// Encode a map with its entries in the order given and the heads and values
/// exactly as supplied, so that non-deterministic encodings can be built.
fn raw_map(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut b = vec![0xa0 | entries.len() as u8];
    for (k, v) in entries {
        b.extend(Value::text(k).encode());
        b.extend(v);
    }
    b
}

fn good_entries() -> Vec<(&'static str, Vec<u8>)> {
    // In deterministic key order: chain-id, anchored-at, block-height,
    // transaction-id, checkpoint-hash (shorter encoded keys sort first).
    vec![
        ("chain-id", Value::text("solana-mainnet").encode()),
        ("anchored-at", Value::Int(NOW - 3_000).encode()),
        ("block-height", Value::Int(280_000_000).encode()),
        ("transaction-id", Value::text("5VERv8NMvz").encode()),
        (
            "checkpoint-hash",
            Value::bytes(&label_hash("anchor/rec/hash")).encode(),
        ),
    ]
}

fn rec_with(edit: impl FnOnce(&mut Vec<(&'static str, Vec<u8>)>)) -> Vec<u8> {
    let mut es = good_entries();
    edit(&mut es);
    raw_map(&es)
}

fn set(es: &mut [(&'static str, Vec<u8>)], key: &str, v: Value) {
    for (k, val) in es.iter_mut() {
        if *k == key {
            *val = v.encode();
        }
    }
}

fn del(es: &mut Vec<(&'static str, Vec<u8>)>, key: &str) {
    es.retain(|(k, _)| *k != key);
}

fn anchor_record_vectors(out: &mut Vec<Vector>) -> R<()> {
    let hash = label_hash("anchor/rec/hash");
    let valid = |name: &str, desc: &str, r: AnchorRecord| -> R<Vector> {
        let cbor = r.encode();
        let expected = run_anchor_record(&cbor)?;
        if expected != json!({ "ok": true, "record": record_json(&r) }) {
            return Err(e(format!("generator bug: anchor-record/{name}")));
        }
        Ok(vec_of(
            "anchor-record",
            name,
            desc,
            cbor,
            json!({ "check": "anchor-record" }),
            expected,
        ))
    };
    let base = |chain: &str, tx: &str, height: Option<i64>| AnchorRecord {
        checkpoint_hash: hash,
        chain_id: chain.to_string(),
        transaction_id: tx.to_string(),
        block_height: height,
        anchored_at: NOW - 3_000,
    };
    out.push(valid(
        "valid-solana-with-block-height",
        "A record on a registered chain with every key. Decoding gives the five fields; encoding them gives these bytes (map keys sorted by encoded length: chain-id, anchored-at, block-height, transaction-id, checkpoint-hash).",
        base("solana-mainnet", "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnb", Some(280_000_000)),
    )?);
    out.push(valid(
        "valid-ethereum-with-block-height",
        "A record on `ethereum-mainnet` with a 0x transaction hash.",
        base(
            "ethereum-mainnet",
            "0x88df016429689c079f3b2f6ad39fa052532c56795b733da78a91ebe6a713944b",
            Some(19_000_000),
        ),
    )?);
    out.push(valid(
        "valid-bitcoin-with-block-height",
        "A record on `bitcoin-mainnet`.",
        base(
            "bitcoin-mainnet",
            "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
            Some(850_000),
        ),
    )?);
    out.push(valid(
        "valid-opentimestamps-without-block-height",
        "`block-height` is optional: a witness with no height omits the key (it is never encoded as null or zero).",
        base("opentimestamps", "ots-calendar-a-0001", None),
    )?);
    out.push(valid(
        "valid-rekor-without-block-height",
        "A record on `rekor`, a public append-only log that is not a chain, with no `block-height`.",
        base("rekor", "24296fb24b8ad77a0d3ac2c6d5e2f1a6", None),
    )?);
    out.push(valid(
        "valid-extension-chain-id",
        "A record whose `chain-id` is an extension id, `x-acme-ledger`, valid without registration.",
        base("x-acme-ledger", "acme-tx-1", Some(7)),
    )?);
    out.push(valid(
        "valid-block-height-zero",
        "`block-height` 0 is an unsigned integer and is accepted (one byte head).",
        base("solana-mainnet", "zero-height", Some(0)),
    )?);
    out.push(valid(
        "valid-transaction-id-one-byte",
        "The shortest `transaction-id`, one byte.",
        base("rekor", "a", None),
    )?);
    out.push(valid(
        "valid-transaction-id-512-bytes",
        "The longest `transaction-id`, 512 bytes (a two byte text head).",
        base("rekor", &"t".repeat(512), None),
    )?);

    // Rejections. Every one is {ok: false, error: anchor_record_invalid}.
    let mut bad = |name: &str, desc: &str, cbor: Vec<u8>| -> R<()> {
        let expected = run_anchor_record(&cbor)?;
        if expected != json!({ "ok": false, "error": "anchor_record_invalid" }) {
            return Err(e(format!(
                "generator bug: anchor-record/{name}: {expected}"
            )));
        }
        out.push(vec_of(
            "anchor-record",
            name,
            desc,
            cbor,
            json!({ "check": "anchor-record" }),
            expected,
        ));
        Ok(())
    };
    bad(
        "reject-unknown-key",
        "A sixth key, `note`: a record has no other keys than the five.",
        rec_with(|es| {
            es.insert(1, ("note", Value::text("x").encode()));
            // keep deterministic order: `note` (4) sorts before every other key
            es.sort_by(|a, b| Value::text(a.0).encode().cmp(&Value::text(b.0).encode()));
        }),
    )?;
    bad(
        "reject-missing-checkpoint-hash",
        "`checkpoint-hash` is absent.",
        rec_with(|es| del(es, "checkpoint-hash")),
    )?;
    bad(
        "reject-missing-chain-id",
        "`chain-id` is absent.",
        rec_with(|es| del(es, "chain-id")),
    )?;
    bad(
        "reject-missing-transaction-id",
        "`transaction-id` is absent.",
        rec_with(|es| del(es, "transaction-id")),
    )?;
    bad(
        "reject-missing-anchored-at",
        "`anchored-at` is absent.",
        rec_with(|es| del(es, "anchored-at")),
    )?;
    bad(
        "reject-checkpoint-hash-31-bytes",
        "`checkpoint-hash` has 31 bytes.",
        rec_with(|es| set(es, "checkpoint-hash", Value::bytes(&hash[..31]))),
    )?;
    bad(
        "reject-checkpoint-hash-33-bytes",
        "`checkpoint-hash` has 33 bytes.",
        rec_with(|es| {
            let mut h = hash.to_vec();
            h.push(0);
            set(es, "checkpoint-hash", Value::bytes(&h))
        }),
    )?;
    bad(
        "reject-checkpoint-hash-as-text",
        "`checkpoint-hash` is the lowercase hex text of the hash, not a byte string.",
        rec_with(|es| set(es, "checkpoint-hash", Value::text(&hx(&hash)))),
    )?;
    bad(
        "reject-chain-id-unregistered",
        "`chain-id` is `dogecoin`: neither registered nor an `x-` extension id.",
        rec_with(|es| set(es, "chain-id", Value::text("dogecoin"))),
    )?;
    bad(
        "reject-chain-id-wrong-case",
        "`chain-id` is `Solana-mainnet`: registered ids are lowercase.",
        rec_with(|es| set(es, "chain-id", Value::text("Solana-mainnet"))),
    )?;
    bad(
        "reject-chain-id-empty",
        "`chain-id` is the empty string.",
        rec_with(|es| set(es, "chain-id", Value::text(""))),
    )?;
    bad(
        "reject-chain-id-not-text",
        "`chain-id` is the integer 7.",
        rec_with(|es| set(es, "chain-id", Value::Int(7))),
    )?;
    bad(
        "reject-transaction-id-empty",
        "`transaction-id` is empty.",
        rec_with(|es| set(es, "transaction-id", Value::text(""))),
    )?;
    bad(
        "reject-transaction-id-513-bytes",
        "`transaction-id` has 513 bytes.",
        rec_with(|es| set(es, "transaction-id", Value::text(&"t".repeat(513)))),
    )?;
    bad(
        "reject-transaction-id-as-bytes",
        "`transaction-id` is a byte string, not text.",
        rec_with(|es| set(es, "transaction-id", Value::bytes(b"tx"))),
    )?;
    bad(
        "reject-block-height-negative",
        "`block-height` is -1: it is unsigned.",
        rec_with(|es| set(es, "block-height", Value::Int(-1))),
    )?;
    bad(
        "reject-block-height-as-text",
        "`block-height` is the text `280000000`.",
        rec_with(|es| set(es, "block-height", Value::text("280000000"))),
    )?;
    bad(
        "reject-block-height-null",
        "`block-height` is present as null: an absent height is omitted, never null.",
        rec_with(|es| set(es, "block-height", Value::Null)),
    )?;
    bad(
        "reject-anchored-at-negative",
        "`anchored-at` is -1.",
        rec_with(|es| set(es, "anchored-at", Value::Int(-1))),
    )?;
    bad(
        "reject-anchored-at-as-text",
        "`anchored-at` is a text string.",
        rec_with(|es| set(es, "anchored-at", Value::text("1799997000"))),
    )?;
    bad(
        "reject-not-a-map",
        "The document is an array of one integer, not a map.",
        Value::Array(vec![Value::Int(1)]).encode(),
    )?;
    bad(
        "reject-non-text-key",
        "A key is the integer 1 where a text key belongs.",
        {
            let mut b = vec![0xa5];
            b.extend(Value::Int(1).encode());
            b.extend(Value::text("solana-mainnet").encode());
            for (k, v) in good_entries().into_iter().skip(1) {
                b.extend(Value::text(k).encode());
                b.extend(v);
            }
            b
        },
    )?;
    bad(
        "reject-map-keys-not-sorted",
        "A valid record whose map keys are not in the deterministic order (`anchored-at` before `chain-id`): not strict deterministic CBOR.",
        rec_with(|es| es.swap(0, 1)),
    )?;
    bad(
        "reject-duplicate-key",
        "`chain-id` appears twice.",
        rec_with(|es| {
            let first = es[0].clone();
            es.insert(1, first);
        }),
    )?;
    bad(
        "reject-integer-not-shortest-form",
        "`anchored-at` is encoded with a one byte argument head where the value fits in the initial byte: not shortest form.",
        rec_with(|es| {
            for (k, v) in es.iter_mut() {
                if *k == "anchored-at" {
                    // 5 in a two byte head (0x18 0x05) instead of 0x05.
                    *v = vec![0x18, 0x05];
                }
            }
        }),
    )?;
    bad(
        "reject-indefinite-length-map",
        "The record is an indefinite length map (0xbf ... 0xff).",
        {
            let mut b = vec![0xbf];
            for (k, v) in good_entries() {
                b.extend(Value::text(k).encode());
                b.extend(v);
            }
            b.push(0xff);
            b
        },
    )?;
    bad(
        "reject-trailing-bytes",
        "A valid record followed by one extra byte.",
        {
            let mut b = rec_with(|_| {});
            b.push(0x00);
            b
        },
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// chain-id

fn run_chain_id(cbor: &[u8], inputs: &J) -> R<J> {
    let id = Value::decode(cbor)?
        .as_text()
        .ok_or_else(|| e("chain-id vector is not a CBOR text string"))?
        .to_string();
    if jstr(inputs, "id")? != id {
        return Err(e("`inputs.id` is not the text in the CBOR file"));
    }
    Ok(if is_registered_chain(&id) {
        json!({ "ok": true, "kind": "registered" })
    } else if is_extension_chain(&id) {
        json!({ "ok": true, "kind": "extension" })
    } else {
        json!({ "ok": false })
    })
}

fn chain_id_vectors(out: &mut Vec<Vector>) -> R<()> {
    let long_ok = format!("x-{}", "a".repeat(62));
    let long_bad = format!("x-{}", "a".repeat(63));
    let table: Vec<(&str, String, &str, &str)> = vec![
        // name, id, kind (registered, extension or "" for invalid), description
        (
            "registered-solana-mainnet",
            "solana-mainnet".into(),
            "registered",
            "Registered: Solana mainnet-beta.",
        ),
        (
            "registered-ethereum-mainnet",
            "ethereum-mainnet".into(),
            "registered",
            "Registered: Ethereum mainnet.",
        ),
        (
            "registered-bitcoin-mainnet",
            "bitcoin-mainnet".into(),
            "registered",
            "Registered: Bitcoin mainnet, direct transaction.",
        ),
        (
            "registered-opentimestamps",
            "opentimestamps".into(),
            "registered",
            "Registered: Bitcoin via an OpenTimestamps calendar.",
        ),
        (
            "registered-rekor",
            "rekor".into(),
            "registered",
            "Registered: Sigstore Rekor.",
        ),
        (
            "extension-one-letter",
            "x-a".into(),
            "extension",
            "Extension id with a one character name.",
        ),
        (
            "extension-name",
            "x-acme".into(),
            "extension",
            "Extension id `x-acme`.",
        ),
        (
            "extension-inner-hyphens-and-digits",
            "x-acme-ledger-2".into(),
            "extension",
            "Extension id with inner hyphens and a digit.",
        ),
        (
            "extension-digit-first",
            "x-0ledger".into(),
            "extension",
            "The name may begin with a digit.",
        ),
        (
            "extension-64-bytes",
            long_ok,
            "extension",
            "Extension id of exactly 64 bytes: the longest allowed.",
        ),
        (
            "invalid-extension-65-bytes",
            long_bad,
            "",
            "Extension id of 65 bytes: too long.",
        ),
        ("invalid-empty", String::new(), "", "The empty string."),
        (
            "invalid-extension-prefix-only",
            "x-".into(),
            "",
            "`x-` with no name.",
        ),
        (
            "invalid-extension-hyphen-only-name",
            "x--".into(),
            "",
            "The name is a single hyphen: it begins and ends with a hyphen.",
        ),
        (
            "invalid-extension-trailing-hyphen",
            "x-acme-".into(),
            "",
            "The name ends with a hyphen.",
        ),
        (
            "invalid-extension-leading-hyphen",
            "x--acme".into(),
            "",
            "The name begins with a hyphen.",
        ),
        (
            "invalid-extension-uppercase",
            "x-Acme".into(),
            "",
            "The name has an uppercase letter.",
        ),
        (
            "invalid-extension-underscore",
            "x-acme_ledger".into(),
            "",
            "The name has an underscore.",
        ),
        (
            "invalid-extension-dot",
            "x-acme.ledger".into(),
            "",
            "The name has a dot.",
        ),
        (
            "invalid-extension-space",
            "x-acme ledger".into(),
            "",
            "The name has a space.",
        ),
        (
            "invalid-extension-non-ascii",
            "x-caf\u{e9}".into(),
            "",
            "The name has a non ASCII letter.",
        ),
        (
            "invalid-extension-prefix-uppercase",
            "X-acme".into(),
            "",
            "The prefix is `X-`: the extension prefix is lowercase `x-`.",
        ),
        (
            "invalid-extension-prefix-underscore",
            "x_acme".into(),
            "",
            "`x_acme` is not an extension id.",
        ),
        (
            "invalid-extension-prefix-missing-hyphen",
            "xacme".into(),
            "",
            "`xacme` is not an extension id.",
        ),
        (
            "invalid-unregistered-dogecoin",
            "dogecoin".into(),
            "",
            "Not in the table and not an extension id.",
        ),
        (
            "invalid-unregistered-prefix-of-registered",
            "solana".into(),
            "",
            "A prefix of a registered id is not registered.",
        ),
        (
            "invalid-registered-wrong-case",
            "Solana-mainnet".into(),
            "",
            "Registered ids are matched exactly, in lowercase.",
        ),
        (
            "invalid-registered-trailing-space",
            "solana-mainnet ".into(),
            "",
            "A registered id with a trailing space.",
        ),
        (
            "invalid-registered-with-suffix",
            "rekor2".into(),
            "",
            "A registered id with a suffix.",
        ),
        (
            "invalid-unregistered-testnet",
            "bitcoin-testnet".into(),
            "",
            "A plausible chain that is not in the table.",
        ),
    ];
    for (name, id, kind, desc) in table {
        let cbor = Value::text(&id).encode();
        let inputs = json!({ "check": "chain-id", "id": id });
        let expected = run_chain_id(&cbor, &inputs)?;
        let want = if kind.is_empty() {
            json!({ "ok": false })
        } else {
            json!({ "ok": true, "kind": kind })
        };
        if expected != want {
            return Err(e(format!("generator bug: chain-id/{name}: {expected}")));
        }
        out.push(vec_of("chain-id", name, desc, cbor, inputs, expected));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// anchor-envelope

fn run_anchor_envelope(cbor: &[u8], inputs: &J) -> R<J> {
    let now = jint(inputs, "now")?;
    let log = AgentId::parse(jstr(inputs, "log")?)?;
    let hash: [u8; 32] = jhex(inputs, "checkpoint_hash_hex")?;
    Ok(match check_published_anchor(cbor, &log, &hash, now) {
        Ok(rec) => json!({ "ok": true, "log": log.to_text(), "record": record_json(&rec) }),
        Err(x) => rejection_json(&x),
    })
}

fn anchor_payload(hash: [u8; 32], chain: &str, tx: &str, height: Option<i64>) -> Vec<u8> {
    AnchorRecord {
        checkpoint_hash: hash,
        chain_id: chain.to_string(),
        transaction_id: tx.to_string(),
        block_height: height,
        anchored_at: NOW - 3_000,
    }
    .encode()
}

fn anchor_env(signer: &Identity, ct: &str, payload: &[u8], label: &str, issued: i64) -> R<Vec<u8>> {
    let mut sp = SignParams::new(payload, ct, nonce(label), issued);
    sp.mode = SignMode::Deterministic;
    sign(signer, &sp)
}

fn anchor_envelope_vectors(out: &mut Vec<Vector>, n: &Net) -> R<()> {
    let log = &n.log;
    let cp = Checkpoint {
        tree_size: 12,
        root_hash: label_hash("anchor/env/root"),
        timestamp: T_CP,
    };
    let hash = cp.hash();
    let other = Checkpoint {
        tree_size: 13,
        root_hash: label_hash("anchor/env/root13"),
        timestamp: T_CP + 60,
    }
    .hash();
    let issued = NOW - 2_900;
    let push = |out: &mut Vec<Vector>,
                name: &str,
                desc: &str,
                cbor: Vec<u8>,
                looking_at: [u8; 32],
                want: Result<(), (u8, &str)>|
     -> R<()> {
        let inputs = json!({
            "now": NOW,
            "log": log.agent_id().to_text(),
            "checkpoint_hash_hex": hx(&looking_at),
        });
        let expected = run_anchor_envelope(&cbor, &inputs)?;
        let ok = match want {
            Ok(()) => expected["ok"] == true,
            Err((step, code)) => {
                expected["ok"] == false && expected["step"] == step && expected["error"] == code
            }
        };
        if !ok {
            return Err(e(format!(
                "generator bug: anchor-envelope/{name}: {expected}"
            )));
        }
        out.push(vec_of(
            "anchor-envelope",
            name,
            desc,
            cbor,
            inputs,
            expected,
        ));
        Ok(())
    };
    let sol = anchor_payload(
        hash,
        "solana-mainnet",
        "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnb",
        Some(280_000_000),
    );
    let valid = anchor_env(log, CT_ANCHOR, &sol, "ae/valid", issued)?;
    push(
        out,
        "valid-solana",
        "A log-signed anchor record: tag 98, content type application/atep-anchor+cbor, no expires-at, signer bundle inline, signed by the log the verifier asked about, and its checkpoint-hash is the hash of the checkpoint the verifier is looking at. Accepted.",
        valid.clone(),
        hash,
        Ok(()),
    )?;
    let rekor = anchor_payload(hash, "rekor", "24296fb24b8ad77a0d3ac2c6d5e2f1a6", None);
    push(
        out,
        "valid-rekor-without-block-height",
        "As valid-solana for `rekor`, a record without `block-height`.",
        anchor_env(log, CT_ANCHOR, &rekor, "ae/rekor", issued)?,
        hash,
        Ok(()),
    )?;
    let ext = anchor_payload(hash, "x-acme-ledger", "acme-tx-1", Some(7));
    push(
        out,
        "valid-extension-chain-id",
        "As valid-solana for the extension witness `x-acme-ledger`: the extension rule makes it a valid record.",
        anchor_env(log, CT_ANCHOR, &ext, "ae/ext", issued)?,
        hash,
        Ok(()),
    )?;
    push(
        out,
        "forged-eddsa-signature",
        "valid-solana with the last byte of the EdDSA signature flipped. Expect step 4 eddsa_signature_invalid: a record whose envelope does not verify is not published.",
        mutate(&valid, |a| flip_last(sig_slot(a, 0)))?,
        hash,
        Err((4, "eddsa_signature_invalid")),
    )?;
    push(
        out,
        "forged-mldsa-signature",
        "valid-solana with the last byte of the ML-DSA-65 signature flipped. Expect step 4 mldsa_signature_invalid.",
        mutate(&valid, |a| flip_last(sig_slot(a, 1)))?,
        hash,
        Err((4, "mldsa_signature_invalid")),
    )?;
    push(
        out,
        "forged-payload-altered-after-signing",
        "The last byte of the attached record (part of `checkpoint-hash`) is changed after signing. Expect step 4 eddsa_signature_invalid.",
        mutate(&valid, |a| flip_last(&mut a[2]))?,
        hash,
        Err((4, "eddsa_signature_invalid")),
    )?;
    push(
        out,
        "signed-by-another-identity",
        "A well formed record signed by mallory, whose bundle is inline, for the right checkpoint. The envelope verifies, but its signer is not the log the verifier asked about. Expect step 9 anchor_log_mismatch.",
        anchor_env(&n.mallory, CT_ANCHOR, &sol, "ae/mallory", issued)?,
        hash,
        Err((9, "anchor_log_mismatch")),
    )?;
    push(
        out,
        "unknown-checkpoint",
        "valid-solana, looked at by a verifier that is examining another checkpoint of the same log: the record's checkpoint-hash is not the hash of that checkpoint. Expect step 9 anchor_checkpoint_mismatch.",
        valid.clone(),
        other,
        Err((9, "anchor_checkpoint_mismatch")),
    )?;
    push(
        out,
        "wrong-content-type",
        "A record payload signed by the log under the checkpoint content type, which verifies (a trust document label) but is not an anchor envelope. Expect step 9 anchor_content_type_invalid.",
        anchor_env(log, CT_CHECKPOINT, &sol, "ae/wrongct", issued)?,
        hash,
        Err((9, "anchor_content_type_invalid")),
    )?;
    let mut unknown_key = Value::decode(&sol)?;
    if let Value::Map(m) = &mut unknown_key {
        m.push((Value::text("note"), Value::text("x")));
    }
    push(
        out,
        "payload-unknown-key",
        "A validly signed envelope of the anchor type whose record has a sixth key. Expect step 9 anchor_schema_invalid.",
        anchor_env(log, CT_ANCHOR, &unknown_key.encode(), "ae/unkkey", issued)?,
        hash,
        Err((9, "anchor_schema_invalid")),
    )?;
    push(
        out,
        "payload-unregistered-chain-id",
        "A validly signed envelope whose record names the chain `dogecoin`. Expect step 9 anchor_schema_invalid.",
        anchor_env(
            log,
            CT_ANCHOR,
            &anchor_payload(hash, "dogecoin", "tx", None),
            "ae/badchain",
            issued,
        )?,
        hash,
        Err((9, "anchor_schema_invalid")),
    )?;
    push(
        out,
        "payload-not-a-map",
        "A validly signed envelope of the anchor type whose payload is the text `hello`. Expect step 9 anchor_schema_invalid.",
        anchor_env(log, CT_ANCHOR, &Value::text("hello").encode(), "ae/notmap", issued)?,
        hash,
        Err((9, "anchor_schema_invalid")),
    )?;
    push(
        out,
        "issued-in-the-future",
        "A record whose envelope has issued-at an hour after now: it fails step 5 like any envelope. Expect step 5 issued_in_future.",
        anchor_env(log, CT_ANCHOR, &sol, "ae/future", NOW + 3_600)?,
        hash,
        Err((5, "issued_in_future")),
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// anchor-media-type

fn anchor_media_type_vectors(out: &mut Vec<Vector>, n: &Net) -> R<()> {
    let log = &n.log;
    let hash = label_hash("anchor/mt/hash");
    let sol = anchor_payload(hash, "solana-mainnet", "5VERv8NMvz", Some(1));
    let at = NOW - 2_900;
    // With no trust policy the core verifier checks steps 1 to 8 and the label only.
    push_verify(
        out,
        "anchor-media-type",
        "bare-anchor-envelope-accepted",
        "A bare tag 98 envelope with content type application/atep-anchor+cbor is a trust document: step 1 accepts it unencrypted (Draft 03 rejected it as unencrypted_non_trust_document). No expires-at is needed, unlike an attestation. Expect acceptance with no trust policy.",
        anchor_env(log, CT_ANCHOR, &sol, "amt/ok", at)?,
        pol(NOW),
        None,
    )?;
    push_verify(
        out,
        "anchor-media-type",
        "bare-anchor-envelope-garbage-payload-accepted",
        "A bare envelope of the anchor type whose payload is the text `not a record`. The core verifier checks the label only (section 5), so with no trust policy it is accepted; whoever interprets the payload as an anchor record validates it (anchor-envelope vectors).",
        anchor_env(log, CT_ANCHOR, &Value::text("not a record").encode(), "amt/garbage", at)?,
        pol(NOW),
        None,
    )?;
    push_verify(
        out,
        "anchor-media-type",
        "lookalike-media-type-rejected",
        "A bare envelope with content type application/atep-anchor+json: only the four listed media types may travel unencrypted, so this is not a trust document. Expect step 1 unencrypted_non_trust_document.",
        anchor_env(log, "application/atep-anchor+json", &sol, "amt/lookalike", at)?,
        pol(NOW),
        Some((1, "unencrypted_non_trust_document")),
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// require-anchor (policy parse)

fn run_require_anchor(cbor: &[u8], inputs: &J) -> R<J> {
    let policy = jget(inputs, "policy")?;
    json_cbor_agree(cbor, policy)?;
    Ok(match TrustPolicy::from_json(policy) {
        Ok(p) => {
            let rules: Vec<J> = p
                .require_anchor
                .iter()
                .map(|r| {
                    let mut m = Map::new();
                    m.insert("log".into(), r.log.to_text().into());
                    m.insert("chain".into(), r.chain.clone().into());
                    match r.max_age {
                        crate::anchor::AnchorMaxAge::Days(d) => {
                            m.insert("max_age_days".into(), d.into())
                        }
                        crate::anchor::AnchorMaxAge::Hours(h) => {
                            m.insert("max_age_hours".into(), h.into())
                        }
                    };
                    J::Object(m)
                })
                .collect();
            json!({ "ok": true, "require_anchor": rules })
        }
        Err(_) => json!({ "ok": false, "error": "policy_invalid" }),
    })
}

fn require_anchor_vectors(out: &mut Vec<Vector>) -> R<()> {
    let log = ident("log", false)?.agent_id().to_text();
    let log_did = log.replacen("atep:", "did:atep:", 1);
    let mut one = |name: &str, desc: &str, policy: J, ok: bool| -> R<()> {
        let cbor = crate::attestation::json_to_cbor(&policy)?.encode();
        let inputs = json!({ "check": "require-anchor", "policy": policy });
        let expected = run_require_anchor(&cbor, &inputs)?;
        if (expected["ok"] == true) != ok {
            return Err(e(format!(
                "generator bug: require-anchor/{name}: {expected}"
            )));
        }
        out.push(vec_of("require-anchor", name, desc, cbor, inputs, expected));
        Ok(())
    };
    let rule = |chain: &str, age: (&str, i64)| json!({ "log": log, "chain": chain, age.0: age.1 });
    one(
        "valid-max-age-days",
        "One rule with `max_age_days`. Parses; `require_anchor` is a known member.",
        json!({ "require_anchor": [rule("solana-mainnet", ("max_age_days", 2))] }),
        true,
    )?;
    one(
        "valid-max-age-hours",
        "One rule with `max_age_hours`.",
        json!({ "require_anchor": [rule("ethereum-mainnet", ("max_age_hours", 6))] }),
        true,
    )?;
    one(
        "valid-minimum-age-of-one",
        "`max_age_days` 1 is the smallest allowed value.",
        json!({ "require_anchor": [rule("rekor", ("max_age_days", 1))] }),
        true,
    )?;
    one(
        "valid-two-rules-conjunction",
        "Two rules, two witnesses: the array is a conjunction, so both are kept in order.",
        json!({ "require_anchor": [
            rule("bitcoin-mainnet", ("max_age_days", 3)),
            rule("opentimestamps", ("max_age_hours", 12)),
        ]}),
        true,
    )?;
    one(
        "valid-extension-chain",
        "A rule whose `chain` is an extension id.",
        json!({ "require_anchor": [rule("x-acme-ledger", ("max_age_days", 7))] }),
        true,
    )?;
    one(
        "valid-empty-array",
        "An empty `require_anchor` array is the same as no member: no rules.",
        json!({ "require_anchor": [] }),
        true,
    )?;
    one(
        "valid-log-in-did-form",
        "`log` in the `did:atep:` form is accepted and reported in the canonical `atep:` form.",
        json!({ "require_anchor": [{ "log": log_did, "chain": "rekor", "max_age_days": 1 }] }),
        true,
    )?;
    one(
        "valid-with-other-members",
        "A policy that sets other members as well; only `require_anchor` is reported.",
        json!({ "roots": [log], "max_depth": 3, "require_inclusion": false,
                "require_anchor": [rule("solana-mainnet", ("max_age_hours", 24))] }),
        true,
    )?;
    one(
        "invalid-missing-log",
        "A rule without `log`: a configuration error.",
        json!({ "require_anchor": [{ "chain": "rekor", "max_age_days": 1 }] }),
        false,
    )?;
    one(
        "invalid-missing-chain",
        "A rule without `chain`.",
        json!({ "require_anchor": [{ "log": log, "max_age_days": 1 }] }),
        false,
    )?;
    one(
        "invalid-missing-age",
        "A rule with neither `max_age_days` nor `max_age_hours`.",
        json!({ "require_anchor": [{ "log": log, "chain": "rekor" }] }),
        false,
    )?;
    one(
        "invalid-both-ages",
        "A rule with both `max_age_days` and `max_age_hours`: exactly one is allowed.",
        json!({ "require_anchor": [{ "log": log, "chain": "rekor", "max_age_days": 1, "max_age_hours": 1 }] }),
        false,
    )?;
    one(
        "invalid-unknown-rule-member",
        "A rule with an extra member, `min_age_days`.",
        json!({ "require_anchor": [{ "log": log, "chain": "rekor", "max_age_days": 1, "min_age_days": 1 }] }),
        false,
    )?;
    one(
        "invalid-age-days-zero",
        "`max_age_days` 0: at least 1 is required.",
        json!({ "require_anchor": [rule("rekor", ("max_age_days", 0))] }),
        false,
    )?;
    one(
        "invalid-age-hours-zero",
        "`max_age_hours` 0.",
        json!({ "require_anchor": [rule("rekor", ("max_age_hours", 0))] }),
        false,
    )?;
    one(
        "invalid-age-negative",
        "`max_age_days` -1.",
        json!({ "require_anchor": [rule("rekor", ("max_age_days", -1))] }),
        false,
    )?;
    one(
        "invalid-age-as-text",
        "`max_age_days` is the text `2`.",
        json!({ "require_anchor": [{ "log": log, "chain": "rekor", "max_age_days": "2" }] }),
        false,
    )?;
    one(
        "invalid-chain-unregistered",
        "`chain` is `dogecoin`: not registered and not an extension id. A policy rule with an invalid chain-id is a configuration error, not a rule that never matches.",
        json!({ "require_anchor": [rule("dogecoin", ("max_age_days", 1))] }),
        false,
    )?;
    one(
        "invalid-chain-malformed-extension",
        "`chain` is `x-`: an extension id needs a name.",
        json!({ "require_anchor": [rule("x-", ("max_age_days", 1))] }),
        false,
    )?;
    one(
        "invalid-chain-not-text",
        "`chain` is the integer 1.",
        json!({ "require_anchor": [{ "log": log, "chain": 1, "max_age_days": 1 }] }),
        false,
    )?;
    one(
        "invalid-log-malformed",
        "`log` is `nope`, not an Agent ID.",
        json!({ "require_anchor": [{ "log": "nope", "chain": "rekor", "max_age_days": 1 }] }),
        false,
    )?;
    one(
        "invalid-log-not-text",
        "`log` is the integer 5.",
        json!({ "require_anchor": [{ "log": 5, "chain": "rekor", "max_age_days": 1 }] }),
        false,
    )?;
    one(
        "invalid-rule-not-an-object",
        "A rule that is a text string.",
        json!({ "require_anchor": ["rekor"] }),
        false,
    )?;
    one(
        "invalid-one-bad-rule-among-good",
        "The second of two rules is malformed: the whole policy is refused, never partly applied.",
        json!({ "require_anchor": [
            rule("rekor", ("max_age_days", 1)),
            { "log": log, "chain": "rekor" },
        ]}),
        false,
    )?;
    one(
        "invalid-member-is-an-object",
        "`require_anchor` is an object, not an array.",
        json!({ "require_anchor": { "log": log, "chain": "rekor", "max_age_days": 1 } }),
        false,
    )?;
    one(
        "invalid-member-is-null",
        "`require_anchor` is null.",
        json!({ "require_anchor": null }),
        false,
    )?;
    one(
        "invalid-member-spelled-with-hyphen",
        "`require-anchor` (hyphen) is not a member of the policy: an unknown member is an error, so the typo cannot silently weaken the policy.",
        json!({ "require-anchor": [rule("rekor", ("max_age_days", 1))] }),
        false,
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// anchor-not-supported (verification vectors)

fn anchor_not_supported_vectors(out: &mut Vec<Vector>, n: &Net) -> R<()> {
    const CAT: &str = "anchor-not-supported";
    let log = n.log.agent_id().to_text();
    let anchor_rule = json!({ "log": log, "chain": "solana-mainnet", "max_age_hours": 6 });
    let alice_env = |label: &str, inline: &[&[u8]]| -> R<Vec<u8>> {
        envelope_for(
            n,
            &n.alice,
            label,
            None,
            payload_for(&format!("ans/{label}")),
            inline,
        )
    };
    // alice holds `operator` from the root: a rule that would pass.
    let op = issue_att(
        &A::std(&n.root, n.alice.agent_id(), claims::OPERATOR, "ans/op")
            .data(text_map(vec![("name", Value::text("Acme Robotics Ltd"))])),
    )?;

    push_verify(
        out,
        CAT,
        "policy-with-only-require-anchor",
        "The policy has a require_anchor rule and nothing else. A verifier that cannot evaluate anchors fails closed: step 9 anchor_not_supported, although there is no other rule and the envelope would otherwise be accepted.",
        alice_env("only", &[])?,
        policy_with(n, json!({ "require_anchor": [anchor_rule] })),
        Some((9, "anchor_not_supported")),
    )?;
    push_verify(
        out,
        CAT,
        "with-a-rule-that-would-pass",
        "roots [root], rule `operator`, and alice holds an operator attestation from the root: without require_anchor this is accepted. With the require_anchor rule it is step 9 anchor_not_supported, whether or not the other rules would have passed.",
        alice_env("pass", &[&op])?,
        policy_with(
            n,
            trust_json(
                &[&n.root],
                vec![rule("operator")],
                json!({ "require_anchor": [anchor_rule] }),
            ),
        ),
        Some((9, "anchor_not_supported")),
    )?;
    push_verify(
        out,
        CAT,
        "with-a-rule-that-would-fail",
        "As with-a-rule-that-would-pass but alice holds no attestation: without require_anchor the rule fails with claim_missing. The anchor refusal is reported first, so the result is anchor_not_supported and not claim_missing.",
        alice_env("fail", &[])?,
        policy_with(
            n,
            trust_json(
                &[&n.root],
                vec![rule("operator")],
                json!({ "require_anchor": [anchor_rule] }),
            ),
        ),
        Some((9, "anchor_not_supported")),
    )?;
    push_verify(
        out,
        CAT,
        "two-require-anchor-rules",
        "Two require_anchor rules (a policy that wants two witnesses). Same result.",
        alice_env("two", &[])?,
        policy_with(
            n,
            json!({ "require_anchor": [
                anchor_rule,
                { "log": log, "chain": "opentimestamps", "max_age_days": 2 },
            ]}),
        ),
        Some((9, "anchor_not_supported")),
    )?;
    push_verify(
        out,
        CAT,
        "before-the-atep-r-class-requirement",
        "ATEP-R is on, the envelope is an encrypted `telemetry` command with no fleet-member attestation (the class requirement would fail with claim_missing), and the policy has a require_anchor rule. Step 1 passes, then step 9 reports anchor_not_supported first.",
        envelope_for(
            n,
            &n.alice,
            "ans/atepr",
            Some("telemetry"),
            payload_for("ans/atepr"),
            &[],
        )?,
        policy_with(
            n,
            json!({ "atep_r": true, "require_anchor": [anchor_rule] }),
        ),
        Some((9, "anchor_not_supported")),
    )?;
    push_verify(
        out,
        CAT,
        "empty-array-is-no-rule",
        "`require_anchor` is an empty array: the policy behaves exactly as under Draft 03. With no other rule step 9 evaluates nothing and the envelope is accepted.",
        alice_env("empty", &[])?,
        policy_with(n, json!({ "require_anchor": [] })),
        None,
    )?;
    push_verify(
        out,
        CAT,
        "empty-array-and-a-failing-rule",
        "An empty `require_anchor` array and a rule alice cannot satisfy: the result is claim_missing, not anchor_not_supported.",
        alice_env("emptyfail", &[])?,
        policy_with(
            n,
            trust_json(
                &[&n.root],
                vec![rule("operator")],
                json!({ "require_anchor": [] }),
            ),
        ),
        Some((9, "claim_missing")),
    )?;
    // Steps 1 to 8 come first: the refusal is reported after they have passed.
    let mut revoked = policy_with(n, json!({ "require_anchor": [anchor_rule] }));
    revoked.revocations = vec![Revocation {
        id: n.alice.agent_id(),
        reason: RevocationReason::Compromised,
        revoked_at: NOW - 7_200,
    }];
    push_verify(
        out,
        CAT,
        "step-8-failure-is-reported-first",
        "alice is listed as compromised since before the envelope was issued, and the policy has a require_anchor rule. The anchor refusal is reported after steps 1 to 8 have passed, so the result is step 8 signer_revoked.",
        alice_env("revoked", &[])?,
        revoked,
        Some((8, "signer_revoked")),
    )?;
    let mut wrong_recipient = policy_with(n, json!({ "require_anchor": [anchor_rule] }));
    wrong_recipient.recipient = Some(n.carol.seeds().clone());
    push_verify(
        out,
        CAT,
        "step-2-failure-is-reported-first",
        "The envelope is encrypted to bob but the verifier holds carol's keys, and the policy has a require_anchor rule. Step 2 not_addressed_to_recipient is reported, not the anchor refusal.",
        alice_env("wrongrec", &[])?,
        wrong_recipient,
        Some((2, "not_addressed_to_recipient")),
    )?;
    Ok(())
}
