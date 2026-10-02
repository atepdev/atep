// Runs every vector in ../vectors through the @atep/core npm package (wasm).
// Mirrors the checks of `atep-vectors check` (rust/atep-core/src/vectors.rs).
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";
import {
  init, Identity, parseAgentId, agentId, encryptDeterministic, decrypt, verify, view, sha256,
  verifyCheckpoint, verifyInclusion, checkConsistency, checkSplitView, verifySrl,
  hexToBytes, bytesToHex, submittedFormOf,
  chainIdKind, parseAnchorRecord, encodeAnchorRecord, checkpointHash, checkPublishedAnchor,
  parseRequireAnchor, checkAdmission, checkDomainBinding,
} from "../dist/index.js";

const vecDir = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "vectors");
const manifest = JSON.parse(readFileSync(join(vecDir, "manifest.json"), "utf8"));
const rd = (p) => readFileSync(join(vecDir, p));
const eqBytes = (a, b, msg) => assert.equal(bytesToHex(a), bytesToHex(b), msg);

// Categories that need a transparency log or a monitor, which this package does
// not have (it is a verifier). Draft 04 vectors/RETIRED-SUCCESSOR-NOTES.md
// section 1: they apply only to implementations with a log or monitor.
const SKIPPED = {
  "log-admission": "stateful log admission needs a log (section 9); this package has no log (checkAdmission only checks one submission, used for registry-endpoint)",
  "monitor": "the successor_chain alert needs a monitor; this package has none",
};
const counts = {};
const skipped = {};
const byCat = {};
for (const v of manifest.vectors) (byCat[v.category] ??= []).push(v);

before(async () => { await init(); });
after(() => {
  console.log("\nvectors passed per category:");
  let total = 0;
  for (const [c, n] of Object.entries(counts)) { console.log(`  ${c.padEnd(16)} ${n}/${byCat[c].length}`); total += n; }
  let skips = 0;
  for (const [c, names] of Object.entries(skipped)) {
    console.log(`  ${c.padEnd(16)} SKIPPED ${names.length}/${byCat[c].length}: ${SKIPPED[c]}`);
    console.log(`    ${names.join(", ")}`);
    skips += names.length;
  }
  console.log(`  ${"total".padEnd(16)} ${total} passed + ${skips} skipped = ${total + skips}/${manifest.vectors.length}`);
});

function load(cat, name) {
  const meta = JSON.parse(rd(`${cat}/${name}.expected.json`));
  const cbor = new Uint8Array(rd(`${cat}/${meta.cbor_file}`));
  return { meta, cbor, inputs: meta.inputs, expected: meta.expected };
}

// Checks every vector gets, regardless of category.
function common(cat, name, meta, cbor, listed) {
  assert.equal(bytesToHex(sha256(cbor)), meta.cbor_sha256, "cbor_sha256");
  assert.equal(listed.cbor_sha256, meta.cbor_sha256, "manifest sha256");
  const onDisk = JSON.parse(rd(`${cat}/${name}.json`).toString("utf8"));
  // Bytes that are not strict deterministic CBOR (some anchor-record rejections, on purpose) have
  // no JSON view; their .json is {not_strict_cbor: true, hex} (vectors/README.md).
  let shown;
  try { shown = view(cbor); } catch (e) {
    // Only a vector that says so may be unreadable as strict CBOR.
    assert.ok(onDisk && onDisk.not_strict_cbor === true, `view failed: ${e.message}`);
    shown = { not_strict_cbor: true, hex: bytesToHex(cbor) };
  }
  assert.deepEqual(shown, onDisk, "JSON view differs from the vector .json");
}

// Object under test is a JSON value (require-anchor, domain-binding, chain-id): the .cbor is its
// deterministic CBOR encoding, so the CBOR view must equal the JSON in `inputs`.
function agrees(cbor, value) {
  const v = view(cbor);
  assert.deepEqual(v, value, "the CBOR file is not the encoding of the JSON in inputs");
}

const checkers = {
  identity({ cbor, inputs, expected }) {
    const id = Identity.fromSeedsHex(inputs.seeds);
    eqBytes(id.publicBundle, cbor, "bundle bytes");
    assert.equal(agentId(cbor), expected.agent_id);
    assert.equal(id.agentId, expected.agent_id);
    assert.equal(id.did, expected.did);
    const p = parseAgentId(expected.did);
    assert.equal(p.text, expected.agent_id);
    assert.equal(p.hex, expected.agent_id_hex);
    assert.equal(id.hasEncryption, !!inputs.seeds.x25519);
    assert.equal(cbor.length, expected.bundle_len);
    id.free();
  },
  signing({ cbor, inputs, expected }) {
    const id = Identity.fromSeedsHex(inputs.signer_seeds);
    const out = id.sign(hexToBytes(inputs.payload_hex), {
      contentType: inputs.content_type,
      nonce: hexToBytes(inputs.nonce_hex),
      issuedAt: inputs.issued_at,
      expiresAt: inputs.expires_at,
      detached: inputs.detached,
      includeBundle: inputs.include_bundle,
      deterministic: inputs.mode === "deterministic",
    });
    eqBytes(out, cbor, "signed envelope bytes");
    assert.equal(bytesToHex(sha256(cbor)), expected.envelope_sha256);
    assert.equal(cbor.length, expected.envelope_len);
    assert.equal(id.agentId, expected.signer);
    id.free();
  },
  encryption({ cbor, inputs, expected }) {
    const rec = Identity.fromSeedsHex(inputs.recipient_seeds);
    const inner = hexToBytes(inputs.inner_envelope_hex);
    const r = inputs.randomness;
    const ct = encryptDeterministic(inner, rec.publicBundle, {
      x25519Ephemeral: hexToBytes(r.x25519_ephemeral_hex),
      mlkemM: hexToBytes(r.mlkem_m_hex),
      iv: hexToBytes(r.iv_hex),
    });
    eqBytes(ct, cbor, "ciphertext bytes");
    eqBytes(decrypt(rec, cbor), inner, "decrypted inner envelope");
    assert.equal(cbor.length, expected.ciphertext_len);
    assert.equal(bytesToHex(sha256(cbor)), expected.ciphertext_sha256);
    assert.equal(rec.agentId, expected.recipient);
    rec.free();
  },
  verifyLike({ cbor, inputs, expected }) {
    const policy = inputs.policy;
    const now = policy.now;
    assert.deepEqual(verify(cbor, policy, { now }), expected);
  },
  attestation({ cbor, inputs, expected }) {
    const issuer = Identity.fromSeedsHex(inputs.issuer_seeds);
    const out = issuer.issueAttestation({
      subject: inputs.subject,
      claim: inputs.claim,
      issuedAt: inputs.issued_at,
      expiresAt: inputs.expires_at,
      dataCbor: hexToBytes(inputs.data_hex),
      evidence: inputs.evidence_hex ? hexToBytes(inputs.evidence_hex) : undefined,
      evidenceUri: inputs.evidence_uri ?? undefined,
      id: hexToBytes(inputs.id_hex),
      nonce: hexToBytes(inputs.nonce_hex),
      deterministic: true,
    });
    eqBytes(out, cbor, "attestation bytes");
    const r = verify(cbor, {}, { now: manifest.now });
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.equal(r.payload_hex, expected.payload_hex);
    assert.equal(r.signer, expected.issuer);
    assert.equal(bytesToHex(sha256(cbor)), expected.envelope_sha256);
    issuer.free();
  },
  srl({ cbor, inputs, expected }) {
    const got = verifySrl(cbor, {
      now: inputs.now,
      onStale: inputs.srl_policy.on_stale,
      cached: inputs.cached_srl_hex ? hexToBytes(inputs.cached_srl_hex) : undefined,
    });
    assert.deepEqual(got, expected);
  },
  // Draft 04: the cached list and the list are loaded in the verifier's context.
  "srl-context"({ cbor, inputs, expected }) {
    const got = verifySrl(cbor, {
      now: inputs.now,
      onStale: inputs.srl_policy.on_stale,
      cached: inputs.cached_srl_hex ? hexToBytes(inputs.cached_srl_hex) : undefined,
      context: {
        known_bundles: inputs.known_bundles ?? [],
        attestations: inputs.attestations ?? [],
        revocations: inputs.revocations ?? [],
      },
    });
    assert.deepEqual(got, expected);
  },
  log({ cbor, inputs, expected }) {
    const t = inputs.trusted_logs;
    let got;
    switch (inputs.check) {
      case "checkpoint": got = verifyCheckpoint(cbor, t, inputs.now); break;
      case "inclusion": got = verifyInclusion(cbor, t, inputs.now); break;
      case "consistency": got = checkConsistency(cbor, t, inputs.now); break;
      case "split-view": got = checkSplitView(cbor, t, inputs.now); break;
      default: throw new Error(`unknown log check ${inputs.check}`);
    }
    assert.deepEqual(got, expected);
  },
  // Draft 05 anchoring and discovery
  "chain-id"({ cbor, inputs, expected }) {
    assert.equal(view(cbor), inputs.id, "inputs.id is not the text in the CBOR file");
    assert.deepEqual(chainIdKind(inputs.id), expected);
  },
  "anchor-record"({ cbor, expected }) {
    const got = parseAnchorRecord(cbor);
    assert.deepEqual(got, expected);
    if (got.ok) eqBytes(encodeAnchorRecord(got.record), cbor, "re-encoded anchor record");
  },
  "checkpoint-hash"({ cbor, inputs, expected }) {
    const got = checkpointHash(cbor, inputs.trusted_logs, inputs.now);
    assert.deepEqual(got, expected);
    if (got.ok) {
      assert.equal(bytesToHex(sha256(hexToBytes(got.payload_hex))), got.checkpoint_hash);
    }
  },
  "anchor-envelope"({ cbor, inputs, expected }) {
    assert.deepEqual(checkPublishedAnchor(cbor, inputs.log, inputs.checkpoint_hash_hex, inputs.now), expected);
  },
  "require-anchor"({ cbor, inputs, expected }) {
    agrees(cbor, inputs.policy);
    assert.deepEqual(parseRequireAnchor(inputs.policy), expected);
  },
  "registry-endpoint"({ cbor, inputs, expected }) {
    const got = checkAdmission(cbor, {
      now: inputs.now, log: inputs.log, maxEnvelopeBytes: inputs.max_envelope_bytes, logged: inputs.logged,
    });
    assert.deepEqual(got, expected);
  },
  "domain-binding"({ cbor, inputs, expected }) {
    agrees(cbor, inputs.fixture);
    assert.deepEqual(checkDomainBinding(inputs.fixture), expected);
  },
};
for (const c of ["anchor-media-type", "anchor-not-supported", "verify-positive", "verify-negative", "chain-positive", "chain-negative", "atep-r-positive", "atep-r-negative",
  "retired-positive", "retired-negative", "successor-positive", "successor-negative"]) {
  checkers[c] = checkers.verifyLike;
}

for (const [cat, list] of Object.entries(byCat)) {
  describe(cat, () => {
    for (const v of list) {
      if (SKIPPED[cat]) {
        test(`${cat}/${v.name}`, { skip: SKIPPED[cat] }, () => {});
        (skipped[cat] ??= []).push(v.name);
        continue;
      }
      test(`${cat}/${v.name}`, () => {
        const d = load(cat, v.name);
        common(cat, v.name, d.meta, d.cbor, v);
        const fn = checkers[cat];
        assert.ok(fn, `no checker for category ${cat}`);
        fn(d);
        counts[cat] = (counts[cat] ?? 0) + 1;
      });
    }
  });
}
