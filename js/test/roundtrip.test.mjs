import { test, before } from "node:test";
import assert from "node:assert/strict";
import {
  init, Identity, keygen, sign, encrypt, decrypt, verify, view, hexToBytes, bytesToHex,
  verifySrl, verifyCheckpoint, verifyInclusion, merkleRoot, auditPath, submittedFormOf,
  withInclusionProof, withAttestations,
} from "../dist/index.js";

const te = new TextEncoder();
const td = new TextDecoder();
const now = () => Math.floor(Date.now() / 1000);

before(async () => { await init(); });

test("two identities exchange an encrypted envelope", () => {
  const alice = keygen(false);
  const bob = keygen(true);
  const payload = te.encode("hello bob, this is alice");
  const t = now();
  const signed = sign(alice, payload, { issuedAt: t, expiresAt: t + 600 });
  const sealed = encrypt(signed, bob.publicBundle);

  // Verifier holding bob's identity: opens, verifies all steps.
  const r = verify(sealed, {}, { recipient: bob, now: t });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(r.signer, alice.agentId);
  assert.equal(r.encrypted, true);
  assert.equal(td.decode(hexToBytes(r.payload_hex)), "hello bob, this is alice");

  // Manual path: decrypt then verify the inner envelope.
  const inner = decrypt(bob, sealed);
  assert.deepEqual(inner, signed);
  // A data envelope must travel encrypted (spec section 5): bare is refused at step 1.
  const bare = verify(inner, {}, { now: t });
  assert.deepEqual([bare.ok, bare.step, bare.error], [false, 1, "unencrypted_non_trust_document"]);

  // Wrong recipient cannot open it; rejection is data, not an exception.
  const eve = keygen(true);
  const bad = verify(sealed, {}, { recipient: eve, now: t });
  assert.equal(bad.ok, false);
  assert.throws(() => decrypt(eve, sealed));

  // Replay protection (step 6) and tampering (step 7).
  const replay = verify(sealed, { seen_nonces: [r.nonce_hex] }, { recipient: bob, now: t });
  assert.equal(replay.ok, false);
  const tampered = sealed.slice();
  tampered[tampered.length - 1] ^= 1;
  assert.equal(verify(tampered, {}, { recipient: bob, now: t }).ok, false);

  // Reply in the other direction.
  const reply = sign(bob, te.encode("hi alice"), { issuedAt: t });
  const sealed2 = encrypt(reply, bob.publicBundle);
  assert.equal(verify(sealed2, {}, { recipient: bob, now: t }).ok, true);
  [alice, bob, eve].forEach((i) => i.free());
});

test("detached payload, expiry, view", () => {
  const a = keygen(false);
  const t = now();
  const rcpt = keygen(true);
  const inner = a.sign(te.encode("big payload"), { issuedAt: t, expiresAt: t + 60, detached: true });
  const env = encrypt(inner, rcpt.publicBundle);
  assert.equal(verify(env, {}, { recipient: rcpt, now: t }).ok, false); // payload missing
  const pol = { detached_payload_hex: te.encode("big payload") };
  const ok = verify(env, pol, { recipient: rcpt, now: t });
  assert.equal(ok.ok, true, JSON.stringify(ok));
  assert.equal(verify(env, pol, { recipient: rcpt, now: t + 61 }).ok, false);
  const v = view(env);
  assert.equal(typeof v, "object");
  a.free(); rcpt.free();
});

test("secret export and import keeps the identity", () => {
  const a = keygen(true);
  const secret = a.exportSecret();
  const b = Identity.fromSecret(secret);
  secret.fill(0);
  assert.equal(b.agentId, a.agentId);
  assert.deepEqual(b.publicBundle, a.publicBundle);
  a.free(); b.free();
});

test("attestation, chain trust policy, SRL revocation and log inclusion", () => {
  const t = now();
  const root = keygen(false), agent = keygen(false), logId = keygen(false);
  const att = root.issueAttestation({
    subject: agent.agentId, claim: "operator-of", issuedAt: t - 10, expiresAt: t + 3600,
    data: { operator: "Example Corp" },
  });
  const rcpt = keygen(true);
  const msg = encrypt(withAttestations(agent.sign(te.encode("act"), { issuedAt: t }), [att]), rcpt.publicBundle);
  const policy = { trust: { roots: [root.agentId], rules: [{ claim: "operator-of" }] }, known_bundles: [root.publicBundle] };
  const r = verify(msg, policy, { now: t, recipient: rcpt });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(r.claims.length, 1);
  assert.equal(r.claims[0].root, root.agentId);

  // Revoke the attestation with an SRL: verification now fails at step 9.
  const attId = hexToBytes(r.claims[0].chain[0].id);
  const srl = root.createSrl({ sequence: 1, issuedAt: t, nextUpdate: t + 3600,
    revoked: [{ attestationId: attId, reason: "withdrawn", revokedAt: t }] });
  const sr = verifySrl(srl, { now: t });
  assert.equal(sr.ok, true);
  assert.equal(sr.revoked[0].id_hex, bytesToHex(attId));
  const denied = verify(msg, { ...policy, srls: [srl] }, { now: t, recipient: rcpt });
  assert.equal(denied.ok, false);
  assert.equal(denied.step, 9);

  // Log: tree of 5 leaves, checkpoint, inclusion proof for the attestation.
  const leaves = [1, 2, 3, 4].map((i) => te.encode(`leaf${i}`));
  leaves.splice(2, 0, submittedFormOf(att));
  const cp = logId.createCheckpoint({ treeSize: 5, rootHash: merkleRoot(leaves), timestamp: t });
  assert.equal(verifyCheckpoint(cp, [logId.agentId], t).ok, true);
  assert.equal(verifyCheckpoint(cp, [root.agentId], t).ok, false);
  const withProof = withInclusionProof(att, { leafIndex: 2, auditPath: auditPath(2, leaves), checkpoint: cp });
  const inc = verifyInclusion(withProof, [logId.agentId], t);
  assert.equal(inc.ok, true, JSON.stringify(inc));
  assert.equal(inc.checkpoint.tree_size, 5);
  const wrong = withInclusionProof(att, { leafIndex: 1, auditPath: auditPath(1, leaves), checkpoint: cp });
  assert.equal(verifyInclusion(wrong, [logId.agentId], t).ok, false);
  [root, agent, logId, rcpt].forEach((i) => i.free());
});

test("init is idempotent", async () => {
  await init();
  assert.ok(keygen(false).agentId.startsWith("atep:"));
});
