import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { Aedes } from "aedes";
import { init, keygen } from "@atep/core";
import { connect, buildEnvelope, publishEnvelope, subscribeVerified } from "./atep-mqtt.mjs";

let broker, server, url, root, member, outsider, receiver, att, clients = [];

before(async () => {
  await init();
  broker = await Aedes.createBroker();
  server = net.createServer(broker.handle);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  url = `mqtt://127.0.0.1:${server.address().port}`;
  const t = Math.floor(Date.now() / 1000);
  root = keygen(false); member = keygen(true); outsider = keygen(true); receiver = keygen(true);
  att = root.issueAttestation({ subject: member.agentId, claim: "fleet-member", issuedAt: t - 10, expiresAt: t + 3600, data: { fleet: "f1" } });
});
after(async () => { await Promise.all(clients.map((c) => c.endAsync())); await broker.close(); server.close(); });

// One receiver per test with its own unit name, so tests do not see each other's traffic.
async function rig(unit) {
  const sub = await connect(url), pub = await connect(url);
  clients.push(sub, pub);
  const got = [];
  await subscribeVerified(sub, { fleet: "f1", unit, identity: receiver, rootId: root.agentId, rootBundle: root.publicBundle, onMessage: (m) => got.push(m) });
  const waitFor = async (n) => { for (let i = 0; i < 200 && got.length < n; i++) await new Promise((r) => setTimeout(r, 10)); return got; };
  return { pub, got, waitFor };
}
const mk = (over = {}) => buildEnvelope({ cls: "telemetry", sender: member, attestations: [att], payload: "hello", to: receiver.publicBundle, ...over });

test("attested, encrypted envelope on the right topic is accepted", async () => {
  const { pub, waitFor } = await rig("a1");
  await publishEnvelope(pub, { fleet: "f1", unit: "a1", cls: "telemetry", bytes: mk() });
  const [m] = await waitFor(1);
  assert.equal(m.ok, true);
  assert.equal(m.payload, "hello");
  assert.equal(m.signer, member.agentId);
  assert.equal(m.topic, "fleet/f1/a1/telemetry");
});

test("a tampered payload is rejected before any use", async () => {
  const { pub, waitFor } = await rig("a2");
  const bytes = mk(); bytes[bytes.length - 20] ^= 1;
  await publishEnvelope(pub, { fleet: "f1", unit: "a2", cls: "telemetry", bytes });
  const [m] = await waitFor(1);
  assert.equal(m.ok, false);
  assert.ok([1, 2].includes(m.step), `step ${m.step}`);
});

test("a sender with no attestation is rejected at step 9", async () => {
  const { pub, waitFor } = await rig("a3");
  await publishEnvelope(pub, { fleet: "f1", unit: "a3", cls: "telemetry", bytes: mk({ sender: outsider, attestations: [] }) });
  const [m] = await waitFor(1);
  assert.deepEqual([m.ok, m.step, m.error], [false, 9, "claim_missing"]);
});

test("a topic whose class differs from the signed class is refused", async () => {
  const { pub, waitFor } = await rig("a4");
  await publishEnvelope(pub, { fleet: "f1", unit: "a4", cls: "sensor", bytes: mk() });
  const [m] = await waitFor(1);
  assert.deepEqual([m.ok, m.error], [false, "topic_class_mismatch"]);
});

test("a replayed envelope is rejected at step 6", async () => {
  const { pub, waitFor } = await rig("a5");
  const bytes = mk();
  await publishEnvelope(pub, { fleet: "f1", unit: "a5", cls: "telemetry", bytes });
  await publishEnvelope(pub, { fleet: "f1", unit: "a5", cls: "telemetry", bytes });
  const got = await waitFor(2);
  assert.equal(got[0].ok, true);
  assert.deepEqual([got[1].ok, got[1].step, got[1].error], [false, 6, "nonce_replayed"]);
});
