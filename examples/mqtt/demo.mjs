// Runs an in-process aedes broker, one unit that subscribes, one that publishes.
import net from "node:net";
import { Aedes } from "aedes";
import { init, keygen } from "@atep/core";
import { connect, buildEnvelope, publishEnvelope, subscribeVerified } from "./atep-mqtt.mjs";

await init();
const broker = await Aedes.createBroker();
const server = net.createServer(broker.handle);
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const url = `mqtt://127.0.0.1:${server.address().port}`;

const t = Math.floor(Date.now() / 1000);
const root = keygen(false), u1 = keygen(true), u2 = keygen(true);
const att = root.issueAttestation({
  subject: u1.agentId, claim: "fleet-member", issuedAt: t - 10, expiresAt: t + 3600, data: { fleet: "f1" },
});
const sub = await connect(url), pub = await connect(url);
await subscribeVerified(sub, {
  fleet: "f1", unit: "u2", identity: u2, rootId: root.agentId, rootBundle: root.publicBundle,
  onMessage: (m) => { console.log(m); if (m.ok || m.error) done(); },
});
let done; const finished = new Promise((r) => (done = r));
const bytes = buildEnvelope({ cls: "telemetry", sender: u1, attestations: [att], payload: '{"battery":0.82}', to: u2.publicBundle });
await publishEnvelope(pub, { fleet: "f1", unit: "u2", cls: "telemetry", bytes });
await finished;
await Promise.all([sub.endAsync(), pub.endAsync()]);
await broker.close(); server.close();
