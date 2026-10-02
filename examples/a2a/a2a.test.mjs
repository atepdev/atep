import { test } from "node:test";
import assert from "node:assert/strict";
import { defineAdapterCases } from "../common/cases.mjs";
import { makeFixture, agentConfig, trustAnchor } from "../common/atep.mjs";
import { createA2AServer, ATEP_EXTENSION_URI } from "./server.mjs";
import { discover, summarize, messageSend } from "./client.mjs";

let svc, d, fx;
defineAdapterCases("a2a/http", async () => {
  fx = makeFixture(["server", "client"]);
  svc = createA2AServer(agentConfig(fx.root, fx.agents.server));
  const url = await svc.listen();
  d = await discover(url, {
    identity: fx.agents.client.identity, attestation: fx.agents.client.attestation,
    anchor: trustAnchor(fx.root), expectedServerId: fx.agents.server.identity.agentId,
  });
  return {
    fixture: fx, client: d.client,
    send: (req) => summarize(d.rpcUrl, d.client, req),
    sideEffects: async () => svc.agent.sideEffects.dangerousCalls,
    close: () => svc.close(),
  };
});

test("a2a: agent card declares the ATEP extension with Agent ID and suite", async () => {
  assert.equal(d.card.protocolVersion, "0.3.0");
  assert.equal(d.ext.uri, ATEP_EXTENSION_URI);
  assert.equal(d.ext.params.agentId, fx.agents.server.identity.agentId);
  assert.equal(d.ext.params.suite, "ATEP-1");
  const legacy = await (await fetch(new URL("/.well-known/agent.json", d.rpcUrl))).json();
  assert.deepEqual(legacy, d.card);
});

test("a2a: file part carriage and JSON-RPC level errors", async () => {
  const req = d.client.request("via file part");
  const bytes = Buffer.from(req.envelopeB64u, "base64url");
  const body = (message, method = "message/send") => JSON.stringify({ jsonrpc: "2.0", id: 1, method, params: { message } });
  const post = async (b) => (await fetch(d.rpcUrl, { method: "POST", body: b })).json();
  const ok = await post(body({
    kind: "message", messageId: "x", role: "user",
    parts: [{ kind: "file", file: { bytes: bytes.toString("base64"), mimeType: "application/atep+cbor", name: "req.atep" }, metadata: { atep_reply_to_bundle: req.replyToBundleB64u } }],
  }));
  assert.equal(ok.result.status.state, "completed", JSON.stringify(ok));
  assert.equal((await post("{")).error.code, -32700);
  assert.equal((await post(body({ kind: "message", messageId: "y", role: "user", parts: [{ kind: "text", text: "hi" }] }))).error.code, -32602);
  assert.equal((await post(body({}, "tasks/get"))).error.code, -32601);
  assert.equal((await messageSend(d.rpcUrl, { envelopeB64u: "", replyToBundleB64u: "" })).result.status.state, "rejected");
});
