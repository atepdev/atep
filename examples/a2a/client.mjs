// ATEP over A2A: client agent (JSON-RPC over HTTP with fetch).
import { AtepClient } from "../common/client-core.mjs";
import { ATEP_EXTENSION_URI } from "./server.mjs";

/** Discover the agent: read the Agent Card, find the ATEP extension, build the pinned client. */
export async function discover(baseUrl, { identity, attestation, anchor, expectedServerId }) {
  const card = await (await fetch(new URL("/.well-known/agent-card.json", baseUrl))).json();
  const ext = card.capabilities?.extensions?.find((e) => e.uri === ATEP_EXTENSION_URI);
  if (!ext) throw new Error("agent card has no ATEP extension");
  const client = new AtepClient({
    identity, attestation, ...anchor, expectedServerId, serverBundleB64u: ext.params.bundle,
  });
  return { card, ext, client, rpcUrl: card.url };
}

let rpcId = 0;
export async function messageSend(rpcUrl, req) {
  const body = {
    jsonrpc: "2.0", id: ++rpcId, method: "message/send",
    params: {
      message: {
        kind: "message", messageId: crypto.randomUUID(), role: "user",
        extensions: [ATEP_EXTENSION_URI],
        parts: [{
          kind: "data",
          data: { atep_envelope: req.envelopeB64u, atep_reply_to_bundle: req.replyToBundleB64u },
          metadata: { mimeType: "application/atep+cbor" },
        }],
      },
    },
  };
  const res = await fetch(rpcUrl, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  return res.json();
}

/** One request/reply; resolves to {ok:true, ...reply} or {ok:false, error}. */
export async function summarize(rpcUrl, atep, req) {
  const rpc = await messageSend(rpcUrl, req);
  if (rpc.error) return { ok: false, error: { stage: "jsonrpc", step: 0, code: rpc.error.message, rpc: rpc.error } };
  const task = rpc.result;
  if (task.status.state === "rejected") return { ok: false, error: task.status.message.parts[0].data.atep_error };
  const part = task.artifacts[0].parts[0];
  return { ok: true, ...atep.openReply(part.data.atep_envelope, req.nonceHex) };
}
