// ATEP over A2A: server agent. Minimal A2A style JSON-RPC 2.0 over HTTP, following
// A2A protocol v0.3.0 (message/send, kind discriminated Message/Task/Part objects).
import http from "node:http";
import { b64u, unb64u, identityFromConfig, Verifier } from "../common/atep.mjs";
import { SummarizerAgent } from "../common/receiver.mjs";

export const ATEP_EXTENSION_URI = "https://atep.dev/extensions/a2a/envelope/v1"; // provisional
export const ENVELOPE_MIME = "application/atep+cbor";

export function buildAgentCard(identity, url) {
  return {
    protocolVersion: "0.3.0",
    name: "ATEP Summarizer",
    description: "Summarizes notes. Accepts only sign-then-encrypt ATEP envelopes from attested agents.",
    url,
    preferredTransport: "JSONRPC",
    version: "0.1.0",
    capabilities: {
      streaming: false,
      pushNotifications: false,
      extensions: [{
        uri: ATEP_EXTENSION_URI,
        description: "Messages carry ATEP envelopes (base64url) in a data part; the reply is an ATEP envelope too.",
        required: true,
        params: { agentId: identity.agentId, suite: "ATEP-1", contentType: ENVELOPE_MIME, bundle: b64u(identity.publicBundle) },
      }],
    },
    defaultInputModes: [ENVELOPE_MIME],
    defaultOutputModes: [ENVELOPE_MIME],
    skills: [{ id: "summarize-note", name: "Summarize note", description: "Word and character statistics for a note.", tags: ["atep", "summary"] }],
  };
}

const rpcError = (id, code, message, data) => ({ jsonrpc: "2.0", id: id ?? null, error: { code, message, ...(data ? { data } : {}) } });

/** Pull the envelope out of the first data (or file) part of a Message. */
export function extractEnvelope(message) {
  for (const part of message?.parts ?? []) {
    if (part.kind === "data" && typeof part.data?.atep_envelope === "string") {
      return { envelopeB64u: part.data.atep_envelope, replyToBundleB64u: part.data.atep_reply_to_bundle };
    }
    if (part.kind === "file" && part.file?.bytes && part.file.mimeType === ENVELOPE_MIME) {
      // A2A defines file.bytes as base64; base64url is accepted too (Buffer decodes both alphabets).
      return { envelopeB64u: Buffer.from(part.file.bytes, "base64").toString("base64url"), replyToBundleB64u: part.metadata?.atep_reply_to_bundle };
    }
  }
  return null;
}

export function createA2AServer(cfg) {
  const identity = identityFromConfig(cfg);
  const verifier = new Verifier({ identity, rootAgentId: cfg.rootAgentId, rootBundleB64u: cfg.rootBundleB64u });
  const agent = new SummarizerAgent({ identity, attestation: unb64u(cfg.attestationB64u), verifier });
  let taskCounter = 0;
  let url = "";

  const server = http.createServer(async (req, res) => {
    const send = (status, body) => { res.writeHead(status, { "content-type": "application/json" }); res.end(JSON.stringify(body)); };
    if (req.method === "GET" && (req.url === "/.well-known/agent-card.json" || req.url === "/.well-known/agent.json")) {
      // agent-card.json is the v0.3 path; agent.json is the earlier (0.2.x) path, served as an alias.
      return send(200, buildAgentCard(identity, url));
    }
    if (req.method !== "POST" || req.url !== "/") return send(404, { error: "not found" });
    const chunks = [];
    for await (const c of req) chunks.push(c);
    let rpc;
    try { rpc = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { return send(200, rpcError(null, -32700, "Parse error")); }
    if (rpc?.jsonrpc !== "2.0" || typeof rpc.method !== "string") return send(200, rpcError(rpc?.id, -32600, "Invalid Request"));
    if (rpc.method !== "message/send") return send(200, rpcError(rpc.id, -32601, "Method not found"));

    const message = rpc.params?.message;
    const found = message && extractEnvelope(message);
    if (!found) return send(200, rpcError(rpc.id, -32602, "Invalid params: message needs a data part with atep_envelope"));

    const r = agent.handle(found.envelopeB64u, found.replyToBundleB64u);
    const taskId = `task-${++taskCounter}`;
    const contextId = message.contextId ?? `ctx-${taskId}`;
    const base = { kind: "task", id: taskId, contextId };
    const now = new Date().toISOString();
    if (!r.ok) {
      // Rejection is task state "rejected" with a structured data part naming the failing ATEP step.
      return send(200, { jsonrpc: "2.0", id: rpc.id, result: {
        ...base,
        status: {
          state: "rejected", timestamp: now,
          message: {
            kind: "message", messageId: `m-${taskId}`, role: "agent", taskId, contextId,
            parts: [{ kind: "data", data: { atep_error: { stage: r.stage, step: r.step, code: r.error, cause: r.cause ?? null } } }],
          },
        },
      } });
    }
    return send(200, { jsonrpc: "2.0", id: rpc.id, result: {
      ...base,
      status: { state: "completed", timestamp: now },
      artifacts: [{
        artifactId: `a-${taskId}`, name: "summary",
        parts: [{ kind: "data", data: { atep_envelope: r.envelopeB64u }, metadata: { mimeType: ENVELOPE_MIME } }],
      }],
    } });
  });

  return {
    server, agent, identity,
    listen: () => new Promise((resolve) => server.listen(0, "127.0.0.1", () => {
      url = `http://127.0.0.1:${server.address().port}/`;
      resolve(url);
    })),
    close: () => new Promise((resolve) => { server.close(resolve); server.closeAllConnections?.(); }),
  };
}
