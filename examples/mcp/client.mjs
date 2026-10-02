// ATEP over MCP: client agent. Spawns the server over stdio and talks to it.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { fileURLToPath } from "node:url";
import { AtepClient } from "../common/client-core.mjs";

const serverPath = fileURLToPath(new URL("./server.mjs", import.meta.url));

export async function connectMcp(serverConfig) {
  const transport = new StdioClientTransport({
    command: process.execPath, args: [serverPath],
    env: { ...process.env, ATEP_AGENT_CONFIG: JSON.stringify(serverConfig) },
    stderr: "pipe",
  });
  const mcp = new Client({ name: "atep-client", version: "0.1.0" });
  await mcp.connect(transport);
  return mcp;
}

/** Fetch the pinned server's identity and build the transport independent AtepClient. */
export async function makeAtepClient(mcp, { identity, attestation, anchor, expectedServerId }) {
  const res = await mcp.callTool({ name: "atep_identity", arguments: {} });
  return new AtepClient({
    identity, attestation, ...anchor, expectedServerId, serverBundleB64u: res.structuredContent.bundle,
  });
}

/** Send one request envelope; resolves to {ok:true, ...reply} or {ok:false, error}. */
export async function summarize(mcp, atep, req) {
  const res = await mcp.callTool({
    name: "atep_summarize", arguments: { envelope: req.envelopeB64u, reply_to_bundle: req.replyToBundleB64u },
  });
  if (res.isError) return { ok: false, error: res.structuredContent?.error, text: res.content?.[0]?.text };
  return { ok: true, ...atep.openReply(res.structuredContent.envelope, req.nonceHex) };
}
