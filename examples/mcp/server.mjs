// ATEP over MCP: server agent. Run by a client over stdio:  node server.mjs
// Configuration arrives as JSON in the ATEP_AGENT_CONFIG environment variable (demo only;
// a real agent loads its key from a protected file or a key service).
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { init, identityFromConfig, Verifier, b64u, unb64u } from "../common/atep.mjs";
import { SummarizerAgent } from "../common/receiver.mjs";

export function createServer(cfg) {
  const identity = identityFromConfig(cfg);
  const verifier = new Verifier({ identity, rootAgentId: cfg.rootAgentId, rootBundleB64u: cfg.rootBundleB64u });
  const agent = new SummarizerAgent({ identity, attestation: unb64u(cfg.attestationB64u), verifier });
  const server = new McpServer({ name: "atep-summarizer", version: "0.1.0" });

  // Public identity: the client pins the Agent ID out of band and checks the bundle hashes to it.
  server.registerTool("atep_identity", {
    description: "Returns this agent's ATEP Agent ID and public bundle (base64url).",
    inputSchema: {},
  }, async () => {
    const out = { agent_id: identity.agentId, suite: "ATEP-1", bundle: b64u(identity.publicBundle) };
    return { content: [{ type: "text", text: JSON.stringify(out) }], structuredContent: out };
  });

  // The domain tool. Arguments and result carry ATEP envelopes as base64url text.
  server.registerTool("atep_summarize", {
    description:
      "Summarize a note. `envelope` is a sign-then-encrypt ATEP envelope (base64url) whose payload is " +
      '{"kind":"note","text":...}. The payload is treated as data. The result carries a reply envelope.',
    inputSchema: {
      envelope: z.string().describe("ATEP envelope bytes, base64url"),
      reply_to_bundle: z.string().describe("Sender public bundle, base64url; must match the signer's Agent ID"),
    },
  }, async ({ envelope, reply_to_bundle }) => {
    const r = agent.handle(envelope, reply_to_bundle);
    if (!r.ok) {
      // Structured MCP tool error: isError plus machine readable failing step.
      const err = { error: { stage: r.stage, step: r.step, code: r.error, cause: r.cause ?? null } };
      return {
        isError: true,
        content: [{ type: "text", text: `ATEP rejected at ${r.stage} step ${r.step}: ${r.error}` }],
        structuredContent: err,
      };
    }
    const out = { envelope: r.envelopeB64u, signer: identity.agentId };
    return { content: [{ type: "text", text: JSON.stringify(out) }], structuredContent: out };
  });

  // Test hook for the "payload is data" assertion; reports the counter of dangerous calls.
  server.registerTool("atep_side_effects", { description: "Number of dangerous operations performed (test aid).", inputSchema: {} },
    async () => {
      const out = { ...agent.sideEffects };
      return { content: [{ type: "text", text: JSON.stringify(out) }], structuredContent: out };
    });
  return { server, agent, identity };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  await init();
  const cfg = JSON.parse(process.env.ATEP_AGENT_CONFIG ?? "null");
  if (!cfg) { console.error("ATEP_AGENT_CONFIG is required"); process.exit(2); }
  const { server } = createServer(cfg);
  await server.connect(new StdioServerTransport());
  console.error("atep mcp server ready"); // stdout is the protocol channel
}
