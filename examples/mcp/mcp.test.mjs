import { defineAdapterCases } from "../common/cases.mjs";
import { makeFixture, agentConfig, trustAnchor } from "../common/atep.mjs";
import { connectMcp, makeAtepClient, summarize } from "./client.mjs";

defineAdapterCases("mcp/stdio", async () => {
  const fixture = makeFixture(["server", "client"]);
  const mcp = await connectMcp(agentConfig(fixture.root, fixture.agents.server)); // spawns server.mjs
  const client = await makeAtepClient(mcp, {
    identity: fixture.agents.client.identity, attestation: fixture.agents.client.attestation,
    anchor: trustAnchor(fixture.root), expectedServerId: fixture.agents.server.identity.agentId,
  });
  return {
    fixture, client,
    send: (req) => summarize(mcp, client, req),
    sideEffects: async () => (await mcp.callTool({ name: "atep_side_effects", arguments: {} })).structuredContent.dangerousCalls,
    close: () => mcp.close(),
  };
});
