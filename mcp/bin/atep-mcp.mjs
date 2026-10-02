#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createAtepServer } from "../src/server.mjs";

try {
  const { server, client } = await createAtepServer();
  await server.connect(new StdioServerTransport());
  // stdout is the protocol channel; log to stderr only.
  console.error(`atep-mcp ready (read-only; log: ${client.configured ? client.base.href : "none, set ATEP_LOG_URL"})`);
} catch (e) {
  console.error(`atep-mcp failed to start: ${e?.message ?? e}`);
  process.exit(1);
}
