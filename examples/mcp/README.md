# ATEP over MCP

Two agents, a summarizer MCP server and a client agent, exchange sign-then-encrypt ATEP envelopes using the official MCP TypeScript SDK (`@modelcontextprotocol/sdk` 1.31.0, high level `McpServer`, `StdioServerTransport`, `StdioClientTransport`).

## Shape

Carriage is in tool arguments and results as base64url text of the exact envelope bytes (the same bytes as in a file or an HTTP body).

| Tool | Arguments | Result |
| --- | --- | --- |
| `atep_identity` | none | `{agent_id, suite, bundle}` (public bundle, base64url) |
| `atep_summarize` | `envelope`, `reply_to_bundle` (base64url) | `structuredContent {envelope, signer}`: a reply envelope; or an error |
| `atep_side_effects` | none | counter of dangerous operations (test aid) |

Server flow (`common/receiver.mjs`): decode, `verify` with the trust policy and replay set (steps 1 to 10), check `reply_to_bundle` hashes to the verified signer, parse the payload as JSON data, build a summary, sign with its identity plus its attestation, encrypt to the sender. A rejection becomes an MCP tool error:

```
{ isError: true,
  content: [{type: "text", text: "ATEP rejected at verify step 6: nonce_replayed"}],
  structuredContent: {error: {stage: "verify", step: 6, code: "nonce_replayed", cause: null}} }
```

The client pins the server's Agent ID out of band, fetches the bundle with `atep_identity`, and refuses it unless it hashes to the pinned ID. It verifies the reply envelope with its own policy.

Payload is data (spec section 11): the agent never interprets note text as instructions; see `SummarizerAgent` in `../common/receiver.mjs` and the test "payload text is data".

## Notes on the SDK

* A plain tool, not a custom MCP method, so any MCP client can carry ATEP. Envelopes are about 6 KB to 12 KB once base64url encoded, which is fine for tool arguments but is wasteful for large payloads (use resources or detached payloads then).
* The SDK API needed no adaptation. Stdout is the protocol channel, so the server logs to stderr only.
* The server process gets its identity from the `ATEP_AGENT_CONFIG` environment variable (demo only).

## Run

```
npm test            (from examples/: runs everything)
node --test mcp/mcp.test.mjs
node mcp/demo.mjs
```
The test spawns `server.mjs` over stdio and runs the ten shared cases (`../common/cases.mjs`).
