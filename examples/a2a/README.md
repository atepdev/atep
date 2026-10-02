# ATEP over A2A

A minimal A2A style agent pair: JSON-RPC 2.0 over HTTP (`node:http` and `fetch`, no SDK, no framework). Each side runs the real ATEP verifier with a trust policy and a replay set.

## A2A version followed

A2A protocol **v0.3.0** (https://a2a-protocol.org/v0.3.0/specification/), checked against the published spec text on 2026-10-01:

* Agent Card at `/.well-known/agent-card.json` (the v0.3 path). The task asked for `/.well-known/agent.json`, the earlier 0.2.x path, so the server serves both with identical content.
* Card fields used: `protocolVersion`, `name`, `description`, `url`, `preferredTransport: "JSONRPC"`, `version`, `capabilities` (`streaming`, `pushNotifications`, `extensions`), `defaultInputModes`, `defaultOutputModes`, `skills`.
* Extension declaration `{uri, description, required, params}` with `uri = https://atep.dev/extensions/a2a/envelope/v1` (provisional, not registered). `params` holds `agentId`, `suite: "ATEP-1"`, `contentType`, and the public `bundle`.
* Method `message/send`; Message `{kind: "message", messageId, role: "user" | "agent", parts, extensions}`; parts discriminated by `kind` (`text`, `file`, `data`); results are a Task `{kind: "task", id, contextId, status{state, timestamp, message?}, artifacts[{artifactId, parts}]}`; JSON-RPC errors -32700, -32600, -32601, -32602 for protocol level faults.

Caveat: the A2A project has since published a 1.0 line that renames methods (`SendMessage`), drops the `kind` discriminator and changes enum spellings. This example does not follow it, and the web text was read through a summarizing fetcher, so field names beyond those above are not independently verified. The ATEP part (the envelope bytes inside one data part) does not depend on those details.

## Shape

* Request: `message/send` with one `data` part `{atep_envelope: <base64url>, atep_reply_to_bundle: <base64url>}`, part metadata `mimeType: application/atep+cbor`. The server also accepts a `file` part with `file.bytes` (A2A defines it as base64; base64url is tolerated) and the reply bundle in part metadata.
* Success: Task `completed`, one artifact whose data part carries the reply envelope (`atep_envelope`).
* ATEP rejection: Task `rejected`; `status.message` has a data part `{atep_error: {stage, step, code, cause}}`. This is a choice of this example (A2A does not define ATEP errors); a JSON-RPC error would also be valid.
* The client reads the Agent Card, finds the extension, and accepts the bundle only if it hashes to the pinned Agent ID.

Payload is data (spec section 11), the same receiver as the MCP example.

## Run

```
node --test a2a/a2a.test.mjs     (or npm test from examples/)
node a2a/demo.mjs
```
The test runs the ten shared cases (`../common/cases.mjs`) plus Agent Card, file part and JSON-RPC error tests.
