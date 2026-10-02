import { test, before } from "node:test";
import assert from "node:assert/strict";
import { init, sha256Hex, te } from "../common/atep.mjs";
import { runSameBytes } from "./same-bytes.mjs";

before(() => init());

test("identical envelope bytes and identical verification over file, HTTP, MCP and A2A", async () => {
  const { hops, direct, dangerousCalls, hostileText } = await runSameBytes();
  const created = hops[0].sha256;
  assert.deepEqual(hops.map((h) => h.hop), ["created", "direct", "file", "http", "mcp", "a2a"]);
  for (const h of hops) assert.equal(h.sha256, created, `bytes changed at hop ${h.hop}`);

  assert.equal(direct.ok, true);
  assert.equal(direct.payloadSha256, sha256Hex(te.encode(JSON.stringify({ kind: "note", text: hostileText }))));
  for (const h of hops.slice(1)) {
    assert.equal(h.verification.ok, true, `${h.hop}: ${JSON.stringify(h.verification)}`);
    assert.equal(h.verification.signer, direct.signer, h.hop);
    assert.equal(h.verification.nonce, direct.nonce, h.hop);
    assert.deepEqual(h.verification.claims, direct.claims, h.hop);
  }
  // MCP and A2A receivers saw the same note text as the direct verifier.
  const textHash = sha256Hex(te.encode(hostileText));
  for (const h of hops.filter((x) => x.hop === "mcp" || x.hop === "a2a")) assert.equal(h.verification.payloadTextSha256, textHash);
  assert.equal(dangerousCalls, 0);
});
