import { test, before } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { init, makeFixture, trustAnchor, Verifier, seal, sha256Hex } from "../common/atep.mjs";
import { writeEnvelopeFile, readEnvelopeFile } from "./files.mjs";

before(() => init());

test("an envelope written to disk and read back verifies and is byte identical", async () => {
  const fx = makeFixture(["server", "client"]);
  const { bytes } = seal({
    sender: fx.agents.client.identity, attestation: fx.agents.client.attestation,
    payload: "file carried", recipientBundle: fx.agents.server.identity.publicBundle,
  });
  const dir = await mkdtemp(join(tmpdir(), "atep-file-"));
  try {
    const p = join(dir, "msg.atep");
    await writeEnvelopeFile(p, bytes);
    const back = await readEnvelopeFile(p);
    assert.equal(sha256Hex(back), sha256Hex(bytes));
    const v = new Verifier({ identity: fx.agents.server.identity, ...trustAnchor(fx.root) }).check(back);
    assert.equal(v.ok, true);
    assert.equal(v.signer, fx.agents.client.identity.agentId);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
