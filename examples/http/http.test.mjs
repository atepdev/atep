import { test, before } from "node:test";
import assert from "node:assert/strict";
import { init, makeFixture, trustAnchor, Verifier, seal, sha256Hex } from "../common/atep.mjs";
import { serveEnvelope, fetchEnvelope, ENVELOPE_MIME } from "./http.mjs";

before(() => init());

test("an envelope served as application/atep+cbor verifies and is byte identical", async () => {
  const fx = makeFixture(["server", "client"]);
  const { bytes } = seal({
    sender: fx.agents.client.identity, attestation: fx.agents.client.attestation,
    payload: "http carried", recipientBundle: fx.agents.server.identity.publicBundle,
  });
  const web = await serveEnvelope(bytes);
  try {
    const res = await fetch(web.url);
    assert.equal(res.headers.get("content-type"), ENVELOPE_MIME);
    const back = await fetchEnvelope(web.url);
    assert.equal(sha256Hex(back), sha256Hex(bytes));
    const v = new Verifier({ identity: fx.agents.server.identity, ...trustAnchor(fx.root) }).check(back);
    assert.equal(v.ok, true);
    await assert.rejects(fetchEnvelope(web.url.replace("/envelope", "/nope")));
  } finally { await web.close(); }
});
