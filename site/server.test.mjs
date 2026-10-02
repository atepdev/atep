// Tests for server.mjs. Run: node --test server.test.mjs (from site/)
import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { createServer } from "./server.mjs";

async function start(site) {
  const s = createServer(site);
  await new Promise((r) => s.listen(0, "127.0.0.1", r));
  return { s, base: `http://127.0.0.1:${s.address().port}` };
}
const get = (base, p, opts = {}) => fetch(base + p, { redirect: "manual", ...opts });
// fetch() would otherwise add its own accept-encoding and decompress; ask for identity unless testing gzip.
const plain = { headers: { "accept-encoding": "identity", "x-forwarded-proto": "https" } };

for (const site of ["atep.dev", "airadlabs.com"]) {
  test(`${site}: pages, headers and files`, async () => {
    const { s, base } = await start(site);
    try {
      let r = await get(base, "/", plain);
      assert.equal(r.status, 200);
      assert.match(r.headers.get("content-type"), /^text\/html/);
      assert.match(r.headers.get("content-security-policy"), /default-src 'none'/);
      assert.equal(r.headers.get("x-content-type-options"), "nosniff");
      assert.ok(r.headers.get("strict-transport-security"));
      assert.equal(r.headers.get("x-frame-options"), "DENY");
      assert.match(await r.text(), /<title>/);

      r = await get(base, "/llms.txt", plain);
      assert.equal(r.status, 200);
      assert.match(r.headers.get("content-type"), /^text\/plain; charset=utf-8/);

      r = await get(base, "/style.css", plain);
      assert.match(r.headers.get("content-type"), /^text\/css/);
      r = await get(base, "/site.js", plain);
      assert.match(r.headers.get("content-type"), /^text\/javascript/);
    } finally { s.close(); }
  });

  test(`${site}: hidden files, traversal, methods, 404`, async () => {
    const { s, base } = await start(site);
    try {
      for (const p of ["/static.json", "/../server.mjs", "/..%2fserver.mjs", "/%2e%2e/%2e%2e/etc/passwd", "/assets/build-assets.mjs", "/assets/README.md", "/nope.html", "/%00"]) {
        const r = await get(base, p, plain);
        assert.equal(r.status, 404, p);
      }
      let r = await get(base, "/%zz", plain);
      assert.equal(r.status, 400);
      r = await fetch(base + "/", { method: "POST", headers: plain.headers });
      assert.equal(r.status, 405);
      r = await fetch(base + "/", { method: "HEAD", headers: plain.headers });
      assert.equal(r.status, 200);
      assert.equal(await r.text(), "");
    } finally { s.close(); }
  });

  test(`${site}: etag, gzip and https redirect`, async () => {
    const { s, base } = await start(site);
    try {
      let r = await get(base, "/index.html", plain);
      const etag = r.headers.get("etag");
      assert.ok(etag);
      r = await get(base, "/index.html", { headers: { ...plain.headers, "if-none-match": etag } });
      assert.equal(r.status, 304);

      r = await get(base, "/index.html", { headers: { "x-forwarded-proto": "https", "accept-encoding": "gzip" } });
      assert.equal(r.status, 200);
      assert.match(await r.text(), /<title>/);

      // fetch() cannot override Host, so use a raw request for the redirect target.
      const res = await new Promise((resolve, reject) => {
        const u = new URL(base);
        http.get({ host: u.hostname, port: u.port, path: "/quickstart.html?x=1", headers: { host: "example.test", "x-forwarded-proto": "http" } }, resolve).on("error", reject);
      });
      assert.equal(res.statusCode, 301);
      assert.equal(res.headers.location, "https://example.test/quickstart.html?x=1");
      res.resume();
    } finally { s.close(); }
  });
}

test("unknown site folder is an error", () => {
  assert.throws(() => createServer("does-not-exist"), /no such site folder/);
});
