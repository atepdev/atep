// Tests for server.mjs. Run: node --test server.test.mjs (from site/)
import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createServer } from "./server.mjs";

async function start(site, env = process.env) {
  const s = createServer(site, env);
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

// ---------------------------------------------------------------------------------------------
// Raw request, so tests can set Host (fetch cannot).
const raw = (base, p, headers = {}) =>
  new Promise((resolve, reject) => {
    const u = new URL(base);
    http.get({ host: u.hostname, port: u.port, path: p, headers }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") }));
    }).on("error", reject);
  });
const H = { "x-forwarded-proto": "https", "accept-encoding": "identity" };

for (const site of ["atep.dev", "airadlabs.com"]) {
  test(`${site}: 404 page has status 404 and the usual headers`, async () => {
    const { s, base } = await start(site);
    try {
      const r = await get(base, "/nope", plain);
      assert.equal(r.status, 404);
      assert.match(r.headers.get("content-type"), /^text\/html/);
      assert.match(r.headers.get("content-security-policy"), /default-src 'none'/);
      assert.equal(r.headers.get("cache-control"), "no-store");
      assert.equal(r.headers.get("x-content-type-options"), "nosniff");
      const body = await r.text();
      assert.match(body, /404|not found/i);
      if (site === "atep.dev") {
        assert.match(body, /Page not found/);
        assert.match(body, /href="\/claims\/"/);
        assert.match(body, /href="\/specification\.html"/);
      }
    } finally { s.close(); }
  });

  test(`${site}: CANONICAL_HOST redirects www only when set`, async () => {
    const off = await start(site, { ...process.env, CANONICAL_HOST: "" });
    const on = await start(site, { ...process.env, CANONICAL_HOST: "example.test" });
    try {
      const hdr = { ...H, host: "www.example.test" };
      // unset: no effect (www is served like any host)
      let r = await raw(off.base, "/index.html", hdr);
      assert.equal(r.status, 200);
      // set: www redirects, path and query kept, one hop to https
      r = await raw(on.base, "/index.html?a=1&b=%20x", hdr);
      assert.equal(r.status, 301);
      assert.equal(r.headers.location, "https://example.test/index.html?a=1&b=%20x");
      r = await raw(on.base, "/", { host: "www.example.test", "x-forwarded-proto": "http" });
      assert.equal(r.status, 301);
      assert.equal(r.headers.location, "https://example.test/");
      r = await raw(on.base, "/", { host: "WWW.Example.Test:443", ...H });
      assert.equal(r.status, 301);
      // path that starts with slashes cannot change the host
      r = await raw(on.base, "//evil.test/x", hdr);
      assert.equal(r.status, 301);
      assert.equal(r.headers.location, "https://example.test/evil.test/x");
      // the canonical host and unrelated hosts are served; plain http still goes to https
      for (const h of ["example.test", "other.herokuapp.com", "www.other.test", "wwwexample.test"]) {
        r = await raw(on.base, "/index.html", { ...H, host: h });
        assert.equal(r.status, 200, h);
      }
      r = await raw(on.base, "/index.html", { host: "example.test", "x-forwarded-proto": "http" });
      assert.equal(r.status, 301);
      assert.equal(r.headers.location, "https://example.test/index.html");
    } finally { off.s.close(); on.s.close(); }
  });

  test(`${site}: directories are not listed and traversal stays out of the new routes`, async () => {
    const { s, base } = await start(site);
    try {
      for (const p of [
        "/assets", "/assets/", "/.well-known/", "/.well-known", "/.git/config", "/.well-known/../static.json", "/.well-known/%2e%2e/static.json",
        "/claims/..%2fstatic.json", "/claims/%2e%2e/%2e%2e/server", "/claims/%2e%2e%2f%2e%2e%2fserver.mjs", "/claims/audited%00", "/claims/audited.html%00.json",
        "/claims/robotics/..%2f..%2f..%2fetc%2fpasswd", "/%2e%2e/server", "/..%2fserver", "/index%00", "/claims/%5c..%5cstatic.json", "/.well-known/%2e%2e%2fstatic.json",
      ]) {
        const r = await get(base, p, plain);
        assert.equal(r.status, 404, p);
        const t = await r.text();
        assert.ok(!/Index of|passwd|"https_only"/.test(t), p);
      }
    } finally { s.close(); }
  });
}

test("atep.dev: claim URIs resolve, with content negotiation", async () => {
  const { s, base } = await start("atep.dev");
  const html = { ...plain.headers, accept: "text/html,application/xhtml+xml,*/*;q=0.8" };
  const json = { ...plain.headers, accept: "application/json" };
  try {
    for (const name of ["audited", "registry-endpoint", "domain-control", "operator", "robotics/fleet-member", "robotics/peer-motion", "robotics/safety-certified"]) {
      let r = await get(base, `/claims/${name}`, { headers: html });
      assert.equal(r.status, 200, name);
      assert.match(r.headers.get("content-type"), /^text\/html/);
      assert.match(r.headers.get("vary"), /Accept/);
      const page = await r.text();
      assert.ok(page.includes(`<link rel="canonical" href="https://atep.dev/claims/${name}">`), name);

      r = await get(base, `/claims/${name}`, { headers: json });
      assert.equal(r.status, 200, name);
      assert.match(r.headers.get("content-type"), /^application\/json/);
      assert.match(r.headers.get("vary"), /Accept/);
      assert.equal(r.headers.get("access-control-allow-origin"), "*");
      const doc = await r.json();
      assert.equal(doc.claim, `https://atep.dev/claims/${name}`);
      assert.equal(doc.name, name);
      assert.ok(doc["data-schema"].includes("-data ="));

      r = await get(base, `/claims/${name}.html`, plain);
      assert.match(r.headers.get("content-type"), /^text\/html/);
      assert.ok(!r.headers.get("vary").includes("Accept,"), "explicit suffix is not negotiated");
      r = await get(base, `/claims/${name}.json`, { headers: html });
      assert.match(r.headers.get("content-type"), /^application\/json/);
    }
    // Preference by quality value: JSON listed higher, or HTML lower.
    for (const [accept, expect] of [
      ["application/json, text/plain, */*", "json"], ["text/html;q=0.5, application/json", "json"], ["application/json;q=0.9, text/html;q=0.8", "json"],
      ["text/html", "html"], ["text/html, application/json;q=0.5", "html"], ["*/*", "json"], ["", "json"], ["application/json;q=0, */*", "html"],
    ]) {
      const r = await get(base, "/claims/audited", { headers: { ...plain.headers, accept } });
      assert.match(r.headers.get("content-type"), expect === "json" ? /^application\/json/ : /^text\/html/, `Accept: ${accept}`);
    }
    // The directory, with and without the slash.
    let r = await get(base, "/claims/", { headers: html });
    assert.equal(r.status, 200);
    assert.match(await r.text(), /Claim types/);
    r = await get(base, "/claims/", { headers: json });
    assert.match(r.headers.get("content-type"), /^application\/json/);
    assert.equal((await r.json()).claims.length, 14);
    r = await get(base, "/claims/index.html", plain);
    assert.equal(r.status, 200);
    r = await get(base, "/claims?x=1", plain);
    assert.equal(r.status, 301);
    assert.equal(r.headers.get("location"), "/claims/?x=1");
    // Unknown names, the robotics name without its prefix, a trailing slash on a claim, no listing.
    for (const p of ["/claims/unknown", "/claims/fleet-member", "/claims/robotics/audited", "/claims/audited/", "/claims/robotics", "/claims/robotics/", "/claims/unknown.json", "/claims/unknown.html", "/claims/audited.json.html", "/claims/index.js"]) {
      r = await get(base, p, { headers: json });
      assert.equal(r.status, 404, p);
      assert.match(r.headers.get("content-type"), /^text\/html/, p);
    }
    // Generic: an extensionless path serves <path>.html, and JSON is negotiated only under /claims/.
    r = await get(base, "/quickstart", { headers: json });
    assert.equal(r.status, 200);
    assert.match(r.headers.get("content-type"), /^text\/html/);
    r = await get(base, "/quickstart.json", plain);
    assert.equal(r.status, 404);
    // HEAD and conditional requests work on the negotiated routes.
    r = await fetch(`${base}/claims/audited`, { method: "HEAD", headers: json });
    assert.equal(r.status, 200);
    assert.equal(await r.text(), "");
    const etag = (await get(base, "/claims/audited", { headers: json })).headers.get("etag");
    r = await get(base, "/claims/audited", { headers: { ...json, "if-none-match": etag } });
    assert.equal(r.status, 304);
  } finally { s.close(); }
});

test("atep.dev: a tie (no Accept, */*) answers JSON by default, as the reference log does; CLAIMS_DEFAULT=html flips it", async () => {
  const hdr = (accept) => ({ "x-forwarded-proto": "https", "accept-encoding": "identity", ...(accept ? { accept } : {}) });
  let { s, base } = await start("atep.dev");
  try {
    for (const accept of [undefined, "*/*"]) {
      const r = await get(base, "/claims/audited", { headers: hdr(accept) });
      assert.match(r.headers.get("content-type"), /^application\/json/, String(accept));
    }
    const r = await get(base, "/claims/audited", { headers: hdr("text/html,application/xhtml+xml,*/*;q=0.8") });
    assert.match(r.headers.get("content-type"), /^text\/html/);
  } finally { s.close(); }
  ({ s, base } = await start("atep.dev", { ...process.env, CLAIMS_DEFAULT: "html" }));
  try {
    for (const accept of [undefined, "*/*"]) {
      const r = await get(base, "/claims/audited", { headers: hdr(accept) });
      assert.match(r.headers.get("content-type"), /^text\/html/, String(accept));
    }
  } finally { s.close(); }
});

test("atep.dev: well-known, robots, sitemap, other dotfiles stay hidden", async () => {
  const { s, base } = await start("atep.dev");
  try {
    let r = await get(base, "/.well-known/security.txt", plain);
    assert.equal(r.status, 200);
    assert.match(r.headers.get("content-type"), /^text\/plain; charset=utf-8/);
    assert.match(await r.text(), /^Contact: mailto:/m);
    r = await get(base, "/robots.txt", plain);
    assert.equal(r.status, 200);
    assert.match(await r.text(), /^Sitemap: https:\/\/atep\.dev\/sitemap\.xml$/m);
    r = await get(base, "/sitemap.xml", plain);
    assert.equal(r.status, 200);
    assert.match(r.headers.get("content-type"), /^application\/xml/);
    for (const p of ["/.well-known/nothing", "/.gitignore", "/.env"]) assert.equal((await get(base, p, plain)).status, 404, p);
  } finally { s.close(); }
});

test("generic mechanism on a scratch site: .well-known served, dot directories hidden, custom 404 optional", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "atep-site-test-"));
  try {
    const w = (f, t) => { fs.mkdirSync(path.dirname(path.join(dir, f)), { recursive: true }); fs.writeFileSync(path.join(dir, f), t); };
    w("static.json", JSON.stringify({ https_only: true, headers: { "/**": { "X-Test": "1" } } }));
    w("index.html", "<title>home</title>");
    w("page.html", "<title>page</title>");
    w(".well-known/thing.txt", "wk");
    w(".well-known/.secret", "no");
    w(".hidden/x.txt", "no");
    w("claims/a.html", "A html");
    w("claims/a.json", "{\"a\":1}");
    w("claims/only.html", "only html");
    w("sub/index.html", "sub");
    w("empty/readme.txt", "no index here");
    let { s, base } = await start(dir);
    try {
      assert.equal((await get(base, "/.well-known/thing.txt", plain)).status, 200);
      for (const p of ["/.well-known/.secret", "/.hidden/x.txt", "/.hidden/", "/empty/", "/empty"]) assert.equal((await get(base, p, plain)).status, 404, p);
      let r = await get(base, "/page", plain);
      assert.equal(await r.text(), "<title>page</title>");
      r = await get(base, "/claims/a", { headers: { ...plain.headers, accept: "application/json" } });
      assert.equal(await r.text(), "{\"a\":1}");
      r = await get(base, "/claims/only", { headers: { ...plain.headers, accept: "application/json" } });
      assert.equal(await r.text(), "only html", "no json variant: the html is served");
      r = await get(base, "/sub", plain);
      assert.equal(r.status, 301);
      assert.equal(r.headers.get("location"), "/sub/");
      // No 404.html: the minimal fallback, still 404 with the site headers.
      r = await get(base, "/missing", plain);
      assert.equal(r.status, 404);
      assert.equal(r.headers.get("x-test"), "1");
      assert.match(await r.text(), /404 Not found/);
    } finally { s.close(); }
    w("404.html", "<title>custom</title><h1>Custom missing</h1>");
    ({ s, base } = await start(dir));
    try {
      const r = await get(base, "/missing", plain);
      assert.equal(r.status, 404);
      assert.equal(r.headers.get("x-test"), "1");
      assert.match(await r.text(), /Custom missing/);
      // A direct request for the 404 page is an ordinary page (200); hidden things still use it with 404.
      assert.equal((await get(base, "/.hidden/x.txt", plain)).status, 404);
    } finally { s.close(); }
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
