// Runs the vector checks of js/test/vectors.test.mjs inside a real browser (Chromium through
// Playwright), against the built package in js/dist. Not part of `npm test` or of CI, and not
// shipped in the package: the repository has no dependency on Playwright.
//
//   npm install --no-save playwright-core            (once, from the repository root)
//   npm run build -w js
//   CHROMIUM=/path/to/chromium-or-headless-shell node js/scripts/browser-vectors.mjs
//
// Without CHROMIUM, Playwright's own browser is used (`npx playwright-core install chromium`).
// The test file is read, its Node imports are replaced by small shims (fetch instead of
// node:fs, a minimal assert, a sequential runner) and the result is served to the browser from
// a throwaway local server; every check body is the one in vectors.test.mjs. Exit code 1 if any
// check fails.
import { createServer } from "node:http";
import { readFileSync, existsSync, statSync } from "node:fs";
import { dirname, join, resolve, extname } from "node:path";
import { fileURLToPath } from "node:url";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
if (!existsSync(join(repo, "js/dist/index.js"))) {
  console.error("js/dist is missing: run `npm run build -w js` first");
  process.exit(2);
}
let chromium;
try {
  ({ chromium } = await import("playwright-core"));
} catch {
  console.error("playwright-core is not installed: run `npm install --no-save playwright-core`");
  process.exit(2);
}

const src = readFileSync(join(repo, "js/test/vectors.test.mjs"), "utf8");
const marker = '} from "../dist/index.js";';
const importsEnd = src.indexOf(marker) + marker.length;
const distImport = src.slice(src.indexOf("import {\n  init"), importsEnd).replace("../dist/index.js", "/js/dist/index.js");
const body = src.slice(importsEnd).replace(/const vecDir = [^\n]*\nconst manifest = [^\n]*\nconst rd = [^\n]*\n/, "");
if (!distImport.includes("init") || body.length === src.length - importsEnd) {
  console.error("vectors.test.mjs has changed shape: update the transform in this script");
  process.exit(2);
}

const shim = `
${distImport}
class Buf extends Uint8Array { toString() { return new TextDecoder().decode(this); } }
const files = new Map();
const manifestText = await (await fetch("/vectors/manifest.json")).text();
const manifest = JSON.parse(manifestText);
await Promise.all(manifest.vectors.flatMap((v) => [".cbor", ".json", ".expected.json"].map(async (ext) => {
  const p = v.category + "/" + v.name + ext;
  files.set(p, new Buf(new Uint8Array(await (await fetch("/vectors/" + p)).arrayBuffer())));
})));
const rd = (p) => { const f = files.get(p); if (!f) throw new Error("missing " + p); return f; };
const queue = [];
let beforeFn = async () => {};
const describe = (n, f) => f();
const test = (name, a, b) => queue.push({ name, opts: typeof a === "function" ? {} : a, fn: typeof a === "function" ? a : b });
const before = (f) => { beforeFn = f; };
const after = () => {};
const same = (a, b) => {
  if (a === b) return true;
  if (typeof a !== "object" || typeof b !== "object" || !a || !b) return false;
  const ka = Object.keys(a), kb = Object.keys(b);
  return ka.length === kb.length && ka.every((k) => same(a[k], b[k]));
};
const fail = (m, a, b) => { throw new Error(m + ": " + JSON.stringify(a)?.slice(0, 300) + " vs " + JSON.stringify(b)?.slice(0, 300)); };
const assert = {
  equal: (a, b, m = "equal") => { if (a !== b) fail(m, a, b); },
  deepEqual: (a, b, m = "deepEqual") => { if (!same(a, b)) fail(m, a, b); },
  ok: (v, m = "not ok") => { if (!v) throw new Error(m); },
};
`;
const tail = `
await beforeFn();
const results = { passed: 0, skipped: 0, failed: [] };
for (const t of queue) {
  if (t.opts && t.opts.skip) { results.skipped++; continue; }
  try { await t.fn(); results.passed++; } catch (e) { results.failed.push(t.name + ": " + e.message); }
}
window.__results = results;
`;
const mod = shim + body + tail;

const types = { ".html": "text/html", ".js": "text/javascript", ".mjs": "text/javascript", ".wasm": "application/wasm", ".json": "application/json" };
const server = createServer((req, res) => {
  const u = new URL(req.url, "http://localhost").pathname;
  if (u === "/__run.html") { res.setHeader("content-type", "text/html"); return res.end('<!doctype html><script type="module" src="/__run.mjs"></script>'); }
  if (u === "/__run.mjs") { res.setHeader("content-type", "text/javascript"); return res.end(mod); }
  const f = join(repo, u);
  if (!f.startsWith(repo) || !existsSync(f) || !statSync(f).isFile()) { res.statusCode = 404; return res.end("not found"); }
  res.setHeader("content-type", types[extname(f)] || "application/octet-stream");
  res.end(readFileSync(f));
});
await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
const port = server.address().port;

const browser = await chromium.launch(process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {});
let code = 0;
try {
  const page = await browser.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  const crashed = new Promise((_, reject) => page.on("pageerror", (e) => reject(new Error("page error: " + e.message))));
  await page.goto(`http://127.0.0.1:${port}/__run.html`);
  await Promise.race([page.waitForFunction(() => window.__results, null, { timeout: 240000 }), crashed]);
  const r = await page.evaluate(() => window.__results);
  console.log(await page.evaluate(() => navigator.userAgent));
  console.log(`vectors in the browser: ${r.passed} passed, ${r.skipped} skipped by name, ${r.failed.length} failed`);
  for (const f of r.failed.slice(0, 10)) console.log("FAIL " + f);
  if (errors.length) { console.log("page errors: " + errors.slice(0, 3).join(" | ")); code = 1; }
  if (r.failed.length) code = 1;
} finally {
  await browser.close();
  server.close();
}
process.exit(code);
