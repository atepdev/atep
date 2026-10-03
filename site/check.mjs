// Static checks for site/: JSON-LD parses, internal links and fragments resolve, basic accessibility
// hygiene, no em or en dashes, llms.txt size, llms-full.txt, claim pages and sitemap.xml up to date, canonical URLs,
// claim page and JSON counts, robots.txt and security.txt (expired fails, under 60 days warns).
// Usage: node site/check.mjs     (SITE_CHECK_NOW=<ISO date> overrides the clock for the security.txt expiry check)
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const sites = { "atep.dev": path.join(here, "atep.dev") };
const errors = [];
const err = (m) => errors.push(m);
const read = (p) => fs.readFileSync(p, "utf8");
const exists = (p) => fs.existsSync(p) && fs.statSync(p).isFile();
const EM = String.fromCharCode(0x2014);
const EN = String.fromCharCode(0x2013);
const warnings = [];
const warn = (m) => warnings.push(m);
const ATEP = "https://atep.dev";
let nLinks = 0, nLd = 0, nPages = 0;

function resolveTarget(fromFile, siteRoot, href) {
  let u = href;
  const m = /^https?:\/\/([^/]+)(\/.*)?$/.exec(u);
  if (m) {
    const host = m[1].replace(/^www\./, "");
    if (!sites[host]) return { external: true };
    return { file: path.join(sites[host], (m[2] || "/").split(/[?#]/)[0]), hash: (u.split("#")[1] || ""), isDirUrl: (m[2] || "/").endsWith("/") };
  }
  if (/^(mailto:|tel:|data:|javascript:)/.test(u)) return { external: true };
  const pathPart = u.split(/[?#]/)[0];
  const hash = u.includes("#") ? u.split("#")[1] : "";
  const file = pathPart === "" ? fromFile : pathPart.startsWith("/") ? path.join(siteRoot, pathPart) : path.resolve(path.dirname(fromFile), pathPart);
  return { file, hash, isDirUrl: pathPart.endsWith("/") };
}

// Canonical URL of a page by its path inside the site folder.
function canonicalOf(rel) {
  if (rel === "index.html") return `${ATEP}/`;
  if (rel === "claims/index.html") return `${ATEP}/claims/`;
  if (rel === "demo/index.html") return `${ATEP}/demo/`;
  if (rel.startsWith("claims/")) return `${ATEP}/${rel.slice(0, -5)}`;
  return `${ATEP}/${rel}`;
}

function finalFile(t) {
  if (fs.existsSync(t.file) && fs.statSync(t.file).isDirectory()) return path.join(t.file, "index.html");
  // The server maps an extensionless URL to <path>.html.
  if (!fs.existsSync(t.file) && path.extname(t.file) === "" && exists(t.file + ".html")) return t.file + ".html";
  return t.file;
}

const idsOf = (html) => new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((x) => x[1]));


// The plain-language page: nav order, wording rules, the illustration disclaimer, diagram accessibility, no inline style or script.
function checkInPractice(html, rel) {
  const nav = [...(/<nav aria-label="Main">([\s\S]*?)<\/nav>/.exec(html)?.[1] || "").matchAll(/<a [^>]*>([\s\S]*?)<\/a>/g)].map((m) => m[1].replace(/<span class="sr-only">[^<]*<\/span>/g, "").replace(/<[^>]+>/g, "").trim()).join("|");
  const want = "Overview|In practice|Specification|Claims|Live simulator|Quick start|Test vectors|Governance|Security|About";
  if (nav !== want) err(`${rel}: nav order is ${nav}, expected ${want}`);
  if (!/<a [^>]*href="in-practice\.html" aria-current="page"/.test(html)) err(`${rel}: nav lacks aria-current on In practice`);
  const main = (/<main[\s\S]*<\/main>/.exec(html) || [""])[0];
  const text = main.replace(/<svg[\s\S]*?<\/svg>/g, " ").replace(/<[^>]+>/g, " ");
  if (/<script(?![^>]*\b(src=|type="application\/ld\+json"))/.test(html) || /\son[a-z]+=/.test(html)) err(`${rel}: inline script or event handler (CSP)`);
  if (/\b(first|only)\b/i.test(text)) err(`${rel}: uses "first" or "only" (needs the related-work hedge; reword)`);
  if (/quantum-proof|unbreakable|revolutionary/i.test(text)) err(`${rel}: overclaiming wording`);
  if (!/quantum-safe/i.test(text)) err(`${rel}: should say quantum-safe`);
  if (!/Illustrations of how the protocol behaves, not case studies: no deployment is described\./.test(text)) err(`${rel}: missing the scenarios disclaimer`);
  if (!/To our knowledge, no open, vendor-neutral standard combines these today/.test(text)) err(`${rel}: missing the hedged positioning sentence`);
  if (!/#18-related-work-and-positioning/.test(html)) err(`${rel}: no link to the related-work section`);
  for (const w of ["Envelope", "Attestation", "Certifier", "Revocation list", "Offline verification"]) if (!new RegExp(`<dt>${w}</dt>`).test(html)) err(`${rel}: Words box lacks ${w}`);
  if ((html.match(/<section class="card"><h3>/g) || []).length < 11) err(`${rel}: expected 6 point cards and 5 scenario cards`);
  if ((html.match(/class="spec"/g) || []).length !== 5) err(`${rel}: each of the five scenarios needs a Spec link`);
  const svgs = [...html.matchAll(/<svg\b[\s\S]*?<\/svg>/g)].map((m) => m[0]);
  if (svgs.length < 1) err(`${rel}: no diagram`);
  for (const v of svgs) if (!/role="img"/.test(v) || !/<title\b/.test(v) || !/<desc\b/.test(v)) err(`${rel}: an svg lacks role=img, title or desc`);
  if (!/<ol class="alt"/.test(html)) err(`${rel}: no text alternative list under the diagram`);
  if (!/<th scope="row">/.test((/<table class="compare">[\s\S]*?<\/table>/.exec(html) || [""])[0])) err(`${rel}: Without/With table missing`);
  const words = text.replace(/\s+/g, " ").trim().split(" ").length;
  if (words < 900 || words > 2000) err(`${rel}: ${words} words (expected about 900 to 1400 of prose plus tables)`);
}

function checkHtml(file, siteRoot) {
  const html = read(file);
  const rel = path.relative(here, file);
  const relInSite = path.relative(siteRoot, file).split(path.sep).join("/");
  nPages++;
  if (!/^<!doctype html>/i.test(html)) err(`${rel}: missing doctype`);
  if (!/<html lang="[a-z-]+"/.test(html)) err(`${rel}: missing html lang`);
  if (!/<meta name="viewport"/.test(html)) err(`${rel}: missing viewport meta`);
  if (!/<title>[^<]{3,}<\/title>/.test(html)) err(`${rel}: missing title`);
  if ((html.match(/<h1[ >]/g) || []).length !== 1) err(`${rel}: expected exactly one h1`);
  if (!/<main[ >]/.test(html)) err(`${rel}: missing main landmark`);
  const ids = [...html.matchAll(/\sid="([^"]+)"/g)].map((x) => x[1]);
  if (new Set(ids).size !== ids.length) err(`${rel}: duplicate ids`);
  if (siteRoot === sites["atep.dev"]) {
    for (const needle of [/<link rel="icon" href="\/?assets\/favicon\.svg"/, /<link rel="apple-touch-icon" href="\/?assets\/apple-touch-icon\.png"/, /<meta name="theme-color" content="#[0-9a-f]{6}"/, /<meta property="og:title" content="[^"]+"/, /<meta property="og:description" content="[^"]+"/, /<meta property="og:image" content="https:\/\/atep\.dev\/assets\/[^"]+"/, /<meta name="twitter:card" content="summary_large_image"/, /<meta name="twitter:image" content="https:\/\/atep\.dev\/assets\//]) {
      if (!needle.test(html)) err(`${rel}: missing meta tag ${needle}`);
    }
  }
  if (siteRoot === sites["atep.dev"] && relInSite !== "404.html") {
    const want = canonicalOf(relInSite);
    const can = [...html.matchAll(/<link rel="canonical" href="([^"]*)"/g)].map((x) => x[1]);
    if (can.length !== 1) err(`${rel}: expected exactly one canonical link, found ${can.length}`);
    else if (!/^https:\/\/atep\.dev\//.test(can[0])) err(`${rel}: canonical is not an absolute https://atep.dev URL: ${can[0]}`);
    else if (can[0] !== want) err(`${rel}: canonical is ${can[0]}, expected ${want}`);
    const ou = /<meta property="og:url" content="([^"]*)"/.exec(html);
    if (!ou) err(`${rel}: missing og:url`);
    else if (ou[1] !== (can[0] || want)) err(`${rel}: og:url ${ou[1]} differs from canonical`);
    const isDemo = relInSite === "demo/index.html";
    if (!isDemo && !/<a [^>]*href="(\/|)claims\/?"/.test(html)) err(`${rel}: no visible link to the claims directory in the nav`);
    if (!isDemo && !/<a [^>]*href="(\/|)demo\/"[^>]*>Live simulator(<span class="sr-only">[^<]*<\/span>)?<\/a>/.test(html)) err(`${rel}: no Live simulator link in the nav`);
    if (!isDemo && !/<a [^>]*href="(\/|)in-practice\.html"[^>]*>In practice<\/a>/.test(html)) err(`${rel}: no In practice link in the nav`);
    if (/\sstyle=|<style/.test(html)) err(`${rel}: inline style (CSP)`);
  }
  if (relInSite === "404.html" && !/<a [^>]*href="\/in-practice\.html"[^>]*>In practice<\/a>/.test(html)) err(`${rel}: no In practice link in the nav`);
  if (relInSite === "in-practice.html") checkInPractice(html, rel);
  for (const img of html.matchAll(/<img\b[^>]*>/g)) if (!/\salt=/.test(img[0])) err(`${rel}: img without alt`);
  for (const m of html.matchAll(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/g)) {
    nLd++;
    try {
      const o = JSON.parse(m[1]);
      if (!o["@context"] || !o["@type"]) err(`${rel}: JSON-LD without @context or @type`);
    } catch (e) { err(`${rel}: JSON-LD does not parse: ${e.message}`); }
  }
  for (const m of html.matchAll(/\s(?:href|src)="([^"]*)"/g)) {
    const href = m[1];
    if (href === "") { err(`${rel}: empty link`); continue; }
    nLinks++;
    const t = resolveTarget(file, siteRoot, href);
    if (t.external) continue;
    const f = finalFile(t);
    if (!exists(f)) { err(`${rel}: broken link ${href} (no file ${path.relative(path.join(here, ".."), f)})`); continue; }
    if (t.hash && f.endsWith(".html") && !idsOf(read(f)).has(t.hash)) err(`${rel}: missing fragment #${t.hash} in ${href}`);
  }
}

const TEXT = /\.(html|txt|css|js|json|xml|webmanifest)$/;
function listFiles(dir, base = "") {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? listFiles(path.join(dir, e.name), base + e.name + "/") : [base + e.name]));
}
for (const [host, dir] of Object.entries(sites)) {
  for (const f of listFiles(dir)) {
    const p = path.join(dir, f);
    if (f.endsWith(".html")) checkHtml(p, dir);
    if (TEXT.test(f) || f.endsWith("security.txt")) {
      if (f.startsWith("assets/") || f === "llms-full.txt") continue;
      const t = read(p);
      if (t.includes(EM)) err(`${host}/${f}: contains an em dash`);
      if (host === "atep.dev" && t.includes(EN)) err(`${host}/${f}: contains an en dash`);
    }
  }
  const llms = path.join(dir, "llms.txt");
  if (!exists(llms)) { err(`${host}: llms.txt missing`); continue; }
  const txt = read(llms);
  if (txt.split("\n").length > 40) err(`${host}/llms.txt: longer than one screen (40 lines)`);
  for (const m of txt.matchAll(/\]\(([^)]+)\)/g)) {
    nLinks++;
    const t = resolveTarget(llms, dir, m[1]);
    if (t.external) continue;
    if (!exists(finalFile(t))) err(`${host}/llms.txt: broken link ${m[1]}`);
  }
}

const atepRoot = sites["atep.dev"];
const run = (script, label) => {
  try { execFileSync(process.execPath, [path.join(here, script), "--check"], { stdio: "pipe" }); }
  catch (e) { err(`${label} is out of date or invalid (run node site/${script}): ${String(e.stderr || e.stdout || e.message).trim().split("\n").join(" | ")}`); }
};
if (exists(path.join(here, "..", "rust/atep-log/data/claims.json"))) run("build-claims.mjs", "claim pages");
else err("rust/atep-log/data/claims.json not found (claim pages cannot be checked)");
run("build-sitemap.mjs", "sitemap.xml");
run("build-demo.mjs", "demo copy (site/atep.dev/demo/)");

// The hosted demo: no inline script or style (it runs under a CSP without 'unsafe-inline'), the files it loads exist,
// only the Content-Security-Policy differs for /demo/** and only by 'wasm-unsafe-eval' in script-src.
{
  const dp = path.join(atepRoot, "demo", "index.html");
  if (!exists(dp)) err("atep.dev/demo/index.html missing (run node site/build-demo.mjs)");
  else {
    const h = read(dp);
    if (/<script(?![^>]*\bsrc=)/.test(h) || /\sstyle=|<style|\son[a-z]+=/.test(h)) err("demo/index.html: inline script, style or event handler (CSP)");
    for (const f of ["style.css", "demo-site.css", "src/ui.mjs", "src/engine.mjs", "src/cbor.mjs", "vendor/atep-core/index.js", "vendor/atep-core/wasm/atep_wasm.js", "vendor/atep-core/wasm/atep_wasm_bg.wasm", "vendor/atep-core/THIRD-PARTY-NOTICES.md"]) {
      if (!exists(path.join(atepRoot, "demo", f))) err(`demo/${f} missing`);
    }
    for (const f of ["selftest.mjs", "serve.mjs", "package.json", "README.md"]) if (exists(path.join(atepRoot, "demo", f))) err(`demo/${f} must not be published`);
    for (const f of listFiles(path.join(atepRoot, "demo")).filter((x) => x.endsWith(".mjs") || x.endsWith(".js"))) {
      if (/\b(eval\s*\(|new Function\s*\()/.test(read(path.join(atepRoot, "demo", f)))) err(`demo/${f}: eval or new Function (the CSP does not allow it)`);
    }
    const hdr = JSON.parse(read(path.join(atepRoot, "static.json"))).headers;
    const base = hdr["/**"]?.["Content-Security-Policy"] || "", demo = hdr["/demo/**"]?.["Content-Security-Policy"] || "";
    if (!demo) err("static.json: no /demo/** Content-Security-Policy");
    else {
      if (demo.replace(" 'wasm-unsafe-eval'", "") !== base) err("static.json: the /demo/** CSP may differ from the site CSP only by 'wasm-unsafe-eval' in script-src");
      if (!/script-src[^;]*'wasm-unsafe-eval'/.test(demo)) err("static.json: the /demo/** CSP lacks 'wasm-unsafe-eval' in script-src");
      if (/unsafe-inline|'unsafe-eval'/.test(demo)) err("static.json: the /demo/** CSP must not allow unsafe-inline or unsafe-eval");
    }
    if (/wasm-unsafe-eval/.test(base)) err("static.json: the site-wide CSP must stay strict (no wasm-unsafe-eval)");
  }
}

// Claim pages: one HTML page and one JSON file per claim in claims.json, no extras; JSON-LD is a DefinedTerm in the set.
{
  const defs = JSON.parse(read(path.join(here, "..", "rust/atep-log/data/claims.json"))).claims;
  const cdir = path.join(atepRoot, "claims");
  const names = new Set(defs.map((c) => c.name));
  const files = listFiles(cdir);
  const htmls = files.filter((f) => f.endsWith(".html") && f !== "index.html").map((f) => f.slice(0, -5));
  const jsons = files.filter((f) => f.endsWith(".json") && f !== "index.json").map((f) => f.slice(0, -5));
  if (htmls.length !== defs.length) err(`claims: ${htmls.length} claim pages but claims.json defines ${defs.length}`);
  if (jsons.length !== defs.length) err(`claims: ${jsons.length} claim JSON files but claims.json defines ${defs.length}`);
  for (const n of [...htmls, ...jsons]) if (!names.has(n)) err(`claims: extra file for undefined claim ${n}`);
  for (const f of files) if (!/\.(html|json)$/.test(f)) err(`claims: unexpected file ${f}`);
  for (const c of defs) {
    for (const ext of ["html", "json"]) if (!exists(path.join(cdir, `${c.name}.${ext}`))) err(`claims: ${c.name}.${ext} missing`);
    const jp = path.join(cdir, `${c.name}.json`);
    if (exists(jp)) {
      let j; try { j = JSON.parse(read(jp)); } catch (e) { err(`claims/${c.name}.json does not parse`); continue; }
      for (const k of ["claim", "name", "core", "status", "profile", "definition", "title", "description", "issued-by", "subject", "data-schema", "data-schema-format", "attestation-schema", "data-checked-by", "evidence", "lifetime", "spec", "example-data", "links"]) if (!(k in j)) err(`claims/${c.name}.json lacks ${k}`);
      if (j.claim !== `${ATEP}/claims/${c.name}`) err(`claims/${c.name}.json has claim ${j.claim}`);
    }
    const hp = path.join(cdir, `${c.name}.html`);
    if (exists(hp)) {
      const h = read(hp);
      const ldm = /<script type="application\/ld\+json">([\s\S]*?)<\/script>/.exec(h);
      let o = null; try { o = JSON.parse(ldm[1]); } catch { err(`claims/${c.name}.html: JSON-LD missing or invalid`); }
      if (o && (o["@type"] !== "DefinedTerm" || o.inDefinedTermSet?.["@type"] !== "DefinedTermSet" || o["@id"] !== `${ATEP}/claims/${c.name}`)) err(`claims/${c.name}.html: JSON-LD is not a DefinedTerm in a DefinedTermSet`);
      if (!h.includes("<pre><code>") || !h.includes(c["data-schema"].split("\n")[0].replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"))) err(`claims/${c.name}.html: CDDL schema block missing`);
      if (/<script(?![^>]*\b(src=|type="application\/ld\+json"))/.test(h) || /\sstyle=|<style/.test(h)) err(`claims/${c.name}.html: inline script or style (CSP)`);
    }
  }
  const ix = exists(path.join(cdir, "index.json")) ? JSON.parse(read(path.join(cdir, "index.json"))) : null;
  if (!ix || ix.claims.length !== defs.length) err("claims/index.json does not list every claim");
  if (!exists(path.join(cdir, "index.html"))) err("claims/index.html missing");
}

// Sitemap lists exactly the pages that exist (index and 404 handled), every canonical is in it.
{
  const sp = path.join(atepRoot, "sitemap.xml");
  if (!exists(sp)) err("atep.dev/sitemap.xml missing");
  else {
    const listed = [...read(sp).matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1]);
    const expected = listFiles(atepRoot).filter((f) => f.endsWith(".html") && f !== "404.html").map(canonicalOf);
    if (new Set(listed).size !== listed.length) err("sitemap.xml has duplicate URLs");
    for (const u of expected) if (!listed.includes(u)) err(`sitemap.xml lacks ${u}`);
    for (const u of listed) if (!expected.includes(u)) err(`sitemap.xml lists ${u}, which is not a page`);
    for (const u of listed) if (!u.startsWith(`${ATEP}/`)) err(`sitemap.xml URL is not absolute https://atep.dev: ${u}`);
  }
}
if (!exists(path.join(atepRoot, "404.html"))) err("atep.dev/404.html missing");

// robots.txt: only the agreed lines; the AI crawler and content-signal policy is the owner's, set at Cloudflare.
{
  const rp = path.join(atepRoot, "robots.txt");
  if (!exists(rp)) err("atep.dev/robots.txt missing");
  else {
    const lines = read(rp).split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
    const want = ["User-agent: *", "Allow: /", `Sitemap: ${ATEP}/sitemap.xml`];
    if (lines.join("\n") !== want.join("\n")) err(`robots.txt must contain exactly: ${want.join(" / ")}`);
  }
}

// security.txt (RFC 9116): required fields, canonical, expiry.
{
  const sp = path.join(atepRoot, ".well-known", "security.txt");
  if (!exists(sp)) err("atep.dev/.well-known/security.txt missing");
  else {
    const f = {};
    for (const line of read(sp).split("\n")) { const m = /^([A-Za-z-]+):\s*(.*)$/.exec(line); if (m) (f[m[1]] ||= []).push(m[2].trim()); }
    if (!f.Contact?.length) err("security.txt: Contact missing");
    if (f.Canonical?.[0] !== `${ATEP}/.well-known/security.txt`) err("security.txt: Canonical must be https://atep.dev/.well-known/security.txt");
    if (!f.Expires || f.Expires.length !== 1) err("security.txt: exactly one Expires field required");
    else if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(f.Expires[0]) || Number.isNaN(Date.parse(f.Expires[0]))) err(`security.txt: Expires is not an ISO 8601 UTC timestamp: ${f.Expires[0]}`);
    else {
      const now = process.env.SITE_CHECK_NOW ? Date.parse(process.env.SITE_CHECK_NOW) : Date.now();
      const days = (Date.parse(f.Expires[0]) - now) / 86400000;
      if (days <= 0) err(`security.txt: expired on ${f.Expires[0]}; renew Expires`);
      else if (days < 60) warn(`security.txt expires in ${Math.floor(days)} days (${f.Expires[0]}); renew it`);
    }
  }
}

// Brand assets must exist and stay small.
for (const [f, max] of [["atep-wordmark.jpg", 60000], ["og-card.jpg", 120000], ["favicon.svg", 5000], ["favicon-32.png", 5000], ["apple-touch-icon.png", 20000], ["README.md", 1e6], ["build-assets.mjs", 1e6]]) {
  const p = path.join(sites["atep.dev"], "assets", f);
  if (!exists(p)) err(`atep.dev/assets/${f} missing`);
  else if (fs.statSync(p).size > max) err(`atep.dev/assets/${f} larger than ${max} bytes`);
}
for (const f of ["theme-boot.js", "site.js", "style.css"]) if (!exists(path.join(sites["atep.dev"], f))) err(`atep.dev/${f} missing`);

// llms-full.txt must match the spec it claims to contain.
const full = path.join(sites["atep.dev"], "llms-full.txt");
const specFile = path.join(here, "..", "spec", "ATEP-Specification-Draft-08.md");
if (!exists(full)) err("atep.dev/llms-full.txt missing (run node site/build-llms-full.mjs)");
else {
  const spec = read(specFile);
  const sha = crypto.createHash("sha256").update(spec).digest("hex");
  if (!read(full).endsWith(spec) || !read(full).includes(sha)) err("atep.dev/llms-full.txt is out of date (run node site/build-llms-full.mjs)");
}

for (const w of warnings) console.warn("WARN " + w);
console.log(`checked ${nPages} pages, ${nLinks} links, ${nLd} JSON-LD blocks`);
if (errors.length) { console.error(errors.map((e) => "FAIL " + e).join("\n")); process.exit(1); }
console.log("OK");
