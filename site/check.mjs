// Static checks for site/: JSON-LD parses, internal links and fragments resolve, basic accessibility
// hygiene, no em dashes, llms.txt size, llms-full.txt up to date. Usage: node site/check.mjs
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const sites = { "atep.dev": path.join(here, "atep.dev"), "airadlabs.com": path.join(here, "airadlabs.com") };
const errors = [];
const err = (m) => errors.push(m);
const read = (p) => fs.readFileSync(p, "utf8");
const exists = (p) => fs.existsSync(p) && fs.statSync(p).isFile();
const EM = String.fromCharCode(0x2014);
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
  const file = pathPart === "" ? fromFile : path.resolve(path.dirname(fromFile), pathPart);
  return { file, hash, isDirUrl: pathPart.endsWith("/") };
}

function finalFile(t) {
  if (fs.existsSync(t.file) && fs.statSync(t.file).isDirectory()) return path.join(t.file, "index.html");
  return t.file;
}

const idsOf = (html) => new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((x) => x[1]));

function checkHtml(file, siteRoot) {
  const html = read(file);
  const rel = path.relative(here, file);
  nPages++;
  if (!/^<!doctype html>/i.test(html)) err(`${rel}: missing doctype`);
  if (!/<html lang="[a-z-]+"/.test(html)) err(`${rel}: missing html lang`);
  if (!/<meta name="viewport"/.test(html)) err(`${rel}: missing viewport meta`);
  if (!/<title>[^<]{3,}<\/title>/.test(html)) err(`${rel}: missing title`);
  if ((html.match(/<h1[ >]/g) || []).length !== 1) err(`${rel}: expected exactly one h1`);
  if (!/<main[ >]/.test(html)) err(`${rel}: missing main landmark`);
  const ids = [...html.matchAll(/\sid="([^"]+)"/g)].map((x) => x[1]);
  if (new Set(ids).size !== ids.length) err(`${rel}: duplicate ids`);
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

for (const [host, dir] of Object.entries(sites)) {
  for (const f of fs.readdirSync(dir)) {
    const p = path.join(dir, f);
    if (f.endsWith(".html")) checkHtml(p, dir);
    if (f.endsWith(".html") || f.endsWith(".txt") || f.endsWith(".css") || f.endsWith(".js")) {
      if (f !== "llms-full.txt" && read(p).includes(EM)) err(`${host}/${f}: contains an em dash`);
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

// llms-full.txt must match the spec it claims to contain.
const full = path.join(sites["atep.dev"], "llms-full.txt");
const specFile = path.join(here, "..", "spec", "ATEP-Specification-Draft-07.md");
if (!exists(full)) err("atep.dev/llms-full.txt missing (run node site/build-llms-full.mjs)");
else {
  const spec = read(specFile);
  const sha = crypto.createHash("sha256").update(spec).digest("hex");
  if (!read(full).endsWith(spec) || !read(full).includes(sha)) err("atep.dev/llms-full.txt is out of date (run node site/build-llms-full.mjs)");
}

console.log(`checked ${nPages} pages, ${nLinks} links, ${nLd} JSON-LD blocks`);
if (errors.length) { console.error(errors.map((e) => "FAIL " + e).join("\n")); process.exit(1); }
console.log("OK");
