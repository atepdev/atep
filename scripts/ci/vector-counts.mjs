// Vector consistency check. Usage: node scripts/ci/vector-counts.mjs
//
// 1. vectors/manifest.json lists N vectors; every listed vector has its .cbor, .json
//    and .expected.json files, and every .cbor on disk is listed (no orphans).
// 2. Each category directory exists, and every vector sha256 matches its .cbor file.
// 3. js/README.md and python/README.md each state "<passed> passed + <skipped> skipped =
//    <total>"; the total must equal the manifest count and skipped must equal the
//    log-admission plus monitor vectors.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const errors = [];
const err = (m) => errors.push(m);

const manifest = JSON.parse(fs.readFileSync(path.join(root, "vectors/manifest.json"), "utf8"));
const list = manifest.vectors;
if (!Array.isArray(list) || list.length === 0) err("manifest.json has no vectors array");
const total = list.length;

const listed = new Set();
const perCat = {};
for (const v of list) {
  perCat[v.category] = (perCat[v.category] || 0) + 1;
  const base = path.join(root, "vectors", v.category, v.name);
  listed.add(`${v.category}/${v.name}`);
  for (const ext of [".cbor", ".json", ".expected.json"]) {
    if (!fs.existsSync(base + ext)) err(`missing vector file: vectors/${v.category}/${v.name}${ext}`);
  }
  if (fs.existsSync(base + ".cbor")) {
    const sha = crypto.createHash("sha256").update(fs.readFileSync(base + ".cbor")).digest("hex");
    if (sha !== v.cbor_sha256) err(`sha256 mismatch: vectors/${v.category}/${v.name}.cbor`);
  }
}
if (listed.size !== total) err(`manifest has duplicate entries (${total} entries, ${listed.size} unique)`);

for (const cat of Object.keys(perCat)) {
  const dir = path.join(root, "vectors", cat);
  if (!fs.existsSync(dir)) { err(`missing category directory vectors/${cat}`); continue; }
  for (const f of fs.readdirSync(dir)) {
    if (f.endsWith(".cbor") && !listed.has(`${cat}/${f.slice(0, -5)}`)) err(`vector not in manifest: vectors/${cat}/${f}`);
  }
}

// Documented counts. log-admission and monitor are skipped by name in implementations
// without a log or monitor. Both READMEs state "<passed> passed + <skipped> skipped = <total>".
const skipped = (perCat["log-admission"] || 0) + (perCat["monitor"] || 0);
const read = (p) => fs.readFileSync(path.join(root, p), "utf8");
const re = /(\d+) passed \+ (\d+) skipped = (\d+)/g;
for (const file of ["js/README.md", "python/README.md"]) {
  let n = 0;
  for (const m of read(file).matchAll(re)) {
    n++;
    if (Number(m[3]) !== total) err(`${file}: documents ${m[3]} vectors in total, manifest has ${total}`);
    if (Number(m[2]) !== skipped) err(`${file}: documents ${m[2]} skipped, expected ${skipped} (log-admission and monitor)`);
    if (Number(m[1]) !== total - skipped) err(`${file}: documents ${m[1]} passed, expected ${total - skipped}`);
  }
  if (n === 0) err(`${file}: no "<n> passed + <n> skipped = <n>" statement found (documentation wording changed?)`);
}

if (errors.length) {
  console.error(errors.map((e) => "error: " + e).join("\n"));
  process.exit(1);
}
console.log(`vector counts ok: ${total} vectors in ${Object.keys(perCat).length} categories, all files present, hashes match`);
