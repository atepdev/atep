// Check relative links and anchors in the repository's Markdown files.
// Usage: node scripts/ci/check-md-links.mjs   (run from anywhere inside the repository)
// External links (http, https, mailto) are not fetched. Links inside code spans and
// fenced code blocks are ignored. Anchors use GitHub's heading slug rules.
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

const root = execFileSync("git", ["rev-parse", "--show-toplevel"], { encoding: "utf8" }).trim();
const listed = execFileSync("git", ["ls-files", "-z", "--cached", "--others", "--exclude-standard"], { cwd: root, encoding: "utf8" })
  .split("\0")
  .filter(Boolean);
const files = [...new Set(listed)].filter(
  (f) => f.endsWith(".md") && !/(^|\/)(node_modules|vendor)\//.test(f) && fs.existsSync(path.join(root, f)),
);

const errors = [];
const slugCache = new Map();

function slugify(heading) {
  return heading
    .trim()
    .toLowerCase()
    .replace(/<[^>]*>/g, "")
    .replace(/[`*_~]/g, "")
    .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/[^\p{L}\p{N}\s-]/gu, "")
    .replace(/\s/g, "-");
}

function anchorsOf(file) {
  if (slugCache.has(file)) return slugCache.get(file);
  const seen = new Map();
  const set = new Set();
  let fence = false;
  for (const line of fs.readFileSync(file, "utf8").split("\n")) {
    if (/^\s*(```|~~~)/.test(line)) { fence = !fence; continue; }
    if (fence) continue;
    const m = /^#{1,6}\s+(.*?)\s*#*\s*$/.exec(line);
    if (!m) continue;
    let s = slugify(m[1]);
    const n = seen.get(s) || 0;
    seen.set(s, n + 1);
    if (n > 0) s = `${s}-${n}`;
    set.add(s);
  }
  slugCache.set(file, set);
  return set;
}

let nLinks = 0;
for (const rel of files) {
  const abs = path.join(root, rel);
  let fence = false;
  const lines = fs.readFileSync(abs, "utf8").split("\n");
  lines.forEach((raw, i) => {
    if (/^\s*(```|~~~)/.test(raw)) { fence = !fence; return; }
    if (fence) return;
    const line = raw.replace(/`[^`]*`/g, "");
    for (const m of line.matchAll(/!?\[[^\]]*\]\(\s*(<[^>]+>|[^)\s]+)(?:\s+"[^"]*")?\s*\)/g)) {
      let href = m[1].replace(/^<|>$/g, "");
      if (/^([a-z][a-z0-9+.-]*:|\/\/)/i.test(href)) continue;
      nLinks++;
      const [pathPart, hash = ""] = href.split("#");
      let target = abs;
      if (pathPart) {
        let decoded = pathPart;
        try { decoded = decodeURIComponent(pathPart); } catch { /* keep raw */ }
        target = path.resolve(path.dirname(abs), decoded);
      }
      if (!target.startsWith(root + path.sep) && target !== root) { errors.push(`${rel}:${i + 1}: link leaves the repository: ${href}`); continue; }
      if (!fs.existsSync(target)) { errors.push(`${rel}:${i + 1}: broken link ${href}`); continue; }
      if (hash) {
        const st = fs.statSync(target);
        if (st.isFile() && target.endsWith(".md")) {
          let h = hash;
          try { h = decodeURIComponent(hash); } catch { /* keep raw */ }
          if (!anchorsOf(target).has(h.toLowerCase())) errors.push(`${rel}:${i + 1}: missing anchor #${hash} in ${pathPart || path.basename(rel)}`);
        }
      }
    }
  });
}

console.log(`checked ${files.length} Markdown files, ${nLinks} relative links`);
if (errors.length) {
  console.error(errors.map((e) => "FAIL " + e).join("\n"));
  process.exit(1);
}
console.log("OK");
