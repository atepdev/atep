// Generates site/atep.dev/sitemap.xml: every HTML page of the site plus the claims directory and every claim page,
// as absolute https://atep.dev URLs. No lastmod (a deterministic build needs none). 404.html is not listed.
//
//   node site/build-sitemap.mjs           write the file
//   node site/build-sitemap.mjs --check   fail (exit 1) when it is stale
//
// Run build-claims.mjs first: the claim pages are found on disk. No dependencies.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, "atep.dev");
const outFile = path.join(root, "sitemap.xml");
const ORIGIN = "https://atep.dev";

export function pageUrls() {
  const urls = [];
  for (const f of fs.readdirSync(root).sort()) {
    if (!f.endsWith(".html") || f === "404.html") continue;
    urls.push(f === "index.html" ? `${ORIGIN}/` : `${ORIGIN}/${f}`);
  }
  const walk = (dir, rel) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
      if (e.isDirectory()) walk(path.join(dir, e.name), `${rel}${e.name}/`);
      else if (e.name.endsWith(".html")) urls.push(e.name === "index.html" ? `${ORIGIN}/claims/${rel}` : `${ORIGIN}/claims/${rel}${e.name.slice(0, -5)}`);
    }
  };
  const claims = path.join(root, "claims");
  if (fs.existsSync(claims)) walk(claims, "");
  return urls;
}

export function sitemapXml() {
  const urls = pageUrls();
  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.map((u) => `  <url><loc>${u}</loc></url>`).join("\n")}\n</urlset>\n`;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const xml = sitemapXml();
  if (process.argv.includes("--check")) {
    if (!fs.existsSync(outFile) || fs.readFileSync(outFile, "utf8") !== xml) {
      console.error("FAIL atep.dev/sitemap.xml is missing or out of date\nrun: node site/build-sitemap.mjs");
      process.exit(1);
    }
    console.log(`sitemap up to date: ${pageUrls().length} URLs`);
  } else {
    fs.writeFileSync(outFile, xml);
    console.log(`wrote atep.dev/sitemap.xml (${pageUrls().length} URLs)`);
  }
}
