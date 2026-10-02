// Minimal static file server for the sites in this folder. No dependencies.
//
//   SITE=atep.dev PORT=8080 node server.mjs
//
// SITE names the folder to serve (atep.dev or airadlabs.com). Response headers and the
// HTTPS-only switch come from that folder's static.json. Only GET and HEAD are accepted.
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
  ".md": "text/markdown; charset=utf-8",
  ".xml": "application/xml; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".ico": "image/x-icon",
  ".webmanifest": "application/manifest+json",
};
const COMPRESSIBLE = new Set([".html", ".css", ".js", ".json", ".txt", ".md", ".xml", ".svg"]);
// Files that live in the site folders but are never served. Dot directories and files stay hidden except
// the .well-known directory (RFC 8615), whose files are served.
const HIDDEN = (rel) =>
  rel === "static.json" || rel.endsWith(".mjs") || /(^|\/)README\.md$/i.test(rel) ||
  rel.split("/").some((p) => p.startsWith(".") && p !== ".well-known");

// Under /claims/ an extensionless URL names a claim type that has an HTML and a JSON representation.
// Quality value of a media type in an Accept header: the most specific matching range wins (RFC 9110).
function acceptQ(header, type) {
  const [want] = type.split("/");
  let q = 0, bestSpec = -1;
  for (const part of header.split(",")) {
    const [range, ...params] = part.trim().toLowerCase().split(";").map((x) => x.trim());
    const spec = range === "*/*" ? 0 : range === `${want}/*` ? 1 : range === type ? 2 : -1;
    if (spec <= bestSpec) continue;
    bestSpec = spec;
    q = 1;
    for (const p of params) { const m = /^q=([0-9.]+)$/.exec(p); if (m) q = Math.min(1, Number(m[1]) || 0); }
  }
  return [q, bestSpec];
}
// JSON only when the client prefers it to HTML: a higher quality value, or equal quality with application/json
// named and text/html only matched by a wildcard ("application/json, */*"). No Accept header, "*/*" and any other
// tie give the default representation: JSON, as the specification says and as the reference log does, unless
// CLAIMS_DEFAULT=html. Browsers and crawlers send an Accept header that ranks text/html first and get the page.
function prefersJson(accept, tieIsJson) {
  const [jq, js] = acceptQ(accept || "", "application/json"), [hq, hs] = acceptQ(accept || "", "text/html");
  if (jq !== hq) return jq > hq;
  if (jq > 0 && js !== hs) return js > hs;
  return tieIsJson;
}

export function createServer(site, env = process.env) {
  const root = path.resolve(here, site);
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) throw new Error(`no such site folder: ${site}`);
  const cfg = JSON.parse(fs.readFileSync(path.join(root, "static.json"), "utf8"));
  const httpsOnly = cfg.https_only !== false && env.ATEP_SITE_ALLOW_HTTP !== "1";
  const rules = Object.entries(cfg.headers || {})
    .map(([pattern, headers]) => ({ prefix: pattern.endsWith("/**") ? pattern.slice(0, -2) : pattern, exact: !pattern.endsWith("/**"), headers }))
    .sort((a, b) => a.prefix.length - b.prefix.length);

  const headersFor = (urlPath) => {
    const out = {};
    for (const r of rules) {
      if (r.exact ? urlPath === r.prefix : urlPath.startsWith(r.prefix)) Object.assign(out, r.headers);
    }
    return out;
  };

  const canonicalHost = (env.CANONICAL_HOST || "").trim().toLowerCase().replace(/\.$/, "");
  const tieIsJson = (env.CLAIMS_DEFAULT || "json").toLowerCase() !== "html";
  const notFoundPage = path.join(root, "404.html");

  const send = (req, res, status, headers, body) => {
    res.writeHead(status, headers);
    res.end(req.method === "HEAD" ? undefined : body);
  };

  return http.createServer((req, res) => {
    const base = headersFor("/");
    if (req.method !== "GET" && req.method !== "HEAD") {
      return send(req, res, 405, { ...base, Allow: "GET, HEAD", "Content-Type": "text/plain; charset=utf-8" }, "Method not allowed\n");
    }
    // www.<CANONICAL_HOST> goes to the bare host in one hop (Cloudflare and Heroku send the original Host).
    if (canonicalHost) {
      const reqHost = (req.headers.host || "").toLowerCase().replace(/:\d+$/, "").replace(/\.$/, "");
      if (reqHost === `www.${canonicalHost}`) {
        let target = req.url || "/";
        if (!target.startsWith("/")) { try { const u = new URL(target); target = u.pathname + u.search; } catch { target = "/"; } }
        target = "/" + target.replace(/^\/+/, "");
        return send(req, res, 301, { Location: `https://${canonicalHost}${target}`, "Cache-Control": "public, max-age=3600", "Content-Type": "text/plain; charset=utf-8" }, "Moved permanently\n");
      }
    }
    // Heroku terminates TLS and tells us the original scheme.
    if (httpsOnly && req.headers["x-forwarded-proto"] === "http") {
      const host = req.headers.host || "";
      return send(req, res, 301, { Location: `https://${host}${req.url}`, "Content-Type": "text/plain; charset=utf-8" }, "Moved permanently\n");
    }

    let urlPath, search = "";
    try {
      const u = new URL(req.url, "http://x");
      urlPath = decodeURIComponent(u.pathname);
      search = u.search;
    } catch {
      return send(req, res, 400, { ...base, "Content-Type": "text/plain; charset=utf-8" }, "Bad request\n");
    }
    const fallback404 = "<!doctype html><meta charset=utf-8><title>Not found</title><h1>404 Not found</h1><p><a href=\"/\">Home</a></p>\n";
    const notFound = () => {
      let body = fallback404;
      try { body = fs.readFileSync(notFoundPage); } catch { /* no 404.html: minimal page */ }
      return send(req, res, 404, { ...base, "Cache-Control": "no-store", "Content-Type": "text/html; charset=utf-8" }, body);
    };
    if (urlPath.includes("\0")) return notFound();

    const isFile = (p) => { try { return fs.statSync(p).isFile(); } catch { return false; } };
    const isDir = (p) => { try { return fs.statSync(p).isDirectory(); } catch { return false; } };
    const relOf = (p) => path.relative(root, p).split(path.sep).join("/");
    const safe = (p) => p === root || p.startsWith(root + path.sep);

    let file = path.join(root, path.normalize(urlPath));
    if (!safe(file)) return notFound();
    const accept = req.headers.accept || "";
    let negotiated = false;
    if (isDir(file)) {
      const dirRel = relOf(file);
      if (HIDDEN(dirRel + "/x")) return notFound();
      // A directory is served only through its index file; there is no listing.
      const underClaims = dirRel === "claims";
      const html = path.join(file, "index.html"), json = path.join(file, "index.json");
      if (!isFile(html)) return notFound();
      if (!urlPath.endsWith("/")) {
        const to = "/" + urlPath.replace(/^\/+/, "") + "/" + search;
        return send(req, res, 301, { Location: to, "Content-Type": "text/plain; charset=utf-8" }, "Moved permanently\n");
      }
      if (underClaims && isFile(json)) { negotiated = true; if (prefersJson(accept, tieIsJson)) file = json; else file = html; }
      else file = html;
    } else if (!urlPath.endsWith("/") && path.extname(urlPath) === "" && !isFile(file)) {
      // Extensionless URL: serve <path>.html; under /claims/ also <path>.json when the client prefers it.
      const html = file + ".html", json = file + ".json";
      const inClaims = relOf(file).startsWith("claims/");
      if (inClaims && isFile(json) && isFile(html)) { negotiated = true; file = prefersJson(accept, tieIsJson) ? json : html; }
      else if (isFile(html)) file = html;
      else return notFound();
    }
    const rel = relOf(file);
    if (HIDDEN(rel)) return notFound();

    let stat;
    try {
      stat = fs.statSync(file);
      if (!stat.isFile()) return notFound();
    } catch {
      return notFound();
    }
    const ext = path.extname(file).toLowerCase();
    const type = TYPES[ext] || "application/octet-stream";
    const etag = `W/"${stat.size.toString(16)}-${Math.floor(stat.mtimeMs).toString(16)}"`;
    const headers = { ...headersFor(`/${rel}`), "Content-Type": type, ETag: etag, "Last-Modified": stat.mtime.toUTCString(), Vary: negotiated ? "Accept, Accept-Encoding" : "Accept-Encoding" };
    if (req.headers["if-none-match"] === etag) return send(req, res, 304, headers);

    let body = fs.readFileSync(file);
    if (COMPRESSIBLE.has(ext) && body.length > 1024 && /\bgzip\b/.test(req.headers["accept-encoding"] || "")) {
      body = zlib.gzipSync(body);
      headers["Content-Encoding"] = "gzip";
    }
    headers["Content-Length"] = body.length;
    return send(req, res, 200, headers, body);
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const site = process.env.SITE;
  if (!site) {
    console.error("error: set SITE to the folder to serve, for example SITE=atep.dev");
    process.exit(2);
  }
  const port = Number(process.env.PORT || 8080);
  createServer(site).listen(port, "0.0.0.0", () => console.log(`serving ${site} on port ${port}`));
}
