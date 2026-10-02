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
// Files that live in the site folders but are never served.
const HIDDEN = (rel) =>
  rel === "static.json" || rel.endsWith(".mjs") || /(^|\/)README\.md$/i.test(rel) || rel.split("/").some((p) => p.startsWith("."));

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

  const send = (req, res, status, headers, body) => {
    res.writeHead(status, headers);
    res.end(req.method === "HEAD" ? undefined : body);
  };

  return http.createServer((req, res) => {
    const base = headersFor("/");
    if (req.method !== "GET" && req.method !== "HEAD") {
      return send(req, res, 405, { ...base, Allow: "GET, HEAD", "Content-Type": "text/plain; charset=utf-8" }, "Method not allowed\n");
    }
    // Heroku terminates TLS and tells us the original scheme.
    if (httpsOnly && req.headers["x-forwarded-proto"] === "http") {
      const host = req.headers.host || "";
      return send(req, res, 301, { Location: `https://${host}${req.url}`, "Content-Type": "text/plain; charset=utf-8" }, "Moved permanently\n");
    }

    let urlPath;
    try {
      urlPath = decodeURIComponent(new URL(req.url, "http://x").pathname);
    } catch {
      return send(req, res, 400, { ...base, "Content-Type": "text/plain; charset=utf-8" }, "Bad request\n");
    }
    const notFound = () =>
      send(req, res, 404, { ...base, "Cache-Control": "no-store", "Content-Type": "text/html; charset=utf-8" },
        "<!doctype html><meta charset=utf-8><title>Not found</title><h1>404 Not found</h1><p><a href=\"/\">Home</a></p>\n");
    if (urlPath.includes("\0")) return notFound();

    let file = path.join(root, path.normalize(urlPath));
    if (file !== root && !file.startsWith(root + path.sep)) return notFound();
    try {
      if (fs.statSync(file).isDirectory()) file = path.join(file, "index.html");
    } catch {
      return notFound();
    }
    const rel = path.relative(root, file).split(path.sep).join("/");
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
    const headers = { ...headersFor(`/${rel}`), "Content-Type": type, ETag: etag, "Last-Modified": stat.mtime.toUTCString(), Vary: "Accept-Encoding" };
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
