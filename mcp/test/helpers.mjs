import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const here = path.dirname(fileURLToPath(import.meta.url));
export const BIN = path.join(here, "..", "bin", "atep-mcp.mjs");
export const VECTORS = path.join(here, "..", "..", "vectors");

export async function connect(env = {}) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [BIN],
    env: { PATH: process.env.PATH, ...env },
    stderr: "pipe",
  });
  const client = new Client({ name: "atep-mcp-test", version: "0.0.0" });
  await client.connect(transport);
  return client;
}

export async function call(client, name, args) {
  const r = await client.callTool({ name, arguments: args });
  return { isError: r.isError === true, out: r.structuredContent, text: r.content?.[0]?.text };
}

export function b64u(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

export function readVector(category, name) {
  const dir = path.join(VECTORS, category);
  return {
    bytes: fs.readFileSync(path.join(dir, `${name}.cbor`)),
    meta: JSON.parse(fs.readFileSync(path.join(dir, `${name}.expected.json`), "utf8")),
  };
}

export function listVectors(category) {
  return fs.readdirSync(path.join(VECTORS, category)).filter((f) => f.endsWith(".cbor")).map((f) => f.slice(0, -5));
}

/** A small fake ATEP log. `routes` maps "/path" to a handler (req, res, url). Records every request path. */
export async function fakeServer(routes) {
  const seen = [];
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://x");
    seen.push(req.method + " " + url.pathname + url.search);
    const h = routes[url.pathname];
    if (!h) {
      res.writeHead(404, { "content-type": "application/json" });
      res.end('{"error":"not_found"}');
      return;
    }
    h(req, res, url);
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  return {
    url: `http://127.0.0.1:${port}/`,
    seen,
    close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }),
  };
}

export const json = (obj, status = 200) => (req, res) => {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(obj));
};
