// Envelope bytes as an HTTP body with media type application/atep+cbor.
import http from "node:http";

export const ENVELOPE_MIME = "application/atep+cbor";

/** Serve one envelope at GET /envelope (and accept POST /envelope, answering with the stored bytes' length). */
export function serveEnvelope(bytes) {
  const server = http.createServer((req, res) => {
    if (req.method === "GET" && req.url === "/envelope") {
      res.writeHead(200, { "content-type": ENVELOPE_MIME, "content-length": bytes.length });
      return res.end(Buffer.from(bytes));
    }
    res.writeHead(404).end();
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({
    url: `http://127.0.0.1:${server.address().port}/envelope`,
    close: () => new Promise((r) => { server.close(r); server.closeAllConnections?.(); }),
  })));
}

/** Fetch envelope bytes; refuses a response that is not application/atep+cbor. */
export async function fetchEnvelope(url) {
  const res = await fetch(url);
  const ct = res.headers.get("content-type");
  if (!res.ok || ct !== ENVELOPE_MIME) throw new Error(`unexpected response ${res.status} ${ct}`);
  return new Uint8Array(await res.arrayBuffer());
}

/** POST envelope bytes to a receiver URL (body is the raw envelope). */
export async function postEnvelope(url, bytes) {
  return fetch(url, { method: "POST", headers: { "content-type": ENVELOPE_MIME }, body: bytes });
}
