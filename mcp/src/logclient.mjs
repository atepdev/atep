// Minimal, defensive HTTP client for an ATEP log or registry (rust/docs/log-api.md).
//
// Safety properties:
//  * Only the configured base URL is ever contacted. Callers pass a path and a query
//    object; nothing a model supplies can change scheme, host or port.
//  * Redirects are never followed to another origin; same-origin redirects are followed
//    at most MAX_REDIRECTS times, and only to paths under the configured base path.
//  * Per-request timeout and a hard response size limit (streamed, not buffered first).
//  * GET only, no credentials, no cookies, JSON only.

const MAX_REDIRECTS = 2;

export class LogError extends Error {
  constructor(code, message, extra = {}) {
    super(message);
    this.code = code;
    Object.assign(this, extra);
  }
}

export function parseBaseUrl(raw) {
  if (!raw) return null;
  let u;
  try {
    u = new URL(raw);
  } catch {
    throw new Error(`ATEP_LOG_URL is not a valid URL: ${raw}`);
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") throw new Error("ATEP_LOG_URL must be http or https");
  if (u.username || u.password) throw new Error("ATEP_LOG_URL must not contain credentials");
  u.hash = "";
  u.search = "";
  if (!u.pathname.endsWith("/")) u.pathname += "/";
  return u;
}

export class LogClient {
  /**
   * @param {string|URL|null} baseUrl
   * @param {{timeoutMs?: number, maxBytes?: number, fetchImpl?: typeof fetch}} [opts]
   */
  constructor(baseUrl, opts = {}) {
    this.base = baseUrl instanceof URL ? baseUrl : parseBaseUrl(baseUrl);
    this.timeoutMs = opts.timeoutMs ?? 10_000;
    this.maxBytes = opts.maxBytes ?? 4 * 1024 * 1024;
    this.fetch = opts.fetchImpl ?? globalThis.fetch;
  }

  get configured() {
    return this.base !== null;
  }

  /** GET `path` (relative, no leading slash needed) with query params. Returns parsed JSON. */
  async getJson(path, query = {}) {
    if (!this.base) throw new LogError("not_configured", "No log or registry is configured (set ATEP_LOG_URL).");
    // Build the URL from the base; the path is appended as a relative reference after
    // stripping anything that could escape the base path.
    const rel = String(path).replace(/^\/+/, "");
    if (rel.split("/").some((seg) => seg === ".." || seg === ".")) throw new LogError("bad_path", "Path traversal refused.");
    let url = new URL(rel, this.base);
    for (const [k, v] of Object.entries(query)) if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
    this.#assertAllowed(url);

    for (let hop = 0; ; hop++) {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
      let res;
      try {
        res = await this.fetch(url, {
          method: "GET",
          redirect: "manual",
          signal: ctrl.signal,
          headers: { accept: "application/json", "user-agent": "atep-mcp/0.1" },
          credentials: "omit",
        });
      } catch (e) {
        clearTimeout(timer);
        if (ctrl.signal.aborted) throw new LogError("timeout", `Request timed out after ${this.timeoutMs} ms.`);
        throw new LogError("network", `Request failed: ${e?.cause?.code ?? e?.message ?? "unknown error"}`);
      }
      try {
        if (res.status >= 300 && res.status < 400) {
          const loc = res.headers.get("location");
          await res.body?.cancel().catch(() => {});
          if (!loc || hop >= MAX_REDIRECTS) throw new LogError("redirect", "Too many redirects or redirect without location.");
          let next;
          try {
            next = new URL(loc, url);
          } catch {
            throw new LogError("redirect", "Invalid redirect location.");
          }
          this.#assertAllowed(next, true);
          url = next;
          continue;
        }
        const text = await readLimited(res, this.maxBytes, ctrl.signal);
        if (res.status === 404) throw new LogError("not_found", "Log returned 404.", { status: 404 });
        if (!res.ok) throw new LogError("http_error", `Log returned HTTP ${res.status}.`, { status: res.status });
        try {
          return JSON.parse(text);
        } catch {
          throw new LogError("bad_json", "Log response was not valid JSON.");
        }
      } finally {
        clearTimeout(timer);
      }
    }
  }

  #assertAllowed(url, isRedirect = false) {
    if (url.origin !== this.base.origin) {
      throw new LogError(isRedirect ? "redirect_off_host" : "off_host", "Refusing to contact a host other than the configured log.");
    }
    if (!url.pathname.startsWith(this.base.pathname)) {
      throw new LogError("off_path", "Refusing a path outside the configured base path.");
    }
  }
}

async function readLimited(res, maxBytes, signal) {
  const len = Number(res.headers.get("content-length"));
  if (Number.isFinite(len) && len > maxBytes) {
    await res.body?.cancel().catch(() => {});
    throw new LogError("too_large", `Response larger than ${maxBytes} bytes.`);
  }
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    let r;
    try {
      r = await reader.read();
    } catch {
      throw new LogError(signal.aborted ? "timeout" : "network", "Failed while reading the response.");
    }
    if (r.done) break;
    total += r.value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => {});
      throw new LogError("too_large", `Response larger than ${maxBytes} bytes.`);
    }
    chunks.push(r.value);
  }
  return Buffer.concat(chunks).toString("utf8");
}
