// Minimal CBOR encoder and decoder for the demo payloads (maps with text
// keys, text, unsigned and negative integers, arrays, booleans, null, bytes).
// Payload bytes are what the real ATEP envelope signs and encrypts; the real
// verifier decodes them too (for example to recognise an e-stop).

function head(major, n, out) {
  if (n < 24) out.push((major << 5) | n);
  else if (n < 256) out.push((major << 5) | 24, n);
  else if (n < 65536) out.push((major << 5) | 25, n >> 8, n & 255);
  else out.push((major << 5) | 26, (n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
}

function enc(v, out) {
  if (v === null || v === undefined) out.push(0xf6);
  else if (v === true) out.push(0xf5);
  else if (v === false) out.push(0xf4);
  else if (typeof v === "number") {
    if (!Number.isInteger(v)) throw new Error("cbor: integers only");
    if (v >= 0) head(0, v, out);
    else head(1, -1 - v, out);
  } else if (typeof v === "string") {
    const b = new TextEncoder().encode(v);
    head(3, b.length, out);
    for (const x of b) out.push(x);
  } else if (v instanceof Uint8Array) {
    head(2, v.length, out);
    for (const x of v) out.push(x);
  } else if (Array.isArray(v)) {
    head(4, v.length, out);
    for (const x of v) enc(x, out);
  } else if (typeof v === "object") {
    const keys = Object.keys(v);
    head(5, keys.length, out);
    for (const k of keys) {
      enc(k, out);
      enc(v[k], out);
    }
  } else throw new Error("cbor: unsupported value");
}

export function encode(v) {
  const out = [];
  enc(v, out);
  return Uint8Array.from(out);
}

export function decode(bytes) {
  let i = 0;
  const arg = (ai) => {
    if (ai < 24) return ai;
    if (ai === 24) return bytes[i++];
    if (ai === 25) { const v = (bytes[i] << 8) | bytes[i + 1]; i += 2; return v; }
    if (ai === 26) { const v = ((bytes[i] << 24) >>> 0) + (bytes[i + 1] << 16) + (bytes[i + 2] << 8) + bytes[i + 3]; i += 4; return v; }
    throw new Error("cbor: unsupported length");
  };
  const item = () => {
    const b = bytes[i++];
    const major = b >> 5;
    const ai = b & 31;
    if (major === 7) {
      if (ai === 20) return false;
      if (ai === 21) return true;
      if (ai === 22) return null;
      throw new Error("cbor: unsupported simple value");
    }
    const n = arg(ai);
    switch (major) {
      case 0: return n;
      case 1: return -1 - n;
      case 2: { const r = bytes.slice(i, i + n); i += n; return r; }
      case 3: { const r = new TextDecoder().decode(bytes.slice(i, i + n)); i += n; return r; }
      case 4: { const a = []; for (let k = 0; k < n; k++) a.push(item()); return a; }
      case 5: { const o = {}; for (let k = 0; k < n; k++) { const key = item(); o[key] = item(); } return o; }
      default: throw new Error("cbor: unsupported major type");
    }
  };
  return item();
}
