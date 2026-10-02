// Minimal CBOR reader for the ATEP vectors (no dependencies). Only what the
// protocol uses: unsigned and negative integers, byte and text strings, arrays,
// maps, tags, booleans and null. Every node carries its byte span in the input,
// so a nested item can be sliced out byte for byte (no re-encoding).
export function decode(buf) {
  let p = 0;
  function head() {
    const ib = buf[p++];
    const major = ib >> 5;
    const ai = ib & 31;
    let arg;
    if (ai < 24) arg = BigInt(ai);
    else if (ai === 24) arg = BigInt(buf[p++]);
    else if (ai === 25) { arg = BigInt(buf.readUInt16BE(p)); p += 2; }
    else if (ai === 26) { arg = BigInt(buf.readUInt32BE(p)); p += 4; }
    else if (ai === 27) { arg = buf.readBigUInt64BE(p); p += 8; }
    else throw new Error(`unsupported additional info ${ai} at ${p - 1}`);
    return { major, arg, ai };
  }
  function item() {
    const start = p;
    const { major, arg, ai } = head();
    const n = Number(arg);
    let node;
    switch (major) {
      case 0: node = { t: 'uint', v: arg }; break;
      case 1: node = { t: 'nint', v: -1n - arg }; break;
      case 2: node = { t: 'bstr', bytes: buf.subarray(p, p + n) }; p += n; break;
      case 3: node = { t: 'tstr', v: buf.subarray(p, p + n).toString('utf8') }; p += n; break;
      case 4: { const items = []; for (let i = 0; i < n; i++) items.push(item()); node = { t: 'array', items }; break; }
      case 5: { const pairs = []; for (let i = 0; i < n; i++) { const k = item(); const v = item(); pairs.push([k, v]); } node = { t: 'map', pairs }; break; }
      case 6: node = { t: 'tag', tag: n, inner: item() }; break;
      case 7:
        if (ai === 20) node = { t: 'bool', v: false };
        else if (ai === 21) node = { t: 'bool', v: true };
        else if (ai === 22) node = { t: 'null' };
        else throw new Error(`unsupported simple/float ${ai}`);
        break;
    }
    node.start = start;
    node.end = p;
    return node;
  }
  const root = item();
  if (p !== buf.length) throw new Error(`trailing bytes after item (${buf.length - p})`);
  return root;
}

// Look up an integer or text map key.
export function get(map, key) {
  for (const [k, v] of map.pairs) {
    if (typeof key === 'number' && (k.t === 'uint' || k.t === 'nint') && k.v === BigInt(key)) return v;
    if (typeof key === 'string' && k.t === 'tstr' && k.v === key) return v;
  }
  return undefined;
}

// ---- encoder for the mutation checks (shortest-form heads, definite lengths) ----
function headBytes(major, n) {
  n = BigInt(n);
  if (n < 24n) return Buffer.from([(major << 5) | Number(n)]);
  if (n < 256n) return Buffer.from([(major << 5) | 24, Number(n)]);
  if (n < 65536n) { const b = Buffer.alloc(3); b[0] = (major << 5) | 25; b.writeUInt16BE(Number(n), 1); return b; }
  if (n < 4294967296n) { const b = Buffer.alloc(5); b[0] = (major << 5) | 26; b.writeUInt32BE(Number(n), 1); return b; }
  const b = Buffer.alloc(9); b[0] = (major << 5) | 27; b.writeBigUInt64BE(n, 1); return b;
}
export function encode(n) {
  switch (n.t) {
    case 'uint': return headBytes(0, n.v);
    case 'nint': return headBytes(1, -1n - n.v);
    case 'bstr': return Buffer.concat([headBytes(2, n.bytes.length), Buffer.from(n.bytes)]);
    case 'tstr': { const b = Buffer.from(n.v, 'utf8'); return Buffer.concat([headBytes(3, b.length), b]); }
    case 'array': return Buffer.concat([headBytes(4, n.items.length), ...n.items.map(encode)]);
    case 'map': return Buffer.concat([headBytes(5, n.pairs.length), ...n.pairs.flatMap(([k, v]) => [encode(k), encode(v)])]);
    case 'tag': return Buffer.concat([headBytes(6, n.tag), encode(n.inner)]);
    case 'bool': return Buffer.from([n.v ? 0xf5 : 0xf4]);
    case 'null': return Buffer.from([0xf6]);
    case 'wrapped': { const b = encode(n.inner); return Buffer.concat([headBytes(2, b.length), b]); }
    default: throw new Error(`cannot encode ${n.t}`);
  }
}
export const intNode = (v) => { v = BigInt(v); return v >= 0n ? { t: 'uint', v } : { t: 'nint', v }; };
