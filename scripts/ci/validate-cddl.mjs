#!/usr/bin/env node
// Validate the ATEP vectors against spec/schemas/atep.cddl with the Rust `cddl`
// crate (the version pinned in scripts/ci/cddl-map.json), driven by the table in
// scripts/ci/cddl-map.json. Deterministic; exits 1 on any mismatch between the
// expected and the actual result, on a stale map entry, or on a wrong tool version.
//
//   node scripts/ci/validate-cddl.mjs            (cddl on PATH, or CDDL=/path/to/cddl)
//   node scripts/ci/validate-cddl.mjs --list     (print every check and its expectation)
//
// Why a script and not just `cddl validate`: the tool takes one root rule per run
// (it uses the first rule of the file, so this script prepends `root = <rule>`),
// reports failure in its text output while still exiting 0, and cannot look inside
// a bstr payload, so the payloads of envelopes are cut out here (byte for byte, with
// scripts/ci/cbor-mini.mjs) and validated against their own rule.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { decode, encode, get, intNode } from './cbor-mini.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const map = JSON.parse(fs.readFileSync(path.join(root, 'scripts/ci/cddl-map.json'), 'utf8'));
const schema = fs.readFileSync(path.join(root, 'spec/schemas/atep.cddl'), 'utf8');
const manifest = JSON.parse(fs.readFileSync(path.join(root, 'vectors/manifest.json'), 'utf8'));
const cddl = process.env.CDDL || 'cddl';
const listOnly = process.argv.includes('--list');
const verbose = process.argv.includes('--verbose'); // print the tool's message for every expected failure
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'atep-cddl-'));
process.on('exit', () => fs.rmSync(tmp, { recursive: true, force: true }));

function die(msg) { console.error(`validate-cddl: ${msg}`); process.exit(1); }

// ---- tool ----
const ver = spawnSync(cddl, ['--version'], { encoding: 'utf8' });
if (ver.error) die(`cannot run '${cddl}': ${ver.error.message}`);
if (!listOnly && ver.stdout.trim() !== `cddl ${map.validator.version}`) {
  die(`expected 'cddl ${map.validator.version}', found '${ver.stdout.trim()}'`);
}

// Work around defects of the validator (not of the schema): see "tool_workarounds" in the map.
// Each replacement must apply to the schema exactly `count` times, so a schema edit that
// makes one obsolete or ineffective is noticed.
let toolSchema = schema;
for (const w of map.tool_workarounds ?? []) {
  const n = toolSchema.split(w.from).length - 1;
  if (n !== w.count) die(`tool workaround '${w.from}' applies ${n} times, expected ${w.count}`);
  toolSchema = toolSchema.split(w.from).join(w.to);
}

const ruleFiles = new Map();
function ruleFile(rule) {
  if (!ruleFiles.has(rule)) {
    const f = path.join(tmp, `root-${rule}.cddl`);
    fs.writeFileSync(f, `root = ${rule}\n\n${toolSchema}`);
    ruleFiles.set(rule, f);
  }
  return ruleFiles.get(rule);
}

let seq = 0;
function run(rule, kind, bytes) {
  const f = path.join(tmp, `in-${seq++}.${kind}`);
  fs.writeFileSync(f, bytes);
  const r = spawnSync(cddl, ['validate', '--cddl', ruleFile(rule), `--${kind}`, f], { encoding: 'utf8', maxBuffer: 1 << 26 });
  const out = `${r.stdout}${r.stderr}`.replace(/\x1b\[[0-9;]*m/g, '');
  // The tool exits 0 even when validation fails, so the verdict is read from its text.
  if (/Validation of ".*" is successful/.test(out)) return { ok: true, msg: '' };
  const m = /Validation of ".*" failed: ([^\n]*)/.exec(out);
  if (m) return { ok: false, msg: m[1].replace(/\s+/g, ' ').slice(0, 160) };
  die(`unrecognized tool output for rule '${rule}': ${out.slice(0, 300)}`);
}

// ---- extraction ----
const hex = (s) => Buffer.from(s, 'hex');
const re = (glob) => new RegExp('^' + glob.split('*').map((x) => x.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$');

function envelopeParts(bytes) {
  const d = decode(bytes);
  if (d.t !== 'tag' || d.inner.t !== 'array') return null;
  const items = d.inner.items;
  const out = { tag: d.tag, node: d, bytes };
  if (d.tag === 98) {
    const ph = decode(Buffer.from(items[0].bytes));
    out.contentType = get(ph, 3)?.v;
    out.payload = items[2].t === 'bstr' ? Buffer.from(items[2].bytes) : null;
    out.unprotected = items[1];
  }
  return out;
}

function walkPath(node, segs) {
  for (const s of segs) {
    if (!node || node.t !== 'map') return undefined;
    node = get(node, /^-?\d+$/.test(s) ? Number(s) : s);
  }
  return node;
}

function jsonPath(obj, p) {
  // dotted path, "[]" suffix flattens an array
  let cur = [obj];
  for (const seg of p.split('.')) {
    const flat = seg.endsWith('[]');
    const key = flat ? seg.slice(0, -2) : seg;
    cur = cur.flatMap((o) => {
      const v = o == null ? undefined : o[key];
      if (v === undefined) return [];
      return flat ? v : [v];
    });
  }
  return cur;
}

// Items: { id, label, rule, kind, bytes } or { id, label, skip }
function itemsFor(vec, c) {
  const id = `${vec.category}/${vec.name}`;
  const base = path.join(root, 'vectors', vec.category, vec.name);
  const rulePick = (parts, what) => {
    if (what === 'envelope') return map.envelope_rules[String(parts.tag)];
    return map.payload_rules[parts.contentType];
  };
  const out = [];
  const addEnvelopeAndPayload = (label, bytes, want) => {
    const parts = envelopeParts(bytes);
    if (!parts) die(`${id}: ${label} is not a tagged envelope`);
    if (want.includes('envelope')) {
      out.push({ id, label: `${label}:envelope`, rule: rulePick(parts, 'envelope'), kind: 'cbor', bytes });
    }
    if (want.includes('payload')) {
      if (parts.tag !== 98) out.push({ id, label: `${label}:payload`, skip: 'encrypted, payload not visible' });
      else if (!parts.payload) out.push({ id, label: `${label}:payload`, skip: 'detached payload' });
      else if (!map.payload_rules[parts.contentType]) out.push({ id, label: `${label}:payload`, skip: `no rule for ${parts.contentType}` });
      else {
        out.push({ id, label: `${label}:payload`, rule: rulePick(parts, 'payload'), kind: 'cbor', bytes: parts.payload });
        // the `data` map of an attestation, against the layout of its claim (spec section 7)
        if (parts.contentType === 'application/atep-attestation+cbor') {
          let doc;
          try { doc = decode(parts.payload); } catch { doc = null; }
          const claim = doc?.t === 'map' ? get(doc, 'claim') : undefined;
          const data = doc?.t === 'map' ? get(doc, 'data') : undefined;
          const rule = claim?.t === 'tstr' ? map.claim_data_rules[claim.v] : undefined;
          if (rule && data) {
            out.push({ id, label: `${label}:data(${claim.v.split('/').slice(-1)[0]})`, rule, kind: 'cbor', bytes: parts.payload.subarray(data.start, data.end) });
          }
        }
      }
    }
  };
  if (c.check === 'file') {
    const bytes = fs.readFileSync(`${base}.cbor`);
    if (c.rule === '@envelope') addEnvelopeAndPayload('file', bytes, ['envelope']);
    else out.push({ id, label: 'file', rule: c.rule, kind: 'cbor', bytes });
  } else if (c.check === 'payload') {
    addEnvelopeAndPayload('file', fs.readFileSync(`${base}.cbor`), ['payload']);
  } else if (c.check === 'nested') {
    // c.from: "file"; c.path: map keys from the unprotected header ("unprotected") or the document ("document");
    // c.as: "envelope" (rule by tag, then payload by content type) of the node found, one per path in c.paths
    const bytes = fs.readFileSync(`${base}.cbor`);
    const parts = envelopeParts(bytes);
    for (const p of c.paths) {
      let start;
      if (c.start === 'unprotected') start = parts?.unprotected;
      else { const d = decode(bytes); start = d.t === 'tag' ? d.inner : d; }
      const node = start && walkPath(start, p.split('.'));
      if (!node) { out.push({ id, label: `nested:${p}`, skip: 'absent' }); continue; }
      addEnvelopeAndPayload(`nested:${p}`, bytes.subarray(node.start, node.end), ['envelope', 'payload']);
    }
  } else if (c.check === 'input-envelopes') {
    const exp = JSON.parse(fs.readFileSync(`${base}.expected.json`, 'utf8'));
    jsonPath(exp, c.path).forEach((h, i) => {
      if (typeof h !== 'string') return;
      if (c.allow_non_envelope) {
        let ok = false;
        try { ok = !!envelopeParts(hex(h)); } catch { ok = false; }
        if (!ok) { out.push({ id, label: `${c.path}#${i}`, skip: 'not an envelope (an input the verifier must ignore)' }); return; }
      }
      addEnvelopeAndPayload(`${c.path}#${i}`, hex(h), ['envelope', 'payload']);
    });
  } else if (c.check === 'json') {
    const exp = JSON.parse(fs.readFileSync(`${base}.expected.json`, 'utf8'));
    jsonPath(exp, c.path).forEach((v, i) => {
      let rule = c.rule;
      if (rule === '@result') rule = v.ok ? 'verify-ok' : 'verify-rejected';
      out.push({ id, label: `json:${c.path}#${i}`, rule, kind: 'json', bytes: JSON.stringify(v) });
    });
  } else if (c.check === 'wk-body') {
    // domain-binding fixtures: the body of the well-known answer for the domain asked about, when the
    // expected state says the document was read as valid ("listed" or "not-listed")
    const exp = JSON.parse(fs.readFileSync(`${base}.expected.json`, 'utf8'));
    const ans = exp.inputs.fixture?.well_known?.[exp.inputs.fixture.domain];
    if (['listed', 'not-listed'].includes(exp.expected.well_known) && typeof ans?.body === 'string') {
      out.push({ id, label: 'wk-body', rule: 'well-known-document', kind: 'json', bytes: ans.body });
    } else out.push({ id, label: 'wk-body', skip: `well-known state ${exp.expected.well_known}, not a valid document` });
  } else die(`unknown check '${c.check}'`);
  return out;
}

// ---- plan: the last matching case wins per (vector, label) ----
const plan = new Map();
const caseHits = map.cases.map(() => 0);
const covered = new Set();
map.cases.forEach((c, ci) => {
  if (c.expect === 'fail' && !c.reason) die(`case ${ci} (${c.select}) expects a failure and needs a reason`);
  const ms = [].concat(c.select).map(re);
  for (const vec of manifest.vectors) {
    if (!ms.some((m) => m.test(`${vec.category}/${vec.name}`))) continue;
    if (c.except && [].concat(c.except).some((x) => re(x).test(`${vec.category}/${vec.name}`))) continue;
    const items = itemsFor(vec, c);
    if (items.length) { caseHits[ci]++; covered.add(`${vec.category}/${vec.name}`); }
    for (const it of items) {
      if (c.only_label && !re(c.only_label).test(it.label)) continue;
      if (it.skip) { plan.set(`${it.id}|${it.label}`, { ...it, ci }); continue; }
      if (!it.rule) die(`${it.id} ${it.label}: no rule`);
      plan.set(`${it.id}|${it.label}`, { ...it, expect: c.expect ?? 'pass', reason: c.reason, ci });
    }
  }
});
map.cases.forEach((c, ci) => { if (!caseHits[ci]) die(`stale map: case ${ci} (${c.select}, ${c.check}) matched nothing`); });

for (const vec of manifest.vectors) {
  if (!covered.has(`${vec.category}/${vec.name}`)) die(`vector ${vec.category}/${vec.name} is not covered by any case of the map`);
}

// ---- mutation checks: derived or literal documents whose verdict is known by construction ----
// They guard against a validator that silently accepts what the schema forbids (the vectors
// alone cannot show that, because most vectors are valid) and cover the formats that have no
// vector (anchor record, well-known document, log policy, trust policy members of Draft 04).
function literal(v) {
  if (v.bstr !== undefined) return { t: 'bstr', bytes: Buffer.alloc(v.bstr, 0x11) };
  if (v.tstr !== undefined) return { t: 'tstr', v: v.tstr };
  if (v.uint !== undefined) return { t: 'uint', v: BigInt(v.uint) };
  if (v.int !== undefined) return intNode(v.int);
  if (v.bool !== undefined) return { t: 'bool', v: v.bool };
  if (v.null !== undefined) return { t: 'null' };
  if (v.array) return { t: 'array', items: v.array.map(literal) };
  if (v.map) return { t: 'map', pairs: v.map.map(([k, x]) => [typeof k === 'number' ? intNode(k) : { t: 'tstr', v: k }, literal(x)]) };
  throw new Error(`bad literal ${JSON.stringify(v)}`);
}
function descend(node, seg) {
  if (seg === 'tag') return node.inner;
  if (seg === '~') { // look inside a bstr that wraps CBOR (bstr .cbor)
    if (node.t !== 'wrapped') { node.inner = decode(Buffer.from(node.bytes)); node.t = 'wrapped'; }
    return node.inner;
  }
  if (node.t === 'array') return node.items[seg];
  const v = get(node, seg);
  if (!v) throw new Error(`mutation path: no key ${seg}`);
  return v;
}
function mutate(root, steps) {
  for (const st of steps) {
    let node = root;
    for (const seg of st.at ?? []) node = descend(node, seg);
    const isKey = (k, key) => (typeof key === 'number' ? (k.t === 'uint' || k.t === 'nint') && k.v === BigInt(key) : k.t === 'tstr' && k.v === key);
    if (st.op === 'retag') node.tag = st.tag;
    else if (st.op === 'delete') {
      if (node.t === 'array') node.items.splice(st.key, 1);
      else node.pairs = node.pairs.filter(([k]) => !isKey(k, st.key));
    } else if (st.op === 'set') {
      if (node.t === 'array') node.items[st.key] = literal(st.value);
      else { const p = node.pairs.find(([k]) => isKey(k, st.key)); if (!p) throw new Error(`mutation set: no key ${st.key}`); p[1] = literal(st.value); }
    } else if (st.op === 'add') node.pairs.push([typeof st.key === 'number' ? intNode(st.key) : { t: 'tstr', v: st.key }, literal(st.value)]);
    else if (st.op === 'append') node.items.push(literal(st.value));
    else if (st.op === 'reverse') node.items.reverse();
    else throw new Error(`unknown mutation op ${st.op}`);
  }
  return root;
}
function mutationBytes(mu) {
  if (mu.json !== undefined) return { kind: 'json', bytes: JSON.stringify(mu.json) };
  let bytes;
  if (mu.doc !== undefined) return { kind: 'cbor', bytes: encode(literal(mu.doc)) };
  const base = path.join(root, 'vectors', mu.base);
  const file = fs.readFileSync(`${base}.cbor`);
  bytes = mu.from === 'payload' ? envelopeParts(file).payload : file;
  const tree = decode(bytes);
  if (!encode(tree).equals(bytes)) die(`mutation ${mu.id}: encoder does not round-trip ${mu.base}`);
  return { kind: 'cbor', bytes: encode(mutate(tree, mu.steps ?? [])) };
}

// ---- run ----
const stats = {};
const bad = [];
const t0 = Date.now();
for (const it of plan.values()) {
  const key = it.skip ? '(skipped)' : it.rule;
  const s = (stats[key] ??= { pass: 0, failExpected: 0, skipped: 0 });
  if (listOnly) { console.log(`${it.id} ${it.label} ${it.skip ? 'SKIP ' + it.skip : `${it.rule} expect ${it.expect}`}`); continue; }
  if (it.skip) { s.skipped++; continue; }
  if (it.expect === '@ok') {
    // pass exactly when the vector's own expected result is a success
    const e = JSON.parse(fs.readFileSync(path.join(root, 'vectors', `${it.id}.expected.json`), 'utf8'));
    it.expect = e.expected.ok === true ? 'pass' : 'fail';
    it.reason = 'the vector is rejected by its expected result';
  }
  const r = run(it.rule, it.kind, it.bytes);
  if (r.ok && it.expect === 'pass') s.pass++;
  else if (!r.ok && it.expect === 'fail') { s.failExpected++; if (verbose) console.log(`expected failure ${it.id} ${it.label}: ${r.msg}`); }
  else bad.push(`${it.id} ${it.label} rule ${it.rule}: expected ${it.expect}, got ${r.ok ? 'pass' : 'fail'}${r.ok ? '' : ' (' + r.msg + ')'}`);
}
const mstats = { pass: 0, fail: 0 };
for (const mu of map.mutations ?? []) {
  const { kind, bytes } = mutationBytes(mu);
  if (listOnly) { console.log(`mutation ${mu.id} ${mu.rule} expect ${mu.expect}`); continue; }
  const r = run(mu.rule, kind, bytes);
  if (r.ok === (mu.expect === 'pass')) { mstats[mu.expect]++; if (verbose && !r.ok) console.log(`expected failure mutation ${mu.id}: ${r.msg}`); }
  else bad.push(`mutation ${mu.id} rule ${mu.rule}: expected ${mu.expect}, got ${r.ok ? 'pass' : 'fail'}${r.ok ? '' : ' (' + r.msg + ')'}`);
}
if (listOnly) process.exit(0);

console.log(`cddl ${map.validator.version}, ${plan.size} vector checks and ${(map.mutations ?? []).length} mutation checks in ${((Date.now() - t0) / 1000).toFixed(1)} s`);
console.log('rule'.padEnd(26), 'pass'.padStart(5), 'fail-by-design'.padStart(15), 'skipped'.padStart(8));
let tp = 0, tf = 0, ts = 0;
for (const [k, s] of Object.entries(stats).sort()) {
  console.log(k.padEnd(26), String(s.pass).padStart(5), String(s.failExpected).padStart(15), String(s.skipped).padStart(8));
  tp += s.pass; tf += s.failExpected; ts += s.skipped;
}
console.log('total'.padEnd(26), String(tp).padStart(5), String(tf).padStart(15), String(ts).padStart(8));
if (bad.length) {
  console.error(`\n${bad.length} mismatch(es):`);
  for (const b of bad) console.error('  ' + b);
  process.exit(1);
}
console.log(`mutation checks: ${mstats.pass} accepted as expected, ${mstats.fail} rejected as expected`);
console.log('all results as expected');
