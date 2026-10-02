// Generates the claim-type pages of https://atep.dev/claims/ into site/atep.dev/claims/.
//
//   node site/build-claims.mjs           write the files
//   node site/build-claims.mjs --check   fail (exit 1) when the committed files are stale or incomplete
//
// Source: rust/atep-log/data/claims.json (the definitions the reference log serves), checked against the CDDL rules in
// spec/schemas/atep.cddl. The output is committed because Heroku deploys only site/. No dependencies, Node 18 or later.
//
// Output: claims/index.html and claims/index.json, and for every claim <name> (core claims) or robotics/<name>:
// claims/<name>.html and claims/<name>.json. The JSON mirrors what the reference log returns for GET /v1/claims/<claim>
// (rust/docs/log-api.md); the only difference is `links`: the log's `api` member is left out because this host has no
// /v1 routes, `directory` is /claims/ here, and a `json` member is added (clients ignore unknown members).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.join(here, "..");
const outDir = path.join(here, "atep.dev", "claims");
const check = process.argv.includes("--check");

const data = JSON.parse(fs.readFileSync(path.join(repo, "rust/atep-log/data/claims.json"), "utf8"));
const NS = data.namespace; // https://atep.dev/claims/
const SPEC_GH = "https://github.com/atepdev/atep/blob/main/spec/ATEP-Specification-Draft-07.md";
const GH_VECTORS = "https://github.com/atepdev/atep/tree/main/vectors/";
const OG_IMAGE = "https://atep.dev/assets/og-card.jpg";

// Vector categories that exercise a claim without naming its URI inside the vector files.
const VECTOR_SUPPLEMENT = { "domain-control": ["domain-binding"] };

const claims = data.claims.map((c) => ({ ...c, uri: NS + c.name }));
if (claims.length === 0) throw new Error("claims.json has no claims");
const failures = [];

// ---------------------------------------------------------------- CDDL cross-check
// A rule that a claim carries and atep.cddl also defines must have the same body (comments and spacing ignored).
function ruleBodies(text) {
  const rules = new Map();
  let cur = null;
  for (const raw of text.split("\n")) {
    const line = raw.replace(/;.*$/, "").trimEnd();
    const m = /^([A-Za-z][\w-]*)\s*=\s*(.*)$/.exec(line);
    if (m) { cur = m[1]; rules.set(cur, m[2]); }
    else if (cur && /^\s+\S/.test(line)) rules.set(cur, rules.get(cur) + " " + line.trim());
    else if (line.trim() === "") cur = null;
  }
  for (const [k, v] of rules) rules.set(k, v.replace(/\s+/g, " ").trim());
  return rules;
}
const specRules = ruleBodies(fs.readFileSync(path.join(repo, "spec/schemas/atep.cddl"), "utf8"));
let shared = 0;
for (const c of claims) {
  const own = ruleBodies(c["data-schema"]);
  if (own.size === 0) failures.push(`${c.name}: data-schema has no CDDL rule`);
  const main = [...own.keys()][0];
  if (!/-data$/.test(main || "")) failures.push(`${c.name}: first CDDL rule ${main} is not a *-data rule`);
  for (const [k, v] of own) {
    if (!specRules.has(k)) continue;
    shared++;
    if (specRules.get(k) !== v) failures.push(`${c.name}: CDDL rule ${k} differs from spec/schemas/atep.cddl`);
  }
}

// ---------------------------------------------------------------- vector categories
const vectorsDir = path.join(repo, "vectors");
const vecDirs = fs.existsSync(vectorsDir) ? fs.readdirSync(vectorsDir).filter((d) => fs.statSync(path.join(vectorsDir, d)).isDirectory()).sort() : [];
const isTokenChar = (b) => b !== undefined && ((b >= 97 && b <= 122) || (b >= 48 && b <= 57) || b === 45);
function hasToken(buf, needle, boundaryBefore) {
  let i = -1;
  while ((i = buf.indexOf(needle, i + 1)) >= 0) {
    const before = buf[i - 1];
    const okBefore = !boundaryBefore || !(isTokenChar(before) || before === 47);
    if (okBefore && !isTokenChar(buf[i + needle.length])) return true;
  }
  return false;
}
const vecFiles = {};
for (const d of vecDirs) {
  vecFiles[d] = fs.readdirSync(path.join(vectorsDir, d))
    .filter((f) => /\.(cbor|json)$/.test(f))
    .sort()
    .map((f) => ({ f, buf: fs.readFileSync(path.join(vectorsDir, d, f)) }));
}
function vectorCategories(c) {
  const uri = Buffer.from(c.uri);
  const short = c.name.split("/").pop();
  const shortNeedle = Buffer.from(short);
  const ticked = Buffer.from("`" + short + "`");
  const found = new Set(VECTOR_SUPPLEMENT[c.name] || []);
  for (const d of vecDirs) {
    for (const { f, buf } of vecFiles[d]) {
      // The URI as a whole, a backticked short name in a description, or (for hyphenated names) the bare short name.
      if (hasToken(buf, uri, false) || buf.includes(ticked) || (short.includes("-") && hasToken(buf, shortNeedle, true))) { found.add(d); break; }
    }
  }
  return [...found].filter((d) => vecDirs.includes(d)).sort();
}

// ---------------------------------------------------------------- helpers
const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const ld = (o) => JSON.stringify(o, null, 2).replace(/</g, "\\u003c");
const pct = (s) => [...Buffer.from(s)].map((b) => (/[A-Za-z0-9\-._~]/.test(String.fromCharCode(b)) ? String.fromCharCode(b) : "%" + b.toString(16).toUpperCase().padStart(2, "0"))).join("");
const urlOf = (c) => `/claims/${c.name}`;
const isRobotics = (c) => c.profile === "robotics";
const hasHex = (v) => JSON.stringify(v).includes('"$hex"');
const SET_ID = NS; // https://atep.dev/claims/

const NAV = [
  ["/", "Overview"], ["/in-practice.html", "In practice"], ["/specification.html", "Specification"], ["/claims/", "Claims"], ["/demo/", "Demo"], ["/quickstart.html", "Quick start"],
  ["/vectors.html", "Test vectors"], ["/governance.html", "Governance"], ["/security.html", "Security"], ["/about.html", "About"], ["/llms.txt", "llms.txt"],
];

function page({ title, description, canonical, jsonld, body, current, alternate }) {
  const nav = NAV.map(([h, t]) => `      <a href="${h}"${h === "/claims/" ? ` aria-current="${current}"` : ""}>${t}</a>`).join("\n");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<meta name="description" content="${esc(description)}">
<link rel="canonical" href="${canonical}">
${alternate ? `<link rel="alternate" type="application/json" href="${alternate}">\n` : ""}<link rel="stylesheet" href="/style.css">
<script src="/theme-boot.js"></script>
<meta name="theme-color" content="#0c0d0f">
<link rel="icon" href="/assets/favicon.svg" type="image/svg+xml">
<link rel="icon" href="/assets/favicon-32.png" type="image/png" sizes="32x32">
<link rel="apple-touch-icon" href="/assets/apple-touch-icon.png">
<meta property="og:type" content="website">
<meta property="og:site_name" content="ATEP">
<meta property="og:title" content="${esc(title)}">
<meta property="og:description" content="${esc(description)}">
<meta property="og:url" content="${canonical}">
<meta property="og:image" content="${OG_IMAGE}">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:alt" content="ATEP">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${esc(title)}">
<meta name="twitter:description" content="${esc(description)}">
<meta name="twitter:image" content="${OG_IMAGE}">
<script type="application/ld+json">
${ld(jsonld)}
</script>
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header class="site">
  <a class="brand" href="/"><img src="/assets/atep-wordmark.jpg" alt="ATEP" width="970" height="340"></a>
  <nav aria-label="Main">
${nav}
  </nav>
  <button id="theme" type="button">Use dark theme</button>
</header>
<main id="main">
${body}
</main>
<footer class="site">
  <p>ATEP is an open protocol. The specification is licensed CC BY 4.0 and the reference code Apache-2.0. Stewarded by AIRAD LABS (<a href="/about.html">about</a>). Source: <a href="https://github.com/atepdev/atep">github.com/atepdev/atep</a>.</p>
</footer>
<script src="/site.js"></script>
</body>
</html>
`;
}

const termSet = { "@type": "DefinedTermSet", "@id": SET_ID, name: "ATEP claim types", url: SET_ID };
const term = (c) => ({
  "@type": "DefinedTerm", "@id": c.uri, url: c.uri, name: c.title, termCode: c.name, description: c.summary, inDefinedTermSet: SET_ID,
});

// ---------------------------------------------------------------- JSON documents (mirror of the log's resolver)
// Public draft numbering starts at Draft 07; the data file cites the internal drafts where a rule was introduced.
const specRef = (t) => t.replace(/Draft 0\d section/g, "Specification section");
function definitionJson(c) {
  return {
    claim: c.uri, name: c.name, core: c.status === "core", status: c.status, profile: c.profile, definition: c.summary,
    "data-schema": c["data-schema"], title: c.title, description: c.description, "issued-by": c["issued-by"], subject: c.subject,
    "data-schema-format": "cddl", "attestation-schema": data["attestation-schema"], "data-checked-by": c["data-checked-by"],
    evidence: c.evidence, lifetime: c.lifetime, spec: c.spec.map(specRef), "example-data": c["example-data"],
    links: { self: urlOf(c), html: `${urlOf(c)}.html`, json: `${urlOf(c)}.json`, directory: "/claims/" },
  };
}
function indexJson() {
  return {
    namespace: NS,
    claims: claims.map((c) => ({
      claim: c.uri, name: c.name, core: c.status === "core", status: c.status, profile: c.profile, definition: c.summary, title: c.title, url: c.uri,
    })),
  };
}

// ---------------------------------------------------------------- HTML pages
function lifetimeNotes(c) {
  const notes = [`<p><strong>${esc(c.lifetime)}.</strong></p>`];
  if (/audit-backed/.test(c.lifetime) || c.evidence === "required") {
    notes.push("<p>This claim is audit-backed: the attestation must carry an <code>evidence</code> hash, and audit-backed attestations may live up to 400 days because audits are commonly annual. The issuer still publishes a revocation through its signed revocation list if the underlying audit is withdrawn.</p>");
  } else {
    notes.push("<p>Attestations are short-lived. Issuers should keep them to 180 days with automatic re-issuance; the 180 day default is enforced by issuing tools only. A verifier rejects any attestation whose <code>expires-at</code> minus <code>issued-at</code> exceeds 400 days (<code>attestation_lifetime_exceeded</code>); exactly 400 days is allowed. An attestation of any type that carries <code>evidence</code> counts as audit-backed.</p>");
  }
  return notes.join("\n");
}

function claimPage(c) {
  const cats = vectorCategories(c);
  const robotics = isRobotics(c);
  const title = `${c.title} (ATEP claim type)`;
  const crumbs = `<nav class="crumbs" aria-label="Breadcrumb"><a href="/claims/">Claims</a> / ${robotics ? "robotics / " : ""}${esc(c.name.split("/").pop())}</nav>`;
  const rows = [
    ["Claim URI", `<code>${esc(c.uri)}</code>`],
    ["Group", robotics ? "Robotics profile (ATEP-R)" : "Core"],
    ["Status", esc(c.status)],
    ["Issued by", esc(c["issued-by"])],
    ["Subject", esc(c.subject)],
    ["Evidence", esc(c.evidence)],
    ["Lifetime", esc(c.lifetime)],
    ["Data checked by", esc(c["data-checked-by"])],
  ].map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("\n");
  const ex = JSON.stringify(c["example-data"], null, 2);
  const body = `${crumbs}
<h1>${esc(c.title)}</h1>
<p class="uri"><code>${esc(c.uri)}</code> <span class="badge">${esc(c.status)}</span></p>
<p class="lead">${esc(c.summary)}</p>
<section class="blk" aria-labelledby="def"><h2 id="def">Definition</h2>
${c.description.map((p) => `<p>${esc(p)}</p>`).join("\n")}
</section>
<section class="blk" aria-labelledby="facts"><h2 id="facts">Who issues it and what it asserts</h2>
<dl class="kv">
${rows}
</dl>
</section>
<section class="blk" aria-labelledby="data"><h2 id="data">The <code>data</code> layout</h2>
<p>CDDL (RFC 8610) schema of the <code>data</code> map of an attestation with this claim:</p>
<pre><code>${esc(c["data-schema"])}</code></pre>
<p>Example <code>data</code> in JSON form${hasHex(c["example-data"]) ? ` (<code>{"$hex": ...}</code> stands for a byte string)` : ""}:</p>
<pre><code>${esc(ex)}</code></pre>
<p>The whole attestation payload around <code>data</code>:</p>
<pre><code>${esc(data["attestation-schema"])}</code></pre>
</section>
<section class="blk" aria-labelledby="life"><h2 id="life">Lifetime</h2>
${lifetimeNotes(c)}
</section>
<section class="blk" aria-labelledby="refs"><h2 id="refs">Specification</h2>
<ul>
${c.spec.map((s) => `<li>${esc(specRef(s))}</li>`).join("\n")}
</ul>
<p>Read the specification in the <a href="/specification.html">section map</a>, as one Markdown file (<a href="/llms-full.txt">llms-full.txt</a>) or <a href="${SPEC_GH}">on GitHub</a>. Section numbers follow Draft 07.</p>
</section>
<section class="blk" aria-labelledby="vec"><h2 id="vec">Test vectors</h2>
${cats.length
    ? `<p>Vector categories that exercise this claim: ${cats.map((d) => `<a href="${GH_VECTORS}${d}"><code>${d}</code></a>`).join(", ")}. See <a href="/vectors.html">test vectors</a>.</p>`
    : `<p>No vector category exercises this claim type on its own. See <a href="/vectors.html">test vectors</a> for the suite as a whole.</p>`}
</section>
<section class="blk" aria-labelledby="mr"><h2 id="mr">Machine-readable</h2>
<p>This definition as JSON: <a href="${urlOf(c)}.json"><code>${urlOf(c)}.json</code></a>, or request <code>${esc(c.uri)}</code> with <code>Accept: application/json</code>. The reference transparency log serves the same document at <code>/v1/claims/&lt;claim&gt;</code>. <a href="/claims/">All claim types</a>.</p>
</section>`;
  return page({
    title, description: c.summary, canonical: c.uri, current: "true", alternate: `${c.uri}.json`, body,
    jsonld: { "@context": "https://schema.org", ...term(c), inDefinedTermSet: termSet },
  });
}

function indexPage() {
  const groups = [
    ["core", "Core claims", claims.filter((c) => !isRobotics(c))],
    ["robotics", "Robotics claims (ATEP-R)", claims.filter(isRobotics)],
  ];
  const table = ([id, label, list]) => `<section class="blk" aria-labelledby="g-${id}"><h2 id="g-${id}">${label}</h2>
<div class="tablewrap"><table class="claimtable">
<caption>${list.length} claim types</caption>
<thead><tr><th scope="col">Claim</th><th scope="col">Status</th><th scope="col">Definition</th><th scope="col">Issued by</th></tr></thead>
<tbody>
${list.map((c) => `<tr><th scope="row"><a href="${urlOf(c)}"><code>${esc(c.name)}</code></a></th><td>${esc(c.status)}</td><td>${esc(c.summary)}</td><td>${esc(c["issued-by"])}</td></tr>`).join("\n")}
</tbody></table></div>
</section>`;
  const body = `<h1>Claim types</h1>
<p class="uri"><code>${NS}</code></p>
<p class="lead">An ATEP attestation names what it asserts with a claim type, a URI. ATEP reserves <code>${NS}</code> for a closed core set of ${claims.length} claim types, listed here: seven core claim types and the seven of the robotics profile (ATEP-R). Each URI resolves to a definition, who issues it, the CDDL schema of <code>data</code>, and the evidence and lifetime rules. Anyone may use their own namespace for other claim types.</p>
<div class="note"><p>Fetch a claim URI with a browser for the page, with <code>Accept: application/json</code> for the JSON document, or add <code>.json</code> or <code>.html</code> to the path. The directory itself is also available as <a href="/claims/index.json"><code>/claims/index.json</code></a>. Robotics claim types live under <code>/claims/robotics/</code>. Sections 7 and 17 of the <a href="/specification.html">specification</a> define the vocabulary.</p></div>
${groups.map(table).join("\n")}`;
  return page({
    title: "ATEP claim types", description: `The ${claims.length} core claim types of ATEP under ${NS}: definitions, who issues them, the CDDL schema of data, and lifetimes.`,
    canonical: NS, current: "page", alternate: `${NS}index.json`, body,
    jsonld: { "@context": "https://schema.org", ...termSet, description: "The closed core vocabulary of ATEP claim types.", hasDefinedTerm: claims.map(term) },
  });
}

// ---------------------------------------------------------------- write or check
const out = new Map();
out.set("index.html", indexPage());
out.set("index.json", JSON.stringify(indexJson(), null, 2) + "\n");
for (const c of claims) {
  out.set(`${c.name}.html`, claimPage(c));
  out.set(`${c.name}.json`, JSON.stringify(definitionJson(c), null, 2) + "\n");
}
const BAD = [String.fromCharCode(0x2014), String.fromCharCode(0x2013)];
for (const [f, text] of out) if (BAD.some((b) => text.includes(b))) failures.push(`${f}: contains an em or en dash (fix the source or the generator)`);

function existing(dir, base = "") {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? existing(path.join(dir, e.name), base + e.name + "/") : [base + e.name]));
}
const have = existing(outDir);
if (failures.length) { console.error(failures.map((f) => "FAIL " + f).join("\n")); process.exit(1); }

if (check) {
  const stale = [];
  for (const [f, text] of out) {
    const p = path.join(outDir, f);
    if (!fs.existsSync(p) || fs.readFileSync(p, "utf8") !== text) stale.push(`atep.dev/claims/${f} is missing or out of date`);
  }
  for (const f of have) if (!out.has(f)) stale.push(`atep.dev/claims/${f} is not generated (extra file)`);
  if (stale.length) { console.error(stale.map((s) => "FAIL " + s).join("\n") + "\nrun: node site/build-claims.mjs"); process.exit(1); }
  console.log(`claims up to date: ${claims.length} claims, ${out.size} files (${shared} CDDL rules shared with atep.cddl match)`);
} else {
  for (const f of have) if (!out.has(f)) fs.rmSync(path.join(outDir, f));
  for (const [f, text] of out) {
    const p = path.join(outDir, f);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, text);
  }
  console.log(`wrote ${out.size} files for ${claims.length} claims to site/atep.dev/claims/ (${shared} CDDL rules shared with atep.cddl match)`);
}
