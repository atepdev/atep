// Smoke test for the packed npm tarballs, run against a project that installed them:
//
//   mkdir smoke && cd smoke && npm init -y
//   npm install ../atep-core-*.tgz ../atep-mcp-*.tgz
//   node <repo>/scripts/release/smoke-npm.mjs <path to the project> <path to vectors/>
//
// 1. Verifies a positive and a negative vector with the installed @atep/core.
// 2. Starts the installed atep-mcp over stdio with the MCP client SDK and lists its tools.
//
// Packages are resolved from the project, never from the repository.
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import assert from "node:assert/strict";

const [projectArg, vectorsArg] = process.argv.slice(2);
if (!projectArg || !vectorsArg) {
  console.error("usage: node smoke-npm.mjs <project dir> <vectors dir>");
  process.exit(2);
}
const project = resolve(projectArg);
const vectors = resolve(vectorsArg);
const req = createRequire(join(project, "package.json"));
const load = (spec) => import(pathToFileURL(req.resolve(spec)).href);

const core = await load("@atep/core");
await core.init();

function check(name, expectOk, step) {
  const cbor = readFileSync(join(vectors, `${name}.cbor`));
  const exp = JSON.parse(readFileSync(join(vectors, `${name}.expected.json`), "utf8"));
  const policy = exp.inputs.policy;
  const r = core.verify(cbor, policy, { now: policy.now });
  assert.equal(r.ok, expectOk, `${name}: ${JSON.stringify(r)}`);
  if (!expectOk) assert.equal(r.step, step, `${name}: step`);
  console.log(`@atep/core verify ${name}: ${r.ok ? "OK, signer " + r.signer : "REJECTED at step " + r.step + " (" + r.error + ")"}`);
}
check("verify-positive/signed-trust-doc-inline-bundle", true);
check("verify-negative/bad-eddsa-signature", false, 4);

const { Client } = await load("@modelcontextprotocol/sdk/client/index.js");
const { StdioClientTransport } = await load("@modelcontextprotocol/sdk/client/stdio.js");
const transport = new StdioClientTransport({ command: process.execPath, args: [req.resolve("@atep/mcp/package.json").replace(/package\.json$/, "bin/atep-mcp.mjs")], cwd: project });
const client = new Client({ name: "atep-smoke", version: "0.0.0" });
await client.connect(transport);
const { tools } = await client.listTools();
const names = tools.map((t) => t.name).sort();
console.log(`atep-mcp tools (${names.length}): ${names.join(", ")}`);
for (const want of ["atep_verify", "atep_inspect", "atep_lookup_agent", "atep_lookup_issuer", "atep_resolve_claim", "atep_check_revocation"]) {
  assert.ok(names.includes(want), `missing tool ${want}`);
}
await client.close();
console.log("npm smoke test passed");
