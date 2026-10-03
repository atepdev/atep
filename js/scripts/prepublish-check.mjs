// Guard run before `npm pack` and `npm publish` (prepack, prepublishOnly): the
// package must never ship without a built dist, or with a build that embeds a
// local machine path (the WebAssembly build keeps panic locations, so a build
// without --remap-path-prefix would leak one; scripts/build.mjs remaps them).
//
// This is the same pattern list as scripts/ci/no-local-paths.sh, applied to
// dist/ only, so it also works outside a git checkout.
import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const dist = join(root, "dist");

const required = ["index.js", "index.d.ts", "wasm/atep_wasm_bg.wasm"];
const patterns = ["/home/", "/root/", "/Users/", "/tmp/claude", "C:\\Users", ".cargo/registry", ".rustup/toolchains"];

const problems = [];
for (const f of required) {
  if (!existsSync(join(dist, f))) problems.push(`dist/${f} is missing: run "npm run build" first`);
}

function* walk(dir) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) yield* walk(p);
    else yield p;
  }
}

if (existsSync(dist)) {
  for (const file of walk(dist)) {
    const text = readFileSync(file).toString("latin1");
    for (const p of patterns) {
      if (text.includes(p)) problems.push(`local path pattern "${p}" in ${file.slice(root.length + 1)}`);
    }
  }
}

if (problems.length) {
  console.error("prepublish check failed:");
  for (const p of problems) console.error("  " + p);
  process.exit(1);
}
console.log("prepublish check: dist is built and free of local paths");
