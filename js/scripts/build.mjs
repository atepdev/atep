// Build @atep/core: cargo (wasm32) -> wasm-bindgen -> tsc -> dist/.
//
// Needs: rustup target wasm32-unknown-unknown, wasm-bindgen-cli matching the
// wasm-bindgen version in rust/Cargo.lock (checked below; set WASM_BINDGEN=/path/to/wasm-bindgen if
// it is not on PATH). Optional: wasm-opt on PATH shrinks the binary further.
import { execFileSync, spawnSync } from "node:child_process";
import { cpSync, mkdirSync, rmSync, statSync, existsSync, readFileSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const repo = resolve(root, "..");
const rust = resolve(repo, "rust");
const run = (cmd, args, opts = {}) => {
  console.log("+", cmd, args.join(" "));
  execFileSync(cmd, args, { stdio: "inherit", ...opts });
};

// ---- Preflight: fail with an actionable message instead of a raw ENOENT ----
const wbgBin = process.env.WASM_BINDGEN ?? "wasm-bindgen";

function wantedWbgVersion() {
  const lock = readFileSync(join(rust, "Cargo.lock"), "utf8");
  const m = /\[\[package\]\]\nname = "wasm-bindgen"\nversion = "([0-9]+\.[0-9]+\.[0-9]+)"/.exec(lock);
  if (!m) fail(`could not read the wasm-bindgen version from ${join(rust, "Cargo.lock")}`);
  return m[1];
}

function fail(msg, hints = []) {
  console.error(`\nerror: ${msg}`);
  for (const h of hints) console.error(`  ${h}`);
  console.error("\nSee js/README.md, section \"Install and build\".");
  process.exit(1);
}

function preflight() {
  const want = wantedWbgVersion();
  const installHints = [
    "rustup target add wasm32-unknown-unknown",
    `cargo install wasm-bindgen-cli --version ${want} --locked --no-default-features`,
    "(--no-default-features needs no C compiler; the default-features form builds ring, which needs one.)",
    "If the CLI is installed outside PATH, set WASM_BINDGEN=/path/to/wasm-bindgen.",
  ];
  const cargo = spawnSync("cargo", ["--version"], { encoding: "utf8" });
  if (cargo.error || cargo.status !== 0) {
    fail("cargo was not found on PATH. Install Rust from https://rustup.rs first.");
  }
  const problems = [];
  const libdir = spawnSync("rustc", ["--print", "target-libdir", "--target", "wasm32-unknown-unknown"], { encoding: "utf8" });
  const libOk = !libdir.error && libdir.status === 0 && existsSync(libdir.stdout.trim()) && readdirSync(libdir.stdout.trim()).length > 0;
  if (!libOk) problems.push("the wasm32-unknown-unknown target is not installed: run `rustup target add wasm32-unknown-unknown`");
  const wbg = spawnSync(wbgBin, ["--version"], { encoding: "utf8" });
  if (wbg.error || wbg.status !== 0) {
    problems.push(`wasm-bindgen (${wbgBin}) was not found or did not run`);
  } else {
    const have = /([0-9]+\.[0-9]+\.[0-9]+)/.exec(wbg.stdout)?.[1];
    if (have !== want) {
      fail(
        `wasm-bindgen CLI version mismatch: found ${have ?? wbg.stdout.trim()}, but rust/Cargo.lock pins the wasm-bindgen crate at ${want}. The CLI and the crate must match exactly.`,
        [`cargo install wasm-bindgen-cli --version ${want} --locked --no-default-features --force`],
      );
    }
  }
  if (problems.length) fail(`missing build prerequisites:\n  - ${problems.join("\n  - ")}`, ["", "Install commands:", ...installHints]);
}
preflight();

// ---- Keep absolute local paths out of the binary (panic locations embed them) ----
const sysroot = execFileSync("rustc", ["--print", "sysroot"], { encoding: "utf8" }).trim();
const cargoHome = process.env.CARGO_HOME ?? join(homedir(), ".cargo");
const remap = [
  [cargoHome, "/cargo"],
  [sysroot, "/rustup-toolchain"],
  [repo, "/atep"],
].map(([from, to]) => `--remap-path-prefix=${from}=${to}`);
const rustflags = [process.env.RUSTFLAGS, ...remap, "-C", "debuginfo=0"].filter(Boolean).join(" ");

const env = {
  ...process.env,
  RUSTFLAGS: rustflags,
  CARGO_PROFILE_RELEASE_LTO: "true",
  CARGO_PROFILE_RELEASE_CODEGEN_UNITS: "1",
  CARGO_PROFILE_RELEASE_PANIC: "abort",
  CARGO_PROFILE_RELEASE_STRIP: "symbols",
  CARGO_PROFILE_RELEASE_DEBUG: "false",
  CARGO_PROFILE_RELEASE_OPT_LEVEL: process.env.ATEP_WASM_OPT_LEVEL ?? "3",
};
run("cargo", ["build", "-p", "atep-wasm", "--target", "wasm32-unknown-unknown", "--release"], { cwd: rust, env });

const wasmIn = join(rust, "target/wasm32-unknown-unknown/release/atep_wasm.wasm");
const gen = join(root, "src/wasm");
rmSync(gen, { recursive: true, force: true });
mkdirSync(gen, { recursive: true });
run(wbgBin, ["--target", "web", "--remove-name-section", "--remove-producers-section", "--out-dir", gen, wasmIn]);

const opt = spawnSync("wasm-opt", ["--version"]);
if (opt.status === 0) {
  const f = join(gen, "atep_wasm_bg.wasm");
  run("wasm-opt", ["-O3", "--all-features", f, "-o", f]);
}

rmSync(join(root, "dist"), { recursive: true, force: true });
// With npm workspaces (the root package.json) the dependencies are hoisted to the
// repository root; a standalone install keeps them in js/node_modules.
const tsc = [join(root, "node_modules/.bin/tsc"), join(repo, "node_modules/.bin/tsc")].find((p) => existsSync(p));
if (!tsc) fail("tsc was not found", ["Run `npm ci` (in the repository root or in js/) first."]);
run(tsc, ["-p", "tsconfig.json"], { cwd: root });
cpSync(gen, join(root, "dist/wasm"), { recursive: true });
const size = statSync(join(root, "dist/wasm/atep_wasm_bg.wasm")).size;
console.log(`wasm binary: ${size} bytes (${(size / 1024).toFixed(0)} KiB)`);
