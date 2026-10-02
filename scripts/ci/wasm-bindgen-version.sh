#!/usr/bin/env bash
# Print the wasm-bindgen crate version pinned in rust/Cargo.lock, so CI installs the
# matching wasm-bindgen CLI (the CLI and the crate must have the same version).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
v=$(awk '/^name = "wasm-bindgen"$/ { getline; gsub(/[^0-9.]/, "", $0); print; exit }' rust/Cargo.lock)
if ! [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "error: could not read wasm-bindgen version from rust/Cargo.lock (got '$v')" >&2
  exit 1
fi
echo "$v"
