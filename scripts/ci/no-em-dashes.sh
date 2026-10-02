#!/usr/bin/env bash
# Fail if any tracked text file contains an em dash (U+2014).
# Excludes node_modules, vendor directories, wasm and other binary files.
# Usage: scripts/ci/no-em-dashes.sh   (run from anywhere inside the repository)
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

found=0
while IFS= read -r -d '' f; do
  case "$f" in
    */node_modules/*|node_modules/*|*/vendor/*|vendor/*|*.wasm) continue ;;
  esac
  [ -f "$f" ] || continue
  # -I skips binary files, -n prints line numbers, -H the file name.
  if grep -InH -- $'\xe2\x80\x94' "$f"; then
    found=1
  fi
done < <(git ls-files -z)

if [ "$found" -ne 0 ]; then
  echo "error: em dash (U+2014) found in the files above; use a comma, colon, period or parentheses" >&2
  exit 1
fi
echo "no em dashes found"
