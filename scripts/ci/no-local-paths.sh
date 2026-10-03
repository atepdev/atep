#!/usr/bin/env bash
# Fail if a tracked file, or a built artifact, embeds an absolute local path
# (a developer home directory, a rustup/cargo cache, a session scratch dir).
# The WebAssembly build embeds such paths in panic locations unless it is built
# with --remap-path-prefix (js/scripts/build.mjs does that).
#
# Usage: scripts/ci/no-local-paths.sh [extra file or directory ...]
#   Extra arguments (for example js/dist) are scanned in addition to the tracked
#   files. demo/vendor/atep-core is tracked, so it is always covered.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

patterns=(
  '/home/'
  '/root/'
  '/Users/'
  '/tmp/claude'
  'C:\Users'
  '.cargo/registry'
  '.rustup/toolchains'
)

# Explicit exclusions (keep this list tiny): each file below is itself a path check and so
# spells out the patterns as text; none of them embeds a real local path.
#   this script
#   the release workflow: its step that scans the built wheel for the same patterns
#   js/scripts/prepublish-check.mjs: refuses to publish a dist that contains the same patterns
excluded=(
  'scripts/ci/no-local-paths.sh'
  '.github/workflows/release.yml'
  'js/scripts/prepublish-check.mjs'
)

args=()
for p in "${patterns[@]}"; do args+=(-e "$p"); done

fail=0
scan() { # scan <file>...
  local f hit
  for f in "$@"; do
    [ -f "$f" ] || continue
    for e in "${excluded[@]}"; do [ "$f" = "$e" ] && continue 2; done
    # -a: treat binaries (the wasm) as text; -F: patterns are literal
    if hit=$(grep -a -n -o -F "${args[@]}" -- "$f" | sort -u | head -3) && [ -n "$hit" ]; then
      echo "local path in $f:"
      echo "$hit" | sed 's/^/    /'
      fail=1
    fi
  done
}

mapfile -d '' tracked < <(git ls-files -z)
scan "${tracked[@]}"

for extra in "$@"; do
  if [ -d "$extra" ]; then
    mapfile -d '' found < <(find "$extra" -type f -print0)
    scan "${found[@]}"
  elif [ -f "$extra" ]; then
    scan "$extra"
  else
    echo "error: $extra does not exist (build first?)" >&2
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "error: absolute local paths found (see above)" >&2
  exit 1
fi
echo "no local paths found"
