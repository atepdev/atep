#!/usr/bin/env bash
# Check that every release version in the repository agrees, and (optionally) that a
# git tag names it.
#
# Usage:
#   scripts/release/check-versions.sh                 consistency only
#   scripts/release/check-versions.sh v0.1.0-alpha.2  also require the tag to match
#   scripts/release/check-versions.sh --npm-tag       print the npm dist-tag for this version
#   scripts/release/check-versions.sh --pypi-version  print the PEP 440 version
#
# The version scheme is SemVer for crates.io and npm (0.1.0-alpha.2) and its PEP 440
# spelling for PyPI (0.1.0a2). Mapping: -alpha.N -> aN, -beta.N -> bN, -rc.N -> rcN.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

fail=0
err() { echo "error: $*" >&2; fail=1; }

# crates: [workspace.package] version of rust/Cargo.toml
crate_v=$(awk '/^\[workspace\.package\]/{f=1;next} /^\[/{f=0} f && /^version *=/{gsub(/[" ]/,"",$0); sub(/^version=/,"",$0); print; exit}' rust/Cargo.toml)
[ -n "$crate_v" ] || { echo "error: no [workspace.package] version in rust/Cargo.toml" >&2; exit 1; }

js_v=$(node -p 'require("./js/package.json").version')
mcp_v=$(node -p 'require("./mcp/package.json").version')
mcp_dep=$(node -p 'require("./mcp/package.json").dependencies["@atep/core"]')
py_v=$(sed -n 's/^version *= *"\(.*\)"/\1/p' python/pyproject.toml | head -n 1)
py_init=$(sed -n 's/^__version__ *= *"\(.*\)"/\1/p' python/atep_py/__init__.py)

# SemVer -> PEP 440
pep440() {
  local v=$1 base pre
  case "$v" in
    *-*) base=${v%%-*}; pre=${v#*-}
         case "$pre" in
           alpha.*) echo "${base}a${pre#alpha.}" ;;
           beta.*)  echo "${base}b${pre#beta.}" ;;
           rc.*)    echo "${base}rc${pre#rc.}" ;;
           *) echo "error: unsupported prerelease '$pre' (use alpha.N, beta.N or rc.N)" >&2; return 1 ;;
         esac ;;
    *) echo "$v" ;;
  esac
}

want_py=$(pep440 "$crate_v") || exit 1

case "${1:-}" in
  --npm-tag)
    case "$crate_v" in
      *-*) pre=${crate_v#*-}; echo "${pre%%.*}" ;;
      *)   echo latest ;;
    esac
    exit 0 ;;
  --pypi-version) echo "$want_py"; exit 0 ;;
esac

[ "$js_v" = "$crate_v" ]  || err "js/package.json is $js_v, rust/Cargo.toml is $crate_v"
[ "$mcp_v" = "$crate_v" ] || err "mcp/package.json is $mcp_v, rust/Cargo.toml is $crate_v"
[ "$py_v" = "$want_py" ]  || err "python/pyproject.toml is $py_v, expected $want_py (PEP 440 form of $crate_v)"
[ "$py_init" = "$want_py" ] || err "python/atep_py/__init__.py __version__ is $py_init, expected $want_py"

# internal dependencies must be satisfied by this version
for f in rust/atep-cli/Cargo.toml rust/atep/Cargo.toml rust/atep-log/Cargo.toml rust/atep-monitor/Cargo.toml rust/atep-wasm/Cargo.toml; do
  d=$(sed -n 's/^atep-\(core\|log\) *= *{ *version *= *"\([^"]*\)".*/\2/p' "$f" | sort -u)
  for x in $d; do [ "$x" = "$crate_v" ] || err "$f depends on an atep crate at $x, expected $crate_v"; done
done
[ "$mcp_dep" = "^$crate_v" ] || err "mcp/package.json depends on @atep/core $mcp_dep, expected ^$crate_v"

if [ -n "${1:-}" ]; then
  tag=$1
  [ "$tag" = "v$crate_v" ] || err "tag is $tag, the versions say v$crate_v"
fi

if [ "$fail" -ne 0 ]; then exit 1; fi
echo "versions agree: crates and npm $crate_v, PyPI $want_py, npm dist-tag $("$0" --npm-tag)${1:+, tag $1}"
