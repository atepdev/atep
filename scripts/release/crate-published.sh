#!/usr/bin/env bash
# crate-published.sh <crate> <version>
# Exit 0 if the version is in the crates.io sparse index, 1 if not (2 on a lookup error).
set -euo pipefail
name=$1 version=$2
case ${#name} in
  1) path="1/$name" ;;
  2) path="2/$name" ;;
  3) path="3/${name:0:1}/$name" ;;
  *) path="${name:0:2}/${name:2:2}/$name" ;;
esac
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
code=$(curl -sS -o "$tmp" -w '%{http_code}' -H 'Cache-Control: no-cache' "https://index.crates.io/$path") || exit 2
if [ "$code" = 404 ]; then exit 1; fi
[ "$code" = 200 ] || { echo "index lookup for $name returned HTTP $code" >&2; exit 2; }
grep -q "\"vers\":\"$version\"" "$tmp"
