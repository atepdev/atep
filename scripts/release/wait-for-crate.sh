#!/usr/bin/env bash
# wait-for-crate.sh <crate> <version> [max seconds, default 900]
# Poll the sparse index until the version shows up (a dependent crate cannot be
# published before that).
set -euo pipefail
here=$(dirname "$0")
name=$1 version=$2 max=${3:-900}
start=$(date +%s)
while :; do
  if "$here/crate-published.sh" "$name" "$version"; then
    echo "$name $version is in the crates.io index"
    exit 0
  fi
  if [ $(( $(date +%s) - start )) -ge "$max" ]; then
    echo "error: $name $version did not appear in the index within ${max}s" >&2
    exit 1
  fi
  sleep 15
done
