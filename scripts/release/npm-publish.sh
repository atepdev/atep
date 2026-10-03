#!/usr/bin/env bash
# Publish the packed npm tarballs, or rehearse it. Used by BOTH the dry-run job and the
# publish job of .github/workflows/release.yml, so the two cannot drift apart.
#
# Usage: scripts/release/npm-publish.sh <tarball dir> <version> <dist-tag> [--dry-run]
#
# Tarballs are always passed to npm as absolute paths. A relative path of the form
# "dir/file.tgz" (two segments, no leading ./) is read by npm as GitHub shorthand
# ("owner/repo") and makes it run `git ls-remote ssh://git@github.com/...`, which fails.
#
# A real run publishes with provenance (needs the GitHub OIDC token of the publish job),
# skips a package version that is already on the registry, and waits until @atep/core is
# visible before publishing @atep/mcp (which depends on it). A dry run publishes nothing
# and omits --provenance, which only works inside the publish job.
set -euo pipefail

if [ "$#" -lt 3 ]; then
  echo "usage: $0 <tarball dir> <version> <dist-tag> [--dry-run]" >&2
  exit 2
fi
dir=$(cd "$1" && pwd)
version=$2
tag=$3
dry=${4:-}

if [ -f "$dir/SHA256SUMS" ]; then
  (cd "$dir" && sha256sum -c SHA256SUMS)
fi

for pkg in core mcp; do
  name="@atep/$pkg"
  file="$dir/atep-$pkg-$version.tgz"
  if [ ! -f "$file" ]; then
    echo "error: missing tarball $file" >&2
    exit 1
  fi
  if [ -n "$dry" ]; then
    npm publish --dry-run --access public --tag "$tag" "$file"
    continue
  fi
  if [ "$(npm view "$name@$version" version 2>/dev/null || true)" = "$version" ]; then
    echo "::notice::$name@$version is already on npm, skipping"
    continue
  fi
  npm publish --provenance --access public --tag "$tag" "$file"
  # @atep/mcp resolves @atep/core from the registry, so wait for it to be visible
  for _ in $(seq 1 30); do
    [ "$(npm view "$name@$version" version 2>/dev/null || true)" = "$version" ] && break
    sleep 10
  done
done
