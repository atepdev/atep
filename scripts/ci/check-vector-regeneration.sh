#!/usr/bin/env bash
# Regenerate the vectors with the Rust reference implementation and fail if anything
# under vectors/ changed (modified, deleted or new files). Generation is a pure
# function of fixed seeds, so the output must be byte-identical to what is committed.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
before=$(git status --porcelain -- vectors/)
if [ -n "$before" ]; then
  echo "error: vectors/ has uncommitted changes before regeneration; cannot compare" >&2
  echo "$before" >&2
  exit 1
fi
(cd rust && cargo run --locked -p atep-core --bin atep-vectors -- generate ../vectors)
if ! git diff --exit-code -- vectors/; then
  echo "error: regenerating vectors changed committed files" >&2
  exit 1
fi
untracked=$(git ls-files --others --exclude-standard -- vectors/)
if [ -n "$untracked" ]; then
  echo "error: regeneration produced files that are not committed:" >&2
  echo "$untracked" >&2
  exit 1
fi
echo "vectors regenerate byte-identically"
