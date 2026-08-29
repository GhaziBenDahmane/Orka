#!/bin/sh
set -eu

output=$(mktemp)
cleanup() { rm -f -- "$output"; }
trap cleanup EXIT HUP INT TERM

if ! go run github.com/google/go-licenses@v1.6.0 check ./... \
  --disallowed_types=forbidden,restricted >"$output" 2>&1; then
  cat "$output" >&2
  exit 1
fi
cat "$output"
if grep -q 'Failed to find license' "$output"; then
  echo 'license scan could not classify every package' >&2
  exit 1
fi
