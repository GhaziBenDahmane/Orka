#!/bin/sh
set -eu

output=$(mktemp)
cleanup() { rm -f -- "$output"; }
handle_signal() {
  status=$1
  trap - EXIT HUP INT TERM
  cleanup
  exit "$status"
}
trap cleanup EXIT
trap 'handle_signal 129' HUP
trap 'handle_signal 130' INT
trap 'handle_signal 143' TERM

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
