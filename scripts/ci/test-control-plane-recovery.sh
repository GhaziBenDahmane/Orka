#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
temporary="$(mktemp -d)"
cleanup() { rm -rf -- "$temporary"; }
trap cleanup EXIT

mkdir -p "$temporary/bin" "$temporary/output" "$temporary/bundle"
cat >"$temporary/bin/docker" <<'MOCK'
#!/bin/sh
printf '%s\n' "$*" >>"$DOCKYARD_RECOVERY_TEST_DOCKER_LOG"
exit 99
MOCK
chmod +x "$temporary/bin/docker"

export PATH="$temporary/bin:$PATH"
export DOCKYARD_RECOVERY_TEST_DOCKER_LOG="$temporary/docker.log"
export DOCKYARD_IMAGE='example/dockyard@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
export DOCKYARD_RESTORE_CONFIRM='restore:dockyard'
unset DOCKYARD_MASTER_KEY DOCKYARD_MASTER_KEY_FILE DOCKYARD_RECOVERY_SIGNING_KEY_FILE DOCKYARD_RECOVERY_VERIFY_KEY_FILE
: >"$DOCKYARD_RECOVERY_TEST_DOCKER_LOG"

key_file="$temporary/master-key"
printf '%s' 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' >"$key_file"
chmod 0600 "$key_file"

assert_rejected() {
  expected=$1
  shift
  if "$@" >"$temporary/stdout" 2>"$temporary/stderr"; then
    echo "recovery command accepted unsafe master-key input: $*" >&2
    exit 1
  fi
  grep -q "$expected" "$temporary/stderr"
}

for script_and_target in \
  "$root/scripts/backup-control-plane.sh|$temporary/output/backup" \
  "$root/scripts/restore-control-plane.sh|$temporary/bundle"; do
  script=${script_and_target%%|*}
  target=${script_and_target#*|}

  export DOCKYARD_MASTER_KEY='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
  export DOCKYARD_MASTER_KEY_FILE="$key_file"
  assert_rejected 'cannot both be configured' "$script" "$target"

  unset DOCKYARD_MASTER_KEY
  chmod 0644 "$key_file"
  assert_rejected 'must not be accessible by group or other users' "$script" "$target"

  chmod 0600 "$key_file"
  ln -s "$key_file" "$temporary/master-key-link"
  export DOCKYARD_MASTER_KEY_FILE="$temporary/master-key-link"
  assert_rejected 'must name a readable regular file, not a symbolic link' "$script" "$target"
  rm "$temporary/master-key-link"

  export DOCKYARD_MASTER_KEY_FILE="$temporary/missing-master-key"
  assert_rejected 'must name a readable regular file, not a symbolic link' "$script" "$target"
done

export DOCKYARD_MASTER_KEY_FILE="$key_file"
assert_rejected 'DOCKYARD_RECOVERY_SIGNING_KEY_FILE must name' \
  "$root/scripts/backup-control-plane.sh" "$temporary/output/valid-key-backup"
assert_rejected 'recovery bundle must contain regular' \
  "$root/scripts/restore-control-plane.sh" "$temporary/bundle"

if [ -s "$DOCKYARD_RECOVERY_TEST_DOCKER_LOG" ]; then
  echo 'invalid recovery secret input reached Docker' >&2
  exit 1
fi

printf '%s\n' 'Control-plane recovery secret preflight checks passed.'
