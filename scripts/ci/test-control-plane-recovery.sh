#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
temporary="$(mktemp -d)"
cleanup() { rm -rf -- "$temporary"; }
trap cleanup EXIT

for command in awk base64 date go jq openssl sha256sum; do
  command -v "$command" >/dev/null || { echo "$command is required for control-plane recovery checks" >&2; exit 1; }
done
real_go="$(command -v go)"

mkdir -p "$temporary/bin" "$temporary/output" "$temporary/bundle"
cat >"$temporary/bin/docker" <<'MOCK'
#!/bin/sh
printf '%s\n' "$*" >>"$DOCKYARD_RECOVERY_TEST_DOCKER_LOG"
exit 99
MOCK
chmod +x "$temporary/bin/docker"

export PATH="$temporary/bin:$PATH"
export DOCKYARD_RECOVERY_TEST_DOCKER_LOG="$temporary/docker.log"
export DOCKYARD_RECOVERY_WORK_DIR="$temporary"
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

openssl genpkey -algorithm ED25519 -out "$temporary/signing-key.pem" >/dev/null 2>&1
openssl pkey -in "$temporary/signing-key.pem" -pubout -out "$temporary/verify-key.pem" >/dev/null 2>&1
base64 -d <"$key_file" >"$temporary/master-key.bin"
master_key_sha256="$(sha256sum "$temporary/master-key.bin" | awk '{print $1}')"
signing_key_sha256="$(openssl pkey -pubin -in "$temporary/verify-key.pem" -outform DER | sha256sum | awk '{print $1}')"
created_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
jq -n \
  --arg createdAt "$created_at" \
  --arg controllerImage "$DOCKYARD_IMAGE" \
  --arg masterKeySha256 "$master_key_sha256" \
  --arg recoverySigningKeySha256 "$signing_key_sha256" \
  '{formatVersion:2,createdAt:$createdAt,stack:"dockyard",database:"dockyard",schemaVersion:"202608310001",controllerImage:$controllerImage,databaseSha256:("b"*64),databaseBytes:4096,masterKeySha256:$masterKeySha256,agentCaSha256:"",recoverySigningKeySha256:$recoverySigningKeySha256}' \
  >"$temporary/manifest.json"
openssl pkeyutl -sign -rawin -inkey "$temporary/signing-key.pem" -in "$temporary/manifest.json" -out "$temporary/manifest.sig"
verified_manifest="$(cd "$root" && "$real_go" run ./cmd/dockyard verify-control-plane-recovery-manifest \
  --manifest "$temporary/manifest.json" --signature "$temporary/manifest.sig" \
  --public-key-file "$temporary/verify-key.pem" --master-key-file "$temporary/master-key.bin" \
  --stack dockyard --database dockyard --controller-image "$DOCKYARD_IMAGE")"
jq -e --argjson verified "$verified_manifest" '. == $verified' "$temporary/manifest.json" >/dev/null

jq '.databaseBytes += 1' "$temporary/manifest.json" >"$temporary/tampered-manifest.json"
if (cd "$root" && "$real_go" run ./cmd/dockyard verify-control-plane-recovery-manifest \
  --manifest "$temporary/tampered-manifest.json" --signature "$temporary/manifest.sig" \
  --public-key-file "$temporary/verify-key.pem" --master-key-file "$temporary/master-key.bin" \
  --stack dockyard --database dockyard --controller-image "$DOCKYARD_IMAGE") >"$temporary/stdout" 2>"$temporary/stderr"; then
  echo 'control-plane verifier accepted a manifest modified after signing' >&2
  exit 1
fi
grep -q 'manifest signature is invalid' "$temporary/stderr"

printf '%s\n' 'Control-plane recovery secret preflight checks passed.'
