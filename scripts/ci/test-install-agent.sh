#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
temporary="$(mktemp -d)"
cleanup() { rm -rf -- "$temporary"; }
trap cleanup EXIT

mkdir -p "$temporary/bin" "$temporary/secrets"
printf '%s' 'one-time-enrollment-token-value' >"$temporary/secrets/enrollment-token"
chmod 0600 "$temporary/secrets/enrollment-token"

cat >"$temporary/bin/docker" <<'MOCK'
#!/bin/sh
set -eu
printf '%s\n' "$*" >>"$DOCKYARD_INSTALL_TEST_LOG"
case "$1 $2" in
  "info --format") printf '%s\n' 'active true' ;;
  "secret inspect")
    if [ "${DOCKYARD_INSTALL_TEST_SECRET_EXISTS:-false}" = true ]; then exit 0; else exit 1; fi ;;
  "secret create")
    if [ "${DOCKYARD_INSTALL_TEST_FAIL_SECRET:-false}" = true ]; then exit 1; fi ;;
  "network inspect") exit 1 ;;
  "stack config")
    printf 'service=%s network=%s\n' "$DOCKYARD_AGENT_SERVICE_NAME" "$DOCKYARD_TRAEFIK_NETWORK" >>"$DOCKYARD_INSTALL_TEST_LOG" ;;
  "service inspect")
    image=${DOCKYARD_INSTALL_TEST_AGENT_IMAGE:-$DOCKYARD_IMAGE}
    state=${DOCKYARD_INSTALL_TEST_UPDATE_STATE:-completed}
    printf '%s|%s\n' "$image" "$state" ;;
  "stack services") printf '%s\n' 'edge_agent 1/1' ;;
esac
MOCK
chmod +x "$temporary/bin/docker"

digest='sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
export PATH="$temporary/bin:$PATH"
export DOCKYARD_INSTALL_TEST_LOG="$temporary/docker.log"
export DOCKYARD_IMAGE="example/dockyard@$digest"
export DOCKYARD_CONTROL_PLANE_URL='https://dockyard.example.test'
export DOCKYARD_AGENT_URL='https://agents.example.test:8444'
export DOCKYARD_AGENT_STACK_NAME='edge'
export DOCKYARD_AGENT_ENROLLMENT_TOKEN_FILE="$temporary/secrets/enrollment-token"
export DOCKYARD_INSTALL_STABILITY_SECONDS=0

: >"$DOCKYARD_INSTALL_TEST_LOG"
DOCKYARD_INSTALL_DRY_RUN=true "$root/scripts/install-agent.sh" | grep -q 'no resources were changed'
grep -q '^stack config ' "$DOCKYARD_INSTALL_TEST_LOG"
grep -q '^service=edge_agent network=dockyard-public$' "$DOCKYARD_INSTALL_TEST_LOG"
if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'agent dry-run mutated Docker state' >&2
  exit 1
fi

: >"$DOCKYARD_INSTALL_TEST_LOG"
"$root/scripts/install-agent.sh" | grep -q 'installed and remained converged'
grep -q '^network create --driver overlay --attachable dockyard-public$' "$DOCKYARD_INSTALL_TEST_LOG"
grep -q "^secret create dockyard_agent_enrollment_token $DOCKYARD_AGENT_ENROLLMENT_TOKEN_FILE$" "$DOCKYARD_INSTALL_TEST_LOG"
grep -q '^stack deploy --prune --with-registry-auth ' "$DOCKYARD_INSTALL_TEST_LOG"
if grep -q 'one-time-enrollment-token-value' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'enrollment token leaked to Docker command log' >&2
  exit 1
fi

: >"$DOCKYARD_INSTALL_TEST_LOG"
if DOCKYARD_INSTALL_TEST_SECRET_EXISTS=true "$root/scripts/install-agent.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'agent installer accepted an existing token secret without explicit reuse' >&2
  exit 1
fi
grep -q 'DOCKYARD_REUSE_EXISTING_SECRETS=true' "$temporary/err"
if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'existing agent secret failure mutated Docker state' >&2
  exit 1
fi

: >"$DOCKYARD_INSTALL_TEST_LOG"
if DOCKYARD_INSTALL_TEST_FAIL_SECRET=true "$root/scripts/install-agent.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'agent installer ignored a Docker secret creation failure' >&2
  exit 1
fi
grep -q '^network rm dockyard-public$' "$DOCKYARD_INSTALL_TEST_LOG"
if grep -q '^stack deploy' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'agent installer deployed after a secret creation failure' >&2
  exit 1
fi

if DOCKYARD_CONTROL_PLANE_URL='http://dockyard.example.test' "$root/scripts/install-agent.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'agent installer accepted a plaintext control-plane URL' >&2
  exit 1
fi
grep -q 'DOCKYARD_CONTROL_PLANE_URL must be an https:// URL' "$temporary/err"

if DOCKYARD_IMAGE='example/dockyard:latest' "$root/scripts/install-agent.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'agent installer accepted a mutable image' >&2
  exit 1
fi
grep -q 'DOCKYARD_IMAGE must be an image reference pinned by sha256 digest' "$temporary/err"

if DOCKYARD_INSTALL_STABILITY_SECONDS=301 "$root/scripts/install-agent.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'agent installer accepted a stability window longer than its timeout' >&2
  exit 1
fi
grep -q 'DOCKYARD_INSTALL_STABILITY_SECONDS must not exceed' "$temporary/err"

if DOCKYARD_INSTALL_WAIT_TIMEOUT=1 \
  DOCKYARD_INSTALL_TEST_AGENT_IMAGE="example/dockyard@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" \
  "$root/scripts/install-agent.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'agent installer accepted a rolled-back image' >&2
  exit 1
fi
grep -q 'edge_agent image is .* expected' "$temporary/err"

if DOCKYARD_INSTALL_WAIT_TIMEOUT=1 DOCKYARD_INSTALL_TEST_UPDATE_STATE=rollback_completed \
  "$root/scripts/install-agent.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'agent installer accepted a completed Swarm rollback' >&2
  exit 1
fi
grep -q 'edge_agent update state is rollback_completed' "$temporary/err"

chmod 0644 "$temporary/secrets/enrollment-token"
if "$root/scripts/install-agent.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'agent installer accepted a broadly readable enrollment token' >&2
  exit 1
fi
grep -q 'must not be accessible by group or other users' "$temporary/err"

printf '%s\n' 'Agent installer preflight, mutation, rollback, and security checks passed.'
