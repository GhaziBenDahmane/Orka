#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
temporary="$(mktemp -d)"
cleanup() { rm -rf -- "$temporary"; }
trap cleanup EXIT

mkdir -p "$temporary/bin" "$temporary/secrets"
auditor_token='auditor-token-value'
model_key='model-gateway-key'
printf '%s' "$auditor_token" >"$temporary/secrets/auditor-token"
printf '%s' "$model_key" >"$temporary/secrets/model-key"
chmod 0600 "$temporary/secrets/auditor-token" "$temporary/secrets/model-key"

cat >"$temporary/bin/docker" <<'MOCK'
#!/bin/sh
set -eu
printf '%s\n' "$*" >>"$DOCKYARD_AI_INSTALL_TEST_LOG"
case "$1 $2" in
  "info --format") printf '%s\n' 'active true' ;;
  "node inspect")
    [ "${DOCKYARD_AI_INSTALL_TEST_BAD_NODE:-false}" != true ] || { printf '%s\n' 'down drain'; exit 0; }
    printf '%s\n' 'ready active' ;;
  "manifest inspect")
    [ "${DOCKYARD_AI_INSTALL_TEST_UNAVAILABLE_IMAGE:-}" != "$3" ] || exit 1 ;;
  "run --rm")
    case "$*" in *' validate-ai-auditor-config '*) ;; *) exit 1 ;; esac ;;
  "secret inspect")
    case " ${DOCKYARD_AI_INSTALL_TEST_EXISTING_SECRETS:-} " in *" $3 "*) exit 0 ;; *) exit 1 ;; esac ;;
  "secret create")
    [ "${DOCKYARD_AI_INSTALL_TEST_FAIL_SECRET:-}" != "$3" ] || exit 1 ;;
  "stack config")
    printf 'stack=%s token-secret=%s key-secret=%s\n' "${DOCKYARD_AI_STACK_NAME:-dockyard-ai}" "$DOCKYARD_AI_AUDITOR_TOKEN_SECRET" "$DOCKYARD_AI_API_KEY_SECRET" >>"$DOCKYARD_AI_INSTALL_TEST_LOG" ;;
  "stack deploy")
    [ "${DOCKYARD_AI_INSTALL_TEST_FAIL_DEPLOY:-false}" != true ] || exit 1 ;;
  "stack services")
    stack=$3
    printf '%s\n' "${stack}_9router 1/1" "${stack}_headroom 1/1" "${stack}_security-auditor 1/1" "${stack}_reliability-auditor 1/1" ;;
  "service inspect")
    for argument in "$@"; do service=$argument; done
    state=${DOCKYARD_AI_INSTALL_TEST_UPDATE_STATE:-completed}
    case "$service" in
      *_9router) image=${DOCKYARD_AI_INSTALL_TEST_NINEROUTER_IMAGE:-$NINEROUTER_IMAGE} ;;
      *_headroom) image=$HEADROOM_IMAGE ;;
      *) image=$DOCKYARD_IMAGE ;;
    esac
    printf '%s|%s\n' "$image" "$state" ;;
esac
MOCK
chmod +x "$temporary/bin/docker"

digest_a='sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
digest_b='sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
digest_c='sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'
export PATH="$temporary/bin:$PATH"
export DOCKYARD_AI_INSTALL_TEST_LOG="$temporary/docker.log"
export DOCKYARD_IMAGE="example/dockyard@$digest_a"
export NINEROUTER_IMAGE="example/9router@$digest_b"
export HEADROOM_IMAGE="example/headroom@$digest_c"
export NINEROUTER_STORAGE_NODE_ID='nodeabc123'
export DOCKYARD_CONTROL_PLANE_URL='https://dockyard.example.test'
export DOCKYARD_AI_BASE_URL='http://9router:20128/v1'
export DOCKYARD_AI_MODEL='provider/model'
export DOCKYARD_AI_AUDITOR_TOKEN_FILE="$temporary/secrets/auditor-token"
export DOCKYARD_AI_API_KEY_FILE="$temporary/secrets/model-key"
export DOCKYARD_INSTALL_STABILITY_SECONDS=0

: >"$DOCKYARD_AI_INSTALL_TEST_LOG"
DOCKYARD_INSTALL_DRY_RUN=true "$root/scripts/install-ai-auditors.sh" | grep -q 'no resources were changed'
grep -Fqx "manifest inspect $DOCKYARD_IMAGE" "$DOCKYARD_AI_INSTALL_TEST_LOG"
grep -Fqx "manifest inspect $NINEROUTER_IMAGE" "$DOCKYARD_AI_INSTALL_TEST_LOG"
grep -Fqx "manifest inspect $HEADROOM_IMAGE" "$DOCKYARD_AI_INSTALL_TEST_LOG"
grep -Fqx "node inspect --format {{.Status.State}} {{.Spec.Availability}} $NINEROUTER_STORAGE_NODE_ID" "$DOCKYARD_AI_INSTALL_TEST_LOG"
grep -q ' validate-ai-auditor-config ' "$DOCKYARD_AI_INSTALL_TEST_LOG"
grep -q '^stack=dockyard-ai token-secret=dockyard_ai_auditor_token key-secret=dockyard_ai_api_key$' "$DOCKYARD_AI_INSTALL_TEST_LOG"
if grep -Eq '^(secret create|stack deploy)' "$DOCKYARD_AI_INSTALL_TEST_LOG"; then
  echo 'AI auditor dry-run mutated Docker state' >&2
  exit 1
fi

: >"$DOCKYARD_AI_INSTALL_TEST_LOG"
"$root/scripts/install-ai-auditors.sh" | grep -q 'installed and remained converged'
grep -Fqx "secret create dockyard_ai_auditor_token $DOCKYARD_AI_AUDITOR_TOKEN_FILE" "$DOCKYARD_AI_INSTALL_TEST_LOG"
grep -Fqx "secret create dockyard_ai_api_key $DOCKYARD_AI_API_KEY_FILE" "$DOCKYARD_AI_INSTALL_TEST_LOG"
grep -q '^stack deploy --prune --with-registry-auth ' "$DOCKYARD_AI_INSTALL_TEST_LOG"
for service in dockyard-ai_9router dockyard-ai_headroom dockyard-ai_security-auditor dockyard-ai_reliability-auditor; do
  grep -q "service inspect .* $service$" "$DOCKYARD_AI_INSTALL_TEST_LOG"
done
if grep -Fq "$auditor_token" "$DOCKYARD_AI_INSTALL_TEST_LOG" || grep -Fq "$model_key" "$DOCKYARD_AI_INSTALL_TEST_LOG"; then
  echo 'AI credential leaked to Docker command log' >&2
  exit 1
fi

: >"$DOCKYARD_AI_INSTALL_TEST_LOG"
if DOCKYARD_AI_INSTALL_TEST_EXISTING_SECRETS='dockyard_ai_auditor_token' "$root/scripts/install-ai-auditors.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'AI installer accepted an existing secret without explicit reuse' >&2
  exit 1
fi
grep -q 'DOCKYARD_REUSE_EXISTING_SECRETS=true' "$temporary/err"
if grep -Eq '^(secret create|stack deploy)' "$DOCKYARD_AI_INSTALL_TEST_LOG"; then
  echo 'existing AI secret failure mutated Docker state' >&2
  exit 1
fi

: >"$DOCKYARD_AI_INSTALL_TEST_LOG"
if DOCKYARD_AI_INSTALL_TEST_FAIL_SECRET='dockyard_ai_api_key' "$root/scripts/install-ai-auditors.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'AI installer ignored a Docker secret creation failure' >&2
  exit 1
fi
grep -q '^secret rm dockyard_ai_auditor_token$' "$DOCKYARD_AI_INSTALL_TEST_LOG"
if grep -q '^stack deploy' "$DOCKYARD_AI_INSTALL_TEST_LOG"; then
  echo 'AI installer deployed after a secret creation failure' >&2
  exit 1
fi

: >"$DOCKYARD_AI_INSTALL_TEST_LOG"
if DOCKYARD_AI_INSTALL_TEST_BAD_NODE=true "$root/scripts/install-ai-auditors.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'AI installer accepted an unavailable 9Router storage node' >&2
  exit 1
fi
grep -q 'must identify a ready, active Swarm node' "$temporary/err"

: >"$DOCKYARD_AI_INSTALL_TEST_LOG"
if DOCKYARD_AI_INSTALL_TEST_UNAVAILABLE_IMAGE="$NINEROUTER_IMAGE" "$root/scripts/install-ai-auditors.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'AI installer accepted an unavailable 9Router image' >&2
  exit 1
fi
grep -q 'NINEROUTER_IMAGE cannot be resolved' "$temporary/err"

if NINEROUTER_IMAGE='example/9router:latest' "$root/scripts/install-ai-auditors.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'AI installer accepted a mutable 9Router image' >&2
  exit 1
fi
grep -q 'NINEROUTER_IMAGE must be an image reference pinned by sha256 digest' "$temporary/err"

printf '%s\n%s' "$model_key" 'second-value' >"$temporary/secrets/model-key"
if "$root/scripts/install-ai-auditors.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'AI installer accepted a multiline model key' >&2
  exit 1
fi
grep -q 'must contain one value without CR or LF characters' "$temporary/err"
