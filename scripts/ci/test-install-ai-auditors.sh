#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
real_docker="$(command -v docker)"
temporary="$(mktemp -d)"
cleanup() { rm -rf -- "$temporary"; }
trap cleanup EXIT

mkdir -p "$temporary/bin" "$temporary/secrets"
security_token='security-auditor-token-value'
reliability_token='reliability-auditor-token-value'
model_key='model-gateway-key'
printf '%s' "$security_token" >"$temporary/secrets/security-token"
printf '%s' "$reliability_token" >"$temporary/secrets/reliability-token"
printf '%s' "$model_key" >"$temporary/secrets/model-key"
chmod 0600 "$temporary/secrets/security-token" "$temporary/secrets/reliability-token" "$temporary/secrets/model-key"

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
    case "$*" in
      *' validate-ai-auditor-config '*) ;;
      *' verify-ai-auditor-runs '*)
        read -r token || true
        case "$*" in
          *' --agent-name security-auditor '*) [ "$token" = 'security-auditor-token-value' ] || exit 1 ;;
          *' --agent-name reliability-auditor '*) [ "$token" = 'reliability-auditor-token-value' ] || exit 1 ;;
          *) exit 1 ;;
        esac
        case "${DOCKYARD_AI_INSTALL_TEST_FAIL_VERIFY:-}" in "$token") exit 1 ;; esac ;;
      *) exit 1 ;;
    esac ;;
  "secret inspect")
    case " ${DOCKYARD_AI_INSTALL_TEST_EXISTING_SECRETS:-} " in *" $3 "*) exit 0 ;; *) exit 1 ;; esac ;;
  "secret create")
    [ "${DOCKYARD_AI_INSTALL_TEST_FAIL_SECRET:-}" != "$3" ] || exit 1 ;;
  "stack config")
    printf 'stack=%s security-secret=%s reliability-secret=%s key-secret=%s\n' "${DOCKYARD_AI_STACK_NAME:-dockyard-ai}" "$DOCKYARD_AI_SECURITY_AUDITOR_TOKEN_SECRET" "$DOCKYARD_AI_RELIABILITY_AUDITOR_TOKEN_SECRET" "$DOCKYARD_AI_API_KEY_SECRET" >>"$DOCKYARD_AI_INSTALL_TEST_LOG" ;;
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
export DOCKYARD_AI_SECURITY_AUDITOR_TOKEN_FILE="$temporary/secrets/security-token"
export DOCKYARD_AI_RELIABILITY_AUDITOR_TOKEN_FILE="$temporary/secrets/reliability-token"
export DOCKYARD_AI_API_KEY_FILE="$temporary/secrets/model-key"
export DOCKYARD_INSTALL_STABILITY_SECONDS=0

"$real_docker" stack config -c "$root/deploy/ai-auditors.yml" >"$temporary/rendered.yml"
for image in "$DOCKYARD_IMAGE" "$NINEROUTER_IMAGE" "$HEADROOM_IMAGE"; do
  grep -Fq "image: $image" "$temporary/rendered.yml" || {
    echo "real docker stack config did not preserve requested image $image" >&2
    exit 1
  }
done
grep -Fq "DOCKYARD_AI_MODEL: $DOCKYARD_AI_MODEL" "$temporary/rendered.yml" || {
  echo 'real docker stack config did not preserve the requested AI model' >&2
  exit 1
}

: >"$DOCKYARD_AI_INSTALL_TEST_LOG"
DOCKYARD_INSTALL_DRY_RUN=true "$root/scripts/install-ai-auditors.sh" | grep -q 'no resources were changed'
grep -Fqx "manifest inspect $DOCKYARD_IMAGE" "$DOCKYARD_AI_INSTALL_TEST_LOG"
grep -Fqx "manifest inspect $NINEROUTER_IMAGE" "$DOCKYARD_AI_INSTALL_TEST_LOG"
grep -Fqx "manifest inspect $HEADROOM_IMAGE" "$DOCKYARD_AI_INSTALL_TEST_LOG"
grep -Fqx "node inspect --format {{.Status.State}} {{.Spec.Availability}} $NINEROUTER_STORAGE_NODE_ID" "$DOCKYARD_AI_INSTALL_TEST_LOG"
grep -q ' validate-ai-auditor-config ' "$DOCKYARD_AI_INSTALL_TEST_LOG"
grep -q '^stack=dockyard-ai security-secret=dockyard_ai_security_auditor_token reliability-secret=dockyard_ai_reliability_auditor_token key-secret=dockyard_ai_api_key$' "$DOCKYARD_AI_INSTALL_TEST_LOG"
if grep -Eq '^(secret create|stack deploy)' "$DOCKYARD_AI_INSTALL_TEST_LOG"; then
  echo 'AI auditor dry-run mutated Docker state' >&2
  exit 1
fi

: >"$DOCKYARD_AI_INSTALL_TEST_LOG"
"$root/scripts/install-ai-auditors.sh" | grep -q 'completed both fresh audit runs'
grep -Fqx "secret create dockyard_ai_security_auditor_token $DOCKYARD_AI_SECURITY_AUDITOR_TOKEN_FILE" "$DOCKYARD_AI_INSTALL_TEST_LOG"
grep -Fqx "secret create dockyard_ai_reliability_auditor_token $DOCKYARD_AI_RELIABILITY_AUDITOR_TOKEN_FILE" "$DOCKYARD_AI_INSTALL_TEST_LOG"
grep -Fqx "secret create dockyard_ai_api_key $DOCKYARD_AI_API_KEY_FILE" "$DOCKYARD_AI_INSTALL_TEST_LOG"
grep -q '^stack deploy --prune --with-registry-auth ' "$DOCKYARD_AI_INSTALL_TEST_LOG"
for service in dockyard-ai_9router dockyard-ai_headroom dockyard-ai_security-auditor dockyard-ai_reliability-auditor; do
  grep -q "service inspect .* $service$" "$DOCKYARD_AI_INSTALL_TEST_LOG"
done
grep -q ' verify-ai-auditor-runs .* --agent-name security-auditor ' "$DOCKYARD_AI_INSTALL_TEST_LOG"
grep -q ' verify-ai-auditor-runs .* --agent-name reliability-auditor ' "$DOCKYARD_AI_INSTALL_TEST_LOG"
if grep -Fq "$security_token" "$DOCKYARD_AI_INSTALL_TEST_LOG" || grep -Fq "$reliability_token" "$DOCKYARD_AI_INSTALL_TEST_LOG" || grep -Fq "$model_key" "$DOCKYARD_AI_INSTALL_TEST_LOG"; then
  echo 'AI credential leaked to Docker command log' >&2
  exit 1
fi

: >"$DOCKYARD_AI_INSTALL_TEST_LOG"
DOCKYARD_INSTALL_SKIP_WAIT=true "$root/scripts/install-ai-auditors.sh" | grep -q 'convergence wait was skipped'
if grep -q ' verify-ai-auditor-runs ' "$DOCKYARD_AI_INSTALL_TEST_LOG"; then
  echo 'AI installer verified runs despite the explicit asynchronous escape hatch' >&2
  exit 1
fi

: >"$DOCKYARD_AI_INSTALL_TEST_LOG"
if DOCKYARD_AI_INSTALL_TEST_EXISTING_SECRETS='dockyard_ai_security_auditor_token' "$root/scripts/install-ai-auditors.sh" >"$temporary/out" 2>"$temporary/err"; then
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
grep -q '^secret rm dockyard_ai_security_auditor_token$' "$DOCKYARD_AI_INSTALL_TEST_LOG"
grep -q '^secret rm dockyard_ai_reliability_auditor_token$' "$DOCKYARD_AI_INSTALL_TEST_LOG"
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

printf '%s' "$model_key" >"$temporary/secrets/model-key"
printf '%s' "$security_token" >"$temporary/secrets/reliability-token"
if "$root/scripts/install-ai-auditors.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'AI installer accepted one credential for both auditor identities' >&2
  exit 1
fi
grep -q 'security and reliability auditor credentials must be distinct' "$temporary/err"
printf '%s' "$reliability_token" >"$temporary/secrets/reliability-token"

: >"$DOCKYARD_AI_INSTALL_TEST_LOG"
if DOCKYARD_AI_INSTALL_TEST_FAIL_VERIFY="$security_token" DOCKYARD_AI_VERIFY_TIMEOUT=1 "$root/scripts/install-ai-auditors.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'AI installer reported success after audit verification failed' >&2
  exit 1
fi
grep -q 'security-auditor did not complete a fresh run' "$temporary/err"
if grep -Fq "$security_token" "$DOCKYARD_AI_INSTALL_TEST_LOG" || grep -Fq "$reliability_token" "$DOCKYARD_AI_INSTALL_TEST_LOG"; then
  echo 'AI auditor token leaked while verifying runs' >&2
  exit 1
fi
