#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
temporary="$(mktemp -d)"
cleanup() { rm -rf -- "$temporary"; }
trap cleanup EXIT

mkdir -p "$temporary/bin" "$temporary/secrets"
enrollment_token='one-time-enrollment-token-value-0123456789'
printf '%s' "$enrollment_token" >"$temporary/secrets/enrollment-token"
chmod 0600 "$temporary/secrets/enrollment-token"

cat >"$temporary/bin/docker" <<'MOCK'
#!/bin/sh
set -eu
printf '%s\n' "$*" >>"$DOCKYARD_INSTALL_TEST_LOG"
case "$1 $2" in
  "info --format") printf '%s\n' 'active true' ;;
  "manifest inspect")
    if [ "${DOCKYARD_INSTALL_TEST_UNAVAILABLE_IMAGE:-}" = "$3" ]; then exit 1; fi ;;
  "run --rm")
    case "$*" in
      *' validate-agent-endpoints '*)
        case "${DOCKYARD_CONTROL_PLANE_URL:-}|${DOCKYARD_AGENT_URL:-}" in
          'https://dockyard.example.test|https://agents.example.test:8444'|'https://127.0.0.1|https://[::1]:8444') ;;
          *) exit 1 ;;
        esac
        ;;
      *not-a-cidr*) exit 1 ;;
    esac ;;
  "secret inspect")
    if [ "${DOCKYARD_INSTALL_TEST_SECRET_EXISTS:-false}" = true ]; then exit 0; else exit 1; fi ;;
  "secret create")
    if [ "${DOCKYARD_INSTALL_TEST_FAIL_SECRET:-false}" = true ]; then exit 1; fi ;;
  "network inspect")
    if [ "${DOCKYARD_INSTALL_TEST_NETWORK_EXISTS:-false}" = true ]; then
      if [ "${3:-}" = --format ]; then printf '%s\n' "${DOCKYARD_INSTALL_TEST_NETWORK_PROPERTIES:-bridge|local|false|{}}"; fi
      exit 0
    fi
    exit 1 ;;
  "stack config")
    printf 'service=%s network=%s\n' "$DOCKYARD_AGENT_SERVICE_NAME" "$DOCKYARD_TRAEFIK_NETWORK" >>"$DOCKYARD_INSTALL_TEST_LOG"
    printf 'enrollment-secret=%s\n' "$DOCKYARD_AGENT_ENROLLMENT_TOKEN_SECRET" >>"$DOCKYARD_INSTALL_TEST_LOG" ;;
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
grep -Fqx "manifest inspect $DOCKYARD_IMAGE" "$DOCKYARD_INSTALL_TEST_LOG"
grep -Fqx "run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --entrypoint /usr/local/bin/dockyard $DOCKYARD_IMAGE validate-agent-endpoints --control-plane-url $DOCKYARD_CONTROL_PLANE_URL --agent-url $DOCKYARD_AGENT_URL" "$DOCKYARD_INSTALL_TEST_LOG"
grep -q '^service=edge_agent network=dockyard-public$' "$DOCKYARD_INSTALL_TEST_LOG"
grep -q '^enrollment-secret=dockyard_agent_enrollment_token$' "$DOCKYARD_INSTALL_TEST_LOG"
if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'agent dry-run mutated Docker state' >&2
  exit 1
fi

: >"$DOCKYARD_INSTALL_TEST_LOG"
DOCKYARD_EGRESS_PRIVATE_CIDRS='10.40.12.0/24,fd00:40:12::/64' \
  DOCKYARD_INSTALL_DRY_RUN=true "$root/scripts/install-agent.sh" >/dev/null
grep -q '^run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --entrypoint /usr/local/bin/dockyard .* validate-egress-policy --cidrs 10.40.12.0/24,fd00:40:12::/64$' "$DOCKYARD_INSTALL_TEST_LOG"

: >"$DOCKYARD_INSTALL_TEST_LOG"
if DOCKYARD_EGRESS_PRIVATE_CIDRS='not-a-cidr' "$root/scripts/install-agent.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'agent installer accepted an invalid private egress CIDR' >&2
  exit 1
fi
grep -q 'DOCKYARD_EGRESS_PRIVATE_CIDRS must contain' "$temporary/err"
if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'invalid agent egress policy mutated Docker state' >&2
  exit 1
fi

: >"$DOCKYARD_INSTALL_TEST_LOG"
DOCKYARD_CONTROL_PLANE_URL='https://127.0.0.1' DOCKYARD_AGENT_URL='https://[::1]:8444' \
  DOCKYARD_INSTALL_DRY_RUN=true "$root/scripts/install-agent.sh" >/dev/null
if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'IP-origin agent dry-run mutated Docker state' >&2
  exit 1
fi

: >"$DOCKYARD_INSTALL_TEST_LOG"
"$root/scripts/install-agent.sh" | grep -q 'installed and remained converged'
grep -q '^network create --driver overlay --opt encrypted --attachable dockyard-public$' "$DOCKYARD_INSTALL_TEST_LOG"
grep -q "^secret create dockyard_agent_enrollment_token $DOCKYARD_AGENT_ENROLLMENT_TOKEN_FILE$" "$DOCKYARD_INSTALL_TEST_LOG"
grep -q '^stack deploy --prune --with-registry-auth ' "$DOCKYARD_INSTALL_TEST_LOG"
if grep -Fq "$enrollment_token" "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'enrollment token leaked to Docker command log' >&2
  exit 1
fi

: >"$DOCKYARD_INSTALL_TEST_LOG"
DOCKYARD_AGENT_ENROLLMENT_TOKEN_SECRET=dockyard_agent_enrollment_token_v2 \
  "$root/scripts/install-agent.sh" >/dev/null
grep -q '^secret inspect dockyard_agent_enrollment_token_v2$' "$DOCKYARD_INSTALL_TEST_LOG"
grep -q "^secret create dockyard_agent_enrollment_token_v2 $DOCKYARD_AGENT_ENROLLMENT_TOKEN_FILE$" "$DOCKYARD_INSTALL_TEST_LOG"
grep -q '^enrollment-secret=dockyard_agent_enrollment_token_v2$' "$DOCKYARD_INSTALL_TEST_LOG"
if grep -Eq '^secret (inspect|create) dockyard_agent_enrollment_token( |$)' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'versioned agent installation used the default enrollment secret' >&2
  exit 1
fi

for unsafe_secret in '-leading' 'bad/name' 'bad secret' 'bad:secret'; do
  : >"$DOCKYARD_INSTALL_TEST_LOG"
  if DOCKYARD_AGENT_ENROLLMENT_TOKEN_SECRET="$unsafe_secret" \
    "$root/scripts/install-agent.sh" >"$temporary/out" 2>"$temporary/err"; then
    echo "agent installer accepted unsafe enrollment secret name: $unsafe_secret" >&2
    exit 1
  fi
  grep -q 'invalid DOCKYARD_AGENT_ENROLLMENT_TOKEN_SECRET' "$temporary/err"
  if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
    echo "unsafe agent enrollment secret name mutated Docker state: $unsafe_secret" >&2
    exit 1
  fi
done

: >"$DOCKYARD_INSTALL_TEST_LOG"
if DOCKYARD_INSTALL_TEST_NETWORK_EXISTS=true DOCKYARD_INSTALL_TEST_NETWORK_PROPERTIES='bridge|local|false|{}' \
  "$root/scripts/install-agent.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'agent installer accepted an unencrypted existing overlay network' >&2
  exit 1
fi
grep -q 'existing Docker network dockyard-public must be an attachable encrypted Swarm overlay' "$temporary/err"
if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'unencrypted agent-network failure mutated Docker state' >&2
  exit 1
fi

: >"$DOCKYARD_INSTALL_TEST_LOG"
if DOCKYARD_INSTALL_TEST_NETWORK_EXISTS=true DOCKYARD_INSTALL_TEST_NETWORK_PROPERTIES='overlay|swarm|true|{"encrypted":"false"}' \
  "$root/scripts/install-agent.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'agent installer accepted an overlay with encryption explicitly disabled' >&2
  exit 1
fi
grep -q 'existing Docker network dockyard-public must be an attachable encrypted Swarm overlay' "$temporary/err"
if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'disabled agent-network encryption failure mutated Docker state' >&2
  exit 1
fi

: >"$DOCKYARD_INSTALL_TEST_LOG"
DOCKYARD_INSTALL_TEST_NETWORK_EXISTS=true DOCKYARD_INSTALL_TEST_NETWORK_PROPERTIES='overlay|swarm|true|{"encrypted":""}' \
  "$root/scripts/install-agent.sh" >/dev/null
if grep -q '^network create' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'agent installer recreated an encrypted existing overlay network' >&2
  exit 1
fi

: >"$DOCKYARD_INSTALL_TEST_LOG"
DOCKYARD_TRAEFIK_NETWORK='shared_tenant.routing' \
  "$root/scripts/install-agent.sh" >/dev/null
grep -q '^service=edge_agent network=shared_tenant.routing$' "$DOCKYARD_INSTALL_TEST_LOG"
grep -q '^network create --driver overlay --opt encrypted --attachable shared_tenant.routing$' "$DOCKYARD_INSTALL_TEST_LOG"

for unsafe_network in 'Public' '-public' '.public' 'public/network' 'bad network' 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; do
  : >"$DOCKYARD_INSTALL_TEST_LOG"
  if DOCKYARD_TRAEFIK_NETWORK="$unsafe_network" \
    "$root/scripts/install-agent.sh" >"$temporary/out" 2>"$temporary/err"; then
    echo "agent installer accepted unsafe Traefik network name: $unsafe_network" >&2
    exit 1
  fi
  grep -q 'DOCKYARD_TRAEFIK_NETWORK must be a lowercase Docker network name of at most 63 characters' "$temporary/err"
  if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
    echo "unsafe agent network name mutated Docker state: $unsafe_network" >&2
    exit 1
  fi
done

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
grep -q 'must be valid HTTPS origins without credentials, paths, queries, or fragments' "$temporary/err"

for unsafe_origin in \
  'https://dockyard.example.test/v1' \
  'https://bad_label.example.test' \
  'https://dockyard.example.test:' \
  'https://dockyard.example.test:0' \
  'https://dockyard.example.test:65536'; do
  : >"$DOCKYARD_INSTALL_TEST_LOG"
  if DOCKYARD_CONTROL_PLANE_URL="$unsafe_origin" "$root/scripts/install-agent.sh" >"$temporary/out" 2>"$temporary/err"; then
    echo "agent installer accepted unsafe control-plane origin: $unsafe_origin" >&2
    exit 1
  fi
  grep -q 'must be valid HTTPS origins without credentials, paths, queries, or fragments' "$temporary/err"
  if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
    echo "unsafe control-plane origin mutated Docker state: $unsafe_origin" >&2
    exit 1
  fi
done

: >"$DOCKYARD_INSTALL_TEST_LOG"
if DOCKYARD_AGENT_URL='https://agents.example.test/mtls' "$root/scripts/install-agent.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'agent installer accepted an agent API URL with a path' >&2
  exit 1
fi
grep -q 'must be valid HTTPS origins without credentials, paths, queries, or fragments' "$temporary/err"
if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'unsafe agent API origin mutated Docker state' >&2
  exit 1
fi

if DOCKYARD_IMAGE='example/dockyard:latest' "$root/scripts/install-agent.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'agent installer accepted a mutable image' >&2
  exit 1
fi
grep -q 'DOCKYARD_IMAGE must be an image reference pinned by sha256 digest' "$temporary/err"

: >"$DOCKYARD_INSTALL_TEST_LOG"
if DOCKYARD_INSTALL_TEST_UNAVAILABLE_IMAGE="$DOCKYARD_IMAGE" "$root/scripts/install-agent.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'agent installer accepted an unavailable immutable image' >&2
  exit 1
fi
grep -q 'DOCKYARD_IMAGE cannot be resolved from the configured registry' "$temporary/err"
if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'unavailable agent image failure mutated Docker state' >&2
  exit 1
fi

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

printf '%s' 'short-enrollment-token' >"$temporary/secrets/enrollment-token"
: >"$DOCKYARD_INSTALL_TEST_LOG"
if "$root/scripts/install-agent.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'agent installer accepted a short enrollment token' >&2
  exit 1
fi
grep -q 'must contain between 32 and 4096 bytes' "$temporary/err"
if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'short enrollment token mutated Docker state' >&2
  exit 1
fi

printf '%s\n%s' "$enrollment_token" 'second-token' >"$temporary/secrets/enrollment-token"
: >"$DOCKYARD_INSTALL_TEST_LOG"
if "$root/scripts/install-agent.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'agent installer accepted a multiline enrollment token' >&2
  exit 1
fi
grep -q 'must contain exactly one token without CR or LF characters' "$temporary/err"
if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'multiline enrollment token mutated Docker state' >&2
  exit 1
fi
if grep -Fq "$enrollment_token" "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'multiline enrollment token leaked to Docker command log' >&2
  exit 1
fi

printf '%s' "$enrollment_token" >"$temporary/secrets/enrollment-token"
chmod 0644 "$temporary/secrets/enrollment-token"
if "$root/scripts/install-agent.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'agent installer accepted a broadly readable enrollment token' >&2
  exit 1
fi
grep -q 'must not be accessible by group or other users' "$temporary/err"

printf '%s\n' 'Agent installer preflight, mutation, rollback, and security checks passed.'
