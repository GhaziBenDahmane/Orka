#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
temporary="$(mktemp -d)"
cleanup() { rm -rf -- "$temporary"; }
trap cleanup EXIT

mkdir -p "$temporary/bin" "$temporary/secrets"
printf '%s' 'correct horse battery staple' >"$temporary/secrets/database-password"
printf '%s' 'postgres://dockyard:safe-value@postgres:5432/dockyard?sslmode=disable' >"$temporary/secrets/database-url"
printf '%s' 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' >"$temporary/secrets/master-key"
chmod 0600 "$temporary"/secrets/*

cat >"$temporary/bin/docker" <<'MOCK'
#!/bin/sh
set -eu
printf '%s\n' "$*" >>"$DOCKYARD_INSTALL_TEST_LOG"
case "$1 $2" in
  "info --format") printf '%s\n' 'active true' ;;
  "secret inspect")
    case " ${DOCKYARD_INSTALL_TEST_EXISTING_SECRETS:-} " in *" $3 "*) exit 0 ;; *) exit 1 ;; esac ;;
  "secret create")
    if [ "${DOCKYARD_INSTALL_TEST_FAIL_SECRET:-}" = "$3" ]; then exit 1; fi ;;
  "network inspect") exit 1 ;;
  "service inspect")
    service=$5
    state=${DOCKYARD_INSTALL_TEST_UPDATE_STATE:-completed}
    case "$service" in
      *_dockyard) image=${DOCKYARD_INSTALL_TEST_CONTROLLER_IMAGE:-$DOCKYARD_IMAGE} ;;
      *_postgres) image=$POSTGRES_IMAGE ;;
      *_traefik) image=$TRAEFIK_IMAGE ;;
      *) exit 1 ;;
    esac
    printf '%s|%s\n' "$image" "$state" ;;
  "stack services")
    if [ "${DOCKYARD_INSTALL_TEST_FLAP_ONCE:-false}" = true ]; then
      count=0
      [ ! -f "$DOCKYARD_INSTALL_TEST_STATE" ] || count=$(cat "$DOCKYARD_INSTALL_TEST_STATE")
      count=$((count + 1))
      printf '%s' "$count" >"$DOCKYARD_INSTALL_TEST_STATE"
      if [ "$count" -eq 2 ]; then
        printf '%s\n' 'dockyard_dockyard 0/1' 'dockyard_postgres 1/1' 'dockyard_traefik 1/1'
        exit 0
      fi
    fi
    printf '%s\n' 'dockyard_dockyard 1/1' 'dockyard_postgres 1/1' 'dockyard_traefik 1/1' ;;
esac
MOCK
chmod +x "$temporary/bin/docker"

digest='sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
export PATH="$temporary/bin:$PATH"
export DOCKYARD_INSTALL_TEST_LOG="$temporary/docker.log"
export DOCKYARD_INSTALL_TEST_STATE="$temporary/state"
export DOCKYARD_HOST='dockyard.example.test'
export ACME_EMAIL='ops@example.test'
export DOCKYARD_IMAGE="example/dockyard@$digest"
export POSTGRES_IMAGE="postgres@$digest"
export TRAEFIK_IMAGE="traefik@$digest"
export DOCKYARD_DB_PASSWORD_FILE="$temporary/secrets/database-password"
export DOCKYARD_DATABASE_URL_FILE="$temporary/secrets/database-url"
export DOCKYARD_MASTER_KEY_FILE="$temporary/secrets/master-key"
export DOCKYARD_INSTALL_STABILITY_SECONDS=0

: >"$DOCKYARD_INSTALL_TEST_LOG"
DOCKYARD_INSTALL_DRY_RUN=true "$root/scripts/install-swarm.sh" | grep -q 'no resources were changed'
grep -q '^stack config ' "$DOCKYARD_INSTALL_TEST_LOG"
if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'dry-run mutated Docker state' >&2
  exit 1
fi

: >"$DOCKYARD_INSTALL_TEST_LOG"
"$root/scripts/install-swarm.sh" | grep -q 'installed and remained converged'
grep -q '^network create --driver overlay --attachable dockyard-public$' "$DOCKYARD_INSTALL_TEST_LOG"
grep -q "^secret create dockyard_db_password $DOCKYARD_DB_PASSWORD_FILE$" "$DOCKYARD_INSTALL_TEST_LOG"
grep -q '^stack deploy --prune --with-registry-auth ' "$DOCKYARD_INSTALL_TEST_LOG"
if grep -q 'correct horse battery staple' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'secret value leaked to Docker command log' >&2
  exit 1
fi

: >"$DOCKYARD_INSTALL_TEST_LOG"
rm -f "$DOCKYARD_INSTALL_TEST_STATE"
DOCKYARD_INSTALL_TEST_FLAP_ONCE=true DOCKYARD_INSTALL_STABILITY_SECONDS=3 \
  "$root/scripts/install-swarm.sh" | grep -q 'remained converged for 3s'
[ "$(cat "$DOCKYARD_INSTALL_TEST_STATE")" -ge 4 ] || {
  echo 'installer did not reset its stability window after replica loss' >&2
  exit 1
}

: >"$DOCKYARD_INSTALL_TEST_LOG"
if DOCKYARD_INSTALL_TEST_EXISTING_SECRETS='dockyard_master_key' "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'installer accepted an existing secret without explicit reuse' >&2
  exit 1
fi
grep -q 'DOCKYARD_REUSE_EXISTING_SECRETS=true' "$temporary/err"
if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'existing-secret failure mutated Docker state' >&2
  exit 1
fi

: >"$DOCKYARD_INSTALL_TEST_LOG"
DOCKYARD_INSTALL_TEST_EXISTING_SECRETS='dockyard_db_password dockyard_database_url dockyard_master_key' \
  DOCKYARD_REUSE_EXISTING_SECRETS=true \
  "$root/scripts/install-swarm.sh" >/dev/null
if grep -q '^secret create' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'installer recreated an explicitly reused secret' >&2
  exit 1
fi

: >"$DOCKYARD_INSTALL_TEST_LOG"
if DOCKYARD_INSTALL_TEST_FAIL_SECRET='dockyard_database_url' \
  "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'installer ignored a Docker secret creation failure' >&2
  exit 1
fi
grep -q '^secret rm dockyard_db_password$' "$DOCKYARD_INSTALL_TEST_LOG"
grep -q '^network rm dockyard-public$' "$DOCKYARD_INSTALL_TEST_LOG"
if grep -q '^stack deploy' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'installer deployed after a secret creation failure' >&2
  exit 1
fi

if DOCKYARD_IMAGE='example/dockyard:latest' "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'installer accepted a mutable controller image' >&2
  exit 1
fi
grep -q 'DOCKYARD_IMAGE must be an image reference pinned by sha256 digest' "$temporary/err"

if DOCKYARD_INSTALL_STABILITY_SECONDS=301 "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'installer accepted a stability window longer than its timeout' >&2
  exit 1
fi
grep -q 'DOCKYARD_INSTALL_STABILITY_SECONDS must not exceed' "$temporary/err"

if DOCKYARD_INSTALL_WAIT_TIMEOUT=1 \
  DOCKYARD_INSTALL_TEST_CONTROLLER_IMAGE="example/dockyard@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" \
  "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'installer accepted a rolled-back controller image' >&2
  exit 1
fi
grep -q 'dockyard_dockyard image is .* expected' "$temporary/err"

if DOCKYARD_INSTALL_WAIT_TIMEOUT=1 DOCKYARD_INSTALL_TEST_UPDATE_STATE=rollback_completed \
  "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'installer accepted a completed Swarm rollback' >&2
  exit 1
fi
grep -q 'dockyard_dockyard update state is rollback_completed' "$temporary/err"

for unsafe_host in 'dockyard.example.test`)||Host(`attacker.example.test' 'bad_label.example.test' '-leading.example.test' 'single-label'; do
  : >"$DOCKYARD_INSTALL_TEST_LOG"
  if DOCKYARD_HOST="$unsafe_host" "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
    echo "installer accepted unsafe hostname: $unsafe_host" >&2
    exit 1
  fi
  grep -q 'DOCKYARD_HOST must be a DNS hostname' "$temporary/err"
  if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
    echo "unsafe hostname mutated Docker state: $unsafe_host" >&2
    exit 1
  fi
done

for unsafe_email in 'ops@example.test,attacker@example.test' 'ops@bad_label.example.test' '.ops@example.test'; do
  : >"$DOCKYARD_INSTALL_TEST_LOG"
  if ACME_EMAIL="$unsafe_email" "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
    echo "installer accepted unsafe ACME email: $unsafe_email" >&2
    exit 1
  fi
  grep -q 'ACME_EMAIL must be a valid email address' "$temporary/err"
  if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
    echo "unsafe ACME email mutated Docker state: $unsafe_email" >&2
    exit 1
  fi
done

if DOCKYARD_INSTALL_MODE=ha "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'HA installer accepted a database URL without certificate verification' >&2
  exit 1
fi
grep -q 'sslmode=verify-full' "$temporary/err"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=Dockyard Test CA' \
  -keyout "$temporary/secrets/agent-ca.key" -out "$temporary/secrets/agent-ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj '/CN=agents.example.test' \
  -addext 'subjectAltName=DNS:agents.example.test' \
  -keyout "$temporary/secrets/agent-server.key" -out "$temporary/agent-server.csr" >/dev/null 2>&1
openssl x509 -req -days 1 -CA "$temporary/secrets/agent-ca.crt" -CAkey "$temporary/secrets/agent-ca.key" \
  -CAcreateserial -copy_extensions copy -in "$temporary/agent-server.csr" \
  -out "$temporary/secrets/agent-server.crt" >/dev/null 2>&1
printf '%s' 'postgres://dockyard:safe-value@database.example.test:5432/dockyard?sslmode=verify-full' >"$temporary/secrets/database-url-ha"
chmod 0600 "$temporary"/secrets/*
export DOCKYARD_DATABASE_URL_FILE="$temporary/secrets/database-url-ha"
export DOCKYARD_AGENT_HOST='agents.example.test'
export DOCKYARD_AGENT_CA_CERT_FILE="$temporary/secrets/agent-ca.crt"
export DOCKYARD_AGENT_CA_KEY_FILE="$temporary/secrets/agent-ca.key"
export DOCKYARD_AGENT_SERVER_CERT_FILE="$temporary/secrets/agent-server.crt"
export DOCKYARD_AGENT_SERVER_KEY_FILE="$temporary/secrets/agent-server.key"

: >"$DOCKYARD_INSTALL_TEST_LOG"
DOCKYARD_INSTALL_MODE=ha DOCKYARD_INSTALL_DRY_RUN=true "$root/scripts/install-swarm.sh" >/dev/null
grep -q "stack config -c $root/deploy/swarm.yml -c $root/deploy/swarm-ha.yml" "$DOCKYARD_INSTALL_TEST_LOG"
for secret in dockyard_agent_ca_cert dockyard_agent_ca_key dockyard_agent_server_cert dockyard_agent_server_key; do
  grep -q "^secret inspect $secret$" "$DOCKYARD_INSTALL_TEST_LOG"
done

if DOCKYARD_INSTALL_MODE=ha DOCKYARD_INSTALL_DRY_RUN=true \
  DOCKYARD_AGENT_SERVER_KEY_FILE="$temporary/secrets/agent-ca.key" \
  "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'HA installer accepted a mismatched server key' >&2
  exit 1
fi
grep -q 'server certificate and private key do not match' "$temporary/err"

if DOCKYARD_INSTALL_MODE=ha DOCKYARD_INSTALL_DRY_RUN=true \
  DOCKYARD_AGENT_HOST='agents.example.test`)||Host(`attacker.example.test' \
  "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'HA installer accepted an unsafe agent hostname' >&2
  exit 1
fi
grep -q 'DOCKYARD_AGENT_HOST must be a DNS hostname' "$temporary/err"

printf '%s\n' 'Swarm installer preflight, mutation, reuse, and immutability checks passed.'
