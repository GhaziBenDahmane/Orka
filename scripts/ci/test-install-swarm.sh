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
  "stack services")
    printf '%s\n' 'dockyard_dockyard 1/1' 'dockyard_postgres 1/1' 'dockyard_traefik 1/1' ;;
esac
MOCK
chmod +x "$temporary/bin/docker"

digest='sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
export PATH="$temporary/bin:$PATH"
export DOCKYARD_INSTALL_TEST_LOG="$temporary/docker.log"
export DOCKYARD_HOST='dockyard.example.test'
export ACME_EMAIL='ops@example.test'
export DOCKYARD_IMAGE="example/dockyard@$digest"
export POSTGRES_IMAGE="postgres@$digest"
export TRAEFIK_IMAGE="traefik@$digest"
export DOCKYARD_DB_PASSWORD_FILE="$temporary/secrets/database-password"
export DOCKYARD_DATABASE_URL_FILE="$temporary/secrets/database-url"
export DOCKYARD_MASTER_KEY_FILE="$temporary/secrets/master-key"

: >"$DOCKYARD_INSTALL_TEST_LOG"
DOCKYARD_INSTALL_DRY_RUN=true "$root/scripts/install-swarm.sh" | grep -q 'no resources were changed'
grep -q '^stack config ' "$DOCKYARD_INSTALL_TEST_LOG"
if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'dry-run mutated Docker state' >&2
  exit 1
fi

: >"$DOCKYARD_INSTALL_TEST_LOG"
"$root/scripts/install-swarm.sh" | grep -q 'installed and converged'
grep -q '^network create --driver overlay --attachable dockyard-public$' "$DOCKYARD_INSTALL_TEST_LOG"
grep -q "^secret create dockyard_db_password $DOCKYARD_DB_PASSWORD_FILE$" "$DOCKYARD_INSTALL_TEST_LOG"
grep -q '^stack deploy --prune --with-registry-auth ' "$DOCKYARD_INSTALL_TEST_LOG"
if grep -q 'correct horse battery staple' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'secret value leaked to Docker command log' >&2
  exit 1
fi

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

printf '%s\n' 'Swarm installer preflight, mutation, reuse, and immutability checks passed.'
