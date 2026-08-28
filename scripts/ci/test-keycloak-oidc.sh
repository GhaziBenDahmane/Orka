#!/usr/bin/env bash
set -euo pipefail

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
run_id="$$-${RANDOM}"
keycloak_container="dockyard-keycloak-${run_id}"
postgres_container="dockyard-keycloak-postgres-${run_id}"
work_dir=$(mktemp -d)

cleanup() {
  docker rm -f "$keycloak_container" "$postgres_container" >/dev/null 2>&1 || true
  rm -rf "$work_dir"
}
trap cleanup EXIT INT TERM

# Compile before replacing SSL_CERT_FILE with the ephemeral Keycloak CA so a
# cold Go module cache can still use the host's normal public trust roots.
go test -c -o "$work_dir/httpapi-conformance.test" ./internal/httpapi

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  -keyout "$work_dir/keycloak.key" -out "$work_dir/keycloak.crt" >/dev/null 2>&1
chmod 644 "$work_dir/keycloak.key" "$work_dir/keycloak.crt"

docker run -d --name "$postgres_container" -p 127.0.0.1::5432 \
  -e POSTGRES_USER=dockyard -e POSTGRES_PASSWORD=dockyard -e POSTGRES_DB=dockyard_test \
  "${POSTGRES_IMAGE:-postgres@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193}" >/dev/null
postgres_port=$(docker port "$postgres_container" 5432/tcp | awk -F: 'NR==1 {print $NF}')

docker run -d --name "$keycloak_container" -p 127.0.0.1::8443 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -v "$work_dir/keycloak.crt:/opt/keycloak/conf/server.crt:ro" \
  -v "$work_dir/keycloak.key:/opt/keycloak/conf/server.key:ro" \
  -v "$root_dir/deploy/conformance/keycloak-realm.json:/opt/keycloak/data/import/dockyard-realm.json:ro" \
  "${KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak@sha256:98fab020a3a490aba0978f237e2a06cd0ea42bf149c6cf10f11c0aaf27728ff2}" start-dev --import-realm \
  --https-certificate-file=/opt/keycloak/conf/server.crt \
  --https-certificate-key-file=/opt/keycloak/conf/server.key \
  --hostname-strict=false >/dev/null
keycloak_port=$(docker port "$keycloak_container" 8443/tcp | awk -F: 'NR==1 {print $NF}')
issuer="https://localhost:${keycloak_port}/realms/dockyard-conformance"

for _ in $(seq 1 90); do
  postgres_ready=false
  keycloak_ready=false
  docker exec "$postgres_container" pg_isready -U dockyard -d dockyard_test >/dev/null 2>&1 && postgres_ready=true
  curl --fail --silent --cacert "$work_dir/keycloak.crt" "$issuer/.well-known/openid-configuration" >/dev/null 2>&1 && keycloak_ready=true
  if "$postgres_ready" && "$keycloak_ready"; then
    break
  fi
  sleep 2
done
if ! docker exec "$postgres_container" pg_isready -U dockyard -d dockyard_test >/dev/null 2>&1; then
  docker logs "$postgres_container"
  exit 1
fi
if ! curl --fail --silent --cacert "$work_dir/keycloak.crt" "$issuer/.well-known/openid-configuration" >/dev/null; then
  docker logs "$keycloak_container"
  exit 1
fi

export SSL_CERT_FILE="$work_dir/keycloak.crt"
export DOCKYARD_TEST_DATABASE_URL="postgres://dockyard:dockyard@127.0.0.1:${postgres_port}/dockyard_test?sslmode=disable"
export DOCKYARD_TEST_KEYCLOAK_ISSUER="$issuer"
"$work_dir/httpapi-conformance.test" -test.timeout=5m -test.run='^TestKeycloakOIDCConformance$' -test.count=1 -test.v
