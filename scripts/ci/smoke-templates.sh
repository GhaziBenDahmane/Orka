#!/usr/bin/env bash
set -euo pipefail

project="dockyard-template-smoke"
port="${DOCKYARD_TEMPLATE_SMOKE_PORT:-18081}"
export DOCKYARD_HTTP_BIND="127.0.0.1:$port"
export DOCKYARD_POSTGRES_BIND="${DOCKYARD_POSTGRES_BIND:-127.0.0.1:54339}"
base_url="http://127.0.0.1:$port"
network="dockyard-public"
initialized_swarm=false
created_network=false
stacks=()

wait_for_deployment() {
  local deployment_id="$1"
  local response status=""
  for _ in {1..120}; do
    response="$(curl --fail --silent --show-error "${headers[@]}" "$base_url/v1/deployments/$deployment_id")"
    status="$(jq -er '.status' <<<"$response")"
    [[ "$status" == succeeded ]] && return 0
    if [[ "$status" == failed || "$status" == cancelled ]]; then
      jq . <<<"$response" >&2
      return 1
    fi
    sleep 1
  done
  echo "deployment $deployment_id did not succeed before the timeout" >&2
  return 1
}

wait_for_service() {
  local service_name="$1"
  for _ in {1..90}; do
    if [[ "$(docker service ls --filter "name=$service_name" --format '{{.Replicas}}')" == "1/1" ]]; then
      return 0
    fi
    sleep 1
  done
  docker service ps --no-trunc "$service_name" >&2 || true
  return 1
}

service_container() {
  local service_name="$1"
  docker ps --filter "label=com.docker.swarm.service.name=$service_name" --filter status=running --format '{{.ID}}' | head -1
}

probe_product() {
  local template_key="$1" service_name="$2" stack="$3" container_id postgres_id migration_count
  container_id="$(service_container "$service_name")"
  test -n "$container_id"
  case "$template_key" in
    postgres)
      docker exec --env PGPASSWORD=template-smoke-postgres "$container_id" \
        psql --username smoke --dbname smoke --set ON_ERROR_STOP=1 \
        --command 'CREATE TABLE IF NOT EXISTS dockyard_template_smoke (id integer PRIMARY KEY, value text NOT NULL)' \
        --command "INSERT INTO dockyard_template_smoke(id,value) VALUES (1,'persisted') ON CONFLICT(id) DO UPDATE SET value=excluded.value" >/dev/null
      test "$(docker exec --env PGPASSWORD=template-smoke-postgres "$container_id" psql --username smoke --dbname smoke --tuples-only --no-align --command 'SELECT value FROM dockyard_template_smoke WHERE id=1')" = persisted
      ;;
    redis)
      docker exec "$container_id" redis-cli --no-auth-warning -a template-smoke-redis SET dockyard:template:smoke persisted >/dev/null
      test "$(docker exec "$container_id" redis-cli --no-auth-warning -a template-smoke-redis GET dockyard:template:smoke)" = persisted
      ;;
    barktrace-sqlite)
      docker exec "$container_id" /app/barktrace healthcheck
      docker run --rm --volume "${stack}_barktrace-data:/data:ro" alpine:3.22 test -s /data/barktrace.db
      ;;
    barktrace-postgres)
      docker exec "$container_id" /app/barktrace healthcheck
      postgres_id="$(service_container "${stack}_postgres")"
      test -n "$postgres_id"
      migration_count="$(docker exec --env PGPASSWORD=template-smoke-barktrace "$postgres_id" psql --username barktrace --dbname barktrace --tuples-only --no-align --command 'SELECT count(*) FROM schema_migrations')"
      test "$migration_count" -gt 0
      ;;
  esac
}

cleanup() {
  for stack in "${stacks[@]}"; do docker stack rm "$stack" >/dev/null 2>&1 || true; done
  docker compose --project-name "$project" down --volumes --remove-orphans >/dev/null 2>&1 || true
  if [[ "$created_network" == true ]]; then docker network rm "$network" >/dev/null 2>&1 || true; fi
  if [[ "$initialized_swarm" == true ]]; then docker swarm leave --force >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

if [[ "$(docker info --format '{{.Swarm.LocalNodeState}}')" != "active" ]]; then docker swarm init --advertise-addr 127.0.0.1 >/dev/null; initialized_swarm=true; fi
if ! docker network inspect "$network" >/dev/null 2>&1; then docker network create --driver overlay --attachable "$network" >/dev/null; created_network=true; fi

if [[ "${DOCKYARD_TEMPLATE_SMOKE_PREBUILT:-false}" == "true" ]]; then
  docker image inspect "$project-dockyard" >/dev/null
  docker compose --project-name "$project" up --detach --no-build
elif [[ -n "${DOCKYARD_BUILD_CA_CERT:-}" ]]; then
  test -r "$DOCKYARD_BUILD_CA_CERT"
  docker build --secret "id=build_ca,src=$DOCKYARD_BUILD_CA_CERT" --tag "$project-dockyard" .
  docker compose --project-name "$project" up --detach --no-build
else
  docker compose --project-name "$project" up --detach --build
fi
for _ in {1..90}; do curl --fail --silent "$base_url/readyz" >/dev/null && break; sleep 2; done
curl --fail --silent "$base_url/readyz" >/dev/null

bootstrap="$(curl --fail --silent --show-error -H 'Content-Type: application/json' --data '{"email":"templates@example.test","password":"correct horse battery staple","organization":"Template Smoke"}' "$base_url/v1/auth/bootstrap")"
token="$(jq -er '.token' <<<"$bootstrap")"
organization="$(jq -er '.principal.organizationId' <<<"$bootstrap")"
headers=(-H "Authorization: Bearer $token" -H "X-Organization-ID: $organization" -H 'Content-Type: application/json')
project_id="$(curl --fail --silent --show-error "${headers[@]}" --data '{"name":"Products","slug":"products"}' "$base_url/v1/projects" | jq -er '.id')"
environment_id="$(curl --fail --silent --show-error "${headers[@]}" --data '{"name":"Test","slug":"test"}' "$base_url/v1/projects/$project_id/environments" | jq -er '.id')"
catalog="$(curl --fail --silent --show-error "${headers[@]}" "$base_url/v1/templates")"

for template_key in postgres redis barktrace-sqlite barktrace-postgres; do
  template_id="$(jq -er --arg key "$template_key" '.items[] | select(.key==$key) | .id' <<<"$catalog")"
  case "$template_key" in
    postgres)
      variables='{"postgres_user":"smoke","postgres_password":"template-smoke-postgres","postgres_database":"smoke"}'
      ;;
    redis)
      variables='{"redis_password":"template-smoke-redis"}'
      ;;
    barktrace-sqlite)
      variables="{\"domain\":\"barktrace-sqlite.example.test\",\"barktrace_version\":\"${DOCKYARD_TEMPLATE_SMOKE_BARKTRACE_VERSION:-0.31.0}\",\"oidc_issuer_url\":\"${DOCKYARD_TEMPLATE_SMOKE_OIDC_ISSUER:-https://accounts.google.com}\",\"oidc_client_id\":\"dockyard-template-smoke\",\"oidc_client_secret\":\"template-smoke-oidc-secret\",\"mcp_token\":\"template-smoke-mcp-token-0000000000000000\"}"
      ;;
    barktrace-postgres)
      variables="{\"domain\":\"barktrace-postgres.example.test\",\"barktrace_version\":\"${DOCKYARD_TEMPLATE_SMOKE_BARKTRACE_VERSION:-0.31.0}\",\"postgres_password\":\"template-smoke-barktrace\",\"oidc_issuer_url\":\"${DOCKYARD_TEMPLATE_SMOKE_OIDC_ISSUER:-https://accounts.google.com}\",\"oidc_client_id\":\"dockyard-template-smoke\",\"oidc_client_secret\":\"template-smoke-oidc-secret\",\"mcp_token\":\"template-smoke-mcp-token-0000000000000000\"}"
      ;;
  esac
  service="$(curl --fail --silent --show-error "${headers[@]}" --data "{\"environmentId\":\"$environment_id\",\"name\":\"$template_key\",\"variables\":$variables}" "$base_url/v1/templates/$template_id/instantiate")"
  service_id="$(jq -er '.service.id' <<<"$service")"
  stack="$(jq -er '.service.stackName' <<<"$service")"
  stacks+=("$stack")
  deployment_id="$(curl --fail --silent --show-error "${headers[@]}" --data '{}' "$base_url/v1/services/$service_id/deployments" | jq -er '.id')"
  wait_for_deployment "$deployment_id"
  service_name="${stack}_${template_key}"
  if [[ "$template_key" == barktrace-sqlite ]]; then service_name="${stack}_barktrace"; fi
  wait_for_service "$service_name"
  probe_product "$template_key" "$service_name" "$stack"

  docker service update --force --detach=false "$service_name" >/dev/null
  wait_for_service "$service_name"
  probe_product "$template_key" "$service_name" "$stack"
done

printf 'Built-in PostgreSQL, Redis, BarkTrace SQLite, and BarkTrace PostgreSQL templates deployed and retained state across Swarm task replacement.\n'
