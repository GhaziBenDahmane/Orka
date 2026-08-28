#!/usr/bin/env bash
set -euo pipefail

project="dockyard-smoke"
smoke_port="${DOCKYARD_SMOKE_PORT:-8080}"
export DOCKYARD_HTTP_BIND="${DOCKYARD_HTTP_BIND:-127.0.0.1:$smoke_port}"
base_url="http://127.0.0.1:$smoke_port"
public_network="dockyard-public"
initialized_swarm=false
created_network=false
stack_name=""
cleanup() {
  if [[ -n "$stack_name" ]]; then
    docker stack rm "$stack_name" >/dev/null 2>&1 || true
  fi
  docker compose --project-name "$project" down --volumes --remove-orphans
  if [[ "$created_network" == true ]]; then
    for _ in {1..30}; do
      docker network rm "$public_network" >/dev/null 2>&1 && break
      sleep 1
    done
  fi
  if [[ "$initialized_swarm" == true ]]; then
    docker swarm leave --force >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if [[ "$(docker info --format '{{.Swarm.LocalNodeState}}')" != "active" ]]; then
  docker swarm init --advertise-addr 127.0.0.1 >/dev/null
  initialized_swarm=true
fi
if ! docker network inspect "$public_network" >/dev/null 2>&1; then
  docker network create --driver overlay --attachable "$public_network" >/dev/null
  created_network=true
fi

docker compose --project-name "$project" up --detach --build
for _ in {1..90}; do
  if curl --fail --silent "$base_url/healthz" >/dev/null; then
    break
  fi
  sleep 2
done
curl --fail --silent "$base_url/healthz" >/dev/null

bootstrap_response="$(curl --fail --silent --show-error \
  --header 'Content-Type: application/json' \
  --data '{"email":"admin@example.test","password":"correct horse battery staple","organization":"Smoke Test"}' \
  "$base_url/v1/auth/bootstrap")"
token="$(jq --exit-status --raw-output '.token' <<<"$bootstrap_response")"
organization_id="$(jq --exit-status --raw-output '.principal.organizationId' <<<"$bootstrap_response")"
auth_headers=(-H "Authorization: Bearer $token" -H "X-Organization-ID: $organization_id" -H 'Content-Type: application/json')

project_response="$(curl --fail --silent --show-error "${auth_headers[@]}" \
  --data '{"name":"Smoke Project","slug":"smoke-project"}' "$base_url/v1/projects")"
project_id="$(jq --exit-status --raw-output '.id' <<<"$project_response")"
environment_response="$(curl --fail --silent --show-error "${auth_headers[@]}" \
  --data '{"name":"Production","slug":"production"}' "$base_url/v1/projects/$project_id/environments")"
environment_id="$(jq --exit-status --raw-output '.id' <<<"$environment_response")"
service_response="$(curl --fail --silent --show-error "${auth_headers[@]}" \
  --data '{"name":"Web","slug":"web","composeYaml":"services:\n  web:\n    image: nginx:1.29-alpine\n"}' \
  "$base_url/v1/environments/$environment_id/services")"
service_id="$(jq --exit-status --raw-output '.id' <<<"$service_response")"
stack_name="$(jq --exit-status --raw-output '.stackName' <<<"$service_response")"

deployment_response="$(curl --fail --silent --show-error "${auth_headers[@]}" \
  --data '{}' "$base_url/v1/services/$service_id/deployments")"
deployment_id="$(jq --exit-status --raw-output '.id' <<<"$deployment_response")"
for _ in {1..120}; do
  deployment_response="$(curl --fail --silent --show-error "${auth_headers[@]}" "$base_url/v1/deployments/$deployment_id")"
  deployment_status="$(jq --exit-status --raw-output '.status' <<<"$deployment_response")"
  if [[ "$deployment_status" == "succeeded" ]]; then
    break
  fi
  if [[ "$deployment_status" == "failed" || "$deployment_status" == "cancelled" ]]; then
    jq . <<<"$deployment_response" >&2
    exit 1
  fi
  sleep 1
done
test "${deployment_status:-}" = "succeeded"
docker stack services "$stack_name" --format '{{.Name}} {{.Replicas}}' | grep -E "^${stack_name}_web 1/1$"

expected_migrations="$(find internal/store/migrations -maxdepth 1 -name '*.sql' | wc -l | tr -d ' ')"
actual_migrations="$(docker compose --project-name "$project" exec -T postgres \
  psql --username dockyard --dbname dockyard --tuples-only --no-align \
  --command 'SELECT count(*) FROM schema_migrations')"
test "$actual_migrations" = "$expected_migrations"

docker compose --project-name "$project" restart dockyard
for _ in {1..60}; do
  if curl --fail --silent "$base_url/healthz" >/dev/null; then
    break
  fi
  sleep 2
done
curl --fail --silent --show-error "${auth_headers[@]}" "$base_url/v1/me" | jq --exit-status --arg id "$organization_id" '.organizationId == $id' >/dev/null
curl --fail --silent --show-error "${auth_headers[@]}" "$base_url/v1/services/$service_id" | jq --exit-status --arg id "$service_id" '.id == $id' >/dev/null
