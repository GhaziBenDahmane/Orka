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
for _ in {1..90}; do curl --fail --silent "$base_url/healthz" >/dev/null && break; sleep 2; done
curl --fail --silent "$base_url/healthz" >/dev/null

bootstrap="$(curl --fail --silent --show-error -H 'Content-Type: application/json' --data '{"email":"templates@example.test","password":"correct horse battery staple","organization":"Template Smoke"}' "$base_url/v1/auth/bootstrap")"
token="$(jq -er '.token' <<<"$bootstrap")"
organization="$(jq -er '.principal.organizationId' <<<"$bootstrap")"
headers=(-H "Authorization: Bearer $token" -H "X-Organization-ID: $organization" -H 'Content-Type: application/json')
project_id="$(curl --fail --silent --show-error "${headers[@]}" --data '{"name":"Products","slug":"products"}' "$base_url/v1/projects" | jq -er '.id')"
environment_id="$(curl --fail --silent --show-error "${headers[@]}" --data '{"name":"Test","slug":"test"}' "$base_url/v1/projects/$project_id/environments" | jq -er '.id')"
catalog="$(curl --fail --silent --show-error "${headers[@]}" "$base_url/v1/templates")"

for template_key in postgres redis; do
  template_id="$(jq -er --arg key "$template_key" '.items[] | select(.key==$key) | .id' <<<"$catalog")"
  service="$(curl --fail --silent --show-error "${headers[@]}" --data "{\"environmentId\":\"$environment_id\",\"name\":\"$template_key\",\"variables\":{}}" "$base_url/v1/templates/$template_id/instantiate")"
  service_id="$(jq -er '.service.id' <<<"$service")"
  stack="$(jq -er '.service.stackName' <<<"$service")"
  stacks+=("$stack")
  deployment_id="$(curl --fail --silent --show-error "${headers[@]}" --data '{}' "$base_url/v1/services/$service_id/deployments" | jq -er '.id')"
  status=""
  for _ in {1..120}; do
    status="$(curl --fail --silent --show-error "${headers[@]}" "$base_url/v1/deployments/$deployment_id" | jq -er '.status')"
    [[ "$status" == succeeded ]] && break
    [[ "$status" == failed || "$status" == cancelled ]] && exit 1
    sleep 1
  done
  [[ "$status" == succeeded ]]
  docker stack services "$stack" --format '{{.Replicas}}' | grep -q '^1/1$'
done

printf 'Built-in PostgreSQL and Redis templates deployed and converged on Docker Swarm.\n'
