#!/usr/bin/env bash
set -euo pipefail

project="dockyard-smoke"
base_url="http://127.0.0.1:8080"
cleanup() {
  docker compose --project-name "$project" down --volumes --remove-orphans
}
trap cleanup EXIT

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
