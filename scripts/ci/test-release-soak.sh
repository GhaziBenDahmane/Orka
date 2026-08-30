#!/usr/bin/env bash
set -euo pipefail

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
release_image="${DOCKYARD_IMAGE:?DOCKYARD_IMAGE is required}"
evidence_file="${DOCKYARD_SOAK_EVIDENCE:-release-soak-evidence.json}"
postgres_image="${DOCKYARD_SOAK_POSTGRES_IMAGE:-postgres@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193}"
metrics_token="${DOCKYARD_SOAK_METRICS_TOKEN:-release-soak-metrics-token-at-least-32-bytes}"
soak_seconds="${DOCKYARD_RELEASE_SOAK_SECONDS:-300}"
run_id="${GITHUB_RUN_ID:-local}-$$"
prefix="dockyard-soak-${run_id//[^A-Za-z0-9_.-]/-}"
network="$prefix-control"
postgres_service="$prefix-postgres"
controller_service="$prefix-controller"
postgres_volume="$prefix-postgres"
initialized_swarm=false

fail() {
  printf 'release soak: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  docker service rm "$controller_service" "$postgres_service" >/dev/null 2>&1 || true
  for _ in {1..30}; do
    docker network rm "$network" >/dev/null 2>&1 && break
    sleep 1
  done
  docker volume rm "$postgres_volume" >/dev/null 2>&1 || true
  if [[ "$initialized_swarm" == true ]]; then
    docker swarm leave --force >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

for command in awk curl date docker grep head jq; do
  command -v "$command" >/dev/null || fail "$command is required"
done
case "$soak_seconds" in
  ''|*[!0-9]*) fail "DOCKYARD_RELEASE_SOAK_SECONDS must be an integer" ;;
esac
(( soak_seconds >= 60 && soak_seconds <= 86400 )) || fail "DOCKYARD_RELEASE_SOAK_SECONDS must be between 60 and 86400"
if ! "$root_dir/scripts/ci/validate-image-reference.sh" "$postgres_image"; then
  fail "DOCKYARD_SOAK_POSTGRES_IMAGE must be pinned by digest"
fi
if ! "$root_dir/scripts/ci/validate-image-reference.sh" "$release_image" && [[ "${DOCKYARD_SOAK_ALLOW_MUTABLE_IMAGE:-false}" != true ]]; then
  fail "DOCKYARD_IMAGE must be pinned by digest"
fi
case "${DOCKYARD_SOAK_SKIP_PULLS:-false}" in
  true|false) ;;
  *) fail "DOCKYARD_SOAK_SKIP_PULLS must be true or false" ;;
esac

if [[ "$(docker info --format '{{.Swarm.LocalNodeState}}')" != active ]]; then
  docker swarm init --advertise-addr 127.0.0.1 >/dev/null
  initialized_swarm=true
fi
if [[ "${DOCKYARD_SOAK_SKIP_PULLS:-false}" != true ]]; then
  docker pull "$release_image" >/dev/null
  docker pull "$postgres_image" >/dev/null
fi
docker network create --driver overlay --opt encrypted --attachable "$network" >/dev/null
docker volume create "$postgres_volume" >/dev/null

docker service create --detach --name "$postgres_service" \
  --constraint node.role==manager --network "$network" \
  --env POSTGRES_USER=dockyard --env POSTGRES_PASSWORD=dockyard --env POSTGRES_DB=dockyard \
  --mount "type=volume,source=$postgres_volume,target=/var/lib/postgresql/data" \
  "$postgres_image" >/dev/null
postgres_deadline=$((SECONDS + 120))
postgres_ready=false
while (( SECONDS < postgres_deadline )); do
  postgres_container="$(docker ps --filter "label=com.docker.swarm.service.name=$postgres_service" --format '{{.ID}}' | head -1)"
  if [[ -n "$postgres_container" ]] && docker exec "$postgres_container" pg_isready --username dockyard --dbname dockyard >/dev/null 2>&1; then
    postgres_ready=true
    break
  fi
  sleep 2
done
[[ "$postgres_ready" == true ]] || fail "PostgreSQL did not become ready"

docker service create --detach --name "$controller_service" \
  --constraint node.role==manager --network "$network" \
  --publish target=8080,mode=host \
  --env "DOCKYARD_DATABASE_URL=postgres://dockyard:dockyard@$postgres_service:5432/dockyard?sslmode=disable" \
  --env 'DOCKYARD_MASTER_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' \
  --env "DOCKYARD_METRICS_TOKEN=$metrics_token" \
  --env "DOCKYARD_TRAEFIK_NETWORK=$network" \
  --env 'DOCKYARD_PUBLIC_URL=http://127.0.0.1:8080' \
  --mount type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock \
  --health-cmd 'wget --quiet --tries=1 --spider http://127.0.0.1:8080/readyz' \
  --health-interval 5s --health-timeout 3s --health-start-period 10s --health-retries 3 \
  --update-order start-first --update-failure-action rollback --update-monitor 15s \
  --rollback-order stop-first --rollback-monitor 15s \
  "$release_image" >/dev/null

controller_port() {
  local task_id
  task_id="$(docker service ps --filter desired-state=running --quiet "$controller_service" | head -1)"
  [[ -n "$task_id" ]] || return 1
  docker inspect "$task_id" --format '{{(index .Status.PortStatus.Ports 0).PublishedPort}}'
}

published_port=""
base_url=""
ready_deadline=$((SECONDS + 180))
while (( SECONDS < ready_deadline )); do
  published_port="$(controller_port 2>/dev/null || true)"
  base_url="http://127.0.0.1:$published_port"
  if [[ -n "$published_port" && "$published_port" != 0 ]] && curl --fail --silent "$base_url/readyz" >/dev/null; then
    break
  fi
  sleep 2
done
if ! curl --fail --silent "$base_url/readyz" >/dev/null; then
  docker service ps --no-trunc "$controller_service" >&2 || true
  while read -r failed_container; do
    [[ -n "$failed_container" ]] && docker logs "$failed_container" >&2 || true
  done < <(docker ps --all --filter "label=com.docker.swarm.service.name=$controller_service" --format '{{.ID}}')
  fail "release controller did not become ready"
fi
actual_image="$(docker service inspect "$controller_service" --format '{{.Spec.TaskTemplate.ContainerSpec.Image}}')"
[[ "$actual_image" == "$release_image" ]] || fail "controller runs $actual_image instead of $release_image"

bootstrap="$(curl --fail-with-body --silent --show-error --header 'Content-Type: application/json' \
  --data '{"email":"soak@example.test","password":"correct horse battery staple","organization":"Release Soak"}' \
  "$base_url/v1/auth/bootstrap")"
token="$(jq -er '.token' <<<"$bootstrap")"
organization_id="$(jq -er '.principal.organizationId' <<<"$bootstrap")"
auth_headers=(-H "Authorization: Bearer $token" -H "X-Organization-ID: $organization_id")
tenant_metrics_status="$(curl --silent --output /dev/null --write-out '%{http_code}' "${auth_headers[@]}" "$base_url/metrics")"
[[ "$tenant_metrics_status" == 401 ]] || fail "tenant bearer token unexpectedly accessed global metrics (status $tenant_metrics_status)"

started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
start_epoch="$(date +%s)"
deadline=$((start_epoch + soak_seconds))
health_checks=0
while (( $(date +%s) < deadline )); do
  curl --fail --silent "$base_url/healthz" >/dev/null || fail "health check failed during soak"
  curl --fail --silent "$base_url/readyz" >/dev/null || fail "readiness check failed during soak"
  curl --fail --silent "${auth_headers[@]}" "$base_url/v1/me" | \
    jq -e --arg organization "$organization_id" '.organizationId == $organization' >/dev/null || fail "authenticated check failed during soak"
  curl --fail --silent --header "Authorization: Bearer $metrics_token" "$base_url/metrics" | grep -q '^dockyard_http_requests_total' || fail "metrics disappeared during soak"
  replicas="$(docker service ls --filter "name=$controller_service" --format '{{.Replicas}}')"
  [[ "$replicas" == 1/1 ]] || fail "controller replica count changed during soak: $replicas"
  ((health_checks += 1))
  sleep 5
done

docker service update --detach \
  --health-cmd 'exit 1' --health-interval 2s --health-timeout 1s \
  --health-start-period 1s --health-retries 1 \
  "$controller_service" >/dev/null
rollback_deadline=$((SECONDS + 240))
rollback_state=""
while (( SECONDS < rollback_deadline )); do
  rollback_state="$(docker service inspect "$controller_service" --format '{{if .UpdateStatus}}{{.UpdateStatus.State}}{{end}}')"
  case "$rollback_state" in
    rollback_completed) break ;;
    rollback_paused) fail "automatic rollback paused" ;;
  esac
  sleep 3
done
[[ "$rollback_state" == rollback_completed ]] || fail "failed update did not roll back: ${rollback_state:-no update state}"
rolled_back_image="$(docker service inspect "$controller_service" --format '{{.Spec.TaskTemplate.ContainerSpec.Image}}')"
[[ "$rolled_back_image" == "$release_image" ]] || fail "rollback restored $rolled_back_image instead of $release_image"
rolled_back_healthcheck="$(docker service inspect "$controller_service" --format '{{json .Spec.TaskTemplate.ContainerSpec.Healthcheck.Test}}')"
jq -e '.[0] == "CMD-SHELL" and (.[1] | contains("/readyz")) and (.[1] | contains("exit 1") | not)' \
  <<<"$rolled_back_healthcheck" >/dev/null || fail "rollback did not restore the release health check"

recovery_deadline=$((SECONDS + 120))
while (( SECONDS < recovery_deadline )); do
  published_port="$(controller_port 2>/dev/null || true)"
  base_url="http://127.0.0.1:$published_port"
  if [[ "$(docker service ls --filter "name=$controller_service" --format '{{.Replicas}}')" == 1/1 ]] && \
    [[ -n "$published_port" && "$published_port" != 0 ]] && curl --fail --silent "$base_url/readyz" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
curl --fail --silent "$base_url/readyz" >/dev/null || fail "controller did not recover after rollback"
curl --fail --silent "${auth_headers[@]}" "$base_url/v1/me" | \
  jq -e --arg organization "$organization_id" '.organizationId == $organization' >/dev/null || fail "session did not survive rollback"

finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
jq -n \
  --arg status passed --arg image "$release_image" --arg sourceCommit "${GITHUB_SHA:-local}" \
  --arg startedAt "$started_at" --arg finishedAt "$finished_at" --arg rollbackState "$rollback_state" \
  --argjson configuredSoakSeconds "$soak_seconds" --argjson healthChecks "$health_checks" \
  '{status:$status,image:$image,sourceCommit:$sourceCommit,startedAt:$startedAt,finishedAt:$finishedAt,configuredSoakSeconds:$configuredSoakSeconds,healthChecks:$healthChecks,healthVerified:true,readinessVerified:true,authenticationVerified:true,metricsVerified:true,replicaConvergenceVerified:true,failedHealthCheckInjected:true,automaticRollbackVerified:true,originalHealthcheckRestored:true,rollbackState:$rollbackState}' \
  >"$evidence_file"
jq -e '.status == "passed" and .healthVerified and .readinessVerified and .authenticationVerified and .metricsVerified and .replicaConvergenceVerified and .failedHealthCheckInjected and .automaticRollbackVerified and .originalHealthcheckRestored and .rollbackState == "rollback_completed"' "$evidence_file" >/dev/null
cat "$evidence_file"
