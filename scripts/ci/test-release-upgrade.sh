#!/usr/bin/env bash
set -euo pipefail

previous_image="${DOCKYARD_PREVIOUS_IMAGE:?DOCKYARD_PREVIOUS_IMAGE is required}"
candidate_image="${DOCKYARD_CANDIDATE_IMAGE:?DOCKYARD_CANDIDATE_IMAGE is required}"
evidence_file="${DOCKYARD_UPGRADE_EVIDENCE:-upgrade-conformance.json}"
postgres_image="${DOCKYARD_UPGRADE_POSTGRES_IMAGE:-postgres@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193}"
master_key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
metrics_token="release-upgrade-metrics-token-at-least-32-bytes"
run_id="${GITHUB_RUN_ID:-local}-$$"
prefix="dockyard-upgrade-${run_id//[^A-Za-z0-9_.-]/-}"
postgres_container="$prefix-postgres"
old_container="$prefix-old"
candidate_container="$prefix-candidate"
bridge_network="$prefix-control"
public_network="$prefix-public"
postgres_volume="$prefix-postgres"
initialized_swarm=false
stable_stack=""
recovery_stack=""

fail() {
  printf 'upgrade conformance: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  if [[ -n "$stable_stack" ]]; then
    docker stack rm "$stable_stack" >/dev/null 2>&1 || true
  fi
  if [[ -n "$recovery_stack" ]]; then
    docker stack rm "$recovery_stack" >/dev/null 2>&1 || true
  fi
  docker rm --force "$old_container" "$candidate_container" "$postgres_container" >/dev/null 2>&1 || true
  for _ in {1..30}; do
    docker network rm "$public_network" >/dev/null 2>&1 && break
    sleep 1
  done
  docker network rm "$bridge_network" >/dev/null 2>&1 || true
  docker volume rm "$postgres_volume" >/dev/null 2>&1 || true
  if [[ "$initialized_swarm" == true ]]; then
    docker swarm leave --force >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

for command in curl docker jq openssl sha256sum; do
  command -v "$command" >/dev/null || fail "$command is required"
done
if [[ "$previous_image" != *@sha256:* && "${DOCKYARD_UPGRADE_ALLOW_MUTABLE_PREVIOUS:-false}" != true ]]; then
  fail "the previous release image must be pinned by digest"
fi
[[ "$candidate_image" != "$previous_image" ]] || fail "candidate and previous image must differ"

if [[ "$(docker info --format '{{.Swarm.LocalNodeState}}')" != active ]]; then
  docker swarm init --advertise-addr 127.0.0.1 >/dev/null
  initialized_swarm=true
fi
docker network create "$bridge_network" >/dev/null
docker network create --driver overlay --opt encrypted --attachable "$public_network" >/dev/null
docker volume create "$postgres_volume" >/dev/null

docker run --detach --name "$postgres_container" \
  --network "$bridge_network" --network-alias postgres \
  --env POSTGRES_USER=dockyard --env POSTGRES_PASSWORD=dockyard \
  --env POSTGRES_DB=dockyard --volume "$postgres_volume:/var/lib/postgresql/data" \
  "$postgres_image" >/dev/null
for _ in {1..60}; do
  if docker exec "$postgres_container" pg_isready --username dockyard --dbname dockyard >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
docker exec "$postgres_container" pg_isready --username dockyard --dbname dockyard >/dev/null

controller_url=""
start_controller() {
  local name=$1 image=$2
  docker run --detach --name "$name" --network "$bridge_network" \
    --publish 127.0.0.1::8080 \
    --env 'DOCKYARD_DATABASE_URL=postgres://dockyard:dockyard@postgres:5432/dockyard?sslmode=disable' \
    --env "DOCKYARD_MASTER_KEY=$master_key" \
    --env "DOCKYARD_METRICS_TOKEN=$metrics_token" \
    --env "DOCKYARD_TRAEFIK_NETWORK=$public_network" \
    --env 'DOCKYARD_PUBLIC_URL=http://127.0.0.1:8080' \
    --volume /var/run/docker.sock:/var/run/docker.sock \
    "$image" >/dev/null
  local port
  port="$(docker inspect "$name" --format '{{(index (index .NetworkSettings.Ports "8080/tcp") 0).HostPort}}')"
  controller_url="http://127.0.0.1:$port"
  for _ in {1..90}; do
    if curl --fail --silent "$controller_url/readyz" >/dev/null; then
      return
    fi
    if [[ "$(docker inspect "$name" --format '{{.State.Running}}')" != true ]]; then
      docker logs "$name" >&2 || true
      fail "$name stopped before becoming ready"
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  fail "$name did not become ready"
}

api() {
  local method=$1 path=$2 data=${3:-}
  local arguments=(--fail-with-body --silent --show-error --request "$method" --header 'Content-Type: application/json')
  if [[ -n "${token:-}" ]]; then
    arguments+=(--header "Authorization: Bearer $token" --header "X-Organization-ID: $organization_id")
  fi
  if [[ -n "$data" ]]; then
    arguments+=(--data "$data")
  fi
  curl "${arguments[@]}" "$controller_url$path"
}

wait_for_deployment() {
  local deployment_id=$1 deadline=$((SECONDS + 180)) response status
  while (( SECONDS < deadline )); do
    response="$(api GET "/v1/deployments/$deployment_id")"
    status="$(jq -er '.status' <<<"$response")"
    case "$status" in
      succeeded) return ;;
      failed|cancelled) jq . <<<"$response" >&2; fail "deployment $deployment_id ended as $status" ;;
    esac
    sleep 2
  done
  fail "deployment $deployment_id did not complete"
}

wait_for_replica() {
  local stack=$1 deadline=$((SECONDS + 120))
  while (( SECONDS < deadline )); do
    if docker stack services "$stack" --format '{{.Replicas}}' 2>/dev/null | grep -qx '1/1'; then
      return
    fi
    sleep 2
  done
  docker stack services "$stack" >&2 || true
  fail "stack $stack did not converge to one replica"
}

psql_scalar() {
  docker exec "$postgres_container" psql --username dockyard --dbname dockyard --tuples-only --no-align --command "$1"
}

start_controller "$old_container" "$previous_image"
bootstrap="$(api POST /v1/auth/bootstrap '{"email":"upgrade@example.test","password":"correct horse battery staple","organization":"Upgrade Conformance"}')"
token="$(jq -er '.token' <<<"$bootstrap")"
organization_id="$(jq -er '.principal.organizationId' <<<"$bootstrap")"
user_id="$(jq -er '.principal.userId' <<<"$bootstrap")"

project="$(api POST /v1/projects '{"name":"Upgrade Project","slug":"upgrade-project"}')"
project_id="$(jq -er '.id' <<<"$project")"
environment="$(api POST "/v1/projects/$project_id/environments" '{"name":"Production","slug":"production"}')"
environment_id="$(jq -er '.id' <<<"$environment")"
compose='services:\n  app:\n    image: redis@sha256:becdda6c7f4b3fb42e42fd7f120bbf5c54c4caaaf16f26da24e4563d2c1f0576\n    environment:\n      STATE_MARKER: ${STATE_MARKER}\n'
stable="$(api POST "/v1/environments/$environment_id/services" "{\"name\":\"Stable\",\"slug\":\"stable\",\"composeYaml\":\"$compose\",\"environment\":{\"STATE_MARKER\":\"preserved\"}}")"
stable_service_id="$(jq -er '.id' <<<"$stable")"
stable_stack="$(jq -er '.stackName' <<<"$stable")"
recovery="$(api POST "/v1/environments/$environment_id/services" "{\"name\":\"Recovery\",\"slug\":\"recovery\",\"composeYaml\":\"$compose\",\"environment\":{\"STATE_MARKER\":\"recovered\"}}")"
recovery_service_id="$(jq -er '.id' <<<"$recovery")"
recovery_stack="$(jq -er '.stackName' <<<"$recovery")"

api POST /v1/source-credentials '{"kind":"registry","name":"Upgrade Registry","server":"registry.example.test","username":"upgrade","secret":"source-secret-survives-upgrade"}' >/dev/null
api POST /v1/sso/oidc-providers '{"name":"Upgrade OIDC","issuer":"https://id.example.test","clientId":"dockyard-upgrade","clientSecret":"oidc-secret-survives-upgrade","domains":["example.test"],"scopes":["openid","email","profile"],"defaultRole":"developer"}' >/dev/null
webhook="$(api POST "/v1/services/$stable_service_id/webhooks" '{"name":"Upgrade Hook","provider":"github","branch":"main"}')"
webhook_id="$(jq -er '.integration.id' <<<"$webhook")"
webhook_secret="$(jq -er '.secret' <<<"$webhook")"

stable_deployment="$(api POST "/v1/services/$stable_service_id/deployments" '{}')"
stable_deployment_id="$(jq -er '.id' <<<"$stable_deployment")"
wait_for_deployment "$stable_deployment_id"
wait_for_replica "$stable_stack"

old_migration_count="$(psql_scalar 'SELECT count(*) FROM schema_migrations')"
old_counts="$(psql_scalar "SELECT json_build_object('users',(SELECT count(*) FROM users),'organizations',(SELECT count(*) FROM organizations),'memberships',(SELECT count(*) FROM memberships),'projects',(SELECT count(*) FROM projects),'environments',(SELECT count(*) FROM environments),'services',(SELECT count(*) FROM compose_services),'sourceCredentials',(SELECT count(*) FROM source_credentials),'oidcProviders',(SELECT count(*) FROM oidc_providers),'webhooks',(SELECT count(*) FROM webhook_integrations))")"
[[ "$(psql_scalar "SELECT encrypted_env <> '' AND encrypted_env NOT LIKE '%preserved%' FROM compose_services WHERE id='$stable_service_id'")" == t ]] || fail "old release did not encrypt service environment"
[[ "$(psql_scalar "SELECT encrypted_secret <> '' AND encrypted_secret NOT LIKE '%survives-upgrade%' FROM source_credentials WHERE organization_id='$organization_id'")" == t ]] || fail "old release did not encrypt source credential"

docker stop --time 20 "$old_container" >/dev/null
recovery_deployment_id="$(cat /proc/sys/kernel/random/uuid)"
recovery_job_id="$(cat /proc/sys/kernel/random/uuid)"
docker exec -i "$postgres_container" psql --username dockyard --dbname dockyard \
  --set=ON_ERROR_STOP=1 --set=deployment_id="$recovery_deployment_id" \
  --set=job_id="$recovery_job_id" --set=service_id="$recovery_service_id" \
  --set=user_id="$user_id" <<'SQL' >/dev/null
BEGIN;
INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,env_snapshot,status,trigger,actor_user_id)
SELECT :'deployment_id'::uuid,id,revision,compose_yaml,encrypted_env,'queued','manual',:'user_id'::uuid
FROM compose_services WHERE id=:'service_id'::uuid;
INSERT INTO jobs(id,kind,payload,status,max_attempts)
VALUES(:'job_id'::uuid,'deploy.compose',jsonb_build_object('deploymentId',:'deployment_id'),'pending',3);
COMMIT;
SQL

start_controller "$candidate_container" "$candidate_image"
login="$(api POST /v1/auth/login '{"email":"upgrade@example.test","password":"correct horse battery staple"}')"
token="$(jq -er '.token' <<<"$login")"
api GET /v1/me | jq -e --arg organization "$organization_id" '.organizationId == $organization' >/dev/null
api GET /v1/source-credentials | jq -e '.items | length == 1 and .[0].name == "Upgrade Registry" and (tostring | contains("survives-upgrade") | not)' >/dev/null
api GET /v1/sso/oidc-providers | jq -e '.items | length == 1 and .[0].name == "Upgrade OIDC" and (tostring | contains("survives-upgrade") | not)' >/dev/null

wait_for_deployment "$recovery_deployment_id"
wait_for_replica "$recovery_stack"
docker service inspect "${recovery_stack}_app" --format '{{json .Spec.TaskTemplate.ContainerSpec.Env}}' | jq -e 'index("STATE_MARKER=recovered") != null' >/dev/null

payload='{"ref":"refs/heads/main","after":"0123456789abcdef0123456789abcdef01234567"}'
signature="$(printf '%s' "$payload" | openssl dgst -sha256 -hmac "$webhook_secret" -hex | awk '{print $NF}')"
webhook_response="$(curl --fail --silent --show-error --request POST \
  --header 'Content-Type: application/json' --header 'X-GitHub-Event: push' \
  --header "X-GitHub-Delivery: upgrade-$run_id" --header "X-Hub-Signature-256: sha256=$signature" \
  --data "$payload" "$controller_url/v1/hooks/provider/$webhook_id")"
webhook_deployment_id="$(jq -er '.id' <<<"$webhook_response")"
wait_for_deployment "$webhook_deployment_id"

new_migration_count="$(psql_scalar 'SELECT count(*) FROM schema_migrations')"
(( new_migration_count >= old_migration_count )) || fail "candidate migration count regressed"
[[ "$(psql_scalar "SELECT count(*) FROM schema_migrations WHERE checksum=''")" == 0 ]] || fail "migration checksum is missing"
for migration in internal/store/migrations/*.sql; do
  version="$(basename "$migration")"
  checksum="$(sha256sum "$migration" | awk '{print $1}')"
  recorded="$(psql_scalar "SELECT checksum FROM schema_migrations WHERE version='$version'")"
  [[ "$recorded" == "$checksum" ]] || fail "migration checksum mismatch for $version"
done

new_counts="$(psql_scalar "SELECT json_build_object('users',(SELECT count(*) FROM users),'organizations',(SELECT count(*) FROM organizations),'memberships',(SELECT count(*) FROM memberships),'projects',(SELECT count(*) FROM projects),'environments',(SELECT count(*) FROM environments),'services',(SELECT count(*) FROM compose_services),'sourceCredentials',(SELECT count(*) FROM source_credentials),'oidcProviders',(SELECT count(*) FROM oidc_providers),'webhooks',(SELECT count(*) FROM webhook_integrations))")"
jq -e --argjson old "$old_counts" --argjson new "$new_counts" -n '$old == $new' >/dev/null || fail "resource counts changed across upgrade"

reconciliation_deadline=$((SECONDS + 150))
while (( SECONDS < reconciliation_deadline )); do
  reconciliation_state="$(psql_scalar "SELECT COALESCE((SELECT state FROM service_reconciliations WHERE compose_service_id='$stable_service_id'),'')")"
  [[ "$reconciliation_state" == healthy ]] && break
  sleep 3
done
[[ "${reconciliation_state:-}" == healthy ]] || fail "existing stack was not reconciled as healthy"

previous_id="$(docker image inspect "$previous_image" --format '{{.Id}}')"
candidate_id="$(docker image inspect "$candidate_image" --format '{{.Id}}')"
created_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
jq -n \
  --arg status passed --arg previousImage "$previous_image" --arg previousImageId "$previous_id" \
  --arg candidateImage "$candidate_image" --arg candidateImageId "$candidate_id" \
  --arg sourceCommit "${GITHUB_SHA:-local}" \
  --arg createdAt "$created_at" --argjson oldMigrationCount "$old_migration_count" \
  --argjson newMigrationCount "$new_migration_count" --argjson resourceCounts "$new_counts" \
  '{status:$status,previousImage:$previousImage,previousImageId:$previousImageId,candidateImage:$candidateImage,candidateImageId:$candidateImageId,sourceCommit:$sourceCommit,createdAt:$createdAt,migrations:{before:$oldMigrationCount,after:$newMigrationCount,checksumsVerified:true},authenticationVerified:true,encryptedSecretsVerified:true,resourceCountsVerified:true,queueRecoveryVerified:true,existingStackReconciliationVerified:true,resourceCounts:$resourceCounts}' \
  >"$evidence_file"
jq -e '.status == "passed" and .migrations.checksumsVerified and .authenticationVerified and .encryptedSecretsVerified and .resourceCountsVerified and .queueRecoveryVerified and .existingStackReconciliationVerified' "$evidence_file" >/dev/null
cat "$evidence_file"
