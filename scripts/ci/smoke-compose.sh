#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
project="dockyard-smoke"
smoke_port="${DOCKYARD_SMOKE_PORT:-8080}"
export DOCKYARD_HTTP_BIND="${DOCKYARD_HTTP_BIND:-127.0.0.1:$smoke_port}"
base_url="http://127.0.0.1:$smoke_port"
public_network="dockyard-public"
initialized_swarm=false
created_network=false
stack_name=""
recovery_root="$(mktemp -d)"
evidence_file="${DOCKYARD_CONTROL_PLANE_RECOVERY_EVIDENCE:-$recovery_root/control-plane-recovery-conformance.json}"
openssl genpkey -algorithm ED25519 -out "$recovery_root/signing-key.pem" >/dev/null 2>&1
openssl pkey -in "$recovery_root/signing-key.pem" -pubout -out "$recovery_root/verify-key.pem" >/dev/null 2>&1
openssl genrsa -traditional -out "$recovery_root/agent-ca.key" 3072 >/dev/null 2>&1
openssl req -x509 -new -key "$recovery_root/agent-ca.key" -days 2 -subj '/CN=Dockyard Recovery Test Agent CA' \
  -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign,digitalSignature' \
  -out "$recovery_root/agent-ca.crt" >/dev/null 2>&1
chmod 0600 "$recovery_root/signing-key.pem"
chmod 0600 "$recovery_root/agent-ca.key"
export DOCKYARD_RECOVERY_SIGNING_KEY_FILE="$recovery_root/signing-key.pem"
export DOCKYARD_RECOVERY_VERIFY_KEY_FILE="$recovery_root/verify-key.pem"
export DOCKYARD_AGENT_CA_CERT_FILE="$recovery_root/agent-ca.crt"
export DOCKYARD_AGENT_CA_KEY_FILE="$recovery_root/agent-ca.key"
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
  rm -rf -- "$recovery_root"
}
trap cleanup EXIT

if [[ "$(docker info --format '{{.Swarm.LocalNodeState}}')" != "active" ]]; then
  docker swarm init --advertise-addr 127.0.0.1 >/dev/null
  initialized_swarm=true
fi
if ! docker network inspect "$public_network" >/dev/null 2>&1; then
  docker network create --driver overlay --opt encrypted --attachable "$public_network" >/dev/null
  created_network=true
fi

if [[ "${DOCKYARD_SMOKE_PREBUILT:-false}" == "true" ]]; then
  docker image inspect "$project-dockyard" >/dev/null
  docker compose --project-name "$project" up --detach --no-build
elif [[ -n "${DOCKYARD_BUILD_CA_CERT:-}" ]]; then
  test -r "$DOCKYARD_BUILD_CA_CERT"
  docker build --secret "id=build_ca,src=$DOCKYARD_BUILD_CA_CERT" --tag "$project-dockyard" .
  docker compose --project-name "$project" up --detach --no-build
else
  docker compose --project-name "$project" up --detach --build
fi
for _ in {1..90}; do
  if curl --fail --silent "$base_url/readyz" >/dev/null; then
    break
  fi
  sleep 2
done
curl --fail --silent "$base_url/readyz" >/dev/null

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

updated_service="$(curl --fail --silent --show-error --request PATCH "${auth_headers[@]}" \
  --data '{"composeYaml":"services:\n  web:\n    image: nginx:1.28-alpine\n","environment":{"ROLLBACK_PROBE":"changed"}}' \
  "$base_url/v1/services/$service_id")"
jq --exit-status '.revision == 2 and (.composeYaml | contains("nginx:1.28-alpine"))' <<<"$updated_service" >/dev/null

docker compose --project-name "$project" restart dockyard
for _ in {1..60}; do
  if curl --fail --silent "$base_url/readyz" >/dev/null; then
    break
  fi
  sleep 2
done
curl --fail --silent --show-error "${auth_headers[@]}" "$base_url/v1/me" | jq --exit-status --arg id "$organization_id" '.organizationId == $id' >/dev/null
persisted_service="$(curl --fail --silent --show-error "${auth_headers[@]}" "$base_url/v1/services/$service_id")"
jq --exit-status --arg id "$service_id" '.service.id == $id and .service.revision == 2 and (.service.composeYaml | contains("nginx:1.28-alpine"))' <<<"$persisted_service" >/dev/null

rollback_response="$(curl --fail --silent --show-error "${auth_headers[@]}" \
  --data '{}' "$base_url/v1/services/$service_id/rollback")"
rollback_id="$(jq --exit-status --raw-output '.id' <<<"$rollback_response")"
for _ in {1..120}; do
  rollback_response="$(curl --fail --silent --show-error "${auth_headers[@]}" "$base_url/v1/deployments/$rollback_id")"
  rollback_status="$(jq --exit-status --raw-output '.status' <<<"$rollback_response")"
  if [[ "$rollback_status" == "succeeded" ]]; then
    break
  fi
  if [[ "$rollback_status" == "failed" || "$rollback_status" == "cancelled" ]]; then
    jq . <<<"$rollback_response" >&2
    exit 1
  fi
  sleep 1
done
test "${rollback_status:-}" = "succeeded"
jq --exit-status '.trigger == "rollback" and .revision == 3' <<<"$rollback_response" >/dev/null

rolled_back_service="$(curl --fail --silent --show-error "${auth_headers[@]}" "$base_url/v1/services/$service_id")"
jq --exit-status '.service.revision == 3 and (.service.composeYaml | contains("nginx:1.29-alpine")) and (.service.composeYaml | contains("nginx:1.28-alpine") | not)' <<<"$rolled_back_service" >/dev/null
docker service inspect "${stack_name}_web" --format '{{.Spec.TaskTemplate.ContainerSpec.Image}}' | grep -E '^nginx:1\.29-alpine(@sha256:[a-f0-9]{64})?$'

# Exercise a complete control-plane recovery using the same PostgreSQL tools as
# the bundled production stack. The backup intentionally excludes the master
# key and records only its fingerprint.
controller_image_id="$(docker image inspect "$project-dockyard" --format '{{.Id}}')"
# Compose-built images have a local config digest but no pullable repository
# digest. The restore script accepts this explicit runtime alias only after
# proving its local image ID equals the signed DOCKYARD_IMAGE suffix.
export DOCKYARD_RECOVERY_VERIFIER_IMAGE="$project-dockyard"
export DOCKYARD_RECOVERY_WORK_DIR="$recovery_root"
if DOCKYARD_STACK_NAME="$project" \
  DOCKYARD_POSTGRES_CONTAINER="$project-postgres-1" \
  DOCKYARD_CONTROLLER_CONTAINER="$project-dockyard-1" \
  DOCKYARD_MASTER_KEY='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' \
  DOCKYARD_IMAGE='example.invalid/dockyard@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
  scripts/backup-control-plane.sh "$recovery_root/wrong-controller-image" >/dev/null 2>&1; then
  echo "control-plane backup accepted an image other than the deployed controller" >&2
  exit 1
fi
DOCKYARD_STACK_NAME="$project" \
  DOCKYARD_POSTGRES_CONTAINER="$project-postgres-1" \
  DOCKYARD_CONTROLLER_CONTAINER="$project-dockyard-1" \
  DOCKYARD_MASTER_KEY='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' \
  DOCKYARD_IMAGE="$project-dockyard@$controller_image_id" \
  scripts/backup-control-plane.sh "$recovery_root/control-plane"
test ! -e "$recovery_root/control-plane/master-key.bin"
test ! -e "$recovery_root/control-plane/signing-key.pem"
test ! -e "$recovery_root/control-plane/verify-key.pem"
test "$(wc -c <"$recovery_root/control-plane/manifest.sig" | tr -d ' ')" = "64"
if DOCKYARD_STACK_NAME="$project" \
  DOCKYARD_POSTGRES_CONTAINER="$project-postgres-1" \
  DOCKYARD_CONTROLLER_CONTAINER="$project-dockyard-1" \
  DOCKYARD_RESTORE_CONFIRM="restore:$project" \
  DOCKYARD_MASTER_KEY='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' \
  DOCKYARD_IMAGE="$project-dockyard@$controller_image_id" \
  scripts/restore-control-plane.sh "$recovery_root/control-plane" >/dev/null 2>&1; then
  echo "restore unexpectedly ran while the controller was active" >&2
  exit 1
fi
docker compose --project-name "$project" stop dockyard
cp -a "$recovery_root/control-plane" "$recovery_root/tampered-manifest"
jq '.createdAt = "attacker-controlled"' "$recovery_root/tampered-manifest/manifest.json" >"$recovery_root/tampered-manifest/manifest.updated.json"
mv "$recovery_root/tampered-manifest/manifest.updated.json" "$recovery_root/tampered-manifest/manifest.json"
if DOCKYARD_STACK_NAME="$project" \
  DOCKYARD_POSTGRES_CONTAINER="$project-postgres-1" \
  DOCKYARD_CONTROLLER_CONTAINER="$project-dockyard-1" \
  DOCKYARD_RESTORE_CONFIRM="restore:$project" \
  DOCKYARD_MASTER_KEY='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' \
  DOCKYARD_IMAGE="$project-dockyard@$controller_image_id" \
  scripts/restore-control-plane.sh "$recovery_root/tampered-manifest" >/dev/null 2>&1; then
  echo "restore unexpectedly accepted a modified signed manifest" >&2
  exit 1
fi
cp -a "$recovery_root/control-plane" "$recovery_root/tampered"
printf 'tampered' >>"$recovery_root/tampered/database.dump"
if DOCKYARD_STACK_NAME="$project" \
  DOCKYARD_POSTGRES_CONTAINER="$project-postgres-1" \
  DOCKYARD_CONTROLLER_CONTAINER="$project-dockyard-1" \
  DOCKYARD_RESTORE_CONFIRM="restore:$project" \
  DOCKYARD_MASTER_KEY='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' \
  DOCKYARD_IMAGE="$project-dockyard@$controller_image_id" \
  scripts/restore-control-plane.sh "$recovery_root/tampered" >/dev/null 2>&1; then
  echo "restore unexpectedly accepted a modified database dump" >&2
  exit 1
fi
cp -a "$recovery_root/control-plane" "$recovery_root/wrong-stack"
jq '.stack = "different-stack"' "$recovery_root/wrong-stack/manifest.json" >"$recovery_root/wrong-stack/manifest.updated.json"
mv "$recovery_root/wrong-stack/manifest.updated.json" "$recovery_root/wrong-stack/manifest.json"
openssl pkeyutl -sign -rawin -inkey "$DOCKYARD_RECOVERY_SIGNING_KEY_FILE" -in "$recovery_root/wrong-stack/manifest.json" -out "$recovery_root/wrong-stack/manifest.sig"
if DOCKYARD_STACK_NAME="$project" \
  DOCKYARD_POSTGRES_CONTAINER="$project-postgres-1" \
  DOCKYARD_CONTROLLER_CONTAINER="$project-dockyard-1" \
  DOCKYARD_RESTORE_CONFIRM="restore:$project" \
  DOCKYARD_MASTER_KEY='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' \
  DOCKYARD_IMAGE="$project-dockyard@$controller_image_id" \
  scripts/restore-control-plane.sh "$recovery_root/wrong-stack" >/dev/null 2>&1; then
  echo "restore unexpectedly accepted a bundle for another stack" >&2
  exit 1
fi
openssl genrsa -traditional -out "$recovery_root/wrong-agent-ca.key" 3072 >/dev/null 2>&1
chmod 0600 "$recovery_root/wrong-agent-ca.key"
if DOCKYARD_STACK_NAME="$project" \
  DOCKYARD_POSTGRES_CONTAINER="$project-postgres-1" \
  DOCKYARD_CONTROLLER_CONTAINER="$project-dockyard-1" \
  DOCKYARD_RESTORE_CONFIRM="restore:$project" \
  DOCKYARD_MASTER_KEY='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' \
  DOCKYARD_AGENT_CA_KEY_FILE="$recovery_root/wrong-agent-ca.key" \
  DOCKYARD_IMAGE="$project-dockyard@$controller_image_id" \
  scripts/restore-control-plane.sh "$recovery_root/control-plane" >/dev/null 2>&1; then
  echo "restore unexpectedly accepted a mismatched agent CA private key" >&2
  exit 1
fi
if DOCKYARD_STACK_NAME="$project" \
  DOCKYARD_POSTGRES_CONTAINER="$project-postgres-1" \
  DOCKYARD_CONTROLLER_CONTAINER="$project-dockyard-1" \
  DOCKYARD_RESTORE_CONFIRM="restore:$project" \
  DOCKYARD_MASTER_KEY='AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=' \
  DOCKYARD_IMAGE="$project-dockyard@$controller_image_id" \
  scripts/restore-control-plane.sh "$recovery_root/control-plane" >/dev/null 2>&1; then
  echo "restore unexpectedly accepted the wrong master key" >&2
  exit 1
fi
docker compose --project-name "$project" exec -T postgres \
  psql --username dockyard --dbname dockyard --command "DELETE FROM projects WHERE id='$project_id'" >/dev/null
remaining_projects="$(docker compose --project-name "$project" exec -T postgres \
  psql --username dockyard --dbname dockyard --tuples-only --no-align \
  --command "SELECT count(*) FROM projects WHERE id='$project_id'")"
test "$remaining_projects" = "0"
cp -a "$recovery_root/control-plane" "$recovery_root/wrong-schema"
jq '.schemaVersion = "not-the-restored-version"' "$recovery_root/wrong-schema/manifest.json" >"$recovery_root/wrong-schema/manifest.updated.json"
mv "$recovery_root/wrong-schema/manifest.updated.json" "$recovery_root/wrong-schema/manifest.json"
openssl pkeyutl -sign -rawin -inkey "$DOCKYARD_RECOVERY_SIGNING_KEY_FILE" -in "$recovery_root/wrong-schema/manifest.json" -out "$recovery_root/wrong-schema/manifest.sig"
if DOCKYARD_STACK_NAME="$project" \
  DOCKYARD_POSTGRES_CONTAINER="$project-postgres-1" \
  DOCKYARD_CONTROLLER_CONTAINER="$project-dockyard-1" \
  DOCKYARD_RESTORE_CONFIRM="restore:$project" \
  DOCKYARD_MASTER_KEY='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' \
  DOCKYARD_IMAGE="$project-dockyard@$controller_image_id" \
  scripts/restore-control-plane.sh "$recovery_root/wrong-schema" >/dev/null 2>&1; then
  echo "restore unexpectedly cut over a staging database with the wrong schema" >&2
  exit 1
fi
test "$(docker compose --project-name "$project" exec -T postgres psql --username dockyard --dbname dockyard --tuples-only --no-align --command "SELECT count(*) FROM projects WHERE id='$project_id'")" = "0"
test "$(docker compose --project-name "$project" exec -T postgres psql --username dockyard --dbname postgres --tuples-only --no-align --command "SELECT count(*) FROM pg_database WHERE datname LIKE 'dockyard_restore_%'")" = "0"
restore_output="$(DOCKYARD_STACK_NAME="$project" \
  DOCKYARD_POSTGRES_CONTAINER="$project-postgres-1" \
  DOCKYARD_CONTROLLER_CONTAINER="$project-dockyard-1" \
  DOCKYARD_RESTORE_CONFIRM="restore:$project" \
  DOCKYARD_MASTER_KEY='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' \
  DOCKYARD_IMAGE="$project-dockyard@$controller_image_id" \
  scripts/restore-control-plane.sh "$recovery_root/control-plane")"
previous_database="$(printf '%s\n' "$restore_output" | sed -n 's/^previous database retained for rollback: //p')"
test -n "$previous_database"
test "$(docker compose --project-name "$project" exec -T postgres psql --username dockyard --dbname "$previous_database" --tuples-only --no-align --command "SELECT count(*) FROM projects WHERE id='$project_id'")" = "0"
test "$(docker compose --project-name "$project" exec -T postgres psql --username dockyard --dbname dockyard --tuples-only --no-align --command "SELECT count(*) FROM projects WHERE id='$project_id'")" = "1"
docker compose --project-name "$project" exec -T postgres dropdb --username dockyard --maintenance-db postgres --force "$previous_database"
docker compose --project-name "$project" start dockyard
for _ in {1..60}; do
  if curl --fail --silent "$base_url/readyz" >/dev/null; then
    break
  fi
  sleep 2
done
curl --fail --silent --show-error "${auth_headers[@]}" "$base_url/v1/services/$service_id" |
  jq --exit-status --arg id "$service_id" '.service.id == $id and .service.revision == 3' >/dev/null

mkdir -p "$(dirname "$evidence_file")"
jq -n \
  --arg sourceCommit "${GITHUB_SHA:-$(git -C "$root" rev-parse HEAD)}" \
  --arg createdAt "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
  --arg controllerImage "$project-dockyard@$controller_image_id" \
  --arg schemaVersion "$(jq -er '.schemaVersion' "$recovery_root/control-plane/manifest.json")" \
  --argjson databaseBytes "$(jq -er '.databaseBytes' "$recovery_root/control-plane/manifest.json")" \
  '{status:"passed",sourceCommit:$sourceCommit,createdAt:$createdAt,controllerImage:$controllerImage,schemaVersion:$schemaVersion,databaseBytes:$databaseBytes,signedManifestVerified:true,singleSnapshotMetadataVerified:true,deploymentIdentityBound:true,agentCAKeypairVerified:true,mismatchedAgentCAKeyRejected:true,runningControllerRejected:true,tamperedManifestRejected:true,tamperedDumpRejected:true,wrongMasterKeyRejected:true,schemaMismatchRejected:true,privateDumpSnapshotVerified:true,stagedCutoverVerified:true,rollbackDatabaseRetained:true,authenticatedStateRecovered:true,candidateVerifierImage:"",candidateManifestVerifierVerified:false,candidateTamperedManifestRejected:false,candidateAgentCAKeypairVerified:false,auditChainContinuity:"production-required"}' \
  >"$evidence_file"
jq -e '
  .status == "passed" and (.sourceCommit | test("^[a-f0-9]{40}$")) and
  (.controllerImage | test("@sha256:[a-f0-9]{64}$")) and
  (.schemaVersion | test("^[A-Za-z0-9._-]+$")) and .databaseBytes > 0 and
  .signedManifestVerified and .singleSnapshotMetadataVerified and .deploymentIdentityBound and
  .agentCAKeypairVerified and .mismatchedAgentCAKeyRejected and
  .runningControllerRejected and .tamperedManifestRejected and .tamperedDumpRejected and
  .wrongMasterKeyRejected and .schemaMismatchRejected and .privateDumpSnapshotVerified and
  .stagedCutoverVerified and .rollbackDatabaseRetained and .authenticatedStateRecovered and
  .candidateVerifierImage == "" and (.candidateManifestVerifierVerified | not) and
  (.candidateTamperedManifestRejected | not) and (.candidateAgentCAKeypairVerified | not) and
  .auditChainContinuity == "production-required"
' "$evidence_file" >/dev/null
cat "$evidence_file"
