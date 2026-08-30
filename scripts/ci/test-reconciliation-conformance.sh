#!/usr/bin/env bash
set -euo pipefail

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
evidence_file="${DOCKYARD_RECONCILIATION_EVIDENCE:-reconciliation-conformance.json}"
postgres_image="${DOCKYARD_RECONCILIATION_POSTGRES_IMAGE:-postgres@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193}"
run_id="$$-${RANDOM}"
postgres_container="dockyard-reconcile-postgres-${run_id}"
work_dir=$(mktemp -d)
created_swarm=false
network_existed=false

cleanup() {
  docker rm -f "$postgres_container" >/dev/null 2>&1 || true
  if [ "$network_existed" = false ]; then
    for _ in $(seq 1 10); do
      docker network rm dockyard-public >/dev/null 2>&1 && break
      sleep 1
    done
  fi
  if [ "$created_swarm" = true ]; then
    docker swarm leave --force >/dev/null 2>&1 || true
  fi
  rm -rf "$work_dir"
}
trap cleanup EXIT INT TERM

for command in docker go jq; do
  command -v "$command" >/dev/null || { echo "$command is required for reconciliation conformance" >&2; exit 1; }
done

cd "$root_dir"
go test -c -o "$work_dir/deploy.test" ./internal/deploy
go test -c -o "$work_dir/store.test" ./internal/store
go test -c -o "$work_dir/observability.test" ./internal/observability

swarm_state=$(docker info --format '{{.Swarm.LocalNodeState}}')
if [ "$swarm_state" != active ]; then
  docker swarm init --advertise-addr 127.0.0.1 >/dev/null
  created_swarm=true
fi
if docker network inspect dockyard-public >/dev/null 2>&1; then
  network_existed=true
fi

docker run -d --name "$postgres_container" -p 127.0.0.1::5432 \
  -e POSTGRES_USER=dockyard -e POSTGRES_PASSWORD=dockyard -e POSTGRES_DB=dockyard_test \
  "$postgres_image" >/dev/null
postgres_port=$(docker port "$postgres_container" 5432/tcp | awk -F: 'NR==1 {print $NF}')
for _ in $(seq 1 60); do
  if docker exec "$postgres_container" pg_isready -U dockyard -d dockyard_test >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
if ! docker exec "$postgres_container" pg_isready -U dockyard -d dockyard_test >/dev/null 2>&1; then
  docker logs "$postgres_container" >&2
  exit 1
fi

export DOCKYARD_TEST_DATABASE_URL="postgres://dockyard:dockyard@127.0.0.1:${postgres_port}/dockyard_test?sslmode=disable"
export DOCKYARD_TEST_SWARM=1

"$work_dir/deploy.test" \
  -test.timeout=3m \
  -test.run='^(TestReconciliationRepairsMissingLiveSwarmStack|TestReconciliationDeploymentUsesEffectiveSnapshotWithoutRebuild)$' \
  -test.count=1 -test.v | tee "$work_dir/deploy.log"

"$work_dir/store.test" \
  -test.timeout=2m \
  -test.run='^(TestReconciliationQueuesImmutableRepairAndSuppressesDuplicates|TestReconciliationHonorsMaintenanceAndNeedsEffectiveSourceSnapshot|TestRemoteReconciliationWaitsForFreshCapacityAfterPartition|TestAIAuditsAndTemplateRepositories)$' \
  -test.count=1 -test.v | tee "$work_dir/store.log"

"$work_dir/observability.test" \
  -test.timeout=1m \
  -test.run='^TestDatabaseMetricsQueriesRemainValid$' \
  -test.count=1 -test.v | tee "$work_dir/observability.log"

while read -r log_file test_name; do
  grep -F -- "--- PASS: $test_name " "$work_dir/$log_file" >/dev/null
done <<'EOF'
deploy.log TestReconciliationRepairsMissingLiveSwarmStack
deploy.log TestReconciliationDeploymentUsesEffectiveSnapshotWithoutRebuild
store.log TestReconciliationQueuesImmutableRepairAndSuppressesDuplicates
store.log TestReconciliationHonorsMaintenanceAndNeedsEffectiveSourceSnapshot
store.log TestRemoteReconciliationWaitsForFreshCapacityAfterPartition
store.log TestAIAuditsAndTemplateRepositories
observability.log TestDatabaseMetricsQueriesRemainValid
EOF

source_commit="${GITHUB_SHA:-$(git rev-parse HEAD)}"
jq -n \
  --arg sourceCommit "$source_commit" \
  --arg createdAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{
    status:"passed",
    sourceCommit:$sourceCommit,
    createdAt:$createdAt,
    localMissingStackRepaired:true,
    twoObservationThreshold:true,
    duplicateRepairSuppressed:true,
    immutableSnapshotPreserved:true,
    desiredEditsPreserved:true,
    maintenanceSuppressed:true,
    activeDeploymentSuppressed:true,
    remoteHeartbeatSuppressed:true,
    remoteCapacitySuppressed:true,
    remoteCapacityRecoveryQueued:true,
    metricsExposed:true,
    aiAuditSnapshotExposed:true,
    productionRemoteUnderReplication:"staging-required"
  }' >"$evidence_file"

jq -e '
  .status == "passed" and .localMissingStackRepaired and
  .twoObservationThreshold and .duplicateRepairSuppressed and
  .immutableSnapshotPreserved and .desiredEditsPreserved and
  .maintenanceSuppressed and .activeDeploymentSuppressed and
  .remoteHeartbeatSuppressed and .remoteCapacitySuppressed and
  .remoteCapacityRecoveryQueued and .metricsExposed and
  .aiAuditSnapshotExposed and (.sourceCommit | test("^[a-f0-9]{40}$"))
' "$evidence_file" >/dev/null

cat "$evidence_file"
