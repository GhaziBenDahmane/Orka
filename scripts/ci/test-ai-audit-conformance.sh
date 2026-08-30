#!/usr/bin/env bash
set -euo pipefail

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
evidence_file="${DOCKYARD_AI_AUDIT_EVIDENCE:-ai-audit-conformance.json}"
postgres_image="${DOCKYARD_AI_AUDIT_POSTGRES_IMAGE:-postgres@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193}"
run_id="$$-${RANDOM}"
postgres_container="dockyard-ai-audit-postgres-${run_id}"
work_dir=$(mktemp -d)

cleanup() {
  docker rm -f "$postgres_container" >/dev/null 2>&1 || true
  rm -rf "$work_dir"
}
trap cleanup EXIT INT TERM

for command in docker go jq; do
  command -v "$command" >/dev/null || { echo "$command is required for AI audit conformance" >&2; exit 1; }
done

cd "$root_dir"
go test -c -o "$work_dir/dockyard.test" ./cmd/dockyard

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
export DOCKYARD_AI_AUDIT_CONFORMANCE=1

"$work_dir/dockyard.test" \
  -test.timeout=2m \
  -test.run='^TestAIAuditorEndToEndConformance$' \
  -test.count=1 -test.v | tee "$work_dir/conformance.log"

grep -F -- '--- PASS: TestAIAuditorEndToEndConformance ' "$work_dir/conformance.log" >/dev/null
sed -n 's/^AI_AUDIT_EVIDENCE //p' "$work_dir/conformance.log" >"$work_dir/evidence.json"
test "$(wc -l <"$work_dir/evidence.json")" -eq 1

jq \
  --arg sourceCommit "${GITHUB_SHA:-$(git rev-parse HEAD)}" \
  --arg createdAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '. + {
    sourceCommit:$sourceCommit,
    createdAt:$createdAt,
    externalModelGateway:"staging-required"
  }' "$work_dir/evidence.json" >"$evidence_file"

jq -e '
  .status == "passed" and .realPlatformAPI and
  .openAICompatibleGateway and .snapshotSecretsRedacted and
  .promptInjectionBoundaryPresent and .deterministicFindingsPersisted and
  .deployedImageProvenanceAudited and
  .agentCAMismatchDetected and .agentImageProvenanceAudited and
  .databaseAvailabilityAudited and
  .customTLSValidityAudited and .edgeTLSConvergenceAudited and
  .modelFindingsPersisted and .durableRunCompleted and
  .lifecycleAudited and .auditorLeastPrivilege and
  .findingTriageAudited and .findingTriageAtomic and .criticalFindingNotified and .auditorTriageDenied and
  .triageTenantIsolated and
  (.sourceCommit | test("^[a-f0-9]{40}$"))
' "$evidence_file" >/dev/null

cat "$evidence_file"
