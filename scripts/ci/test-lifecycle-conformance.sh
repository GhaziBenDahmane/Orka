#!/usr/bin/env bash
set -euo pipefail

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
evidence_file="${DOCKYARD_LIFECYCLE_EVIDENCE:-lifecycle-conformance.json}"
postgres_image="${DOCKYARD_LIFECYCLE_POSTGRES_IMAGE:-postgres@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193}"
run_id="$$-${RANDOM}"
postgres_container="dockyard-lifecycle-postgres-${run_id}"
work_dir=$(mktemp -d)

cleanup() {
  docker rm -f "$postgres_container" >/dev/null 2>&1 || true
  rm -rf "$work_dir"
}
trap cleanup EXIT INT TERM

for command in docker go jq; do
  command -v "$command" >/dev/null || { echo "$command is required for lifecycle conformance" >&2; exit 1; }
done

cd "$root_dir"
go test -c -o "$work_dir/httpapi.test" ./internal/httpapi
go test -c -o "$work_dir/deploy.test" ./internal/deploy

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
export DOCKYARD_LIFECYCLE_CONFORMANCE=1

"$work_dir/httpapi.test" \
  -test.timeout=1m \
  -test.run='^TestLifecycleAPIConformance$' \
  -test.count=1 -test.v | tee "$work_dir/api.log"

"$work_dir/deploy.test" \
  -test.timeout=1m \
  -test.run='^(TestJobLeaseFencesStaleWorkerAfterTakeover|TestFinishSerializesWithCancellation|TestDeploymentTakeoverRejectsPausedWorkerCompletion|TestRemoteSwarmQueuesEncryptedCommandAndWaitsForFencedResult)$' \
  -test.count=1 -test.v | tee "$work_dir/worker.log"

for test_name in \
  TestJobLeaseFencesStaleWorkerAfterTakeover \
  TestFinishSerializesWithCancellation \
  TestDeploymentTakeoverRejectsPausedWorkerCompletion \
  TestRemoteSwarmQueuesEncryptedCommandAndWaitsForFencedResult; do
  grep -F -- "--- PASS: $test_name " "$work_dir/worker.log" >/dev/null
done

sed -n 's/^LIFECYCLE_EVIDENCE //p' "$work_dir/api.log" >"$work_dir/api-evidence.json"
test "$(wc -l <"$work_dir/api-evidence.json")" -eq 1
source_commit="${GITHUB_SHA:-$(git rev-parse HEAD)}"
created_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
jq \
  --arg sourceCommit "$source_commit" \
  --arg createdAt "$created_at" \
  '. + {
    sourceCommit:$sourceCommit,
    createdAt:$createdAt,
    workerTakeoverFenced:true,
    staleCompletionRejected:true,
    cancellationCompletionRace:true,
    remoteAgentCommand:true,
    notificationProvider:"signed-webhook",
    externalNotificationProviders:"staging-required"
  }' "$work_dir/api-evidence.json" >"$evidence_file"

jq -e '
  .status == "passed" and .deploySucceeded and .deployFailed and
  .deploymentCancelled and .rollbackSucceeded and .resolvedImageSnapshot and
  .signedWebhookAccepted and
  .webhookReplayRejected and .commitStatusDelivered and
  .failureNotificationDelivered and .workerTakeoverFenced and
  .staleCompletionRejected and .cancellationCompletionRace and
  .remoteAgentCommand and (.sourceCommit | test("^[a-f0-9]{40}$"))
' "$evidence_file" >/dev/null

cat "$evidence_file"
