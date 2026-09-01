#!/usr/bin/env bash
set -euo pipefail

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
evidence_file="${DOCKYARD_NOTIFICATION_EVIDENCE:-notification-conformance.json}"
postgres_image="${DOCKYARD_NOTIFICATION_POSTGRES_IMAGE:-postgres@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193}"
run_id="$$-${RANDOM}"
postgres_container="dockyard-notification-postgres-${run_id}"
work_dir=$(mktemp -d)

cleanup() {
  docker rm -f "$postgres_container" >/dev/null 2>&1 || true
  rm -rf "$work_dir"
}
handle_signal() {
  local status="$1"
  trap - EXIT HUP INT TERM
  cleanup
  exit "$status"
}
trap cleanup EXIT
trap 'handle_signal 129' HUP
trap 'handle_signal 130' INT
trap 'handle_signal 143' TERM

for command in docker go jq; do
  command -v "$command" >/dev/null || { echo "$command is required for notification conformance" >&2; exit 1; }
done

cd "$root_dir"
go test -c -o "$work_dir/deploy.test" ./internal/deploy
go test -c -o "$work_dir/store.test" ./internal/store
go test -c -o "$work_dir/auditor.test" ./cmd/dockyard
go test -c -o "$work_dir/observability.test" ./internal/observability

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
export DOCKYARD_NOTIFICATION_CONFORMANCE=1

"$work_dir/deploy.test" \
  -test.timeout=2m \
  -test.run='^(TestNotificationProviderConformance|TestTerminalFailureAndNotificationOutboxAreAtomic|TestSeparateTerminalOperationsNotifyForTheSameResource)$' \
  -test.count=1 -test.v | tee "$work_dir/conformance.log"

"$work_dir/store.test" \
  -test.timeout=2m \
  -test.run='^(TestCommitStatusFailuresUseDeploymentTenantEvent|TestEdgeCertificateFailureNotificationsFanOutToAffectedTenants|TestNotificationDeliveryHistoryAndAuditedRedrive)$' \
  -test.count=1 -test.v | tee -a "$work_dir/conformance.log"

"$work_dir/auditor.test" \
  -test.timeout=2m \
  -test.run='^TestDeterministicAuditDetectsExhaustedNotificationDelivery$' \
  -test.count=1 -test.v | tee -a "$work_dir/conformance.log"

(
  cd "$root_dir/internal/observability"
  "$work_dir/observability.test" \
    -test.timeout=2m \
    -test.run='^(TestDatabaseMetricsQueriesRemainValid|TestPrometheusAlertsCoverExhaustedNotificationDeliveries)$' \
    -test.count=1 -test.v
) | tee -a "$work_dir/conformance.log"

grep -F -- '--- PASS: TestNotificationProviderConformance ' "$work_dir/conformance.log" >/dev/null
grep -F -- '--- PASS: TestTerminalFailureAndNotificationOutboxAreAtomic ' "$work_dir/conformance.log" >/dev/null
grep -F -- '--- PASS: TestSeparateTerminalOperationsNotifyForTheSameResource ' "$work_dir/conformance.log" >/dev/null
grep -F -- '--- PASS: TestEdgeCertificateFailureNotificationsFanOutToAffectedTenants ' "$work_dir/conformance.log" >/dev/null
grep -F -- '--- PASS: TestCommitStatusFailuresUseDeploymentTenantEvent ' "$work_dir/conformance.log" >/dev/null
grep -F -- '--- PASS: TestNotificationDeliveryHistoryAndAuditedRedrive ' "$work_dir/conformance.log" >/dev/null
grep -F -- '--- PASS: TestDeterministicAuditDetectsExhaustedNotificationDelivery ' "$work_dir/conformance.log" >/dev/null
grep -F -- '--- PASS: TestDatabaseMetricsQueriesRemainValid ' "$work_dir/conformance.log" >/dev/null
grep -F -- '--- PASS: TestPrometheusAlertsCoverExhaustedNotificationDeliveries ' "$work_dir/conformance.log" >/dev/null
sed -n 's/^NOTIFICATION_EVIDENCE //p' "$work_dir/conformance.log" >"$work_dir/evidence.json"
test "$(wc -l <"$work_dir/evidence.json")" -eq 1

jq \
  --arg sourceCommit "${GITHUB_SHA:-$(git rev-parse HEAD)}" \
  --arg createdAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '. + {sourceCommit:$sourceCommit,createdAt:$createdAt,realProviderCredentials:"staging-required",atomicTerminalOutbox:true,operationScopedDeduplication:true,edgeCertificateFailureFanout:true,commitStatusFailureNotification:true,auditedDeliveryRedrive:true,exhaustedDeliverySignals:true}' \
  "$work_dir/evidence.json" >"$evidence_file"

jq -e '
  .status == "passed" and .durableWorkerPath and .signedWebhook and
  .slackCompatible and .pagerDuty and .opsgenie and
  .authenticatedImplicitTLSSMTP and .retryRecovered and
  .tenantIsolation and .deduplicated and .secretsEncrypted and
  .offlineRecoveryContext and .atomicTerminalOutbox and
  .operationScopedDeduplication and
  .edgeCertificateFailureFanout and
  .commitStatusFailureNotification and
  .auditedDeliveryRedrive and
  .exhaustedDeliverySignals and
  .deliveries == 6 and .jobAttempts == 7 and
  (.sourceCommit | test("^[a-f0-9]{40}$"))
' "$evidence_file" >/dev/null

cat "$evidence_file"
