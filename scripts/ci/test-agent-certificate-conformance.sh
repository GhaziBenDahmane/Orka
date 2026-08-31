#!/usr/bin/env bash
set -euo pipefail

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
evidence_file="${DOCKYARD_AGENT_CERTIFICATE_EVIDENCE:-agent-certificate-conformance.json}"
postgres_image="${DOCKYARD_AGENT_CERTIFICATE_POSTGRES_IMAGE:-postgres@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193}"
run_id="$$-${RANDOM}"
postgres_container="dockyard-agent-certificate-postgres-${run_id}"
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
  command -v "$command" >/dev/null || { echo "$command is required for agent certificate conformance" >&2; exit 1; }
done

cd "$root_dir"
go test -c -o "$work_dir/httpapi.test" ./internal/httpapi
go test -c -o "$work_dir/agent.test" ./internal/agent

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
export DOCKYARD_AGENT_CERTIFICATE_CONFORMANCE=1

"$work_dir/httpapi.test" \
  -test.timeout=2m \
  -test.run='^TestAgentCertificateMTLSConformance$' \
  -test.count=1 -test.v | tee "$work_dir/conformance.log"

"$work_dir/agent.test" \
  -test.timeout=1m \
  -test.run='^TestRotateCertificateValidatesBeforeAtomicIdentityReplacement$' \
  -test.count=1 -test.v | tee "$work_dir/client.log"

grep -F -- '--- PASS: TestAgentCertificateMTLSConformance ' "$work_dir/conformance.log" >/dev/null
grep -F -- '--- PASS: TestRotateCertificateValidatesBeforeAtomicIdentityReplacement ' "$work_dir/client.log" >/dev/null
sed -n 's/^AGENT_CERTIFICATE_EVIDENCE //p' "$work_dir/conformance.log" >"$work_dir/evidence.json"
test "$(wc -l <"$work_dir/evidence.json")" -eq 1

jq \
  --arg sourceCommit "${GITHUB_SHA:-$(git rev-parse HEAD)}" \
  --arg createdAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '. + {
    sourceCommit:$sourceCommit,
    createdAt:$createdAt,
    invalidReplacementPreservesIdentity:true,
    productionListenerCertificateRotation:"staging-required"
  }' "$work_dir/evidence.json" >"$evidence_file"

jq -e '
  .status == "passed" and .tlsVersion == "1.3" and
  .oldCertificateAuthenticated and .replacementIssuedPending and
  .oldValidBeforeConfirmation and .replacementPromotedOnHeartbeat and
  .oldRejectedAfterPromotion and .wrongClusterRejected and
  .untrustedCARejected and .expiredCertificateRejected and
  .mismatchedKeyRejected and .pendingMetricsConverged and
  .invalidReplacementPreservesIdentity and .caDualTrustMigrationVerified and
  .caFingerprintConverged and .newOnlyListenerVerified and .retiredCARejected and
  (.sourceCommit | test("^[a-f0-9]{40}$"))
' "$evidence_file" >/dev/null

cat "$evidence_file"
