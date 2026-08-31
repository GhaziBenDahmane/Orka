#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)

unsafe=$(grep -R -n -E 'trap[[:space:]]+cleanup[[:space:]]+EXIT.*(HUP|INT|TERM)' \
  "$root/scripts" --include='*.sh' || true)
if [ -n "$unsafe" ]; then
  echo "unsafe combined EXIT/signal cleanup traps found:" >&2
  printf '%s\n' "$unsafe" >&2
  exit 1
fi

for relative_path in \
  scripts/install-swarm.sh \
  scripts/install-agent.sh \
  scripts/install-ai-auditors.sh \
  scripts/backup-control-plane.sh \
  scripts/restore-control-plane.sh \
  scripts/backup-ai-gateway.sh \
  scripts/restore-ai-gateway.sh \
  scripts/ci/check-licenses.sh \
  scripts/ci/test-agent-certificate-conformance.sh \
  scripts/ci/test-ai-audit-conformance.sh \
  scripts/ci/test-keycloak-oidc.sh \
  scripts/ci/test-lifecycle-conformance.sh \
  scripts/ci/test-migration-conformance.sh \
  scripts/ci/test-notification-conformance.sh \
  scripts/ci/test-reconciliation-conformance.sh; do
  file="$root/$relative_path"
  grep -Eq "^trap '.* 129' HUP$" "$file" &&
    grep -Eq "^trap '.* 130' INT$" "$file" &&
    grep -Eq "^trap '.* 143' TERM$" "$file" || {
      echo "$relative_path must terminate with conventional nonzero signal statuses" >&2
      exit 1
    }
done

echo 'Shell cleanup traps keep exit and signal handling separate.'
