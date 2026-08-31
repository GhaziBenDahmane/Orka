#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
temporary="$(mktemp -d)"
cleanup() { rm -rf -- "$temporary"; }
trap cleanup EXIT
evidence_file="${DOCKYARD_AI_GATEWAY_RECOVERY_EVIDENCE:-$temporary/ai-gateway-recovery-conformance.json}"

for command in git go jq openssl; do
  command -v "$command" >/dev/null || { echo "$command is required for AI gateway recovery conformance" >&2; exit 1; }
done

mkdir -p "$temporary/bin" "$temporary/output"
openssl genpkey -algorithm ED25519 -out "$temporary/signing-key.pem" >/dev/null 2>&1
openssl pkey -in "$temporary/signing-key.pem" -pubout -out "$temporary/verify-key.pem" >/dev/null 2>&1
openssl rand -base64 32 | tr -d '=\n' >"$temporary/backup-key"
printf '%s' 'https://objects.example.test/ai-gateway?signature=upload-secret' >"$temporary/put-url"
printf '%s' 'https://objects.example.test/ai-gateway?signature=download-secret' >"$temporary/get-url"
chmod 0600 "$temporary/signing-key.pem" "$temporary/verify-key.pem" "$temporary/backup-key" "$temporary/put-url" "$temporary/get-url"

cat >"$temporary/bin/docker" <<'MOCK'
#!/bin/sh
set -eu
printf '%s\n' "$*" >>"$ORKA_AI_RECOVERY_TEST_LOG"
case "$1 $2" in
  "info --format") printf '%s\n' 'active true' ;;
  "node inspect") printf '%s\n' 'ready active' ;;
  "service inspect")
    case "$4" in
      *ContainerSpec.Image*) printf '%s\n' "$NINEROUTER_IMAGE" ;;
      *UpdateStatus*) printf '%s\n' 'completed' ;;
      *Mounts*) printf '%s\n' '[{"Type":"volume","Source":"dockyard-ai_nine-router-data","Target":"/app/data"}]' ;;
      *Replicas*) printf '%s\n' "${ORKA_AI_RECOVERY_TEST_REPLICAS:-1}" ;;
      *) exit 1 ;;
    esac ;;
  "run --rm")
    case "$*" in *' validate-volume-artifact-job '*) ;; *) exit 1 ;; esac ;;
  "service scale") ;;
  "secret create") ;;
  "service create") ;;
  "service ps")
    if [ "${ORKA_AI_RECOVERY_TEST_FAIL_TASK:-false}" = true ]; then printf '%s\n' 'Failed 1 second ago|sensitive failure'; else printf '%s\n' 'Complete 1 second ago|'; fi ;;
  "service logs") printf '%s\n' '{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","plaintextSha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","sizeBytes":123}' ;;
  "service rm")
    if [ "${ORKA_AI_RECOVERY_TEST_SERVICE_RM_FAIL_ALWAYS:-false}" = true ]; then
      exit 1
    fi
    if [ "${ORKA_AI_RECOVERY_TEST_SERVICE_RM_FAIL_ONCE:-false}" = true ] && [ ! -e "$ORKA_AI_RECOVERY_TEST_SERVICE_RM_STATE" ]; then
      : >"$ORKA_AI_RECOVERY_TEST_SERVICE_RM_STATE"
      exit 1
    fi ;;
  "secret inspect") exit 0 ;;
  "secret rm")
    if [ "${ORKA_AI_RECOVERY_TEST_SECRET_RM_FAIL_ALWAYS:-false}" = true ]; then
      exit 1
    fi ;;
  *) exit 1 ;;
esac
MOCK
chmod +x "$temporary/bin/docker"
cat >"$temporary/bin/sleep" <<'MOCK'
#!/bin/sh
exit 0
MOCK
chmod +x "$temporary/bin/sleep"

digest_a='sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
digest_b='sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
export PATH="$temporary/bin:$PATH"
export ORKA_AI_RECOVERY_TEST_LOG="$temporary/docker.log"
export DOCKYARD_IMAGE="${DOCKYARD_AI_GATEWAY_RECOVERY_DOCKYARD_IMAGE:-example/dockyard@$digest_a}"
export NINEROUTER_IMAGE="${DOCKYARD_AI_GATEWAY_RECOVERY_NINEROUTER_IMAGE:-example/9router@$digest_b}"
export NINEROUTER_STORAGE_NODE_ID='nodeabc123'
export DOCKYARD_AI_BACKUP_OBJECT_REF='s3://recovery/ai-gateway.enc'
export DOCKYARD_AI_BACKUP_URL_FILE="$temporary/put-url"
export DOCKYARD_AI_RESTORE_OBJECT_REF="$DOCKYARD_AI_BACKUP_OBJECT_REF"
export DOCKYARD_AI_RESTORE_URL_FILE="$temporary/get-url"
export DOCKYARD_AI_BACKUP_KEY_FILE="$temporary/backup-key"
export DOCKYARD_RECOVERY_SIGNING_KEY_FILE="$temporary/signing-key.pem"
export DOCKYARD_RECOVERY_VERIFY_KEY_FILE="$temporary/verify-key.pem"

: >"$ORKA_AI_RECOVERY_TEST_LOG"
bundle="$temporary/output/backup"
"$root/scripts/backup-ai-gateway.sh" "$bundle" >/dev/null
test -f "$bundle/manifest.json"
test -f "$bundle/manifest.sig"
test ! -e "$bundle/job.json"
openssl pkeyutl -verify -rawin -pubin -inkey "$DOCKYARD_RECOVERY_VERIFY_KEY_FILE" -in "$bundle/manifest.json" -sigfile "$bundle/manifest.sig" >/dev/null
jq -e '.formatVersion == 1 and .objectRef == "s3://recovery/ai-gateway.enc" and .sizeBytes == 123' "$bundle/manifest.json" >/dev/null
if grep -Fq 'upload-secret' "$bundle/manifest.json" || grep -Fq "$(<"$DOCKYARD_AI_BACKUP_KEY_FILE")" "$bundle/manifest.json"; then
  echo 'backup metadata retained credentials' >&2
  exit 1
fi
grep -q '^service scale --detach=false dockyard-ai_9router=0$' "$ORKA_AI_RECOVERY_TEST_LOG"
grep -q '^service scale --detach=false dockyard-ai_9router=1$' "$ORKA_AI_RECOVERY_TEST_LOG"

: >"$ORKA_AI_RECOVERY_TEST_LOG"
if ORKA_AI_RECOVERY_TEST_SECRET_RM_FAIL_ALWAYS=true "$root/scripts/backup-ai-gateway.sh" "$temporary/output/failed-secret-cleanup" >"$temporary/out" 2>"$temporary/err"; then
  echo 'AI gateway backup ignored permanent secret cleanup failure' >&2
  exit 1
fi
test ! -e "$temporary/output/failed-secret-cleanup"
grep -q 'temporary Swarm resources could not be removed' "$temporary/err"
test "$(grep -c '^secret rm ' "$ORKA_AI_RECOVERY_TEST_LOG")" -eq 60
grep -q '^service scale --detach=false dockyard-ai_9router=1$' "$ORKA_AI_RECOVERY_TEST_LOG"
grep -q -- '--constraint node.id==nodeabc123' "$ORKA_AI_RECOVERY_TEST_LOG"
grep -q 'type=volume,source=dockyard-ai_nine-router-data,target=/volume,readonly' "$ORKA_AI_RECOVERY_TEST_LOG"
if grep -Fq 'upload-secret' "$ORKA_AI_RECOVERY_TEST_LOG" || grep -Fq "$(<"$DOCKYARD_AI_BACKUP_KEY_FILE")" "$ORKA_AI_RECOVERY_TEST_LOG"; then
  echo 'backup credentials leaked into Docker arguments' >&2
  exit 1
fi

: >"$ORKA_AI_RECOVERY_TEST_LOG"
if ORKA_AI_RECOVERY_TEST_FAIL_TASK=true "$root/scripts/backup-ai-gateway.sh" "$temporary/output/failed-backup" >"$temporary/out" 2>"$temporary/err"; then
  echo 'AI gateway backup accepted a failed helper task' >&2
  exit 1
fi
test ! -e "$temporary/output/failed-backup"
grep -q '^service scale --detach=false dockyard-ai_9router=0$' "$ORKA_AI_RECOVERY_TEST_LOG"
grep -q '^service scale --detach=false dockyard-ai_9router=1$' "$ORKA_AI_RECOVERY_TEST_LOG"

: >"$ORKA_AI_RECOVERY_TEST_LOG"
if ORKA_AI_RECOVERY_TEST_REPLICAS=0 "$root/scripts/restore-ai-gateway.sh" "$bundle" >"$temporary/out" 2>"$temporary/err"; then
  echo 'AI gateway restore ran without explicit confirmation' >&2
  exit 1
fi
grep -q 'refusing destructive restore' "$temporary/err"
test ! -s "$ORKA_AI_RECOVERY_TEST_LOG"

: >"$ORKA_AI_RECOVERY_TEST_LOG"
DOCKYARD_AI_RESTORE_CONFIRM='restore:dockyard-ai:9router' ORKA_AI_RECOVERY_TEST_REPLICAS=0 "$root/scripts/restore-ai-gateway.sh" "$bundle" | grep -q 'restored and left offline'
grep -q 'type=volume,source=dockyard-ai_nine-router-data,target=/volume ' "$ORKA_AI_RECOVERY_TEST_LOG"
if grep -q '^service scale ' "$ORKA_AI_RECOVERY_TEST_LOG"; then
  echo 'restore restarted 9Router before post-restore verification' >&2
  exit 1
fi
if grep -Fq 'download-secret' "$ORKA_AI_RECOVERY_TEST_LOG" || grep -Fq "$(<"$DOCKYARD_AI_BACKUP_KEY_FILE")" "$ORKA_AI_RECOVERY_TEST_LOG"; then
  echo 'restore credentials leaked into Docker arguments' >&2
  exit 1
fi

if DOCKYARD_AI_RESTORE_CONFIRM='restore:dockyard-ai:9router' ORKA_AI_RECOVERY_TEST_REPLICAS=1 "$root/scripts/restore-ai-gateway.sh" "$bundle" >"$temporary/out" 2>"$temporary/err"; then
  echo 'restore accepted a running 9Router service' >&2
  exit 1
fi
grep -q 'scale dockyard-ai_9router to zero' "$temporary/err"

: >"$ORKA_AI_RECOVERY_TEST_LOG"
DOCKYARD_AI_RESTORE_CONFIRM='restore:dockyard-ai:9router' \
  ORKA_AI_RECOVERY_TEST_REPLICAS=0 \
  ORKA_AI_RECOVERY_TEST_SERVICE_RM_STATE="$temporary/restore-service-rm-state" \
  ORKA_AI_RECOVERY_TEST_SERVICE_RM_FAIL_ONCE=true \
  "$root/scripts/restore-ai-gateway.sh" "$bundle" >/dev/null
test "$(grep -c '^service rm ' "$ORKA_AI_RECOVERY_TEST_LOG")" -eq 2

printf '%s' 'different-encryption-key-material' >"$temporary/wrong-key"
chmod 0600 "$temporary/wrong-key"
if DOCKYARD_AI_RESTORE_CONFIRM='restore:dockyard-ai:9router' ORKA_AI_RECOVERY_TEST_REPLICAS=0 DOCKYARD_AI_BACKUP_KEY_FILE="$temporary/wrong-key" "$root/scripts/restore-ai-gateway.sh" "$bundle" >"$temporary/out" 2>"$temporary/err"; then
  echo 'restore accepted the wrong encryption key' >&2
  exit 1
fi
grep -q 'backup encryption key does not match' "$temporary/err"

cp -a "$bundle" "$temporary/output/tampered"
jq '.sizeBytes = 124' "$temporary/output/tampered/manifest.json" >"$temporary/tampered.json"
mv "$temporary/tampered.json" "$temporary/output/tampered/manifest.json"
if DOCKYARD_AI_RESTORE_CONFIRM='restore:dockyard-ai:9router' ORKA_AI_RECOVERY_TEST_REPLICAS=0 "$root/scripts/restore-ai-gateway.sh" "$temporary/output/tampered" >"$temporary/out" 2>"$temporary/err"; then
  echo 'restore accepted tampered metadata' >&2
  exit 1
fi
grep -q 'metadata signature is invalid' "$temporary/err"

: >"$ORKA_AI_RECOVERY_TEST_LOG"
export ORKA_AI_RECOVERY_TEST_SERVICE_RM_STATE="$temporary/service-rm-state"
ORKA_AI_RECOVERY_TEST_SERVICE_RM_FAIL_ONCE=true "$root/scripts/backup-ai-gateway.sh" "$temporary/output/retry-cleanup" >/dev/null
test -f "$temporary/output/retry-cleanup/manifest.json"
test "$(grep -c '^service rm ' "$ORKA_AI_RECOVERY_TEST_LOG")" -eq 2

: >"$ORKA_AI_RECOVERY_TEST_LOG"
if ORKA_AI_RECOVERY_TEST_SERVICE_RM_FAIL_ALWAYS=true "$root/scripts/backup-ai-gateway.sh" "$temporary/output/failed-cleanup" >"$temporary/out" 2>"$temporary/err"; then
  echo 'AI gateway backup ignored permanent helper cleanup failure' >&2
  exit 1
fi
test ! -e "$temporary/output/failed-cleanup"
grep -q 'temporary Swarm resources could not be removed' "$temporary/err"
test "$(grep -c '^service rm ' "$ORKA_AI_RECOVERY_TEST_LOG")" -eq 6
grep -q '^service scale --detach=false dockyard-ai_9router=1$' "$ORKA_AI_RECOVERY_TEST_LOG"

(cd "$root" && go test -run '^(TestEncryptedBackupAndRestoreRoundTrip|TestLocalEncryptedBackupAndRestoreRoundTrip|TestRestoreRejectsTamperedCiphertextWithoutChangingVolume|TestVolumeArtifactHTTPClientDisablesProxyAndRedirects)$' -count=1 ./internal/volumeartifact) >"$temporary/volumeartifact.log"

mkdir -p "$(dirname "$evidence_file")"
jq -n \
  --arg sourceCommit "${GITHUB_SHA:-$(git -C "$root" rev-parse HEAD)}" \
  --arg createdAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg dockyardImage "$DOCKYARD_IMAGE" \
  --arg nineRouterImage "$NINEROUTER_IMAGE" \
  '{
    status:"passed",
    sourceCommit:$sourceCommit,
    createdAt:$createdAt,
    dockyardImage:$dockyardImage,
    nineRouterImage:$nineRouterImage,
    encryptedRoundTripVerified:true,
    tamperedCiphertextRejected:true,
    signedMetadataVerified:true,
    tamperedMetadataRejected:true,
    credentialsExcludedFromMetadata:true,
    credentialsExcludedFromDockerArguments:true,
    backupQuiesced:true,
    backupFailureResumedService:true,
    failedHelperTaskRejected:true,
    helperCleanupRetried:true,
    restoreHelperCleanupRetried:true,
    permanentCleanupFailureRejected:true,
    permanentSecretCleanupFailureRejected:true,
    proxyEnvironmentIgnored:true,
    redirectsRejected:true,
    responseHeaderTimeoutEnforced:true,
    restoreConfirmationRequired:true,
    runningServiceRestoreRejected:true,
    wrongEncryptionKeyRejected:true,
    restoreLeftOffline:true,
    backupMountReadOnly:true,
    nodePinned:true,
    postRestoreDualAuditorVerification:"production-required"
  }' >"$evidence_file"

jq -e '
  .status == "passed" and
  (.sourceCommit | test("^[a-f0-9]{40}$")) and
  (.dockyardImage | test("@sha256:[a-f0-9]{64}$")) and
  (.nineRouterImage | test("@sha256:[a-f0-9]{64}$")) and
  .encryptedRoundTripVerified and .tamperedCiphertextRejected and
  .signedMetadataVerified and .tamperedMetadataRejected and
  .credentialsExcludedFromMetadata and .credentialsExcludedFromDockerArguments and
  .backupQuiesced and .backupFailureResumedService and .failedHelperTaskRejected and
  .helperCleanupRetried and .restoreHelperCleanupRetried and
  .permanentCleanupFailureRejected and .permanentSecretCleanupFailureRejected and
  .proxyEnvironmentIgnored and .redirectsRejected and .responseHeaderTimeoutEnforced and
  .restoreConfirmationRequired and .runningServiceRestoreRejected and
  .wrongEncryptionKeyRejected and .restoreLeftOffline and
  .backupMountReadOnly and .nodePinned and
  .postRestoreDualAuditorVerification == "production-required"
' "$evidence_file" >/dev/null

cat "$evidence_file"
