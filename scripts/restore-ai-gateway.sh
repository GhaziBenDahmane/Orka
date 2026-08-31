#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)

if [ "$#" -ne 1 ]; then
  echo "usage: $0 RECOVERY_METADATA_DIRECTORY" >&2
  exit 2
fi

bundle=$1
stack=${DOCKYARD_AI_STACK_NAME:-dockyard-ai}
service=${DOCKYARD_AI_GATEWAY_SERVICE:-${stack}_9router}
volume=${NINEROUTER_VOLUME_NAME:-${stack}_nine-router-data}
node=${NINEROUTER_STORAGE_NODE_ID:-}
router_image=${NINEROUTER_IMAGE:-}
helper_image=${DOCKYARD_IMAGE:-}
object_ref=${DOCKYARD_AI_RESTORE_OBJECT_REF:-}
url_file=${DOCKYARD_AI_RESTORE_URL_FILE:-}
key_file=${DOCKYARD_AI_BACKUP_KEY_FILE:-}
verify_key=${DOCKYARD_RECOVERY_VERIFY_KEY_FILE:-}

fail() { echo "restore-ai-gateway: $*" >&2; exit 1; }
safe_name() { case "$2" in ""|-*|*[!A-Za-z0-9_.-]*) fail "invalid $1" ;; esac; }
restricted_file() {
  label=$1
  path=$2
  [ -n "$path" ] && [ ! -L "$path" ] && [ -f "$path" ] && [ -r "$path" ] || fail "$label must name a readable regular file, not a symbolic link"
  [ -z "$(find "$path" -prune -perm /077 -print)" ] || fail "$label must not be accessible by group or other users"
  size=$(wc -c <"$path" | tr -d ' ')
  [ "$size" -gt 0 ] && [ "$size" -le 32768 ] || fail "$label has an invalid size"
  compact_size=$(tr -d '\r\n' <"$path" | wc -c | tr -d ' ')
  [ "$compact_size" -eq "$size" ] || fail "$label must contain one value without CR or LF characters"
}

[ "${DOCKYARD_AI_RESTORE_CONFIRM:-}" = "restore:${stack}:9router" ] || fail "refusing destructive restore; set DOCKYARD_AI_RESTORE_CONFIRM=restore:${stack}:9router"
safe_name DOCKYARD_AI_STACK_NAME "$stack"
safe_name DOCKYARD_AI_GATEWAY_SERVICE "$service"
safe_name NINEROUTER_VOLUME_NAME "$volume"
case "$node" in ""|*[!a-z0-9]*) fail "NINEROUTER_STORAGE_NODE_ID must be a lowercase Swarm node ID" ;; esac
[ "${#node}" -le 64 ] || fail "NINEROUTER_STORAGE_NODE_ID must be a lowercase Swarm node ID"
[ -n "$object_ref" ] && [ "${#object_ref}" -le 2048 ] || fail "DOCKYARD_AI_RESTORE_OBJECT_REF is required and must not exceed 2048 bytes"
for command in awk date docker find grep head jq mktemp openssl sha256sum sleep tail tr wc; do
  command -v "$command" >/dev/null 2>&1 || fail "$command is required"
done
"$root/scripts/ci/validate-image-reference.sh" "$helper_image" >/dev/null || fail "DOCKYARD_IMAGE must be pinned by sha256 digest"
"$root/scripts/ci/validate-image-reference.sh" "$router_image" >/dev/null || fail "NINEROUTER_IMAGE must be pinned by sha256 digest"
restricted_file DOCKYARD_AI_RESTORE_URL_FILE "$url_file"
restricted_file DOCKYARD_AI_BACKUP_KEY_FILE "$key_file"
[ -n "$verify_key" ] && [ ! -L "$verify_key" ] && [ -f "$verify_key" ] && [ -r "$verify_key" ] || fail "DOCKYARD_RECOVERY_VERIFY_KEY_FILE must name a readable regular Ed25519 public key"
openssl pkey -pubin -in "$verify_key" -text_pub -noout 2>/dev/null | grep -q '^ED25519 Public-Key:' || fail "DOCKYARD_RECOVERY_VERIFY_KEY_FILE must contain an Ed25519 public key"
[ -f "$bundle/manifest.json" ] && [ ! -L "$bundle/manifest.json" ] && [ -f "$bundle/manifest.sig" ] && [ ! -L "$bundle/manifest.sig" ] || fail "recovery metadata must contain regular manifest.json and manifest.sig files"
[ "$(wc -c <"$bundle/manifest.json" | tr -d ' ')" -le 65536 ] && [ "$(wc -c <"$bundle/manifest.sig" | tr -d ' ')" -eq 64 ] || fail "recovery metadata has an invalid size"
openssl pkeyutl -verify -rawin -pubin -inkey "$verify_key" -in "$bundle/manifest.json" -sigfile "$bundle/manifest.sig" >/dev/null 2>&1 || fail "recovery metadata signature is invalid"

canonical_file() {
  directory=$(CDPATH= cd -- "$(dirname "$1")" && pwd -P) || fail "cannot resolve recovery input path"
  printf '%s/%s' "$directory" "$(basename "$1")"
}
manifest_file=$(canonical_file "$bundle/manifest.json")
signature_file=$(canonical_file "$bundle/manifest.sig")
verify_key=$(canonical_file "$verify_key")
key_file=$(canonical_file "$key_file")
for recovery_path in "$manifest_file" "$signature_file" "$verify_key" "$key_file"; do
  case "$recovery_path" in *,*) fail "recovery input paths must not contain commas" ;; esac
done
verified_manifest=$(docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --mount "type=bind,src=$manifest_file,dst=/input/manifest.json,readonly" \
  --mount "type=bind,src=$signature_file,dst=/input/manifest.sig,readonly" \
  --mount "type=bind,src=$verify_key,dst=/input/verify-key.pem,readonly" \
  --mount "type=bind,src=$key_file,dst=/input/encryption-key,readonly" \
  --entrypoint /usr/local/bin/dockyard "$helper_image" verify-ai-gateway-recovery-manifest \
  --manifest /input/manifest.json --signature /input/manifest.sig \
  --public-key-file /input/verify-key.pem --encryption-key-file /input/encryption-key \
  --stack "$stack" --service "$service" --volume "$volume" --storage-node "$node" \
  --router-image "$router_image" --helper-image "$helper_image" --object-ref "$object_ref") || fail "recovery metadata verification failed"

format_version=$(printf '%s' "$verified_manifest" | jq -er '.formatVersion')
expected_stack=$(printf '%s' "$verified_manifest" | jq -er '.stack')
expected_service=$(printf '%s' "$verified_manifest" | jq -er '.service')
expected_volume=$(printf '%s' "$verified_manifest" | jq -er '.volume')
expected_node=$(printf '%s' "$verified_manifest" | jq -er '.storageNodeId')
expected_router_image=$(printf '%s' "$verified_manifest" | jq -er '.routerImage')
expected_helper_image=$(printf '%s' "$verified_manifest" | jq -er '.helperImage')
expected_object_ref=$(printf '%s' "$verified_manifest" | jq -er '.objectRef')
aad=$(printf '%s' "$verified_manifest" | jq -er '.encryptionAad')
expected_key_sha256=$(printf '%s' "$verified_manifest" | jq -er '.encryptionKeySha256 | select(test("^[a-f0-9]{64}$"))')
artifact_sha256=$(printf '%s' "$verified_manifest" | jq -er '.sha256 | select(test("^[a-f0-9]{64}$"))')
plaintext_sha256=$(printf '%s' "$verified_manifest" | jq -er '.plaintextSha256 | select(test("^[a-f0-9]{64}$"))')
artifact_bytes=$(printf '%s' "$verified_manifest" | jq -er '.sizeBytes | select(type == "number" and . > 0 and floor == .)')
expected_signing_key_sha256=$(printf '%s' "$verified_manifest" | jq -er '.recoverySigningKeySha256 | select(test("^[a-f0-9]{64}$"))')
[ "$format_version" = 1 ] && [ "$expected_stack" = "$stack" ] && [ "$expected_service" = "$service" ] && [ "$expected_volume" = "$volume" ] && [ "$expected_node" = "$node" ] || fail "recovery metadata does not match the requested stack, service, volume, or node"
[ "$expected_router_image" = "$router_image" ] && [ "$expected_helper_image" = "$helper_image" ] || fail "recovery metadata image identities do not match"
[ "$expected_object_ref" = "$object_ref" ] || fail "DOCKYARD_AI_RESTORE_OBJECT_REF does not match the signed metadata"
[ "$(sha256sum "$key_file" | awk '{print $1}')" = "$expected_key_sha256" ] || fail "backup encryption key does not match the signed metadata"
signing_key_sha256=$(openssl pkey -pubin -in "$verify_key" -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
[ "$signing_key_sha256" = "$expected_signing_key_sha256" ] || fail "recovery verification key does not match the signed metadata"

swarm_state=$(docker info --format '{{.Swarm.LocalNodeState}} {{.Swarm.ControlAvailable}}')
[ "$swarm_state" = "active true" ] || fail "run this command on an active Docker Swarm manager"
node_state=$(docker node inspect --format '{{.Status.State}} {{.Spec.Availability}}' "$node" 2>/dev/null) || fail "storage node is unavailable"
[ "$node_state" = "ready active" ] || fail "storage node must be ready and active"
actual_image=$(docker service inspect --format '{{.Spec.TaskTemplate.ContainerSpec.Image}}' "$service" 2>/dev/null) || fail "9Router service is unavailable"
[ "$actual_image" = "$router_image" ] || fail "NINEROUTER_IMAGE does not match the deployed 9Router service"
update_state=$(docker service inspect --format '{{if .UpdateStatus}}{{.UpdateStatus.State}}{{end}}' "$service")
[ -z "$update_state" ] || [ "$update_state" = completed ] || fail "9Router service update is not complete"
replicas=$(docker service inspect --format '{{.Spec.Mode.Replicated.Replicas}}' "$service")
[ "$replicas" = 0 ] || fail "scale $service to zero before restoring"
mounts=$(docker service inspect --format '{{json .Spec.TaskTemplate.ContainerSpec.Mounts}}' "$service")
printf '%s' "$mounts" | jq -e --arg volume "$volume" 'any(.[]; .Type == "volume" and .Source == $volume and .Target == "/app/data")' >/dev/null || fail "9Router service does not mount the expected data volume"

temporary=$(mktemp -d)
case "$temporary" in *,*) fail "temporary path must not contain commas" ;; esac
helper_service="orka-ai-restore-$$_$(date +%s)"
job_secret="orka-ai-restore-job-$$_$(date +%s)"
helper_created=false
secret_created=false
remove_helper_resources() {
  cleanup_failed=false
  if [ "$helper_created" = true ]; then
    attempts=0
    while ! docker service rm "$helper_service" >/dev/null 2>&1; do
      attempts=$((attempts + 1))
      if [ "$attempts" -ge 3 ]; then
        cleanup_failed=true
        break
      fi
      sleep 1
    done
    [ "$cleanup_failed" = true ] || helper_created=false
  fi
  if [ "$secret_created" = true ]; then
    attempts=0
    while docker secret inspect "$job_secret" >/dev/null 2>&1; do
      if docker secret rm "$job_secret" >/dev/null 2>&1; then
        secret_created=false
        break
      fi
      attempts=$((attempts + 1))
      if [ "$attempts" -ge 30 ]; then
        cleanup_failed=true
        break
      fi
      sleep 1
    done
    if ! docker secret inspect "$job_secret" >/dev/null 2>&1; then
      secret_created=false
    fi
  fi
  [ "$cleanup_failed" = false ]
}
cleanup() {
  status=${1:-$?}
  remove_helper_resources || status=1
  rm -rf -- "$temporary"
  trap - EXIT HUP INT TERM
  exit "$status"
}
trap cleanup EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM

jq -n --rawfile transferUrl "$url_file" --rawfile encryptionKey "$key_file" --arg aad "$aad" --arg sha256 "$artifact_sha256" --arg plaintextSha256 "$plaintext_sha256" --argjson sizeBytes "$artifact_bytes" '{mode:"restore",transferUrl:$transferUrl,encryptionKey:$encryptionKey,encryptionAad:$aad,sha256:$sha256,plaintextSha256:$plaintextSha256,sizeBytes:$sizeBytes}' >"$temporary/job.json"
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --mount "type=bind,src=$temporary/job.json,dst=/run/job.json,readonly" --entrypoint /usr/local/bin/dockyard "$helper_image" validate-volume-artifact-job --job-file /run/job.json >/dev/null || fail "restore URL or signed artifact parameters are invalid"
docker secret create "$job_secret" "$temporary/job.json" >/dev/null
secret_created=true
docker service create --quiet --detach --name "$helper_service" --constraint "node.id==$node" --restart-condition none --read-only --tmpfs /tmp --security-opt no-new-privileges --limit-cpu 1 --limit-memory 512M --mount "type=volume,source=$volume,target=/volume" --secret "source=$job_secret,target=volume-job.json,mode=0400" "$helper_image" volume-artifact --job-file /run/secrets/volume-job.json >/dev/null
helper_created=true

deadline=$(( $(date +%s) + 1800 ))
while :; do
  task=$(docker service ps --no-trunc --format '{{.CurrentState}}|{{.Error}}' "$helper_service" | head -n 1)
  state=$(printf '%s' "$task" | awk -F'|' '{print tolower($1)}' | awk '{print $1}')
  case "$state" in
    complete) break ;;
    failed|rejected|orphaned|shutdown) fail "volume restore task failed" ;;
  esac
  [ "$(date +%s)" -lt "$deadline" ] || fail "volume restore task timed out"
  sleep 2
done
result=$(docker service logs --raw "$helper_service" 2>/dev/null | jq -Rrc 'fromjson? | select((.sha256|type) == "string" and (.plaintextSha256|type) == "string" and (.sizeBytes|type) == "number")' | tail -n 1)
printf '%s' "$result" | jq -e --arg sha256 "$artifact_sha256" --arg plaintext "$plaintext_sha256" --argjson size "$artifact_bytes" '.sha256 == $sha256 and .plaintextSha256 == $plaintext and .sizeBytes == $size' >/dev/null || fail "volume restore task returned no matching result"

remove_helper_resources || fail "restore succeeded but temporary Swarm resources could not be removed"
echo "9Router data restored and left offline; rerun scripts/install-ai-auditors.sh with the signed image set to resume and verify both auditors."
