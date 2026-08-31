#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)

if [ "$#" -ne 1 ]; then
  echo "usage: $0 OUTPUT_METADATA_DIRECTORY" >&2
  exit 2
fi

output=$1
parent=$(dirname "$output")
stack=${DOCKYARD_AI_STACK_NAME:-dockyard-ai}
service=${DOCKYARD_AI_GATEWAY_SERVICE:-${stack}_9router}
volume=${NINEROUTER_VOLUME_NAME:-${stack}_nine-router-data}
node=${NINEROUTER_STORAGE_NODE_ID:-}
router_image=${NINEROUTER_IMAGE:-}
helper_image=${DOCKYARD_IMAGE:-}
object_ref=${DOCKYARD_AI_BACKUP_OBJECT_REF:-}
url_file=${DOCKYARD_AI_BACKUP_URL_FILE:-}
key_file=${DOCKYARD_AI_BACKUP_KEY_FILE:-}
signing_key=${DOCKYARD_RECOVERY_SIGNING_KEY_FILE:-}

fail() { echo "backup-ai-gateway: $*" >&2; exit 1; }
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

safe_name DOCKYARD_AI_STACK_NAME "$stack"
safe_name DOCKYARD_AI_GATEWAY_SERVICE "$service"
safe_name NINEROUTER_VOLUME_NAME "$volume"
case "$node" in ""|*[!a-z0-9]*) fail "NINEROUTER_STORAGE_NODE_ID must be a lowercase Swarm node ID" ;; esac
[ "${#node}" -le 64 ] || fail "NINEROUTER_STORAGE_NODE_ID must be a lowercase Swarm node ID"
[ -n "$object_ref" ] && [ "${#object_ref}" -le 2048 ] || fail "DOCKYARD_AI_BACKUP_OBJECT_REF is required and must not exceed 2048 bytes"
object_ref_bytes=$(printf '%s' "$object_ref" | wc -c | tr -d ' ')
object_ref_compact_bytes=$(printf '%s' "$object_ref" | tr -d '\r\n' | wc -c | tr -d ' ')
[ "$object_ref_bytes" -eq "$object_ref_compact_bytes" ] || fail "DOCKYARD_AI_BACKUP_OBJECT_REF must not contain line breaks"
[ ! -e "$output" ] || fail "refusing to overwrite existing recovery metadata: $output"
[ -d "$parent" ] || fail "output parent directory does not exist: $parent"
case "$parent" in *,*) fail "output path must not contain commas" ;; esac
for command in awk date docker find grep head jq mktemp mv openssl sha256sum sleep tail tr wc; do
  command -v "$command" >/dev/null 2>&1 || fail "$command is required"
done
"$root/scripts/ci/validate-image-reference.sh" "$helper_image" >/dev/null || fail "DOCKYARD_IMAGE must be pinned by sha256 digest"
"$root/scripts/ci/validate-image-reference.sh" "$router_image" >/dev/null || fail "NINEROUTER_IMAGE must be pinned by sha256 digest"
restricted_file DOCKYARD_AI_BACKUP_URL_FILE "$url_file"
restricted_file DOCKYARD_AI_BACKUP_KEY_FILE "$key_file"
[ -n "$signing_key" ] && [ ! -L "$signing_key" ] && [ -f "$signing_key" ] && [ -r "$signing_key" ] || fail "DOCKYARD_RECOVERY_SIGNING_KEY_FILE must name a readable regular Ed25519 private key"
[ -z "$(find "$signing_key" -prune -perm /077 -print)" ] || fail "DOCKYARD_RECOVERY_SIGNING_KEY_FILE must not be accessible by group or other users"
openssl pkey -in "$signing_key" -text_pub -noout 2>/dev/null | grep -q '^ED25519 Public-Key:' || fail "DOCKYARD_RECOVERY_SIGNING_KEY_FILE must contain an Ed25519 private key"

swarm_state=$(docker info --format '{{.Swarm.LocalNodeState}} {{.Swarm.ControlAvailable}}')
[ "$swarm_state" = "active true" ] || fail "run this command on an active Docker Swarm manager"
node_state=$(docker node inspect --format '{{.Status.State}} {{.Spec.Availability}}' "$node" 2>/dev/null) || fail "storage node is unavailable"
[ "$node_state" = "ready active" ] || fail "storage node must be ready and active"
actual_image=$(docker service inspect --format '{{.Spec.TaskTemplate.ContainerSpec.Image}}' "$service" 2>/dev/null) || fail "9Router service is unavailable"
[ "$actual_image" = "$router_image" ] || fail "NINEROUTER_IMAGE does not match the deployed 9Router service"
update_state=$(docker service inspect --format '{{if .UpdateStatus}}{{.UpdateStatus.State}}{{end}}' "$service")
[ -z "$update_state" ] || [ "$update_state" = completed ] || fail "9Router service update is not complete"
mounts=$(docker service inspect --format '{{json .Spec.TaskTemplate.ContainerSpec.Mounts}}' "$service")
printf '%s' "$mounts" | jq -e --arg volume "$volume" 'any(.[]; .Type == "volume" and .Source == $volume and .Target == "/app/data")' >/dev/null || fail "9Router service does not mount the expected data volume"
replicas=$(docker service inspect --format '{{.Spec.Mode.Replicated.Replicas}}' "$service")
case "$replicas" in ""|*[!0-9]*) fail "could not determine 9Router replica count" ;; esac
[ "$replicas" -gt 0 ] || fail "9Router must be running before backup"

umask 077
temporary=$(mktemp -d "$parent/.orka-ai-gateway.XXXXXX")
helper_service="orka-ai-backup-$$_$(date +%s)"
job_secret="orka-ai-backup-job-$$_$(date +%s)"
quiesced=false
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
  status=$?
  remove_helper_resources || status=1
  if [ "$quiesced" = true ]; then
    docker service scale --detach=false "$service=$replicas" >/dev/null 2>&1 || status=1
  fi
  [ ! -d "$temporary" ] || rm -rf -- "$temporary"
  trap - EXIT HUP INT TERM
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

created_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
aad="orka-ai-gateway:${stack}:${created_at}"
jq -n --rawfile transferUrl "$url_file" --rawfile encryptionKey "$key_file" --arg aad "$aad" '{mode:"backup",transferUrl:$transferUrl,encryptionKey:$encryptionKey,encryptionAad:$aad}' >"$temporary/job.json"
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --mount "type=bind,src=$temporary/job.json,dst=/run/job.json,readonly" --entrypoint /usr/local/bin/dockyard "$helper_image" validate-volume-artifact-job --job-file /run/job.json >/dev/null || fail "backup URL or encryption parameters are invalid"

docker service scale --detach=false "$service=0" >/dev/null || fail "could not quiesce 9Router"
quiesced=true
docker secret create "$job_secret" "$temporary/job.json" >/dev/null
secret_created=true
docker service create --quiet --detach --name "$helper_service" --constraint "node.id==$node" --restart-condition none --read-only --tmpfs /tmp --security-opt no-new-privileges --limit-cpu 1 --limit-memory 512M --mount "type=volume,source=$volume,target=/volume,readonly" --secret "source=$job_secret,target=volume-job.json,mode=0400" "$helper_image" volume-artifact --job-file /run/secrets/volume-job.json >/dev/null
helper_created=true

deadline=$(( $(date +%s) + 1800 ))
while :; do
  task=$(docker service ps --no-trunc --format '{{.CurrentState}}|{{.Error}}' "$helper_service" | head -n 1)
  state=$(printf '%s' "$task" | awk -F'|' '{print tolower($1)}' | awk '{print $1}')
  case "$state" in
    complete) break ;;
    failed|rejected|orphaned|shutdown) fail "volume backup task failed" ;;
  esac
  [ "$(date +%s)" -lt "$deadline" ] || fail "volume backup task timed out"
  sleep 2
done
result=$(docker service logs --raw "$helper_service" 2>/dev/null | jq -Rrc 'fromjson? | select((.sha256|type) == "string" and (.plaintextSha256|type) == "string" and (.sizeBytes|type) == "number")' | tail -n 1)
printf '%s' "$result" | jq -e '(.sha256|test("^[a-f0-9]{64}$")) and (.plaintextSha256|test("^[a-f0-9]{64}$")) and (.sizeBytes > 0)' >/dev/null || fail "volume backup task returned no valid result"
artifact_sha256=$(printf '%s' "$result" | jq -r '.sha256')
plaintext_sha256=$(printf '%s' "$result" | jq -r '.plaintextSha256')
artifact_bytes=$(printf '%s' "$result" | jq -r '.sizeBytes')
key_sha256=$(sha256sum "$key_file" | awk '{print $1}')
signing_key_sha256=$(openssl pkey -in "$signing_key" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
jq -n \
  --arg createdAt "$created_at" --arg stack "$stack" --arg service "$service" \
  --arg volume "$volume" --arg storageNodeId "$node" --arg routerImage "$router_image" \
  --arg helperImage "$helper_image" --arg objectRef "$object_ref" --arg encryptionAad "$aad" \
  --arg encryptionKeySha256 "$key_sha256" --arg sha256 "$artifact_sha256" \
  --arg plaintextSha256 "$plaintext_sha256" --argjson sizeBytes "$artifact_bytes" \
  --arg recoverySigningKeySha256 "$signing_key_sha256" \
  '{formatVersion:1,createdAt:$createdAt,stack:$stack,service:$service,volume:$volume,storageNodeId:$storageNodeId,routerImage:$routerImage,helperImage:$helperImage,objectRef:$objectRef,encryptionAad:$encryptionAad,encryptionKeySha256:$encryptionKeySha256,sha256:$sha256,plaintextSha256:$plaintextSha256,sizeBytes:$sizeBytes,recoverySigningKeySha256:$recoverySigningKeySha256}' >"$temporary/manifest.json"
openssl pkeyutl -sign -rawin -inkey "$signing_key" -in "$temporary/manifest.json" -out "$temporary/manifest.sig"
chmod 0600 "$temporary/manifest.json" "$temporary/manifest.sig"

docker service scale --detach=false "$service=$replicas" >/dev/null || fail "backup succeeded but 9Router could not be resumed"
quiesced=false
remove_helper_resources || fail "backup succeeded but temporary Swarm resources could not be removed"
rm -f -- "$temporary/job.json"
mv "$temporary" "$output"
temporary=""
trap - EXIT HUP INT TERM
printf '%s\n' "$output"
