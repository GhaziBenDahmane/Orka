#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
stack=${DOCKYARD_AI_STACK_NAME:-dockyard-ai}
security_token_secret=${DOCKYARD_AI_SECURITY_AUDITOR_TOKEN_SECRET:-dockyard_ai_security_auditor_token}
reliability_token_secret=${DOCKYARD_AI_RELIABILITY_AUDITOR_TOKEN_SECRET:-dockyard_ai_reliability_auditor_token}
api_key_secret=${DOCKYARD_AI_API_KEY_SECRET:-dockyard_ai_api_key}
reuse=${DOCKYARD_REUSE_EXISTING_SECRETS:-false}
dry_run=${DOCKYARD_INSTALL_DRY_RUN:-false}
skip_wait=${DOCKYARD_INSTALL_SKIP_WAIT:-false}
wait_timeout=${DOCKYARD_INSTALL_WAIT_TIMEOUT:-300}
stability_seconds=${DOCKYARD_INSTALL_STABILITY_SECONDS:-90}
audit_verify_timeout=${DOCKYARD_AI_VERIFY_TIMEOUT:-900}

fail() {
  echo "install-ai-auditors: $*" >&2
  exit 1
}

case "$stack" in ""|-*|*[!A-Za-z0-9_.-]*) fail "invalid DOCKYARD_AI_STACK_NAME" ;; esac
for secret_name in "$security_token_secret" "$reliability_token_secret" "$api_key_secret"; do
  case "$secret_name" in ""|-*|*[!A-Za-z0-9_.-]*) fail "invalid AI Docker secret name" ;; esac
done
[ "$security_token_secret" != "$reliability_token_secret" ] && [ "$security_token_secret" != "$api_key_secret" ] && [ "$reliability_token_secret" != "$api_key_secret" ] || fail "AI Docker secret names must be distinct"
case "$reuse" in true|false) ;; *) fail "DOCKYARD_REUSE_EXISTING_SECRETS must be true or false" ;; esac
case "$dry_run" in true|false) ;; *) fail "DOCKYARD_INSTALL_DRY_RUN must be true or false" ;; esac
case "$skip_wait" in true|false) ;; *) fail "DOCKYARD_INSTALL_SKIP_WAIT must be true or false" ;; esac
case "$wait_timeout" in ""|*[!0-9]*) fail "DOCKYARD_INSTALL_WAIT_TIMEOUT must be a positive integer" ;; esac
[ "$wait_timeout" -gt 0 ] || fail "DOCKYARD_INSTALL_WAIT_TIMEOUT must be a positive integer"
case "$stability_seconds" in ""|*[!0-9]*) fail "DOCKYARD_INSTALL_STABILITY_SECONDS must be a non-negative integer" ;; esac
[ "$stability_seconds" -le "$wait_timeout" ] || fail "DOCKYARD_INSTALL_STABILITY_SECONDS must not exceed DOCKYARD_INSTALL_WAIT_TIMEOUT"
case "$audit_verify_timeout" in ""|*[!0-9]*) fail "DOCKYARD_AI_VERIFY_TIMEOUT must be a positive integer" ;; esac
[ "$audit_verify_timeout" -gt 0 ] && [ "$audit_verify_timeout" -le 3600 ] || fail "DOCKYARD_AI_VERIFY_TIMEOUT must be between 1 and 3600 seconds"

for command in awk cmp date docker find grep sleep tr wc; do
  command -v "$command" >/dev/null 2>&1 || fail "$command is required"
done

DOCKYARD_IMAGE=${DOCKYARD_IMAGE:-}
NINEROUTER_IMAGE=${NINEROUTER_IMAGE:-}
HEADROOM_IMAGE=${HEADROOM_IMAGE:-}
DOCKYARD_CONTROL_PLANE_URL=${DOCKYARD_CONTROL_PLANE_URL:-}
DOCKYARD_AI_BASE_URL=${DOCKYARD_AI_BASE_URL:-http://9router:20128/v1}
DOCKYARD_AI_MODEL=${DOCKYARD_AI_MODEL:-}
NINEROUTER_STORAGE_NODE_ID=${NINEROUTER_STORAGE_NODE_ID:-}
export DOCKYARD_IMAGE NINEROUTER_IMAGE HEADROOM_IMAGE DOCKYARD_CONTROL_PLANE_URL DOCKYARD_AI_BASE_URL DOCKYARD_AI_MODEL NINEROUTER_STORAGE_NODE_ID
export DOCKYARD_AI_SECURITY_AUDITOR_TOKEN_SECRET="$security_token_secret"
export DOCKYARD_AI_RELIABILITY_AUDITOR_TOKEN_SECRET="$reliability_token_secret"
export DOCKYARD_AI_API_KEY_SECRET="$api_key_secret"

"$root/scripts/ci/check-image-digests.sh" ai
case "$NINEROUTER_STORAGE_NODE_ID" in ""|*[!a-z0-9]*) fail "NINEROUTER_STORAGE_NODE_ID must be a lowercase Swarm node ID" ;; esac
[ "${#NINEROUTER_STORAGE_NODE_ID}" -le 64 ] || fail "NINEROUTER_STORAGE_NODE_ID must be a lowercase Swarm node ID"

swarm_state=$(docker info --format '{{.Swarm.LocalNodeState}} {{.Swarm.ControlAvailable}}')
[ "$swarm_state" = "active true" ] || fail "run this installer on an active Docker Swarm manager"
node_state=$(docker node inspect --format '{{.Status.State}} {{.Spec.Availability}}' "$NINEROUTER_STORAGE_NODE_ID" 2>/dev/null) || fail "NINEROUTER_STORAGE_NODE_ID does not identify a Swarm node"
[ "$node_state" = "ready active" ] || fail "NINEROUTER_STORAGE_NODE_ID must identify a ready, active Swarm node"

validate_secret_file() {
  label=$1
  path=$2
  [ -n "$path" ] || fail "$label is required"
  [ ! -L "$path" ] && [ -f "$path" ] && [ -r "$path" ] || fail "$label must name a readable regular file, not a symbolic link"
  [ -z "$(find "$path" -prune -perm /077 -print)" ] || fail "$label must not be accessible by group or other users"
  size=$(wc -c <"$path" | tr -d ' ')
  [ "$size" -gt 0 ] && [ "$size" -le 16384 ] || fail "$label must contain between 1 and 16384 bytes"
  compact_size=$(tr -d '\r\n' <"$path" | wc -c | tr -d ' ')
  [ "$compact_size" -eq "$size" ] || fail "$label must contain one value without CR or LF characters"
  grep -q '[^[:space:]]' "$path" || fail "$label must not contain only whitespace"
}

security_token_file=${DOCKYARD_AI_SECURITY_AUDITOR_TOKEN_FILE:-}
reliability_token_file=${DOCKYARD_AI_RELIABILITY_AUDITOR_TOKEN_FILE:-}
api_key_file=${DOCKYARD_AI_API_KEY_FILE:-}
validate_secret_file DOCKYARD_AI_SECURITY_AUDITOR_TOKEN_FILE "$security_token_file"
validate_secret_file DOCKYARD_AI_RELIABILITY_AUDITOR_TOKEN_FILE "$reliability_token_file"
validate_secret_file DOCKYARD_AI_API_KEY_FILE "$api_key_file"
cmp -s "$security_token_file" "$reliability_token_file" && fail "security and reliability auditor credentials must be distinct"
cmp -s "$security_token_file" "$api_key_file" && fail "auditor and model credentials must be distinct"
cmp -s "$reliability_token_file" "$api_key_file" && fail "auditor and model credentials must be distinct"

for image_spec in "DOCKYARD_IMAGE:$DOCKYARD_IMAGE" "NINEROUTER_IMAGE:$NINEROUTER_IMAGE" "HEADROOM_IMAGE:$HEADROOM_IMAGE"; do
  image_label=${image_spec%%:*}
  image=${image_spec#*:}
  docker manifest inspect "$image" >/dev/null 2>&1 || fail "$image_label cannot be resolved from the configured registry; authenticate Docker and verify the immutable digest"
done
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --entrypoint /usr/local/bin/dockyard "$DOCKYARD_IMAGE" validate-ai-auditor-config --control-plane-url "$DOCKYARD_CONTROL_PLANE_URL" --model-url "$DOCKYARD_AI_BASE_URL" --model "$DOCKYARD_AI_MODEL" >/dev/null || fail "AI auditor URLs or model name are invalid"

existing=""
for secret_name in "$security_token_secret" "$reliability_token_secret" "$api_key_secret"; do
  if docker secret inspect "$secret_name" >/dev/null 2>&1; then
    existing="$existing $secret_name"
  fi
done
[ -z "$existing" ] || [ "$reuse" = true ] || fail "Docker secrets already exist:$existing; set DOCKYARD_REUSE_EXISTING_SECRETS=true only after verifying their values"

docker stack config -c "$root/deploy/ai-auditors.yml" >/dev/null
if [ "$dry_run" = true ]; then
  echo "Preflight passed for AI auditor stack $stack; no resources were changed."
  exit 0
fi

created_secrets=""
deployment_started=false
cleanup() {
  status=$?
  if [ "$status" -ne 0 ] && [ "$deployment_started" = false ]; then
    for created_secret in $created_secrets; do
      docker secret rm "$created_secret" >/dev/null 2>&1 || true
    done
  fi
  trap - EXIT HUP INT TERM
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

create_secret() {
	name=$1
	path=$2
	if ! docker secret inspect "$name" >/dev/null 2>&1; then
		docker secret create "$name" "$path" >/dev/null
		created_secrets="$created_secrets $name"
	fi
}
create_secret "$security_token_secret" "$security_token_file"
create_secret "$reliability_token_secret" "$reliability_token_file"
create_secret "$api_key_secret" "$api_key_file"

deployment_started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
docker stack deploy --prune --with-registry-auth -c "$root/deploy/ai-auditors.yml" "$stack" || fail "could not submit AI auditor stack $stack"
deployment_started=true
if [ "$skip_wait" = true ]; then
  echo "AI auditor stack $stack submitted; convergence wait was skipped."
  exit 0
fi

deadline=$(( $(date +%s) + wait_timeout ))
stable_since=
while :; do
  services=$(docker stack services "$stack" --format '{{.Name}} {{.Replicas}}') || fail "could not inspect AI auditor stack"
  [ -n "$services" ] || fail "AI auditor stack has no services"
  [ "$(printf '%s\n' "$services" | wc -l | tr -d ' ')" -eq 4 ] || fail "AI auditor stack must contain exactly four services"
  unconverged=$(printf '%s\n' "$services" | awk '{ split($2,n,"/"); if (n[1] != n[2]) print }')
  release_pending=""
  while IFS='|' read -r service expected_image; do
    inspection=$(docker service inspect --format '{{.Spec.TaskTemplate.ContainerSpec.Image}}|{{if .UpdateStatus}}{{.UpdateStatus.State}}{{end}}' "$service" 2>/dev/null || true)
    actual_image=${inspection%%|*}
    update_state=${inspection#*|}
    if [ -z "$inspection" ] || [ "$actual_image" != "$expected_image" ]; then
      release_pending="$release_pending\n$service image is ${actual_image:-unavailable}; expected $expected_image"
    elif [ -n "$update_state" ] && [ "$update_state" != completed ]; then
      release_pending="$release_pending\n$service update state is $update_state"
    fi
  done <<EOF
${stack}_9router|$NINEROUTER_IMAGE
${stack}_headroom|$HEADROOM_IMAGE
${stack}_security-auditor|$DOCKYARD_IMAGE
${stack}_reliability-auditor|$DOCKYARD_IMAGE
EOF
  now=$(date +%s)
  if [ -z "$unconverged" ] && [ -z "$release_pending" ]; then
    [ -n "$stable_since" ] || stable_since=$now
    if [ $((now - stable_since)) -ge "$stability_seconds" ]; then
      break
    fi
  else
    stable_since=
  fi
  if [ "$now" -ge "$deadline" ]; then
    printf '%s\n' "$unconverged" >&2
    printf '%b\n' "$release_pending" >&2
    fail "AI auditor stack $stack did not run the requested images and remain converged for ${stability_seconds}s within ${wait_timeout}s"
  fi
  sleep 2
done
verify_auditor_run() {
  auditor_name=$1
  auditor_token_file=$2
  docker run --rm -i --network host --read-only --cap-drop ALL --security-opt no-new-privileges \
    --entrypoint /usr/local/bin/dockyard "$DOCKYARD_IMAGE" verify-ai-auditor-runs \
    --control-plane-url "$DOCKYARD_CONTROL_PLANE_URL" --agent-name "$auditor_name" --since "$deployment_started_at" \
    --timeout "${audit_verify_timeout}s" <"$auditor_token_file" || fail "$auditor_name did not complete a fresh run within ${audit_verify_timeout}s"
}
verify_auditor_run security-auditor "$security_token_file"
verify_auditor_run reliability-auditor "$reliability_token_file"
echo "AI auditor stack $stack installed, remained converged for ${stability_seconds}s, and completed both fresh audit runs."
