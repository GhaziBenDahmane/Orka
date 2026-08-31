#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
stack=${DOCKYARD_AGENT_STACK_NAME:-dockyard-agent}
network=${DOCKYARD_TRAEFIK_NETWORK:-dockyard-public}
reuse=${DOCKYARD_REUSE_EXISTING_SECRETS:-false}
dry_run=${DOCKYARD_INSTALL_DRY_RUN:-false}
skip_wait=${DOCKYARD_INSTALL_SKIP_WAIT:-false}
wait_timeout=${DOCKYARD_INSTALL_WAIT_TIMEOUT:-300}
stability_seconds=${DOCKYARD_INSTALL_STABILITY_SECONDS:-90}
egress_private_cidrs=${DOCKYARD_EGRESS_PRIVATE_CIDRS:-}
token_secret=${DOCKYARD_AGENT_ENROLLMENT_TOKEN_SECRET:-dockyard_agent_enrollment_token}
edge_proxy_service=${DOCKYARD_EDGE_PROXY_SERVICE_NAME:-}
edge_proxy_dynamic_path=${DOCKYARD_EDGE_PROXY_DYNAMIC_CONFIG_PATH:-}

fail() {
  echo "install-agent: $*" >&2
  exit 1
}

case "$stack" in ""|-*|*[!A-Za-z0-9_.-]*) fail "invalid DOCKYARD_AGENT_STACK_NAME" ;; esac
case "$token_secret" in ""|-*|*[!A-Za-z0-9_.-]*) fail "invalid DOCKYARD_AGENT_ENROLLMENT_TOKEN_SECRET" ;; esac
case "$network" in ""|[!a-z0-9]*|*[!a-z0-9_.-]*) fail "DOCKYARD_TRAEFIK_NETWORK must be a lowercase Docker network name of at most 63 characters" ;; esac
[ "${#network}" -le 63 ] || fail "DOCKYARD_TRAEFIK_NETWORK must be a lowercase Docker network name of at most 63 characters"
case "$edge_proxy_service" in "") [ -z "$edge_proxy_dynamic_path" ] || fail "DOCKYARD_EDGE_PROXY_SERVICE_NAME is required with DOCKYARD_EDGE_PROXY_DYNAMIC_CONFIG_PATH" ;; -*|*[!A-Za-z0-9_.-]*) fail "invalid DOCKYARD_EDGE_PROXY_SERVICE_NAME" ;; *) [ -n "$edge_proxy_dynamic_path" ] || fail "DOCKYARD_EDGE_PROXY_DYNAMIC_CONFIG_PATH is required with DOCKYARD_EDGE_PROXY_SERVICE_NAME" ;; esac
case "$edge_proxy_dynamic_path" in "") ;; /*) case "$edge_proxy_dynamic_path" in *".."*|*[!A-Za-z0-9_./-]*) fail "invalid DOCKYARD_EDGE_PROXY_DYNAMIC_CONFIG_PATH" ;; esac ;; *) fail "DOCKYARD_EDGE_PROXY_DYNAMIC_CONFIG_PATH must be absolute" ;; esac
case "$reuse" in true|false) ;; *) fail "DOCKYARD_REUSE_EXISTING_SECRETS must be true or false" ;; esac
case "$dry_run" in true|false) ;; *) fail "DOCKYARD_INSTALL_DRY_RUN must be true or false" ;; esac
case "$skip_wait" in true|false) ;; *) fail "DOCKYARD_INSTALL_SKIP_WAIT must be true or false" ;; esac
case "$wait_timeout" in ""|*[!0-9]*) fail "DOCKYARD_INSTALL_WAIT_TIMEOUT must be a positive integer" ;; esac
[ "$wait_timeout" -gt 0 ] || fail "DOCKYARD_INSTALL_WAIT_TIMEOUT must be a positive integer"
case "$stability_seconds" in ""|*[!0-9]*) fail "DOCKYARD_INSTALL_STABILITY_SECONDS must be a non-negative integer" ;; esac
[ "$stability_seconds" -le "$wait_timeout" ] || fail "DOCKYARD_INSTALL_STABILITY_SECONDS must not exceed DOCKYARD_INSTALL_WAIT_TIMEOUT"

for command in awk date docker find grep sleep tr wc; do
  command -v "$command" >/dev/null 2>&1 || fail "$command is required"
done

control_plane_url=${DOCKYARD_CONTROL_PLANE_URL:-}
agent_url=${DOCKYARD_AGENT_URL:-}

DOCKYARD_IMAGE=${DOCKYARD_IMAGE:-}
export DOCKYARD_IMAGE
"$root/scripts/ci/check-image-digests.sh" agent

swarm_state=$(docker info --format '{{.Swarm.LocalNodeState}} {{.Swarm.ControlAvailable}}')
[ "$swarm_state" = "active true" ] || fail "run this installer on an active Docker Swarm manager"

token_file=${DOCKYARD_AGENT_ENROLLMENT_TOKEN_FILE:-}
[ -n "$token_file" ] || fail "DOCKYARD_AGENT_ENROLLMENT_TOKEN_FILE is required"
[ ! -L "$token_file" ] && [ -f "$token_file" ] && [ -r "$token_file" ] || fail "DOCKYARD_AGENT_ENROLLMENT_TOKEN_FILE must name a readable regular file, not a symbolic link"
[ -z "$(find "$token_file" -prune -perm /077 -print)" ] || fail "DOCKYARD_AGENT_ENROLLMENT_TOKEN_FILE must not be accessible by group or other users"
token_size=$(wc -c <"$token_file" | tr -d ' ')
[ "$token_size" -ge 32 ] && [ "$token_size" -le 4096 ] || fail "DOCKYARD_AGENT_ENROLLMENT_TOKEN_FILE must contain between 32 and 4096 bytes"
token_without_line_breaks_size=$(tr -d '\r\n' <"$token_file" | wc -c | tr -d ' ')
[ "$token_without_line_breaks_size" -eq "$token_size" ] || fail "DOCKYARD_AGENT_ENROLLMENT_TOKEN_FILE must contain exactly one token without CR or LF characters"
unset token_without_line_breaks_size

DOCKYARD_AGENT_SERVICE_NAME=${stack}_agent
export DOCKYARD_CONTROL_PLANE_URL="$control_plane_url"
export DOCKYARD_AGENT_URL="$agent_url"
export DOCKYARD_AGENT_ENROLLMENT_TOKEN_SECRET="$token_secret"
export DOCKYARD_AGENT_SERVICE_NAME DOCKYARD_TRAEFIK_NETWORK="$network"
export DOCKYARD_EGRESS_PRIVATE_CIDRS="$egress_private_cidrs"
export DOCKYARD_EDGE_PROXY_SERVICE_NAME="$edge_proxy_service"
export DOCKYARD_EDGE_PROXY_DYNAMIC_CONFIG_PATH="$edge_proxy_dynamic_path"

docker manifest inspect "$DOCKYARD_IMAGE" >/dev/null 2>&1 || fail "DOCKYARD_IMAGE cannot be resolved from the configured registry; authenticate Docker and verify the immutable digest"
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --entrypoint /usr/local/bin/dockyard "$DOCKYARD_IMAGE" validate-agent-endpoints --control-plane-url "$control_plane_url" --agent-url "$agent_url" >/dev/null || fail "DOCKYARD_CONTROL_PLANE_URL and DOCKYARD_AGENT_URL must be valid HTTPS origins without credentials, paths, queries, or fragments"
if [ -n "$egress_private_cidrs" ]; then
  docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --entrypoint /usr/local/bin/dockyard "$DOCKYARD_IMAGE" validate-egress-policy --cidrs "$egress_private_cidrs" >/dev/null || fail "DOCKYARD_EGRESS_PRIVATE_CIDRS must contain at most 64 unique CIDR networks"
fi

if docker secret inspect "$token_secret" >/dev/null 2>&1 && [ "$reuse" != true ]; then
  fail "Docker secret $token_secret already exists; set DOCKYARD_REUSE_EXISTING_SECRETS=true only when the agent identity volume is intact"
fi

docker stack config -c "$root/deploy/agent-swarm.yml" >/dev/null
stack_existed=false
stack_inventory=$(docker stack ls --format '{{.Name}}') || fail "could not inspect existing Swarm stacks"
if printf '%s\n' "$stack_inventory" | grep -Fxq "$stack"; then
  stack_existed=true
fi
unset stack_inventory
network_exists=false
if docker network inspect "$network" >/dev/null 2>&1; then
  network_exists=true
  network_properties=$(docker network inspect --format '{{.Driver}}|{{.Scope}}|{{.Attachable}}|{{json .Options}}' "$network") || fail "could not inspect Docker network $network"
  printf '%s\n' "$network_properties" | grep -Eq '^overlay\|swarm\|true\|.*"encrypted":(""|"true")([,}]|$)' || fail "existing Docker network $network must be an attachable encrypted Swarm overlay; remove and recreate it with --driver overlay --opt encrypted --attachable"
fi
if [ -n "$edge_proxy_service" ]; then
  proxy_args=$(docker service inspect --format '{{range .Spec.TaskTemplate.ContainerSpec.Args}}{{println .}}{{end}}' "$edge_proxy_service" 2>/dev/null) || fail "edge proxy service $edge_proxy_service does not exist"
  printf '%s\n' "$proxy_args" | grep -Fx -- "--providers.file.directory=$edge_proxy_dynamic_path" >/dev/null || fail "edge proxy service $edge_proxy_service does not enable the Traefik file provider at $edge_proxy_dynamic_path"
  network_id=$(docker network inspect --format '{{.ID}}' "$network") || fail "could not resolve Docker network $network"
  proxy_networks=$(docker service inspect --format '{{range .Spec.TaskTemplate.Networks}}{{println .Target}}{{end}}' "$edge_proxy_service") || fail "could not inspect edge proxy networks"
  printf '%s\n' "$proxy_networks" | grep -Fx -- "$network_id" >/dev/null || fail "edge proxy service $edge_proxy_service is not attached to $network"
fi
if [ "$dry_run" = true ]; then
  echo "Preflight passed for agent stack $stack; no resources were changed."
  exit 0
fi

created_secret=false
created_network=false
deployment_started=false
remove_created_resources() {
  cleanup_deadline=$(( $(date +%s) + 60 ))
  while :; do
    if [ "$created_secret" = true ] && docker secret rm "$token_secret" >/dev/null 2>&1; then
      created_secret=false
    fi
    if [ "$created_network" = true ] && docker network rm "$network" >/dev/null 2>&1; then
      created_network=false
    fi
    [ "$created_secret" = false ] && [ "$created_network" = false ] && return 0
    if [ "$(date +%s)" -ge "$cleanup_deadline" ]; then
      echo "install-agent: cleanup timed out; remove the remaining agent secret or network manually" >&2
      return 1
    fi
    sleep 2
  done
}
cleanup() {
  status=${1:-$?}
  if [ "$status" -ne 0 ]; then
    if [ "$deployment_started" = true ] && [ "$stack_existed" = false ]; then
      echo "install-agent: first installation failed; removing stack $stack and newly created resources" >&2
      if docker stack rm "$stack" >/dev/null 2>&1; then
        remove_created_resources || true
      else
        echo "install-agent: could not remove failed stack $stack; newly created resources were retained" >&2
      fi
    elif [ "$deployment_started" = false ]; then
      remove_created_resources || true
    fi
  fi
  trap - EXIT HUP INT TERM
  exit "$status"
}
trap cleanup EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM

if [ "$network_exists" = false ]; then
  docker network create --driver overlay --opt encrypted --attachable "$network" >/dev/null
  created_network=true
fi
if ! docker secret inspect "$token_secret" >/dev/null 2>&1; then
  docker secret create "$token_secret" "$token_file" >/dev/null
  created_secret=true
fi

docker stack deploy --prune --with-registry-auth -c "$root/deploy/agent-swarm.yml" "$stack" || fail "could not submit agent stack $stack"
deployment_started=true
if [ "$skip_wait" = true ]; then
  echo "Agent stack $stack submitted; convergence wait was skipped."
  exit 0
fi

deadline=$(( $(date +%s) + wait_timeout ))
stable_since=
while :; do
  services=$(docker stack services "$stack" --format '{{.Name}} {{.Replicas}}') || fail "could not inspect agent stack"
  [ -n "$services" ] || fail "agent stack has no services"
  unconverged=$(printf '%s\n' "$services" | awk '{ split($2,n,"/"); if (n[1] != n[2]) print }')
  inspection=$(docker service inspect --format '{{.Spec.TaskTemplate.ContainerSpec.Image}}|{{if .UpdateStatus}}{{.UpdateStatus.State}}{{end}}' "$DOCKYARD_AGENT_SERVICE_NAME" 2>/dev/null || true)
  actual_image=${inspection%%|*}
  update_state=${inspection#*|}
  release_pending=""
  if [ -z "$inspection" ] || [ "$actual_image" != "$DOCKYARD_IMAGE" ]; then
    release_pending="$DOCKYARD_AGENT_SERVICE_NAME image is ${actual_image:-unavailable}; expected $DOCKYARD_IMAGE"
  elif [ -n "$update_state" ] && [ "$update_state" != completed ]; then
    release_pending="$DOCKYARD_AGENT_SERVICE_NAME update state is $update_state"
  fi
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
    printf '%s\n' "$release_pending" >&2
    fail "agent stack $stack did not run the requested image and remain converged for ${stability_seconds}s within ${wait_timeout}s"
  fi
  sleep 2
done
echo "Agent stack $stack installed and remained converged for ${stability_seconds}s; verify its heartbeat in the Dockyard cluster view."
