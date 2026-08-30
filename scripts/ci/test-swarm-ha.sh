#!/usr/bin/env bash
set -euo pipefail

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
dind_image="${DOCKYARD_TEST_DIND_IMAGE:-docker:29-dind@sha256:12e683a161823b2a839aeea999b9d960e6e1f9a97b1679ad6b441982e2d9cf07}"
probe_image="${DOCKYARD_TEST_SWARM_PROBE_IMAGE:-docker:29-cli@sha256:000bb62ff495f986c9f5578eb67cc2cb98b91138eda81d7762d5371eb8a497fe}"
evidence_file="${1:-swarm-ha-conformance.json}"
run_id="${GITHUB_RUN_ID:-local}-$$"
network="dockyard-ha-$run_id"
manager1="dockyard-ha-$run_id-manager-1"
manager2="dockyard-ha-$run_id-manager-2"
manager3="dockyard-ha-$run_id-manager-3"
work_dir="$(mktemp -d)"
probe_tag="dockyard-ha-probe-image:$run_id"

cleanup() {
  docker rm -f "$manager1" "$manager2" "$manager3" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker image rm "$probe_tag" >/dev/null 2>&1 || true
  rm -rf "$work_dir"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

for command in docker git jq timeout; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "$command is required for Swarm HA conformance" >&2
    exit 1
  fi
done
for image in "$dind_image" "$probe_image"; do
  if [[ ! "$image" =~ ^[^[:space:]]+@sha256:[a-f0-9]{64}$ ]]; then
    echo "Swarm HA conformance images must be pinned by sha256 digest: $image" >&2
    exit 1
  fi
done

wait_for_daemon() {
  local node="$1"
  for _ in {1..60}; do
    if docker exec "$node" docker info >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "Docker daemon did not become ready in $node" >&2
  return 1
}

wait_for_managers() {
  local node="$1" expected="$2"
  for _ in {1..60}; do
    local count
    count="$(docker exec "$node" docker node ls --filter role=manager --format '{{.ID}}' 2>/dev/null | wc -l | tr -d ' ' || true)"
    if [ "$count" = "$expected" ]; then
      return 0
    fi
    sleep 1
  done
  echo "Swarm did not report $expected managers through $node" >&2
  return 1
}

wait_for_leader() {
  local node="$1"
  for _ in {1..90}; do
    if docker exec "$node" docker node ls --filter role=manager --format '{{.ManagerStatus}}' 2>/dev/null | grep -qx Leader; then
      return 0
    fi
    sleep 1
  done
  echo "Swarm did not elect a leader reachable through $node" >&2
  return 1
}

wait_for_replicas() {
  local node="$1" expected="$2"
  for _ in {1..90}; do
    local replicas
    replicas="$(docker exec "$node" docker service ls --filter name=dockyard-ha-probe --format '{{.Replicas}}' 2>/dev/null || true)"
    if [ "$replicas" = "$expected/$expected" ]; then
      return 0
    fi
    sleep 1
  done
  echo "probe service did not converge to $expected/$expected through $node" >&2
  docker exec "$node" docker service ps dockyard-ha-probe --no-trunc >&2 || true
  return 1
}

docker network create "$network" >/dev/null
echo "PHASE start-daemons"
for node in "$manager1" "$manager2" "$manager3"; do
  docker run --detach --privileged --name "$node" --hostname "$node" --network "$network" \
    --env DOCKER_TLS_CERTDIR= "$dind_image" >/dev/null
  wait_for_daemon "$node"
done

manager1_ip="$(docker inspect --format "{{with index .NetworkSettings.Networks \"$network\"}}{{.IPAddress}}{{end}}" "$manager1")"
echo "PHASE form-swarm"
docker exec "$manager1" docker swarm init --advertise-addr "$manager1_ip" >/dev/null
join_token="$(docker exec "$manager1" docker swarm join-token --quiet manager)"
for node in "$manager2" "$manager3"; do
  docker exec "$node" docker swarm join --token "$join_token" "$manager1_ip:2377" >/dev/null
done
wait_for_managers "$manager1" 3
wait_for_leader "$manager1"

docker image inspect "$probe_image" >/dev/null 2>&1 || docker pull "$probe_image" >/dev/null
docker tag "$probe_image" "$probe_tag"
docker save --output "$work_dir/probe-image.tar" "$probe_tag"
for node in "$manager1" "$manager2" "$manager3"; do
  docker exec --interactive "$node" docker load < "$work_dir/probe-image.tar" >/dev/null
done

echo "PHASE converge-baseline"
docker exec "$manager1" docker service create --detach --name dockyard-ha-probe --replicas 3 \
  --constraint node.role==manager --no-resolve-image "$probe_tag" sh -c 'while :; do sleep 60; done' >/dev/null
wait_for_replicas "$manager1" 3

leader="$(docker exec "$manager1" docker node ls --filter role=manager --format '{{.Hostname}} {{.ManagerStatus}}' | awk '$2=="Leader" {print $1}')"
if [ "$leader" != "$manager1" ]; then
  echo "expected bootstrap manager $manager1 to be leader, got $leader" >&2
  exit 1
fi

failover_started="$(date +%s)"
echo "PHASE partition-leader"
docker pause "$manager1" >/dev/null
wait_for_managers "$manager2" 3
wait_for_leader "$manager2"
wait_for_replicas "$manager2" 3
replacement_leader="$(docker exec "$manager2" docker node ls --filter role=manager --format '{{.Hostname}} {{.ManagerStatus}}' | awk '$2=="Leader" {print $1}')"
test -n "$replacement_leader"
failover_seconds="$(( $(date +%s) - failover_started ))"

docker unpause "$manager1" >/dev/null
wait_for_managers "$manager2" 3
wait_for_leader "$manager2"

echo "PHASE lose-quorum"
docker pause "$manager1" "$manager2" >/dev/null
if timeout 15 docker exec "$manager3" docker service update --label-add dockyard.quorum-test=true dockyard-ha-probe >/dev/null 2>&1; then
  echo "Swarm accepted a service mutation without manager quorum" >&2
  exit 1
fi

quorum_started="$(date +%s)"
echo "PHASE restore-quorum"
docker unpause "$manager2" >/dev/null
wait_for_leader "$manager2"
docker exec "$manager2" docker service update --detach --label-add dockyard.quorum-restored=true dockyard-ha-probe >/dev/null
wait_for_replicas "$manager2" 3
quorum_recovery_seconds="$(( $(date +%s) - quorum_started ))"

created_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
source_commit="${GITHUB_SHA:-$(git -C "$root_dir" rev-parse HEAD)}"
jq -n \
  --arg status passed \
  --arg createdAt "$created_at" \
	--arg sourceCommit "$source_commit" \
  --arg dindImage "$dind_image" \
  --arg probeImage "$probe_image" \
  --arg initialLeader "$leader" \
  --arg replacementLeader "$replacement_leader" \
  --argjson failoverSeconds "$failover_seconds" \
  --argjson quorumRecoverySeconds "$quorum_recovery_seconds" \
  '{status:$status,sourceCommit:$sourceCommit,createdAt:$createdAt,dindImage:$dindImage,probeImage:$probeImage,managers:3,replicas:3,initialLeader:$initialLeader,replacementLeader:$replacementLeader,leaderFailoverSeconds:$failoverSeconds,minorityMutationRejected:true,quorumRecoverySeconds:$quorumRecoverySeconds,replicasConverged:true}' \
  > "$evidence_file"
jq -e --arg sourceCommit "$source_commit" '
  .status == "passed" and .sourceCommit == $sourceCommit and
  (.dindImage | test("@sha256:[a-f0-9]{64}$")) and
  (.probeImage | test("@sha256:[a-f0-9]{64}$")) and
  .managers == 3 and .replicas == 3 and .minorityMutationRejected and
  .replicasConverged and .leaderFailoverSeconds >= 0 and
  .quorumRecoverySeconds >= 0
' "$evidence_file" >/dev/null
printf 'HA_EVIDENCE '
cat "$evidence_file"
