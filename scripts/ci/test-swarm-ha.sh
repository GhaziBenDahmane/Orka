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

for command in awk docker git jq; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "$command is required for Swarm HA conformance" >&2
    exit 1
  fi
done
for image in "$dind_image" "$probe_image"; do
  if ! "$root_dir/scripts/ci/validate-image-reference.sh" "$image"; then
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

wait_for_manager_state() {
  local observer="$1" target="$2" expected_state="$3" expected_reachability="$4"
  for _ in {1..90}; do
    local observation
    observation="$(docker exec "$observer" docker node inspect --format '{{.Status.State}} {{.ManagerStatus.Reachability}}' "$target" 2>/dev/null || true)"
    if [ "$observation" = "$expected_state $expected_reachability" ]; then
      printf '%s' "$observation"
      return 0
    fi
    sleep 1
  done
  echo "manager $target did not reach $expected_state/$expected_reachability through $observer" >&2
  return 1
}

wait_for_manager_unreachable() {
  local observer="$1" target="$2"
  for _ in {1..90}; do
    local observation state reachability
    observation="$(docker exec "$observer" docker node inspect --format '{{.Status.State}} {{.ManagerStatus.Reachability}}' "$target" 2>/dev/null || true)"
    read -r state reachability <<<"$observation"
    if [ "$reachability" = "unreachable" ] && [ "$state" != "ready" ]; then
      printf '%s' "$observation"
      return 0
    fi
    sleep 1
  done
  echo "manager $target did not become unreachable through $observer" >&2
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

wait_for_replaced_tasks() {
  local node="$1" failed_node="$2" previous_task_ids="$3"
  for _ in {1..120}; do
    failover_replicas="$(docker exec "$node" docker service ls --filter name=dockyard-ha-probe --format '{{.Replicas}}' 2>/dev/null || true)"
    failover_task_ids="$(docker exec "$node" docker service ps dockyard-ha-probe --filter desired-state=running --format '{{.ID}}' 2>/dev/null | sort || true)"
    failover_task_nodes="$(docker exec "$node" docker service ps dockyard-ha-probe --filter desired-state=running --format '{{.Node}}' 2>/dev/null | sort -u || true)"
    if [ "$failover_task_ids" != "$previous_task_ids" ] &&
      [ "$(wc -l <<<"$failover_task_ids" | tr -d ' ')" -eq 3 ] &&
      ! grep -qx "$failed_node" <<<"$failover_task_nodes"; then
      return 0
    fi
    sleep 1
  done
  echo "probe workload was not rescheduled away from failed manager $failed_node" >&2
  docker exec "$node" docker service ps dockyard-ha-probe --no-trunc >&2 || true
  return 1
}

docker network create "$network" >/dev/null
echo "PHASE start-daemons"
for node in "$manager1" "$manager2" "$manager3"; do
  docker run --detach --privileged --name "$node" --hostname "$node" --network "$network" \
    --env DOCKER_TLS_CERTDIR= "$dind_image" >/dev/null
done
for node in "$manager1" "$manager2" "$manager3"; do
  wait_for_daemon "$node"
done
if ! docker exec "$manager1" sh -c 'command -v timeout >/dev/null'; then
  echo "the pinned DinD image must provide timeout for minority-write cancellation" >&2
  exit 1
fi

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

initial_manager_count="$(docker exec "$manager1" docker node ls --filter role=manager --format '{{.ID}}' | wc -l | tr -d ' ')"
initial_replicas="$(docker exec "$manager1" docker service ls --filter name=dockyard-ha-probe --format '{{.Replicas}}')"
initial_task_ids="$(docker exec "$manager1" docker service ps dockyard-ha-probe --filter desired-state=running --format '{{.ID}}' | sort)"
initial_task_nodes="$(docker exec "$manager1" docker service ps dockyard-ha-probe --filter desired-state=running --format '{{.Node}}' | sort -u)"
test "$(wc -l <<<"$initial_task_ids" | tr -d ' ')" -eq 3
test "$(wc -l <<<"$initial_task_nodes" | tr -d ' ')" -eq 3

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
replacement_leader="$(docker exec "$manager2" docker node ls --filter role=manager --format '{{.Hostname}} {{.ManagerStatus}}' | awk '$2=="Leader" {print $1}')"
if [ -z "$replacement_leader" ] || [ "$replacement_leader" = "$leader" ]; then
  echo "leader did not move away from failed manager $leader: replacement=$replacement_leader" >&2
  exit 1
fi
failed_manager_observation="$(wait_for_manager_unreachable "$manager2" "$manager1")"
wait_for_replaced_tasks "$manager2" "$manager1" "$initial_task_ids"
failover_active_task_count="$(wc -l <<<"$failover_task_ids" | tr -d ' ')"
failover_failed_node_task_count="$(grep -cx "$manager1" <<<"$failover_task_nodes" || true)"
failover_seconds="$(( $(date +%s) - failover_started ))"

docker unpause "$manager1" >/dev/null
wait_for_managers "$manager2" 3
wait_for_leader "$manager2"
recovered_manager_observation="$(wait_for_manager_state "$manager2" "$manager1" ready reachable)"
wait_for_replicas "$manager2" 3
rejoined_replicas="$(docker exec "$manager2" docker service ls --filter name=dockyard-ha-probe --format '{{.Replicas}}')"

echo "PHASE lose-quorum"
minority_version_before="$(docker exec "$manager2" docker service inspect --format '{{.Version.Index}}' dockyard-ha-probe)"
docker pause "$manager1" "$manager2" >/dev/null
set +e
docker exec "$manager3" timeout -s KILL 15 docker service update --label-add dockyard.quorum-test=true dockyard-ha-probe >/dev/null 2>&1
minority_update_exit="$?"
set -e
if [ "$minority_update_exit" -eq 0 ]; then
  echo "Swarm accepted a service mutation without manager quorum" >&2
  exit 1
fi
if [ "$minority_update_exit" -ne 137 ]; then
  echo "minority mutation failed unexpectedly with status $minority_update_exit" >&2
  exit 1
fi
minority_processes_after="$(docker exec "$manager3" sh -c 'ps -o args | grep -F "docker service update --label-add dockyard.quorum-test=true" | grep -v grep || true')"
if [ -n "$minority_processes_after" ]; then
  echo "minority mutation process survived its deadline: $minority_processes_after" >&2
  exit 1
fi

quorum_started="$(date +%s)"
echo "PHASE restore-quorum"
docker unpause "$manager2" >/dev/null
wait_for_leader "$manager2"
minority_version_after="$(docker exec "$manager2" docker service inspect --format '{{.Version.Index}}' dockyard-ha-probe)"
minority_label_after_recovery="$(docker exec "$manager2" docker service inspect --format '{{json .Spec.Labels}}' dockyard-ha-probe | jq -r '.["dockyard.quorum-test"] // ""')"
if [ "$minority_version_after" != "$minority_version_before" ] || [ -n "$minority_label_after_recovery" ]; then
  echo "minority manager changed service state: version $minority_version_before -> $minority_version_after label=$minority_label_after_recovery" >&2
  exit 1
fi
docker exec "$manager2" docker service update --detach --label-add dockyard.quorum-restored=true dockyard-ha-probe >/dev/null
wait_for_replicas "$manager2" 3
quorum_version="$(docker exec "$manager2" docker service inspect --format '{{.Version.Index}}' dockyard-ha-probe)"
quorum_label="$(docker exec "$manager2" docker service inspect --format '{{json .Spec.Labels}}' dockyard-ha-probe | jq -r '.["dockyard.quorum-restored"] // ""')"
if [ "$quorum_label" != "true" ] || [ -n "$minority_label_after_recovery" ] || [ "$quorum_version" -le "$minority_version_after" ]; then
  echo "service mutation was not committed after quorum recovery" >&2
  exit 1
fi
recovered_replicas="$(docker exec "$manager2" docker service ls --filter name=dockyard-ha-probe --format '{{.Replicas}}')"
quorum_recovery_seconds="$(( $(date +%s) - quorum_started ))"

initial_tasks_json="$(jq -R -s 'split("\n") | map(select(length > 0))' <<<"$initial_task_ids")"
failover_tasks_json="$(jq -R -s 'split("\n") | map(select(length > 0))' <<<"$failover_task_ids")"

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
  --arg failedManagerObservation "$failed_manager_observation" \
  --arg recoveredManagerObservation "$recovered_manager_observation" \
  --arg initialReplicas "$initial_replicas" \
  --arg failoverReplicas "$failover_replicas" \
  --arg rejoinedReplicas "$rejoined_replicas" \
  --arg recoveredReplicas "$recovered_replicas" \
  --argjson initialTaskIds "$initial_tasks_json" \
  --argjson failoverTaskIds "$failover_tasks_json" \
  --argjson managerCount "$initial_manager_count" \
  --argjson failoverActiveTaskCount "$failover_active_task_count" \
  --argjson failoverFailedNodeTaskCount "$failover_failed_node_task_count" \
  --argjson minorityVersionBefore "$minority_version_before" \
  --argjson minorityVersionAfter "$minority_version_after" \
  --argjson minorityUpdateExit "$minority_update_exit" \
  --argjson quorumVersion "$quorum_version" \
  --arg quorumRestoredLabel "$quorum_label" \
  --arg minorityLabelAfterRecovery "$minority_label_after_recovery" \
  --argjson failoverSeconds "$failover_seconds" \
  --argjson quorumRecoverySeconds "$quorum_recovery_seconds" \
  '{status:$status,sourceCommit:$sourceCommit,createdAt:$createdAt,dindImage:$dindImage,probeImage:$probeImage,managers:$managerCount,replicas:($initialTaskIds | length),observations:{initialLeader:$initialLeader,replacementLeader:$replacementLeader,failedManager:$failedManagerObservation,recoveredManager:$recoveredManagerObservation,initialReplicas:$initialReplicas,failoverReplicas:$failoverReplicas,rejoinedReplicas:$rejoinedReplicas,recoveredReplicas:$recoveredReplicas,initialTaskIds:$initialTaskIds,failoverTaskIds:$failoverTaskIds,failoverActiveTaskCount:$failoverActiveTaskCount,failoverFailedNodeTaskCount:$failoverFailedNodeTaskCount,minorityUpdateExit:$minorityUpdateExit,minorityVersionBefore:$minorityVersionBefore,minorityVersionAfter:$minorityVersionAfter,quorumVersion:$quorumVersion,quorumRestoredLabel:$quorumRestoredLabel,minorityLabelAfterRecovery:$minorityLabelAfterRecovery},leaderFailoverSeconds:$failoverSeconds,leaderChanged:($initialLeader != $replacementLeader),failedManagerObserved:($failedManagerObservation | test("^(down|unknown) unreachable$")),failedManagerRecovered:($recoveredManagerObservation == "ready reachable"),workloadTaskReplaced:($initialTaskIds != $failoverTaskIds),workloadAvailableAfterFailover:($failoverActiveTaskCount == 3 and $failoverFailedNodeTaskCount == 0),minorityMutationRejected:($minorityUpdateExit == 137 and $minorityVersionBefore == $minorityVersionAfter and $minorityLabelAfterRecovery == ""),quorumMutationCommitted:($quorumVersion > $minorityVersionAfter and $quorumRestoredLabel == "true"),quorumRecoverySeconds:$quorumRecoverySeconds,replicasConverged:($initialReplicas == "3/3" and $rejoinedReplicas == "3/3" and $recoveredReplicas == "3/3")}' \
  > "$evidence_file"
jq -e --arg sourceCommit "$source_commit" '
  .status == "passed" and .sourceCommit == $sourceCommit and
  (.dindImage | test("@sha256:[a-f0-9]{64}$")) and
  (.probeImage | test("@sha256:[a-f0-9]{64}$")) and
  .managers == 3 and .replicas == 3 and .minorityMutationRejected and
  .quorumMutationCommitted and .leaderChanged and .failedManagerObserved and
  .failedManagerRecovered and .workloadTaskReplaced and .workloadAvailableAfterFailover and .replicasConverged and
  .observations.initialLeader != .observations.replacementLeader and
  .observations.initialReplicas == "3/3" and .observations.rejoinedReplicas == "3/3" and
  .observations.recoveredReplicas == "3/3" and
  (.observations.initialTaskIds | length) == 3 and (.observations.failoverTaskIds | length) == 3 and
  .observations.failoverActiveTaskCount == 3 and .observations.failoverFailedNodeTaskCount == 0 and
  .observations.minorityVersionBefore == .observations.minorityVersionAfter and
  .observations.minorityUpdateExit == 137 and
  .observations.minorityLabelAfterRecovery == "" and
  .observations.quorumVersion > .observations.minorityVersionAfter and
  .observations.quorumRestoredLabel == "true" and .leaderFailoverSeconds >= 0 and
  .quorumRecoverySeconds >= 0
' "$evidence_file" >/dev/null
printf 'HA_EVIDENCE '
cat "$evidence_file"
