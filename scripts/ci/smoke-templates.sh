#!/usr/bin/env bash
set -euo pipefail

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
project="dockyard-template-smoke"
port="${DOCKYARD_TEMPLATE_SMOKE_PORT:-18081}"
evidence_file="${DOCKYARD_TEMPLATE_EVIDENCE:-template-conformance.json}"
barktrace_version="${DOCKYARD_TEMPLATE_SMOKE_BARKTRACE_VERSION:-0.48.0}"
template_selection="${DOCKYARD_TEMPLATE_SMOKE_TEMPLATES:-9router postgres timescaledb mysql mariadb mongo redis valkey libsql clickhouse qdrant meilisearch barktrace-sqlite barktrace-postgres}"
read -r -a template_keys <<<"$template_selection"
if (( ${#template_keys[@]} == 0 )); then
  echo "DOCKYARD_TEMPLATE_SMOKE_TEMPLATES must select at least one template" >&2
  exit 1
fi
declare -A selected_templates=()
for template_key in "${template_keys[@]}"; do
  case "$template_key" in
    9router|postgres|timescaledb|mysql|mariadb|mongo|redis|valkey|libsql|clickhouse|qdrant|meilisearch|barktrace-sqlite|barktrace-postgres) ;;
    *) echo "unsupported template smoke target: $template_key" >&2; exit 1 ;;
  esac
  if [[ -n "${selected_templates[$template_key]:-}" ]]; then
    echo "duplicate template smoke target: $template_key" >&2
    exit 1
  fi
  selected_templates[$template_key]=true
done
export DOCKYARD_HTTP_BIND="127.0.0.1:$port"
export DOCKYARD_POSTGRES_BIND="${DOCKYARD_POSTGRES_BIND:-127.0.0.1:54339}"
base_url="http://127.0.0.1:$port"
network="dockyard-public"
initialized_swarm=false
created_network=false
stacks=()
products='[]'
state_marker='dockyard-template-smoke-v1'
barktrace_sqlite_file_id=''

wait_for_deployment() {
  local deployment_id="$1"
  local response status=""
  for _ in {1..120}; do
    response="$(curl --fail --silent --show-error "${headers[@]}" "$base_url/v1/deployments/$deployment_id")"
    status="$(jq -er '.status' <<<"$response")"
    [[ "$status" == succeeded ]] && return 0
    if [[ "$status" == failed || "$status" == cancelled ]]; then
      jq . <<<"$response" >&2
      return 1
    fi
    sleep 1
  done
  echo "deployment $deployment_id did not succeed before the timeout" >&2
  if [[ -n "$response" ]]; then
    jq . <<<"$response" >&2 || printf '%s\n' "$response" >&2
  fi
  return 1
}

wait_for_service() {
  local service_name="$1"
  for _ in {1..90}; do
    if [[ "$(docker service ls --filter "name=$service_name" --format '{{.Replicas}}')" == "1/1" ]]; then
      return 0
    fi
    sleep 1
  done
  docker service ps --no-trunc "$service_name" >&2 || true
  return 1
}

service_container() {
  local service_name="$1"
  docker ps --filter "label=com.docker.swarm.service.name=$service_name" --filter status=running --format '{{.ID}}' | head -1
}

service_task() {
  local service_name="$1"
  docker service ps --filter desired-state=running --quiet "$service_name" | head -1
}

task_local_image_id() {
  local task_id="$1" container_id
  container_id="$(docker inspect "$task_id" --format '{{.Status.ContainerStatus.ContainerID}}')"
  test -n "$container_id"
  docker inspect "$container_id" --format '{{.Image}}'
}

libsql_request() {
  local stack="$1" service_name="$2" statements="$3"
  docker run --rm --network "${stack}_default" \
    --env LIBSQL_HOST="$service_name" \
    --env LIBSQL_USER=smoke \
    --env LIBSQL_PASSWORD=template-smoke-libsql \
    --env LIBSQL_STATEMENTS="$statements" \
    python:3.13-alpine python3 -c '
import base64, json, os, time, urllib.request
url = "http://%s:8080/" % os.environ["LIBSQL_HOST"]
token = base64.b64encode((os.environ["LIBSQL_USER"] + ":" + os.environ["LIBSQL_PASSWORD"]).encode()).decode()
request = urllib.request.Request(url, data=json.dumps({"statements": json.loads(os.environ["LIBSQL_STATEMENTS"])}).encode(), headers={"authorization": "Basic " + token, "content-type": "application/json"}, method="POST")
for attempt in range(60):
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            result = json.load(response)
        if any(item.get("error") for item in result): raise RuntimeError(result)
        print(json.dumps(result, separators=(",", ":")))
        break
    except Exception:
        if attempt == 59: raise
        time.sleep(1)
'
}

http_database_probe() {
  local stack="$1" service_name="$2" engine="$3" mode="$4" secret="$5"
  docker run --rm --network "${stack}_default" \
    --env PROBE_HOST="$service_name" --env PROBE_ENGINE="$engine" \
    --env PROBE_MODE="$mode" --env PROBE_SECRET="$secret" \
    --env STATE_MARKER="$state_marker" \
    python:3.13-alpine python3 -c '
import json, os, time, urllib.request
engine, mode, host = os.environ["PROBE_ENGINE"], os.environ["PROBE_MODE"], os.environ["PROBE_HOST"]
secret, marker = os.environ["PROBE_SECRET"], os.environ["STATE_MARKER"]
if engine == "qdrant":
    base = "http://%s:6333" % host
    headers = {"api-key": secret, "content-type": "application/json"}
    def request(method, path, value=None):
        data = json.dumps(value).encode() if value is not None else None
        with urllib.request.urlopen(urllib.request.Request(base + path, data=data, headers=headers, method=method), timeout=30) as response: return json.load(response)
    if mode == "seed":
        request("PUT", "/collections/dockyard_template_smoke", {"vectors": {"size": 4, "distance": "Cosine"}})
        request("PUT", "/collections/dockyard_template_smoke/points?wait=true", {"points": [{"id": 1, "vector": [1, 0, 0, 0], "payload": {"value": marker}}]})
    else:
        print(request("GET", "/collections/dockyard_template_smoke/points/1")["result"]["payload"]["value"])
elif engine == "meilisearch":
    base = "http://%s:7700" % host
    headers = {"authorization": "Bearer " + secret, "content-type": "application/json"}
    def request(method, path, value=None):
        data = json.dumps(value).encode() if value is not None else None
        with urllib.request.urlopen(urllib.request.Request(base + path, data=data, headers=headers, method=method), timeout=30) as response:
            body = response.read()
            return json.loads(body) if body else None
    def wait(task):
        for _ in range(150):
            state = request("GET", "/tasks/%s" % task["taskUid"])
            if state["status"] == "succeeded": return
            if state["status"] in ("failed", "canceled"): raise RuntimeError(state)
            time.sleep(0.2)
        raise RuntimeError("Meilisearch task timed out")
    if mode == "seed":
        wait(request("POST", "/indexes", {"uid": "dockyard_template_smoke", "primaryKey": "id"}))
        wait(request("POST", "/indexes/dockyard_template_smoke/documents", [{"id": 1, "value": marker}]))
    else:
        print(request("GET", "/indexes/dockyard_template_smoke/documents/1")["value"])
else:
    raise RuntimeError("unsupported HTTP database probe")
'
}

seed_product_state() {
  local template_key="$1" service_name="$2" stack="$3" container_id postgres_id
  container_id="$(service_container "$service_name")"
  test -n "$container_id"
  case "$template_key" in
    9router)
      ;;
    postgres)
      docker exec --env PGPASSWORD=template-smoke-postgres "$container_id" \
        psql --username smoke --dbname smoke --set ON_ERROR_STOP=1 \
        --command 'CREATE TABLE IF NOT EXISTS dockyard_template_smoke (id integer PRIMARY KEY, value text NOT NULL)' \
        --command "INSERT INTO dockyard_template_smoke(id,value) VALUES (1,'$state_marker') ON CONFLICT(id) DO UPDATE SET value=excluded.value" >/dev/null
      ;;
    timescaledb)
      docker exec --env PGPASSWORD=template-smoke-timescaledb "$container_id" \
        psql --username smoke --dbname smoke --set ON_ERROR_STOP=1 \
        --command 'CREATE TABLE IF NOT EXISTS dockyard_template_smoke (id integer PRIMARY KEY, value text NOT NULL)' \
        --command "INSERT INTO dockyard_template_smoke(id,value) VALUES (1,'$state_marker') ON CONFLICT(id) DO UPDATE SET value=excluded.value" >/dev/null
      ;;
    mysql)
      docker exec --env MYSQL_PWD=template-smoke-mysql "$container_id" mysql --user=smoke --database=smoke \
        --execute="CREATE TABLE IF NOT EXISTS dockyard_template_smoke (id INTEGER PRIMARY KEY, value TEXT NOT NULL); INSERT INTO dockyard_template_smoke(id,value) VALUES (1,'$state_marker') ON DUPLICATE KEY UPDATE value=VALUES(value)" >/dev/null
      ;;
    mariadb)
      docker exec --env MYSQL_PWD=template-smoke-mariadb "$container_id" mariadb --user=smoke --database=smoke \
        --execute="CREATE TABLE IF NOT EXISTS dockyard_template_smoke (id INTEGER PRIMARY KEY, value TEXT NOT NULL); INSERT INTO dockyard_template_smoke(id,value) VALUES (1,'$state_marker') ON DUPLICATE KEY UPDATE value=VALUES(value)" >/dev/null
      ;;
    mongo)
      docker exec --env MONGO_INITDB_ROOT_USERNAME=smoke --env MONGO_INITDB_ROOT_PASSWORD=template-smoke-mongo --env STATE_MARKER="$state_marker" "$container_id" \
        mongosh --quiet --nodb --eval 'const u=encodeURIComponent(process.env.MONGO_INITDB_ROOT_USERNAME),p=encodeURIComponent(process.env.MONGO_INITDB_ROOT_PASSWORD); const c=new Mongo("mongodb://"+u+":"+p+"@127.0.0.1:27017/admin"); c.getDB("smoke").dockyard_template_smoke.updateOne({_id:1},{$set:{value:process.env.STATE_MARKER}},{upsert:true})' >/dev/null
      ;;
    redis)
      docker exec "$container_id" redis-cli --no-auth-warning -a template-smoke-redis SET dockyard:template:smoke "$state_marker" >/dev/null
      ;;
    valkey)
      docker exec "$container_id" valkey-cli --no-auth-warning -a template-smoke-valkey SET dockyard:template:smoke "$state_marker" >/dev/null
      ;;
    libsql)
      libsql_request "$stack" "$service_name" "$(jq -cn --arg marker "$state_marker" '["CREATE TABLE IF NOT EXISTS dockyard_template_smoke (id INTEGER PRIMARY KEY, value TEXT NOT NULL)","INSERT OR REPLACE INTO dockyard_template_smoke(id,value) VALUES (1,\""+$marker+"\")"]')" >/dev/null
      ;;
    clickhouse)
      docker exec "$container_id" clickhouse-client --user smoke --password template-smoke-clickhouse --database smoke --multiquery \
        --query "CREATE TABLE IF NOT EXISTS dockyard_template_smoke (id UInt64,value String) ENGINE=MergeTree ORDER BY id; INSERT INTO dockyard_template_smoke VALUES (1,'$state_marker')" >/dev/null
      ;;
    qdrant)
      http_database_probe "$stack" "$service_name" qdrant seed template-smoke-qdrant
      ;;
    meilisearch)
      http_database_probe "$stack" "$service_name" meilisearch seed template-smoke-meilisearch-key
      ;;
    barktrace-sqlite)
      docker exec "$container_id" /app/barktrace healthcheck
      docker run --rm --env STATE_MARKER="$state_marker" --volume "${stack}_barktrace-data:/data" alpine:3.22 \
        sh -eu -c 'printf "%s\n" "$STATE_MARKER" > /data/.dockyard-template-smoke'
      barktrace_sqlite_file_id="$(docker run --rm --volume "${stack}_barktrace-data:/data:ro" alpine:3.22 stat -c '%d:%i' /data/barktrace.db)"
      test -n "$barktrace_sqlite_file_id"
      ;;
    barktrace-postgres)
      postgres_id="$(service_container "${stack}_postgres")"
      test -n "$postgres_id"
      docker exec --env PGPASSWORD=template-smoke-barktrace "$postgres_id" \
        psql --username barktrace --dbname barktrace --set ON_ERROR_STOP=1 \
        --command 'CREATE TABLE IF NOT EXISTS dockyard_template_smoke (id integer PRIMARY KEY, value text NOT NULL)' \
        --command "INSERT INTO dockyard_template_smoke(id,value) VALUES (1,'$state_marker') ON CONFLICT(id) DO UPDATE SET value=excluded.value" >/dev/null
      ;;
  esac
}

verify_product_state() {
  local template_key="$1" service_name="$2" stack="$3" container_id postgres_id migration_count value
  container_id="$(service_container "$service_name")"
  test -n "$container_id"
  case "$template_key" in
    9router)
      # Replica convergence is the product-level assertion for 9Router. Provider
      # setup is intentionally out of scope for this deployment smoke test.
      ;;
    postgres)
      value="$(docker exec --env PGPASSWORD=template-smoke-postgres "$container_id" psql --username smoke --dbname smoke --tuples-only --no-align --set ON_ERROR_STOP=1 --command 'SELECT value FROM dockyard_template_smoke WHERE id=1')"
      test "$value" = "$state_marker"
      ;;
    timescaledb)
      value="$(docker exec --env PGPASSWORD=template-smoke-timescaledb "$container_id" psql --username smoke --dbname smoke --tuples-only --no-align --set ON_ERROR_STOP=1 --command 'SELECT value FROM dockyard_template_smoke WHERE id=1')"
      test "$value" = "$state_marker"
      ;;
    mysql)
      value="$(docker exec --env MYSQL_PWD=template-smoke-mysql "$container_id" mysql --user=smoke --database=smoke --batch --skip-column-names --execute='SELECT value FROM dockyard_template_smoke WHERE id=1')"
      test "$value" = "$state_marker"
      ;;
    mariadb)
      value="$(docker exec --env MYSQL_PWD=template-smoke-mariadb "$container_id" mariadb --user=smoke --database=smoke --batch --skip-column-names --execute='SELECT value FROM dockyard_template_smoke WHERE id=1')"
      test "$value" = "$state_marker"
      ;;
    mongo)
      value="$(docker exec --env MONGO_INITDB_ROOT_USERNAME=smoke --env MONGO_INITDB_ROOT_PASSWORD=template-smoke-mongo "$container_id" mongosh --quiet --nodb --eval 'const u=encodeURIComponent(process.env.MONGO_INITDB_ROOT_USERNAME),p=encodeURIComponent(process.env.MONGO_INITDB_ROOT_PASSWORD); const c=new Mongo("mongodb://"+u+":"+p+"@127.0.0.1:27017/admin"); print(c.getDB("smoke").dockyard_template_smoke.findOne({_id:1}).value)')"
      test "$value" = "$state_marker"
      ;;
    redis)
      test "$(docker exec "$container_id" redis-cli --no-auth-warning -a template-smoke-redis GET dockyard:template:smoke)" = "$state_marker"
      ;;
    valkey)
      test "$(docker exec "$container_id" valkey-cli --no-auth-warning -a template-smoke-valkey GET dockyard:template:smoke)" = "$state_marker"
      ;;
    libsql)
      value="$(libsql_request "$stack" "$service_name" '["SELECT value FROM dockyard_template_smoke WHERE id=1"]' | jq -er '.[0].results.rows[0][0]')"
      test "$value" = "$state_marker"
      ;;
    clickhouse)
      value="$(docker exec "$container_id" clickhouse-client --user smoke --password template-smoke-clickhouse --database smoke --query 'SELECT value FROM dockyard_template_smoke WHERE id=1')"
      test "$value" = "$state_marker"
      ;;
    qdrant)
      test "$(http_database_probe "$stack" "$service_name" qdrant verify template-smoke-qdrant)" = "$state_marker"
      ;;
    meilisearch)
      test "$(http_database_probe "$stack" "$service_name" meilisearch verify template-smoke-meilisearch-key)" = "$state_marker"
      ;;
    barktrace-sqlite)
      docker exec "$container_id" /app/barktrace healthcheck
      docker run --rm --env STATE_MARKER="$state_marker" --volume "${stack}_barktrace-data:/data:ro" alpine:3.22 \
        sh -eu -c 'test -s /data/barktrace.db && test "$(cat /data/.dockyard-template-smoke)" = "$STATE_MARKER"'
      test "$(docker run --rm --volume "${stack}_barktrace-data:/data:ro" alpine:3.22 stat -c '%d:%i' /data/barktrace.db)" = "$barktrace_sqlite_file_id"
      ;;
    barktrace-postgres)
      docker exec "$container_id" /app/barktrace healthcheck
      postgres_id="$(service_container "${stack}_postgres")"
      test -n "$postgres_id"
      migration_count="$(docker exec --env PGPASSWORD=template-smoke-barktrace "$postgres_id" psql --username barktrace --dbname barktrace --tuples-only --no-align --set ON_ERROR_STOP=1 --command 'SELECT count(*) FROM schema_migrations')"
      test "$migration_count" -gt 0
      value="$(docker exec --env PGPASSWORD=template-smoke-barktrace "$postgres_id" psql --username barktrace --dbname barktrace --tuples-only --no-align --set ON_ERROR_STOP=1 --command 'SELECT value FROM dockyard_template_smoke WHERE id=1')"
      test "$value" = "$state_marker"
      ;;
  esac
}

cleanup() {
  for stack in "${stacks[@]}"; do docker stack rm "$stack" >/dev/null 2>&1 || true; done
  docker compose --project-name "$project" down --volumes --remove-orphans >/dev/null 2>&1 || true
  if [[ "$created_network" == true ]]; then docker network rm "$network" >/dev/null 2>&1 || true; fi
  if [[ "$initialized_swarm" == true ]]; then docker swarm leave --force >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

if [[ "$(docker info --format '{{.Swarm.LocalNodeState}}')" != "active" ]]; then docker swarm init --advertise-addr 127.0.0.1 >/dev/null; initialized_swarm=true; fi
if ! docker network inspect "$network" >/dev/null 2>&1; then docker network create --driver overlay --opt encrypted --attachable "$network" >/dev/null; created_network=true; fi

if [[ "${DOCKYARD_TEMPLATE_SMOKE_PREBUILT:-false}" == "true" ]]; then
  docker image inspect "$project-dockyard" >/dev/null
  docker compose --project-name "$project" up --detach --no-build
elif [[ -n "${DOCKYARD_BUILD_CA_CERT:-}" ]]; then
  test -r "$DOCKYARD_BUILD_CA_CERT"
  docker build --secret "id=build_ca,src=$DOCKYARD_BUILD_CA_CERT" --tag "$project-dockyard" .
  docker compose --project-name "$project" up --detach --no-build
else
  docker compose --project-name "$project" up --detach --build
fi
for _ in {1..90}; do curl --fail --silent "$base_url/readyz" >/dev/null && break; sleep 2; done
curl --fail --silent "$base_url/readyz" >/dev/null

bootstrap="$(curl --fail --silent --show-error -H 'Content-Type: application/json' --data '{"email":"templates@example.test","password":"correct horse battery staple","organization":"Template Smoke"}' "$base_url/v1/auth/bootstrap")"
token="$(jq -er '.token' <<<"$bootstrap")"
organization="$(jq -er '.principal.organizationId' <<<"$bootstrap")"
headers=(-H "Authorization: Bearer $token" -H "X-Organization-ID: $organization" -H 'Content-Type: application/json')
project_id="$(curl --fail --silent --show-error "${headers[@]}" --data '{"name":"Products","slug":"products"}' "$base_url/v1/projects" | jq -er '.id')"
environment_id="$(curl --fail --silent --show-error "${headers[@]}" --data '{"name":"Test","slug":"test"}' "$base_url/v1/projects/$project_id/environments" | jq -er '.id')"
catalog="$(curl --fail --silent --show-error "${headers[@]}" "$base_url/v1/templates")"

for template_key in "${template_keys[@]}"; do
  template_id="$(jq -er --arg key "$template_key" '.items[] | select(.key==$key) | .id' <<<"$catalog")"
  template_version="$(jq -er --arg key "$template_key" '.items[] | select(.key==$key) | .version' <<<"$catalog")"
  case "$template_key" in
    9router)
      variables='{"domain":"9router.example.test"}'
      ;;
    postgres)
      variables='{"postgres_user":"smoke","postgres_password":"template-smoke-postgres","postgres_database":"smoke"}'
      ;;
    timescaledb)
      variables='{"postgres_user":"smoke","postgres_password":"template-smoke-timescaledb","postgres_database":"smoke"}'
      ;;
    mysql)
      variables='{"mysql_user":"smoke","mysql_password":"template-smoke-mysql","mysql_root_password":"template-smoke-mysql-root","mysql_database":"smoke"}'
      ;;
    mariadb)
      variables='{"mariadb_user":"smoke","mariadb_password":"template-smoke-mariadb","mariadb_root_password":"template-smoke-mariadb-root","mariadb_database":"smoke"}'
      ;;
    mongo)
      variables='{"mongo_user":"smoke","mongo_password":"template-smoke-mongo","mongo_database":"smoke"}'
      ;;
    redis)
      variables='{"redis_password":"template-smoke-redis"}'
      ;;
    valkey)
      variables='{"valkey_password":"template-smoke-valkey"}'
      ;;
    libsql)
      variables='{"libsql_user":"smoke","libsql_password":"template-smoke-libsql"}'
      ;;
    clickhouse)
      variables='{"clickhouse_user":"smoke","clickhouse_password":"template-smoke-clickhouse","clickhouse_database":"smoke"}'
      ;;
    qdrant)
      variables='{"qdrant_api_key":"template-smoke-qdrant"}'
      ;;
    meilisearch)
      variables='{"meilisearch_master_key":"template-smoke-meilisearch-key"}'
      ;;
    barktrace-sqlite)
      variables="{\"domain\":\"barktrace-sqlite.example.test\",\"barktrace_version\":\"$barktrace_version\",\"oidc_issuer_url\":\"${DOCKYARD_TEMPLATE_SMOKE_OIDC_ISSUER:-https://accounts.google.com}\",\"oidc_client_id\":\"dockyard-template-smoke\",\"oidc_client_secret\":\"template-smoke-oidc-secret\",\"mcp_token\":\"template-smoke-mcp-token-0000000000000000\"}"
      ;;
    barktrace-postgres)
      variables="{\"domain\":\"barktrace-postgres.example.test\",\"barktrace_version\":\"$barktrace_version\",\"postgres_password\":\"template-smoke-barktrace\",\"oidc_issuer_url\":\"${DOCKYARD_TEMPLATE_SMOKE_OIDC_ISSUER:-https://accounts.google.com}\",\"oidc_client_id\":\"dockyard-template-smoke\",\"oidc_client_secret\":\"template-smoke-oidc-secret\",\"mcp_token\":\"template-smoke-mcp-token-0000000000000000\"}"
      ;;
  esac
  service="$(curl --fail --silent --show-error "${headers[@]}" --data "{\"environmentId\":\"$environment_id\",\"name\":\"$template_key\",\"variables\":$variables}" "$base_url/v1/templates/$template_id/instantiate")"
  service_id="$(jq -er '.service.id' <<<"$service")"
  stack="$(jq -er '.service.stackName' <<<"$service")"
  stacks+=("$stack")
  deployment_id="$(curl --fail --silent --show-error "${headers[@]}" --data '{}' "$base_url/v1/services/$service_id/deployments" | jq -er '.id')"
  wait_for_deployment "$deployment_id"
  service_name="${stack}_${template_key}"
  if [[ "$template_key" == 9router ]]; then
    service_name="${stack}_router"
    wait_for_service "${stack}_headroom"
  elif [[ "$template_key" == barktrace-sqlite ]]; then
    service_name="${stack}_barktrace"
  fi
  wait_for_service "$service_name"
  seed_product_state "$template_key" "$service_name" "$stack"
  verify_product_state "$template_key" "$service_name" "$stack"

  task_before="$(service_task "$service_name")"
  runtime_image_before="$(task_local_image_id "$task_before")"
  [[ "$runtime_image_before" =~ ^sha256:[a-f0-9]{64}$ ]]
  docker service update --force --detach=false "$service_name" >/dev/null
  wait_for_service "$service_name"
  verify_product_state "$template_key" "$service_name" "$stack"
  task_after="$(service_task "$service_name")"
  runtime_image_after="$(task_local_image_id "$task_after")"
  test "$task_before" != "$task_after"
  test "$runtime_image_before" = "$runtime_image_after"
  dependency_task_before=''
  dependency_task_after=''
  dependency_runtime_image_before=''
  dependency_runtime_image_after=''
  if [[ "$template_key" == barktrace-postgres ]]; then
    dependency_task_before="$(service_task "${stack}_postgres")"
    dependency_runtime_image_before="$(task_local_image_id "$dependency_task_before")"
    [[ "$dependency_runtime_image_before" =~ ^sha256:[a-f0-9]{64}$ ]]
    docker service update --force --detach=false "${stack}_postgres" >/dev/null
    wait_for_service "${stack}_postgres"
    verify_product_state "$template_key" "$service_name" "$stack"
    dependency_task_after="$(service_task "${stack}_postgres")"
    dependency_runtime_image_after="$(task_local_image_id "$dependency_task_after")"
    test "$dependency_task_before" != "$dependency_task_after"
    test "$dependency_runtime_image_before" = "$dependency_runtime_image_after"
  fi
  resolved_image="$(docker service inspect "$service_name" --format '{{.Spec.TaskTemplate.ContainerSpec.Image}}')"
  "$root_dir/scripts/ci/validate-image-reference.sh" "$resolved_image"
  if [[ "$template_key" == barktrace-* ]]; then
    [[ "$resolved_image" == "ghcr.io/barktrace/bark:$barktrace_version@sha256:"* ]]
  fi
  dependency_images='[]'
  data_verified=true
  data_verification_applicable=true
  state_seeded_before_restart=true
  post_restart_read_only=true
  dependency_restart_verified=false
  dependency_runtime_image_identity_verified=false
  sqlite_file_identity_verified=false
  if [[ "$template_key" == 9router ]]; then
    headroom_image="$(docker service inspect "${stack}_headroom" --format '{{.Spec.TaskTemplate.ContainerSpec.Image}}')"
    "$root_dir/scripts/ci/validate-image-reference.sh" "$headroom_image"
    dependency_images="$(jq -cn --arg image "$headroom_image" '[{service:"headroom",image:$image}]')"
    data_verified=false
    data_verification_applicable=false
    state_seeded_before_restart=false
    post_restart_read_only=false
  elif [[ "$template_key" == barktrace-postgres ]]; then
    postgres_image="$(docker service inspect "${stack}_postgres" --format '{{.Spec.TaskTemplate.ContainerSpec.Image}}')"
    "$root_dir/scripts/ci/validate-image-reference.sh" "$postgres_image"
    dependency_images="$(jq -cn --arg image "$postgres_image" '[{service:"postgres",image:$image}]')"
    dependency_restart_verified=true
    dependency_runtime_image_identity_verified=true
  elif [[ "$template_key" == barktrace-sqlite ]]; then
    sqlite_file_identity_verified=true
  fi
  products="$(jq -c \
    --arg template "$template_key" --arg templateVersion "$template_version" \
    --arg deploymentId "$deployment_id" --arg service "$service_name" --arg image "$resolved_image" \
    --arg taskBefore "$task_before" --arg taskAfter "$task_after" \
    --arg runtimeImageBefore "$runtime_image_before" --arg runtimeImageAfter "$runtime_image_after" \
    --arg dependencyTaskBefore "$dependency_task_before" --arg dependencyTaskAfter "$dependency_task_after" \
    --arg dependencyRuntimeImageBefore "$dependency_runtime_image_before" --arg dependencyRuntimeImageAfter "$dependency_runtime_image_after" \
    --argjson dependencyImages "$dependency_images" --argjson dataVerified "$data_verified" \
    --argjson dataVerificationApplicable "$data_verification_applicable" \
    --argjson stateSeededBeforeRestart "$state_seeded_before_restart" --argjson postRestartReadOnly "$post_restart_read_only" \
    --argjson dependencyRestartVerified "$dependency_restart_verified" --argjson dependencyRuntimeImageIdentityVerified "$dependency_runtime_image_identity_verified" --argjson sqliteFileIdentityVerified "$sqlite_file_identity_verified" \
    '. + [{template:$template,templateVersion:$templateVersion,deploymentId:$deploymentId,service:$service,image:$image,dependencyImages:$dependencyImages,deploymentVerified:true,dataVerified:$dataVerified,dataVerificationApplicable:$dataVerificationApplicable,stateSeededBeforeRestart:$stateSeededBeforeRestart,postRestartReadOnly:$postRestartReadOnly,restartVerified:($taskBefore != $taskAfter),taskBefore:$taskBefore,taskAfter:$taskAfter,runtimeImageBefore:$runtimeImageBefore,runtimeImageAfter:$runtimeImageAfter,runtimeImageIdentityVerified:($runtimeImageBefore == $runtimeImageAfter),dependencyRestartVerified:$dependencyRestartVerified,dependencyTaskBefore:$dependencyTaskBefore,dependencyTaskAfter:$dependencyTaskAfter,dependencyRuntimeImageBefore:$dependencyRuntimeImageBefore,dependencyRuntimeImageAfter:$dependencyRuntimeImageAfter,dependencyRuntimeImageIdentityVerified:$dependencyRuntimeImageIdentityVerified,sqliteFileIdentityVerified:$sqliteFileIdentityVerified}]' \
    <<<"$products")"
done

jq -n \
  --arg status passed --arg sourceCommit "${GITHUB_SHA:-local}" --arg createdAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg barktraceVersion "$barktrace_version" --argjson products "$products" \
  '{status:$status,sourceCommit:$sourceCommit,createdAt:$createdAt,barktraceVersion:$barktraceVersion,productCount:($products|length),products:$products}' \
  >"$evidence_file"
jq -e '
  .status == "passed" and .productCount == ($expected | length) and
  ([.products[].template] | sort == ($expected | sort)) and
  all(.products[]; .deploymentVerified and .restartVerified and .runtimeImageIdentityVerified and .taskBefore != .taskAfter and (.runtimeImageBefore | test("^sha256:[a-f0-9]{64}$")) and .runtimeImageAfter == .runtimeImageBefore and (.image | test("@sha256:[a-f0-9]{64}$"))) and
  all(.products[]; .dataVerified or (.dataVerificationApplicable == false)) and
  all(.products[]; if .dataVerificationApplicable then .stateSeededBeforeRestart and .postRestartReadOnly else true end) and
  all(.products[] | select(.template == "barktrace-postgres"); .dependencyRestartVerified and .dependencyRuntimeImageIdentityVerified and .dependencyTaskBefore != .dependencyTaskAfter and (.dependencyRuntimeImageBefore | test("^sha256:[a-f0-9]{64}$")) and .dependencyRuntimeImageAfter == .dependencyRuntimeImageBefore) and
  all(.products[] | select(.template == "barktrace-postgres"); .dependencyImages | length == 1 and .[0].service == "postgres" and (.[0].image | test("@sha256:[a-f0-9]{64}$"))) and
  all(.products[] | select(.template == "barktrace-sqlite"); .sqliteFileIdentityVerified) and
  all(.products[].dependencyImages[]?; .image | test("@sha256:[a-f0-9]{64}$")) and
  all(.products[] | select(.template | startswith("barktrace-")); .image | startswith("ghcr.io/barktrace/bark:" + $version + "@sha256:"))
' --arg version "$barktrace_version" --argjson expected "$(printf '%s\n' "${template_keys[@]}" | jq -R . | jq -s .)" "$evidence_file" >/dev/null
printf 'TEMPLATE_EVIDENCE '
cat "$evidence_file"
printf 'Selected built-in templates deployed and survived Swarm task replacement; stateful products retained application data.\n'
