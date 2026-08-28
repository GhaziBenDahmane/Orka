#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 RECOVERY_BUNDLE_DIRECTORY" >&2
  exit 2
fi

bundle=$1
stack=${DOCKYARD_STACK_NAME:-dockyard}
database=${DOCKYARD_POSTGRES_DATABASE:-dockyard}
database_user=${DOCKYARD_POSTGRES_USER:-dockyard}
image=${DOCKYARD_IMAGE:-}

if [ "${DOCKYARD_RESTORE_CONFIRM:-}" != "restore:${stack}" ]; then
  echo "refusing destructive restore; set DOCKYARD_RESTORE_CONFIRM=restore:${stack}" >&2
  exit 1
fi
case "$stack" in
  ""|-*|*[!A-Za-z0-9_.-]*) echo "invalid DOCKYARD_STACK_NAME" >&2; exit 1 ;;
esac
case "$database" in
  ""|-*|*[!A-Za-z0-9_]*) echo "invalid DOCKYARD_POSTGRES_DATABASE" >&2; exit 1 ;;
esac
case "$database_user" in
  ""|-*|*[!A-Za-z0-9_]*) echo "invalid DOCKYARD_POSTGRES_USER" >&2; exit 1 ;;
esac
for command in docker jq sha256sum base64 openssl; do
  command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 1; }
done
if [ ! -f "$bundle/manifest.json" ] || [ ! -f "$bundle/database.dump" ] || [ -L "$bundle/manifest.json" ] || [ -L "$bundle/database.dump" ]; then
  echo "recovery bundle must contain regular manifest.json and database.dump files" >&2
  exit 1
fi

controller_service=${DOCKYARD_CONTROLLER_SERVICE:-${stack}_dockyard}
case "$controller_service" in
  ""|-*|*[!A-Za-z0-9_.-]*) echo "invalid controller service name" >&2; exit 1 ;;
esac
if docker service inspect "$controller_service" >/dev/null 2>&1; then
  replicas=$(docker service inspect "$controller_service" --format '{{.Spec.Mode.Replicated.Replicas}}')
  if [ "$replicas" != "0" ]; then
    echo "scale $controller_service to zero before restoring" >&2
    exit 1
  fi
elif [ -n "${DOCKYARD_CONTROLLER_CONTAINER:-}" ]; then
  case "$DOCKYARD_CONTROLLER_CONTAINER" in
    -*|*[!A-Za-z0-9_.-]*) echo "invalid controller container name or ID" >&2; exit 1 ;;
  esac
  if [ "$(docker inspect "$DOCKYARD_CONTROLLER_CONTAINER" --format '{{.State.Running}}')" != "false" ]; then
    echo "stop $DOCKYARD_CONTROLLER_CONTAINER before restoring" >&2
    exit 1
  fi
else
  echo "cannot prove the controller is stopped; set DOCKYARD_CONTROLLER_SERVICE or DOCKYARD_CONTROLLER_CONTAINER" >&2
  exit 1
fi

postgres_container=${DOCKYARD_POSTGRES_CONTAINER:-}
if [ -z "$postgres_container" ]; then
  postgres_container=$(docker ps --filter "label=com.docker.swarm.service.name=${stack}_postgres" --filter status=running --format '{{.ID}}')
fi
if [ -z "$postgres_container" ] || [ "$(printf '%s\n' "$postgres_container" | wc -l | tr -d ' ')" -ne 1 ]; then
  echo "exactly one local PostgreSQL task is required; run on its node or set DOCKYARD_POSTGRES_CONTAINER" >&2
  exit 1
fi
case "$postgres_container" in
  -*|*[!A-Za-z0-9_.-]*) echo "invalid PostgreSQL container name or ID" >&2; exit 1 ;;
esac

format_version=$(jq -er '.formatVersion' "$bundle/manifest.json")
expected_database=$(jq -er '.database' "$bundle/manifest.json")
expected_image=$(jq -er '.controllerImage' "$bundle/manifest.json")
expected_dump_sha256=$(jq -er '.databaseSha256' "$bundle/manifest.json")
expected_dump_bytes=$(jq -er '.databaseBytes' "$bundle/manifest.json")
expected_master_sha256=$(jq -er '.masterKeySha256' "$bundle/manifest.json")
expected_agent_ca_sha256=$(jq -er '.agentCaSha256' "$bundle/manifest.json")
expected_schema_version=$(jq -er '.schemaVersion' "$bundle/manifest.json")
if [ "$format_version" != "1" ] || [ "$expected_database" != "$database" ]; then
  echo "recovery bundle format or database does not match" >&2
  exit 1
fi
if [ "$expected_image" != "$image" ]; then
  echo "DOCKYARD_IMAGE does not match the recovery bundle" >&2
  exit 1
fi
actual_dump_sha256=$(sha256sum "$bundle/database.dump" | awk '{print $1}')
actual_dump_bytes=$(wc -c <"$bundle/database.dump" | tr -d ' ')
if [ "$actual_dump_bytes" -eq 0 ] || [ "$actual_dump_sha256" != "$expected_dump_sha256" ] || [ "$actual_dump_bytes" != "$expected_dump_bytes" ]; then
  echo "database dump checksum or size does not match the manifest" >&2
  exit 1
fi

master_key=${DOCKYARD_MASTER_KEY:-}
if [ -n "${DOCKYARD_MASTER_KEY_FILE:-}" ]; then
  master_key=$(tr -d '\r\n' <"$DOCKYARD_MASTER_KEY_FILE")
fi
temporary=$(mktemp -d)
cleanup() { rm -rf -- "$temporary"; }
trap cleanup EXIT HUP INT TERM
if ! printf '%s' "$master_key" | base64 -d >"$temporary/master-key.bin" 2>/dev/null || [ "$(wc -c <"$temporary/master-key.bin" | tr -d ' ')" -ne 32 ]; then
  echo "DOCKYARD_MASTER_KEY must be a base64-encoded 32-byte key" >&2
  exit 1
fi
actual_master_sha256=$(sha256sum "$temporary/master-key.bin" | awk '{print $1}')
rm -f -- "$temporary/master-key.bin"
if [ "$actual_master_sha256" != "$expected_master_sha256" ]; then
  echo "master key does not match the recovery bundle" >&2
  exit 1
fi

if [ -n "$expected_agent_ca_sha256" ]; then
  if [ -n "${DOCKYARD_AGENT_CA_CERT_FILE:-}" ]; then
    openssl x509 -in "$DOCKYARD_AGENT_CA_CERT_FILE" -outform DER >"$temporary/agent-ca.der"
  elif [ -n "${DOCKYARD_AGENT_CA_CERT:-}" ]; then
    printf '%s' "$DOCKYARD_AGENT_CA_CERT" | openssl x509 -outform DER >"$temporary/agent-ca.der"
  else
    echo "the recovery bundle requires the matching agent CA certificate" >&2
    exit 1
  fi
  actual_agent_ca_sha256=$(sha256sum "$temporary/agent-ca.der" | awk '{print $1}')
  rm -f -- "$temporary/agent-ca.der"
  if [ "$actual_agent_ca_sha256" != "$expected_agent_ca_sha256" ]; then
    echo "agent CA certificate does not match the recovery bundle" >&2
    exit 1
  fi
fi

docker exec --interactive --user postgres "$postgres_container" pg_restore --list <"$bundle/database.dump" >/dev/null
docker exec --user postgres "$postgres_container" dropdb --username "$database_user" --maintenance-db postgres --if-exists --force "$database"
docker exec --user postgres "$postgres_container" createdb --username "$database_user" --owner "$database_user" "$database"
docker exec --interactive --user postgres "$postgres_container" pg_restore --username "$database_user" --dbname "$database" --no-owner --no-privileges --single-transaction --exit-on-error <"$bundle/database.dump"
actual_schema_version=$(docker exec --user postgres "$postgres_container" psql --username "$database_user" --dbname "$database" --tuples-only --no-align --command "SELECT COALESCE(max(version),'') FROM schema_migrations")
actual_schema_version=$(printf '%s' "$actual_schema_version" | tr -d '\r\n')
if [ "$actual_schema_version" != "$expected_schema_version" ]; then
  echo "restored schema version does not match the recovery bundle" >&2
  exit 1
fi
echo "control-plane database restored; restart the matching controller image and verify secrets before upgrading"
