#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 OUTPUT_DIRECTORY" >&2
  exit 2
fi

output=$1
parent=$(dirname "$output")
stack=${DOCKYARD_STACK_NAME:-dockyard}
database=${DOCKYARD_POSTGRES_DATABASE:-dockyard}
database_user=${DOCKYARD_POSTGRES_USER:-dockyard}
image=${DOCKYARD_IMAGE:-}

case "$stack" in
  ""|-*|*[!A-Za-z0-9_.-]*) echo "invalid DOCKYARD_STACK_NAME" >&2; exit 1 ;;
esac
case "$database" in
  ""|-*|*[!A-Za-z0-9_]*) echo "invalid DOCKYARD_POSTGRES_DATABASE" >&2; exit 1 ;;
esac
case "$database_user" in
  ""|-*|*[!A-Za-z0-9_]*) echo "invalid DOCKYARD_POSTGRES_USER" >&2; exit 1 ;;
esac
if ! printf '%s\n' "$image" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[a-f0-9]{64}$'; then
  echo "DOCKYARD_IMAGE must be the deployed image reference pinned by sha256 digest" >&2
  exit 1
fi
if [ -e "$output" ]; then
  echo "refusing to overwrite existing recovery bundle: $output" >&2
  exit 1
fi
if [ ! -d "$parent" ]; then
  echo "output parent directory does not exist: $parent" >&2
  exit 1
fi
for command in docker jq sha256sum base64 openssl; do
  command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 1; }
done

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

master_key=${DOCKYARD_MASTER_KEY:-}
if [ -n "${DOCKYARD_MASTER_KEY_FILE:-}" ]; then
  master_key=$(tr -d '\r\n' <"$DOCKYARD_MASTER_KEY_FILE")
fi
if [ -z "$master_key" ]; then
  echo "DOCKYARD_MASTER_KEY or DOCKYARD_MASTER_KEY_FILE is required for recovery-set verification" >&2
  exit 1
fi

umask 077
temporary=$(mktemp -d "$parent/.dockyard-recovery.XXXXXX")
cleanup() { rm -rf -- "$temporary"; }
trap cleanup EXIT HUP INT TERM
if ! printf '%s' "$master_key" | base64 -d >"$temporary/master-key.bin" 2>/dev/null || [ "$(wc -c <"$temporary/master-key.bin" | tr -d ' ')" -ne 32 ]; then
  echo "DOCKYARD_MASTER_KEY must be a base64-encoded 32-byte key" >&2
  exit 1
fi
master_key_sha256=$(sha256sum "$temporary/master-key.bin" | awk '{print $1}')
rm -f -- "$temporary/master-key.bin"

agent_ca_sha256=""
if [ -n "${DOCKYARD_AGENT_CA_CERT_FILE:-}" ]; then
  openssl x509 -in "$DOCKYARD_AGENT_CA_CERT_FILE" -outform DER >"$temporary/agent-ca.der"
  agent_ca_sha256=$(sha256sum "$temporary/agent-ca.der" | awk '{print $1}')
  rm -f -- "$temporary/agent-ca.der"
elif [ -n "${DOCKYARD_AGENT_CA_CERT:-}" ]; then
  printf '%s' "$DOCKYARD_AGENT_CA_CERT" | openssl x509 -outform DER >"$temporary/agent-ca.der"
  agent_ca_sha256=$(sha256sum "$temporary/agent-ca.der" | awk '{print $1}')
  rm -f -- "$temporary/agent-ca.der"
fi

schema_version=$(docker exec --user postgres "$postgres_container" psql --username "$database_user" --dbname "$database" --tuples-only --no-align --command "SELECT COALESCE(max(version),'') FROM schema_migrations")
schema_version=$(printf '%s' "$schema_version" | tr -d '\r\n')
case "$schema_version" in
  ""|*[!A-Za-z0-9._-]*) echo "could not determine a valid schema version" >&2; exit 1 ;;
esac

docker exec --user postgres "$postgres_container" pg_dump --username "$database_user" --dbname "$database" --format=custom --no-owner --no-privileges --serializable-deferrable >"$temporary/database.dump"
database_sha256=$(sha256sum "$temporary/database.dump" | awk '{print $1}')
database_bytes=$(wc -c <"$temporary/database.dump" | tr -d ' ')
created_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
jq --null-input \
  --arg createdAt "$created_at" \
  --arg stack "$stack" \
  --arg database "$database" \
  --arg schemaVersion "$schema_version" \
  --arg controllerImage "$image" \
  --arg databaseSha256 "$database_sha256" \
  --argjson databaseBytes "$database_bytes" \
  --arg masterKeySha256 "$master_key_sha256" \
  --arg agentCaSha256 "$agent_ca_sha256" \
  '{formatVersion:1,createdAt:$createdAt,stack:$stack,database:$database,schemaVersion:$schemaVersion,controllerImage:$controllerImage,databaseSha256:$databaseSha256,databaseBytes:$databaseBytes,masterKeySha256:$masterKeySha256,agentCaSha256:$agentCaSha256}' \
  >"$temporary/manifest.json"
chmod 0600 "$temporary/database.dump" "$temporary/manifest.json"
mv "$temporary" "$output"
trap - EXIT HUP INT TERM
printf '%s\n' "$output"
