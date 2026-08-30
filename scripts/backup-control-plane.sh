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
for command in awk base64 date docker find grep jq mktemp mv openssl sha256sum tr wc; do
  command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 1; }
done

signing_key=${DOCKYARD_RECOVERY_SIGNING_KEY_FILE:-}
if [ -z "$signing_key" ] || [ ! -f "$signing_key" ] || [ ! -r "$signing_key" ] || [ -L "$signing_key" ]; then
  echo "DOCKYARD_RECOVERY_SIGNING_KEY_FILE must name a readable regular Ed25519 private key" >&2
  exit 1
fi
if [ -n "$(find "$signing_key" -prune -perm /077 -print)" ]; then
  echo "DOCKYARD_RECOVERY_SIGNING_KEY_FILE must not be accessible by group or other users" >&2
  exit 1
fi
if ! openssl pkey -in "$signing_key" -text_pub -noout 2>/dev/null | grep -q '^ED25519 Public-Key:'; then
  echo "DOCKYARD_RECOVERY_SIGNING_KEY_FILE must contain an Ed25519 private key" >&2
  exit 1
fi
recovery_signing_key_sha256=$(openssl pkey -in "$signing_key" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')

controller_service=${DOCKYARD_CONTROLLER_SERVICE:-${stack}_dockyard}
case "$controller_service" in
  ""|-*|*[!A-Za-z0-9_.-]*) echo "invalid controller service name" >&2; exit 1 ;;
esac
controller_inspection=$(docker service inspect --format '{{.Spec.TaskTemplate.ContainerSpec.Image}}|{{if .UpdateStatus}}{{.UpdateStatus.State}}{{end}}' "$controller_service" 2>/dev/null || true)
if [ -n "$controller_inspection" ]; then
  deployed_image=${controller_inspection%%|*}
  update_state=${controller_inspection#*|}
  if [ "$deployed_image" != "$image" ]; then
    echo "DOCKYARD_IMAGE does not match deployed controller service $controller_service" >&2
    exit 1
  fi
  if [ -n "$update_state" ] && [ "$update_state" != "completed" ]; then
    echo "controller service $controller_service update state is $update_state; wait for a stable rollout before backup" >&2
    exit 1
  fi
elif [ -n "${DOCKYARD_CONTROLLER_CONTAINER:-}" ]; then
  case "$DOCKYARD_CONTROLLER_CONTAINER" in
    -*|*[!A-Za-z0-9_.-]*) echo "invalid controller container name or ID" >&2; exit 1 ;;
  esac
  deployed_image_id=$(docker inspect "$DOCKYARD_CONTROLLER_CONTAINER" --format '{{.Image}}' 2>/dev/null) || {
    echo "could not inspect controller container $DOCKYARD_CONTROLLER_CONTAINER" >&2
    exit 1
  }
  case "$image" in
    *@"$deployed_image_id") ;;
    *) echo "DOCKYARD_IMAGE does not match controller container $DOCKYARD_CONTROLLER_CONTAINER" >&2; exit 1 ;;
  esac
else
  echo "cannot verify DOCKYARD_IMAGE; set DOCKYARD_CONTROLLER_SERVICE or DOCKYARD_CONTROLLER_CONTAINER" >&2
  exit 1
fi
unset controller_inspection deployed_image deployed_image_id update_state

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
  --arg recoverySigningKeySha256 "$recovery_signing_key_sha256" \
  '{formatVersion:2,createdAt:$createdAt,stack:$stack,database:$database,schemaVersion:$schemaVersion,controllerImage:$controllerImage,databaseSha256:$databaseSha256,databaseBytes:$databaseBytes,masterKeySha256:$masterKeySha256,agentCaSha256:$agentCaSha256,recoverySigningKeySha256:$recoverySigningKeySha256}' \
  >"$temporary/manifest.json"
openssl pkeyutl -sign -rawin -inkey "$signing_key" -in "$temporary/manifest.json" -out "$temporary/manifest.sig"
chmod 0600 "$temporary/database.dump" "$temporary/manifest.json" "$temporary/manifest.sig"
mv "$temporary" "$output"
trap - EXIT HUP INT TERM
printf '%s\n' "$output"
