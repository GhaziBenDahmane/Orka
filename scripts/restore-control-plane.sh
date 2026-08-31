#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)

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
for command in awk base64 cp docker find grep jq mktemp openssl sha256sum tr wc; do
  command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 1; }
done

master_key=${DOCKYARD_MASTER_KEY:-}
master_key_file=${DOCKYARD_MASTER_KEY_FILE:-}
if [ -n "$master_key" ] && [ -n "$master_key_file" ]; then
  echo "DOCKYARD_MASTER_KEY and DOCKYARD_MASTER_KEY_FILE cannot both be configured" >&2
  exit 1
fi
if [ -n "$master_key_file" ]; then
  if [ ! -f "$master_key_file" ] || [ ! -r "$master_key_file" ] || [ -L "$master_key_file" ]; then
    echo "DOCKYARD_MASTER_KEY_FILE must name a readable regular file, not a symbolic link" >&2
    exit 1
  fi
  if [ -n "$(find "$master_key_file" -prune -perm /077 -print)" ]; then
    echo "DOCKYARD_MASTER_KEY_FILE must not be accessible by group or other users" >&2
    exit 1
  fi
  master_key=$(tr -d '\r\n' <"$master_key_file")
fi
if [ -z "$master_key" ]; then
  echo "DOCKYARD_MASTER_KEY or DOCKYARD_MASTER_KEY_FILE is required for recovery-set verification" >&2
  exit 1
fi
umask 077
work_root=${DOCKYARD_RECOVERY_WORK_DIR:-${TMPDIR:-/var/tmp}}
work_root=$(CDPATH= cd -- "$work_root" && pwd -P) || {
  echo "DOCKYARD_RECOVERY_WORK_DIR must name an existing writable directory" >&2
  exit 1
}
temporary=$(mktemp -d "$work_root/.dockyard-restore.XXXXXX") || {
  echo "could not create a private recovery workspace in DOCKYARD_RECOVERY_WORK_DIR" >&2
  exit 1
}
staging_database=""
cleanup() {
  status=$?
  if [ "$status" -ne 0 ] && [ -n "$staging_database" ]; then
    docker exec --user postgres "$postgres_container" dropdb --username "$database_user" --maintenance-db postgres --if-exists --force "$staging_database" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$temporary"
  trap - EXIT HUP INT TERM
  exit "$status"
}
trap cleanup EXIT HUP INT TERM
if ! printf '%s' "$master_key" | base64 -d >"$temporary/master-key.bin" 2>/dev/null || [ "$(wc -c <"$temporary/master-key.bin" | tr -d ' ')" -ne 32 ]; then
  echo "DOCKYARD_MASTER_KEY must be a base64-encoded 32-byte key" >&2
  exit 1
fi
unset master_key DOCKYARD_MASTER_KEY

agent_ca_certificate_file=${DOCKYARD_AGENT_CA_CERT_FILE:-}
agent_ca_certificate_value=${DOCKYARD_AGENT_CA_CERT:-}
agent_ca_key_file=${DOCKYARD_AGENT_CA_KEY_FILE:-}
agent_ca_key_value=${DOCKYARD_AGENT_CA_KEY:-}
if { [ -n "$agent_ca_certificate_file" ] && [ -n "$agent_ca_certificate_value" ]; } || { [ -n "$agent_ca_key_file" ] && [ -n "$agent_ca_key_value" ]; }; then
  echo "agent CA certificate and key cannot each be configured through both value and file variables" >&2
  exit 1
fi
agent_ca_certificate_snapshot=""
agent_ca_key_snapshot=""
if [ -n "$agent_ca_certificate_file" ]; then
  [ -f "$agent_ca_certificate_file" ] && [ ! -L "$agent_ca_certificate_file" ] && [ -r "$agent_ca_certificate_file" ] || {
    echo "DOCKYARD_AGENT_CA_CERT_FILE must name a readable regular file, not a symbolic link" >&2
    exit 1
  }
  cp -P -- "$agent_ca_certificate_file" "$temporary/agent-ca.crt"
elif [ -n "$agent_ca_certificate_value" ]; then
  printf '%s' "$agent_ca_certificate_value" >"$temporary/agent-ca.crt"
fi
if [ -n "$agent_ca_key_file" ]; then
  [ -f "$agent_ca_key_file" ] && [ ! -L "$agent_ca_key_file" ] && [ -r "$agent_ca_key_file" ] || {
    echo "DOCKYARD_AGENT_CA_KEY_FILE must name a readable regular file, not a symbolic link" >&2
    exit 1
  }
  [ -z "$(find "$agent_ca_key_file" -prune -perm /077 -print)" ] || {
    echo "DOCKYARD_AGENT_CA_KEY_FILE must not be accessible by group or other users" >&2
    exit 1
  }
  cp -P -- "$agent_ca_key_file" "$temporary/agent-ca.key"
elif [ -n "$agent_ca_key_value" ]; then
  printf '%s' "$agent_ca_key_value" >"$temporary/agent-ca.key"
fi
if { [ -e "$temporary/agent-ca.crt" ] && [ ! -e "$temporary/agent-ca.key" ]; } || { [ ! -e "$temporary/agent-ca.crt" ] && [ -e "$temporary/agent-ca.key" ]; }; then
  echo "agent CA certificate and private key must be configured together" >&2
  exit 1
fi
if [ -e "$temporary/agent-ca.crt" ]; then
  if [ ! -f "$temporary/agent-ca.crt" ] || [ -L "$temporary/agent-ca.crt" ] || [ ! -f "$temporary/agent-ca.key" ] || [ -L "$temporary/agent-ca.key" ]; then
    echo "could not create private agent CA recovery snapshots" >&2
    exit 1
  fi
  chmod 0600 "$temporary/agent-ca.crt" "$temporary/agent-ca.key"
  agent_ca_certificate_snapshot="$temporary/agent-ca.crt"
  agent_ca_key_snapshot="$temporary/agent-ca.key"
fi
unset agent_ca_certificate_value agent_ca_key_value DOCKYARD_AGENT_CA_CERT DOCKYARD_AGENT_CA_KEY
if [ ! -f "$bundle/manifest.json" ] || [ ! -f "$bundle/manifest.sig" ] || [ ! -f "$bundle/database.dump" ] || [ -L "$bundle/manifest.json" ] || [ -L "$bundle/manifest.sig" ] || [ -L "$bundle/database.dump" ]; then
  echo "recovery bundle must contain regular manifest.json, manifest.sig, and database.dump files" >&2
  exit 1
fi
manifest_bytes=$(wc -c <"$bundle/manifest.json" | tr -d ' ')
signature_bytes=$(wc -c <"$bundle/manifest.sig" | tr -d ' ')
if [ "$manifest_bytes" -eq 0 ] || [ "$manifest_bytes" -gt 65536 ] || [ "$signature_bytes" -ne 64 ]; then
  echo "recovery bundle manifest or Ed25519 signature has an invalid size" >&2
  exit 1
fi

verify_key=${DOCKYARD_RECOVERY_VERIFY_KEY_FILE:-}
if [ -z "$verify_key" ] || [ ! -f "$verify_key" ] || [ ! -r "$verify_key" ] || [ -L "$verify_key" ]; then
  echo "DOCKYARD_RECOVERY_VERIFY_KEY_FILE must name a readable regular Ed25519 public key" >&2
  exit 1
fi
if ! openssl pkey -pubin -in "$verify_key" -text_pub -noout 2>/dev/null | grep -q '^ED25519 Public-Key:'; then
  echo "DOCKYARD_RECOVERY_VERIFY_KEY_FILE must contain an Ed25519 public key" >&2
  exit 1
fi
if ! openssl pkeyutl -verify -rawin -pubin -inkey "$verify_key" -in "$bundle/manifest.json" -sigfile "$bundle/manifest.sig" >/dev/null 2>&1; then
  echo "recovery bundle manifest signature is invalid" >&2
  exit 1
fi
recovery_signing_key_sha256=$(openssl pkey -pubin -in "$verify_key" -outform DER 2>/dev/null | sha256sum | awk '{print $1}')

if ! "$root/scripts/ci/validate-image-reference.sh" "$image" >/dev/null; then
  echo "DOCKYARD_IMAGE must be pinned by sha256 digest" >&2
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

canonical_file() {
  directory=$(CDPATH= cd -- "$(dirname "$1")" && pwd -P) || { echo "cannot resolve recovery input path" >&2; exit 1; }
  printf '%s/%s' "$directory" "$(basename "$1")"
}
manifest_file=$(canonical_file "$bundle/manifest.json")
signature_file=$(canonical_file "$bundle/manifest.sig")
verify_key=$(canonical_file "$verify_key")
master_key_snapshot=$(canonical_file "$temporary/master-key.bin")
for recovery_path in "$manifest_file" "$signature_file" "$verify_key" "$master_key_snapshot"; do
  case "$recovery_path" in *,*) echo "recovery input paths must not contain commas" >&2; exit 1 ;; esac
done
if [ -n "$agent_ca_certificate_snapshot" ]; then
  for recovery_path in "$agent_ca_certificate_snapshot" "$agent_ca_key_snapshot"; do
    case "$recovery_path" in *,*) echo "recovery input paths must not contain commas" >&2; exit 1 ;; esac
  done
fi
verifier_image=${DOCKYARD_RECOVERY_VERIFIER_IMAGE:-$image}
if [ "$verifier_image" != "$image" ]; then
  verifier_image_id=$(docker image inspect "$verifier_image" --format '{{.Id}}' 2>/dev/null) || {
    echo "DOCKYARD_RECOVERY_VERIFIER_IMAGE is unavailable" >&2
    exit 1
  }
  [ "${image##*@}" = "$verifier_image_id" ] || {
    echo "DOCKYARD_RECOVERY_VERIFIER_IMAGE does not match DOCKYARD_IMAGE" >&2
    exit 1
  }
fi
set -- docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --mount "type=bind,src=$manifest_file,dst=/input/manifest.json,readonly" \
  --mount "type=bind,src=$signature_file,dst=/input/manifest.sig,readonly" \
  --mount "type=bind,src=$verify_key,dst=/input/verify-key.pem,readonly" \
  --mount "type=bind,src=$master_key_snapshot,dst=/input/master-key.bin,readonly"
if [ -n "$agent_ca_certificate_snapshot" ]; then
  agent_ca_certificate_snapshot=$(canonical_file "$agent_ca_certificate_snapshot")
  agent_ca_key_snapshot=$(canonical_file "$agent_ca_key_snapshot")
  set -- "$@" \
    --mount "type=bind,src=$agent_ca_certificate_snapshot,dst=/input/agent-ca.crt,readonly" \
    --mount "type=bind,src=$agent_ca_key_snapshot,dst=/input/agent-ca.key,readonly"
fi
set -- "$@" \
  --entrypoint /usr/local/bin/dockyard "$verifier_image" verify-control-plane-recovery-manifest \
  --manifest /input/manifest.json --signature /input/manifest.sig \
  --public-key-file /input/verify-key.pem --master-key-file /input/master-key.bin \
  --stack "$stack" --database "$database" --controller-image "$image"
if [ -n "$agent_ca_certificate_snapshot" ]; then
  set -- "$@" --agent-ca-certificate-file /input/agent-ca.crt --agent-ca-key-file /input/agent-ca.key
fi
verified_manifest=$("$@") || {
    echo "recovery bundle manifest verification failed" >&2
    exit 1
  }

format_version=$(printf '%s' "$verified_manifest" | jq -er '.formatVersion')
expected_database=$(printf '%s' "$verified_manifest" | jq -er '.database')
expected_image=$(printf '%s' "$verified_manifest" | jq -er '.controllerImage')
expected_dump_sha256=$(printf '%s' "$verified_manifest" | jq -er '.databaseSha256')
expected_dump_bytes=$(printf '%s' "$verified_manifest" | jq -er '.databaseBytes')
expected_master_sha256=$(printf '%s' "$verified_manifest" | jq -er '.masterKeySha256')
expected_agent_ca_sha256=$(printf '%s' "$verified_manifest" | jq -er '.agentCaSha256')
expected_schema_version=$(printf '%s' "$verified_manifest" | jq -er '.schemaVersion')
expected_recovery_signing_key_sha256=$(printf '%s' "$verified_manifest" | jq -er '.recoverySigningKeySha256 | select(test("^[a-f0-9]{64}$"))')
if [ "$format_version" != "2" ] || [ "$expected_database" != "$database" ]; then
  echo "recovery bundle format or database does not match" >&2
  exit 1
fi
if [ "$expected_recovery_signing_key_sha256" != "$recovery_signing_key_sha256" ]; then
  echo "recovery verification key does not match the signed bundle" >&2
  exit 1
fi
if [ "$expected_image" != "$image" ]; then
  echo "DOCKYARD_IMAGE does not match the recovery bundle" >&2
  exit 1
fi
cp -P -- "$bundle/database.dump" "$temporary/database.dump"
if [ ! -f "$temporary/database.dump" ] || [ -L "$temporary/database.dump" ]; then
  echo "could not create a private database dump snapshot" >&2
  exit 1
fi
chmod 0600 "$temporary/database.dump"
actual_dump_sha256=$(sha256sum "$temporary/database.dump" | awk '{print $1}')
actual_dump_bytes=$(wc -c <"$temporary/database.dump" | tr -d ' ')
if [ "$actual_dump_bytes" -eq 0 ] || [ "$actual_dump_sha256" != "$expected_dump_sha256" ] || [ "$actual_dump_bytes" != "$expected_dump_bytes" ]; then
  echo "database dump checksum or size does not match the manifest" >&2
  exit 1
fi

actual_master_sha256=$(sha256sum "$temporary/master-key.bin" | awk '{print $1}')
if [ "$actual_master_sha256" != "$expected_master_sha256" ]; then
  echo "master key does not match the recovery bundle" >&2
  exit 1
fi

if [ -n "$expected_agent_ca_sha256" ]; then
  openssl x509 -in "$agent_ca_certificate_snapshot" -outform DER >"$temporary/agent-ca.der"
  actual_agent_ca_sha256=$(sha256sum "$temporary/agent-ca.der" | awk '{print $1}')
  rm -f -- "$temporary/agent-ca.der"
  if [ "$actual_agent_ca_sha256" != "$expected_agent_ca_sha256" ]; then
    echo "agent CA certificate does not match the recovery bundle" >&2
    exit 1
  fi
fi

docker exec --interactive --user postgres "$postgres_container" pg_restore --list <"$temporary/database.dump" >/dev/null
staging_database="dockyard_restore_$$"
previous_database="dockyard_previous_$$"
docker exec --user postgres "$postgres_container" createdb --username "$database_user" --owner "$database_user" "$staging_database"
docker exec --interactive --user postgres "$postgres_container" pg_restore --username "$database_user" --dbname "$staging_database" --no-owner --no-privileges --single-transaction --exit-on-error <"$temporary/database.dump"
actual_schema_version=$(docker exec --user postgres "$postgres_container" psql --username "$database_user" --dbname "$staging_database" --tuples-only --no-align --command "SELECT COALESCE(max(version),'') FROM schema_migrations")
actual_schema_version=$(printf '%s' "$actual_schema_version" | tr -d '\r\n')
if [ "$actual_schema_version" != "$expected_schema_version" ]; then
  echo "restored schema version does not match the recovery bundle" >&2
  exit 1
fi
database_exists=$(docker exec --user postgres "$postgres_container" psql --username "$database_user" --dbname postgres --tuples-only --no-align --command "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname='$database')")
database_exists=$(printf '%s' "$database_exists" | tr -d '[:space:]')
case "$database_exists" in
  t)
    docker exec --user postgres "$postgres_container" psql --username "$database_user" --dbname postgres --set ON_ERROR_STOP=1 --command "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='$database' AND pid<>pg_backend_pid()" >/dev/null
    docker exec --user postgres "$postgres_container" psql --username "$database_user" --dbname postgres --set ON_ERROR_STOP=1 --command "BEGIN; ALTER DATABASE \"$database\" RENAME TO \"$previous_database\"; ALTER DATABASE \"$staging_database\" RENAME TO \"$database\"; COMMIT" >/dev/null
    ;;
  f)
    docker exec --user postgres "$postgres_container" psql --username "$database_user" --dbname postgres --set ON_ERROR_STOP=1 --command "ALTER DATABASE \"$staging_database\" RENAME TO \"$database\"" >/dev/null
    previous_database=""
    ;;
  *)
    echo "could not determine whether the target database exists" >&2
    exit 1
    ;;
esac
staging_database=""
echo "control-plane database restored from validated staging database"
if [ -n "$previous_database" ]; then
  echo "previous database retained for rollback: $previous_database"
fi
echo "restart the matching controller image and verify secrets before upgrading"
