#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
mode=${DOCKYARD_INSTALL_MODE:-single}
stack=${DOCKYARD_STACK_NAME:-dockyard}
DOCKYARD_SWARM_SERVICE_NAME=${stack}_dockyard
DOCKYARD_EDGE_PROXY_SERVICE_NAME=${stack}_traefik
export DOCKYARD_SWARM_SERVICE_NAME DOCKYARD_EDGE_PROXY_SERVICE_NAME
network=${DOCKYARD_TRAEFIK_NETWORK:-dockyard-public}
edge_control_network=${DOCKYARD_EDGE_CONTROL_NETWORK:-${stack}-edge-control}
edge_subnet=${DOCKYARD_EDGE_SUBNET:-10.255.250.0/24}
db_password_secret=${DOCKYARD_DB_PASSWORD_SECRET:-dockyard_db_password}
database_url_secret=${DOCKYARD_DATABASE_URL_SECRET:-dockyard_database_url}
master_key_secret=${DOCKYARD_MASTER_KEY_SECRET:-dockyard_master_key}
metrics_token_secret=${DOCKYARD_METRICS_TOKEN_SECRET:-dockyard_metrics_token}
agent_ca_cert_secret=${DOCKYARD_AGENT_CA_CERT_SECRET:-dockyard_agent_ca_cert}
agent_ca_key_secret=${DOCKYARD_AGENT_CA_KEY_SECRET:-dockyard_agent_ca_key}
agent_server_cert_secret=${DOCKYARD_AGENT_SERVER_CERT_SECRET:-dockyard_agent_server_cert}
agent_server_key_secret=${DOCKYARD_AGENT_SERVER_KEY_SECRET:-dockyard_agent_server_key}
agent_previous_ca_cert_secret=${DOCKYARD_AGENT_PREVIOUS_CA_CERT_SECRET:-dockyard_agent_previous_ca_cert}
reuse=${DOCKYARD_REUSE_EXISTING_SECRETS:-false}
dry_run=${DOCKYARD_INSTALL_DRY_RUN:-false}
skip_wait=${DOCKYARD_INSTALL_SKIP_WAIT:-false}
wait_timeout=${DOCKYARD_INSTALL_WAIT_TIMEOUT:-300}
stability_seconds=${DOCKYARD_INSTALL_STABILITY_SECONDS:-90}
egress_private_cidrs=${DOCKYARD_EGRESS_PRIVATE_CIDRS:-}
external_database_drivers=${DOCKYARD_INSTALL_EXTERNAL_DATABASE_DRIVERS:-false}

fail() {
  echo "install-swarm: $*" >&2
  exit 1
}

is_dns_hostname() {
  value=$1
  printf '%s\n' "$value" | awk '
    NR != 1 { exit 1 }
    length($0) < 1 || length($0) > 253 { exit 1 }
    {
      count = split($0, labels, ".")
      if (count < 2) exit 1
      for (i = 1; i <= count; i++) {
        if (length(labels[i]) < 1 || length(labels[i]) > 63) exit 1
        if (labels[i] !~ /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$/) exit 1
      }
    }
    END { if (NR != 1) exit 1 }
  '
}

validate_email() {
  value=$1
  local_part=${value%@*}
  domain=${value#*@}
  [ "$local_part@$domain" = "$value" ] || fail "ACME_EMAIL must be a valid email address"
  case "$local_part" in ""|.*|*.|*[!A-Za-z0-9._+-]*) fail "ACME_EMAIL must be a valid email address" ;; esac
  is_dns_hostname "$domain" || fail "ACME_EMAIL must be a valid email address"
}

case "$mode" in single|ha) ;; *) fail "DOCKYARD_INSTALL_MODE must be single or ha" ;; esac
case "$stack" in ""|-*|*[!A-Za-z0-9_.-]*) fail "invalid DOCKYARD_STACK_NAME" ;; esac
case "$network" in ""|[!a-z0-9]*|*[!a-z0-9_.-]*) fail "DOCKYARD_TRAEFIK_NETWORK must be a lowercase Docker network name of at most 63 characters" ;; esac
[ "${#network}" -le 63 ] || fail "DOCKYARD_TRAEFIK_NETWORK must be a lowercase Docker network name of at most 63 characters"
case "$edge_control_network" in ""|[!a-z0-9]*|*[!a-z0-9_.-]*) fail "DOCKYARD_EDGE_CONTROL_NETWORK must be a lowercase Docker network name of at most 63 characters" ;; esac
[ "${#edge_control_network}" -le 63 ] || fail "DOCKYARD_EDGE_CONTROL_NETWORK must be a lowercase Docker network name of at most 63 characters"
[ "$edge_control_network" != "$network" ] || fail "DOCKYARD_EDGE_CONTROL_NETWORK must differ from DOCKYARD_TRAEFIK_NETWORK"
case "$db_password_secret" in ""|-*|*[!A-Za-z0-9_.-]*) fail "invalid DOCKYARD_DB_PASSWORD_SECRET" ;; esac
case "$database_url_secret" in ""|-*|*[!A-Za-z0-9_.-]*) fail "invalid DOCKYARD_DATABASE_URL_SECRET" ;; esac
case "$master_key_secret" in ""|-*|*[!A-Za-z0-9_.-]*) fail "invalid DOCKYARD_MASTER_KEY_SECRET" ;; esac
case "$metrics_token_secret" in ""|-*|*[!A-Za-z0-9_.-]*) fail "invalid DOCKYARD_METRICS_TOKEN_SECRET" ;; esac
for secret_name in "$agent_ca_cert_secret" "$agent_ca_key_secret" "$agent_server_cert_secret" "$agent_server_key_secret" "$agent_previous_ca_cert_secret"; do
  case "$secret_name" in ""|-*|*[!A-Za-z0-9_.-]*) fail "invalid agent TLS Docker secret name" ;; esac
done
seen_secret_names=" "
for secret_name in "$db_password_secret" "$database_url_secret" "$master_key_secret" "$metrics_token_secret" "$agent_ca_cert_secret" "$agent_ca_key_secret" "$agent_server_cert_secret" "$agent_server_key_secret" "$agent_previous_ca_cert_secret"; do
  case "$seen_secret_names" in *" $secret_name "*) fail "Docker secret names must be distinct" ;; esac
  seen_secret_names="${seen_secret_names}${secret_name} "
done
unset seen_secret_names secret_name
case "$reuse" in true|false) ;; *) fail "DOCKYARD_REUSE_EXISTING_SECRETS must be true or false" ;; esac
case "$dry_run" in true|false) ;; *) fail "DOCKYARD_INSTALL_DRY_RUN must be true or false" ;; esac
case "$skip_wait" in true|false) ;; *) fail "DOCKYARD_INSTALL_SKIP_WAIT must be true or false" ;; esac
case "$external_database_drivers" in true|false) ;; *) fail "DOCKYARD_INSTALL_EXTERNAL_DATABASE_DRIVERS must be true or false" ;; esac
case "$wait_timeout" in ""|*[!0-9]*) fail "DOCKYARD_INSTALL_WAIT_TIMEOUT must be a positive integer" ;; esac
[ "$wait_timeout" -gt 0 ] || fail "DOCKYARD_INSTALL_WAIT_TIMEOUT must be a positive integer"
case "$stability_seconds" in ""|*[!0-9]*) fail "DOCKYARD_INSTALL_STABILITY_SECONDS must be a non-negative integer" ;; esac
[ "$stability_seconds" -le "$wait_timeout" ] || fail "DOCKYARD_INSTALL_STABILITY_SECONDS must not exceed DOCKYARD_INSTALL_WAIT_TIMEOUT"

for command in awk base64 cat date docker find grep mktemp sleep tr wc; do
  command -v "$command" >/dev/null 2>&1 || fail "$command is required"
done
[ -n "${DOCKYARD_HOST:-}" ] || fail "DOCKYARD_HOST is required"
[ -n "${ACME_EMAIL:-}" ] || fail "ACME_EMAIL is required"
is_dns_hostname "$DOCKYARD_HOST" || fail "DOCKYARD_HOST must be a DNS hostname"
validate_email "$ACME_EMAIL"

DOCKYARD_IMAGE=${DOCKYARD_IMAGE:-}
POSTGRES_IMAGE=${POSTGRES_IMAGE:-}
TRAEFIK_IMAGE=${TRAEFIK_IMAGE:-}
export DOCKYARD_HOST ACME_EMAIL DOCKYARD_IMAGE POSTGRES_IMAGE TRAEFIK_IMAGE DOCKYARD_DB_PASSWORD_SECRET DOCKYARD_DATABASE_URL_SECRET DOCKYARD_MASTER_KEY_SECRET DOCKYARD_METRICS_TOKEN_SECRET
DOCKYARD_TRAEFIK_NETWORK=$network
DOCKYARD_EDGE_CONTROL_NETWORK=$edge_control_network
DOCKYARD_EDGE_SUBNET=$edge_subnet
export DOCKYARD_TRAEFIK_NETWORK DOCKYARD_EDGE_CONTROL_NETWORK DOCKYARD_EDGE_SUBNET
export DOCKYARD_EGRESS_PRIVATE_CIDRS="$egress_private_cidrs"
export DOCKYARD_AGENT_CA_CERT_SECRET DOCKYARD_AGENT_CA_KEY_SECRET DOCKYARD_AGENT_SERVER_CERT_SECRET DOCKYARD_AGENT_SERVER_KEY_SECRET DOCKYARD_AGENT_PREVIOUS_CA_CERT_SECRET
"$root/scripts/ci/check-image-digests.sh" controller

swarm_state=$(docker info --format '{{.Swarm.LocalNodeState}} {{.Swarm.ControlAvailable}}')
[ "$swarm_state" = "active true" ] || fail "run this installer on an active Docker Swarm manager"
if [ "$mode" = ha ]; then
  manager_inventory=$(docker node ls --filter role=manager --format '{{.Status}} {{.Availability}}') || fail "could not inspect Swarm managers"
  ready_active_managers=$(printf '%s\n' "$manager_inventory" | awk '$1 == "Ready" && $2 == "Active" { count++ } END { print count+0 }')
  [ "$ready_active_managers" -ge 3 ] || fail "HA installation requires at least three ready, active Swarm managers; found $ready_active_managers"
  unset manager_inventory ready_active_managers
fi

temporary=$(mktemp -d)
created_secrets=""
created_network=false
deployment_started=false
stack_existed=false

remove_created_resources() {
  cleanup_deadline=$(( $(date +%s) + 60 ))
  while :; do
    remaining_secrets=""
    for created_secret in $created_secrets; do
      if ! docker secret rm "$created_secret" >/dev/null 2>&1; then
        remaining_secrets="$remaining_secrets $created_secret"
      fi
    done
    created_secrets=$remaining_secrets

    if [ "$created_network" = true ]; then
      if docker network rm "$network" >/dev/null 2>&1; then
        created_network=false
      fi
    fi

    [ -z "$created_secrets" ] && [ "$created_network" = false ] && return 0
    if [ "$(date +%s)" -ge "$cleanup_deadline" ]; then
      remaining_network=""
      [ "$created_network" = false ] || remaining_network=" network $network"
      echo "install-swarm: cleanup timed out; remove remaining resources manually:${created_secrets}${remaining_network}" >&2
      return 1
    fi
    sleep 2
  done
}

cleanup() {
  status=${1:-$?}
  if [ "$status" -ne 0 ]; then
    if [ "$deployment_started" = true ] && [ "$stack_existed" = false ]; then
      echo "install-swarm: first installation failed; removing stack $stack and newly created resources" >&2
      if docker stack rm "$stack" >/dev/null 2>&1; then
        remove_created_resources || true
      else
        echo "install-swarm: could not remove failed stack $stack; newly created resources were retained" >&2
      fi
    elif [ "$deployment_started" = false ]; then
      remove_created_resources || true
    fi
  fi
  rm -rf -- "$temporary"
  trap - EXIT HUP INT TERM
  exit "$status"
}
trap cleanup EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM

validate_secret_file() {
  label=$1
  path=$2
  [ -n "$path" ] || fail "$label is required"
  [ ! -L "$path" ] && [ -f "$path" ] && [ -r "$path" ] || fail "$label must name a readable regular file, not a symbolic link"
  [ -z "$(find "$path" -prune -perm /077 -print)" ] || fail "$label must not be accessible by group or other users"
  size=$(wc -c <"$path" | tr -d ' ')
  [ "$size" -gt 0 ] && [ "$size" -le 65536 ] || fail "$label must contain between 1 and 65536 bytes"
}

validate_agent_ca() {
  label=$1
  certificate=$2
  openssl x509 -in "$certificate" -noout >/dev/null 2>&1 || fail "$label certificate is invalid"
  openssl verify -CAfile "$certificate" "$certificate" >/dev/null 2>&1 || fail "$label certificate must be a self-signed certificate authority permitted to sign certificates"
  basic_constraints=$(openssl x509 -in "$certificate" -noout -ext basicConstraints 2>/dev/null) || fail "$label certificate must be a self-signed certificate authority permitted to sign certificates"
  key_usage=$(openssl x509 -in "$certificate" -noout -ext keyUsage 2>/dev/null) || fail "$label certificate must be a self-signed certificate authority permitted to sign certificates"
  printf '%s\n' "$basic_constraints" | grep -Eq 'CA:[[:space:]]*TRUE' || fail "$label certificate must be a self-signed certificate authority permitted to sign certificates"
  printf '%s\n' "$key_usage" | grep -Eq 'Certificate Sign|Certificate Signing' || fail "$label certificate must be a self-signed certificate authority permitted to sign certificates"
  openssl x509 -checkend 604800 -noout -in "$certificate" >/dev/null || fail "$label certificate must remain valid for at least 7 days"
  unset basic_constraints key_usage
}

validate_secret_file DOCKYARD_DB_PASSWORD_FILE "${DOCKYARD_DB_PASSWORD_FILE:-}"
validate_secret_file DOCKYARD_DATABASE_URL_FILE "${DOCKYARD_DATABASE_URL_FILE:-}"
validate_secret_file DOCKYARD_MASTER_KEY_FILE "${DOCKYARD_MASTER_KEY_FILE:-}"
validate_secret_file DOCKYARD_METRICS_TOKEN_FILE "${DOCKYARD_METRICS_TOKEN_FILE:-}"

database_password_size=$(wc -c <"$DOCKYARD_DB_PASSWORD_FILE" | tr -d ' ')
database_password_without_line_breaks_size=$(tr -d '\r\n' <"$DOCKYARD_DB_PASSWORD_FILE" | wc -c | tr -d ' ')
[ "$database_password_size" -ge 16 ] && [ "$database_password_size" -le 4096 ] || fail "DOCKYARD_DB_PASSWORD_FILE must contain between 16 and 4096 bytes"
[ "$database_password_without_line_breaks_size" -eq "$database_password_size" ] || fail "DOCKYARD_DB_PASSWORD_FILE must contain one password without line breaks"
unset database_password_size database_password_without_line_breaks_size

if ! tr -d '\r\n' <"$DOCKYARD_MASTER_KEY_FILE" | base64 -d >"$temporary/master-key" 2>/dev/null; then
  fail "DOCKYARD_MASTER_KEY_FILE must contain valid base64"
fi
[ "$(wc -c <"$temporary/master-key" | tr -d ' ')" -eq 32 ] || fail "DOCKYARD_MASTER_KEY_FILE must contain a base64-encoded 32-byte key"
rm -f -- "$temporary/master-key"

metrics_token=$(tr -d '\r\n' <"$DOCKYARD_METRICS_TOKEN_FILE")
metrics_token_size=$(printf '%s' "$metrics_token" | wc -c | tr -d ' ')
[ "$(wc -c <"$DOCKYARD_METRICS_TOKEN_FILE" | tr -d ' ')" -eq "$metrics_token_size" ] || fail "DOCKYARD_METRICS_TOKEN_FILE must contain one token without line breaks"
[ "$metrics_token_size" -ge 32 ] && [ "$metrics_token_size" -le 4096 ] || fail "DOCKYARD_METRICS_TOKEN_FILE must contain between 32 and 4096 bytes"
unset metrics_token metrics_token_size

database_url=$(tr -d '\r\n' <"$DOCKYARD_DATABASE_URL_FILE")
[ "$(wc -c <"$DOCKYARD_DATABASE_URL_FILE" | tr -d ' ')" -eq "$(printf '%s' "$database_url" | wc -c | tr -d ' ')" ] || fail "DOCKYARD_DATABASE_URL_FILE must contain one URL without line breaks"
case "$database_url" in postgres://*|postgresql://*) ;; *) fail "DOCKYARD_DATABASE_URL_FILE must contain a PostgreSQL URL" ;; esac
if [ "$mode" = ha ]; then
  sslmode_count=$(printf '%s\n' "$database_url" | awk -F'[?&]' '{ count=0; for (i=2; i<=NF; i++) if ($i ~ /^sslmode=/) count++; print count }')
  if [ "$sslmode_count" -ne 1 ] || ! printf '%s\n' "$database_url" | grep -Eq '[?&]sslmode=verify-full(&|$)'; then
    fail "HA installation requires exactly one sslmode=verify-full parameter in DOCKYARD_DATABASE_URL_FILE"
  fi
fi
unset database_url

secret_specs="${db_password_secret}:${DOCKYARD_DB_PASSWORD_FILE}
${database_url_secret}:${DOCKYARD_DATABASE_URL_FILE}
${master_key_secret}:${DOCKYARD_MASTER_KEY_FILE}
${metrics_token_secret}:${DOCKYARD_METRICS_TOKEN_FILE}"
if [ "$mode" = ha ]; then
  command -v openssl >/dev/null 2>&1 || fail "openssl is required for HA installation"
  validate_secret_file DOCKYARD_AGENT_CA_CERT_FILE "${DOCKYARD_AGENT_CA_CERT_FILE:-}"
  validate_secret_file DOCKYARD_AGENT_CA_KEY_FILE "${DOCKYARD_AGENT_CA_KEY_FILE:-}"
  validate_secret_file DOCKYARD_AGENT_SERVER_CERT_FILE "${DOCKYARD_AGENT_SERVER_CERT_FILE:-}"
  validate_secret_file DOCKYARD_AGENT_SERVER_KEY_FILE "${DOCKYARD_AGENT_SERVER_KEY_FILE:-}"
  [ -n "${DOCKYARD_AGENT_HOST:-}" ] || fail "DOCKYARD_AGENT_HOST is required for HA installation"
  is_dns_hostname "$DOCKYARD_AGENT_HOST" || fail "DOCKYARD_AGENT_HOST must be a DNS hostname"
  validate_agent_ca "agent CA" "$DOCKYARD_AGENT_CA_CERT_FILE"
  openssl x509 -checkend 604800 -noout -in "$DOCKYARD_AGENT_SERVER_CERT_FILE" >/dev/null || fail "agent server certificate must remain valid for at least 7 days"
  ca_public=$(openssl pkey -in "$DOCKYARD_AGENT_CA_KEY_FILE" -pubout 2>/dev/null) || fail "invalid agent CA private key"
  ca_certificate_public=$(openssl x509 -in "$DOCKYARD_AGENT_CA_CERT_FILE" -pubkey -noout 2>/dev/null) || fail "invalid agent CA certificate"
  [ "$ca_public" = "$ca_certificate_public" ] || fail "agent CA certificate and private key do not match"
  server_public=$(openssl pkey -in "$DOCKYARD_AGENT_SERVER_KEY_FILE" -pubout 2>/dev/null) || fail "invalid agent server private key"
  server_certificate_public=$(openssl x509 -in "$DOCKYARD_AGENT_SERVER_CERT_FILE" -pubkey -noout 2>/dev/null) || fail "invalid agent server certificate"
  [ "$server_public" = "$server_certificate_public" ] || fail "agent server certificate and private key do not match"
	[ "$ca_public" != "$server_public" ] || fail "agent server certificate must use a key distinct from the agent CA"
  unset ca_public ca_certificate_public server_public server_certificate_public
  if [ -n "${DOCKYARD_AGENT_PREVIOUS_CA_CERT_FILE:-}" ]; then
    validate_secret_file DOCKYARD_AGENT_PREVIOUS_CA_CERT_FILE "$DOCKYARD_AGENT_PREVIOUS_CA_CERT_FILE"
    validate_agent_ca "previous agent CA" "$DOCKYARD_AGENT_PREVIOUS_CA_CERT_FILE"
    active_ca_fingerprint=$(openssl x509 -in "$DOCKYARD_AGENT_CA_CERT_FILE" -noout -fingerprint -sha256)
    previous_ca_fingerprint=$(openssl x509 -in "$DOCKYARD_AGENT_PREVIOUS_CA_CERT_FILE" -noout -fingerprint -sha256)
    [ "$active_ca_fingerprint" != "$previous_ca_fingerprint" ] || fail "previous agent CA must differ from the active agent CA"
    unset active_ca_fingerprint previous_ca_fingerprint
  fi
  if ! openssl verify -purpose sslserver -CAfile "$DOCKYARD_AGENT_CA_CERT_FILE" -verify_hostname "$DOCKYARD_AGENT_HOST" "$DOCKYARD_AGENT_SERVER_CERT_FILE" >/dev/null 2>&1; then
    [ -n "${DOCKYARD_AGENT_PREVIOUS_CA_CERT_FILE:-}" ] && openssl verify -purpose sslserver -CAfile "$DOCKYARD_AGENT_PREVIOUS_CA_CERT_FILE" -verify_hostname "$DOCKYARD_AGENT_HOST" "$DOCKYARD_AGENT_SERVER_CERT_FILE" >/dev/null || fail "agent server certificate verification failed against active and previous CAs for TLS server authentication"
  fi
  secret_specs="$secret_specs
${agent_ca_cert_secret}:${DOCKYARD_AGENT_CA_CERT_FILE}
${agent_ca_key_secret}:${DOCKYARD_AGENT_CA_KEY_FILE}
${agent_server_cert_secret}:${DOCKYARD_AGENT_SERVER_CERT_FILE}
${agent_server_key_secret}:${DOCKYARD_AGENT_SERVER_KEY_FILE}"
  if [ -n "${DOCKYARD_AGENT_PREVIOUS_CA_CERT_FILE:-}" ]; then
    secret_specs="$secret_specs
${agent_previous_ca_cert_secret}:${DOCKYARD_AGENT_PREVIOUS_CA_CERT_FILE}"
  fi
elif [ -n "${DOCKYARD_AGENT_PREVIOUS_CA_CERT_FILE:-}" ]; then
  fail "DOCKYARD_AGENT_PREVIOUS_CA_CERT_FILE requires DOCKYARD_INSTALL_MODE=ha"
fi

for image_spec in "DOCKYARD_IMAGE:$DOCKYARD_IMAGE" "POSTGRES_IMAGE:$POSTGRES_IMAGE" "TRAEFIK_IMAGE:$TRAEFIK_IMAGE"; do
  image_label=${image_spec%%:*}
  image=${image_spec#*:}
  docker manifest inspect "$image" >/dev/null 2>&1 || fail "$image_label cannot be resolved from the configured registry; authenticate Docker and verify the immutable digest"
done
if [ "$mode" = ha ]; then
  docker run --rm -i --network none --read-only --cap-drop ALL --security-opt no-new-privileges --entrypoint /usr/local/bin/dockyard "$DOCKYARD_IMAGE" validate-database-url --require-tls=true <"$DOCKYARD_DATABASE_URL_FILE" >/dev/null || fail "DOCKYARD_DATABASE_URL_FILE does not contain a valid PostgreSQL URL for HA mode"
else
  { cat "$DOCKYARD_DB_PASSWORD_FILE"; printf '\0'; cat "$DOCKYARD_DATABASE_URL_FILE"; } | docker run --rm -i --network none --read-only --cap-drop ALL --security-opt no-new-privileges --entrypoint /usr/local/bin/dockyard "$DOCKYARD_IMAGE" validate-bundled-database-credentials >/dev/null || fail "bundled PostgreSQL password and URL credentials are invalid or do not match"
fi
if [ -n "$egress_private_cidrs" ]; then
  docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --entrypoint /usr/local/bin/dockyard "$DOCKYARD_IMAGE" validate-egress-policy --cidrs "$egress_private_cidrs" >/dev/null || fail "DOCKYARD_EGRESS_PRIVATE_CIDRS must contain at most 64 unique CIDR networks"
fi
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --entrypoint /usr/local/bin/dockyard "$DOCKYARD_IMAGE" validate-edge-subnet --cidr "$edge_subnet" >/dev/null || fail "DOCKYARD_EDGE_SUBNET must be a canonical private IPv4 CIDR between /16 and /28"
if [ "$external_database_drivers" = true ]; then
  docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
    --entrypoint /usr/local/bin/dockyard "$DOCKYARD_IMAGE" inspect-database-drivers \
    --directory /usr/local/lib/dockyard/database-drivers >/dev/null || fail "DOCKYARD_IMAGE does not contain a valid external database driver bundle"
fi

existing=""
while IFS= read -r spec; do
  name=${spec%%:*}
  if docker secret inspect "$name" >/dev/null 2>&1; then
    existing="$existing $name"
  fi
done <<EOF
$secret_specs
EOF
if [ -n "$existing" ] && [ "$reuse" != true ]; then
  fail "Docker secrets already exist:$existing; set DOCKYARD_REUSE_EXISTING_SECRETS=true only after verifying their values"
fi

# Render and validate the complete stack before creating any resource. Build
# the same argument vector once so preflight and deployment cannot diverge.
set -- -c "$root/deploy/swarm.yml"
if [ "$mode" = ha ]; then
  set -- "$@" -c "$root/deploy/swarm-ha.yml"
  if [ -n "${DOCKYARD_AGENT_PREVIOUS_CA_CERT_FILE:-}" ]; then
    set -- "$@" -c "$root/deploy/swarm-agent-ca-rollover.yml"
  fi
fi
if [ "$external_database_drivers" = true ]; then
  set -- "$@" -c "$root/deploy/swarm-database-drivers.yml"
fi
docker stack config "$@" >/dev/null
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
if [ "$dry_run" = true ]; then
  echo "Preflight passed for $mode installation of stack $stack; no resources were changed."
  exit 0
fi

if [ "$network_exists" = false ]; then
  docker network create --driver overlay --opt encrypted --attachable "$network" >/dev/null
  created_network=true
fi

while IFS= read -r spec; do
  name=${spec%%:*}
  path=${spec#*:}
  if ! docker secret inspect "$name" >/dev/null 2>&1; then
    docker secret create "$name" "$path" >/dev/null
    created_secrets="$created_secrets $name"
  fi
done <<EOF
$secret_specs
EOF

docker stack deploy --prune --with-registry-auth "$@" "$stack" || fail "could not submit $mode stack $stack"
deployment_started=true
if [ "$skip_wait" = true ]; then
  echo "Stack $stack submitted; convergence wait was skipped."
  exit 0
fi

deadline=$(( $(date +%s) + wait_timeout ))
stable_since=
while :; do
  services=$(docker stack services "$stack" --format '{{.Name}} {{.Replicas}}') || fail "could not inspect stack services"
  [ -n "$services" ] || fail "stack has no services"
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
${stack}_dockyard|$DOCKYARD_IMAGE
${stack}_postgres|$POSTGRES_IMAGE
${stack}_traefik|$TRAEFIK_IMAGE
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
    fail "stack $stack did not run the requested images and remain converged for ${stability_seconds}s within ${wait_timeout}s"
  fi
  sleep 2
done
echo "Stack $stack installed and remained converged for ${stability_seconds}s in $mode mode."
