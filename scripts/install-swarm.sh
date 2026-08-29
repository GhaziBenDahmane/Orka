#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
mode=${DOCKYARD_INSTALL_MODE:-single}
stack=${DOCKYARD_STACK_NAME:-dockyard}
network=dockyard-public
reuse=${DOCKYARD_REUSE_EXISTING_SECRETS:-false}
dry_run=${DOCKYARD_INSTALL_DRY_RUN:-false}
skip_wait=${DOCKYARD_INSTALL_SKIP_WAIT:-false}
wait_timeout=${DOCKYARD_INSTALL_WAIT_TIMEOUT:-300}
stability_seconds=${DOCKYARD_INSTALL_STABILITY_SECONDS:-90}

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
case "$reuse" in true|false) ;; *) fail "DOCKYARD_REUSE_EXISTING_SECRETS must be true or false" ;; esac
case "$dry_run" in true|false) ;; *) fail "DOCKYARD_INSTALL_DRY_RUN must be true or false" ;; esac
case "$skip_wait" in true|false) ;; *) fail "DOCKYARD_INSTALL_SKIP_WAIT must be true or false" ;; esac
case "$wait_timeout" in ""|*[!0-9]*) fail "DOCKYARD_INSTALL_WAIT_TIMEOUT must be a positive integer" ;; esac
[ "$wait_timeout" -gt 0 ] || fail "DOCKYARD_INSTALL_WAIT_TIMEOUT must be a positive integer"
case "$stability_seconds" in ""|*[!0-9]*) fail "DOCKYARD_INSTALL_STABILITY_SECONDS must be a non-negative integer" ;; esac
[ "$stability_seconds" -le "$wait_timeout" ] || fail "DOCKYARD_INSTALL_STABILITY_SECONDS must not exceed DOCKYARD_INSTALL_WAIT_TIMEOUT"

for command in awk base64 date docker find grep mktemp sleep tr wc; do
  command -v "$command" >/dev/null 2>&1 || fail "$command is required"
done
[ -n "${DOCKYARD_HOST:-}" ] || fail "DOCKYARD_HOST is required"
[ -n "${ACME_EMAIL:-}" ] || fail "ACME_EMAIL is required"
is_dns_hostname "$DOCKYARD_HOST" || fail "DOCKYARD_HOST must be a DNS hostname"
validate_email "$ACME_EMAIL"

DOCKYARD_IMAGE=${DOCKYARD_IMAGE:-}
POSTGRES_IMAGE=${POSTGRES_IMAGE:-}
TRAEFIK_IMAGE=${TRAEFIK_IMAGE:-}
export DOCKYARD_HOST ACME_EMAIL DOCKYARD_IMAGE POSTGRES_IMAGE TRAEFIK_IMAGE
"$root/scripts/ci/check-image-digests.sh" controller

swarm_state=$(docker info --format '{{.Swarm.LocalNodeState}} {{.Swarm.ControlAvailable}}')
[ "$swarm_state" = "active true" ] || fail "run this installer on an active Docker Swarm manager"

temporary=$(mktemp -d)
created_secrets=""
created_network=false
deployment_started=false
cleanup() {
  status=$?
  if [ "$status" -ne 0 ] && [ "$deployment_started" = false ]; then
    for created_secret in $created_secrets; do
      docker secret rm "$created_secret" >/dev/null 2>&1 || true
    done
    if [ "$created_network" = true ]; then
      docker network rm "$network" >/dev/null 2>&1 || true
    fi
  fi
  rm -rf -- "$temporary"
  trap - EXIT HUP INT TERM
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

validate_secret_file() {
  label=$1
  path=$2
  [ -n "$path" ] || fail "$label is required"
  [ -f "$path" ] && [ -r "$path" ] || fail "$label must name a readable regular file"
  [ -z "$(find "$path" -prune -perm /077 -print)" ] || fail "$label must not be accessible by group or other users"
  size=$(wc -c <"$path" | tr -d ' ')
  [ "$size" -gt 0 ] && [ "$size" -le 65536 ] || fail "$label must contain between 1 and 65536 bytes"
}

validate_secret_file DOCKYARD_DB_PASSWORD_FILE "${DOCKYARD_DB_PASSWORD_FILE:-}"
validate_secret_file DOCKYARD_DATABASE_URL_FILE "${DOCKYARD_DATABASE_URL_FILE:-}"
validate_secret_file DOCKYARD_MASTER_KEY_FILE "${DOCKYARD_MASTER_KEY_FILE:-}"

if ! tr -d '\r\n' <"$DOCKYARD_MASTER_KEY_FILE" | base64 -d >"$temporary/master-key" 2>/dev/null; then
  fail "DOCKYARD_MASTER_KEY_FILE must contain valid base64"
fi
[ "$(wc -c <"$temporary/master-key" | tr -d ' ')" -eq 32 ] || fail "DOCKYARD_MASTER_KEY_FILE must contain a base64-encoded 32-byte key"
rm -f -- "$temporary/master-key"

database_url=$(tr -d '\r\n' <"$DOCKYARD_DATABASE_URL_FILE")
[ "$(wc -c <"$DOCKYARD_DATABASE_URL_FILE" | tr -d ' ')" -eq "$(printf '%s' "$database_url" | wc -c | tr -d ' ')" ] || fail "DOCKYARD_DATABASE_URL_FILE must contain one URL without line breaks"
case "$database_url" in postgres://*|postgresql://*) ;; *) fail "DOCKYARD_DATABASE_URL_FILE must contain a PostgreSQL URL" ;; esac
if [ "$mode" = ha ] && ! printf '%s\n' "$database_url" | grep -Eq '[?&]sslmode=verify-full(&|$)'; then
  fail "HA installation requires sslmode=verify-full in DOCKYARD_DATABASE_URL_FILE"
fi
unset database_url

secret_specs="dockyard_db_password:${DOCKYARD_DB_PASSWORD_FILE}
dockyard_database_url:${DOCKYARD_DATABASE_URL_FILE}
dockyard_master_key:${DOCKYARD_MASTER_KEY_FILE}"
if [ "$mode" = ha ]; then
  command -v openssl >/dev/null 2>&1 || fail "openssl is required for HA installation"
  validate_secret_file DOCKYARD_AGENT_CA_CERT_FILE "${DOCKYARD_AGENT_CA_CERT_FILE:-}"
  validate_secret_file DOCKYARD_AGENT_CA_KEY_FILE "${DOCKYARD_AGENT_CA_KEY_FILE:-}"
  validate_secret_file DOCKYARD_AGENT_SERVER_CERT_FILE "${DOCKYARD_AGENT_SERVER_CERT_FILE:-}"
  validate_secret_file DOCKYARD_AGENT_SERVER_KEY_FILE "${DOCKYARD_AGENT_SERVER_KEY_FILE:-}"
  [ -n "${DOCKYARD_AGENT_HOST:-}" ] || fail "DOCKYARD_AGENT_HOST is required for HA installation"
  is_dns_hostname "$DOCKYARD_AGENT_HOST" || fail "DOCKYARD_AGENT_HOST must be a DNS hostname"
  openssl verify -CAfile "$DOCKYARD_AGENT_CA_CERT_FILE" -verify_hostname "$DOCKYARD_AGENT_HOST" "$DOCKYARD_AGENT_SERVER_CERT_FILE" >/dev/null || fail "agent server certificate verification failed"
  openssl x509 -checkend 604800 -noout -in "$DOCKYARD_AGENT_CA_CERT_FILE" >/dev/null || fail "agent CA certificate must remain valid for at least 7 days"
  openssl x509 -checkend 604800 -noout -in "$DOCKYARD_AGENT_SERVER_CERT_FILE" >/dev/null || fail "agent server certificate must remain valid for at least 7 days"
  ca_public=$(openssl pkey -in "$DOCKYARD_AGENT_CA_KEY_FILE" -pubout 2>/dev/null) || fail "invalid agent CA private key"
  ca_certificate_public=$(openssl x509 -in "$DOCKYARD_AGENT_CA_CERT_FILE" -pubkey -noout 2>/dev/null) || fail "invalid agent CA certificate"
  [ "$ca_public" = "$ca_certificate_public" ] || fail "agent CA certificate and private key do not match"
  server_public=$(openssl pkey -in "$DOCKYARD_AGENT_SERVER_KEY_FILE" -pubout 2>/dev/null) || fail "invalid agent server private key"
  server_certificate_public=$(openssl x509 -in "$DOCKYARD_AGENT_SERVER_CERT_FILE" -pubkey -noout 2>/dev/null) || fail "invalid agent server certificate"
  [ "$server_public" = "$server_certificate_public" ] || fail "agent server certificate and private key do not match"
  unset ca_public ca_certificate_public server_public server_certificate_public
  secret_specs="$secret_specs
dockyard_agent_ca_cert:${DOCKYARD_AGENT_CA_CERT_FILE}
dockyard_agent_ca_key:${DOCKYARD_AGENT_CA_KEY_FILE}
dockyard_agent_server_cert:${DOCKYARD_AGENT_SERVER_CERT_FILE}
dockyard_agent_server_key:${DOCKYARD_AGENT_SERVER_KEY_FILE}"
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

# Render and validate the complete stack before creating any resource.
if [ "$mode" = ha ]; then
  docker stack config -c "$root/deploy/swarm.yml" -c "$root/deploy/swarm-ha.yml" >/dev/null
else
  docker stack config -c "$root/deploy/swarm.yml" >/dev/null
fi
if [ "$dry_run" = true ]; then
  echo "Preflight passed for $mode installation of stack $stack; no resources were changed."
  exit 0
fi

if ! docker network inspect "$network" >/dev/null 2>&1; then
  docker network create --driver overlay --attachable "$network" >/dev/null
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

deployment_started=true
if [ "$mode" = ha ]; then
  docker stack deploy --prune --with-registry-auth -c "$root/deploy/swarm.yml" -c "$root/deploy/swarm-ha.yml" "$stack"
else
  docker stack deploy --prune --with-registry-auth -c "$root/deploy/swarm.yml" "$stack"
fi
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
