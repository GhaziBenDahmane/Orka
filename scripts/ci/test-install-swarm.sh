#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
temporary="$(mktemp -d)"
cleanup() { rm -rf -- "$temporary"; }
trap cleanup EXIT

mkdir -p "$temporary/bin" "$temporary/secrets"
printf '%s' 'correct horse battery staple' >"$temporary/secrets/database-password"
printf '%s' 'postgres://dockyard:correct%20horse%20battery%20staple@postgres:5432/dockyard?sslmode=disable' >"$temporary/secrets/database-url"
printf '%s' 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' >"$temporary/secrets/master-key"
printf '%s' 'test-metrics-token-at-least-32-bytes' >"$temporary/secrets/metrics-token"
chmod 0600 "$temporary"/secrets/*

cat >"$temporary/bin/docker" <<'MOCK'
#!/bin/sh
set -eu
printf '%s\n' "$*" >>"$DOCKYARD_INSTALL_TEST_LOG"
case "$1 $2" in
  "info --format") printf '%s\n' 'active true' ;;
  "node ls")
    manager_count=${DOCKYARD_INSTALL_TEST_HA_MANAGER_COUNT:-3}
    index=1
    while [ "$index" -le "$manager_count" ]; do
      printf '%s\n' 'Ready Active'
      index=$((index + 1))
    done ;;
  "manifest inspect")
    if [ "${DOCKYARD_INSTALL_TEST_UNAVAILABLE_IMAGE:-}" = "$3" ]; then exit 1; fi ;;
  "run --rm")
    case "$*" in
      *validate-bundled-database-credentials*)
        [ "${DOCKYARD_INSTALL_TEST_INVALID_DATABASE_CREDENTIALS:-false}" != true ] &&
          [ "${DOCKYARD_INSTALL_TEST_INVALID_DATABASE_URL:-false}" != true ] || exit 1 ;;
      *validate-database-url*) [ "${DOCKYARD_INSTALL_TEST_INVALID_DATABASE_URL:-false}" != true ] || exit 1 ;;
      *inspect-database-drivers*) [ "${DOCKYARD_INSTALL_TEST_INVALID_DATABASE_DRIVERS:-false}" != true ] || exit 1 ;;
      *validate-edge-subnet*)
        case "$*" in
          *' --cidr 10.255.250.0/24'|*' --cidr 10.40.0.0/24') ;;
          *) exit 1 ;;
        esac ;;
      *not-a-cidr*) exit 1 ;;
    esac ;;
  "secret inspect")
    case " ${DOCKYARD_INSTALL_TEST_EXISTING_SECRETS:-} " in *" $3 "*) exit 0 ;; *) exit 1 ;; esac ;;
  "secret create")
    if [ "${DOCKYARD_INSTALL_TEST_FAIL_SECRET:-}" = "$3" ]; then exit 1; fi ;;
  "network inspect")
    if [ "${DOCKYARD_INSTALL_TEST_NETWORK_EXISTS:-false}" = true ]; then
      if [ "${3:-}" = --format ]; then printf '%s\n' "${DOCKYARD_INSTALL_TEST_NETWORK_PROPERTIES:-bridge|local|false|{}}"; fi
      exit 0
    fi
    exit 1 ;;
  "stack deploy")
    [ "${DOCKYARD_INSTALL_TEST_FAIL_DEPLOY:-false}" != true ] || exit 1 ;;
  "stack config") printf 'edge-control-network=%s\n' "$DOCKYARD_EDGE_CONTROL_NETWORK" >>"$DOCKYARD_INSTALL_TEST_LOG" ;;
  "service inspect")
    service=$5
    state=${DOCKYARD_INSTALL_TEST_UPDATE_STATE:-completed}
    case "$service" in
      *_dockyard) image=${DOCKYARD_INSTALL_TEST_CONTROLLER_IMAGE:-$DOCKYARD_IMAGE} ;;
      *_postgres) image=$POSTGRES_IMAGE ;;
      *_traefik) image=$TRAEFIK_IMAGE ;;
      *) exit 1 ;;
    esac
    printf '%s|%s\n' "$image" "$state" ;;
  "stack services")
    if [ "${DOCKYARD_INSTALL_TEST_FLAP_ONCE:-false}" = true ]; then
      count=0
      [ ! -f "$DOCKYARD_INSTALL_TEST_STATE" ] || count=$(cat "$DOCKYARD_INSTALL_TEST_STATE")
      count=$((count + 1))
      printf '%s' "$count" >"$DOCKYARD_INSTALL_TEST_STATE"
      if [ "$count" -eq 2 ]; then
        printf '%s\n' 'dockyard_dockyard 0/1' 'dockyard_postgres 1/1' 'dockyard_traefik 1/1'
        exit 0
      fi
    fi
    printf '%s\n' 'dockyard_dockyard 1/1' 'dockyard_postgres 1/1' 'dockyard_traefik 1/1' ;;
esac
MOCK
chmod +x "$temporary/bin/docker"

digest='sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
export PATH="$temporary/bin:$PATH"
export DOCKYARD_INSTALL_TEST_LOG="$temporary/docker.log"
export DOCKYARD_INSTALL_TEST_STATE="$temporary/state"
export DOCKYARD_HOST='dockyard.example.test'
export ACME_EMAIL='ops@example.test'
export DOCKYARD_IMAGE="example/dockyard@$digest"
export POSTGRES_IMAGE="postgres@$digest"
export TRAEFIK_IMAGE="traefik@$digest"
export DOCKYARD_DB_PASSWORD_FILE="$temporary/secrets/database-password"
export DOCKYARD_DATABASE_URL_FILE="$temporary/secrets/database-url"
export DOCKYARD_MASTER_KEY_FILE="$temporary/secrets/master-key"
export DOCKYARD_METRICS_TOKEN_FILE="$temporary/secrets/metrics-token"
export DOCKYARD_INSTALL_STABILITY_SECONDS=0

: >"$DOCKYARD_INSTALL_TEST_LOG"
DOCKYARD_INSTALL_DRY_RUN=true "$root/scripts/install-swarm.sh" | grep -q 'no resources were changed'
grep -q '^stack config ' "$DOCKYARD_INSTALL_TEST_LOG"
for image in "$DOCKYARD_IMAGE" "$POSTGRES_IMAGE" "$TRAEFIK_IMAGE"; do
  grep -Fqx "manifest inspect $image" "$DOCKYARD_INSTALL_TEST_LOG"
done
grep -q '^run --rm -i --network none --read-only --cap-drop ALL --security-opt no-new-privileges --entrypoint /usr/local/bin/dockyard .* validate-bundled-database-credentials$' "$DOCKYARD_INSTALL_TEST_LOG"
grep -q '^run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --entrypoint /usr/local/bin/dockyard .* validate-edge-subnet --cidr 10.255.250.0/24$' "$DOCKYARD_INSTALL_TEST_LOG"
if grep -q 'postgres://dockyard:correct%20horse' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'database URL leaked to Docker command log' >&2
  exit 1
fi
if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'dry-run mutated Docker state' >&2
  exit 1
fi

: >"$DOCKYARD_INSTALL_TEST_LOG"
DOCKYARD_EDGE_SUBNET='10.40.0.0/24' DOCKYARD_INSTALL_DRY_RUN=true \
  "$root/scripts/install-swarm.sh" >/dev/null
grep -q 'validate-edge-subnet --cidr 10.40.0.0/24$' "$DOCKYARD_INSTALL_TEST_LOG"

for unsafe_subnet in '0.0.0.0/0' '10.0.0.0/8' '10.20.0.1/24' '192.0.2.0/24' 'fd00::/64' '192.168.42.0/29'; do
  : >"$DOCKYARD_INSTALL_TEST_LOG"
  if DOCKYARD_EDGE_SUBNET="$unsafe_subnet" \
    "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
    echo "installer accepted unsafe edge subnet: $unsafe_subnet" >&2
    exit 1
  fi
  grep -q 'DOCKYARD_EDGE_SUBNET must be a canonical private IPv4 CIDR between /16 and /28' "$temporary/err"
  if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
    echo "unsafe edge subnet mutated Docker state: $unsafe_subnet" >&2
    exit 1
  fi
done

ln -s "$temporary/secrets/metrics-token" "$temporary/secrets/metrics-token-link"
: >"$DOCKYARD_INSTALL_TEST_LOG"
if DOCKYARD_METRICS_TOKEN_FILE="$temporary/secrets/metrics-token-link" \
  "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'installer accepted a symbolic-link secret input' >&2
  exit 1
fi
grep -q 'must name a readable regular file, not a symbolic link' "$temporary/err"
if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'symbolic-link secret input mutated Docker state' >&2
  exit 1
fi

: >"$DOCKYARD_INSTALL_TEST_LOG"
if DOCKYARD_INSTALL_TEST_INVALID_DATABASE_URL=true "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'installer ignored candidate database URL validation failure' >&2
  exit 1
fi
grep -q 'bundled PostgreSQL password and URL credentials are invalid or do not match' "$temporary/err"
if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'invalid database URL mutated Docker state' >&2
  exit 1
fi

: >"$DOCKYARD_INSTALL_TEST_LOG"
if DOCKYARD_INSTALL_TEST_INVALID_DATABASE_CREDENTIALS=true "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'installer ignored bundled database credential validation failure' >&2
  exit 1
fi
grep -q 'bundled PostgreSQL password and URL credentials are invalid or do not match' "$temporary/err"
if grep -Eq 'correct horse battery staple|postgres://dockyard:correct%20horse' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'bundled database credentials leaked to Docker command log' >&2
  exit 1
fi
if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'mismatched bundled database credentials mutated Docker state' >&2
  exit 1
fi

: >"$DOCKYARD_INSTALL_TEST_LOG"
DOCKYARD_EGRESS_PRIVATE_CIDRS='10.40.12.0/24,fd00:40:12::/64' \
  DOCKYARD_INSTALL_DRY_RUN=true "$root/scripts/install-swarm.sh" >/dev/null
grep -q '^run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --entrypoint /usr/local/bin/dockyard .* validate-egress-policy --cidrs 10.40.12.0/24,fd00:40:12::/64$' "$DOCKYARD_INSTALL_TEST_LOG"

: >"$DOCKYARD_INSTALL_TEST_LOG"
if DOCKYARD_EGRESS_PRIVATE_CIDRS='not-a-cidr' "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'installer accepted an invalid private egress CIDR' >&2
  exit 1
fi
grep -q 'DOCKYARD_EGRESS_PRIVATE_CIDRS must contain' "$temporary/err"
if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'invalid egress policy mutated Docker state' >&2
  exit 1
fi

: >"$DOCKYARD_INSTALL_TEST_LOG"
DOCKYARD_INSTALL_EXTERNAL_DATABASE_DRIVERS=true DOCKYARD_INSTALL_DRY_RUN=true \
  "$root/scripts/install-swarm.sh" >/dev/null
grep -q ' inspect-database-drivers --directory /usr/local/lib/dockyard/database-drivers$' "$DOCKYARD_INSTALL_TEST_LOG"
grep -q "stack config -c $root/deploy/swarm.yml -c $root/deploy/swarm-database-drivers.yml" "$DOCKYARD_INSTALL_TEST_LOG"
if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'external-driver dry-run mutated Docker state' >&2
  exit 1
fi

: >"$DOCKYARD_INSTALL_TEST_LOG"
if DOCKYARD_INSTALL_EXTERNAL_DATABASE_DRIVERS=true DOCKYARD_INSTALL_TEST_INVALID_DATABASE_DRIVERS=true \
  "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'installer accepted an invalid external database driver bundle' >&2
  exit 1
fi
grep -q 'does not contain a valid external database driver bundle' "$temporary/err"
if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'invalid external-driver bundle mutated Docker state' >&2
  exit 1
fi

: >"$DOCKYARD_INSTALL_TEST_LOG"
if DOCKYARD_INSTALL_EXTERNAL_DATABASE_DRIVERS=maybe "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'installer accepted an invalid external-driver mode' >&2
  exit 1
fi
grep -q 'DOCKYARD_INSTALL_EXTERNAL_DATABASE_DRIVERS must be true or false' "$temporary/err"
if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'invalid external-driver mode mutated Docker state' >&2
  exit 1
fi

: >"$DOCKYARD_INSTALL_TEST_LOG"
"$root/scripts/install-swarm.sh" | grep -q 'installed and remained converged'
grep -q '^network create --driver overlay --opt encrypted --attachable dockyard-public$' "$DOCKYARD_INSTALL_TEST_LOG"
grep -q "^secret create dockyard_db_password $DOCKYARD_DB_PASSWORD_FILE$" "$DOCKYARD_INSTALL_TEST_LOG"
grep -q "^secret create dockyard_metrics_token $DOCKYARD_METRICS_TOKEN_FILE$" "$DOCKYARD_INSTALL_TEST_LOG"
grep -q '^stack deploy --prune --with-registry-auth ' "$DOCKYARD_INSTALL_TEST_LOG"
if grep -Eq 'correct horse battery staple|test-metrics-token-at-least-32-bytes' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'secret value leaked to Docker command log' >&2
  exit 1
fi

: >"$DOCKYARD_INSTALL_TEST_LOG"
if DOCKYARD_INSTALL_TEST_FAIL_DEPLOY=true "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'installer ignored an immediate stack deployment failure' >&2
  exit 1
fi
grep -q 'could not submit single stack dockyard' "$temporary/err"
for secret in dockyard_db_password dockyard_database_url dockyard_master_key dockyard_metrics_token; do
  grep -q "^secret rm $secret$" "$DOCKYARD_INSTALL_TEST_LOG"
done
grep -q '^network rm dockyard-public$' "$DOCKYARD_INSTALL_TEST_LOG"

: >"$DOCKYARD_INSTALL_TEST_LOG"
if DOCKYARD_INSTALL_TEST_NETWORK_EXISTS=true DOCKYARD_INSTALL_TEST_NETWORK_PROPERTIES='bridge|local|false|{}' \
  "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'installer accepted an unencrypted existing overlay network' >&2
  exit 1
fi
grep -q 'existing Docker network dockyard-public must be an attachable encrypted Swarm overlay' "$temporary/err"
if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'unencrypted-network failure mutated Docker state' >&2
  exit 1
fi

: >"$DOCKYARD_INSTALL_TEST_LOG"
if DOCKYARD_INSTALL_TEST_NETWORK_EXISTS=true DOCKYARD_INSTALL_TEST_NETWORK_PROPERTIES='overlay|swarm|true|{"encrypted":"false"}' \
  "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'installer accepted an overlay with encryption explicitly disabled' >&2
  exit 1
fi
grep -q 'existing Docker network dockyard-public must be an attachable encrypted Swarm overlay' "$temporary/err"
if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'disabled-encryption failure mutated Docker state' >&2
  exit 1
fi

: >"$DOCKYARD_INSTALL_TEST_LOG"
DOCKYARD_INSTALL_TEST_NETWORK_EXISTS=true DOCKYARD_INSTALL_TEST_NETWORK_PROPERTIES='overlay|swarm|true|{"encrypted":""}' \
  "$root/scripts/install-swarm.sh" >/dev/null
if grep -q '^network create' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'installer recreated an encrypted existing overlay network' >&2
  exit 1
fi

: >"$DOCKYARD_INSTALL_TEST_LOG"
DOCKYARD_TRAEFIK_NETWORK='shared_tenant.routing' \
  "$root/scripts/install-swarm.sh" >/dev/null
grep -q '^network inspect shared_tenant.routing$' "$DOCKYARD_INSTALL_TEST_LOG"
grep -q '^network create --driver overlay --opt encrypted --attachable shared_tenant.routing$' "$DOCKYARD_INSTALL_TEST_LOG"

: >"$DOCKYARD_INSTALL_TEST_LOG"
DOCKYARD_STACK_NAME='dockyard_blue' \
  "$root/scripts/install-swarm.sh" >/dev/null
grep -q '^edge-control-network=dockyard_blue-edge-control$' "$DOCKYARD_INSTALL_TEST_LOG"

: >"$DOCKYARD_INSTALL_TEST_LOG"
DOCKYARD_EDGE_CONTROL_NETWORK='platform-private' \
  "$root/scripts/install-swarm.sh" >/dev/null
grep -q '^edge-control-network=platform-private$' "$DOCKYARD_INSTALL_TEST_LOG"

: >"$DOCKYARD_INSTALL_TEST_LOG"
if DOCKYARD_TRAEFIK_NETWORK='shared-network' DOCKYARD_EDGE_CONTROL_NETWORK='shared-network' \
  "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'installer accepted the public routing network as its private control network' >&2
  exit 1
fi
grep -q 'DOCKYARD_EDGE_CONTROL_NETWORK must differ from DOCKYARD_TRAEFIK_NETWORK' "$temporary/err"
if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'colliding public and control networks mutated Docker state' >&2
  exit 1
fi

for unsafe_network in 'Public' '-public' '.public' 'public/network' 'bad network' 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; do
  : >"$DOCKYARD_INSTALL_TEST_LOG"
  if DOCKYARD_TRAEFIK_NETWORK="$unsafe_network" \
    "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
    echo "installer accepted unsafe Traefik network name: $unsafe_network" >&2
    exit 1
  fi
  grep -q 'DOCKYARD_TRAEFIK_NETWORK must be a lowercase Docker network name of at most 63 characters' "$temporary/err"
  if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
    echo "unsafe Traefik network name mutated Docker state: $unsafe_network" >&2
    exit 1
  fi
done

for unsafe_network in 'Private' '-private' '.private' 'private/network' 'bad network' 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; do
  : >"$DOCKYARD_INSTALL_TEST_LOG"
  if DOCKYARD_EDGE_CONTROL_NETWORK="$unsafe_network" \
    "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
    echo "installer accepted unsafe edge control network name: $unsafe_network" >&2
    exit 1
  fi
  grep -q 'DOCKYARD_EDGE_CONTROL_NETWORK must be a lowercase Docker network name of at most 63 characters' "$temporary/err"
  if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
    echo "unsafe edge control network name mutated Docker state: $unsafe_network" >&2
    exit 1
  fi
done

: >"$DOCKYARD_INSTALL_TEST_LOG"
rm -f "$DOCKYARD_INSTALL_TEST_STATE"
DOCKYARD_INSTALL_TEST_FLAP_ONCE=true DOCKYARD_INSTALL_STABILITY_SECONDS=3 \
  "$root/scripts/install-swarm.sh" | grep -q 'remained converged for 3s'
[ "$(cat "$DOCKYARD_INSTALL_TEST_STATE")" -ge 4 ] || {
  echo 'installer did not reset its stability window after replica loss' >&2
  exit 1
}

: >"$DOCKYARD_INSTALL_TEST_LOG"
if DOCKYARD_INSTALL_TEST_EXISTING_SECRETS='dockyard_master_key' "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'installer accepted an existing secret without explicit reuse' >&2
  exit 1
fi
grep -q 'DOCKYARD_REUSE_EXISTING_SECRETS=true' "$temporary/err"
if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'existing-secret failure mutated Docker state' >&2
  exit 1
fi

: >"$DOCKYARD_INSTALL_TEST_LOG"
DOCKYARD_INSTALL_TEST_EXISTING_SECRETS='dockyard_db_password dockyard_database_url dockyard_master_key dockyard_metrics_token' \
  DOCKYARD_REUSE_EXISTING_SECRETS=true \
  "$root/scripts/install-swarm.sh" >/dev/null
if grep -q '^secret create' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'installer recreated an explicitly reused secret' >&2
  exit 1
fi

: >"$DOCKYARD_INSTALL_TEST_LOG"
DOCKYARD_MASTER_KEY_SECRET='dockyard_master_key_v2' \
  "$root/scripts/install-swarm.sh" >/dev/null
grep -q "^secret inspect dockyard_master_key_v2$" "$DOCKYARD_INSTALL_TEST_LOG"
grep -q "^secret create dockyard_master_key_v2 $DOCKYARD_MASTER_KEY_FILE$" "$DOCKYARD_INSTALL_TEST_LOG"
if grep -q '^secret create dockyard_master_key ' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'installer created the legacy master-key secret during a versioned-key deployment' >&2
  exit 1
fi

: >"$DOCKYARD_INSTALL_TEST_LOG"
DOCKYARD_METRICS_TOKEN_SECRET='dockyard_metrics_token_v2' \
  "$root/scripts/install-swarm.sh" >/dev/null
grep -q "^secret inspect dockyard_metrics_token_v2$" "$DOCKYARD_INSTALL_TEST_LOG"
grep -q "^secret create dockyard_metrics_token_v2 $DOCKYARD_METRICS_TOKEN_FILE$" "$DOCKYARD_INSTALL_TEST_LOG"
if grep -q '^secret create dockyard_metrics_token ' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'installer created the legacy metrics-token secret during a versioned-token deployment' >&2
  exit 1
fi

: >"$DOCKYARD_INSTALL_TEST_LOG"
DOCKYARD_DB_PASSWORD_SECRET='dockyard_blue_db_password_v2' \
  DOCKYARD_DATABASE_URL_SECRET='dockyard_blue_database_url_v2' \
  "$root/scripts/install-swarm.sh" >/dev/null
grep -q "^secret inspect dockyard_blue_db_password_v2$" "$DOCKYARD_INSTALL_TEST_LOG"
grep -q "^secret create dockyard_blue_db_password_v2 $DOCKYARD_DB_PASSWORD_FILE$" "$DOCKYARD_INSTALL_TEST_LOG"
grep -q "^secret inspect dockyard_blue_database_url_v2$" "$DOCKYARD_INSTALL_TEST_LOG"
grep -q "^secret create dockyard_blue_database_url_v2 $DOCKYARD_DATABASE_URL_FILE$" "$DOCKYARD_INSTALL_TEST_LOG"
if grep -Eq '^secret create dockyard_(db_password|database_url) ' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'installer created default database secrets when versioned names were requested' >&2
  exit 1
fi

for unsafe_secret in '-leading' 'bad/name' 'bad secret' 'bad:secret'; do
  : >"$DOCKYARD_INSTALL_TEST_LOG"
  if DOCKYARD_MASTER_KEY_SECRET="$unsafe_secret" \
    "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
    echo "installer accepted unsafe master-key secret name: $unsafe_secret" >&2
    exit 1
  fi
  grep -q 'invalid DOCKYARD_MASTER_KEY_SECRET' "$temporary/err"
  if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
    echo "unsafe master-key secret name mutated Docker state: $unsafe_secret" >&2
    exit 1
  fi
done

for variable in DOCKYARD_DB_PASSWORD_SECRET DOCKYARD_DATABASE_URL_SECRET DOCKYARD_METRICS_TOKEN_SECRET; do
  : >"$DOCKYARD_INSTALL_TEST_LOG"
  if env "$variable=bad/secret" \
    "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
    echo "installer accepted unsafe database secret name in $variable" >&2
    exit 1
  fi
  grep -q "invalid $variable" "$temporary/err"
  if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
    echo "unsafe database secret name mutated Docker state: $variable" >&2
    exit 1
  fi
done

printf '%s' 'too-short' >"$temporary/secrets/metrics-token-invalid"
chmod 0600 "$temporary/secrets/metrics-token-invalid"
: >"$DOCKYARD_INSTALL_TEST_LOG"
if DOCKYARD_METRICS_TOKEN_FILE="$temporary/secrets/metrics-token-invalid" \
  "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'installer accepted a short metrics token' >&2
  exit 1
fi
grep -q 'DOCKYARD_METRICS_TOKEN_FILE must contain between 32 and 4096 bytes' "$temporary/err"
if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'invalid metrics token mutated Docker state' >&2
  exit 1
fi

: >"$DOCKYARD_INSTALL_TEST_LOG"
if DOCKYARD_DB_PASSWORD_SECRET='shared_database_secret' \
  DOCKYARD_DATABASE_URL_SECRET='shared_database_secret' \
  "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'installer accepted colliding Docker secret names' >&2
  exit 1
fi
grep -q 'Docker secret names must be distinct' "$temporary/err"
if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'colliding Docker secret names mutated Docker state' >&2
  exit 1
fi

: >"$DOCKYARD_INSTALL_TEST_LOG"
if DOCKYARD_INSTALL_TEST_FAIL_SECRET='dockyard_database_url' \
  "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'installer ignored a Docker secret creation failure' >&2
  exit 1
fi
grep -q '^secret rm dockyard_db_password$' "$DOCKYARD_INSTALL_TEST_LOG"
grep -q '^network rm dockyard-public$' "$DOCKYARD_INSTALL_TEST_LOG"
if grep -q '^stack deploy' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'installer deployed after a secret creation failure' >&2
  exit 1
fi

if DOCKYARD_IMAGE='example/dockyard:latest' "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'installer accepted a mutable controller image' >&2
  exit 1
fi
grep -q 'DOCKYARD_IMAGE must be an image reference pinned by sha256 digest' "$temporary/err"

: >"$DOCKYARD_INSTALL_TEST_LOG"
if DOCKYARD_INSTALL_TEST_UNAVAILABLE_IMAGE="$POSTGRES_IMAGE" "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'installer accepted an unavailable immutable image' >&2
  exit 1
fi
grep -q 'POSTGRES_IMAGE cannot be resolved from the configured registry' "$temporary/err"
if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'unavailable-image failure mutated Docker state' >&2
  exit 1
fi

if DOCKYARD_INSTALL_STABILITY_SECONDS=301 "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'installer accepted a stability window longer than its timeout' >&2
  exit 1
fi
grep -q 'DOCKYARD_INSTALL_STABILITY_SECONDS must not exceed' "$temporary/err"

if DOCKYARD_INSTALL_WAIT_TIMEOUT=1 \
  DOCKYARD_INSTALL_TEST_CONTROLLER_IMAGE="example/dockyard@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" \
  "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'installer accepted a rolled-back controller image' >&2
  exit 1
fi
grep -q 'dockyard_dockyard image is .* expected' "$temporary/err"

if DOCKYARD_INSTALL_WAIT_TIMEOUT=1 DOCKYARD_INSTALL_TEST_UPDATE_STATE=rollback_completed \
  "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'installer accepted a completed Swarm rollback' >&2
  exit 1
fi
grep -q 'dockyard_dockyard update state is rollback_completed' "$temporary/err"

for unsafe_host in 'dockyard.example.test`)||Host(`attacker.example.test' 'bad_label.example.test' '-leading.example.test' 'single-label'; do
  : >"$DOCKYARD_INSTALL_TEST_LOG"
  if DOCKYARD_HOST="$unsafe_host" "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
    echo "installer accepted unsafe hostname: $unsafe_host" >&2
    exit 1
  fi
  grep -q 'DOCKYARD_HOST must be a DNS hostname' "$temporary/err"
  if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
    echo "unsafe hostname mutated Docker state: $unsafe_host" >&2
    exit 1
  fi
done

for unsafe_email in 'ops@example.test,attacker@example.test' 'ops@bad_label.example.test' '.ops@example.test'; do
  : >"$DOCKYARD_INSTALL_TEST_LOG"
  if ACME_EMAIL="$unsafe_email" "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
    echo "installer accepted unsafe ACME email: $unsafe_email" >&2
    exit 1
  fi
  grep -q 'ACME_EMAIL must be a valid email address' "$temporary/err"
  if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
    echo "unsafe ACME email mutated Docker state: $unsafe_email" >&2
    exit 1
  fi
done

if DOCKYARD_INSTALL_MODE=ha "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'HA installer accepted a database URL without certificate verification' >&2
  exit 1
fi
grep -q 'sslmode=verify-full' "$temporary/err"

for ambiguous_database_url in \
  'postgres://dockyard:safe-value@database.example.test:5432/dockyard?sslmode=verify-full&sslmode=disable' \
  'postgres://dockyard:safe-value@database.example.test:5432/dockyard?sslmode=disable&sslmode=verify-full' \
  'postgres://dockyard:safe-value@database.example.test:5432/dockyard?sslmode=verify-full&sslmode=verify-full'; do
  printf '%s' "$ambiguous_database_url" >"$temporary/secrets/database-url-ambiguous"
  chmod 0600 "$temporary/secrets/database-url-ambiguous"
  : >"$DOCKYARD_INSTALL_TEST_LOG"
  if DOCKYARD_INSTALL_MODE=ha DOCKYARD_DATABASE_URL_FILE="$temporary/secrets/database-url-ambiguous" \
    "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
    echo 'HA installer accepted ambiguous sslmode parameters' >&2
    exit 1
  fi
  grep -q 'requires exactly one sslmode=verify-full parameter' "$temporary/err"
  if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
    echo 'ambiguous database TLS URL mutated Docker state' >&2
    exit 1
  fi
done

openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj '/CN=Dockyard Test CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$temporary/secrets/agent-ca.key" -out "$temporary/secrets/agent-ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj '/CN=agents.example.test' \
  -addext 'subjectAltName=DNS:agents.example.test' \
  -keyout "$temporary/secrets/agent-server.key" -out "$temporary/agent-server.csr" >/dev/null 2>&1
openssl x509 -req -days 30 -CA "$temporary/secrets/agent-ca.crt" -CAkey "$temporary/secrets/agent-ca.key" \
  -CAcreateserial -copy_extensions copy -in "$temporary/agent-server.csr" \
  -out "$temporary/secrets/agent-server.crt" >/dev/null 2>&1
printf '%s' 'postgres://dockyard:safe-value@database.example.test:5432/dockyard?sslmode=verify-full' >"$temporary/secrets/database-url-ha"
chmod 0600 "$temporary"/secrets/*
export DOCKYARD_DATABASE_URL_FILE="$temporary/secrets/database-url-ha"
export DOCKYARD_AGENT_HOST='agents.example.test'
export DOCKYARD_AGENT_CA_CERT_FILE="$temporary/secrets/agent-ca.crt"
export DOCKYARD_AGENT_CA_KEY_FILE="$temporary/secrets/agent-ca.key"
export DOCKYARD_AGENT_SERVER_CERT_FILE="$temporary/secrets/agent-server.crt"
export DOCKYARD_AGENT_SERVER_KEY_FILE="$temporary/secrets/agent-server.key"

: >"$DOCKYARD_INSTALL_TEST_LOG"
if DOCKYARD_INSTALL_MODE=ha DOCKYARD_INSTALL_DRY_RUN=true DOCKYARD_INSTALL_TEST_HA_MANAGER_COUNT=2 \
  "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'HA installer accepted fewer than three ready active managers' >&2
  exit 1
fi
grep -q 'requires at least three ready, active Swarm managers; found 2' "$temporary/err"
if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'insufficient-manager failure mutated Docker state' >&2
  exit 1
fi

: >"$DOCKYARD_INSTALL_TEST_LOG"
DOCKYARD_INSTALL_MODE=ha DOCKYARD_INSTALL_DRY_RUN=true "$root/scripts/install-swarm.sh" >/dev/null
grep -q '^node ls --filter role=manager --format {{.Status}} {{.Availability}}$' "$DOCKYARD_INSTALL_TEST_LOG"
grep -q "stack config -c $root/deploy/swarm.yml -c $root/deploy/swarm-ha.yml" "$DOCKYARD_INSTALL_TEST_LOG"
grep -q '^run --rm -i --network none --read-only --cap-drop ALL --security-opt no-new-privileges --entrypoint /usr/local/bin/dockyard .* validate-database-url --require-tls=true$' "$DOCKYARD_INSTALL_TEST_LOG"
for secret in dockyard_agent_ca_cert dockyard_agent_ca_key dockyard_agent_server_cert dockyard_agent_server_key; do
  grep -q "^secret inspect $secret$" "$DOCKYARD_INSTALL_TEST_LOG"
done

: >"$DOCKYARD_INSTALL_TEST_LOG"
DOCKYARD_INSTALL_MODE=ha DOCKYARD_INSTALL_EXTERNAL_DATABASE_DRIVERS=true DOCKYARD_INSTALL_DRY_RUN=true \
  "$root/scripts/install-swarm.sh" >/dev/null
grep -q "stack config -c $root/deploy/swarm.yml -c $root/deploy/swarm-ha.yml -c $root/deploy/swarm-database-drivers.yml" "$DOCKYARD_INSTALL_TEST_LOG"
grep -q ' inspect-database-drivers --directory /usr/local/lib/dockyard/database-drivers$' "$DOCKYARD_INSTALL_TEST_LOG"

openssl req -newkey rsa:2048 -nodes -subj '/CN=agents.example.test' \
  -addext 'subjectAltName=DNS:agents.example.test' \
  -addext 'extendedKeyUsage=clientAuth' \
  -keyout "$temporary/secrets/agent-client-only.key" -out "$temporary/agent-client-only.csr" >/dev/null 2>&1
openssl x509 -req -days 30 -CA "$temporary/secrets/agent-ca.crt" -CAkey "$temporary/secrets/agent-ca.key" \
  -set_serial 3 -copy_extensions copy -in "$temporary/agent-client-only.csr" \
  -out "$temporary/secrets/agent-client-only.crt" >/dev/null 2>&1
chmod 0600 "$temporary/secrets/agent-client-only.key" "$temporary/secrets/agent-client-only.crt"
: >"$DOCKYARD_INSTALL_TEST_LOG"
if DOCKYARD_INSTALL_MODE=ha DOCKYARD_INSTALL_DRY_RUN=true \
  DOCKYARD_AGENT_SERVER_CERT_FILE="$temporary/secrets/agent-client-only.crt" \
  DOCKYARD_AGENT_SERVER_KEY_FILE="$temporary/secrets/agent-client-only.key" \
  "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'HA installer accepted a client-only certificate for the agent TLS server' >&2
  exit 1
fi
grep -q 'agent server certificate verification failed against active and previous CAs for TLS server authentication' "$temporary/err"
if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'invalid agent server certificate purpose failure mutated Docker state' >&2
  exit 1
fi

openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj '/CN=Not A Certificate Authority' \
  -addext 'basicConstraints=critical,CA:FALSE' \
  -addext 'keyUsage=critical,digitalSignature' \
  -keyout "$temporary/secrets/agent-leaf.key" -out "$temporary/secrets/agent-leaf.crt" >/dev/null 2>&1
chmod 0600 "$temporary/secrets/agent-leaf.key" "$temporary/secrets/agent-leaf.crt"
: >"$DOCKYARD_INSTALL_TEST_LOG"
if DOCKYARD_INSTALL_MODE=ha DOCKYARD_INSTALL_DRY_RUN=true \
  DOCKYARD_AGENT_CA_CERT_FILE="$temporary/secrets/agent-leaf.crt" \
  DOCKYARD_AGENT_CA_KEY_FILE="$temporary/secrets/agent-leaf.key" \
  "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'HA installer accepted a leaf certificate as the active agent CA' >&2
  exit 1
fi
grep -q 'agent CA certificate must be a self-signed certificate authority permitted to sign certificates' "$temporary/err"
if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'invalid active agent CA failure mutated Docker state' >&2
  exit 1
fi

openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj '/CN=Dockyard Replacement CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$temporary/secrets/agent-ca-new.key" -out "$temporary/secrets/agent-ca-new.crt" >/dev/null 2>&1
chmod 0600 "$temporary/secrets/agent-ca-new.key" "$temporary/secrets/agent-ca-new.crt"
: >"$DOCKYARD_INSTALL_TEST_LOG"
DOCKYARD_INSTALL_MODE=ha DOCKYARD_INSTALL_DRY_RUN=true \
  DOCKYARD_AGENT_CA_CERT_FILE="$temporary/secrets/agent-ca-new.crt" \
  DOCKYARD_AGENT_CA_KEY_FILE="$temporary/secrets/agent-ca-new.key" \
  DOCKYARD_AGENT_PREVIOUS_CA_CERT_FILE="$temporary/secrets/agent-ca.crt" \
  DOCKYARD_AGENT_CA_CERT_SECRET='dockyard_agent_ca_cert_v2' \
  DOCKYARD_AGENT_CA_KEY_SECRET='dockyard_agent_ca_key_v2' \
  "$root/scripts/install-swarm.sh" >/dev/null
grep -q "stack config -c $root/deploy/swarm.yml -c $root/deploy/swarm-ha.yml -c $root/deploy/swarm-agent-ca-rollover.yml" "$DOCKYARD_INSTALL_TEST_LOG"
for secret in dockyard_agent_ca_cert_v2 dockyard_agent_ca_key_v2 dockyard_agent_previous_ca_cert; do
  grep -q "^secret inspect $secret$" "$DOCKYARD_INSTALL_TEST_LOG"
done

: >"$DOCKYARD_INSTALL_TEST_LOG"
if DOCKYARD_INSTALL_MODE=ha DOCKYARD_INSTALL_DRY_RUN=true \
  DOCKYARD_AGENT_PREVIOUS_CA_CERT_FILE="$temporary/secrets/agent-leaf.crt" \
  "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'HA installer accepted a leaf certificate as the previous agent CA' >&2
  exit 1
fi
grep -q 'previous agent CA certificate must be a self-signed certificate authority permitted to sign certificates' "$temporary/err"
if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'invalid previous agent CA failure mutated Docker state' >&2
  exit 1
fi

openssl x509 -req -days 1 -CA "$temporary/secrets/agent-ca.crt" -CAkey "$temporary/secrets/agent-ca.key" \
  -set_serial 2 -copy_extensions copy -in "$temporary/agent-server.csr" \
  -out "$temporary/secrets/agent-server-short.crt" >/dev/null 2>&1
chmod 0600 "$temporary/secrets/agent-server-short.crt"
: >"$DOCKYARD_INSTALL_TEST_LOG"
if DOCKYARD_INSTALL_MODE=ha DOCKYARD_INSTALL_DRY_RUN=true \
  DOCKYARD_AGENT_SERVER_CERT_FILE="$temporary/secrets/agent-server-short.crt" \
  "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'HA installer accepted a server certificate expiring within seven days' >&2
  exit 1
fi
grep -q 'agent server certificate must remain valid for at least 7 days' "$temporary/err"
if grep -Eq '^(network create|secret create|stack deploy)' "$DOCKYARD_INSTALL_TEST_LOG"; then
  echo 'near-expiry certificate failure mutated Docker state' >&2
  exit 1
fi

if DOCKYARD_INSTALL_MODE=ha DOCKYARD_INSTALL_DRY_RUN=true \
  DOCKYARD_AGENT_SERVER_KEY_FILE="$temporary/secrets/agent-ca.key" \
  "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'HA installer accepted a mismatched server key' >&2
  exit 1
fi
grep -q 'server certificate and private key do not match' "$temporary/err"

if DOCKYARD_INSTALL_MODE=ha DOCKYARD_INSTALL_DRY_RUN=true \
  DOCKYARD_AGENT_HOST='agents.example.test`)||Host(`attacker.example.test' \
  "$root/scripts/install-swarm.sh" >"$temporary/out" 2>"$temporary/err"; then
  echo 'HA installer accepted an unsafe agent hostname' >&2
  exit 1
fi
grep -q 'DOCKYARD_AGENT_HOST must be a DNS hostname' "$temporary/err"

printf '%s\n' 'Swarm installer preflight, mutation, reuse, and immutability checks passed.'
