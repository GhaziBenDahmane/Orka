#!/bin/sh
# Orka bootstrap installer. The default quick-start needs no configuration:
# it creates a single-node Swarm, runs Orka, and prints generated credentials.
set -eu

repository=${ORKA_INSTALL_REPOSITORY:-GhaziBenDahmane/Orka}
revision=${ORKA_INSTALL_REVISION:-master}
mode=${ORKA_INSTALL_MODE:-quickstart}
install_root=${ORKA_INSTALL_DIR:-/opt/orka}
http_bind=${ORKA_HTTP_BIND:-8080}
dashboard_domain=${ORKA_DOMAIN:-}
acme_email=${ORKA_ACME_EMAIL:-}

fail() {
  echo "orka-install: $*" >&2
  exit 1
}

usage() {
  cat >&2 <<'EOF'
Usage:
  curl -fsSL https://raw.githubusercontent.com/GhaziBenDahmane/Orka/master/install.sh | sh

The default quick-start asks for a dashboard domain and Let's Encrypt email,
installs Docker when needed, initializes a local Swarm, starts Orka behind TLS,
and creates an initial administrator automatically. It prompts for sudo when it
needs system privileges.

Advanced production installation:
  ORKA_INSTALL_MODE=production curl -fsSL .../install.sh | sh

Production mode delegates to scripts/install-swarm.sh and requires its
documented digest-pinned image and secret-file inputs. Set
ORKA_INSTALL_REVISION to an immutable release tag or commit when installing a
released build; master is intended only for evaluation.
EOF
}

owner=${repository%%/*}
name=${repository#*/}
[ "$owner" != "$repository" ] && [ -n "$owner" ] && [ -n "$name" ] || fail "ORKA_INSTALL_REPOSITORY must be an owner/repository pair"
case "$owner" in *[!A-Za-z0-9_.-]* ) fail "invalid ORKA_INSTALL_REPOSITORY" ;; esac
case "$name" in *[!A-Za-z0-9_.-]* ) fail "invalid ORKA_INSTALL_REPOSITORY" ;; esac
case "$revision" in ''|*'..'*|*[!A-Za-z0-9._/-]*|/* ) fail "invalid ORKA_INSTALL_REVISION" ;; esac
case "$mode" in quickstart|production ) ;; *) fail "ORKA_INSTALL_MODE must be quickstart or production" ;; esac
case "$install_root" in /* ) ;; *) fail "ORKA_INSTALL_DIR must be an absolute path" ;; esac
case "$install_root" in / ) fail "ORKA_INSTALL_DIR must not be /" ;; esac
case "$http_bind" in ''|*[!0-9]* ) fail "ORKA_HTTP_BIND must be a TCP port number" ;; esac
[ "$http_bind" -ge 1 ] && [ "$http_bind" -le 65535 ] || fail "ORKA_HTTP_BIND must be a TCP port number"

is_dns_hostname() {
  value=$1
  printf '%s\n' "$value" | awk '
    NR != 1 { exit 1 }
    length($0) < 3 || length($0) > 253 { exit 1 }
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

prompt_from_tty() {
  prompt=$1
  [ -r /dev/tty ] || fail "an interactive terminal is required; set ORKA_DOMAIN and ORKA_ACME_EMAIL instead"
  printf '%s' "$prompt" >/dev/tty
  IFS= read -r value </dev/tty || fail "could not read from terminal"
  printf '%s' "$value"
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  usage
  exit 0
fi
[ "$#" -eq 0 ] || { usage; exit 2; }

for command in awk cp curl cut find id mkdir mktemp openssl rm seq sleep tar tr; do
  command -v "$command" >/dev/null 2>&1 || fail "$command is required"
done

if [ "$mode" = quickstart ]; then
  if [ -z "$dashboard_domain" ]; then
    dashboard_domain=$(prompt_from_tty "Dashboard domain (for example orka.example.com): ")
  fi
  is_dns_hostname "$dashboard_domain" || fail "ORKA_DOMAIN must be a DNS hostname such as orka.example.com"
  if [ -z "$acme_email" ]; then
    acme_email=$(prompt_from_tty "Let's Encrypt email [$dashboard_domain]: ")
    [ -n "$acme_email" ] || acme_email="admin@$dashboard_domain"
  fi
  case "$acme_email" in *'@'*.* ) ;; *) fail "ORKA_ACME_EMAIL must be an email address" ;; esac
fi

# A default installation writes state under /opt and manages Docker. Re-run as
# root so curl | sh remains a one-command installation for a regular user.
if [ "$mode" = quickstart ] && [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null 2>&1 || fail "quick-start needs root privileges; rerun as root"
  bootstrap_url="https://raw.githubusercontent.com/$repository/$revision/install.sh"
  exec sudo env \
    "ORKA_INSTALL_REPOSITORY=$repository" \
    "ORKA_INSTALL_REVISION=$revision" \
    "ORKA_INSTALL_MODE=$mode" \
    "ORKA_INSTALL_DIR=$install_root" \
    "ORKA_HTTP_BIND=$http_bind" \
    "ORKA_DOMAIN=$dashboard_domain" \
    "ORKA_ACME_EMAIL=$acme_email" \
    sh -c "curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 '$bootstrap_url' | sh"
fi

temporary=$(mktemp -d "${TMPDIR:-/tmp}/orka-install.XXXXXX") || fail "could not create temporary directory"
cleanup() {
  status=${1:-$?}
  rm -rf -- "$temporary"
  trap - EXIT HUP INT TERM
  exit "$status"
}
trap cleanup EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM

archive="$temporary/orka.tar.gz"
url="https://codeload.github.com/$repository/tar.gz/$revision"
echo "Downloading Orka source revision $revision from $repository..." >&2
curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
  --output "$archive" "$url" || fail "could not download Orka source"
tar -xzf "$archive" -C "$temporary" || fail "downloaded source archive is invalid"

source_directory=$(find "$temporary" -mindepth 1 -maxdepth 1 -type d -name 'Orka-*' -print -quit)
[ -n "$source_directory" ] || fail "downloaded archive does not contain an Orka source directory"
[ -f "$source_directory/scripts/install-swarm.sh" ] || fail "downloaded source does not contain the Swarm installer"

if [ "$mode" = production ]; then
  echo "Starting Orka production Swarm installation..." >&2
  sh "$source_directory/scripts/install-swarm.sh"
  exit 0
fi

install_docker() {
  command -v docker >/dev/null 2>&1 && return 0
  echo "Docker is not installed; installing Docker Engine..." >&2
  command -v apt-get >/dev/null 2>&1 || fail "Docker is not installed and automatic installation is currently supported only on Debian/Ubuntu; install Docker Engine and rerun"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y ca-certificates curl docker.io docker-compose-v2 || \
    apt-get install -y ca-certificates curl docker.io docker-compose-plugin
}

install_docker
docker info >/dev/null 2>&1 || fail "Docker daemon is not available"
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required"

if [ "$(docker info --format '{{.Swarm.LocalNodeState}}')" != active ]; then
  echo "Initializing a single-node Docker Swarm..." >&2
  docker swarm init >/dev/null
fi
if ! docker network inspect dockyard-public >/dev/null 2>&1; then
  docker network create --driver overlay --attachable --opt encrypted --subnet 10.255.250.0/24 dockyard-public >/dev/null
fi
if ! docker network inspect orka-edge-control >/dev/null 2>&1; then
  docker network create --driver overlay --attachable --opt encrypted --subnet 10.255.251.0/24 orka-edge-control >/dev/null
fi
edge_subnet=$(docker network inspect orka-edge-control --format '{{(index .IPAM.Config 0).Subnet}}')
case "$edge_subnet" in */* ) ;; *) fail "could not determine Orka edge-control network subnet" ;; esac

mkdir -p "$install_root"
cp -R "$source_directory/." "$install_root/"
umask 077
mkdir -p "$install_root/data/backups"

echo "Building and starting Orka..." >&2
DOCKYARD_HTTP_BIND="127.0.0.1:$http_bind" \
DOCKYARD_POSTGRES_BIND=127.0.0.1:54329 \
ORKA_DOMAIN="$dashboard_domain" \
ORKA_ACME_EMAIL="$acme_email" \
ORKA_TRUSTED_PROXY_CIDR="$edge_subnet" \
  docker compose --project-directory "$install_root" --project-name orka -f "$install_root/compose.yml" -f "$install_root/compose.quickstart-domain.yml" up --build --detach

base_url="http://127.0.0.1:$http_bind"
ready=false
for _ in $(seq 1 90); do
  if curl --fail --silent "$base_url/readyz" >/dev/null 2>&1; then ready=true; break; fi
  sleep 2
done
[ "$ready" = true ] || fail "Orka did not become ready; inspect with: docker compose --project-name orka -f $install_root/compose.yml logs"

credentials_file="$install_root/INITIAL_ADMIN.txt"
if [ ! -f "$credentials_file" ]; then
  admin_password=$(openssl rand -base64 48 | tr -d '\r\n' | tr '+/' '-_' | cut -c1-32)
  bootstrap_code=$(curl --silent --show-error --output "$temporary/bootstrap.json" --write-out '%{http_code}' \
    --header 'Content-Type: application/json' \
    --data "{\"email\":\"admin@orka.local\",\"password\":\"$admin_password\",\"organization\":\"Default\"}" \
    "$base_url/v1/auth/bootstrap" || true)
  case "$bootstrap_code" in
    200|201)
      {
        echo "Orka initial administrator"
        echo "URL: https://$dashboard_domain"
        echo "Email: admin@orka.local"
        echo "Password: $admin_password"
        echo "Change this password after first sign-in."
      } >"$credentials_file"
      ;;
    409) ;;
    *) fail "could not bootstrap the initial administrator (HTTP $bootstrap_code)" ;;
  esac
fi

echo >&2
echo "Orka is running at https://$dashboard_domain" >&2
echo "Point DNS for $dashboard_domain to this server and allow inbound TCP ports 80 and 443." >&2
if [ -f "$credentials_file" ]; then
  cat "$credentials_file" >&2
else
  echo "An existing Orka administrator was retained." >&2
fi
echo "Installation directory: $install_root" >&2
