#!/bin/sh
# Orka's pipe-friendly installer. It deliberately delegates all Docker and
# secret validation to scripts/install-swarm.sh from the selected source tree.
set -eu

repository=${ORKA_INSTALL_REPOSITORY:-GhaziBenDahmane/Orka}
revision=${ORKA_INSTALL_REVISION:-master}

fail() {
  echo "orka-install: $*" >&2
  exit 1
}

usage() {
  cat >&2 <<'EOF'
Usage:
  curl -fsSL https://raw.githubusercontent.com/GhaziBenDahmane/Orka/master/install.sh | sh

The command downloads the requested Orka source revision and runs its Swarm
installer. Configure the installer through environment variables, including
DOCKYARD_HOST, ACME_EMAIL, DOCKYARD_IMAGE, POSTGRES_IMAGE, TRAEFIK_IMAGE and
the four DOCKYARD_*_FILE secret paths. Use ORKA_INSTALL_REVISION to select an
immutable release tag or commit; master is intended only for evaluation.
EOF
}

owner=${repository%%/*}
name=${repository#*/}
[ "$owner" != "$repository" ] && [ -n "$owner" ] && [ -n "$name" ] || fail "ORKA_INSTALL_REPOSITORY must be an owner/repository pair"
case "$owner" in *[!A-Za-z0-9_.-]* ) fail "invalid ORKA_INSTALL_REPOSITORY" ;; esac
case "$name" in *[!A-Za-z0-9_.-]* ) fail "invalid ORKA_INSTALL_REPOSITORY" ;; esac
case "$revision" in
  ''|*'..'*|*[!A-Za-z0-9._/-]*|/* ) fail "invalid ORKA_INSTALL_REVISION" ;;
esac

for command in curl find tar mktemp rm; do
  command -v "$command" >/dev/null 2>&1 || fail "$command is required"
done

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  usage
  exit 0
fi
[ "$#" -eq 0 ] || { usage; exit 2; }

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

echo "Starting Orka Swarm installation..." >&2
sh "$source_directory/scripts/install-swarm.sh"
