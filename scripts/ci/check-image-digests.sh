#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
validator="$root/scripts/ci/validate-image-reference.sh"

mode=${1:-controller}
if [ "$mode" = "build" ]; then
  dockerfile=${DOCKYARD_DOCKERFILE:-Dockerfile}
  images=$(awk 'toupper($1)=="FROM" { print $2 }' "$dockerfile")
  if [ -z "$images" ]; then
    echo "$dockerfile contains no base images" >&2
    exit 1
  fi
  for image in $images; do
    if ! "$validator" "$image"; then
      echo "$dockerfile base image must be pinned by sha256 digest: $image" >&2
      exit 1
    fi
  done
  exit 0
fi

variables="DOCKYARD_IMAGE"
if [ "$mode" = "controller" ]; then
  variables="$variables POSTGRES_IMAGE TRAEFIK_IMAGE"
elif [ "$mode" = "ai" ]; then
  variables="$variables NINEROUTER_IMAGE HEADROOM_IMAGE"
elif [ "$mode" != "agent" ]; then
  echo "usage: $0 [build|controller|agent|ai]" >&2
  exit 2
fi

for variable in $variables; do
  value=$(printenv "$variable" || true)
  if ! "$validator" "$value"; then
    echo "$variable must be an image reference pinned by sha256 digest" >&2
    exit 1
  fi
done
