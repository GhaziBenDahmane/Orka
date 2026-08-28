#!/bin/sh
set -eu

mode=${1:-controller}
variables="DOCKYARD_IMAGE"
if [ "$mode" = "controller" ]; then
  variables="$variables POSTGRES_IMAGE TRAEFIK_IMAGE"
elif [ "$mode" != "agent" ]; then
  echo "usage: $0 [controller|agent]" >&2
  exit 2
fi

for variable in $variables; do
  value=$(printenv "$variable" || true)
  if ! printf '%s\n' "$value" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[a-f0-9]{64}$'; then
    echo "$variable must be an image reference pinned by sha256 digest" >&2
    exit 1
  fi
done
