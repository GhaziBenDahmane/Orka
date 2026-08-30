#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
validator="$root/scripts/ci/validate-image-reference.sh"
digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

for image in \
  "postgres@sha256:$digest" \
  "docker.io/library/postgres:17-alpine@sha256:$digest" \
  "ghcr.io/acme/my_app:v1@sha256:$digest" \
  "registry.example.test:5000/team/my--app@sha256:$digest" \
  "[2001:db8::1]:5000/team/app@sha256:$digest"
do
  "$validator" "$image" || { echo "valid image rejected: $image" >&2; exit 1; }
done

for image in \
  "postgres" \
  "postgres:17@sha256:short" \
  "postgres@sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
  "ghcr.io//app@sha256:$digest" \
  "ghcr.io/Acme/app@sha256:$digest" \
  "registry.example.test:0/team/app@sha256:$digest" \
  "registry.example.test:65536/team/app@sha256:$digest" \
  "bad_label.example.test/team/app@sha256:$digest" \
  "[2001:::1]:5000/team/app@sha256:$digest" \
  "[2001:db8:1]:5000/team/app@sha256:$digest" \
  "team/../app@sha256:$digest" \
  "app:bad/tag@sha256:$digest" \
  "app@sha256:${digest}@sha256:${digest}"
do
  if "$validator" "$image"; then
    echo "invalid image accepted: $image" >&2
    exit 1
  fi
done
