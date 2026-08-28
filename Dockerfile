# syntax=docker/dockerfile:1.7
FROM golang:1.26-alpine@sha256:28d89ee9cc0ff9fec75c82ca201e6bf7fdf9a679d4b7b24dfa04f2bb766bb468 AS build
ARG VERSION=dev
ARG TARGETARCH
ARG NIXPACKS_VERSION=v1.41.0
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=secret,id=build_ca,required=false \
    if [ -s /run/secrets/build_ca ]; then \
      SSL_CERT_FILE=/run/secrets/build_ca go mod download; \
    else \
      go mod download; \
    fi
COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/dockyard ./cmd/dockyard \
    && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/dockyardctl ./cmd/dockyardctl
RUN --mount=type=secret,id=build_ca,required=false \
    case "$TARGETARCH" in \
      amd64) artifact=x86_64-unknown-linux-musl; checksum=0f55de7874507b9cf7502113120bd96f2ab6979f78d10eaf2eb2ade9207b3af6 ;; \
      arm64) artifact=aarch64-unknown-linux-musl; checksum=912bd02dd2bb6f9c3a9ed965fe8a68b4aa318dc7a2546e2eca6f2806a894ba39 ;; \
      *) echo "unsupported Nixpacks architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && url="https://github.com/railwayapp/nixpacks/releases/download/${NIXPACKS_VERSION}/nixpacks-${NIXPACKS_VERSION}-${artifact}.tar.gz" \
    && if [ -s /run/secrets/build_ca ]; then SSL_CERT_FILE=/run/secrets/build_ca wget -qO /tmp/nixpacks.tar.gz "$url"; else wget -qO /tmp/nixpacks.tar.gz "$url"; fi \
    && echo "$checksum  /tmp/nixpacks.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/nixpacks.tar.gz -C /out \
    && chmod 0755 /out/nixpacks \
    && rm /tmp/nixpacks.tar.gz

FROM docker:29-cli@sha256:000bb62ff495f986c9f5578eb67cc2cb98b91138eda81d7762d5371eb8a497fe
RUN command -v git >/dev/null && test -s /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/dockyard /usr/local/bin/dockyard
COPY --from=build /out/dockyardctl /usr/local/bin/dockyardctl
COPY --from=build /out/nixpacks /usr/local/bin/nixpacks
ENTRYPOINT ["dockyard"]
CMD ["serve"]
