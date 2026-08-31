# syntax=docker/dockerfile:1.7
FROM golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS build
ARG VERSION=dev
ARG REVISION=unknown
ARG TARGETARCH
ARG NIXPACKS_VERSION=v1.41.0
ARG RAILPACK_VERSION=v0.38.0
ARG PACK_VERSION=v0.40.9
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=secret,id=goproxy,required=false \
    --mount=type=secret,id=build_ca,required=false \
    if [ -s /run/secrets/goproxy ]; then export GOPROXY="$(cat /run/secrets/goproxy)"; fi; \
    if [ -s /run/secrets/build_ca ]; then export SSL_CERT_FILE=/run/secrets/build_ca; fi; \
    go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=secret,id=goproxy,required=false \
    --mount=type=secret,id=build_ca,required=false \
    if [ -s /run/secrets/goproxy ]; then export GOPROXY="$(cat /run/secrets/goproxy)"; fi; \
    if [ -s /run/secrets/build_ca ]; then export SSL_CERT_FILE=/run/secrets/build_ca; fi; \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/dockyard ./cmd/dockyard \
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
RUN --mount=type=secret,id=build_ca,required=false \
    case "$TARGETARCH" in \
      amd64) artifact=x86_64-unknown-linux-musl; checksum=7c3f0e70ca8bf80bde87e8c30cb0171414c2b6bbd794d6f60a19cc3b71772950 ;; \
      arm64) artifact=arm64-unknown-linux-musl; checksum=d33716e87f0e39314898746c806e26d9edde890ac65156891b2f06c8d07ba8c4 ;; \
      *) echo "unsupported Railpack architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && url="https://github.com/railwayapp/railpack/releases/download/${RAILPACK_VERSION}/railpack-${RAILPACK_VERSION}-${artifact}.tar.gz" \
    && if [ -s /run/secrets/build_ca ]; then SSL_CERT_FILE=/run/secrets/build_ca wget -qO /tmp/railpack.tar.gz "$url"; else wget -qO /tmp/railpack.tar.gz "$url"; fi \
    && echo "$checksum  /tmp/railpack.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/railpack.tar.gz -C /out \
    && chmod 0755 /out/railpack \
    && rm /tmp/railpack.tar.gz
RUN --mount=type=secret,id=build_ca,required=false \
    case "$TARGETARCH" in \
      amd64) artifact=linux; checksum=dc0ee1e931cf8a106d7555a01a214864f9acb60b77adf15d69b74df4404758e9 ;; \
      arm64) artifact=linux-arm64; checksum=091ccb213823656c727731537ef8f1000eb4dc3ec61641506653e7f9d6da0c5e ;; \
      *) echo "unsupported pack architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && url="https://github.com/buildpacks/pack/releases/download/${PACK_VERSION}/pack-${PACK_VERSION}-${artifact}.tgz" \
    && if [ -s /run/secrets/build_ca ]; then SSL_CERT_FILE=/run/secrets/build_ca wget -qO /tmp/pack.tgz "$url"; else wget -qO /tmp/pack.tgz "$url"; fi \
    && echo "$checksum  /tmp/pack.tgz" | sha256sum -c - \
    && tar -xzf /tmp/pack.tgz -C /out \
    && chmod 0755 /out/pack \
    && rm /tmp/pack.tgz

FROM docker:29-cli@sha256:000bb62ff495f986c9f5578eb67cc2cb98b91138eda81d7762d5371eb8a497fe
RUN command -v git >/dev/null && test -s /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/dockyard /usr/local/bin/dockyard
COPY --from=build /out/dockyardctl /usr/local/bin/dockyardctl
COPY --from=build /out/nixpacks /usr/local/bin/nixpacks
COPY --from=build /out/railpack /usr/local/bin/railpack
COPY --from=build /out/pack /usr/local/bin/pack
ENTRYPOINT ["dockyard"]
CMD ["serve"]
