# syntax=docker/dockerfile:1.7
FROM golang:1.26-alpine@sha256:28d89ee9cc0ff9fec75c82ca201e6bf7fdf9a679d4b7b24dfa04f2bb766bb468 AS build
ARG VERSION=dev
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

FROM docker:29-cli@sha256:000bb62ff495f986c9f5578eb67cc2cb98b91138eda81d7762d5371eb8a497fe
RUN command -v git >/dev/null && test -s /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/dockyard /usr/local/bin/dockyard
COPY --from=build /out/dockyardctl /usr/local/bin/dockyardctl
ENTRYPOINT ["dockyard"]
CMD ["serve"]
