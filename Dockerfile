# syntax=docker/dockerfile:1.7
FROM golang:1.26-alpine AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/dockyard ./cmd/dockyard \
    && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/dockyardctl ./cmd/dockyardctl

FROM docker:29-cli
RUN apk add --no-cache ca-certificates tzdata git
COPY --from=build /out/dockyard /usr/local/bin/dockyard
COPY --from=build /out/dockyardctl /usr/local/bin/dockyardctl
ENTRYPOINT ["dockyard"]
CMD ["serve"]
