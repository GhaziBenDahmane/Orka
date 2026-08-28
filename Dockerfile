# syntax=docker/dockerfile:1.7
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/dockyard ./cmd/dockyard

FROM docker:29-cli
RUN apk add --no-cache ca-certificates tzdata git
COPY --from=build /out/dockyard /usr/local/bin/dockyard
ENTRYPOINT ["dockyard"]
CMD ["serve"]
