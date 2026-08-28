.PHONY: test lint build run generate-openapi check-openapi

test:
	go test ./...

lint:
	go vet ./...

build:
	go build -o bin/dockyard ./cmd/dockyard
	go build -o bin/dockyardctl ./cmd/dockyardctl

run:
	go run ./cmd/dockyard serve

generate-openapi:
	go run ./tools/generate-openapi

check-openapi: generate-openapi
	git diff --exit-code -- api/openapi.yaml
