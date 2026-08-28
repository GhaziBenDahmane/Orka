.PHONY: test lint build run

test:
	go test ./...

lint:
	go vet ./...

build:
	go build -o bin/dockyard ./cmd/dockyard
	go build -o bin/dockyardctl ./cmd/dockyardctl

run:
	go run ./cmd/dockyard serve
