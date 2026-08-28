.PHONY: test lint build run

test:
	go test ./...

lint:
	go vet ./...

build:
	go build -o bin/dockyard ./cmd/dockyard

run:
	go run ./cmd/dockyard serve
