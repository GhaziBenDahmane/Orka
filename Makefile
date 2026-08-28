.PHONY: test lint build run web generate-openapi check-openapi check-release-images

test:
	go test ./...

lint:
	go vet ./...

build:
	go build -o bin/dockyard ./cmd/dockyard
	go build -o bin/dockyardctl ./cmd/dockyardctl
	go build -o bin/terraform-provider-dockyard ./cmd/terraform-provider-dockyard

web:
	cd web && npm ci && npm run build

run:
	go run ./cmd/dockyard serve

generate-openapi:
	go run ./tools/generate-openapi

check-openapi: generate-openapi
	git diff --exit-code -- api/openapi.yaml

check-release-images:
	./scripts/ci/check-image-digests.sh controller
