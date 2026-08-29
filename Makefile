.PHONY: test test-database-recovery test-install test-keycloak-oidc test-swarm-ha test-templates lint build run web generate-openapi check-openapi check-release-images

test:
	go test ./...

test-database-recovery:
	DOCKYARD_TEST_DATABASE_RECOVERY=1 go test -timeout 35m -run TestNativeDatabaseRecoveryConformance -v -count=1 ./internal/database

test-install:
	./scripts/ci/test-install-swarm.sh
	./scripts/ci/test-install-agent.sh

test-keycloak-oidc:
	./scripts/ci/test-keycloak-oidc.sh

test-swarm-ha:
	./scripts/ci/test-swarm-ha.sh

test-templates:
	./scripts/ci/smoke-templates.sh

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
	./scripts/ci/check-image-digests.sh build
	./scripts/ci/check-image-digests.sh controller
