.PHONY: test test-database-recovery test-install test-keycloak-sso test-keycloak-oidc test-swarm-ha test-templates test-release-soak test-release-upgrade lint build run web generate-openapi check-openapi check-alerts check-licenses check-release-images

test:
	go test ./...

test-database-recovery:
	DOCKYARD_TEST_DATABASE_RECOVERY=1 go test -timeout 35m -run TestNativeDatabaseRecoveryConformance -v -count=1 ./internal/database

test-install:
	./scripts/ci/test-install-swarm.sh
	./scripts/ci/test-install-agent.sh

test-keycloak-sso:
	./scripts/ci/test-keycloak-oidc.sh

# Backward-compatible alias for the original OIDC-only target.
test-keycloak-oidc: test-keycloak-sso

test-swarm-ha:
	./scripts/ci/test-swarm-ha.sh

test-templates:
	./scripts/ci/smoke-templates.sh

test-release-upgrade:
	@test -n "$${DOCKYARD_PREVIOUS_IMAGE:-}" || { echo "DOCKYARD_PREVIOUS_IMAGE must be an immutable image digest" >&2; exit 1; }
	@test -n "$${DOCKYARD_CANDIDATE_IMAGE:-}" || { echo "DOCKYARD_CANDIDATE_IMAGE must name a locally available candidate image" >&2; exit 1; }
	./scripts/ci/test-release-upgrade.sh

test-release-soak:
	@test -n "$${DOCKYARD_IMAGE:-}" || { echo "DOCKYARD_IMAGE must be an immutable image digest" >&2; exit 1; }
	./scripts/ci/test-release-soak.sh

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

check-alerts:
	docker run --rm --entrypoint promtool -v "$(CURDIR):/repo:ro" prom/prometheus@sha256:63805ebb8d2b3920190daf1cb14a60871b16fd38bed42b857a3182bc621f4996 check rules /repo/deploy/prometheus-alerts.yml

check-licenses:
	./scripts/ci/check-licenses.sh

check-release-images:
	./scripts/ci/check-image-digests.sh build
	./scripts/ci/check-image-digests.sh controller
