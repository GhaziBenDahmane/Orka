# Dockyard

Dockyard is a Go control plane for deploying Docker Compose applications and
managed data services to Docker Swarm. It is designed as a clean-room,
open-source alternative to Dokploy's control plane.

The initial implementation includes:

- organization-scoped users, sessions, and role-based access;
- projects, environments, Compose services, routes, and deployment history;
- durable PostgreSQL jobs with leases, heartbeats, cancellation, and stale-worker recovery;
- Docker Swarm stack deployment and rollback;
- Traefik label and overlay-network generation;
- a versioned template catalog with Dokploy template import support;
- extensible managed-database drivers;
- OIDC/PKCE and signed SAML 2.0 login, mandatory SSO, session controls, service accounts, SCIM users/groups, and group-to-role mapping;
- public or authenticated Git/Dockerfile builds pushed to authenticated OCI registries;
- signed GitHub, GitLab, Gitea, and Bitbucket push-to-deploy webhooks;
- checksummed database backups with confirmed restore, scheduling, retention, and S3-compatible storage;
- encrypted secrets and an audit trail.
- request correlation, optional OTLP tracing, and Prometheus operational metrics.
- inherited organization/project/environment maintenance controls and resource quotas.
- an embedded React console for core project, workload, template, database, and cluster workflows.

See [docs/architecture.md](docs/architecture.md) and
[docs/roadmap.md](docs/roadmap.md). The detailed clean-room comparison, effort
estimate, delivery order, and release gates are in
[docs/product-plan.md](docs/product-plan.md).

## Development

```sh
cp .env.example .env
docker compose up -d postgres
set -a; . ./.env; set +a
go run ./cmd/dockyard serve
```

The console is available at `http://localhost:8080/`. Its production assets are
embedded in the Go binary. Run `make web` after changing files under `web/`.

Import the complete upstream Dokploy template checkout with:

```sh
go run ./cmd/dockyard import-dokploy-templates /path/to/dokploy-templates
```

For an idempotent control-plane migration, including a mandatory dry-run and
encrypted environment re-keying, see
[docs/migrating-from-dokploy.md](docs/migrating-from-dokploy.md).

Bootstrap the first administrator:

```sh
curl -X POST http://localhost:8080/v1/auth/bootstrap \
  -H 'content-type: application/json' \
  -d '{"email":"admin@example.com","password":"change-me-now","organization":"Default"}'
```

Every HTTP response includes `X-Request-ID`; callers may supply their own
printable value. `GET /metrics` exposes bounded-route HTTP latency/status,
background-operation duration/status, queue and lease health, deployment
state, and backup/restore state and age. Set
`DOCKYARD_OTEL_EXPORTER_OTLP_ENDPOINT` to an OTLP/gRPC URL (for example,
`http://otel-collector:4317`) to export traces. TLS is the default; set
`DOCKYARD_OTEL_EXPORTER_OTLP_INSECURE=true` only for a trusted plaintext
collector endpoint.

## CLI

Build `dockyardctl` with `make build` or use the copy included in the controller
image. Login reads the password from standard input and stores the returned
token in a mode-0600 user configuration file:

```sh
printf '%s\n' "$DOCKYARD_PASSWORD" | \
  dockyardctl --url https://dockyard.example.com login admin@example.com
dockyardctl projects
dockyardctl create-environment PROJECT_ID '{"name":"Production","clusterId":null}'
dockyardctl deploy SERVICE_ID
```

Core project, environment, service, database, template, deployment, log, and
cluster operations have short commands. `dockyardctl request METHOD /v1/path
'{"json":"body"}'` exposes the remaining API without waiting for a new CLI
release. Environment variables `DOCKYARD_URL`, `DOCKYARD_TOKEN`, and
`DOCKYARD_ORGANIZATION_ID` override saved configuration.

## Terraform / OpenTofu

`terraform-provider-dockyard` manages projects, environments, and Compose
services, including waiting for asynchronous Swarm cleanup during destroy. See
[docs/terraform.md](docs/terraform.md) and [examples/terraform/main.tf](examples/terraform/main.tf).

## License

Apache-2.0. This project is an independent implementation and does not include
Dokploy proprietary source code.
