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

## License

Apache-2.0. This project is an independent implementation and does not include
Dokploy proprietary source code.
