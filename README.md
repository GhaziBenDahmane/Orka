# Dockyard

Dockyard is a Go control plane for deploying Docker Compose applications and
managed data services to Docker Swarm. It is designed as a clean-room,
open-source alternative to Dokploy's control plane.

The initial implementation includes:

- organization-scoped users, sessions, and role-based access;
- projects, environments, Compose services, routes, and deployment history;
- durable PostgreSQL jobs with leases, heartbeats, cancellation, and stale-worker recovery;
- an external-PostgreSQL, three-controller Swarm profile with fenced workers and mandatory remote backups;
- Docker Swarm stack deployment, rollback, and leader-elected drift repair;
- Traefik label and overlay-network generation, with encrypted custom TLS
  certificates reconciled through versioned Swarm secrets locally or by agent;
- a versioned template catalog with Dokploy template import support;
- multiple GitHub template repositories with namespaced Dokploy-compatible Compose catalogs;
- startup-seeded PostgreSQL, Redis, 9Router, and BarkTrace SQLite/PostgreSQL
  templates, plus a public [template request form](https://github.com/GhaziBenDahmane/Orka/issues/new?template=template-request.yml);
- ten built-in managed databases plus a versioned external driver protocol and Go SDK;
- OIDC/PKCE and signed SAML 2.0 login, mandatory SSO, session controls, service accounts, SCIM users/groups, and group-to-role mapping;
- public or authenticated HTTPS/SSH Git builds and encrypted, hardened ZIP uploads, pushed to authenticated OCI registries;
- Dockerfile, static, Nixpacks, Railpack, Paketo, Heroku 24, and custom digest-pinned Cloud Native Buildpack builders;
- signed GitHub, GitLab, Gitea, and Bitbucket push-to-deploy webhooks with durable commit-status callbacks;
- checksummed database backups with confirmed restore, scheduling, retention, and S3-compatible storage;
- encrypted secrets, a queryable audit trail, and hash-chained S3 Object Lock archives.
- request correlation, optional OTLP tracing, and Prometheus operational metrics.
- durable signed webhooks, Slack-compatible notifications, TLS SMTP email, PagerDuty, and Opsgenie alerts.
- inherited organization/project/environment maintenance controls and resource quotas.
- an embedded React console for core project, workload, template, database, and cluster workflows.
- isolated, read-only AI audit agents with structured findings and optional 9Router model routing.

See [docs/architecture.md](docs/architecture.md) and
[docs/roadmap.md](docs/roadmap.md). The detailed clean-room comparison, effort
estimate, delivery order, and release gates are in
[docs/product-plan.md](docs/product-plan.md).
AI deployment and trust boundaries are documented in
[docs/ai-auditing.md](docs/ai-auditing.md); remote catalog layout is in
[docs/template-repositories.md](docs/template-repositories.md), and provider
setup plus release evidence requirements are in
[docs/sso-provider-conformance.md](docs/sso-provider-conformance.md). The
production trust boundaries, attacker model, and residual release risks are in
[docs/threat-model.md](docs/threat-model.md); the protected external-gate
attestation format and stable-promotion procedure are in
[docs/production-certification.md](docs/production-certification.md).

## Installation

Production deployments use immutable image digests and Docker Swarm. The
non-interactive installer validates the manager, images, secret files, and
rendered stack before changing Docker state, and supports both single-manager
and HA controller profiles. A companion installer performs the same checks for
outbound remote-cluster agents. See [deploy/README.md](deploy/README.md) for
the preflight, installation, upgrade, backup, and recovery procedures.

## Development

```sh
cp .env.example .env
docker compose up -d postgres
set -a; . ./.env; set +a
go run ./cmd/dockyard serve
```

Behind a TLS-inspecting corporate proxy, pass a PEM trust bundle containing
its root certificate to container builds without adding it to the runtime
image:

```sh
docker build --secret id=build_ca,src=/path/to/corporate-ca.crt .
```

If the public Go module proxy is blocked, pass an internal proxy URL as a
BuildKit secret as well; neither value is retained in the image or build
history:

```sh
DOCKYARD_GOPROXY=https://proxy.example.com \
  docker build --secret id=goproxy,env=DOCKYARD_GOPROXY \
  --secret id=build_ca,src=/path/to/corporate-ca.crt .
```

The console is available at `http://localhost:8080/`. Its production assets are
embedded in the Go binary. Every interactive user can inspect active device
sessions, revoke individual or all other sessions, and rotate a local password
from the Account page. Users can also enroll a TOTP authenticator, save
one-time recovery codes, replace those codes, and disable MFA. Password and MFA
changes preserve the current session and atomically revoke every other session
for that identity.
Run `make web` after changing files under `web/`.

Run `make test-templates` to start an isolated controller and instantiate the
built-in 9Router, PostgreSQL, Redis, BarkTrace SQLite, and BarkTrace PostgreSQL
products through the API. The test deploys them to Docker Swarm, verifies
replica convergence and immutable image resolution, then forces task
replacement. Stateful products additionally prove application data survives;
9Router only has its deployment lifecycle tested and requires no provider
credentials. For a bounded local run, set `DOCKYARD_TEMPLATE_SMOKE_TEMPLATES`
to a space-separated subset, for example
`barktrace-sqlite barktrace-postgres`; release CI leaves it unset and always
executes the complete five-product gate.

Import the complete upstream Dokploy template checkout with:

```sh
openssl genpkey -algorithm ED25519 -out catalog-signing-key.pem
openssl pkey -in catalog-signing-key.pem -pubout -out catalog-public-key.pem
go run ./cmd/dockyard sign-template-catalog --private-key-file catalog-signing-key.pem /path/to/dokploy-templates
go run ./cmd/dockyard import-dokploy-templates --public-key-file catalog-public-key.pem /path/to/dokploy-templates
```

Unsigned imports require the explicit `--allow-unsigned` development override.
Keep the signing key offline and distribute only the public key.

For an idempotent control-plane migration, including a mandatory dry-run and
encrypted environment re-keying, see
[docs/migrating-from-dokploy.md](docs/migrating-from-dokploy.md).
The same guide covers durable native PostgreSQL, MySQL, MariaDB, MongoDB,
Redis, and libSQL data transfers after the imported target stacks are deployed.

Bootstrap the first administrator:

```sh
curl -X POST http://localhost:8080/v1/auth/bootstrap \
  -H 'content-type: application/json' \
  -d '{"email":"admin@example.com","password":"change-me-now","organization":"Default"}'
```

Every HTTP response includes `X-Request-ID`; callers may supply their own
printable value. `GET /metrics` exposes bounded-route HTTP latency/status,
background-operation duration/status, queue and lease health, deployment
state, edge-TLS expiry/reconciliation, and backup/restore state and age. It requires the dedicated fleet
operator bearer credential in `DOCKYARD_METRICS_TOKEN`, not a tenant session.
Set
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
dockyardctl stop SERVICE_ID
dockyardctl start SERVICE_ID
dockyardctl move-service SERVICE_ID TARGET_ENVIRONMENT_ID
# After a successful stop and an operator-managed volume copy:
dockyardctl rebind-service-storage-node SERVICE_ID TARGET_NODE_ID SERVICE_SLUG
# Or restore each retained backup onto the rebound node before starting:
dockyardctl restore-volume-offline BACKUP_ID SERVICE_SLUG
```

Core project, environment, service, database, template, deployment, log, and
cluster operations have short commands. `dockyardctl request METHOD /v1/path
'{"json":"body"}'` exposes the remaining API without waiting for a new CLI
release. Environment variables `DOCKYARD_URL`, `DOCKYARD_TOKEN`, and
`DOCKYARD_ORGANIZATION_ID` override saved configuration.

Federated catalogs have dedicated `template-repositories`,
`create-template-repository JSON`, `update-template-repository ID JSON`,
`sync-template-repository ID`, webhook rotation/disable, and deletion commands.
Creation and settings JSON can be read from standard input with `-`.

Build credentials have dedicated `source-credentials`,
`create-source-credential JSON`, `rotate-source-credential ID JSON`, and
`delete-source-credential ID` commands. Use `-` for secret-bearing JSON so
tokens and SSH key material do not enter shell history.

AI operations have dedicated service-account, audit-run, current-finding, and
finding-triage CLI commands. `dockyard ai-auditor --once` performs one
fail-fast end-to-end audit to validate model and platform credentials before
deploying the recurring Swarm auditor services.

OIDC providers can be created, rotated, enabled, and disabled with dedicated
CLI commands or managed declaratively with `dockyard_oidc_provider` in
Terraform/OpenTofu. `dockyard_auth_settings` controls mandatory SSO. Client
secrets remain sensitive write-only state. While mandatory SSO is enabled,
sequential and concurrent provider changes cannot disable the final enabled
OIDC or SAML provider; owner break-glass access remains available.

SAML providers likewise have dedicated CLI and Terraform/OpenTofu management.
Signing-certificate creation stays server-side; rotation uses explicit
begin/promote/cancel CLI commands so IdP metadata can be updated before cutover.

SCIM provisioning credentials can be listed, issued, and revoked with
`scim-tokens`, `create-scim-token JSON`, and `revoke-scim-token ID`, or managed
as expiring `dockyard_scim_token` Terraform/OpenTofu resources. Use `-` instead
of JSON to keep token configuration out of shell history; newly issued bearer
tokens are returned only once.

Organization member IDs are available through `members`; `update-member` and
`delete-member` expose guarded manual membership changes. Invitations can be
listed, inspected, issued, and revoked with `invitations`, `invitation ID`,
`create-invitation JSON`, and `revoke-invitation ID`, or managed as expiring
`dockyard_invitation` resources.
Project and environment grants have list, put, and delete CLI commands and can
be managed declaratively with `dockyard_access_grant`.

Local users can rotate their credential without placing it in shell history:

```sh
printf '%s\n' '{"currentPassword":"...","newPassword":"..."}' | dockyardctl change-password -
```

TOTP setup and recovery-code rotation are also stdin-safe:

```sh
printf '%s\n' '{"currentPassword":"..."}' | dockyardctl begin-mfa -
printf '%s\n' '{"code":"123456"}' | dockyardctl confirm-mfa -
printf '%s\n' '{"currentPassword":"...","code":"123456"}' | dockyardctl regenerate-mfa-recovery-codes -
```

After MFA is enabled, CLI login accepts a JSON object on standard input (plain
password input remains backward compatible):

```sh
printf '%s\n' '{"password":"...","totpCode":"123456"}' | \
  dockyardctl --url https://dockyard.example.com login admin@example.com
```

CI deployment hooks use expiring, revocable bearer credentials. Manage them
with `deploy-tokens SERVICE_ID`, `create-deploy-token SERVICE_ID JSON`, and
`revoke-deploy-token SERVICE_ID TOKEN_ID`; creation returns the secret URL only
once, while inventory exposes expiry and last-use timestamps without the token.
Developers can also create, copy, inspect, and revoke these hooks from a
service's web-console page; one-time URLs remain only in transient UI state.

Organization, project, and environment maintenance/quota policy can be read or
updated with the corresponding `policy`/`put-*-policy` CLI commands and managed
declaratively with `dockyard_resource_policy`.

Remote Swarm registration is available through `create-cluster`,
`update-cluster`, and `delete-cluster`; `cluster-token` issues the short-lived
one-time agent credential. Terraform/OpenTofu can own registration and observe
agent posture with `dockyard_cluster`, while drain/activate transitions remain
explicit operational actions.

Failure notification endpoints can be listed, created, and disabled with
`notification-endpoints`, `create-notification-endpoint JSON`, and
`delete-notification-endpoint ID`. `dockyard_notification_endpoint` provides
the same lifecycle in Terraform/OpenTofu while retaining write-only provider
credentials and generated signing secrets only in sensitive state.

Expiring service-account credentials can be managed with
`dockyard_service_account`. Terraform/OpenTofu retains the one-time bearer
token only in sensitive state and plans a replacement before expiry, while
destroy disables the old automation identity.

Audit retention and immutable S3 Object Lock archive destinations have
dedicated `audit-retention`, `put-audit-retention`, and `audit-archive*` CLI
commands. `dockyard_audit_retention` and `dockyard_audit_archive` provide the
same policy lifecycle in Terraform/OpenTofu; archive replacement never deletes
objects already protected by COMPLIANCE retention.

Database recovery has dedicated commands: `database-engines`, `databases
ENVIRONMENT_ID`, `database DATABASE_ID`, `backup-policy DATABASE_ID`,
`put-backup-policy DATABASE_ID JSON`, `delete-backup-policy DATABASE_ID`,
`backup-database DATABASE_ID`, `database-backups DATABASE_ID`, and
`restore-database BACKUP_ID DATABASE_SLUG`. Backup and restore inspection and
cancellation use `database-backup`, `database-restore`,
`cancel-database-backup`, and `cancel-database-restore`.

S3-compatible backup destinations can be managed with `backup-destinations`,
`create-backup-destination JSON`, `update-backup-destination DESTINATION_ID JSON`,
and `delete-backup-destination DESTINATION_ID`. Use `-` instead of JSON to read
credentials from standard input without placing them in shell history.

Named-volume recovery also has dedicated commands: `volumes SERVICE_ID`,
`volume-policies SERVICE_ID`, `put-volume-policy SERVICE_ID VOLUME_NAME JSON`,
`backup-volume SERVICE_ID VOLUME_NAME`, `volume-backups SERVICE_ID`, and
`restore-volume BACKUP_ID SERVICE_SLUG`. After a stopped service is rebound to
a replacement storage node, `restore-volume-offline BACKUP_ID SERVICE_SLUG`
recreates that volume from its encrypted backup without starting the workload.
Backup and restore inspection and
cancellation use `volume-backup`, `volume-restore`, `cancel-volume-backup`, and
`cancel-volume-restore`.

## Terraform / OpenTofu

`terraform-provider-dockyard` manages projects, environments, and Compose
services, including waiting for asynchronous Swarm cleanup during destroy. See
[docs/terraform.md](docs/terraform.md) and [examples/terraform/main.tf](examples/terraform/main.tf).

## License

[Apache-2.0](LICENSE). This project is an independent implementation and does
not include Dokploy proprietary source code.
