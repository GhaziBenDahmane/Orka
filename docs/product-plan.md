# Product plan and parity analysis

This document is based on clean-room inspection of Dokploy, Dokku, and the
public Dokploy template catalog on 2026-08-28. Dockyard deliberately keeps
Docker Compose as the workload format and Docker Swarm as the scheduler.

## How hard is the rewrite?

A useful single-node deployment API is a medium project. A production platform
with the operational depth users expect from Dokploy is a large systems
product: identity, source builds, routing, secrets, databases, backups,
observability, upgrades, and failure recovery all cross trust boundaries.

Reasonable staffing estimates from a clean start are:

| Target | Team | Calendar estimate |
|---|---:|---:|
| Secure API and single-manager deploy MVP | 2 senior engineers | 3–5 months |
| Dokploy-like product including UI and common integrations | 4–6 engineers | 9–15 months |
| Enterprise and multi-cluster production maturity | 6–9 engineers | 15–24 months |

These are engineering estimates, not deadlines. Security review, upgrade and
restore drills, documentation, and support readiness are included in the last
two rows.

## What to preserve and what to change

Dokploy provides the closest product model: projects and environments,
Compose-based applications, domains, databases, templates, deployments, and a
web console. Its catalog format is worth supporting so existing templates are
portable. Dockyard currently imports all 526 templates from the inspected
catalog; 435 pass the safe Swarm profile and 91 remain visible but cannot be
instantiated without explicitly enabling unsafe workloads.

Dokku is strongest as a small, composable, command-oriented PaaS. Its useful
lessons are stable lifecycle hooks, narrow plugin contracts, explicit config,
simple operational commands, and backing-service linking. Dockyard should not
copy Dokku's single-host container lifecycle because that would discard Swarm's
desired-state scheduling and Compose compatibility.

The resulting model is:

```text
Web UI / CLI / API clients
          |
Go API: identity, tenancy, policy, catalog, audit
          |
PostgreSQL: desired state, immutable revisions, durable jobs
          |
Workers / future outbound mTLS agents
          |
Compose compiler -> Swarm stacks -> Traefik routes
          |
Backup stores, registries, Git providers, notifications
```

The control plane must never generate imperative shell scripts from user input.
Compose revisions are immutable deployment inputs, and every asynchronous
operation is represented by a leased, cancellable job.

## Delivery sequence

### 1. Single-cluster foundation

Status: substantially implemented.

- Local identity, organization RBAC, encrypted secrets, and audit events.
- Projects, environments, Compose applications, routes, deploy history, logs,
  rollback, deploy hooks, and source builds.
- PostgreSQL queue with retries, worker leases, heartbeat, stale-job recovery,
  sequential per-service deployment, and cancellation.
- Swarm convergence checks and Traefik label/network compilation.

Exit gate: upgrade and rollback work during controller restart; no cross-tenant
access; worker-kill and Docker-daemon-loss tests pass.

### 2. Catalog and managed databases

Status: core implementation complete; storage breadth remains.

- Native catalog plus Dokploy `template.toml` compatibility and bulk importer.
- Safety classifications instead of silently granting host access.
- PostgreSQL, MySQL, MariaDB, MongoDB, Redis, Valkey, libSQL, ClickHouse,
  Qdrant, and Meilisearch provisioning definitions.
- PostgreSQL, MySQL, MariaDB, and MongoDB native backup/restore, streaming
  checksums, interval policies, and retention.
- S3-compatible multipart storage with encrypted destination credentials.
- Next: automated restore drills and client-side backup encryption per
  destination.

Exit gate: automated restore verification and documented RPO/RTO for every
database advertised as backup-capable.

### 3. Enterprise identity and policy

Status: OIDC/PKCE, signed SAML 2.0 with replay protection, mandatory SSO,
device-session administration, expiring service accounts with atomic token
rotation, SCIM users/groups, group-to-role mapping, and owner protection
implemented.

- Extend RBAC from organization roles to project/environment grants.
- Add immutable audit export and configurable retention.

Exit gate: IdP-initiated and SP-initiated conformance tests against Entra ID,
Okta, Keycloak, and Google Workspace where applicable.

### 4. Delivery integrations and operations

Status: public/private HTTPS Git, private OCI registries, ephemeral build
credentials, generic deploy hooks, and signed/replay-safe provider webhooks
implemented.

- Add SSH deploy keys alongside the implemented encrypted HTTPS Git tokens and
  OCI registry credentials.
- Add build status callbacks to the GitHub, GitLab, Gitea, and Bitbucket
  webhook adapters.
- Notification rules and providers for email, Slack-compatible webhooks, and
  common incident systems.
- OpenTelemetry traces/log correlation, richer Prometheus metrics, alerts,
  maintenance mode, and resource quotas.
- Extend the implemented asynchronous service/stack finalizer model to
  projects, environments, volumes, and clusters.

Exit gate: end-to-end push-to-deploy, cancellation, rollback, alert, and
disaster-recovery scenarios pass under load.

### 5. Multi-cluster and high availability

Status: designed, not implemented.

- Replace direct remote Docker socket access with outbound agents using mTLS,
  short-lived enrollment tokens, certificate rotation, and signed commands.
- Add cluster inventory, placement policy, draining, maintenance windows,
  agent upgrades, and capacity signals.
- Run multiple stateless controllers and workers; prove job fencing and leader
  election behavior under partitions.

Exit gate: loss of a controller or cluster manager does not corrupt desired
state, duplicate destructive jobs, or expose credentials.

### 6. Product surface and migration

Status: Compose, Docker-image application, Dockerfile/HTTPS Git application,
and managed-database Dokploy dry-run/import tooling is implemented. Advanced
build modes and application settings remain manual, and persistent database
data still requires backup/restore. The UI, CLI breadth, and providers remain.

- React/TypeScript console generated from a versioned OpenAPI contract.
- CLI and Terraform/OpenTofu provider for automation.
- Extend the idempotent Dokploy importer to advanced application settings,
  providers, and backup metadata.
- Signed catalog releases and an external driver protocol with compatibility
  tests.

Exit gate: a representative Dokploy installation can be imported, compared,
deployed, and rolled back without manual database edits.

## Release policy

Do not describe the project as production-ready until all release-blocking
threat-model findings are closed, database restores are exercised in CI, an
upgrade from the previous release is tested, and a clean machine can be
installed and recovered using only published documentation. Features without
those guarantees should be marked preview rather than silently presented as
complete.
