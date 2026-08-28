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
  checksums, interval policies, retention, and opt-in isolated restore drills.
- S3-compatible multipart storage with encrypted destination credentials and
  client-side, per-backup envelope encryption for local and remote artifacts.
- Remote backup and restore execution through outbound agents using short-lived
  presigned transfers, per-backup encryption, and end-to-end checksum checks.
- Scheduled drill failure notifications, overdue alerts, and per-database
  recovery-duration metrics are implemented. Production RPO/RTO values still
  require measured operator drills and publication for each supported engine.

Exit gate: automated restore verification and documented RPO/RTO for every
database advertised as backup-capable.

### 3. Enterprise identity and policy

Status: OIDC/PKCE, signed SAML 2.0 with replay protection, mandatory SSO,
device-session administration, expiring service accounts with atomic token
rotation, SCIM users/groups, group-to-role mapping, owner protection, inherited
project/environment grants, resumable audit export, and configurable audit
retention implemented.

- External write-once audit archives use S3 Object Lock COMPLIANCE retention,
  hash-chained manifests, durable retries, delivery inspection, failure
  notifications, and a pruning barrier for unarchived events.

Exit gate: IdP-initiated and SP-initiated conformance tests against Entra ID,
Okta, Keycloak, and Google Workspace where applicable.

### 4. Delivery integrations and operations

Status: public/private HTTPS Git, private OCI registries, ephemeral build
credentials, generic deploy hooks, signed/replay-safe provider webhooks, and
durable provider build-status callbacks implemented.

- Encrypted HTTPS Git tokens, pinned-host SSH deploy keys, and OCI registry
  credentials are implemented.
- Private build-registry authentication is forwarded to local and remote Swarm
  managers with `--with-registry-auth`; remote credentials remain inside the
  encrypted command envelope.
- GitHub, GitLab, Gitea, and Bitbucket callbacks publish ordered pending and
  terminal statuses using snapshotted, host-pinned encrypted credentials.
- Failure notification rules and durable providers for TLS email,
  Slack-compatible webhooks, PagerDuty, and Opsgenie are implemented.
- OpenTelemetry HTTP and worker traces, request/log correlation, and richer
  Prometheus HTTP, deployment, queue, backup, restore, and drill metrics are
  implemented. Hierarchical maintenance mode and transactionally enforced
  organization/project/environment resource quotas and a production
  Prometheus alert pack are also implemented. Durable signed webhook,
  Slack-compatible, TLS SMTP, PagerDuty, and Opsgenie failure notifications
  are implemented.
- Resumable asynchronous finalizers cover services, projects, environments,
  clusters, and opt-in stack-labelled volume cleanup. Parent deletion waits
  for all child stacks and active deployments block the cascade.

Exit gate: end-to-end push-to-deploy, cancellation, rollback, alert, and
disaster-recovery scenarios pass under load.

### 5. Multi-cluster and high availability

Status: in progress; scheduler abstraction, cluster inventory, label/capacity
placement with heartbeat freshness, scheduled maintenance windows,
one-time enrollment, rotating short-lived certificates, mTLS heartbeats, and
fenced outbound command execution are implemented.
Controller singleton loops use expiring database leader leases, while durable
jobs and agent commands use independent fencing so stateless replicas can share
the same PostgreSQL control plane.

- Replace direct remote Docker socket access with outbound agents using mTLS,
  short-lived enrollment tokens, certificate rotation, and signed commands.
- Digest-pinned, start-first agent upgrades are implemented as fenced,
  encrypted asynchronous commands. Heartbeats report ready/active/manager node
  counts plus active-node CPU and memory, all usable as placement constraints.
- Run multiple stateless controllers and workers; prove job fencing and leader
  election behavior under partitions.

Exit gate: loss of a controller or cluster manager does not corrupt desired
state, duplicate destructive jobs, or expose credentials.

### 6. Product surface and migration

Status: Compose, Docker-image application, Dockerfile/HTTPS Git application,
managed-database Dokploy dry-run/import tooling, a secure operational CLI with
a full raw-API escape hatch, generated route-level OpenAPI coverage, and an
embedded React console for core workload, template, database, and cluster
workflows are implemented. Advanced build modes and application settings
remain manual and persistent database data still requires backup/restore. The
Terraform/OpenTofu provider covers projects, environments, Compose services,
routes, managed databases, source credentials, backup destinations, and backup
policies. The console provides credential, backup-destination, OIDC, SAML,
hierarchical policy, mandatory-SSO, audit retention/archive, and notification
administration. Remote clusters can be registered, enrolled, drained,
reactivated, removed, and upgraded to a digest-pinned agent image from the
console; HTTPS tokens and pinned-host SSH deploy keys are also supported.

- React/TypeScript console generated from a versioned OpenAPI contract.
- CLI and Terraform/OpenTofu provider for automation.
- The idempotent Dokploy importer emits and persists a secret-safe parity
  manifest for advanced application settings and unsupported build features;
  compatible S3 destinations and fixed-interval database backup policies are
  imported with secret re-encryption. Registry and static GitLab/Gitea/
  Bitbucket credentials are imported and host-matched to applications; GitHub
  App credentials and backup policies that cannot be represented losslessly
  remain operator-assisted.
- Ed25519-signed deterministic catalog manifests are implemented and verified
  before import by default. A versioned, bounded process protocol and Go SDK
  support externally packaged database drivers with compatibility tests.

Exit gate: a representative Dokploy installation can be imported, compared,
deployed, and rolled back without manual database edits.

## Release policy

Do not describe the project as production-ready until all release-blocking
threat-model findings are closed, database restores are exercised in CI, an
upgrade from the previous release is tested, and a clean machine can be
installed and recovered using only published documentation. Features without
those guarantees should be marked preview rather than silently presented as
complete.

Release automation now covers migration checksums, fresh and checkpoint
upgrades, stale-worker takeover, API security classification, clean Compose
installation, live Swarm convergence, restart persistence,
vulnerability/license checks, an SPDX SBOM, and container scanning. The staging-only conformance, load, real-provider,
full Dokploy cutover, and measured disaster-recovery gates remain open; see
`docs/release-checklist.md`.
