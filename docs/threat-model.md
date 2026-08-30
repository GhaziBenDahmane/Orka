# Threat model

Status: implementation review completed 2026-08-30. This document defines the
security boundary for the current architecture. It does not waive the staging
and external-provider gates in `docs/release-checklist.md`.

## Security objectives

Dockyard must prevent one organization from reading or changing another
organization's resources, keep stored and in-flight credentials confidential,
execute only validated workload intent, and preserve truthful durable state
when controllers, workers, agents, providers, or networks fail. Compromise of a
deployed tenant workload must not grant control-plane or other-tenant access.

Availability is fail-closed: stale clusters, expired leases, maintenance
windows, exhausted quotas, invalid signatures, and unverifiable artifacts stop
new mutations instead of weakening authentication or silently skipping checks.

## Trust boundaries and assets

| Boundary | Trusted material | Untrusted input | Required control |
|---|---|---|---|
| Public API and console | session/service-account hashes, RBAC policy | HTTP bodies, identifiers, forwarded metadata | authentication, tenant-scoped queries, bounded decoding, rate limits, security headers |
| SSO and SCIM | provider configuration, SP keys, SCIM token hashes | discovery documents, assertions, claims, directory writes | exact issuer/audience/domain checks, HTTPS-only OIDC and SAML endpoints, redirect-free and response-bounded OIDC requests, PKCE/nonce/state, XML signatures, replay protection, tenant binding |
| PostgreSQL | desired state, encrypted secrets, audit chain, job fences | concurrent controller/worker transactions | TLS in HA, migrations, row/tenant predicates, transactional state changes, leases and fencing |
| Local Swarm manager | Docker socket, registry credentials | Compose, build sources, image behavior | safe Compose compiler, argument-only process execution, encrypted overlays, temporary credentials, immutable release images |
| Remote Swarm agent | local Docker socket, mTLS private key | encrypted commands and transfer plans | SPIFFE identity, serial binding, TLS 1.3, short leases, command fencing, independent plan validation |
| Template repositories | pinned Ed25519 public keys, scoped GitHub token | archives, Compose and template metadata | GitHub-only fetches, bounded extraction, signature verification, atomic catalog replacement, safe compiler |
| Build sources and registries | Git/OCI credentials | repositories, submodules, Dockerfiles, ZIP files | host-bound credentials, pinned SSH host keys, hardened extraction, BuildKit secret mounts, no shell interpolation |
| Backup/object storage | encrypted destination credentials, per-backup keys | remote objects and checksums | client-side authenticated encryption, presigned single-operation transfers, size/hash verification, restore drills |
| Notifications and webhooks | signing/provider secrets | provider requests, callbacks, receiver URLs | HMAC verification, delivery replay protection, encrypted storage, bounded retries, redacted errors |
| AI auditors and model gateway | short-lived auditor/model tokens | platform snapshot strings and model output | dedicated encrypted model overlay, secret-free snapshot, least-privilege role, prompt trust markers, bounded validated findings, no remediation capability |
| External database drivers | root-owned reviewed executable | driver output and utility plans | no inherited controller environment, file-descriptor execution, owner/mode revalidation, timeout/output bounds, plan validation |

## Principal threats and implemented controls

### Tenant escape and privilege escalation

All user-facing resource access is resolved through organization membership;
project and environment grants can narrow access without bypassing the parent
organization. Owner changes are serialized and retain an active owner. Auditor
accounts are denied normal workload APIs. Tests exercise cross-tenant access,
concurrent last-owner changes, federated session binding, SCIM ownership, and
service-account revocation.

### Credential disclosure

Passwords use Argon2id and bearer credentials are stored as SHA-256 digests.
Application, source, registry, database, notification, SSO, backup, and
migration secrets use AES-256-GCM with resource-bound authenticated context.
Master-key rotation authenticates every ciphertext before transactional writes.
Logs, API projections, AI snapshots, migration reports, driver failures, and
command results omit plaintext credentials. Backups are encrypted before
leaving the executing node.

### Workload-to-control-plane escape

Safe mode rejects privileged containers, custom PID/IPC/UTS/user/cgroup
namespaces, network namespace sharing other than disabled networking, devices,
dangerous capabilities, host/cluster/named-pipe mounts, custom volume drivers,
cross-stack resources, caller-defined Traefik labels, direct port publishing,
and local Compose secret/config imports. Stack-owned overlays are encrypted.
Safe Compose input cannot declare or attach the shared platform routing
network; the compiler attaches it only to services with tenant-scoped approved
routes. The controller and remote agent retain Docker-manager authority and
therefore remain high-value trusted components; tenant workloads never receive
their sockets or credentials.

### Source and supply-chain substitution

Production controller, agent, builder, database-tool, and release images are
required to use immutable digests where the platform owns the image choice.
Git credentials are host-bound, SSH requires pinned known-host entries, and
submodules remain same-origin. Remote template catalogs can require a pinned
Ed25519 signer and are replaced transactionally only after archive and
signature validation. Private catalog downloads refuse redirects rather than
risk forwarding a GitHub token to a substituted host. Releases produce
SBOM/provenance attestations and are keylessly signed.

### Replay, stale work, and split brain

Webhook delivery IDs, SAML assertions, OIDC state, invitation tokens, and agent
enrollment tokens are one-time or replay-protected. Durable jobs and remote
commands use expiring per-attempt fencing identifiers. Resource transitions
lock the owning job, preventing a stale worker from overwriting a replacement.
Singleton schedulers use database leases, while Swarm remains the desired-state
scheduler.

### Remote-agent impersonation and CA rollover

Agents use short-lived client certificates bound to a cluster SPIFFE URI and a
database-held serial. Replacement identities remain pending until first
successful authentication. During CA replacement, controllers temporarily
trust old and new roots while signing only with the new root; agents accept the
new bundle only over the authenticated channel, persist it before rotating,
and report the resulting CA fingerprint. The agent binary requires HTTPS
origins and refuses redirects so enrollment tokens and authenticated requests
cannot be replayed to another endpoint. Operators must follow
`docs/agent-ca-rotation.md` and remove old trust only after every managed
cluster converges.

### Backup destruction and false recovery claims

Backup, restore, drill, and migration jobs share a per-database serialization
key. Artifacts carry encrypted and plaintext checksums, retention is applied
only after successful writes, and destructive restores require explicit
confirmation. A backup is not considered production evidence until its native
engine restore and application-level data checks succeed.

### AI prompt injection and unsafe autonomy

Compose content and secret values are excluded from the model snapshot. All
included strings are marked untrusted, model output is size/count/schema
bounded, and deterministic findings are persisted before a model call. The
auditor role cannot deploy, read credentials, invoke Docker, or remediate a
finding. Auditor control-plane and model requests refuse redirects so neither
bearer token can be forwarded to a substituted endpoint. 9Router and Hermes
remain outside the control-plane trust boundary.

## Explicitly trusted components

- Administrators with host access, Docker-manager access, PostgreSQL owner
  access, or master-key/CA escrow can take control of the platform.
- Installed external database drivers are reviewed root-owned control-plane
  code, not sandboxed tenant plugins. Their provenance must be managed with the
  same release controls as the controller image.
- The configured identity provider, object store, image registry, DNS/TLS
  infrastructure, and notification providers are trusted for their declared
  roles. Provider compromise is not converted into cross-tenant authorization.
- Enabling unsafe workloads explicitly grants the affected organization access
  to capabilities outside the default isolation boundary and must not be
  offered in a shared-hosting tier.

## Residual release risks and required evidence

The following are release gates rather than accepted permanent risks:

- real Entra ID, Okta, Google Workspace, object-store, registry, notification,
  and optional model-gateway conformance;
- upgrade of a production-data clone and a complete live Dokploy migration;
- measured RPO/RTO on production-equivalent storage for every advertised
  backup-capable engine;
- multi-host Swarm partition, manager-loss, workload convergence, and remote
  agent CA rotation exercises on the deployment topology;
- an independently reviewed container/socket hardening assessment and clean,
  blocking vulnerability scans of both architecture manifests in the exact
  signed release digest, including vulnerabilities without an upstream fix;
- restoration from PostgreSQL, master-key and CA escrow, and artifact storage
  with audit-chain continuity.

Any failed or missing item keeps the release in preview. Record evidence and
owners in the release checklist; do not convert an untested boundary into an
implicit acceptance.
