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
| Public API and console | session/service-account hashes, RBAC policy | HTTP bodies, identifiers, forwarded metadata | authentication, tenant-scoped queries, bounded decoding, rate limits, security headers, non-cacheable API responses |
| Global metrics | dedicated operator-token hash | scrape requests | separate fail-closed bearer authentication with no tenant-token fallback |
| SSO and SCIM | provider configuration, SP keys, SCIM token hashes | discovery documents, assertions, claims, directory writes | exact issuer/audience/domain checks, HTTPS-only OIDC and SAML endpoints, redirect-free and response-bounded OIDC requests, PKCE/nonce/state, XML signatures, replay protection, tenant binding |
| PostgreSQL | desired state, encrypted secrets, audit chain, job fences | concurrent controller/worker transactions | TLS in HA, migrations, row/tenant predicates, transactional state changes, leases and fencing |
| Local Swarm manager | Docker socket, registry credentials | Compose, build sources, image behavior | safe Compose compiler, argument-only process execution, encrypted overlays, temporary credentials, immutable release images |
| Remote Swarm agent | local Docker socket, mTLS private key | encrypted commands and transfer plans | SPIFFE identity, serial binding, TLS 1.3, short leases, command fencing, independent plan validation |
| Template repositories | pinned Ed25519 public keys, scoped GitHub token | archives, Compose and template metadata | GitHub-only fetches, bounded extraction, signature verification, atomic catalog replacement, safe compiler |
| Build sources and registries | Git/OCI credentials | repositories, submodules, Dockerfiles, ZIP files | host-bound credentials, pinned SSH host keys, hardened extraction, BuildKit secret mounts, no shell interpolation |
| Backup/object storage | encrypted destination credentials, per-backup keys | remote objects and checksums | client-side authenticated encryption, presigned single-operation transfers, size/hash verification, restore drills |
| Notifications and webhooks | signing/provider secrets | provider requests, callbacks, receiver URLs | HMAC verification, delivery replay protection, encrypted storage, bounded retries, redacted errors |
| AI auditors and model gateway | short-lived auditor/model tokens | platform snapshot strings and model output | dedicated encrypted model overlay, secret-free snapshot, least-privilege role, prompt trust markers, bounded whole-platform chunking, cross-chunk deduplication, validated findings, no remediation capability |
| External database drivers | root-owned reviewed executable | driver output and utility plans | no inherited controller environment, startup-digest binding, file-descriptor execution, owner/mode revalidation, size/timeout/output bounds, plan validation |

## Principal threats and implemented controls

### Tenant escape and privilege escalation

All user-facing resource access is resolved through organization membership;
project and environment grants can narrow access without bypassing the parent
organization. Owner changes are serialized and retain an active owner. Auditor
accounts are denied normal workload APIs. Tests exercise cross-tenant access,
concurrent last-owner changes, federated session binding, SCIM ownership, and
service-account revocation.

The public and dedicated mTLS agent HTTP surfaces share request correlation,
security and no-store headers, panic recovery with secret-safe logging, tracing,
and bounded-cardinality request metrics. Both listeners bound header size and
header, request, response, and idle durations. Agent authentication still runs
before any command or heartbeat handler.

The packaged Swarm topology isolates controller ingress from tenant-routed
services on a dedicated encrypted Traefik edge network. The public API accepts
forwarding headers only when the immediate peer belongs to an explicitly
configured trusted-proxy CIDR, walks proxy chains from right to left, and
ignores malformed chains. This preserves per-client authentication throttling
and audit attribution without allowing direct clients to spoof either value.

### Credential disclosure

Passwords use Argon2id and bearer credentials are stored as SHA-256 digests.
Application, source, registry, database, notification, SSO, backup, and
migration secrets use AES-256-GCM with resource-bound authenticated context.
Master-key rotation authenticates every ciphertext before transactional writes.
Logs, API projections, AI snapshots, migration reports, driver failures, and
command results omit plaintext credentials. Operational 5xx responses use
stable public messages while correlated logs retain only the error type rather
than potentially secret-bearing error text. Backups are encrypted before
leaving the executing node.

### Workload-to-control-plane escape

Safe mode rejects privileged containers, custom PID/IPC/UTS/user/cgroup
namespaces, network namespace sharing other than disabled networking, devices,
dangerous capabilities, host/cluster/named-pipe mounts, custom volume drivers,
device/runtime plugins, cross-stack resources, caller-defined Traefik labels,
direct port publishing, and local Compose environment, label, extension,
secret, or config imports. Stack-owned overlays are encrypted. Safe Compose
input cannot declare or attach the shared platform routing network; the
compiler attaches it only to services with tenant-scoped approved routes. The
safe profile also rejects node-wide global scheduling and caps each stack at
100 aggregate replicated tasks, preventing a single service record from
bypassing resource-count quotas through unbounded Compose fan-out. External
logging drivers and their daemon-side network/plugin execution are rejected;
safe workloads can configure only bounded local log rotation. Host cgroup,
kernel, ulimit, storage, lifecycle-hook, model-runner, legacy scaling, and
generic-resource directives are also rejected. The
controller and remote agent retain Docker-manager authority and therefore
remain high-value trusted components; tenant workloads never receive their
sockets or credentials. Their production services use read-only root
filesystems, drop every Linux capability, forbid privilege escalation, and keep
transient build material on bounded tmpfs mounts. A read-only bind mount does
not reduce the Docker API authority carried by the socket; it only prevents
filesystem mutation of the mount, so host access remains possible after a
controller or agent compromise.

### Source and supply-chain substitution

Production controller, agent, builder, database-tool, and release images are
required to use immutable digests where the platform owns the image choice.
Git credentials are host-bound, SSH requires pinned known-host entries, and
submodules remain same-origin. Remote template catalogs can require a pinned
Ed25519 signer and are replaced transactionally only after archive and
signature validation. Private catalog downloads refuse redirects rather than
risk forwarding a GitHub token to a substituted host. Releases produce
SBOM/provenance attestations and are keylessly signed.
Tenant-configured Git, OIDC, notification, SMTP, backup, and catalog clients use
a shared egress policy. DNS answers are checked again in the dial path and any
answer in loopback, link-local, shared, or private address space is rejected by
default, which prevents DNS rebinding into manager services and cloud metadata
endpoints. Operators may allow only explicit private CIDRs for intentional
self-hosted dependencies; remote-agent artifact transfers apply the same rule.
Proxy environment variables are not honored on these HTTP paths because a
proxy would move destination resolution outside the policy boundary. Docker
image pulls, build steps, and deployed workloads remain outside this
process-level control and require node firewall or network-policy enforcement.

### Replay, stale work, and split brain

Webhook delivery IDs, SAML assertions, OIDC state, invitation tokens, and agent
enrollment tokens are one-time or replay-protected. An agent enrollment result
is retryable only for the exact CSR bound to the consumed token, preventing a
dropped response from requiring an unsafe reusable credential. Durable jobs and remote
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
cluster converges. The agent persists its pending enrollment key before sending
the CSR and validates the returned trust bundle, client certificate, cluster
identity, and key binding before committing durable identity state.

### Backup destruction and false recovery claims

Backup, restore, drill, and migration jobs share a per-database serialization
key. Artifacts carry encrypted and plaintext checksums, retention is applied
only after successful writes, and destructive restores require explicit
confirmation. Named-volume restore admission and retention lock the same backup
record; retention removes metadata before the remote object, so it cannot leave
a restorable record pointing at an object that it already deleted. Database
retention uses the same lock boundary, preserves every manual restore and every
active verification drill, and constrains recursive local cleanup to the exact
backup-ID directory. Remote deletion intent is committed before backup metadata
is removed, retains the destination credential reference, retries transient
object-store failures, and exposes backlog age for alerting. A backup is not
considered production evidence until its native engine restore and
application-level data checks succeed. Destination changes verify access before
atomically replacing resource-bound encrypted credentials, allowing recovery
from key rotation without weakening tenant ownership.
Managed databases backed by Docker's node-local volume driver persist their
first storage-node assignment and receive a platform-owned `node.id` placement
constraint on every deployment. Legacy stacks are adopted only when all
running tasks resolve unambiguously to one node. Loss of that node therefore
causes visible unavailability rather than an apparently healthy database with
empty replacement storage.
Generic named-volume transfer helpers are scheduled only on an explicitly
persisted node and must run the same digest-pinned image as the controller or
cluster agent. Presigned URLs and envelope keys are delivered in an ephemeral
Swarm secret. Plaintext archives are streamed and never persisted as complete
files in the helper. Archive restore rejects absolute paths, traversal, escaping
symlinks, hard links, devices, sockets, FIFOs, duplicates, and paths beneath
symlinks before moving any live volume entry; staged replacement retains the
old top-level tree until all replacement renames succeed.

### AI prompt injection and unsafe autonomy

Compose content and secret values are excluded from the model snapshot. All
included strings are marked untrusted, model output is size/count/schema
bounded, and deterministic findings are persisted before a model call. The
auditor role cannot deploy, read credentials, invoke Docker, or remediate a
finding. Auditor control-plane and model requests refuse redirects so neither
bearer token can be forwarded to a substituted endpoint. 9Router and Hermes
remain outside the control-plane trust boundary.

The snapshot uses explicit allowlisted projections rather than serializing
normal API records. Free-form project descriptions, placement selectors,
agent-reported cluster maps, audit metadata, and network addresses therefore
cannot become model-visible through an unrelated API-struct change.

Raw remote-agent failures, reconciliation details, and upstream API response
bodies remain outside the snapshot and failed-run summaries because they may
echo workload-controlled secrets. The runner rejects an oversized serialized
snapshot before creating a run or sending any content to a model gateway.

OIDC JIT provisioning accepts an `email` claim only when the signed token also
asserts `email_verified=true`; omission fails closed. The signed
`preferred_username` fallback is reserved for providers such as tenant-scoped
Entra issuers that omit `email`. OIDC and SAML provider allowlists contain only
normalized DNS domain names, preventing malformed or URL-shaped trust entries.

Template-generated environment values and managed-file contents are encrypted
at rest. Stored Compose and immutable deployment snapshots contain only opaque
managed-file references. The local Swarm adapter or outbound agent resolves
those references into mode-0600 temporary files immediately before deployment,
removes the internal values from Compose interpolation, and deletes the
temporary directory afterward. Safe-mode compilation permits only bounded
read-only configs that exactly match those platform-generated references.

## Explicitly trusted components

- Administrators with host access, Docker-manager access, PostgreSQL owner
  access, or master-key/CA escrow can take control of the platform.
- Installed external database drivers are reviewed root-owned control-plane
  code, not sandboxed tenant plugins. Their provenance must be managed with the
  same release controls as the controller image. Each managed database is
  bound to its driver source and SHA-256 artifact identity, preventing HA
  workers with different plugin builds from silently sharing recovery jobs.
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
implicit acceptance. Stable promotion enforces this boundary with the
source-commit- and candidate-digest-bound certification described in
`docs/production-certification.md`; both the certification and final promotion
run in separately protected GitHub environments and the certification is
keylessly signed before use.
