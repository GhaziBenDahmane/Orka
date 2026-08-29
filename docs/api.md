# HTTP API

All request and response bodies use JSON. Except for health, bootstrap, login,
SSO discovery/callback, and deploy hooks, endpoints require
`Authorization: Bearer <session-token>`. Use `X-Organization-ID` to select an
organization when a user belongs to more than one. This includes `/metrics`;
Prometheus should use a dedicated read-only service-account token.

`GET /healthz` is the unauthenticated liveness probe and only reports whether
the HTTP process can answer. `GET /readyz` is the unauthenticated readiness
probe; it performs a database ping with a two-second upper bound and returns
503 while PostgreSQL is unavailable. Dependency errors are logged server-side
but are not included in the response. Container health checks and smoke tests
use `/readyz` so traffic is sent only to a usable control plane.

Local password authentication is protected by PostgreSQL-backed fixed-window
limits shared by every controller replica: 300 total login submissions and 10
attempts per existing account per minute. Bootstrap is limited to five attempts
per minute. Rejected requests return 429 with `Retry-After`; stored limiter keys
are SHA-256 digests rather than email addresses or credentials.
Expired limiter state is pruned by the singleton hourly maintenance loop.

Every response includes `X-Request-ID`. A printable caller-provided request ID
is preserved; otherwise the server generates a UUID. `GET /metrics` is a
Prometheus text endpoint covering HTTP requests, durable jobs and stale leases,
deployments, backups, restores, restore drills, and operation durations.

## Identity

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/auth/bootstrap` | Create the first organization owner |
| POST | `/v1/auth/login` | Exchange local credentials for a session |
| POST | `/v1/auth/logout` | Revoke the current session |
| GET | `/v1/me` | Return the current principal and role |
| GET | `/v1/authorization/effective-role?resourceType=…&resourceId=…` | Resolve inherited project/environment RBAC for a resource |
| GET | `/v1/sessions` | List the caller's active device sessions |
| DELETE | `/v1/sessions/{id}` | Revoke one of the caller's sessions |
| POST | `/v1/sessions/revoke-others` | Revoke every session except the caller's |
| GET/PUT | `/v1/sso/settings` | Read or enforce organization-wide SSO |
| GET/POST | `/v1/service-accounts` | List or create scoped automation identities |
| POST | `/v1/service-accounts/{id}/rotate` | Revoke old tokens and issue a replacement |
| DELETE | `/v1/service-accounts/{id}` | Disable an automation identity |
| GET | `/v1/audit-events?beforeId=…&limit=…` | Read a descending audit page |
| GET | `/v1/audit-events/export?afterId=…&limit=…` | Export ascending NDJSON with integrity headers |
| GET/PUT | `/v1/audit-retention` | Read or set the 30–3650 day retention policy |
| GET/POST | `/v1/audit-archives` | List or configure S3 Object Lock audit archives |
| DELETE | `/v1/audit-archives/{id}` | Disable an archive without deleting retained objects |
| POST | `/v1/audit-archives/{id}/run` | Queue an archive batch or explicitly retry a failed batch |
| GET | `/v1/audit-archives/{id}/batches` | Inspect immutable archive delivery history and hashes |
| GET/PUT | `/v1/policy` | Organization maintenance mode and quotas |
| GET/PUT | `/v1/projects/{id}/policy` | Project maintenance mode and quotas |
| GET/PUT | `/v1/environments/{id}/policy` | Environment maintenance mode and quotas |
| GET/POST | `/v1/sso/oidc-providers` | List or configure OIDC providers |
| PUT | `/v1/sso/oidc-providers/{id}` | Update discovery settings and optionally rotate the encrypted client secret |
| POST | `/v1/sso/oidc-providers/{id}/enable` | Re-enable a disabled OIDC provider |
| GET | `/v1/auth/sso/discover?email=…` | Discover providers by email domain |
| GET | `/v1/auth/sso/{providerID}/start` | Start Authorization Code + PKCE |
| GET | `/v1/auth/sso/callback` | Verify the ID token and create a session |
| GET/POST | `/v1/sso/saml-providers` | List or configure SAML identity providers |
| PUT | `/v1/sso/saml-providers/{id}` | Refresh IdP metadata and mappings while preserving the SP key and entity ID |
| POST | `/v1/sso/saml-providers/{id}/enable` | Re-enable a disabled SAML provider |
| GET | `/v1/auth/saml/discover?email=…` | Discover SAML providers by email domain |
| GET | `/v1/auth/saml/{providerID}/metadata` | Download signed-request SP metadata |
| GET | `/v1/auth/saml/{providerID}/start` | Start SP-initiated SAML login |
| POST | `/v1/auth/saml/{providerID}/acs` | Verify an assertion and create a session |
| POST | `/v1/scim/tokens` | Create a one-time-visible SCIM bearer token |
| GET/POST/DELETE | `/v1/source-credentials…` | Manage encrypted HTTPS Git, SSH deploy-key, and OCI registry credentials |
| GET/POST/DELETE | `/v1/notification-endpoints…` | Manage durable webhook, Slack, SMTP, PagerDuty, and Opsgenie notifications |
| GET | `/v1/migration-resources?sourceOrganizationId=…` | Inspect persisted, secret-safe Dokploy application parity records |
| GET/POST | `/v1/clusters` | List or register remote Swarm clusters |
| PATCH | `/v1/clusters/{id}` | Activate, drain, or disable a cluster |
| POST | `/v1/clusters/{id}/enrollment-tokens` | Issue a 15-minute one-time agent token |
| POST | `/v1/clusters/{id}/agent-upgrades` | Queue a digest-pinned rolling agent upgrade |
| GET | `/v1/clusters/{id}/commands/{commandID}` | Inspect redacted asynchronous command state |
| POST | `/v1/agent/enroll` | Exchange a token and CSR for a client certificate |
| POST | `/v1/agent/heartbeat` | Report agent and Swarm capacity over the mTLS listener |
| GET | `/v1/agent/commands/next` | Lease the next encrypted-at-rest Swarm command over mTLS |
| POST | `/v1/agent/commands/{id}/lease` | Renew a command lease using its fencing ID |
| POST | `/v1/agent/commands/{id}/complete` | Store a fenced command result |
| POST | `/v1/agent/rotate` | Rotate the current short-lived client certificate |
| GET/POST/PATCH/DELETE | `/scim/v2/Users…` | SCIM 2.0 user provisioning |
| GET/POST/PATCH/DELETE | `/scim/v2/Groups…` | SCIM groups and group-to-role mapping |

Creating an environment accepts either an explicit `clusterId` or a
`placementSelector` map plus `minimumNodes`, `minimumNanoCpus`, and
`minimumMemoryBytes`. Automatic placement considers only
active clusters with a heartbeat newer than two minutes, matching labels,
sufficient reported node capacity, and no active maintenance window; it picks
the least-loaded eligible cluster. `PATCH /v1/clusters/{id}` accepts
`maintenanceStartsAt` and `maintenanceEndsAt` together. Deployments and remote
commands are rejected during that interval, while reads and heartbeats remain
available.

Policy limits are nullable: `maxProjects`, `maxEnvironments`, `maxServices`,
and `maxDatabases`. Organization limits count all descendants, while project
and environment limits count their own descendants. Every applicable scope is
enforced, so a narrower policy cannot evade a parent quota. Maintenance mode is
also inherited and rejects new resources, configuration mutations, deletions,
deployments, rollbacks, and webhook deployments with `503 maintenance_mode`;
reads, cancellation, backups, and already-running jobs remain available.

Notification endpoints support generic webhook, Slack-compatible payloads,
TLS SMTP (`starttls` or implicit `tls`), PagerDuty Events API v2, and the
Opsgenie Alerts API. SMTP passwords and provider integration keys are
encrypted and never returned. Generic webhook signing secrets are revealed
once. All providers use the same idempotent delivery records and retry queue
for `deployment.failed`, `backup.failed`, `restore.failed`,
`restore.drill.failed`, `database.migration.failed`, and
`audit.archive.failed`. URLs and signing
secrets are encrypted at rest. The secret is returned once at creation; generic
receivers can verify `HMAC-SHA256(timestamp + "." + rawBody)` from
`X-Dockyard-Timestamp` and `X-Dockyard-Signature-256`. Deliveries are
deduplicated per endpoint/event/resource and retried as leased durable jobs.

Agent enrollment is disabled unless both `DOCKYARD_AGENT_CA_CERT` and
`DOCKYARD_AGENT_CA_KEY` (or their `_FILE` variants) are configured. The
enrollment token is stored only as a SHA-256 digest, expires after 15 minutes,
and is consumed atomically. The issued client certificate is bound to the
cluster ID and expires after seven days by default.
Heartbeat traffic is accepted only on the optional dedicated agent listener;
the client certificate must chain to the configured CA and its serial must
match the cluster's latest enrollment, allowing immediate supersession during
rotation.
Remote environments select a cluster with `clusterId` when they are created.
Application deploy, removal, logs, and node operations use encrypted-at-rest
commands claimed by the outbound agent. Expiring leases are retried and every
renewal/completion is fenced by a per-attempt UUID.

## AI auditing

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/ai/audit-snapshot` | Return a secret-free organization inventory to an auditor identity |
| POST | `/v1/ai/audit-runs` | Start an attributed audit run |
| POST | `/v1/ai/audit-runs/{id}/findings` | Upsert a structured finding by fingerprint |
| PATCH | `/v1/ai/audit-runs/{id}` | Complete or fail the caller's active run |
| GET | `/v1/ai/audit-runs` | List runs as an organization administrator |
| GET | `/v1/ai/audit-runs/{id}/findings` | Review findings as an organization administrator |

The first four endpoints require an `auditor` service account; the last two
require an administrator. Auditor identities have no normal RBAC rank and
cannot mutate workloads. See `ai-auditing.md` for the deployment contract.

OIDC uses Authorization Code flow with PKCE, nonce validation, one-time state,
an encrypted browser-bound HttpOnly cookie, and exact issuer/audience
validation. Federated sessions are bound to the organization that owns the
provider and cannot be reused to select another organization where the same
user has a membership. Session listing and revocation from a federated session
are restricted to sessions issued by that same organization; local sessions
retain account-wide device administration.

SAML providers accept identity-provider metadata XML, allowed email domains,
email/name attribute mappings, a default role, and an opt-in
`allowIdpInitiated` flag. Dockyard generates an encrypted per-provider RSA key,
signs authentication requests with RSA-SHA256, validates signed assertions,
binds SP-initiated responses to one-time RelayState and an encrypted
`SameSite=None; Secure` browser cookie, and rejects assertion replays.
Explicitly enabled IdP-initiated login remains cookie-independent. Register the
provider metadata URL with the IdP.
Mandatory SSO can only be enabled after an OIDC or SAML provider is active.
Once enabled, local-password sessions cannot access that organization except
for its owner break-glass account.
Service-account tokens are shown once, stored as hashes, expire within 365
days, carry an organization role, support atomic rotation, and are attributed
separately from users in the audit log.
Audit exports are ordered by immutable event ID. Each response includes
`X-Content-SHA256` for offline verification and `X-Next-After-ID` for resumable
pagination. The default retention is 365 days; configured policies are pruned
hourly by workers. External archives require an HTTPS S3-compatible backup
destination whose bucket has Object Lock enabled. Workers upload batches with
COMPLIANCE retention and create a SHA-256 chain from each manifest to the
previous object. Pruning stops at the least-progressed enabled archive, so an
outage cannot silently erase unexported events. Failed ranges remain pinned
until an administrator retries them.

## Workloads

| Method | Path | Purpose |
|---|---|---|
| GET/POST | `/v1/projects` | List or create projects |
| GET/POST | `/v1/projects/{id}/environments` | List or create environments |
| GET/PUT/DELETE | `/v1/projects/{id}/grants…` | Manage per-user project roles |
| GET/PUT/DELETE | `/v1/environments/{id}/grants…` | Manage per-user environment roles |
| GET/POST | `/v1/environments/{id}/services` | List or create Compose services |
| GET/PATCH/DELETE | `/v1/services/{id}` | Read, revise, or asynchronously remove a service and stack (`?deleteVolumes=true` is explicit destructive cleanup) |
| PUT | `/v1/services/{id}/source` | Configure a Git or uploaded-ZIP application build, registry target, build mode, credentials, arguments, secrets, and submodules |
| PUT | `/v1/services/{id}/artifact-source` | Upload or replace an encrypted ZIP source (25 MiB compressed / 250 MiB expanded limits) |
| POST | `/v1/services/{id}/routes` | Publish a service through Traefik |
| GET/DELETE | `/v1/routes/{id}` | Inspect or remove a route |
| POST | `/v1/services/{id}/deployments` | Enqueue a Swarm deployment |
| GET | `/v1/services/{id}/deployments` | Read deployment history |
| POST | `/v1/deployments/{id}/cancel` | Cancel a queued or running deployment |
| POST | `/v1/services/{id}/rollback` | Redeploy the latest successful snapshot |
| GET | `/v1/services/{id}/logs` | Read aggregated Swarm service logs |
| POST | `/v1/services/{id}/deploy-tokens` | Create a CI deploy hook |
| POST | `/v1/hooks/deploy/{token}` | Trigger a deployment from CI |
| GET/POST | `/v1/services/{id}/webhooks` | List or create provider webhook integrations |
| DELETE | `/v1/webhooks/{id}` | Disable a provider webhook integration |
| POST | `/v1/hooks/provider/{id}` | Verify a provider push event and deploy |

Organization owners and administrators manage scoped grants. A project grant
is inherited by all of its environments, while a more privileged environment
grant applies within that environment. Scoped roles elevate a member's
organization role; they never reduce an owner or administrator's authority.
Service accounts continue to use their organization-scoped role.

Project and environment deletion is asynchronous and cascades through service
stack finalizers. Repeating a delete safely resumes failed finalizers. Cluster
deletion revokes its agent certificate and queued commands and is allowed only
after environments have been moved or deleted. Named volumes are retained by
default; `deleteVolumes=true` removes only volumes carrying Docker's matching
stack-namespace label, after the stack has been removed.

Provider integrations support GitHub, GitLab, Gitea, and Bitbucket. Secrets are
shown once, encrypted at rest, and used to authenticate the raw request body.
Only pushes to the configured branch are deployed; delivery IDs are retained
for 30 days to reject replays. A service source can also set `statusProvider`,
`statusCredentialId`, and `statusContext`. Matching webhook deployments then
publish ordered pending and terminal commit statuses through durable retrying
jobs. The status credential must be a Git-token credential pinned to the
repository host; callback configuration is snapshotted when each delivery is
queued so later source edits cannot redirect an in-flight secret.

Dockerfile sources accept `buildTarget`, `enableSubmodules`, `buildArguments`,
and `buildSecrets`. Argument values are non-secret Docker build arguments and
may appear in image metadata. Build secrets are encrypted at rest, omitted from
API responses and process arguments, materialized as mode `0600` temporary
files, and passed with BuildKit `--secret`. Submodules are restricted to
relative URLs or the source repository's original protocol, hostname, and
port. Omitting either build-settings map preserves its stored values; sending
an empty object clears that map.

Sources with `buildType=static` package an existing repository subdirectory
from `outputDirectory` into a minimal Caddy image pinned by digest. Static mode
does not execute repository build commands and rejects Docker targets,
arguments, and secrets; the output directory must already contain the site.
`buildType=nixpacks` uses the pinned Nixpacks CLI bundled in the controller,
then pushes the generated image through the configured registry credentials.
Build arguments are passed as documented non-secret Nixpacks environment
values. Build secrets are rejected because the Nixpacks CLI does not expose
BuildKit secret mounts.
`buildType=railpack` runs the pinned Railpack planner and its matching,
digest-pinned BuildKit frontend through `docker buildx`. Arguments and secrets
are passed to planning by name through the process environment and mounted into
build steps from short-lived mode-0600 files; values never enter command-line
arguments. Per-deployment cache keys prevent cross-tenant cache sharing.
`buildType=buildpacks` uses the checksum-pinned `pack` CLI and a digest-pinned
Paketo Jammy base builder, publishing directly to the configured registry.
`buildType=heroku_buildpacks` uses the same pinned CLI with a digest-pinned
Heroku 24 builder. Either CNB mode may set `builderImage` to a custom OCI
builder only when the reference includes an immutable `@sha256:` digest.
Build environment values are inherited by name rather than placed in process
arguments. Build secrets are rejected because the CNB lifecycle does not offer
the same ephemeral secret-mount contract as Dockerfile or Railpack builds.

## Catalog and databases

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/templates` | List global and organization templates with redacted variable descriptors |
| GET/POST | `/v1/template-repositories` | List or register organization GitHub catalogs, optionally using an encrypted GitHub token credential |
| PATCH | `/v1/template-repositories/{id}` | Pin or rotate a repository signing key, private-access credential, signature policy, and automatic sync interval |
| POST | `/v1/template-repositories/{id}/sync` | Fetch and import a bounded Dokploy-compatible catalog archive |
| POST/DELETE | `/v1/template-repositories/{id}/webhook-secret` | Create or rotate the one-time GitHub webhook secret, or disable webhook refresh |
| POST | `/v1/hooks/template-repositories/{id}` | Authenticate a GitHub push delivery and queue replay-safe catalog refresh |
| DELETE | `/v1/template-repositories/{id}` | Remove a catalog and its template entries |
| POST | `/v1/templates/import/dokploy` | Import `template.toml` plus Compose YAML |
| POST | `/v1/templates/{id}/preview` | Validate overrides and return secret-free service, route, environment-key, and managed-file-count topology |
| POST | `/v1/templates/{id}/instantiate` | Create a service, encrypted secrets, files and routes; accepts declared `variables` overrides |
| GET | `/v1/services/{id}/template-versions` | List other revisions of the service's source template |
| POST | `/v1/services/{id}/template-upgrades` | Atomically apply another template revision while preserving generated secrets and explicit overrides |
| GET | `/v1/database-engines` | List built-in database drivers |
| POST | `/v1/environments/{id}/databases` | Provision a managed data service definition |
| GET/POST/DELETE | `/v1/backup-destinations…` | Manage encrypted S3-compatible destinations |

Repository creation accepts `trustedPublicKey` as an Ed25519 PEM or base64 raw
public key and `requireSignature` as a boolean. When a key is configured every
sync verifies the catalog manifest and signature before any database write;
`requireSignature` prevents registering the repository without a key.

Template previews execute the same variable resolution, mount conversion, and
safe-Compose validation as creation, but omit secret environment values,
commands, and inline file contents. Template instantiation is atomic: the Compose service, routes, and provenance
record either commit together or are all rolled back. Service detail responses
include redacted template key, version, checksum, base-domain provenance, and a
Compose-drift flag. They also include the tenant-scoped latest Swarm
`reconciliation` state, check timestamp, consecutive failure count, diagnostic
detail, and optional last automatic-repair timestamp;
the resolved template-variable set is encrypted with the service ID as
authenticated context and is never returned by the API.
| GET/POST | `/v1/databases/{id}/backups` | List or queue verified native backups |
| GET | `/v1/databases/{id}/restores` | List manual and verification restores |
| GET/DELETE | `/v1/databases/{id}` | Inspect or asynchronously delete a managed database |
| GET | `/v1/environments/{id}/databases` | List managed databases in an environment |
| GET/PUT/DELETE | `/v1/databases/{id}/backup-policy` | Manage interval scheduling and retention |
| POST | `/v1/database-backups/{id}/restore` | Restore after slug confirmation |
| POST | `/v1/database-backups/{id}/cancel` | Cancel a queued or running backup |
| POST | `/v1/database-restores/{id}/cancel` | Cancel a queued or running restore |
| GET | `/v1/databases/{id}/migrations` | List the latest 100 Dokploy data transfers |
| GET | `/v1/database-migrations/{id}` | Inspect a Dokploy native data transfer |
| POST | `/v1/database-migrations/{id}/cancel` | Request transfer cancellation |

Database credentials are returned once on creation and encrypted at rest.
Creating a database produces a normal Compose service; deploy it through the
same deployment endpoint, preserving one audit and rollback model.
The engine response includes `backupCapable`; native verified backup/restore is
currently available for PostgreSQL, MySQL, MariaDB, MongoDB, Redis, and Valkey.
Pass `destinationId` to a backup request or backup policy to upload through an
S3-compatible multipart client. Restores download to an isolated temporary
directory and verify the stored SHA-256 checksum before invoking native tools.
Every new local or S3 artifact is encrypted before storage with a random
per-backup AES-256-GCM data key; only the master-key-wrapped data key is kept in
PostgreSQL. Chunk authentication detects modification, reordering, and
truncation, and restores also verify the original plaintext checksum.
Redis and Valkey backups stream an authenticated RDB snapshot. Their restore
jobs briefly make the target a replica of an ephemeral, password-protected
source loaded from that snapshot, wait for full synchronization, and promote
the target back to primary. Schedule these destructive restores during a write
maintenance window.
Set `verifyRestore` on a backup policy to enqueue one restore drill after each
successful scheduled backup. Drills create a temporary isolated Swarm stack,
restore the verified artifact with fresh credentials, record the result as a
`kind: "drill"` restore, and always remove the temporary stack. They never
target the production database service.
Prometheus exposes the latest successful drill duration and an overdue signal
per database. A drill is overdue after twice the configured backup interval,
with a 24-hour minimum; the supplied alert rules page on that signal. Migration
metrics expose counts by engine/state, active age by database, latest terminal
duration, and the age of the latest failure. Together, backup age and drill
duration are the measured inputs for deployment-specific RPO and RTO
objectives.
