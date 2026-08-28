# HTTP API

All request and response bodies use JSON. Except for health, bootstrap, login,
SSO discovery/callback, and deploy hooks, endpoints require
`Authorization: Bearer <session-token>`. Use `X-Organization-ID` to select an
organization when a user belongs to more than one. This includes `/metrics`;
Prometheus should use a dedicated read-only service-account token.

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
| GET | `/v1/auth/sso/discover?email=…` | Discover providers by email domain |
| GET | `/v1/auth/sso/{providerID}/start` | Start Authorization Code + PKCE |
| GET | `/v1/auth/sso/callback` | Verify the ID token and create a session |
| GET/POST | `/v1/sso/saml-providers` | List or configure SAML identity providers |
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
`restore.drill.failed`, and `audit.archive.failed`. URLs and signing
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

SAML providers accept identity-provider metadata XML, allowed email domains,
email/name attribute mappings, a default role, and an opt-in
`allowIdpInitiated` flag. Dockyard generates an encrypted per-provider RSA key,
signs authentication requests with RSA-SHA256, validates signed assertions,
binds SP-initiated responses to one-time RelayState, and rejects assertion
replays. Register the provider metadata URL with the IdP.
Mandatory SSO can only be enabled after an OIDC or SAML provider is active.
Once enabled, local-password sessions cannot access that organization.
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
| PUT | `/v1/services/{id}/source` | Configure a Git/Dockerfile build, registry target, and credentials |
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

## Catalog and databases

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/templates` | List global and organization templates |
| POST | `/v1/templates/import/dokploy` | Import `template.toml` plus Compose YAML |
| POST | `/v1/templates/{id}/instantiate` | Create a service, secrets, files and routes |
| GET | `/v1/database-engines` | List built-in database drivers |
| POST | `/v1/environments/{id}/databases` | Provision a managed data service definition |
| GET/POST/DELETE | `/v1/backup-destinations…` | Manage encrypted S3-compatible destinations |
| POST | `/v1/databases/{id}/backups` | Queue a verified native backup |
| GET/DELETE | `/v1/databases/{id}` | Inspect or asynchronously delete a managed database |
| GET/PUT/DELETE | `/v1/databases/{id}/backup-policy` | Manage interval scheduling and retention |
| POST | `/v1/database-backups/{id}/restore` | Restore after slug confirmation |

Database credentials are returned once on creation and encrypted at rest.
Creating a database produces a normal Compose service; deploy it through the
same deployment endpoint, preserving one audit and rollback model.
The engine response includes `backupCapable`; native verified backup/restore is
currently available for PostgreSQL, MySQL, MariaDB, and MongoDB.
Pass `destinationId` to a backup request or backup policy to upload through an
S3-compatible multipart client. Restores download to an isolated temporary
directory and verify the stored SHA-256 checksum before invoking native tools.
Every new local or S3 artifact is encrypted before storage with a random
per-backup AES-256-GCM data key; only the master-key-wrapped data key is kept in
PostgreSQL. Chunk authentication detects modification, reordering, and
truncation, and restores also verify the original plaintext checksum.
Set `verifyRestore` on a backup policy to enqueue one restore drill after each
successful scheduled backup. Drills create a temporary isolated Swarm stack,
restore the verified artifact with fresh credentials, record the result as a
`kind: "drill"` restore, and always remove the temporary stack. They never
target the production database service.
Prometheus exposes the latest successful drill duration and an overdue signal
per database. A drill is overdue after twice the configured backup interval,
with a 24-hour minimum; the supplied alert rules page on that signal. Together,
backup age and drill duration are the measured inputs for deployment-specific
RPO and RTO objectives.
