# HTTP API

All request and response bodies use JSON. Except for health, bootstrap, login,
SSO discovery/callback, and deploy hooks, tenant endpoints require
`Authorization: Bearer <session-token>`. Use `X-Organization-ID` to select an
organization when a user belongs to more than one. Because `/metrics` reports
fleet-wide state, it accepts only the dedicated operator credential configured
with `DOCKYARD_METRICS_TOKEN`; tenant sessions and service-account tokens are
never accepted there.

JSON request bodies must use `application/json` or an `application/*+json`
media type such as `application/scim+json`; unsupported or missing media types
return 415. JSON is limited to 3 MiB, signed provider and template webhooks and
SAML form responses to 2 MiB, and uploaded ZIP source archives to 25 MiB.
Limit violations return 413 before application parsing or persistence.

`GET /healthz` is the unauthenticated liveness probe and only reports whether
the HTTP process can answer. `GET /readyz` is the unauthenticated readiness
probe; it performs a database ping with a two-second upper bound and returns
503 while PostgreSQL is unavailable. Dependency errors are logged server-side
but are not included in the response. Container health checks and smoke tests
use `/readyz` so traffic is sent only to a usable control plane.

Local password authentication is protected by PostgreSQL-backed fixed-window
limits shared by every controller replica: 300 total login submissions and 10
attempts per existing account per minute. Bootstrap is limited to five attempts
per minute. Password input is limited to 1,024 bytes, and encoded Argon2id cost,
salt, and output parameters are bounded before memory is allocated. OIDC/SAML discovery, login initiation, callback processing, SAML
metadata generation, and agent enrollment have global plus domain, provider,
or token limits before outbound discovery, XML/cryptographic processing, or certificate issuance.
Rejected requests return 429 with `Retry-After`; stored limiter keys are
SHA-256 digests rather than email addresses, provider IDs, or credentials.
Expired limiter state is pruned by the singleton hourly maintenance loop.
OIDC configuration bounds provider names, issuer and client identifiers,
secrets, and RFC-compatible scope tokens; `openid` is mandatory. SAML metadata
is limited to 1 MiB and provider/attribute identifiers have independent bounds
before XML or certificate processing.

Every response includes `X-Request-ID`. A printable caller-provided request ID
is preserved; otherwise the server generates a UUID. `GET /metrics` is a
Prometheus text endpoint covering HTTP requests, durable jobs and stale leases,
deployments, backups, restores, restore drills, durable artifact-cleanup backlog,
and operation durations. Named-volume restore counts carry a bounded `mode`
label (`online` or `offline`) in addition to status. Active restore age is
reported per service, volume, mode, and state; the latest failure age is
reported per service, volume, and mode. The supplied rules page immediately on a recent offline
restore failure and page when an offline restore remains active for 30 minutes.
Send
`Authorization: Bearer <metrics-token>` and omit
`X-Organization-ID`.

## Identity

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/auth/bootstrap` | Create the first organization owner |
| POST | `/v1/auth/login` | Exchange local credentials for a session |
| POST | `/v1/auth/logout` | Revoke the current session |
| PUT | `/v1/auth/password` | Change the caller's local password and revoke every other session |
| GET | `/v1/auth/mfa` | Read TOTP status and remaining recovery-code count |
| POST | `/v1/auth/mfa/enrollment` | Verify the current password and return a one-time TOTP secret and `otpauth://` URI |
| POST | `/v1/auth/mfa/enrollment/confirm` | Verify the first TOTP code, enable MFA, and return recovery codes once |
| DELETE | `/v1/auth/mfa` | Verify password plus TOTP/recovery proof and disable MFA |
| POST | `/v1/auth/mfa/recovery-codes` | Verify password plus TOTP/recovery proof and replace all recovery codes |
| GET | `/v1/me` | Return the current principal and role |
| GET | `/v1/authorization/effective-role?resourceType=…&resourceId=…` | Resolve inherited project/environment RBAC for a resource |
| GET | `/v1/sessions` | List the caller's active device sessions |
| DELETE | `/v1/sessions/{id}` | Revoke one of the caller's sessions |
| POST | `/v1/sessions/revoke-others` | Revoke every session except the caller's |

Password changes require the current password and a local interactive session.
The password update, revocation of every other session across organizations,
and audit event commit atomically; the current session remains valid. Logout
fails closed if the authenticated session cannot be deleted; it never
reports success while leaving the bearer token active. Service accounts do not
have interactive sessions and receive `403` from all session-management
routes, including logout. Logout, individual revocation, and bulk revocation
commit atomically with their tenant audit records. Each local, OIDC, or SAML
session is issued atomically with its login event, so a usable session cannot
exist without durable tenant audit evidence. An unscoped local login is
recorded in every organization that identity can enter; a federated login
remains IdP-tenant scoped.
Initial bootstrap creates the first user, organization, owner membership, and
bootstrap audit evidence in one transaction. Failed evidence leaves the
instance uninitialized and safely retryable.

Local login accepts `totpCode` or `recoveryCode` in addition to `email` and
`password`. Once MFA is enabled, a correct password without a proof returns
`mfa_required`; exactly one proof may be supplied. TOTP permits one 30-second
clock step in either direction, while a durable counter prevents reuse of an
accepted code. Recovery codes are normalized, stored only as SHA-256 digests,
and consumed transactionally with session issuance. TOTP secrets are encrypted
with the master key and bound to the user ID. Enrollment, enablement, disable,
recovery-code replacement, other-session revocation, and audit evidence use
atomic database transactions. The current local session is retained so a
successful security change cannot strand its caller.
The AI audit snapshot exposes only aggregate local-account and MFA enrollment
counts; it never exposes TOTP material, recovery-code digests, or user-level
enrollment details.
| GET | `/v1/members` | List organization members, roles, status, and SCIM ownership |
| PATCH | `/v1/members/{userID}` | Change a manually managed organization membership role |
| DELETE | `/v1/members/{userID}` | Remove a manually managed member and their scoped grants |
| GET/POST | `/v1/invitations` | List invitations or create a one-time, 1–30 day organization invitation |
| GET/DELETE | `/v1/invitations/{invitationID}` | Inspect or revoke an organization invitation |
| POST | `/v1/invitations/accept` | Publicly consume an invitation token and create or attach an identity |
| GET/PUT | `/v1/sso/settings` | Read or enforce organization-wide SSO |
| GET/POST | `/v1/service-accounts` | List or create scoped automation identities |
| POST | `/v1/service-accounts/{id}/rotate` | Revoke old tokens and issue a replacement |
| DELETE | `/v1/service-accounts/{id}` | Disable an automation identity |
| GET | `/v1/audit-events?beforeId=…&limit=…` | Read a descending audit page |
| GET | `/v1/audit-events/export?afterId=…&limit=…` | Export ascending NDJSON with integrity headers; responses are capped at 32 MiB and larger ranges must be paged with `afterId` |
| GET/PUT | `/v1/audit-retention` | Read or set the 30–3650 day retention policy |
| GET/POST | `/v1/audit-archives` | List or configure S3 Object Lock audit archives |
| GET/DELETE | `/v1/audit-archives/{id}` | Inspect or disable an archive without deleting retained objects |
| POST | `/v1/audit-archives/{id}/run` | Queue an archive batch or explicitly retry a failed batch |
| GET | `/v1/audit-archives/{id}/batches` | Inspect immutable archive delivery history and hashes |
| GET/PUT | `/v1/policy` | Organization maintenance mode and quotas |
| GET/PUT | `/v1/projects/{id}/policy` | Project maintenance mode and quotas |
| GET/PUT | `/v1/environments/{id}/policy` | Environment maintenance mode and quotas |
| GET/POST | `/v1/sso/oidc-providers` | List or configure OIDC providers |
| PUT | `/v1/sso/oidc-providers/{id}` | Update discovery settings and optionally rotate the encrypted client secret |
| POST | `/v1/sso/oidc-providers/{id}/enable` | Re-enable a disabled OIDC provider |
| DELETE | `/v1/sso/oidc-providers/{id}` | Disable an OIDC provider unless mandatory SSO depends on it as the final provider |
| GET | `/v1/auth/sso/discover?email=…` | Discover providers by email domain |
| GET | `/v1/auth/sso/{providerID}/start` | Start Authorization Code + PKCE |
| GET | `/v1/auth/sso/callback` | Verify the ID token and create a session |
| GET/POST | `/v1/sso/saml-providers` | List or configure SAML identity providers |
| PUT | `/v1/sso/saml-providers/{id}` | Refresh IdP metadata and mappings while preserving the SP key and entity ID |
| POST | `/v1/sso/saml-providers/{id}/enable` | Re-enable a disabled SAML provider |
| DELETE | `/v1/sso/saml-providers/{id}` | Disable a SAML provider unless mandatory SSO depends on it as the final provider |
| POST/DELETE | `/v1/sso/saml-providers/{id}/certificate-rotation` | Publish or cancel a pending SP signing certificate |
| POST | `/v1/sso/saml-providers/{id}/certificate-rotation/promote` | Promote the published certificate after the IdP imports it |
| GET | `/v1/auth/saml/discover?email=…` | Discover SAML providers by email domain |
| GET | `/v1/auth/saml/{providerID}/metadata` | Download signed-request SP metadata |
| GET | `/v1/auth/saml/{providerID}/start` | Start SP-initiated SAML login |
| POST | `/v1/auth/saml/{providerID}/acs` | Verify an assertion and create a session |
| GET/POST | `/v1/scim/tokens` | Inventory token metadata or create a one-time-visible, 1–365 day SCIM bearer token |
| DELETE | `/v1/scim/tokens/{id}` | Revoke a tenant-scoped SCIM bearer token |
| GET/POST | `/v1/source-credentials` | List or create encrypted HTTPS Git, SSH deploy-key, and OCI registry credentials |
| PUT/DELETE | `/v1/source-credentials/{id}` | Rotate write-only secret material in place or remove a credential |
| GET/POST | `/v1/custom-tls-certificates` | List secret-free certificate metadata or upload an encrypted certificate chain and private key |
| PUT/DELETE | `/v1/custom-tls-certificates/{id}` | Rotate with an optimistic revision or delete an unattached custom certificate |
| GET/POST/DELETE | `/v1/notification-endpoints…` | Manage durable webhook, Slack, SMTP, PagerDuty, and Opsgenie notifications |
| GET | `/v1/migration-resources?sourceOrganizationId=…` | Inspect persisted, secret-safe Dokploy application parity records |
| GET/POST | `/v1/clusters` | List or register remote Swarm clusters |
| PATCH | `/v1/clusters/{id}` | Activate, drain, or disable a cluster |
| POST | `/v1/clusters/{id}/enrollment-tokens` | Issue a 15-minute one-time agent token |
| POST | `/v1/clusters/{id}/agent-upgrades` | Queue a digest-pinned rolling agent upgrade |
| DELETE | `/v1/clusters/{id}/agent-upgrades/{commandId}` | Cancel an agent upgrade before execution starts |
| GET | `/v1/clusters/{id}/commands/{commandID}` | Inspect redacted asynchronous command state |
| GET/POST | `/v1/networks` | List or asynchronously provision local/remote managed Docker networks |
| GET/DELETE | `/v1/networks/{networkID}` | Inspect provisioning state or queue safe deletion of an unassigned network |
| POST | `/v1/networks/{networkID}/retry` | Requeue a terminally failed create without changing network identity or configuration |
| POST | `/v1/agent/enroll` | Exchange a token and CSR for a client certificate |
| POST | `/v1/agent/heartbeat` | Report agent and Swarm capacity over the mTLS listener |
| GET | `/v1/agent/commands/next` | Lease the next encrypted-at-rest Swarm command over mTLS |
| POST | `/v1/agent/commands/{id}/lease` | Renew a command lease using its fencing ID |
| POST | `/v1/agent/commands/{id}/complete` | Store a fenced command result |
| POST | `/v1/agent/rotate` | Issue a pending short-lived certificate; first successful authentication promotes it and revokes the old serial |

Service-account creation, token rotation, and disablement commit atomically
with their operator audit records. An audit failure cannot retain a newly
issued bearer token, revoke the prior token, or disable the identity.

Mandatory-SSO policy changes, OIDC/SAML provider creation and configuration
updates, and provider enable or disable transitions commit atomically with
their operator audit records. Provider updates invalidate outstanding login
state in the same transaction. The organization lock protects the
last-enabled-provider invariant, so concurrent changes cannot lock a tenant
out or leave an unaudited identity-policy state.

Source-credential rotation and deletion are serialized with every consumer. A
credential referenced by a queued or running deployment returns
`deployment_active`; a credential used by an active template-repository
synchronization returns `resource_busy`. In either case the credential remains
unchanged and the operator can retry after the operation reaches a terminal
state. Successful creation, rotation, and deletion commit atomically with their
audit event, including service-account attribution; an audit failure rolls back
the secret mutation.
| GET/POST/PUT/PATCH/DELETE | `/scim/v2/Users…` | SCIM 2.0 user provisioning |
| GET/POST/PUT/PATCH/DELETE | `/scim/v2/Groups…` | SCIM groups and group-to-role mapping |
| GET | `/scim/v2/Schemas…`, `/scim/v2/ResourceTypes…` | Public SCIM schema and resource-type discovery |

SCIM user resources are bound to the organization that provisioned them.
SCIM bearer tokens default to a 90-day lifetime, are shown only at creation,
and stop authenticating immediately after expiration or explicit revocation.
User and group collection reads support the SCIM `filter`, one-based
`startIndex`, and bounded `count` parameters (default and maximum 100), and
return the full matching `totalResults` independently of the current page.
User `externalId` values are preserved, unique within an organization, and can
be resolved with an `externalId eq` filter for stable directory correlation.
Group `displayName` and `externalId` filters are supported as well; group names
are limited to 120 bytes, external IDs to 1024 bytes, and each membership
mutation and resulting persisted group to 1000 users. Group mutations are
serialized per group so concurrent additive patches cannot bypass that bound.
SCIM create requests accept extension attributes within the normal bounded request body;
unsupported attributes are ignored so standard Entra and Okta user payloads do
not fail solely because they include optional schema fields.
User PATCH supports explicit paths and the standard pathless `replace` object
for `userName`, `displayName`, `externalId`, and `active`; shared global
identities cannot have tenant-owned profile fields changed across organizations.
Group PATCH likewise accepts pathless `replace` objects containing
`displayName`, `externalId`, `role`, and `members`. PATCH requests are limited
to 100 effective operations after pathless objects are expanded.
User and group `PUT` requests perform full resource replacement, including
group membership reconciliation, while preserving a group's internal role when
the identity provider omits that Orka-specific attribute.
User and group resources expose standard `meta.created`, `meta.lastModified`,
and weak `meta.version` values together with `Location` and `ETag` headers.
`PUT`, `PATCH`, and `DELETE` accept `If-Match` and reject stale versions with
`412 Precondition Failed`; omitting `If-Match` retains normal SCIM behavior.
Successful SCIM user and group creates, replacements, patches, and deletes are recorded in
the tenant audit log without copying profile fields or bearer credentials.
Deactivation removes access but retains that binding, so identity providers can
query and reactivate an inactive user. A tenant cannot PATCH a global user ID
that it does not own. Because email identities are shared across organizations,
SCIM rejects `displayName` changes while the identity is visible in another
organization; this prevents one tenant from rewriting another tenant's profile.
Organization administrators can manage manually provisioned members, while
only owners can assign or alter the owner role. Role changes and removals are
serialized per organization and cannot remove its last active owner. Members
owned by SCIM are read-only through the membership API so the identity provider
remains authoritative. Removing a member also removes their project and
environment grants and revokes federated sessions for that organization.
Membership role changes, member removal, and project/environment grant changes
commit atomically with their administrator audit evidence; an evidence failure
rolls back the complete RBAC transition, including grant and session cleanup.
Invitation tokens are returned only at creation and stored as SHA-256 digests.
Creating another invitation for the same organization and email revokes the
previous token. Creation, revocation, and one-time acceptance commit atomically
with their audit evidence; failed evidence leaves the previous invitation,
membership, and user state unchanged. New local identities
must set a password of at least 12 characters; organizations enforcing SSO can
pre-provision the identity without a local password, ready for OIDC or SAML
linking on first sign-in; any password submitted while accepting an SSO-only
invitation is discarded. Existing identities retain their current credentials.
Invitation acceptance and OIDC, SAML, and SCIM just-in-time provisioning use the
same organization-first identity lock order so concurrent enrollment cannot
create duplicate global identities or deadlock membership creation.

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
Policy creation and replacement commit atomically with operator audit evidence,
so a failed audit write cannot silently change maintenance or quota controls.

Notification endpoints support generic webhook, Slack-compatible payloads,
TLS SMTP (`starttls` or implicit `tls`), PagerDuty Events API v2, and the
Opsgenie Alerts API. SMTP passwords and provider integration keys are
encrypted and never returned. Generic webhook signing secrets are revealed
once. All providers use the same idempotent delivery records and retry queue
for `deployment.failed`, `service.stop.failed`, `service.schedule.failed`,
`backup.failed`, `restore.failed`, `restore.drill.failed`,
`database.migration.failed`, `network.provision.failed`,
`network.delete.failed`, `audit.archive.failed`, `ai.audit.failed`, and
`ai.finding.critical`. Offline named-volume failures use `restore.failed` and
include `mode`, `serviceId`, `volumeName`, and the snapshotted
`targetStorageNodeId`, so responders can identify the stopped workload and
intended recovery node. URLs and signing secrets are encrypted at rest. The secret is returned once at creation; generic
receivers can verify `HMAC-SHA256(timestamp + "." + rawBody)` from
`X-Dockyard-Timestamp` and `X-Dockyard-Signature-256`. Deliveries are
deduplicated per endpoint/event/resource and retried as leased durable jobs.
Endpoint creation and disablement commit atomically with their audit events;
failed evidence cannot retain encrypted credentials or cancel queued delivery.

Agent enrollment is disabled unless both `DOCKYARD_AGENT_CA_CERT` and
`DOCKYARD_AGENT_CA_KEY` (or their `_FILE` variants) are configured. The
enrollment token is stored only as a SHA-256 digest, expires after 15 minutes,
and is consumed atomically. Cluster creation, state/maintenance changes,
enrollment-token issuance, and deletion queueing commit atomically with their
operator audit events; failed evidence also rolls back command cancellation and
the deletion finalizer. The issued client certificate is bound to the cluster
ID and expires after seven days by default.
Heartbeat traffic is accepted only on the optional dedicated agent listener;
the client certificate must chain to the configured active/previous CA trust
bundle and its serial must match the cluster's latest enrollment. Enrollment,
heartbeat, and rotation responses return the authenticated trust bundle, the
active signing CA, and its SHA-256 fingerprint. Agents persist broadened trust
before atomically rotating to the active signer. Cluster list responses expose
`certificateAuthorityFingerprint` and a temporary
`pendingCertificateAuthorityFingerprint`, allowing operators to prove every
managed cluster converged before retiring the previous CA. See
`docs/agent-ca-rotation.md` for the required phased procedure.
Remote environments select a cluster with `clusterId` when they are created.
Application deploy, removal, logs, and node operations use encrypted-at-rest
commands claimed by the outbound agent. Expiring leases are retried and every
renewal/completion is fenced by a per-attempt UUID. Digest-pinned agent-upgrade
queueing and pre-execution cancellation commit with their operator audit events;
an evidence failure leaves no command or preserves the pending command.
Cluster responses also expose the last `capabilities` heartbeat document.
Protocol version 1 proves Compose-on-Swarm support and, when configured, the
observed Traefik edge service, public network, dynamic file-provider path, and
whether custom-certificate reconciliation is currently safe. An empty object
means an older agent has not reported capabilities and must be treated as
unsupported, never as an implicit edge provider.

Custom TLS certificate writes accept a leaf-first PEM certificate chain and a
matching unencrypted PEM private key. The leaf must have DNS SANs, server-auth
usage, a supported RSA/ECDSA/Ed25519 key, and more than 24 hours of validity.
Only certificate metadata is ever returned; both PEM values are encrypted with
resource-bound contexts and remain write-only. A route selects one with
`customCertificateId` and must leave `certificateResolver` empty. Hostname
coverage is checked transactionally. Route attachment and certificate rotation
queue a generation-fenced edge reconciliation; workload deployment waits until
the target generation is ready. Remote reconciliation proceeds only while the
agent reports a fresh, verified custom-certificate edge capability. Certificate
creation, key rotation, and deletion commit atomically with their audit events,
so failed evidence cannot retain or replace private-key material.

## AI auditing

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/ai/audit-snapshot` | Return a secret-free organization inventory to an auditor identity |
| POST | `/v1/ai/audit-runs` | Start an attributed audit run |
| POST | `/v1/ai/audit-runs/{id}/findings` | Upsert a structured finding by fingerprint |
| PATCH | `/v1/ai/audit-runs/{id}` | Complete or fail the caller's active run |
| GET | `/v1/ai/audit-runs` | List runs as an organization administrator |
| GET | `/v1/ai/audit-findings` | List the latest finding in every auditor/agent fingerprint lineage |
| GET | `/v1/ai/audit-runs/{id}/findings` | Review findings as an organization administrator |
| PATCH | `/v1/ai/audit-findings/{id}` | Acknowledge, resolve, or reopen a finding with an operator note |

The snapshot includes tenant-scoped maintenance and quota posture with current
resource counts. Operator-authored maintenance reasons are intentionally
excluded from the model boundary. It also includes effective audit retention
and redacted immutable-archive health: destination IDs, enabled state,
retention, event checkpoints/backlog, and latest batch status/timestamps.
Destination names, storage details, object keys, chain hashes, credentials,
and failure text are excluded. Public route metadata is included, and the
built-in deterministic baseline flags routes that accept plaintext HTTP.
Custom-certificate references, secret-free validity/attachment posture, and
the relevant edge reconciliation generations and states are included; PEM,
keys, certificate names/SAN inventories, ciphertext, and reconciliation errors
are excluded.
Enabled SAML providers expose only an opaque provider ID, certificate
configuration validity, and SP/IdP expiry timestamps; certificates, keys,
metadata, names, and domains remain excluded. Invalid/expired trust is a high
severity baseline finding, while expiry inside thirty days is medium severity.
Desired Compose definitions and latest successful effective runtime snapshots
are summarized as image-provenance counts per workload; image names, registry
paths, build contexts, commands, labels, and environment values are not
returned. The baseline reports malformed desired definitions, missing or
malformed runtime snapshots, mutable deployed images, and services missing
both an image and a build source. Mutable desired template tags alone are not
reported as deployed-image vulnerabilities.
Active and draining remote clusters whose reported agent runtime image is
missing or not digest-pinned produce a high-severity supply-chain finding.
Managed databases left in an error state produce a high-severity availability
finding independently of their backup posture.
Managed-network posture exposes only topology metadata, lifecycle state, and
the last safe state-update timestamp. Raw Docker/agent errors, Docker IDs,
MTU, and IPAM details are excluded. Failed provisioning and provisioning that
remains pending beyond fifteen minutes produce high-severity deterministic
findings.
Deployment-hook posture is aggregate-only and reports active, expiring,
expired-unrevoked, unused, and unused-for-more-than-thirty-days counts plus
oldest active/unused creation times. Tokens, hashes, names, URLs, service
assignments, and creator identities remain excluded. An active credential that
has never been used after thirty days produces a medium-severity cleanup
finding.
Identity posture also reports aggregate service-account counts whose current
credentials remain unused after thirty days, including the privileged subset
and oldest unused creation time. The deterministic baseline raises severity
when stale credentials belong to administrator or developer automation
identities; account names, token hashes, and individual identities remain
excluded.
Source-build posture similarly returns only source/build types, transport and
configuration booleans, artifact/checksum presence, and deployment provenance.
Repository URLs and refs, output image names, credential binding identifiers, artifact
details, and encrypted build configuration are excluded. The baseline detects
invalid transports, missing SSH trust credentials, missing drop artifacts,
undeployed source changes, and successful Git builds without a recorded commit.
Separate source-credential posture exposes an opaque inventory ID, credential
class, creation/last-rotation times, and tenant-scoped workload/status/catalog
reference counts. It excludes names, authorities, usernames, and encrypted
secrets; an unreferenced credential older than thirty days produces a cleanup
finding and a referenced credential older than 180 days produces a rotation
finding. Backup-destination posture applies the same secret-free timestamps
and lifecycle findings using database, volume, and audit-archive references;
object-store endpoints, buckets, prefixes, and credentials remain excluded.
The `signals30d` collection aggregates tenant-scoped deployment, database and
volume recovery, migration, audit archive, remote-agent command, commit-status,
notification, and prior AI-audit counts by status. With at least four
succeeded/failed outcomes, the deterministic baseline reports failure rates of
25% or greater and raises severity from medium to high at 50%; pending,
running, and cancelled outcomes are excluded.

Each run accepts at most 100 distinct finding fingerprints. Re-submitting an
existing fingerprint updates that finding without consuming another slot; a
fingerprint recurring in a later run by the same auditor identity and agent is
linked to its previous occurrence. Acknowledgements carry forward, while a
resolved finding reopens when it recurs. The API reports `previousFindingId`
and `occurrenceNumber` for this lineage. A new fingerprint after the limit
returns `409 ai_audit_finding_limit`.
Starting, completing, or failing a run commits atomically with audit evidence
attributed to the auditor service account. Starting a replacement run also
commits supersession of the previous run and any resulting failure
notifications in that transaction; an audit-write failure rolls all of those
changes back.
The current-findings endpoint accepts optional `disposition` (`active` selects
open and acknowledged findings) and `severity` filters plus a `limit` from 1
to 200 (default 100).

The first four endpoints require an `auditor` service account; the last four
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
Provider responses include the platform signing-certificate and effective IdP
trust expiry. Metadata updates reject expired, malformed, or not-yet-valid
signing material while accepting normal rollover metadata with multiple signing
certificates. Prometheus alerts thirty days before either trust boundary
expires.
SP signing-certificate rotation is two phase. Starting a rotation generates an
encrypted replacement key and adds only its signing certificate to the public
SP metadata while authentication requests continue using the active key. After
the IdP has refreshed that metadata, promote the replacement by sending the
provider name as `confirm`. Promotion atomically switches the key, removes the
pending certificate, and invalidates in-flight SAML requests. Starting,
promoting, and cancelling a rotation each commit atomically with their audit
event, so an audit failure rolls back the certificate transition. A pending
rotation can instead be cancelled without changing the active key.
Mandatory SSO can only be enabled after an OIDC or SAML provider is active.
Once enabled, local-password sessions cannot access that organization except
for its owner break-glass account.
Service-account tokens are shown once, stored as hashes, expire within 365
days, carry an organization role, support atomic rotation, and are attributed
separately from users in the audit log. Prometheus exposes the remaining
lifetime of each enabled account's current token using immutable organization
and account IDs so operators can rotate consuming secrets before expiry.
Non-revoked SCIM tokens expose the same seven-day operational expiry signal.
SCIM token creation and revocation commit atomically with the administrator
audit event, so an evidence failure cannot activate or revoke a provisioning
credential.
CI deployment-hook tokens follow the same bounded-expiry model, record their
last successful use, and expose expiry metrics keyed only by immutable
organization, service, and token IDs. Issuance and revocation commit atomically
with operator audit evidence, so an audit failure cannot activate a new hook or
revoke an existing one. Resource-finalizer metrics report active,
failed, and missing deletion jobs plus oldest deletion age without exporting
job payloads or failure text, including managed-network deletions. Managed
networks additionally expose aggregate lifecycle state by local/remote scope
and driver, plus per-network provisioning age for stalled-create alerts.
Provider-webhook creation and disablement likewise commit with their audit
records; encrypted signing secrets are never included in audit metadata.
Audit exports are ordered by immutable event ID. Each response includes
`X-Content-SHA256` for offline verification and `X-Next-After-ID` for resumable
pagination. The default retention is 365 days and is enforced even before an
organization saves a custom policy; workers prune hourly. Completed AI audit
runs follow the same period, except that the newest completed run in each
auditor/agent lineage is preserved and running audits are never pruned.
External archives require an HTTPS S3-compatible backup
destination whose bucket has Object Lock enabled. Workers upload batches with
COMPLIANCE retention and create a SHA-256 chain from each manifest to the
previous object. Pruning stops at the least-progressed enabled archive, so an
outage cannot silently erase unexported events. Failed ranges remain pinned
until an administrator retries them. Retention-policy changes, archive
destination creation or disablement, and manual archive queueing commit in the
same PostgreSQL transaction as their operator audit event; an evidence failure
rolls back the policy, destination, batch, and job changes.

## Workloads

| Method | Path | Purpose |
|---|---|---|
| GET/POST | `/v1/projects` | List or create projects |
| GET/POST | `/v1/projects/{id}/environments` | List or create environments |
| GET | `/v1/environments` | List active environments across the current organization for destination selection |
| GET/PUT/DELETE | `/v1/projects/{id}/grants…` | Manage per-user project roles |
| GET/PUT/DELETE | `/v1/environments/{id}/grants…` | Manage per-user environment roles |
| GET/POST | `/v1/environments/{id}/services` | List or create Compose services |
| GET/PATCH/DELETE | `/v1/services/{id}` | Read, revise, or asynchronously remove a service and stack (`?deleteVolumes=true` is explicit destructive cleanup); PATCH preserves encrypted variables when `environment` is omitted, while an explicit empty object clears them; revisions cannot race active deployments or remove a named volume while its backup policy exists, and deletion rejects active deployment, migration, backup, or restore work |
| PUT | `/v1/services/{id}/environment` | Move a non-database service to another environment on the same Swarm; both environments require developer access, while active operations, deleting parents, target quotas, and cross-cluster moves fail closed |
| POST | `/v1/services/{id}/storage-node-rebind` | After stopping the service and moving every named volume, confirm and audit its new Swarm node assignment |
| GET/PUT | `/v1/services/{id}/variables` | List configured variable names without values, or atomically add/rotate encrypted values; mutations create a new revision, reject active deployments, and become operator-owned overrides that survive later template upgrades |
| DELETE | `/v1/services/{id}/variables/{name}` | Delete one encrypted runtime variable without revealing any stored value |
| GET/POST | `/v1/tags` | List reusable organization-scoped tags or create one as an administrator |
| GET/PUT/DELETE | `/v1/tags/{id}` | Read or administratively rename/recolor/delete a tag; deletion removes all assignments |
| GET/PUT | `/v1/projects/{id}/tags` | Read or atomically replace a project's complete tag set (maximum 32) |
| GET/PUT | `/v1/services/{id}/tags` | Read or atomically replace a service's complete tag set (maximum 32) |
| GET/PUT | `/v1/services/{id}/networks` | Read or atomically replace up to 16 ready overlay-network assignments on the service's Swarm |
| PUT | `/v1/services/{id}/source` | Configure a Git or uploaded-ZIP application build, registry target, build mode, credentials, arguments, secrets, and submodules |
| PUT | `/v1/services/{id}/artifact-source` | Upload or replace an encrypted ZIP source (25 MiB compressed / 250 MiB expanded limits) |
| POST | `/v1/services/{id}/routes` | Add a Traefik route with optional path rewriting and regex redirect |
| GET/PUT/DELETE | `/v1/routes/{id}` | Inspect, replace, enable/disable, or remove a route; changes apply on the next deployment |
| GET/POST | `/v1/services/{id}/basic-auth-users` | List or add HTTP basic-auth identities protecting every enabled service route |
| PUT/DELETE | `/v1/services/{id}/basic-auth-users/{userId}` | Rotate/rename or remove a route basic-auth identity |
| POST | `/v1/services/{id}/deployments` | Enqueue a Swarm deployment |
| GET | `/v1/services/{id}/deployments` | Read deployment history |
| POST | `/v1/services/{id}/stop` | Persist stopped intent and asynchronously remove the Swarm stack while preserving named volumes; repeated requests are idempotent |
| POST | `/v1/services/{id}/start` | Persist running intent and enqueue the current Compose revision as a `start` deployment |
| GET/POST | `/v1/services/{id}/schedules` | List or create timezone-aware five-field cron commands for a Compose service |
| GET/PUT/DELETE | `/v1/services/{id}/schedules/{scheduleId}` | Inspect, replace, or remove a service schedule |
| POST | `/v1/services/{id}/schedules/{scheduleId}/executions` | Queue an immediate manual execution |
| GET | `/v1/services/{id}/schedule-executions` | Read immutable scheduled-command execution history and bounded output |
| POST | `/v1/services/{id}/schedule-executions/{executionId}/cancel` | Cancel a queued or running scheduled command |
| POST | `/v1/deployments/{id}/cancel` | Cancel a queued or running deployment |
| POST | `/v1/services/{id}/rollback` | Redeploy the latest successful digest-resolved snapshot; returns `409 rollback_unavailable` when no immutable snapshot exists |
| GET | `/v1/services/{id}/logs` | Read the latest 500 lines per Swarm service, with the aggregate response capped at 1 MiB and explicitly marked when truncated |
| GET | `/v1/services/{id}/volumes` | List mounted declared named volumes and their resolved Swarm names |
| GET/PUT/DELETE | `/v1/services/{id}/volume-backup-policies…` | Manage encrypted retained backup policy per named volume; deletion returns `409 volume_backup_policy_busy` while a backup or restore is active and preserves completed history |
| GET/POST | `/v1/services/{id}/volume-backups…` | List or queue named-volume backups; duplicate active requests return `409 backup_in_progress` |
| GET | `/v1/services/{id}/volume-restores` | List restore history, including snapshotted target node and offline mode |
| POST | `/v1/volume-backups/{id}/restore` | Queue a confirmed restore; `offline: true` requires a successfully stopped service and restores directly onto its assigned node without starting the workload; concurrent requests return `409 restore_in_progress` |
| GET | `/v1/services/{id}/deploy-tokens` | List CI deploy-hook credentials without secret material |
| POST | `/v1/services/{id}/deploy-tokens` | Create an expiring CI deploy hook |
| DELETE | `/v1/services/{id}/deploy-tokens/{tokenId}` | Revoke a CI deploy-hook credential |
| POST | `/v1/hooks/deploy/{token}` | Trigger a deployment from CI |
| GET/POST | `/v1/services/{id}/webhooks` | List or create provider webhook integrations |
| DELETE | `/v1/webhooks/{id}` | Disable a provider webhook integration |
| POST | `/v1/hooks/provider/{id}` | Verify a provider push event and deploy |

Operations that need running containers—database backup/restore/migration and
named-volume backup/online restore—return `409 service_stopped` while their
owning service is stopped. A named-volume restore explicitly submitted with
`offline: true` instead requires a completed stop operation, snapshots the
current storage-node assignment, and never restarts the workload. Scheduled
policies remain due and resume after the service is started; their schedule is
not silently advanced while stopped.

Manual deployment, service start/stop, rollback, and deployment cancellation
commit desired-state changes, immutable snapshots, worker jobs, cancellation
state, and operator audit evidence in one transaction. Audit persistence
failure therefore cannot launch, stop, roll back, or cancel Swarm work without
an attributable event; service-account requests remain separately attributed.
Route creation, replacement, and deletion likewise commit with their audit
event and any required edge-certificate reconciliation job.
Compose revisions, encrypted runtime environment replacement, application
build-source settings, encrypted build arguments/secrets, and uploaded source
artifacts also commit with their audit evidence. Failed evidence preserves the
previous revision and ciphertext instead of publishing an unattributed change.
Individual variable upserts and deletions include their revision and
secret-free variable names in that same atomic audit boundary; template-owned
key provenance rolls back with the ciphertext.
Tag creation, updates, deletion, and complete project/service assignment
replacement are also atomic with their operator audit records. Managed-network
provisioning, retry and deletion jobs, service network assignments, and service
environment moves use the same boundary: failed audit persistence rolls back
both the control-plane mutation and any queued network job.
First-time agent enrollment atomically consumes its one-time token, activates
the cluster certificate, and records the system audit event. Signed provider
webhooks likewise record replay protection, deployment snapshots, worker jobs,
pending commit status, and their system audit evidence in one transaction.
Dokploy native database-transfer admission commits the migration record and
worker job with its system audit evidence. Scheduled template-repository sync
finalization commits the fenced attempt status and system audit event together.

Service schedules accept standard five-field cron expressions (including
ranges, lists, steps, month/day names, and common `@hourly` through `@yearly`
descriptors) plus an IANA timezone. Commands run as `sh -lc` or `bash -lc`
in a one-shot Swarm job cloned from the selected running Compose service's
image, environment, networks, mounts, secrets, configs, placement, identity,
and resource limits. They are serialized
with deployment, stop, deletion, and volume operations by the service resource
key. Each invocation has a 1–86400 second timeout, 1 MiB output cap, durable
history, cancellation, and failure notification support. Non-idempotent
commands are never automatically retried after a worker lease expires. A
stopped or maintenance-blocked service keeps its due cursor unchanged.
Operator-created schedule definitions, updates, deletion, manual execution,
and execution cancellation commit with audit evidence. Audit failure preserves
the prior schedule and cannot enqueue or cancel a command job.

Route basic-auth passwords are 1–72 UTF-8 bytes, accepted only on create or
explicit rotation, bcrypt-hashed at cost 12, and never returned. Compiled Traefik labels remove
the inbound `Authorization` header before proxying. Route and credential
mutations are fenced while a deployment is active, and take effect only after
the next deployment. Credential creation, rotation/rename, and deletion commit
atomically with audit evidence; passwords and password hashes are excluded from
that evidence.

Organization owners and administrators manage scoped grants. A project grant
is inherited by all of its environments, while a more privileged environment
grant applies within that environment. Scoped roles elevate a member's
organization role; they never reduce an owner or administrator's authority.
Service accounts continue to use their organization-scoped role.

Project, environment, and Compose-service creation commit atomically with the
operator audit event. An audit persistence failure rolls back the entire new
resource, including encrypted service configuration, and service-account
automation is attributed separately from users.

Project and environment deletion is asynchronous and cascades through service
stack finalizers. Cascades lock every child database and service, reject active
deployment or data work (including databases without a linked Compose service),
and prevent concurrent child creation from escaping the deletion. Parent and
child deletion markers, all finalizer jobs, and the operator audit event commit
together; failed audit evidence rolls back the complete cascade request.
Service deletion also serializes with revisions, source and uploaded-artifact
changes, route creation, deployment-hook issuance, and provider-webhook
creation; once deletion wins, those mutations return not found.
Service and managed-database deletion queueing commit the deletion marker,
finalizer job, and operator audit evidence atomically. An audit failure leaves
the service active and does not enqueue destructive work.
Repeating a delete safely resumes failed finalizers. Cluster
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

Controller and agent Docker subprocesses retain at most 1 MiB of combined
stdout/stderr. Commands whose output is parsed fail closed when that boundary
is reached; verbose build and service-log output is explicitly marked as
truncated so successful work is not discarded merely for being noisy.

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
| GET | `/v1/templates` | Cursor-page templates with redacted inputs, safety classification, and current deployability (`limit` 1-200, opaque `cursor`, `nextCursor`) |
| GET/POST | `/v1/template-repositories` | List or register organization GitHub catalogs, optionally using an encrypted GitHub token credential |
| PATCH | `/v1/template-repositories/{id}` | Pin or rotate a repository signing key, private-access credential, signature policy, and automatic sync interval |
| POST | `/v1/template-repositories/{id}/sync` | Durably queue a bounded Dokploy-compatible catalog refresh |
| POST/DELETE | `/v1/template-repositories/{id}/webhook-secret` | Create or rotate the one-time GitHub webhook secret, or disable webhook refresh |
| POST | `/v1/hooks/template-repositories/{id}` | Authenticate a GitHub push delivery and queue replay-safe catalog refresh |
| DELETE | `/v1/template-repositories/{id}` | Remove a catalog and its template entries |
| POST | `/v1/templates/import/dokploy` | Import `template.toml` plus Compose YAML |
| POST | `/v1/templates/{id}/preview` | Validate overrides and return secret-free service, route, environment-key, and managed-file-count topology |
| POST | `/v1/templates/{id}/instantiate` | Create a service, encrypted secrets, files and routes; accepts declared `variables` overrides |
| GET | `/v1/services/{id}/template-versions` | List other revisions of the service's source template |
| POST | `/v1/services/{id}/template-upgrades` | Atomically apply another template revision while preserving generated secrets and explicit overrides |
| GET | `/v1/database-engines` | List built-in and trusted external database drivers with capabilities |
| POST | `/v1/environments/{id}/databases` | Provision a managed data service definition |
| GET/POST/PUT/DELETE | `/v1/backup-destinations…` | Manage and rotate credentials for encrypted S3-compatible destinations |

Backup-destination rotation is rejected with `resource_busy` while a database
or volume backup/restore or immutable audit-archive batch is running. Worker
operation start and destination mutation share a PostgreSQL advisory fence, so
a race either adopts the new tested credentials or leaves the rotation pending
for the operator to retry; it cannot begin with a silently superseded secret.
Queued operations are not blocked and use the new credentials when they start.
Deletion is rejected with `resource_not_empty` while any database policy,
database or volume artifact, volume policy, queued artifact cleanup, or audit
archive still references the destination. The reference check and deletion run
under the same worker fence instead of exposing database constraint errors.
Successful destination creation, rotation, and deletion commit atomically with
their operator audit events, so an audit persistence failure cannot leave an
unattributed recovery-credential change.

Repository creation accepts `trustedPublicKey` as an Ed25519 PEM or base64 raw
public key and `requireSignature` as a boolean. When a key is configured every
sync verifies the catalog manifest and signature before any database write;
`requireSignature` prevents registering the repository without a key.
Repository creation, trust/credential settings, webhook-secret rotation,
manual and webhook-triggered sync requests, and deletion commit atomically
with their audit evidence. Failed evidence cannot publish trust changes,
retain webhook secrets, enqueue a refresh, consume a delivery ID, or remove a
catalog.

Template previews execute the same variable resolution, mount conversion, and
safe-Compose validation as creation, but omit secret environment values,
commands, and inline file contents. Template instantiation is atomic: the Compose service, routes, and provenance
record and operator audit evidence either commit together or are all rolled
back. Template import and in-place upgrades also commit with their audit
evidence, including every Compose, environment, route, and provenance change.
Service detail responses
include redacted template key, version, checksum, base-domain provenance, and a
Compose-drift flag. They also include the tenant-scoped latest Swarm
`reconciliation` state, check timestamp, consecutive failure count, diagnostic
detail, and optional last automatic-repair timestamp;
the resolved template-variable set is encrypted with the service ID as
authenticated context and is never returned by the API.
| GET/POST | `/v1/databases/{id}/backups` | List or queue verified native backups; duplicate active requests return `409 backup_in_progress` |
| GET | `/v1/databases/{id}/restores` | List manual and verification restores |
| GET/DELETE | `/v1/databases/{id}` | Inspect or asynchronously delete a managed database |
| POST | `/v1/databases/{id}/driver-rebind` | Confirm and audit adoption of the currently installed driver identity |
| GET | `/v1/environments/{id}/databases` | List managed databases in an environment |
| GET/PUT/DELETE | `/v1/databases/{id}/backup-policy` | Manage interval scheduling and retention |
| POST | `/v1/database-backups/{id}/restore` | Restore after slug confirmation; concurrent requests return `409 restore_in_progress` |
| POST | `/v1/database-backups/{id}/cancel` | Cancel a queued or running backup |
| POST | `/v1/database-restores/{id}/cancel` | Cancel a queued or running restore |
| GET | `/v1/databases/{id}/migrations` | List the latest 100 Dokploy data transfers |
| GET | `/v1/database-migrations/{id}` | Inspect a Dokploy native data transfer |
| POST | `/v1/database-migrations/{id}/cancel` | Request transfer cancellation |

Queued database backup, restore, and migration cancellation updates the
operation record, worker job, cancellation timestamp, and operator audit event
in one transaction. Failed audit evidence leaves both the operation and its job
cancellable. Named-volume backup and restore cancellation has the same atomic
guarantee.

Database backup and restore creation commit the operation, worker job, and
operator audit evidence in one transaction. Backup-policy creation, updates,
and deletion use the same boundary. If audit persistence fails, no recovery job
is queued and the previous policy remains intact. User and service-account
callers retain distinct audit attribution.
Named-volume backup/restore creation and volume-policy updates/deletion provide
the same guarantee, including rollback of storage-node binding and queued jobs.

Database credentials are returned once on creation and encrypted at rest.
Creating a database produces a normal Compose service; deploy it through the
same deployment endpoint, preserving one audit and rollback model. The service,
database record, and creation audit event commit together, so failed audit
evidence cannot leave an unattributed credential-bearing workload. Database
records expose `driverSource` and, for external drivers, the bound
`driverArtifactDigest`; recovery workers reject a different artifact. An
administrator can rebind only after typing the database slug and only while no
backup, restore, or migration job is queued or running for it. The identity
change and its before/after digests are committed with one audit event.
On first deployment, every Compose service with a named volume is assigned a
`storageNodeId`; managed databases use the same mechanism. Dockyard discovers
the node for a pre-existing running stack or selects a ready node for a new
stack, persists the assignment, and injects a `node.id` placement constraint
into deployments, rollbacks, and reconciliation snapshots. It refuses
ambiguous legacy stacks spread across nodes and rejects conflicting
caller-supplied node identity constraints. This fails unavailable after node
loss instead of silently starting against a new, empty local volume; restoring
or deliberately relocating that volume remains an explicit operator recovery
action.

Storage-node rebinding never copies data. Stop the service and wait for its
stop job to succeed, then either copy every stack volume onto the replacement
node before rebinding or rebind first and queue one
`restore-volume-offline BACKUP_ID SERVICE_SLUG` operation per named volume.
Offline restores mount only the assigned target volume and keep the workload
stopped, so application initialization cannot race recovery.
Only an administrator can perform this operation. The transaction rejects a
running, deleting, unassigned, or busy service, updates a linked managed
database atomically, and records the old and new node IDs in the audit log.
Before committing, the controller verifies that the target belongs to the
service's local or remote Swarm and is currently ready and active; an
unreachable node inventory fails closed.
Start the service only after the rebind and every required copy or offline
restore succeeds.
The engine response includes a structured `engines` collection with each
driver's `name`, `defaultVersion`, `source` (`built-in` or `external`),
optional SHA-256 `artifactDigest`, `backupCapable`, and `backupExtension`.
The digest is present for external executables; their filesystem paths are
never exposed. The legacy `items` and `backupCapable` name lists remain available for
API compatibility. Verified engine-specific
backup/restore is currently available for PostgreSQL, MySQL, MariaDB, MongoDB,
Redis, Valkey, libSQL, ClickHouse, Qdrant, and Meilisearch.
Pass `destinationId` to a backup request or backup policy to upload through an
S3-compatible multipart client. Destination endpoints must be HTTP(S) origins
with valid DNS/IP hosts and TCP ports; credentials, paths, queries, and
fragments are rejected. Destination names, regions, buckets, prefixes, and
credentials have field-specific size limits, and control characters are not
accepted in credential material. Restores download to an isolated temporary
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
Qdrant backups create one authenticated native snapshot per collection, stream
the snapshots into a single manifest-bearing archive, and restore each
collection through Qdrant's snapshot upload API. No server-local backup path or
shared database volume is required.
Meilisearch backups stream index definitions, settings, documents, and API-key
definitions into a portable logical archive. Restore waits for every
asynchronous Meilisearch task and preserves key UIDs; API key values remain
stable when the managed database's master key is preserved.
libSQL backups use sqld's transactionally consistent streaming SQL dump and
restore it through a long-lived Hrana transaction. Schema objects, triggers,
views, indexes, row IDs, and binary values are covered without direct access to
the database volume.
ClickHouse backups store UUID-free `SHOW CREATE` definitions and each table's
Native-format data in one archive. Materialized views with private storage are
preserved without archiving their hidden internal tables. Because tables are
streamed individually, quiesce writes when cross-table point-in-time
consistency is required.
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
