# AI-first platform auditing

Dockyard includes a small, purpose-built audit runner instead of granting a
general autonomous agent access to the Swarm manager. The runner receives a
secret-free inventory snapshot, calls any OpenAI-compatible model endpoint,
and writes structured, deduplicated findings back to Dockyard.

## Runtime choice

The built-in `dockyard ai-auditor` is the default. It is a single Go binary,
has no shell or Docker socket, runs with a read-only filesystem, and its
`auditor` service-account role cannot use normal workload mutation APIs.

[Hermes Agent](https://github.com/NousResearch/hermes-agent) is useful when an
operator needs an interactive, general-purpose assistant, memory, or messaging
gateways. It is not the default platform auditor because its terminal and tool
surface is intentionally much broader. Integrate it through the same auditor
API and keep its service account separate; never mount the Docker socket.

[9Router](https://github.com/decolua/9router) is supported as an optional
OpenAI-compatible model gateway. It can be imported from the example template
repository in this tree or deployed separately. Pin its images before
production use and put its dashboard behind SSO; provider OAuth tokens and API
keys make it a privileged service.

## Trust model

- Create a service account with role `auditor`. It can authenticate but has no
  viewer/developer/admin rank and therefore cannot invoke normal resource APIs.
- `GET /v1/ai/audit-snapshot` excludes Compose content, environment values,
  database config, credentials, backup payloads, and secret material.
- Inventory records use dedicated allowlisted AI projections rather than the
  normal API structs. Project descriptions, raw placement selectors, cluster
  labels/capacity maps, audit metadata and addresses, and any future API fields
  remain excluded unless they receive a separate model-boundary review.
- Core inventory, route, and workload-provenance projections use a fixed
  number of tenant-scoped queries rather than querying once per project,
  environment, or service, so audit database load scales with returned rows.
- Project and service inventory include organization-authored tag names for
  operational grouping. Tag colors and assignment timestamps are excluded from
  the model boundary.
- Desired Compose and the latest successful effective runtime snapshot are
  reduced to per-workload counts: total containers, digest-pinned images,
  mutable image references, build-only services, and services missing both
  image and build input. Image names, registry paths, build contexts, commands,
  labels, and all other Compose values remain excluded. Missing, malformed, or
  mutable successful runtime snapshots produce deterministic supply-chain
  findings; mutable desired template tags alone do not.
- Source-build posture exposes only the source/build type, repository transport
  class, credential/configuration booleans, submodule use, artifact/checksum
  presence, and whether a successful deployment plus Git commit provenance
  exists after the current source input. Repository URLs and refs, image names,
  credential IDs, artifact names and digests, and encrypted build configuration
  remain excluded.
- The snapshot includes per-database backup policy and restore-drill posture,
  plus the logical names of declared Compose volumes that are actually mounted
  by a service. Bind mounts, tmpfs, anonymous volumes, and unused declarations
  are excluded, allowing the baseline to identify persistent named volumes
  with no backup policy at all. Named-volume posture includes the latest
  restore state, whether it ran offline, and its snapshotted target node so an
  auditor can distinguish routine rehearsal from relocation recovery. It also
  includes the installed database-driver
  catalog with default versions, built-in or
  external provenance, executable SHA-256 digest, and backup capability,
  enabled SSO provider counts,
  notification coverage, and template repository
  signing/synchronization posture so findings can identify concrete gaps. It
  also reports each service's desired and latest deployed revision plus every
  tenant-owned durable worker job, grouped by kind with pending age and running
  lease-heartbeat age. This includes deployments, recovery and migration work,
  notifications, commit statuses, immutable audit archives, and deletion
  finalizers. Resource-policy posture includes
  active maintenance scopes, configured quota limits, and current usage while
  excluding operator-supplied maintenance reasons. Each cluster exposes its
  reported agent runtime image, and the latest agent upgrade includes its
  immutable target, state, attempt count, deadline, and overdue flag, but never
  its encrypted command, result, or raw failure text. Pending and leased
  outbound agent commands are grouped by cluster and kind with due-pending and
  expired-lease counts and timestamps, while their encrypted payloads, results,
  errors, and lease identities remain excluded.
  Reconciliation posture includes only state, failure count, and timestamps;
  raw Docker and agent detail stays outside the model boundary. Queue scoping
  follows validated resource relationships; job payloads, errors, worker names,
  and another organization's jobs are never included.
- Thirty-day operational signals contain only tenant-scoped counts by
  operation kind and status. The deterministic baseline reports a fleet-level
  reliability finding once at least four terminal operations exist and at
  least 25% failed; severity becomes high at 50%. Pending, running, and
  cancelled work is excluded from the denominator.
- Finalizer posture reports tenant-scoped counts of projects, environments,
  services, and clusters awaiting deletion, their oldest request time, deletion
  job states, and resources with no active finalizer. Job payloads, Swarm
  output, and raw failure text remain excluded. Failed or missing finalizers are
  reported immediately; otherwise deletion pending beyond fifteen minutes is
  reported as stalled.
- Audit-log posture reports the effective retention period, enabled and
  disabled immutable archive counts, the tenant's current maximum event ID,
  and per-destination checkpoint, backlog, and latest batch status/timestamps.
  Destination names, storage configuration, object keys, chain hashes,
  credentials, and delivery errors remain outside the agent boundary.
- Public route inventory includes only routing metadata. The deterministic
  baseline reports any Traefik route that permits plaintext HTTP so operators
  can enable certificate-backed TLS or explicitly retire the exposure.
  Custom-certificate references, certificate validity windows/revisions and
  attachment counts, plus relevant edge-reconciliation generations and states
  are included. The deterministic baseline reports expired, not-yet-valid, and
  soon-expiring certificates; active-route expiry is raised above unused
  inventory. It also reports failed reconciliation immediately, pending state
  older than five minutes, a ready target with mismatched desired/applied
  generations, and an enabled custom-certificate route whose local or remote
  edge target is missing. Certificate names, SAN inventories, PEM chains,
  private keys, ciphertext, and reconciliation error strings remain outside
  the model boundary.
- Delivery and storage integration posture exposes only opaque webhook and
  service IDs, webhook provider/enabled state, opaque backup-destination IDs,
  TLS state, creation/last-rotation times, and database/volume/audit-archive
  reference counts. Webhook names, branches and secrets plus object-store
  endpoints, buckets, prefixes, and credentials remain outside the model
  boundary. The deterministic baseline reports plaintext destinations, unused
  destinations older than thirty days, and referenced credentials not rotated
  for more than 180 days.
- Source-credential posture exposes only opaque IDs, credential class,
  creation/last-rotation times, and workload/status/catalog reference counts. Credential
  names, Git or registry authorities, usernames, and encrypted material remain
  excluded. Unreferenced credentials older than thirty days produce a
  deterministic cleanup finding.
- Dokploy migration posture is grouped by source organization and reports
  imported versus unresolved resources plus successful native database
  transfers. Up to 200 unresolved parity records include their source kind,
  identifier, and manual-conversion reason; source metadata and encrypted
  transfer credentials never enter the snapshot.
- Identity posture is aggregate-only: active and disabled membership counts by
  role, active local/OIDC/SAML sessions, active and soon-expiring service
  accounts, auditor accounts, service-account credentials unused for more than
  thirty days (including the privileged subset), active SCIM token count/age, pending and expired
  invitation counts, project/environment grant counts, redundant grant counts,
  SCIM group and membership counts, and pending SAML certificate rotation
  count/age. Invitation email addresses and tokens, scoped user identities, and
  SCIM group names and external IDs never enter the snapshot. The deterministic
  baseline flags pending privileged invitations, unrevoked expired invitations,
  stale unused service-account credentials, and scoped grants that do not raise
  effective access. Enabled SAML providers
  additionally expose only their opaque ID, combined certificate-configuration
  validity, and SP and IdP trust expiry timestamps. Certificates, private keys, IdP metadata,
  provider names, domains, and user identities,
  session metadata, token hashes, and provider configuration remain excluded.
- Deployment-hook posture reports only aggregate active, expiring, expired,
  never-used, and never-used-for-more-than-thirty-days token counts plus the
  oldest active and oldest unused credential creation times.
  Token names, hashes, URLs, service assignments, and creator identities remain
  outside the model boundary. Expiring, unrevoked expired, and stale never-used
  credentials produce deterministic rotation and cleanup findings.
- Auditors may only create runs, add findings to their own active runs, and
  complete those runs. Administrators read results.
- AI output is advisory. It never becomes a deployment, shell command, policy
  change, or remediation without a separate human-approved workflow.
- Organization administrators can acknowledge, resolve, or reopen individual
  findings with an optional operator note. These triage changes are
  tenant-scoped and enter the platform audit log; auditor identities cannot
  alter disposition.
- The console's current-findings review can filter the latest lineage state by
  disposition and severity, and exposes resource identity, remediation, and
  bounded structured evidence before an operator acknowledges or resolves it.
- A recurring fingerprint from the same auditor identity and agent carries an
  acknowledged disposition and its operator context into the next run. A
  finding that reappears after resolution is reopened automatically, linked to
  the prior occurrence, and shown with its occurrence count.
- The current-findings view selects only the newest occurrence in each
  auditor/agent fingerprint lineage, so administrators can review active work
  across runs without older occurrences obscuring the present state.
- Completed run history follows the organization's audit-retention period
  (365 days by default). The newest completed run in every auditor/agent
  lineage is retained even after that period so the current-finding view does
  not silently lose its last known state; running audits are never pruned.
- Notification endpoints can subscribe to `ai.finding.critical`. Delivery is
  queued transactionally for a new critical fingerprint, a same-run escalation
  to critical, or a critical recurrence after resolution. Unchanged open or
  acknowledged critical findings do not alert again on every scheduled run.
- Snapshot strings are explicitly treated as untrusted data. The built-in
  runner bounds the serialized snapshot, model responses, and finding counts, validates every structured
  field, and rejects oversized evidence before submitting results. It retains
  the complete snapshot for deterministic rules, then partitions model input
  into deterministic 512 KiB JSON chunks. Organization and generation context
  accompany every chunk, array entries are never split, and explicit chunk
  metadata tells the model not to infer that omitted sections are absent. All
  chunks must succeed for the run to complete. Duplicate model findings are
  merged by resource identity and the highest reported severity is retained;
  the run scope and summary record the chunk count. The API
  independently enforces the 100-finding limit under concurrent submissions;
  third-party agents cannot bypass the bound, while they may update an existing
  fingerprint without consuming another slot.
- Before calling the model, the built-in runner records a bounded deterministic
  safety baseline for missing, disabled, or overdue backups and restore drills,
  including mounted named volumes with no policy,
  managed databases left in an error state, active maintenance scopes,
  near-capacity quotas, missing owners, disabled
  mandatory SSO, invalid or soon-expiring SAML trust, stale cluster heartbeats,
  missing or mutable active-agent images, expiring agent certificates,
  expiring service-account and deployment-hook credentials, stale SCIM credentials,
  unrevoked expired deployment hooks, abandoned source credentials, referenced source
  credentials not rotated for more than 180 days, agent identities signed
  by a non-active CA, lingering dual-trust rollovers, stalled tenant queues or
  stale running-job lease heartbeats, unclaimed remote commands, expired remote
  command leases that are not recovering,
  notification coverage gaps, unavailable, unbound, mismatched, or
  recovery-incapable database drivers, successful database recovery evidence
  without digest-pinned utility images, unhealthy reconciliation, unsigned,
  failed, never-synchronized, or stale catalogs, undeployed desired revisions, and
  incomplete Dokploy migrations. Failed offline named-volume recovery and
  recovery that remains queued or running for more than thirty minutes are
  critical deterministic findings even when the backup policy was later removed.
  It also reports a missing immutable audit
  archive, a failed latest archive delivery, or tenant events left unarchived
  for more than five minutes, backup destinations that permit plaintext
  object-store traffic, public routes that permit plaintext HTTP, custom TLS
  validity risks, and missing, failed, stalled, or generation-inconsistent
  edge certificate reconciliation, along with malformed workload definitions,
  successful deployments without immutable runtime snapshots, mutable deployed
  images, and services without an image or build source. Invalid source
  transports, SSH sources without pinned-host credentials, missing uploaded
  artifacts, undeployed source changes, and successful Git builds lacking
  commit provenance are also deterministic. Elevated 30-day failure rates
  across deployments, database and volume recovery operations, migrations,
  audit archives, remote agent
  commands, commit-status callbacks, notification delivery, and prior AI
  audits are surfaced even when a resource's latest individual state has
  recovered. Failed, missing, and stalled deletion finalizers are also surfaced
  even though deleting resources are excluded from active workload inventory.
  Managed-network inventory includes Swarm scope, lifecycle state, safe update
  time, and attached network names. Failed provisioning and provisioning that
  remains pending beyond fifteen minutes produce deterministic findings;
  stalled network deletion finalizers are covered separately. Raw Docker or
  agent failure text, Docker IDs, MTU, and IPAM configuration remain outside
  the model boundary.
  These findings survive a model gateway
  failure; the run remains marked failed so operators can distinguish
  baseline-only output from a completed model review.
- Each run records agent name/version, model, scope, timestamps, summary, and
  structured findings. Lifecycle transitions also enter the normal audit log.

## Deploy on Swarm

Create separate short-lived `auditor` service accounts for the security and
reliability agents. Store both tokens and the model gateway key in mode-0600
non-symlink files, then use the supplied fail-closed installer:

```sh
dockyardctl create-service-account '{"name":"security-auditor","role":"auditor","expiresInDays":30}'
dockyardctl create-service-account '{"name":"reliability-auditor","role":"auditor","expiresInDays":30}'
```

Each command returns its token once. Save it in the corresponding file below;
do not reuse either token for the other auditor.

```sh
export DOCKYARD_AI_SECURITY_AUDITOR_TOKEN_SECRET=dockyard_ai_security_auditor_token_v1
export DOCKYARD_AI_RELIABILITY_AUDITOR_TOKEN_SECRET=dockyard_ai_reliability_auditor_token_v1
export DOCKYARD_AI_API_KEY_SECRET=dockyard_ai_api_key_v1
export DOCKYARD_AI_SECURITY_AUDITOR_TOKEN_FILE=/secure/dockyard/security-auditor-token
export DOCKYARD_AI_RELIABILITY_AUDITOR_TOKEN_FILE=/secure/dockyard/reliability-auditor-token
export DOCKYARD_AI_API_KEY_FILE=/secure/dockyard/model-gateway-key
export DOCKYARD_IMAGE='registry.example/dockyard@sha256:...'
export NINEROUTER_IMAGE='decolua/9router@sha256:...'
export HEADROOM_IMAGE='ghcr.io/headroomlabs-ai/headroom@sha256:...'
export NINEROUTER_STORAGE_NODE_ID="$(docker info --format '{{.Swarm.NodeID}}')"
export DOCKYARD_CONTROL_PLANE_URL='https://dockyard.example.com'
export DOCKYARD_AI_MODEL='provider/model-name'

DOCKYARD_INSTALL_DRY_RUN=true scripts/install-ai-auditors.sh
scripts/install-ai-auditors.sh
```

The installer rejects mutable or unavailable images, invalid endpoint/model
configuration, unsafe secret files, and a missing, drained, or unavailable
9Router storage node before it mutates Swarm. It creates only absent secrets,
requires explicit `DOCKYARD_REUSE_EXISTING_SECRETS=true` for rotation, deploys
with registry credentials, and verifies all four services use the requested
digests and remain converged for the configured stability window. It then
streams each auditor token separately over standard input to the immutable
candidate image and verifies a fresh completed run from its exact agent name.
This proves that two independently authenticated agents ran; neither container
can impersonate the other or read the other's history. Tokens are never placed
in process arguments or environment variables. Set
`DOCKYARD_AI_VERIFY_TIMEOUT` to a value from 1 through 3600 seconds when the
default 15-minute model-run window is unsuitable. The installer fails closed
if either named run does not complete; `DOCKYARD_INSTALL_SKIP_WAIT=true` is the
explicit asynchronous deployment escape hatch and skips both convergence and
run verification.

Docker secrets are immutable. To rotate a credential, create a new versioned
secret, update `DOCKYARD_AI_SECURITY_AUDITOR_TOKEN_SECRET`,
`DOCKYARD_AI_RELIABILITY_AUDITOR_TOKEN_SECRET`, or
`DOCKYARD_AI_API_KEY_SECRET`, redeploy the stack, verify both auditors complete
a run, and only then remove the previous secret. External secret names may
change while their container paths remain stable.
Deployments created before the identity split must provision both new token
secrets; the former shared `DOCKYARD_AI_AUDITOR_TOKEN_SECRET` is intentionally
not accepted as a fallback because that would silently preserve impersonation.
9Router stores provider configuration in a node-local volume. The manifest
therefore requires `NINEROUTER_STORAGE_NODE_ID` and constrains the gateway to
that exact node. A node outage remains visible as unavailability instead of
starting 9Router against an unrelated empty volume; move or restore the volume
explicitly before changing this value.

### Back up and restore 9Router

9Router configuration can contain provider credentials, so its node-local
volume is backed up as an authenticated AES-GCM stream through a one-shot Swarm
service on the storage node. Supply a short-lived presigned PUT URL in a
mode-0600 file, a separately escrowed 32-byte base64 key, a non-secret durable
object reference, and the same Ed25519 recovery-signing key used for control
plane recovery:

```sh
openssl rand -base64 32 | tr -d '=\n' > /secure/dockyard/ai-backup-key
chmod 0600 /secure/dockyard/ai-backup-key /secure/dockyard/ai-backup-put-url
export DOCKYARD_AI_BACKUP_KEY_FILE=/secure/dockyard/ai-backup-key
export DOCKYARD_AI_BACKUP_URL_FILE=/secure/dockyard/ai-backup-put-url
export DOCKYARD_AI_BACKUP_OBJECT_REF=s3://recovery/orka/9router-2026-08-31.enc
export DOCKYARD_RECOVERY_SIGNING_KEY_FILE=/secure/dockyard/recovery-signing-key.pem
scripts/backup-ai-gateway.sh /secure/backups/9router-2026-08-31
```

The backup command verifies the deployed image and volume binding, stops the
gateway, uploads the encrypted archive from its owning Swarm node, resumes the
original replica count even after a failure, and writes only signed metadata
locally. Temporary helper-service removal is retried and a cleanup failure
makes the operation fail rather than silently leaving privileged recovery
resources behind. The presigned URL and encryption key exist only in a
temporary Docker secret and are not included in the retained metadata.
Artifact transfers ignore proxy environment variables, reject redirects, and
bound the wait for response headers so capability URLs cannot be silently
forwarded or leave recovery helpers hung before an object-store response.

For a restore, generate a short-lived GET URL for the signed `objectRef`, scale
the gateway to zero, and use the exact images and storage node recorded by the
backup. Restore stays offline so the installer can perform the controlled
restart and fresh dual-auditor verification:

```sh
docker service scale --detach=false dockyard-ai_9router=0
export DOCKYARD_AI_RESTORE_URL_FILE=/secure/dockyard/ai-backup-get-url
export DOCKYARD_AI_RESTORE_OBJECT_REF=s3://recovery/orka/9router-2026-08-31.enc
export DOCKYARD_RECOVERY_VERIFY_KEY_FILE=/secure/dockyard/recovery-verify-key.pem
export DOCKYARD_AI_RESTORE_CONFIRM=restore:dockyard-ai:9router
scripts/restore-ai-gateway.sh /secure/backups/9router-2026-08-31
scripts/install-ai-auditors.sh
```

Restore verifies the Ed25519 signature, encryption-key fingerprint, images,
node and volume identity, encrypted and plaintext checksums, and full archive
safety before atomically replacing top-level volume contents. The exact
helper image strictly decodes and verifies one in-memory snapshot of the signed
manifest before any field is used, rejecting unknown fields and file swaps.
Keep signed
metadata and the encrypted object off-host, and escrow the encryption and
verification keys separately.

Auditor startup fails if a configured secret file is unreadable or empty, or
if an inline value and its `_FILE` setting are both present. This prevents a
stale environment value from overriding a rotated Docker secret and prevents
an unavailable model-key mount from silently degrading to unauthenticated
gateway requests.

Set `DOCKYARD_AI_BASE_URL=http://9router:20128/v1` when using the supplied
stack, or use another OpenAI-compatible endpoint. The stack separates the
gateway-side 9Router-to-Headroom path from the auditor-to-9Router path with two
encrypted overlays. Headroom cannot connect directly to either auditor
identity, while 9Router is the only service bridging both networks. 9Router and
Headroom are intentionally absent from
`dockyard-public`, preventing tenant workloads attached for ingress from
reaching the model gateway directly. Separate replicas can use different
`DOCKYARD_AI_AGENT_NAME` and `DOCKYARD_AI_AUDIT_FOCUS` values. The supplied manifest runs security and reliability specialists daily
and limits each complete audit lifecycle to ten minutes with
`DOCKYARD_AI_AUDIT_TIMEOUT`. A replacement process with the same service
account and agent name marks its predecessor failed before starting, while
different named specialists remain independent.
The overlay also applies configurable CPU and memory reservations and limits
to 9Router, Headroom, and both auditor services. Override the corresponding
`NINEROUTER_*`, `HEADROOM_*`, or `DOCKYARD_AI_AUDITOR_*` resource variables
when capacity planning requires different bounds. The shared
`DOCKYARD_CONTAINER_LOG_MAX_SIZE` and `DOCKYARD_CONTAINER_LOG_MAX_FILES`
variables bound local container-log retention across this overlay as well.
All four services use explicit stop-first updates and automatic rollback. This
prevents two 9Router tasks from writing the node-local data volume concurrently
and prevents replacement auditor tasks from overlapping under the same
service-account identity. Swarm probes 9Router's upstream `/api/health`
endpoint during normal operation and the update monitor, so a replacement that
starts but cannot serve requests is restarted and cannot be treated as a
successful rollout. The gateway processes also run with
`no-new-privileges`; 9Router retains the upstream image's startup capability
set because its entrypoint must repair ownership of a newly mounted data
volume before dropping to its unprivileged Node user.
After a failed run, the auditor retries after
`DOCKYARD_AI_AUDIT_RETRY_INTERVAL` (five minutes by default, or the normal
interval when it is shorter), doubles that delay after consecutive failures,
and caps it at the normal audit interval.
A successful run resets the backoff. The retry interval must be between one
minute and `DOCKYARD_AI_AUDIT_INTERVAL` so a configuration error cannot create
a tight failure loop.
Both base URLs reject embedded credentials, query strings, and fragments. The
control-plane value must be an origin; the model value may include an API path
such as `/v1`. Plain HTTP is intended only for these encrypted in-stack
networks—use HTTPS for external endpoints.
The 9Router service is deliberately not published outside the overlay network;
perform initial provider setup through a temporary authenticated tunnel or a
separately protected administration route.

Before deploying the recurring services, validate the exact control-plane
token, gateway, model, and network path with a single fail-fast run:

```sh
docker run --rm --read-only \
  -e DOCKYARD_CONTROL_PLANE_URL \
  -e DOCKYARD_AI_AUDITOR_TOKEN \
  -e DOCKYARD_AI_BASE_URL \
  -e DOCKYARD_AI_API_KEY \
  -e DOCKYARD_AI_MODEL \
  registry.example/dockyard@sha256:... ai-auditor --once
```

The command exits non-zero if snapshot retrieval, model inference, finding
persistence, or run finalization fails. The default recurring mode continues
to record failures and retries on its configured interval.

## Agent API lifecycle

1. Fetch `GET /v1/ai/audit-snapshot`. Third-party agents should partition
   large model prompts while retaining complete deterministic coverage; the
   built-in runner uses 512 KiB chunks and permits at most 64.
2. Create `POST /v1/ai/audit-runs` with identity, model, and scope metadata.
3. Submit normalized findings to
   `POST /v1/ai/audit-runs/{runID}/findings`.
4. Mark the run `completed` or `failed` with
   `PATCH /v1/ai/audit-runs/{runID}`.

This contract lets Hermes or another agent replace the built-in runner without
changing the platform boundary.

Administrators can automate identity and finding lifecycle without raw HTTP:
`dockyardctl create-service-account JSON` (use role `auditor`),
`service-accounts`, `rotate-service-account ID JSON`,
`disable-service-account ID`, `ai-audit-runs`, `ai-audit-findings`,
`ai-audit-run-findings RUN_ID`, and `triage-ai-audit-finding FINDING_ID JSON`.
Use `-` instead of JSON to keep one-time credentials and triage notes out of
shell history.

## Operational visibility

The control-plane metrics endpoint exposes global run counts by status and
per-organization ages for the latest completion, latest failure, and oldest
running audit. Agent names and model names are deliberately excluded from
labels so user-controlled values cannot create unbounded Prometheus series.
Referenced source credentials and backup destinations also expose secret-free
rotation-age series; the supplied rules warn after 180 days even if the AI
audit schedule is down.

The supplied Prometheus rules warn when an audit fails, remains running for
more than ten minutes, or an organization with an active auditor token has no
completed audit within 48 hours. The overdue check also covers an auditor that
has never completed a run; its window starts when the oldest currently active
auditor token was created. The default Swarm schedule is 24 hours, so the
48-hour threshold tolerates one missed execution before alerting. Failed runs
also enqueue the durable `ai.audit.failed` notification event in the same
transaction as their terminal state, for any subscribed organization endpoint.
Newly critical findings enqueue `ai.finding.critical` transactionally; repeated
unchanged critical occurrences remain visible without paging on every run.

`make test-ai-audit-conformance` runs the built-in auditor against the real
Dockyard API and PostgreSQL store with a disposable OpenAI-compatible model
endpoint. The release-blocking check proves the snapshot reaches the model
without Compose or encrypted environment secrets, deterministic and model
findings are persisted, desired tags are distinguished from effective runtime
image provenance, mutable deployed images are reported without exposing image
identities, the durable run and audit trail complete, and the auditor token is
denied access to normal workload APIs. A production release must still
exercise its configured external model gateway and credentials.

The built-in auditor does not inherit `HTTP_PROXY`, `HTTPS_PROXY`, or
`NO_PROXY`; its control-plane and model bearer credentials travel only to the
validated configured endpoints. Use explicit network routing rather than an
ambient process proxy for these services.
