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
- The snapshot includes per-database backup policy and restore-drill posture,
  the installed database-driver catalog with default versions, built-in or
  external provenance, executable SHA-256 digest, and backup capability,
  enabled SSO provider counts,
  notification coverage, and template repository
  signing/synchronization posture so findings can identify concrete gaps. It
  also reports each service's desired and latest deployed revision plus
  pending/running service and database jobs. The latest agent upgrade for each
  cluster includes its immutable target, state, attempt count, deadline, and
  overdue flag, but never its encrypted command or result. Queue counts cover
  only jobs with a resource key that resolves through the requesting
  organization; unscoped platform jobs and another organization's jobs are
  never included.
- Dokploy migration posture is grouped by source organization and reports
  imported versus unresolved resources plus successful native database
  transfers. Up to 200 unresolved parity records include their source kind,
  identifier, and manual-conversion reason; source metadata and encrypted
  transfer credentials never enter the snapshot.
- Identity posture is aggregate-only: active and disabled membership counts by
  role, active local/OIDC/SAML sessions, active and soon-expiring service
  accounts, auditor accounts, active SCIM token count/age, and pending SAML
  certificate rotation count/age. User identities,
  session metadata, token hashes, and provider configuration remain excluded.
- Auditors may only create runs, add findings to their own active runs, and
  complete those runs. Administrators read results.
- AI output is advisory. It never becomes a deployment, shell command, policy
  change, or remediation without a separate human-approved workflow.
- Organization administrators can acknowledge, resolve, or reopen individual
  findings with an optional operator note. These triage changes are
  tenant-scoped and enter the platform audit log; auditor identities cannot
  alter disposition.
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
  runner bounds model responses and finding counts, validates every structured
  field, and rejects oversized evidence before submitting results. The API
  independently enforces the 100-finding limit under concurrent submissions;
  third-party agents cannot bypass the bound, while they may update an existing
  fingerprint without consuming another slot.
- Before calling the model, the built-in runner records a bounded deterministic
  safety baseline for missing, disabled, or overdue backups and restore drills, missing owners, disabled
  mandatory SSO, stale cluster heartbeats, expiring agent certificates,
  expiring service-account and stale SCIM credentials, agent identities signed
  by a non-active CA, lingering dual-trust rollovers, stalled tenant queues,
  notification coverage gaps, unavailable, unbound, mismatched, or
  recovery-incapable database drivers, unhealthy reconciliation, unsigned, failed,
  never-synchronized, or stale catalogs, undeployed desired revisions, and
  incomplete Dokploy migrations. These findings survive a model gateway
  failure; the run remains marked failed so operators can distinguish
  baseline-only output from a completed model review.
- Each run records agent name/version, model, scope, timestamps, summary, and
  structured findings. Lifecycle transitions also enter the normal audit log.

## Deploy on Swarm

Create one short-lived auditor service-account token in the API, then create
Swarm secrets for it and the model gateway key. Deploy one or more focused
auditors with the supplied overlay:

```sh
printf '%s' "$AUDITOR_TOKEN" | docker secret create dockyard_ai_auditor_token -
printf '%s' "$MODEL_API_KEY" | docker secret create dockyard_ai_api_key -
DOCKYARD_IMAGE='registry.example/dockyard@sha256:...' \
NINEROUTER_IMAGE='decolua/9router@sha256:...' \
HEADROOM_IMAGE='ghcr.io/headroomlabs-ai/headroom@sha256:...' \
DOCKYARD_AI_MODEL='provider/model-name' \
docker stack deploy -c deploy/ai-auditors.yml dockyard-ai
```

Set `DOCKYARD_AI_BASE_URL=http://9router:20128/v1` when 9Router shares the
stack's encrypted `ai-control` network, or use another OpenAI-compatible
endpoint. 9Router and Headroom are intentionally absent from
`dockyard-public`, preventing tenant workloads attached for ingress from
reaching the model gateway directly. Separate replicas can use different
`DOCKYARD_AI_AGENT_NAME` and `DOCKYARD_AI_AUDIT_FOCUS` values. The supplied manifest runs security and reliability specialists daily
and limits each complete audit lifecycle to ten minutes with
`DOCKYARD_AI_AUDIT_TIMEOUT`. A replacement process with the same service
account and agent name marks its predecessor failed before starting, while
different named specialists remain independent.
Both base URLs reject embedded credentials, query strings, and fragments. The
control-plane value must be an origin; the model value may include an API path
such as `/v1`. Plain HTTP is intended only for these encrypted in-stack
networks—use HTTPS for external endpoints.
The 9Router service is deliberately not published outside the overlay network;
perform initial provider setup through a temporary authenticated tunnel or a
separately protected administration route.

## Agent API lifecycle

1. Fetch `GET /v1/ai/audit-snapshot`.
2. Create `POST /v1/ai/audit-runs` with identity, model, and scope metadata.
3. Submit normalized findings to
   `POST /v1/ai/audit-runs/{runID}/findings`.
4. Mark the run `completed` or `failed` with
   `PATCH /v1/ai/audit-runs/{runID}`.

This contract lets Hermes or another agent replace the built-in runner without
changing the platform boundary.

## Operational visibility

The control-plane metrics endpoint exposes global run counts by status and
per-organization ages for the latest completion, latest failure, and oldest
running audit. Agent names and model names are deliberately excluded from
labels so user-controlled values cannot create unbounded Prometheus series.

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
findings are persisted, the durable run and audit trail complete, and the
auditor token is denied access to normal workload APIs. A production release
must still exercise its configured external model gateway and credentials.
