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
  enabled SSO provider counts, notification coverage, and template repository
  signing/synchronization posture so findings can identify concrete gaps. It
  also reports each service's desired and latest deployed revision plus
  pending/running service and database jobs. Queue counts cover only jobs with
  a resource key that resolves through the requesting organization; unscoped
  platform jobs and another organization's jobs are never included.
- Auditors may only create runs, add findings to their own active runs, and
  complete those runs. Administrators read results.
- AI output is advisory. It never becomes a deployment, shell command, policy
  change, or remediation without a separate human-approved workflow.
- Snapshot strings are explicitly treated as untrusted data. The built-in
  runner bounds model responses and finding counts, validates every structured
  field, and rejects oversized evidence before submitting results.
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
HEADROOM_IMAGE='ghcr.io/chopratejas/headroom@sha256:...' \
DOCKYARD_AI_MODEL='provider/model-name' \
docker stack deploy -c deploy/ai-auditors.yml dockyard-ai
```

Set `DOCKYARD_AI_BASE_URL=http://9router:20128/v1` when 9Router shares the
overlay network, or use another OpenAI-compatible endpoint. Separate replicas
can use different `DOCKYARD_AI_AGENT_NAME` and `DOCKYARD_AI_AUDIT_FOCUS`
values. The supplied manifest runs security and reliability specialists daily.
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
