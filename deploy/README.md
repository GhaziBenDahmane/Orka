# Swarm installation

Tagged releases publish a signed amd64/arm64 image and a promotion manifest
through `.github/workflows/release.yml`. Download `image-digest.txt` from the
workflow artifact and use that exact `ghcr.io/...@sha256:...` value for
`DOCKYARD_IMAGE`; the version tag is only a discovery alias. The workflow
verifies the keyless Sigstore signature, SLSA provenance, and SPDX SBOM before
making the promotion artifact available. The exact signed digest is also run
as a disposable Swarm service for a five-minute default soak. That gate checks
health, readiness, authenticated API access, metrics, and replica convergence,
then injects a failing controller health check and requires Swarm to restore
the signed digest automatically. Repository administrators may lengthen the
automated window with the `DOCKYARD_RELEASE_SOAK_SECONDS` Actions variable.

Operators can repeat the same disposable check against any published digest
from a Swarm manager:

```sh
DOCKYARD_IMAGE=ghcr.io/example/dockyard@sha256:... \
DOCKYARD_RELEASE_SOAK_SECONDS=900 \
make test-release-soak
```

The script writes `release-soak-evidence.json`. It does not exercise the real
production topology or replace the monitored production soak window.

For a repeatable non-interactive installation, put the three secret values in
mode-0600 files and run the installer on a Swarm manager:

```sh
export DOCKYARD_HOST=dockyard.example.com
export ACME_EMAIL=ops@example.com
export DOCKYARD_IMAGE=ghcr.io/example/dockyard@sha256:...
export POSTGRES_IMAGE=postgres@sha256:...
export TRAEFIK_IMAGE=traefik@sha256:...
export DOCKYARD_DB_PASSWORD_FILE=/secure/dockyard/database-password
export DOCKYARD_DATABASE_URL_FILE=/secure/dockyard/database-url
export DOCKYARD_MASTER_KEY_FILE=/secure/dockyard/master-key

DOCKYARD_INSTALL_DRY_RUN=true scripts/install-swarm.sh
scripts/install-swarm.sh
```

The installer rejects mutable image tags, non-manager nodes, unsafe or malformed
DNS hostnames and ACME email addresses, loose secret-file permissions, malformed keys, and existing secrets unless reuse is explicitly
acknowledged with `DOCKYARD_REUSE_EXISTING_SECRETS=true`. It validates the
fully rendered stack before creating the overlay network or secrets, then
waits for every service to hold its desired replica count continuously for 90
seconds. It also requires every control-plane service to run the exact requested
image digest and rejects any updating, paused, or rolled-back service state.
This covers the bundled health-check start periods and retry windows, so a task
that starts and then fails readiness—or silently returns to an older image—does
not produce a false installation success. `DOCKYARD_INSTALL_STABILITY_SECONDS`
may extend this window for slower infrastructure but cannot exceed
`DOCKYARD_INSTALL_WAIT_TIMEOUT`. Set
`DOCKYARD_INSTALL_SKIP_WAIT=true` only when another deployment system owns the
convergence check. If pre-deployment setup fails, resources created by that
attempt are removed; once stack deployment begins, failed resources are left
intact for Docker diagnostics and an explicit retry.

Controller startup also rejects ambiguous secret configuration: do not set a
`DOCKYARD_*` secret value and its matching `DOCKYARD_*_FILE` variable at the
same time. `DOCKYARD_PUBLIC_URL` must be a plain HTTP(S) origin without a path,
query, fragment, or embedded credentials, and `DOCKYARD_SESSION_TTL` must be
between five minutes and 30 days. These checks run before database migrations
or Docker operations.

The equivalent manual commands are:

```sh
docker swarm init                         # skip if already active
docker network create --driver overlay --attachable dockyard-public
printf '%s' 'replace-with-a-long-password' | docker secret create dockyard_db_password -
printf '%s' 'postgres://dockyard:replace-with-a-long-password@postgres:5432/dockyard?sslmode=disable' | docker secret create dockyard_database_url -
openssl rand -base64 32 | docker secret create dockyard_master_key -
DOCKYARD_HOST=dockyard.example.com ACME_EMAIL=ops@example.com \
  DOCKYARD_IMAGE=ghcr.io/example/dockyard@sha256:... \
  POSTGRES_IMAGE=postgres@sha256:... \
  TRAEFIK_IMAGE=traefik@sha256:... \
  scripts/ci/check-image-digests.sh controller
DOCKYARD_HOST=dockyard.example.com ACME_EMAIL=ops@example.com \
  DOCKYARD_IMAGE=ghcr.io/example/dockyard@sha256:... \
  POSTGRES_IMAGE=postgres@sha256:... \
  TRAEFIK_IMAGE=traefik@sha256:... \
  docker stack deploy -c deploy/swarm.yml dockyard
```

The controller is constrained to a manager because it uses the manager Docker
API to deploy stacks. The outbound mTLS agent described below keeps the same
Swarm adapter while removing direct control-plane access to remote sockets.
Controller updates are `start-first` and health-gated; a failed task update is
rolled back automatically. PostgreSQL and Traefik use `stop-first` updates
because their local volume and host-mode listener cannot safely overlap on one
node. Watch `docker service ps dockyard_dockyard` and
`docker service inspect dockyard_dockyard --pretty` until the update completes
before removing the previous image.

## Highly available controllers

The base manifest is a recoverable single-manager installation. For production
control-plane availability, provide a PostgreSQL 17-compatible HA endpoint over
TLS in `dockyard_database_url`, create three or more Swarm manager nodes, and
create the agent listener secrets below. The server certificate must cover the
hostname in `DOCKYARD_AGENT_URL` and chain to `dockyard_agent_ca_cert`:

```sh
docker secret create dockyard_agent_ca_cert /secure/pki/agent-ca.crt
docker secret create dockyard_agent_ca_key /secure/pki/agent-ca.key
docker secret create dockyard_agent_server_cert /secure/pki/agent-server.crt
docker secret create dockyard_agent_server_key /secure/pki/agent-server.key

DOCKYARD_HOST=dockyard.example.com ACME_EMAIL=ops@example.com \
  DOCKYARD_IMAGE=ghcr.io/example/dockyard@sha256:... \
  POSTGRES_IMAGE=postgres@sha256:... \
  TRAEFIK_IMAGE=traefik@sha256:... \
  docker stack deploy -c deploy/swarm.yml -c deploy/swarm-ha.yml dockyard
```

The overlay disables the bundled PostgreSQL task, starts three controller
replicas, publishes the mTLS agent API through Swarm ingress on port 8444, and
requires every enabled or manually requested managed-database backup to use an
S3-compatible destination. Startup fails if an older enabled policy still
targets node-local storage. Configure and test remote backup destinations
before switching profiles. It also requires the external PostgreSQL URL to use
`sslmode=verify-full`; install the provider CA in the controller image or use a
libpq `sslrootcert` URL parameter when it is not publicly trusted. PostgreSQL
availability, replication, PITR, connection pooling, and failover remain the
database provider's responsibility.

Before a production rollout, run `make test-swarm-ha` on a host that permits
privileged containers. It creates an isolated three-manager nested Swarm,
converges a three-replica service, partitions the elected leader, verifies
leader replacement and replica recovery, confirms a one-manager minority
cannot mutate desired state, restores quorum, and writes
`swarm-ha-conformance.json`. All temporary managers, networks, images, and
state are removed on exit. This validates Swarm/Raft behavior on one host; the
release gate still requires the same failure sequence on the actual multi-host
network and storage topology.

The installer also supports this profile with
`DOCKYARD_INSTALL_MODE=ha`. In addition to the variables above, set
`DOCKYARD_AGENT_HOST` and the four `DOCKYARD_AGENT_*_FILE` variables shown
below. Preflight verifies certificate validity, hostname coverage, the server
chain, both private-key matches, and at least seven days of remaining validity
for the CA and server certificate before changing Docker state. Controller
startup independently rejects expired, not-yet-valid, mismatched, or
untrusted agent TLS credentials. The database URL file must contain
`sslmode=verify-full`.

```sh
export DOCKYARD_INSTALL_MODE=ha
export DOCKYARD_AGENT_HOST=agents.dockyard.example.com
export DOCKYARD_AGENT_CA_CERT_FILE=/secure/pki/agent-ca.crt
export DOCKYARD_AGENT_CA_KEY_FILE=/secure/pki/agent-ca.key
export DOCKYARD_AGENT_SERVER_CERT_FILE=/secure/pki/agent-server.crt
export DOCKYARD_AGENT_SERVER_KEY_FILE=/secure/pki/agent-server.key

DOCKYARD_INSTALL_DRY_RUN=true scripts/install-swarm.sh
scripts/install-swarm.sh
```

Agent CA replacement is a three-phase dual-trust operation, not an in-place
Docker secret update. Follow [the agent CA rotation runbook](../docs/agent-ca-rotation.md);
it uses versioned secret names, the temporary
`deploy/swarm-agent-ca-rollover.yml` overlay, per-cluster CA fingerprints, and
a reversible old-listener/new-signer transition.

Import `deploy/prometheus-alerts.yml` into Prometheus (or a compatible ruler)
and scrape `http://dockyard:8080/metrics` with a dedicated viewer service
account configured as an HTTP bearer token. The rules cover controller outage,
stale worker leases, queue backlog, failed operations, stale backups, overdue
restore drills, stalled or failed Dokploy database migrations, and maintenance
mode left enabled. They also detect missing remote-cluster heartbeats, stalled
agent upgrades, missed image-verification deadlines, and paused or rolled-back
Swarm agent updates, plus expiring, expired, or stalled certificate rotations.
The `dockyard_control_plane_certificate_expiry_seconds` gauges separately track
the configured active agent CA, optional previous agent CA, and server
certificate; warning alerts begin seven days before expiry. Enabled service-account credentials expose their current token
expiry by immutable account ID and role; warning alerts begin seven days before
expiry and become critical once automation or an AI auditor can no longer
authenticate. Non-revoked SCIM tokens have equivalent expiry gauges and alerts
so directory provisioning does not stop silently. Enabled SAML providers expose
separate service-provider and identity-provider trust expiries; alerts begin
thirty days before expiry and also detect malformed or not-yet-valid rollover
material.
Route those alerts through Alertmanager to the team's email, Slack, PagerDuty,
or other incident receiver.

Validate local rule changes with `make check-alerts`; CI runs the same pinned
Prometheus `promtool` image.

## Remote Swarm agent

Configure the controller with a dedicated TLS 1.3 listener and a private agent
CA. Create a cluster and one-time enrollment token through the API, then install
one outbound agent on a manager of that Swarm. Store the token in a mode-0600
file and use the guarded installer:

```sh
export DOCKYARD_CONTROL_PLANE_URL=https://dockyard.example.com
export DOCKYARD_AGENT_URL=https://agents.dockyard.example.com:8444
export DOCKYARD_IMAGE=ghcr.io/example/dockyard@sha256:...
export DOCKYARD_AGENT_ENROLLMENT_TOKEN_FILE=/secure/dockyard/enrollment-token

DOCKYARD_INSTALL_DRY_RUN=true scripts/install-agent.sh
scripts/install-agent.sh
```

The installer requires HTTPS endpoints, an immutable image, an active Swarm
manager, and a protected non-empty token file. It creates the workload overlay
network when absent, derives the exact self-upgrade service name from
`DOCKYARD_AGENT_STACK_NAME`, and requires the replica count to remain converged
for the same stability window. Existing enrollment
secrets are rejected unless `DOCKYARD_REUSE_EXISTING_SECRETS=true`; only reuse
one when the corresponding agent identity volume is intact. The equivalent
installer verifies the exact requested image digest and rejects active, paused,
or rolled-back service updates before reporting success. Placement, deployment,
remote commands, and drift repair fail closed when the assigned agent has not
heartbeated for two minutes; placement capacity is rechecked before every
deployment or automatic repair. The equivalent manual commands are:

```sh
printf '%s' "$ENROLLMENT_TOKEN" | docker secret create dockyard_agent_enrollment_token -
DOCKYARD_CONTROL_PLANE_URL=https://dockyard.example.com \
  DOCKYARD_AGENT_URL=https://agents.dockyard.example.com:8444 \
  DOCKYARD_IMAGE=ghcr.io/example/dockyard@sha256:... \
  scripts/ci/check-image-digests.sh agent
DOCKYARD_CONTROL_PLANE_URL=https://dockyard.example.com \
  DOCKYARD_AGENT_URL=https://agents.dockyard.example.com:8444 \
  DOCKYARD_IMAGE=ghcr.io/example/dockyard@sha256:... \
  docker stack deploy -c deploy/agent-swarm.yml dockyard-agent
```

Resolve and record real 64-character digests before running these commands;
the abbreviated values above are placeholders. The production manifests have
no mutable-tag defaults, and the validation script rejects tags.

The token is used once. The agent generates its private key locally, stores its
identity in the `agent-state` volume, verifies the controller using the
enrollment CA, and uses mTLS for heartbeat and command polling. No inbound port
or remote Docker socket is exposed on the managed cluster. The agent binary
independently requires both controller addresses to be HTTPS origins and
refuses redirects, preventing an enrollment token or authenticated request
from being replayed to a different endpoint.

Agents can be upgraded through `POST /v1/clusters/{id}/agent-upgrades` or
`dockyardctl agent-upgrade CLUSTER_ID IMAGE@sha256:DIGEST`. Only immutable image
digests are accepted. The agent performs a Swarm `start-first` service update;
the service update automatically rolls back if the replacement task fails. A
successful Docker submission leaves the command in `verifying`; it changes to
`succeeded` only after a replacement agent heartbeat reports both the requested
digest and Swarm's `completed` update state. A paused or rolled-back state marks
the command `failed`; absence of a confirming heartbeat fails verification
after 15 minutes. Poll the returned command with
`dockyardctl cluster-command CLUSTER_ID COMMAND_ID`, or inspect the latest
tenant-scoped upgrade status for every cluster in the web console. A command
that is still pending can be cancelled from the console or with
`dockyardctl cancel-agent-upgrade CLUSTER_ID COMMAND_ID`. Once execution starts,
cancellation is rejected because it could not truthfully stop a Swarm rollout.
Set `DOCKYARD_AGENT_SERVICE_NAME` when the manually deployed stack is not named
`dockyard-agent`; the installer derives it automatically.

Managed-database backup and restore on remote clusters requires an
S3-compatible backup destination whose configured endpoint is reachable from
both the controller and agent. Transfers use one-hour presigned URLs. Backup
bytes are encrypted on the agent before upload; object-storage credentials and
plaintext backup data are never sent to the agent API or controller.

## Control-plane backup and recovery

For the bundled PostgreSQL service, run the backup script on the Swarm node
hosting `dockyard_postgres`. Supply the exact deployed image reference and an
escrowed copy of the master key:

```sh
export DOCKYARD_IMAGE='ghcr.io/example/dockyard@sha256:...'
export DOCKYARD_MASTER_KEY_FILE=/secure/escrow/dockyard-master-key
scripts/backup-control-plane.sh /secure/backups/dockyard-2026-08-28
```

The new directory contains a custom-format PostgreSQL dump and a JSON manifest
with the dump checksum and size, schema version, image digest, and fingerprints
of the master key and optional agent CA certificate. It never contains either
secret. Copy the bundle, master key, agent CA keypair, artifact storage, stack
configuration, and image digest to independently protected storage.

Restore only on the node hosting the PostgreSQL task, with all controller
replicas stopped. The script refuses to proceed unless the controller service
is scaled to zero, the destructive confirmation value is exact, every bundle
integrity check passes, and the supplied key/CA fingerprints match:

```sh
docker service scale dockyard_dockyard=0
export DOCKYARD_RESTORE_CONFIRM='restore:dockyard'
export DOCKYARD_IMAGE='ghcr.io/example/dockyard@sha256:...'
export DOCKYARD_MASTER_KEY_FILE=/secure/escrow/dockyard-master-key
scripts/restore-control-plane.sh /secure/backups/dockyard-2026-08-28
docker service scale dockyard_dockyard=1
```

The restore recreates the `dockyard` database and restores it in one
transaction, then checks the restored migration version. Start the exact image
recorded in the manifest, verify login and representative secret decryption,
and perform a managed-database restore drill before upgrading. Deployments
using external PostgreSQL should use the provider's consistent snapshot/PITR
mechanism and preserve the same recovery-set metadata and secret escrow.

Rotate the control-plane master key with the transactional offline procedure
in [docs/master-key-rotation.md](../docs/master-key-rotation.md). The Swarm
manifest accepts `DOCKYARD_MASTER_KEY_SECRET` so a versioned replacement Docker
secret can be deployed without mutating secret data in place. Keep that variable
set when rerunning `scripts/install-swarm.sh`; the installer creates, validates,
and reuses the selected external secret name.
