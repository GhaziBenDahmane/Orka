# Swarm installation

Stable `vMAJOR.MINOR.PATCH` releases publish a signed amd64/arm64 image and a
promotion manifest through `.github/workflows/release.yml`. Download
`image-digest.txt` from the
workflow artifact and use that exact `ghcr.io/...@sha256:...` value for
`DOCKYARD_IMAGE`; the version tag is only a discovery alias. The workflow
verifies the keyless Sigstore signature, SLSA provenance, and SPDX SBOM before
making the promotion artifact available. The exact signed digest is also run
as a disposable Swarm service for a five-minute default soak. That gate checks
health, readiness, authenticated API access, metrics, and replica convergence,
then injects a failing controller health check and requires Swarm to restore
the signed digest automatically. Repository administrators may lengthen the
automated window with the `DOCKYARD_RELEASE_SOAK_SECONDS` Actions variable.

Before trusting downloaded release evidence, fetch all release assets into one
directory and authenticate the manifest and every file it covers:

```sh
identity='^https://github.com/GhaziBenDahmane/Orka/.github/workflows/release.yml@refs/(heads|tags)/.+$'
cosign verify-blob \
  --bundle promotion-manifest.sigstore.json \
  --certificate-identity-regexp "$identity" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  promotion-manifest.json
certification_identity='^https://github.com/GhaziBenDahmane/Orka/.github/workflows/production-certification.yml@refs/(heads|tags)/.+$'
cosign verify-blob \
  --bundle production-certification.sigstore.json \
  --certificate-identity-regexp "$certification_identity" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  production-certification.json
expected_checksums_sha256="$(jq -er '.evidenceChecksumsSHA256 | select(test("^[a-f0-9]{64}$"))' promotion-manifest.json)"
test "$(sha256sum release-evidence.sha256 | cut -d ' ' -f1)" = "$expected_checksums_sha256"
sha256sum --check --strict release-evidence.sha256
```

The signed manifest names the checksum inventory. A missing or changed
evidence file is not valid release evidence. Upgrade automation performs the
same manifest-signature verification before trusting the previous image digest.
Stable publication is a separate protected job and also requires a signed
production certification for the exact candidate; follow
[`docs/production-certification.md`](../docs/production-certification.md).

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
DNS hostnames, ACME email addresses, and routing-network names, loose secret-file permissions, malformed keys, and existing secrets unless reuse is explicitly
acknowledged with `DOCKYARD_REUSE_EXISTING_SECRETS=true`. It validates the
fully rendered stack and resolves every immutable image through the current
Docker registry credentials before creating the overlay network or secrets, then
rejects existing routing overlays whose `encrypted` option is absent or
explicitly disabled, and then
waits for every service to hold its desired replica count continuously for 90
seconds. It also requires every control-plane service to run the exact requested
image digest and rejects any updating, paused, or rolled-back service state.
The supplied Swarm manifests set CPU and memory reservations plus hard limits
for every long-running platform, agent, and AI service. Override the documented
`*_CPU_LIMIT`, `*_MEMORY_LIMIT`, `*_CPU_RESERVATION`, and
`*_MEMORY_RESERVATION` environment variables when sizing the stack for its
host; Docker validates the rendered values before the installer mutates state.
Defaults are `4.0` CPU/`4G` memory for the controller and remote agent,
`2.0`/`2G` for PostgreSQL, and `1.0`/`512M` for Traefik. Their respective
reservation defaults are `0.25`/`256M`, `0.25`/`256M`, and `0.10`/`64M`.
The full variable prefixes are `DOCKYARD_CONTROLLER`, `DOCKYARD_AGENT`,
`DOCKYARD_POSTGRES`, and `DOCKYARD_TRAEFIK`.
All bundled services use Docker's bounded `local` logging driver with five
20-MiB files by default. Set `DOCKYARD_CONTAINER_LOG_MAX_SIZE` and
`DOCKYARD_CONTAINER_LOG_MAX_FILES` before rendering any platform, agent, or AI
stack to tune retention consistently and prevent container logs from filling
manager disks.
This covers the bundled health-check start periods and retry windows, so a task
that starts and then fails readiness—or silently returns to an older image—does
not produce a false installation success. `DOCKYARD_INSTALL_STABILITY_SECONDS`
may extend this window for slower infrastructure but cannot exceed
`DOCKYARD_INSTALL_WAIT_TIMEOUT`. Set
`DOCKYARD_INSTALL_SKIP_WAIT=true` only when another deployment system owns the
convergence check. If pre-deployment setup fails, resources created by that
attempt are removed; once stack deployment begins, failed resources are left
intact for Docker diagnostics and an explicit retry.

Docker secrets are cluster-global rather than stack-scoped. When installing a
second stack or preparing a coordinated database-credential rotation, set
`DOCKYARD_DB_PASSWORD_SECRET`, `DOCKYARD_DATABASE_URL_SECRET`, and
`DOCKYARD_MASTER_KEY_SECRET` to distinct, versioned secret names. The
installer validates and creates those exact names, and the stack resolves its
logical secret mounts to them. Do not use `DOCKYARD_REUSE_EXISTING_SECRETS`
across independent stacks merely to bypass a name collision. Changing the
password secret alone does not update an initialized PostgreSQL role: change
the role password and database URL together during a maintenance window, keep
the old secrets until the health-gated rollout succeeds, and then remove them.

The stack provisions `backup-artifacts` as a stack-scoped Docker volume and
mounts it at `/var/lib/dockyard/backups`; a clean manager therefore does not
need a pre-created host directory. Local managed-database backups stored there
are encrypted but node-local and are not a substitute for an off-host backup.
Before draining or replacing the manager that runs the controller, either
retain that node and its volume or migrate every required backup to a tested
S3-compatible destination. The HA profile requires remote destinations and
uses the named volume only for temporary encrypted upload and restore staging,
so controllers can be scheduled on any manager without a missing bind source.
Docker does not include this artifact volume in the control-plane PostgreSQL
backup bundle; preserve object storage and local artifacts separately as part
of the documented recovery set.

Controller startup also rejects ambiguous secret configuration: do not set a
`DOCKYARD_*` secret value and its matching `DOCKYARD_*_FILE` variable at the
same time. `DOCKYARD_PUBLIC_URL` must be an HTTPS origin without a path, query,
fragment, or embedded credentials; plain HTTP is accepted only for loopback
development. `DOCKYARD_TRAEFIK_NETWORK` must be a lowercase Docker network
name of at most 63 characters, and `DOCKYARD_SESSION_TTL` must be between five
minutes and 30 days. These checks run before database migrations or Docker
operations.

The equivalent manual commands are:

```sh
docker swarm init                         # skip if already active
docker network create --driver overlay --opt encrypted --attachable dockyard-public
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

The controller is not attached to the tenant routing network selected by
`DOCKYARD_TRAEFIK_NETWORK` (default `dockyard-public`). The installer creates
or safely reuses that attachable encrypted overlay, and the stack passes the
same name to both Dockyard and Traefik. The stack creates a
dedicated encrypted `dockyard-edge-control` network between Traefik and the
controller, using `DOCKYARD_EDGE_SUBNET` (default `10.255.250.0/24`) as both
its IPAM subnet and trusted-proxy CIDR. Choose a non-overlapping subnet before
deployment when that default conflicts with existing infrastructure. AI
auditors reach the controller through its public HTTPS URL rather than joining
the tenant routing network.

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
exactly one `sslmode=verify-full` parameter; ambiguous duplicate TLS modes are
rejected. Install the provider CA in the controller image or use a libpq
`sslrootcert` URL parameter when it is not publicly trusted. PostgreSQL
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
restore drills, stalled durable artifact deletion, stalled or failed Dokploy
database migrations, and maintenance mode left enabled. They also detect
missing remote-cluster heartbeats, stalled agent upgrades, missed
image-verification deadlines, and paused or rolled-back Swarm agent updates,
plus expiring, expired, or stalled certificate rotations.
The `dockyard_control_plane_certificate_expiry_seconds` gauges separately track
the configured active agent CA, optional previous agent CA, and server
certificate; warning alerts begin seven days before expiry. Enabled service-account credentials expose their current token
expiry by immutable account ID and role; warning alerts begin seven days before
expiry and become critical once automation or an AI auditor can no longer
authenticate. Non-revoked deploy-hook credentials expose expiry by immutable
service and token IDs, while deletion finalizer metrics distinguish active,
failed, and missing work and alert after fifteen minutes without convergence.
Non-revoked SCIM tokens have equivalent expiry gauges and alerts
so directory provisioning does not stop silently. Enabled SAML providers expose
separate service-provider and identity-provider trust expiries; alerts begin
thirty days before expiry and also detect malformed or not-yet-valid rollover
material.
Route those alerts through Alertmanager to the team's email, Slack, PagerDuty,
or other incident receiver.

Every controller also publishes a path-free database-driver inventory fingerprint
and one `dockyard_database_driver_info` series per loaded engine. The
`DockyardDatabaseDriverFleetMismatch` alert fires when HA replicas expose
different inventories, including when an engine is absent from one replica.
`dockyard_database_driver_binding_issues` counts persisted databases by engine
and the bounded reason `unbound`, `unavailable`, or `identity_mismatch`; its
critical alert means recovery and migration work may fail closed. First compare
the per-engine digest series across controller targets. Install the reviewed
artifact on every replica and restart them. If the new digest is intentional,
confirm no recovery or migration job is active and use the audited driver-rebind
API only after the fleet is consistent. Do not silence either alert during a
mixed-artifact rolling deployment; drain database jobs until it clears.

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
# Use a new versioned name when rotating the token or replacing lost agent state.
export DOCKYARD_AGENT_ENROLLMENT_TOKEN_SECRET=dockyard_agent_enrollment_token_v2

DOCKYARD_INSTALL_DRY_RUN=true scripts/install-agent.sh
scripts/install-agent.sh
```

The installer requires HTTPS origins without credentials, paths, query strings,
or fragments, with valid hostnames and ports. It also requires an immutable and
registry-resolvable image, an active Swarm manager, and a protected non-empty
token file. It creates the workload overlay network when absent, derives the exact self-upgrade service name from
`DOCKYARD_AGENT_STACK_NAME`, and requires the replica count to remain converged
for the same stability window. Existing enrollment
secrets are rejected unless `DOCKYARD_REUSE_EXISTING_SECRETS=true`; only reuse
one when the corresponding agent identity volume is intact. Docker secrets are
immutable: when issuing a fresh enrollment token or recovering from a lost
agent identity volume, set `DOCKYARD_AGENT_ENROLLMENT_TOKEN_SECRET` to a new,
versioned Docker secret name rather than reusing the old secret. The equivalent
installer verifies the exact requested image digest and rejects active, paused,
or rolled-back service updates before reporting success. Placement, deployment,
remote commands, and drift repair fail closed when the assigned agent has not
heartbeated for two minutes; placement capacity is rechecked before every
deployment or automatic repair. The equivalent manual commands are:

```sh
export DOCKYARD_AGENT_ENROLLMENT_TOKEN_SECRET=dockyard_agent_enrollment_token_v2
printf '%s' "$ENROLLMENT_TOKEN" | docker secret create "$DOCKYARD_AGENT_ENROLLMENT_TOKEN_SECRET" -
DOCKYARD_CONTROL_PLANE_URL=https://dockyard.example.com \
  DOCKYARD_AGENT_URL=https://agents.dockyard.example.com:8444 \
  DOCKYARD_AGENT_ENROLLMENT_TOKEN_SECRET="$DOCKYARD_AGENT_ENROLLMENT_TOKEN_SECRET" \
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

The token enrolls only one locally generated key. The agent stores a protected
pending key in the `agent-state` volume before sending its CSR, so a lost HTTP
response can safely retry the exact exchange until the token expires. The
controller never accepts the consumed token with a different CSR. The agent
validates the returned CA bundle, client-auth certificate, cluster identity,
and private-key binding before committing its identity and removing the pending
key. It then uses mTLS for heartbeat and command polling. No inbound port
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
export DOCKYARD_RECOVERY_SIGNING_KEY_FILE=/secure/escrow/dockyard-recovery-signing-key.pem
scripts/backup-control-plane.sh /secure/backups/dockyard-2026-08-28
```

Generate the recovery identity once with `openssl genpkey -algorithm ED25519`,
derive its public key with `openssl pkey -pubout`, protect the private key with
mode `0600`, and store the public verification key independently from backup
storage. The new directory contains a custom-format PostgreSQL dump, a JSON
manifest with the dump checksum and size, schema version, image digest, and
trusted-key fingerprints, plus an Ed25519 manifest signature. It never contains
the master key, agent CA, recovery signing key, or trusted verification key.
Before dumping PostgreSQL, the script verifies that `DOCKYARD_IMAGE` exactly
matches the deployed Swarm controller and refuses an in-progress, paused, or
rolled-back controller update. For a Compose deployment, explicitly set
`DOCKYARD_CONTROLLER_CONTAINER`; the requested digest must match its immutable
image ID.
Copy the bundle, master key, agent CA keypair, artifact storage, stack
configuration, image digest, and recovery verification key to independently
protected storage.

Restore only on the node hosting the PostgreSQL task, with all controller
replicas stopped. The script refuses to proceed unless the controller service
is scaled to zero, the destructive confirmation value is exact, every bundle
integrity check passes, and the supplied key/CA fingerprints match:

```sh
docker service scale dockyard_dockyard=0
export DOCKYARD_RESTORE_CONFIRM='restore:dockyard'
export DOCKYARD_IMAGE='ghcr.io/example/dockyard@sha256:...'
export DOCKYARD_MASTER_KEY_FILE=/secure/escrow/dockyard-master-key
export DOCKYARD_RECOVERY_VERIFY_KEY_FILE=/secure/escrow/dockyard-recovery-verify-key.pem
scripts/restore-control-plane.sh /secure/backups/dockyard-2026-08-28
docker service scale dockyard_dockyard=1
```

The restore rejects unsigned manifests and verifies the signature with the
independently supplied Ed25519 public key before trusting any bundle metadata.
The current authenticated bundle format is version 2; create a fresh bundle
before upgrading from a version that produced unsigned format-1 bundles. It
then creates a separate staging database, restores the complete
dump in one transaction, and verifies its migration version. Only then does it
atomically rename the current database aside and the validated staging database
into place. It prints the retained previous database name; keep that rollback
copy until the exact image recorded in the manifest starts successfully, login
and representative secret decryption work, and a managed-database restore drill
passes. Drop the retained database explicitly after validation. To roll back,
stop every controller again, drop the failed restored database, and rename the
printed previous database back to `dockyard`. Deployments
using external PostgreSQL should use the provider's consistent snapshot/PITR
mechanism and preserve the same recovery-set metadata and secret escrow.

Rotate the control-plane master key with the transactional offline procedure
in [docs/master-key-rotation.md](../docs/master-key-rotation.md). The Swarm
manifest accepts `DOCKYARD_MASTER_KEY_SECRET` so a versioned replacement Docker
secret can be deployed without mutating secret data in place. Keep that variable
set when rerunning `scripts/install-swarm.sh`; the installer creates, validates,
and reuses the selected external secret name.
