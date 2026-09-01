# Migrating from Dokploy

The migration command reads Dokploy's PostgreSQL database and writes into an
existing Dockyard organization. It never modifies the Dokploy database. The
current converter targets the schema inspected at Dokploy commit
`532de2c59e4d9be13b0c4db2d7cb7f2da9a3cd48`.

Always start with a dry run:

```sh
dockyard migrate-dokploy \
  --source-url 'postgres://dokploy:...@source/dokploy' \
  --source-organization 'dokploy-organization-id' \
  --target-organization 'dockyard-organization-uuid' \
  --registry-prefix 'registry.example.com/team/dockyard' \
  --server-cluster 'dokploy-server-id=orka-cluster-uuid' \
  --dry-run=true
```

Dry runs open the target PostgreSQL database with
`default_transaction_read_only=on`; they cannot apply migrations or persist
import state. The target must already be on the exact schema expected by the
binary and have an initialized master-key verifier, so start the controller
successfully once before running the first dry run.

`--registry-prefix` is required only when the source contains convertible Git
applications. Dockyard uses it as the destination repository prefix for images
built from imported Dockerfiles.

Repeat `--server-cluster SOURCE_SERVER_ID=TARGET_CLUSTER_UUID` for every
Dokploy remote server used by an imported workload or network. Each target
cluster must belong to the target organization. The importer assigns a
homogeneous source environment and its managed networks to that Swarm. It
fails closed when a remote server is unmapped, or when one Dokploy environment
mixes the local server with a remote server or resolves to multiple target
clusters; split that environment before migration instead of silently moving
workloads to the wrong scheduler.

The JSON report lists convertible projects, environments, Compose services,
managed databases, routes, notifications, skipped resources, and manual
actions. Its structured `resources` entries record deterministic target IDs,
dispositions, and secret-safe compatibility metadata. Secret values and URL
credentials are never included. Repeated imports map every source identifier
to the same target UUID, so a retry updates imported resources instead of
duplicating them.

Dokploy environment columns may use AES-256-GCM encryption. Export the derived
keys using Dokploy's `exportEncryptionKeys()` facility, place the resulting
hex lines in a mode-0600 regular file, then pass:

```sh
--encryption-key-file /secure/path/dokploy-encryption.keys
```

The file must not be a symbolic link, is limited to 64 KiB and 256 distinct
keys, and is checked for replacement while it is read.

After reviewing the report, run with `--dry-run=false`. The command decrypts
the source environment only in memory and immediately re-encrypts it with
`DOCKYARD_MASTER_KEY`. It never copies Dokploy authentication sessions or raw
encryption keys.

A real import persists the same application parity manifest in
`dokploy_migration_resources`. Administrators can retrieve it through
`GET /v1/migration-resources?sourceOrganizationId=...`; later imports update
the existing source-to-target records.

## Current conversion coverage

Imported automatically:

- projects and environments;
- organization tags and their project assignments;
- local and mapped-remote managed networks, including overlay/bridge driver,
  attachability, internal mode, IP families, MTU, IPAM, and compatible
  application/database/Compose-service attachments; only overlay networks can
  attach to Swarm services;
- inline/raw Compose definitions;
- Compose environment values when the source key is supplied;
- Docker-image applications and HTTPS Git applications that use a Dockerfile,
  including runtime environment, replicas, resource reservations/limits, and
  enabled application domains; Docker target stages, build arguments,
  re-encrypted BuildKit secrets, and recursive Git submodules are preserved;
- PostgreSQL, MySQL, MariaDB, MongoDB, Redis, and libSQL managed-database
  definitions, including their image, credentials, and custom environment.
  PostgreSQL records using the official `timescale/timescaledb` image and Redis
  records using the official `valkey/valkey` image are promoted to their native
  TimescaleDB and Valkey drivers without changing their stable import identity;
- S3-compatible backup destinations, with credentials decrypted only in memory
  and re-encrypted under the Dockyard master key;
- registry credentials plus GitLab, Gitea, and Bitbucket token credentials;
  compatible credentials are attached to imported Git applications when the
  repository or build-registry host matches;
- the first enabled or disabled database backup policy for each imported,
  backup-capable database when its cron expression has a constant interval;
  per-policy object prefixes are preserved with deterministic destination
  variants;
- Compose-hosted PostgreSQL, MySQL, MariaDB, and MongoDB backup policies as
  linked database targets when the referenced service exists and the required
  credentials can be recovered. PostgreSQL passwords are resolved from the
  service environment (`PGPASSWORD` or `POSTGRES_PASSWORD`); records that rely
  only on container-local authentication remain explicit manual-conversion
  items. Linked targets never create or delete the owning Compose stack;
- named-volume backup policies for imported Compose services and applications
  when the volume is declared in the generated Compose definition and the cron
  expression has a constant interval; the first deployment binds and pins the
  volume to its Swarm storage node;
- Slack webhooks and SMTP email endpoints, with source secrets decrypted only
  in memory and re-encrypted under the Dockyard master key;
- enabled Compose domains with service name and valid target port.

Reported for manual conversion:

- drop applications, because their ZIPs live on Dokploy's filesystem rather
  than in its PostgreSQL database; recreate the application and upload its ZIP
  through the Dockyard console or artifact-source API;
- Heroku Buildpack applications using version 24 and Paketo Buildpack
  applications are imported; other Heroku versions and build-time secrets
  remain manual;
- static applications whose publish directory is generated during the build
  rather than already committed to the repository;
- Git applications with malformed build settings, non-HTTPS clone URLs, or
  provider-specific private access;
- application mounts, published host ports, custom Swarm health/restart/update/
  placement settings, redirects, and security rules;
- Compose definitions stored only in a remote Git repository;
- GitHub App credentials, SSH keys, custom TLS certificates, unsupported or calendar-based
  backup schedules, additional policies for the same database, and Compose
  backup policies;
- Telegram, Discord, Resend, Gotify, ntfy, Mattermost, Pushover, custom, Lark,
  and Teams notification providers.

Dokploy `appBuildError`, `databaseBackup`, and `volumeBackup` notification
triggers map to Dockyard `deployment.failed` and `backup.failed`. Dokploy success,
restart, platform-backup, cleanup, and server-threshold triggers have no direct
Dockyard equivalent and are called out in the migration report. A notification
with only unmapped triggers is left for manual conversion.

Imported backup schedules support fixed 15-minute-or-longer minute steps,
hourly schedules, evenly divisible hour steps, daily schedules, and weekly
schedules. Monthly and other calendar schedules are reported for manual
conversion because Dockyard's current policy model is interval-based. Dokploy
destination `additionalFlags` are reported but are not executed; audit any such
destination before cutover.

GitHub App private keys are intentionally not converted to static credentials:
recreate that integration or attach a scoped token before the first deployment.
Credentials are never attached across hostnames. Docker-image applications that
pull from a private registry still require operator validation because they do
not use an application-source build record. Imported Git builds forward a
matching registry credential to local or remote Swarm managers.

Dokploy certificate private keys are intentionally not copied by the importer.
Upload each chain and key through **Settings → Custom TLS certificates**, the
write-only API/CLI, or `dockyard_custom_tls_certificate`, then attach its ID to
the imported route with an empty ACME resolver. Dockyard validates SAN coverage
and reconciles the certificate before permitting the next deployment.

Managed-database import creates the destination Compose service and database
record, but the control-plane import does not copy persistent volume contents.
Use the native transfer command below for PostgreSQL, TimescaleDB, MySQL,
MariaDB, MongoDB, Redis, Valkey, and libSQL. Other engines still require an
operator-managed backup and restore.

## Transfer managed database data

Deploy the imported target database stacks and verify they are healthy before
queuing data transfers. The target Swarm manager performs both the source dump
and target restore on the target stack's attachable overlay network, so every
source `host` and `port` in the manifest must be reachable from that network.

Create a mode-0600 connection manifest outside the repository. It must be a
regular, non-symlink file no larger than 1 MiB; the migration command checks
that it is not replaced while being read:

```json
{
  "version": 1,
  "connections": [
    {
      "sourceId": "dokploy-postgres-id",
      "host": "old-postgres.internal",
      "port": 5432,
      "username": "migration",
      "password": "replace-me",
      "database": "app"
    }
  ]
}
```

The `sourceId` is Dokploy's database identifier. Start with the default dry
run. `username` and `database` may be empty for Redis; its password remains
required. Prefer the environment variable for the Dokploy control-plane URL so
its credentials do not appear in the process list:

```sh
export DOCKYARD_DOKPLOY_DATABASE_URL='postgres://dokploy:...@source/dokploy'
dockyard migrate-dokploy-data \
  --source-organization 'dokploy-organization-id' \
  --target-organization 'dockyard-organization-uuid' \
  --connections-file /secure/path/database-connections.json
```

For the final transfer, stop application writes or put the source application
in maintenance mode, take a separate recovery backup, then explicitly confirm
the destructive target restore:

```sh
dockyard migrate-dokploy-data \
  --source-organization 'dokploy-organization-id' \
  --target-organization 'dockyard-organization-uuid' \
  --connections-file /secure/path/database-connections.json \
  --dry-run=false \
  --confirm 'dockyard-organization-uuid'
```

Each transfer is a durable, cancellable job. Inspect it with
`GET /v1/database-migrations/{id}` and request cancellation with
`POST /v1/database-migrations/{id}/cancel`. A retry repeats the native restore;
PostgreSQL cleans existing objects, MySQL/MariaDB replay the dump, and MongoDB
uses `--drop`. PostgreSQL custom dumps and MySQL/MariaDB
`--single-transaction` provide consistent snapshots for their supported
workloads. A MongoDB archive is not a globally transactional snapshot; quiesce
writes before the final dump. Temporary dump files stay on the Swarm manager,
are checksummed, and are removed after the attempt. Connection passwords are
encrypted at rest and are not placed in command arguments, reports, or logs.

## Verify the imported control plane

After deploying every imported Compose/application service and completing the
native database transfers, run the fail-closed verifier:

```sh
dockyard verify-dokploy-import \
  --source-organization 'dokploy-organization-id' \
  --target-organization 'dockyard-organization-uuid'
```

The JSON result checks every persisted project, environment, service, route,
database, backup destination/policy, volume-backup policy, source credential, and notification
mapping. With the default `--require-operational=true`, each imported service
and managed-database stack must have a successful deployment of its current
revision plus a healthy Swarm reconciliation observation from the previous
five minutes. Each database, including a Compose-linked target, must also be
running, and each imported managed PostgreSQL,
TimescaleDB, MySQL, MariaDB, MongoDB, Redis, Valkey, or libSQL database must
have a successful Dokploy data-transfer record. Every enabled named-volume policy must be bound to its
service's Swarm storage node and have a successful encrypted backup with
database-validated restore metadata created after the final import. Every
enabled imported database-backup policy likewise needs a valid encrypted
remote recovery point created after that import. Trigger
those backups explicitly if their next scheduled run falls outside the cutover
window with `dockyardctl backup-database DATABASE_ID` and `dockyardctl
backup-volume SERVICE_ID VOLUME_NAME`, then inspect the returned job IDs with
`dockyardctl database-backup BACKUP_ID` and `dockyardctl volume-backup
BACKUP_ID`. Missing targets, stale or unhealthy stacks, incomplete backup evidence,
and unconverted resources make the command exit non-zero. Allow the controller's
one-minute reconciler to observe newly deployed stacks before running the final
verification.

Some source features deliberately require manual conversion. After completing
and documenting one, acknowledge its exact parity key explicitly; the entry
and its reason remain visible in the report:

```sh
dockyard verify-dokploy-import \
  --source-organization 'dokploy-organization-id' \
  --target-organization 'dockyard-organization-uuid' \
  --acknowledge 'source_credential:github:source-github-id'
```

Use repeatable `--acknowledge` flags rather than a blanket skip switch. Run the
non-dry-run importer again before verification so older or changed Dokploy
resources are reflected; manifests created before core-resource tracking are
rejected. This verifier proves Dockyard-side mapping and recorded operation
completion, not application-level correctness or DNS behavior.

Organization administrators can run the same verifier from the Governance
console. The API equivalent is `POST /v1/migration-resources/verify`; it
defaults to operational verification, accepts only explicit `kind:source-id`
acknowledgements, returns every check even when `ready` is false, and appends
the aggregate result to the tenant audit log without storing acknowledgement
text.

For remote automation, `dockyardctl verify-dokploy-migration -` accepts that
request JSON on standard input, prints the complete report, and exits non-zero
when the report is not ready. `dockyardctl migration-resources
[SOURCE_ORGANIZATION_ID] [NEXT_CURSOR]` pages the underlying manifest.

Keep Dokploy running until every reported resource has a documented mapping,
then perform a maintenance-window dry run, database backup, final import,
database transfer, DNS cutover, and application-level validation. The
control-plane importer does not deploy stacks, copy volumes, restore database
data, or modify DNS automatically; the separate data command queues the native
database transfers only.
