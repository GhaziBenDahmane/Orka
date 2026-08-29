# Migrating from Dokploy

The migration command reads Dokploy's PostgreSQL database and writes into an
existing Dockyard organization. It never modifies the Dokploy database. The
current converter targets the schema inspected at Dokploy commit
`ab62080e9d378190594d2f104fbfa287507a5b84`.

Always start with a dry run:

```sh
dockyard migrate-dokploy \
  --source-url 'postgres://dokploy:...@source/dokploy' \
  --source-organization 'dokploy-organization-id' \
  --target-organization 'dockyard-organization-uuid' \
  --registry-prefix 'registry.example.com/team/dockyard' \
  --dry-run=true
```

`--registry-prefix` is required only when the source contains convertible Git
applications. Dockyard uses it as the destination repository prefix for images
built from imported Dockerfiles.

The JSON report lists convertible projects, environments, Compose services,
managed databases, routes, notifications, skipped resources, and manual
actions. Its structured `resources` entries record deterministic target IDs,
dispositions, and secret-safe compatibility metadata. Secret values and URL
credentials are never included. Repeated imports map every source identifier
to the same target UUID, so a retry updates imported resources instead of
duplicating them.

Dokploy environment columns may use AES-256-GCM encryption. Export the derived
keys using Dokploy's `exportEncryptionKeys()` facility, place the resulting
hex lines in a mode-0600 file, then pass:

```sh
--encryption-key-file /secure/path/dokploy-encryption.keys
```

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
- inline/raw Compose definitions;
- Compose environment values when the source key is supplied;
- Docker-image applications and HTTPS Git applications that use a Dockerfile,
  including runtime environment, replicas, resource reservations/limits, and
  enabled application domains; Docker target stages, build arguments,
  re-encrypted BuildKit secrets, and recursive Git submodules are preserved;
- PostgreSQL, MySQL, MariaDB, MongoDB, Redis, and libSQL managed-database
  definitions, including their image, credentials, and custom environment;
- S3-compatible backup destinations, with credentials decrypted only in memory
  and re-encrypted under the Dockyard master key;
- registry credentials plus GitLab, Gitea, and Bitbucket token credentials;
  compatible credentials are attached to imported Git applications when the
  repository or build-registry host matches;
- the first enabled or disabled database backup policy for each imported,
  backup-capable database when its cron expression has a constant interval;
  per-policy object prefixes are preserved with deterministic destination
  variants;
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
- GitHub App credentials, SSH keys, certificates, unsupported or calendar-based
  backup schedules, additional policies for the same database, and Compose
  backup policies;
- Telegram, Discord, Resend, Gotify, ntfy, Mattermost, Pushover, custom, Lark,
  and Teams notification providers.

Dokploy `appBuildError` and `databaseBackup` notification triggers map to
Dockyard `deployment.failed` and `backup.failed`. Dokploy success, volume,
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

Managed-database import creates the destination Compose service and database
record, but the control-plane import does not copy persistent volume contents.
Use the native transfer command below for PostgreSQL, MySQL, MariaDB, MongoDB,
and Redis. libSQL and other engines still require an operator-managed backup
and restore.

## Transfer managed database data

Deploy the imported target database stacks and verify they are healthy before
queuing data transfers. The target Swarm manager performs both the source dump
and target restore on the target stack's attachable overlay network, so every
source `host` and `port` in the manifest must be reachable from that network.

Create a mode-0600 connection manifest outside the repository:

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
database, backup destination/policy, source credential, and notification
mapping. With the default `--require-operational=true`, each imported service
and managed-database stack must have a successful deployment of its current
revision plus a healthy Swarm reconciliation observation from the previous
five minutes. Each database must also be running, and each PostgreSQL, MySQL,
MariaDB, MongoDB, or Redis database must have a successful Dokploy
data-transfer record. Missing targets, stale or unhealthy stacks, and
unconverted resources make the command exit non-zero. Allow the controller's
one-minute reconciler to observe newly deployed stacks before running the
final verification.

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

Keep Dokploy running until every reported resource has a documented mapping,
then perform a maintenance-window dry run, database backup, final import,
database transfer, DNS cutover, and application-level validation. The
control-plane importer does not deploy stacks, copy volumes, restore database
data, or modify DNS automatically; the separate data command queues the native
database transfers only.
