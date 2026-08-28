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
  enabled application domains; Docker target stages and recursive Git
  submodules are preserved;
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

- Nixpacks, Railpack, Paketo/Heroku buildpack, static, and drop applications;
- Git applications with build arguments, build secrets, non-HTTPS clone URLs,
  or provider-specific private access;
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
record, but it does not copy persistent volume contents. Back up every source
database, restore it into the imported destination during a maintenance window,
and validate application-level reads and writes before changing DNS or stopping
Dokploy. Treat Redis and libSQL specially because their automated native
backup/restore workflow is not yet verified by Dockyard.

Keep Dokploy running until every reported resource has a documented mapping,
then perform a maintenance-window dry run, database backup, final import,
database restore, DNS cutover, and application-level validation. The importer
does not deploy stacks, copy volumes, restore database data, or modify DNS
automatically.
