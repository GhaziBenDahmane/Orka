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
managed databases, routes, skipped resources, and manual actions. Its
structured `resources` entries record every application's deterministic target
ID, disposition, source/build mode, resource settings, and boolean flags for
credentials, build arguments, and build secrets. Secret values and URL
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
  enabled application domains;
- PostgreSQL, MySQL, MariaDB, MongoDB, Redis, and libSQL managed-database
  definitions, including their image, credentials, and custom environment;
- enabled Compose domains with service name and valid target port.

Reported for manual conversion:

- Nixpacks, Railpack, Paketo/Heroku buildpack, static, and drop applications;
- Git applications with build arguments, build secrets, target stages,
  submodules, non-HTTPS clone URLs, or provider-specific private access;
- application mounts, published host ports, custom Swarm health/restart/update/
  placement settings, redirects, and security rules;
- Compose definitions stored only in a remote Git repository;
- provider credentials, SSH keys, certificates, schedules, and notifications.

Imported Git applications initially have no Git or registry credential attached.
Recreate those credentials in Dockyard and attach them to the imported source
before the first deployment. Docker-image applications that pull from a private
registry likewise require operator validation; the current Swarm deployment
path does not propagate per-application registry credentials.

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
