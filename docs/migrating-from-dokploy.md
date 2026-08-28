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
  --dry-run=true
```

The JSON report lists convertible projects, environments, Compose services,
routes, skipped resources, and manual actions. Repeated imports map every
source identifier to the same target UUID, so a retry updates imported
resources instead of duplicating them.

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

## Current conversion coverage

Imported automatically:

- projects and environments;
- inline/raw Compose definitions;
- Compose environment values when the source key is supplied;
- enabled Compose domains with service name and valid target port.

Reported for a later conversion phase:

- Dokploy application records that need a generated Compose definition;
- managed databases, because their credentials and persistent volumes require
  an explicit cutover and restore plan;
- Compose definitions stored only in a remote Git repository;
- provider credentials, SSH keys, certificates, schedules, and notifications.

Keep Dokploy running until every reported resource has a documented mapping,
then perform a maintenance-window dry run, database backup, final import, DNS
cutover, and application-level validation. The importer does not deploy stacks
or modify DNS automatically.
