# Master-key rotation

Dockyard encrypts persisted environments, database and source credentials,
OIDC and SAML keys, webhooks, notifications, build material, backup data keys,
remote commands, and template inputs with `DOCKYARD_MASTER_KEY`. Rotate that key
in a maintenance window with `dockyard rotate-master-key`; changing only the
runtime secret makes the stored data unreadable.

The command defaults to a dry run. It discovers every database column whose
name contains `encrypted_` and refuses a schema newer or older than its audited
inventory. It then takes an advisory lock and exclusive locks on the encrypted
tables, rejects live controller leases or running jobs, authenticates every
non-empty ciphertext with the current key, and reports counts and truncated key
fingerprints only. Execution repeats authentication, encrypts and immediately
verifies each replacement, and commits all updates in one PostgreSQL
transaction. A failure leaves every original ciphertext intact. Legacy
resource secrets are rewritten with resource-bound authenticated contexts.

## Preparation

1. Record the running immutable Dockyard image digest and current schema
   version. Do not change versions during rotation.
2. Create and verify a fresh control-plane recovery bundle with
   `scripts/backup-control-plane.sh`. Preserve its matching old master key and
   independently stored Ed25519 recovery verification key.
3. Generate 32 random bytes, base64 encode them as one line, and store them in a
   new mode `0600` file and in the secret manager. Never overwrite the old key.
4. Stop every Dockyard controller replica. Leave PostgreSQL running. Wait for
   in-flight jobs to finish before the shutdown; the rotation refuses any job
   still marked `running`.

Example key generation and local invocation against an externally reachable
PostgreSQL database:

```sh
umask 077
openssl rand -base64 32 > /secure/dockyard/master-key-v2
docker service scale dockyard_dockyard=0

export DOCKYARD_DATABASE_URL_FILE=/secure/dockyard/database-url
dockyard rotate-master-key \
  --old-key-file /secure/dockyard/master-key \
  --new-key-file /secure/dockyard/master-key-v2
```

The dry-run JSON contains `newFingerprint`. Review `validated` and `byTable`,
then execute with that exact fingerprint:

```sh
dockyard rotate-master-key \
  --old-key-file /secure/dockyard/master-key \
  --new-key-file /secure/dockyard/master-key-v2 \
  --dry-run=false \
  --confirm 'sha256:REPLACE_WITH_DRY_RUN_FINGERPRINT'
```

Key files must be regular files with no group or other permissions. Symlinks,
invalid base64, keys other than 32 bytes, and identical old/new keys are
rejected. Supplying the database URL as `--database-url` is supported but is
discouraged because process arguments may be observable.

## Bundled Swarm PostgreSQL

The bundled PostgreSQL service is reachable on the `dockyard_control` overlay.
Run the same immutable Dockyard image as a one-shot Swarm service after scaling
the controller to zero. Mount the database URL, old key, and new key as Docker
secrets. First run the default dry run, inspect its service log for the JSON
report, remove that completed service, and create a second one with
`--dry-run=false --confirm sha256:...`. The one-shot service must use
`--restart-condition none`, the `dockyard_control` network, and no Docker
socket. Remove it after success.

Create a versioned runtime secret rather than deleting the recovery key:

```sh
docker secret create dockyard_master_key_v2 /secure/dockyard/master-key-v2
export DOCKYARD_MASTER_KEY_SECRET=dockyard_master_key_v2
docker stack deploy --with-registry-auth --compose-file deploy/swarm.yml dockyard
```

Persist `DOCKYARD_MASTER_KEY_SECRET=dockyard_master_key_v2` in the deployment
configuration used for later upgrades. `scripts/install-swarm.sh` uses the same
variable when validating, creating, or explicitly reusing the versioned Docker
secret, so later installer-driven upgrades preserve the selection. Confirm
`/readyz`, login, inspect a
service with encrypted environment values, fetch a source-backed build, verify
an SSO provider, and perform a managed-database restore drill. Keep the old key
and pre-rotation recovery bundle under the normal retention policy; do not make
the old key available to the running controller.

## Rollback

Before transaction commit, no rollback action is needed: the command rolls back
automatically and the controller can restart with the old key. After a
successful commit, do not restart against the old database with the old key.
If post-rotation validation fails, stop all controllers, restore the complete
pre-rotation PostgreSQL recovery bundle, select the old versioned Docker secret,
and start the exact recorded image digest. Database and master key must always
come from the same recovery epoch.
