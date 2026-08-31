# External database driver protocol

The current wire protocol is version 2. Drivers built for version 1 must be
rebuilt with the current SDK; version 2 adds explicit non-secret configuration
persistence metadata and keeps exact-version negotiation fail closed.

Trusted executable drivers extend the built-in database catalog without being
linked into the controller. Set `DOCKYARD_DATABASE_DRIVER_DIRECTORY` to an
absolute directory containing executable files owned by the controller's OS
user (root in the published container). The directory must have the same owner;
neither it nor its drivers may be group/world writable. A symlink cannot be
used as the directory, and symlinked entries and non-executable files are
ignored. When configured, startup fails if the directory contains no trusted
executable driver or if any discovered driver is invalid; discovery registers
the complete artifact set atomically. Driver names cannot replace built-ins.
External drivers are supported only on Linux. Every invocation opens the driver
without following symlinks, revalidates the opened inode, and executes that file
descriptor so a path swap cannot bypass the startup checks. The controller also
hashes the executable used for `describe`, rejects files larger than 64 MiB,
and refuses every later operation if the newly opened artifact no longer
matches that startup digest.
The digest, but never the host path, is exposed in engine inventory and AI
audit snapshots for release provenance.

New managed databases persist the driver source and artifact digest used to
render them. Recovery and migration workers compare that identity before
calling a driver, so HA controllers with different external binaries fail
closed instead of processing the same database inconsistently. Databases that
predate this metadata are marked `unbound`; the first leased recovery or
migration job atomically binds them to that worker's installed driver, and a
different worker cannot race in with another artifact.

To adopt a reviewed driver update, an administrator uses
`POST /v1/databases/{id}/driver-rebind` and confirms the database slug. The
operation locks the database against new recovery and migration queue entries,
refuses any already active operation, and commits the new digest with its audit
event atomically. Every controller should have the new artifact before the
rebind; a worker that still has the previous digest will fail closed.

Prometheus exposes `dockyard_database_driver_info` for each loaded engine and a
controller-wide `dockyard_database_driver_inventory_info` fingerprint. The
fingerprint includes only engine, source, artifact identity, and recovery
capability—not executable paths. In HA, every replica must report the same
fingerprint. `dockyard_database_driver_binding_issues` aggregates databases
that are still `unbound`, whose driver is `unavailable`, or whose persisted
identity has an `identity_mismatch`. Treat either supplied driver alert as a
stop signal for recovery and migration work; reconcile controller artifacts
before using the audited rebind endpoint.

Dockyard starts a fresh process for each call, writes one JSON request to stdin,
and reads one JSON response from stdout. Protocol version 2 supports
`describe`, `render`, `backup`, `restore`, and `readiness`. Calls time out after
15 seconds, each invocation and its descendants run in a dedicated process
group that is terminated on return, post-exit output-pipe draining is bounded,
and input and output are each capped at 4 MiB. The Go SDK rejects
unknown request fields, trailing JSON, and operation-confused request shapes
before invoking driver code. The controller independently bounds its encoded
request and validates render names, versions, utility hosts, credential maps,
and artifact filenames before starting the privileged extension process.
Utility plans are executed in the same isolated Docker jobs as built-in
drivers. A driver may return a version tag, but the target Swarm manager pulls
that tag once, inspects the resulting repository digest, and returns a
`repository@sha256:...` identity before any utility command is queued. Local
and remote execution boundaries reject mutable images; encrypted agent
commands for readiness, backup, restore, and migration therefore carry only
the resolved digest. Resolution is bounded to ten minutes and rejects digest
aliases belonging to a different canonical repository. Successful backup,
restore, and migration records expose
the exact utility image identities as recovery evidence. Images without a
repository digest fail closed. Image names and artifact extensions are
validated before resolution. Plans are limited to 128 non-empty
arguments (128 KiB total), 128 POSIX-named environment entries (1 MiB total),
and 32 basename-only helper files (1 MiB total). An argument is at most 16 KiB,
an environment value or helper file is at most 64 KiB, and NUL bytes are
rejected. The controller and remote cluster agent independently apply these
limits before creating files or invoking Docker. Backup and restore plans are
accepted only when `backup-restore` was declared, and their extension must
match `backupExtension`.

`dockyard_database_utility_provenance_issues` reports successful backup,
restore, drill-readiness, and migration records whose stored image identity is
missing or mutable. `DockyardDatabaseUtilityProvenanceMissing` alerts on any
such record, and the deterministic AI auditor raises the corresponding
supply-chain finding without exposing credentials or command arguments.

Driver stderr and protocol error text are deliberately not copied into API,
job, or audit errors: requests may contain plaintext database credentials and a
faulty driver could echo them. Failures identify only the trusted driver and
operation. Diagnose a driver locally with scrubbed test credentials before
installing it. The process receives a fixed system `PATH` and no inherited
controller environment.

Go plugins can import `github.com/bendahma/dokploy-go/pkg/databaseplugin`,
implement `databaseplugin.Driver`, and call:

```go
func main() {
    if err := databaseplugin.Serve(myDriver{}, os.Stdin, os.Stdout); err != nil {
        log.Fatal(err)
    }
}
```

`Describe` returns a lowercase unique name, default image version, and optional
`backup-restore` capability with `backupExtension`. It may also declare
`persistentConfigKeys`, a bounded list of non-secret render-input keys that the
controller may retain as database metadata. External configuration is
render-only by default: undeclared keys are never persisted, so drivers must
return operational secrets through the encrypted `credentials` or `environment`
result maps. Key names and recursively nested JSON configuration are bounded
and validated before the executable runs.

`Render` returns Compose YAML, runtime environment, one-time credentials,
internal URL, and resolved version. Descriptions reject unknown or duplicate
capabilities and persistence keys and require the backup extension to agree
with `backup-restore`. Rendered versions, environment and credential maps, and
absolute internal URLs are bounded and validated at the process boundary.
Internal URLs must be valid UTF-8 and cannot contain Unicode control or
formatting characters. Rendered Compose is passed through
the configured compiler policy used for user services before it can be persisted
or used by a restore drill. Protocol responses reject unknown fields, trailing JSON, and fields that
do not belong to the requested operation. Utility methods return an image,
argv array, environment, extension, and optional small configuration files.
Passwords belong in the environment or files, never argv.

Drivers execute with controller privileges and receive plaintext generated
database credentials when operational plans are requested. Package, sign,
review, and deploy them as trusted control-plane artifacts. Restart controllers
after changing the directory; hot loading is intentionally unsupported.

## Production packaging

Bake reviewed drivers into a derived controller image rather than distributing
mutable host files. A minimal Dockerfile in a private build context is:

```dockerfile
ARG DOCKYARD_IMAGE
FROM ${DOCKYARD_IMAGE}
COPY --chown=0:0 --chmod=0555 database-drivers/ /usr/local/lib/dockyard/database-drivers/
RUN dockyard inspect-database-drivers --directory /usr/local/lib/dockyard/database-drivers
ENV DOCKYARD_DATABASE_DRIVER_DIRECTORY=/usr/local/lib/dockyard/database-drivers
```

Pass an already signed Dockyard digest as `DOCKYARD_IMAGE`, build with network
access disabled when the builder supports it, scan and sign the derived image,
then push and resolve that image to its own immutable digest. The inspection
command executes every driver's bounded `describe` operation and emits a
deterministic, path-free JSON inventory containing the protocol version,
per-driver artifact hashes, and a digest over the complete external inventory.
It fails when the directory is empty or any artifact violates the protocol or
filesystem trust rules.

Deploy the derived digest through the standard fail-closed installer with the
external-driver profile enabled:

```sh
export DOCKYARD_IMAGE='registry.example/dockyard-with-drivers@sha256:...'
export DOCKYARD_INSTALL_EXTERNAL_DATABASE_DRIVERS=true
DOCKYARD_INSTALL_DRY_RUN=true scripts/install-swarm.sh
scripts/install-swarm.sh
```

Embedding the drivers makes every controller task consume the same immutable
artifact set. The installer runs `inspect-database-drivers` inside that exact
image with networking disabled and a read-only root filesystem before rendering
or mutating Swarm, then includes `deploy/swarm-database-drivers.yml` in both
preflight and deployment. Do not mount a mutable shared directory into HA controllers.
After rollout, query every task through the per-replica Prometheus discovery
configuration and require both the controller-build and database-driver
inventory mismatch alerts to remain clear before allowing recovery or migration
jobs.
