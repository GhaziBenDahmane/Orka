# Security policy

## Reporting and support

Report suspected vulnerabilities privately to the project owner. Do not open a
public issue until a fix is available. Security support applies only to the
latest tagged release; deployments must also run supported PostgreSQL, Docker
Engine, Swarm, and object-storage releases with vendor security updates.

## Trust boundaries

Dockyard's API, workers, PostgreSQL database, master key, agent certificate
authority, and local Swarm manager are trusted control-plane components.
Compose documents, source repositories, images, webhooks, template catalogs,
tenants, and workload containers are untrusted.

The local controller mounts the Swarm manager Docker socket. Possession of that
socket is effectively root access to the cluster. Restrict controller
administration, do not expose the socket over TCP, and isolate the manager from
application traffic. Remote clusters use the outbound-only agent instead: its
identity is a short-lived TLS 1.3 mTLS certificate with the SPIFFE identity
`spiffe://dockyard/cluster/{uuid}`. Enrollment tokens are single-use. Protect
the agent state volume, rotate the agent CA according to organizational PKI
policy, and revoke/re-enroll a cluster after suspected key compromise.

Compose workloads are rejected when they request privileged mode, host
namespaces, the Docker socket, or host bind mounts. Setting
`DOCKYARD_ALLOW_UNSAFE_WORKLOADS=true` removes this boundary and is suitable
only for a dedicated, isolated cluster whose workloads are fully trusted.

## Secrets and transport

- Terminate public traffic with modern TLS. The agent listener requires TLS
  1.3 and verified client certificates.
- Generate `DOCKYARD_MASTER_KEY` from 32 random bytes. Store it in a secret
  manager or Docker secret, never in a repository or image.
- Back up the master key separately from PostgreSQL. Losing it makes encrypted
  environment values, source credentials, provider secrets, backup
  destinations, and wrapped backup keys unrecoverable. Database backups alone
  are insufficient.
- Rotating the master key currently requires an operator-controlled re-encrypt
  migration and maintenance window; do not simply replace it in place.
- Use a dedicated PostgreSQL role and database, certificate-and-hostname
  verified network transport when PostgreSQL is remote, and network policy
  limiting access to controllers. The HA profile enforces
  `sslmode=verify-full` instead of accepting encrypted-but-unverified modes.
- External database drivers execute as the controller and are therefore trusted
  code. Their configured directory and executable files must be owned by the
  controller OS user and must not be group/world writable; symlinks are rejected
  or ignored.
- Docker build arguments are not secrets and may be retained in image metadata.
  Build secrets are encrypted in PostgreSQL and exposed to BuildKit only through
  short-lived mode `0600` files; keep credentials out of build arguments.
- Use HTTPS S3-compatible endpoints. Audit archives additionally require S3
  Object Lock in COMPLIANCE mode. Restrict credentials to the configured bucket
  and prefix.
- Treat API bearer tokens, SCIM tokens, deploy hooks, enrollment tokens, SSH
  keys, registry credentials, and presigned artifact URLs as secrets.

## Backup and disaster recovery

Back up all of the following as one recovery set:

1. PostgreSQL with a database-native, transactionally consistent backup.
2. The exact Dockyard master key and agent CA key from the same recovery epoch.
3. Local backup artifacts, or the versioned/object-locked S3 bucket containing
   them.
4. Deployment configuration, Docker secrets, DNS/TLS configuration, and the
   image digest for the running release.

Restore into an isolated environment first. Restore PostgreSQL, provide the
original master key, start the same Dockyard version, verify `/healthz`, login,
decrypt a representative secret, inspect queued/running jobs, and run a managed
database restore drill. Upgrade only after that baseline succeeds. Never roll
back the binary across irreversible schema migrations; restore the pre-upgrade
PostgreSQL snapshot and matching secrets instead.

For the bundled Swarm PostgreSQL service,
`scripts/backup-control-plane.sh` creates a secret-free, checksummed recovery
bundle and `scripts/restore-control-plane.sh` verifies the dump, image, schema,
master-key fingerprint, and optional agent-CA fingerprint before destructive
restore. The restore command also refuses to run while the controller service
is active. These checks detect a mismatched recovery set; they do not replace
encrypted, access-controlled off-site storage for the bundle and escrowed keys.

Recommended starting objectives are PostgreSQL point-in-time recovery with a
15-minute RPO and a four-hour control-plane RTO. These are operator targets,
not product guarantees, until measured drills for the deployment are recorded.

## Release controls

Every release must pass the race-enabled test suite, migration upgrade test,
clean-install/restart smoke test, OpenAPI authentication classification,
`go vet`, `govulncheck`, license policy, SBOM generation, container scan, and
Compose/Swarm validation. See [docs/release-checklist.md](docs/release-checklist.md).
