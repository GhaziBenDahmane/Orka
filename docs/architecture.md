# Architecture

Dockyard is split into a control plane and a Swarm execution adapter. The API,
reconciler, and job workers share PostgreSQL as their source of truth. Docker
Swarm remains responsible for service placement and desired-state convergence;
Docker Compose remains the portable workload definition.

## Deployment lifecycle

1. An authenticated actor creates a deployment for a Compose service.
2. The API stores an immutable deployment snapshot and enqueues a PostgreSQL job.
3. A worker claims the job with `FOR UPDATE SKIP LOCKED`.
4. The Compose compiler validates the document, injects Dockyard and Traefik
   labels, and ensures the public overlay network is attached where needed.
5. The Swarm adapter runs `docker stack deploy --prune --resolve-image=always`.
6. The worker polls Swarm services until replicas converge or the deadline is
   exceeded, then records events and an audit entry.
7. Rollback creates a new deployment from the last successful snapshot. History
   is never edited in place.

Deletion is also asynchronous. The API first marks a service as deleting and
queues a finalizer. The worker removes the Swarm stack before deleting database
records and locally retained backups. A busy service must be cancelled or
allowed to finish before deletion can begin.

## Trust boundaries

- Passwords use Argon2id. Session tokens are random and only their SHA-256
  digests are persisted.
- Sensitive application values are encrypted with AES-256-GCM using the
  instance master key.
- Every query is scoped through an organization membership.
- Compose validation rejects privileged containers, host networking, host PID,
  Docker socket mounts, and host-path volumes unless an administrator explicitly
  enables unsafe workloads.
- Docker commands receive arguments directly; user input is never evaluated by
  a shell.

## Extensibility

Builders, schedulers, routers, backup stores, identity providers, and database
engines are application-layer interfaces. External extensions will use a
versioned RPC protocol instead of Go's ABI-sensitive plugin mechanism.

The `deploy.Scheduler` contract isolates all Swarm operations from the API and
worker. The in-process adapter invokes Docker directly for a single manager;
the multi-cluster adapter can therefore route the same validated Compose
snapshot through outbound agents without changing application or database
models.

Private build-registry credentials are scoped to the configured registry host.
After a successful push, the scheduler supplies them to `docker stack deploy
--with-registry-auth` through a temporary mode-0700 Docker configuration. For a
remote Swarm the credential travels only inside the encrypted, fenced command
payload and is materialized by the outbound agent for that deployment.

Remote agent identities use short-lived X.509 client certificates issued from
a dedicated Dockyard CA. Enrollment accepts a proof-of-possession CSR, ignores
caller-supplied certificate identities, and binds the certificate to
`spiffe://dockyard/cluster/{uuid}`. Agent certificates are client-auth only and
capped by the CA lifetime; rotation reuses the same verified cluster identity.

Heartbeats use a separate optional TLS listener configured with
`DOCKYARD_AGENT_LISTEN_ADDR`, `DOCKYARD_AGENT_SERVER_CERT_FILE`, and
`DOCKYARD_AGENT_SERVER_KEY_FILE`. It requires a CA-verified client certificate
and matches its serial number against the cluster's current database record,
so reenrollment immediately supersedes the previous identity.

Remote database utilities run on the target cluster. The controller grants a
single-operation presigned S3 transfer URL and sends a per-backup encryption
key only inside the encrypted mTLS command. Agents encrypt before upload and
verify encrypted size, encrypted checksum, and plaintext checksum before a
restore. Plaintext artifacts exist only in a mode-0700 temporary agent
directory and are removed when the command completes.

Multiple controller replicas coordinate durable jobs with `SKIP LOCKED` and a
fresh UUID fencing token for every execution attempt. Heartbeats and terminal
job state transitions must present that token. Resource start and completion
transitions for deployments, backups, restores, notifications, commit statuses,
and audit archives lock the owning job and update the resource in one database
transaction. A paused worker therefore cannot restart or finish a resource
after another replica recovers the expired attempt—even when the replacement
uses the same configured worker name. External Swarm, provider, and object-store
operations remain at-least-once and must be idempotent. Singleton maintenance
loops additionally use expiring, database-backed leader leases; only the
current holder schedules backup policy runs or prunes audit history, and
another replica takes over after expiry.

The stale-job reaper locks each expired job before changing either the job or
its resource, and skips rows currently held by a heartbeat or resource
transition. Job completion likewise locks the job while resolving a concurrent
cancellation, so cancellation cannot be lost to a success update.

`deploy/swarm-ha.yml` is layered over the base stack for a three-controller
deployment. It disables the bundled single-node PostgreSQL service, expects an
external highly available PostgreSQL URL, publishes the mTLS agent listener,
and rejects node-local managed-database backup policies. Shared PostgreSQL is
the coordination boundary; controllers do not require shared local state.
