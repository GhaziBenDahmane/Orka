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

Remote agent identities use short-lived X.509 client certificates issued from
a dedicated Dockyard CA. Enrollment accepts a proof-of-possession CSR, ignores
caller-supplied certificate identities, and binds the certificate to
`spiffe://dockyard/cluster/{uuid}`. Agent certificates are client-auth only and
capped by the CA lifetime; rotation reuses the same verified cluster identity.
