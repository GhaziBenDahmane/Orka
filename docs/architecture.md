# Architecture

Dockyard is split into a control plane and a Swarm execution adapter. The API,
reconciler, and job workers share PostgreSQL as their source of truth. Docker
Swarm remains responsible for service placement and desired-state convergence;
Docker Compose remains the portable workload definition.

## Deployment lifecycle

1. An authenticated actor creates a deployment for a Compose service.
2. The API stores an immutable deployment snapshot and enqueues a PostgreSQL job.
   Source, artifact, route, template, and referenced credential mutations are
   rejected while that service has a queued or running deployment, preventing
   the worker from combining the snapshot with newer mutable execution inputs.
3. A worker claims the job with `FOR UPDATE SKIP LOCKED`.
4. The Compose compiler validates the document, injects Dockyard and Traefik
   labels, ensures the public overlay network is attached where needed, and
   adds conservative Swarm update/rollback defaults when the application did
   not declare its own rollout policy. Job-mode services are left unchanged.
5. The Swarm adapter runs `docker stack deploy --prune --resolve-image=always`.
6. The worker polls both replica counts and each service's Swarm update state.
   It records success only after replicas converge and any update completes;
   paused updates and automatic rollbacks remain failed deployments instead of
   being mistaken for success when the old replicas return.
7. Rollback creates a new deployment from the last successful snapshot. History
   is never edited in place.

The leader-elected stack reconciler inspects every previously deployed stack
once per minute through the same local-or-remote scheduler boundary. Missing or
under-replicated stacks must be observed twice before repair. Repairs replay the
last successful effective Compose document and encrypted environment snapshot;
they do not overwrite a newer, undeployed service revision or rebuild a moving
Git ref. Active deployments, deletion finalizers, maintenance policies, and
cluster maintenance windows suppress repair, while a ten-minute cooldown and a
database uniqueness constraint prevent repair storms. Inspection failures are
recorded as `unknown`, not mistaken for missing workloads. Reconciliation state
is included in the secret-free AI audit snapshot and Prometheus metrics.
Services last deployed before the effective-snapshot migration must complete
one normal deployment before automatic repair is enabled.

Deletion is also asynchronous. The API first marks a service as deleting and
queues a finalizer. The worker removes the Swarm stack before deleting database
records and locally retained backups. A busy service must be cancelled or
allowed to finish before deletion can begin.

## Trust boundaries

- Passwords use Argon2id. Session tokens are random and only their SHA-256
  digests are persisted. OIDC and SAML sessions are bound to the organization
  that owns the authenticating provider; upgrades revoke legacy federated
  sessions that predate this binding rather than guessing their tenant.
- Sensitive application values are encrypted with AES-256-GCM using the
  instance master key. New Compose environments use the service ID as
  authenticated context, preventing ciphertext from being transplanted between
  services. Managed-database, source, and backup-destination credentials are
  likewise bound to their resource IDs. Workers retain read compatibility with
  legacy unbound ciphertext.
- Uploaded application ZIPs are size-bounded, fully validated, encrypted with
  service-bound authenticated data, and stored in PostgreSQL so any controller
  can execute the build. Extraction rejects traversal, links, devices, FIFOs,
  duplicate/conflicting paths, encrypted entries, and expansion bombs.
- Every query is scoped through an organization membership.
- Compose validation rejects privileged containers, custom namespace sharing
  (with `network_mode: none` as the disabled-network exception), host mounts,
  cluster/named-pipe mounts, custom volume drivers, device/capability access,
  GPU/runtime plugins, unsafe security profiles, controller-local environment,
  label, or extended Compose files, Compose-managed secrets/configs,
  cross-stack volumes or networks, direct port publishing, and caller-supplied
  Traefik labels unless an administrator explicitly enables unsafe workloads.
  The configured public overlay network is reserved: safe Compose input cannot
  declare or attach it, and the compiler attaches it only to services with
  approved routes. Routing labels are generated only from tenant-scoped route
  records after canonical hostname and injection-safe path validation.
- Safe stacks use replicated scheduling and are capped at 100 aggregate tasks;
  node-wide global services and jobs require explicit unsafe-workload mode.
- Safe workloads may use only Docker's local, JSON-file, or disabled logging
  drivers with local rotation options; daemon-side network/plugin log drivers
  require unsafe-workload mode.
- Host cgroup, kernel, ulimit, storage, lifecycle-hook, model-runner, and generic
  resource directives are also reserved for explicit unsafe workloads.
- Traefik reaches the controller over a dedicated encrypted edge network that
  is not shared with routed tenant workloads. Forwarded client addresses and
  HTTPS state are accepted only from explicitly configured proxy CIDRs; the
  direct mTLS agent listener never trusts forwarding headers.
- Docker commands receive arguments directly; user input is never evaluated by
  a shell.

## Extensibility

Builders, schedulers, routers, backup stores, identity providers, and database
engines are application-layer interfaces. External extensions will use a
versioned RPC protocol instead of Go's ABI-sensitive plugin mechanism.

AI auditors sit outside the trusted control plane. An isolated service-account
role can read a purpose-built, secret-free inventory and append findings only
to runs owned by that identity. The default runner has no shell, Docker socket,
or direct database access. Its OpenAI-compatible model endpoint can be a
self-hosted 9Router service; general agents such as Hermes use the same narrow
API contract rather than privileged infrastructure tools. Findings never
execute automatically.

The `deploy.Scheduler` contract isolates all Swarm operations from the API and
worker. The in-process adapter invokes Docker directly for a single manager;
the multi-cluster adapter can therefore route the same validated Compose
snapshot through outbound agents without changing application or database
models.

Named-volume artifacts use a one-shot Swarm service constrained to the node
that owns the local volume. The service reuses the currently running
digest-pinned controller or agent image. Its presigned object-store URL and
per-artifact encryption key are mounted as a temporary Swarm secret rather
than exposed in arguments or environment variables. Plaintext tar data is
streamed through the authenticated encryption layer and never staged as a
whole archive; restore performs a complete authenticated validation pass
before a second streaming extraction pass. The helper swaps staged data into
the volume with rollback renames. Restore always scales every
mounting stack service to zero and resumes its recorded replica count; backup
policies can require the same quiescence boundary.

Private build-registry credentials are scoped to the configured registry host.
After a successful push, the scheduler supplies them to `docker stack deploy
--with-registry-auth` through a temporary mode-0700 Docker configuration. For a
remote Swarm the credential travels only inside the encrypted, fenced command
payload and is materialized by the outbound agent for that deployment. Each
deployment retains an encrypted copy of the selected registry credential and
its exact authority. Rollback and reconciliation copy that snapshot instead of
consulting the mutable application source, so credential rotation or deletion
cannot silently change the authentication identity of an immutable replay.

Remote agent identities use short-lived X.509 client certificates issued from
a dedicated Dockyard CA. Enrollment accepts a proof-of-possession CSR, ignores
caller-supplied certificate identities, and binds the certificate to
`spiffe://dockyard/cluster/{uuid}`. Agent certificates are client-auth only and
capped by the CA lifetime. Before the first request, the agent durably stores a
mode-0600 pending private key. The controller binds the consumed token to that
exact CSR and stores the issued public certificate material, allowing a lost
response to be retried until token expiry without permitting a second key to
enroll. The pending key is removed only after the validated identity is durable.
Rotation reuses the same verified cluster identity,
validates the replacement against the saved CA and newly generated private key
before atomic persistence, and records it as pending. The controller promotes
that serial and revokes the old one only after the replacement successfully
authenticates, so an interrupted response or disk failure cannot strand the
agent. Each active and pending identity records its signing-CA SHA-256
fingerprint so CA migration is observable per cluster.

Heartbeats use a separate optional TLS listener configured with
`DOCKYARD_AGENT_LISTEN_ADDR`, `DOCKYARD_AGENT_SERVER_CERT_FILE`, and
`DOCKYARD_AGENT_SERVER_KEY_FILE`. It requires a CA-verified client certificate
and matches its serial number against the cluster's current or pending database
record. Reenrollment with a newly issued token immediately supersedes both
identities. Controller
startup validates that the configured active CA is current, self-signed,
signing-capable, and matches its private key. During a bounded CA rollover it
accepts one different, currently valid previous CA and permits the listener
certificate to chain to either authority. Authenticated heartbeat and rotation
responses distribute the combined trust bundle and active signer; agents
persist trust before replacing their identity. The controller also verifies
the listener's server-auth usage, validity window, and private key. Prometheus
exposes fixed-label expiry gauges for the active CA, optional previous CA, and
listener certificate.

The release gate exercises client-certificate and CA rotation through real TLS
1.3 listeners. It preserves the active serial while a replacement is pending,
promotes only after the replacement heartbeat, verifies the cluster's CA
fingerprint, switches to a listener signed by the new CA, removes old trust,
and rejects a retired-CA identity. Production rollout remains a staging gate
because it changes the real controller trust roots and every deployed agent.

Remote database utilities run on the target cluster. The controller grants a
single-operation presigned S3 transfer URL and sends a per-backup encryption
key only inside the encrypted mTLS command. Agents encrypt before upload and
verify encrypted size, encrypted checksum, and plaintext checksum before a
restore. Plaintext artifacts exist only in a mode-0700 temporary agent
directory and are removed when the command completes.

Multiple controller replicas coordinate durable jobs with `SKIP LOCKED` and a
fresh UUID fencing token for every execution attempt. Heartbeats and terminal
job state transitions must present that token. Resource start and completion
transitions for deployments, backups, restores, database migrations,
notifications, commit statuses, and audit archives lock the owning job and update the resource in one database
transaction. A paused worker therefore cannot restart or finish a resource
after another replica recovers the expired attempt—even when the replacement
uses the same configured worker name. Outbound agent commands created by a
worker also persist the parent job ID and lease ID. Command claim, renewal, and
completion validate that exact live parent attempt under a database lock, so
an agent cancels stale execution when recovery fences its originating worker.
External Swarm, provider, and object-store operations remain at-least-once and
must be idempotent. Singleton maintenance
loops additionally use expiring, database-backed leader leases; only the
current holder schedules backup policy runs, reconciles stack state, archives
or prunes audit history, and another replica takes over after expiry. Repair
queue creation is independently serialized on the service row and constrained
to one active reconciliation deployment, so a lease handoff cannot enqueue
duplicate repairs.

The audit-pruner lease also protects credential cleanup. Terminal sessions,
API tokens, invitations, and cluster enrollment tokens are retained for 30
days for operational investigation; expired OIDC/SAML login state and SAML
replay assertions are removed on the next hourly pass. Each pass deletes at
most 10,000 rows of each kind in oldest-first index order to bound transaction
size and lock pressure. Prometheus reports any remaining eligible backlog.

Backup, restore, restore-drill, and migration jobs carry the same
`database:<uuid>` resource key. Workers claim those jobs in FIFO order and a
partial unique index permits only one running operation per database, including
under concurrent claims from separate workers. This prevents a destructive
restore from racing a backup or migration.

The stale-job reaper locks each expired job before changing either the job or
its resource, and skips rows currently held by a heartbeat or resource
transition. Job completion likewise locks the job while resolving a concurrent
cancellation, so cancellation cannot be lost to a success update.

`deploy/swarm-ha.yml` is layered over the base stack for a three-controller
deployment. It disables the bundled single-node PostgreSQL service, expects an
external highly available PostgreSQL URL, publishes the mTLS agent listener,
and rejects node-local managed-database backup policies. Shared PostgreSQL is
the coordination boundary; controllers do not require shared local state.
