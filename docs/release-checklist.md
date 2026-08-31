# Release checklist

A release is a promoted immutable image digest, not a mutable tag. Record the
operator, UTC time, source commit, image digest, schema version, and evidence
links for every item below.

## Automated gates

- Review `docs/threat-model.md` against the release diff. New trust boundaries,
  privileged integrations, or secret flows require controls and evidence in
  that document before promotion.
- Release publication is blocked on the complete reusable CI, eleven-engine
  database recovery, real Keycloak SSO, disposable three-manager Swarm HA,
  joined deployment lifecycle, drift reconciliation, real-mTLS agent
  certificate rotation, AI audit lifecycle, durable notification-provider
  delivery, Dokploy migration, and previous-image upgrade conformance
  workflows. Tag pushes do not run detached copies: the release
  workflow invokes all gates directly and publishes only after every job
  succeeds.
- Automated evidence is bound to the exact release source commit. Final
  promotion revalidates the complete producer assertions and rejects missing,
  stale, duplicated, mutable-image, or commit-mismatched evidence.
- CI is green for race tests, vet, binary and web builds, generated assets,
  OpenAPI coverage/security classification, migration fresh-install and
  checkpoint-upgrade tests, high-contention exactly-once queue claiming across
  multiple workers, per-attempt fenced stale-worker takeover while the
  superseded worker is paused inside a scheduler call, Compose and Swarm
  parsing, and a clean-install workload converging to a live Swarm replica.
- Startup validates the exact migration inventory and checks an established
  master-key verifier before applying newer migrations. Dokploy migration dry
  runs use a PostgreSQL-enforced read-only pool and reject stale, modified, or
  future schemas instead of repairing or advancing them.
- `govulncheck` reports no reachable known vulnerability.
- License policy passes; the SPDX JSON SBOM is attached to the release.
- Build and runtime base images are pinned by manifest digest, and the runtime
  image verifies its Git client and CA trust store without downloading mutable
  operating-system packages during the release build.
- Both amd64 and arm64 manifests referenced by the exact promoted image index
  have no high or critical findings. No finding is ignored merely because an
  upstream fix is unavailable; any exception must identify its owner and
  expiry date in the project's exception register.
- A clean Compose installation bootstraps an owner, creates project,
  environment, and service records, deploys the service to Swarm, verifies its
  replica, persists an undeployed revision across a controller restart, and
  rolls back to the last successful immutable snapshot on the live Swarm. The
  smoke test then backs up the control plane, rejects active-controller,
  modified-dump, and wrong-key restores, deletes live data, restores the dump,
  and verifies the authenticated workload state after restart. Restore metadata
  must be strictly verified as one signed snapshot by the recorded controller
  image, and the staged database must consume the same private dump snapshot
  whose signed checksum and size were validated. The release also invokes the
  verifier from the exact amd64 candidate digest against valid and modified
  signed metadata, including a matching agent CA certificate/private-key
  escrow pair, before accepting `control-plane-recovery-conformance.json`.
- Built-in 9Router, PostgreSQL, Redis, BarkTrace SQLite, and BarkTrace
  PostgreSQL templates deploy through the public API and remain healthy across
  a forced Swarm task replacement. The 9Router check covers deployment and
  replica convergence without requiring provider configuration or testing its
  product behavior. The data services also accept authenticated
  application-level writes and reads; the BarkTrace checks verify its SQLite
  file identity or PostgreSQL migration and marker state survives replacement.
  Post-replacement assertions are read-only and cannot recreate missing test
  data; the BarkTrace PostgreSQL variant replaces both its application and
  database services. Evidence records distinct pre/post task IDs and matching
  local image IDs for every replacement, including that PostgreSQL dependency,
  so a no-op update or image change cannot satisfy the gate. CI publishes
  `template-conformance.json` with template versions and Swarm-resolved image
  digests, including BarkTrace PostgreSQL's database dependency; both
  BarkTrace variants must resolve from the released
  `ghcr.io/barktrace/bark:0.31.0` tag.
- Run the AI-gateway recovery conformance test. It must quiesce and resume the
  9Router service around backup, keep presigned URLs and the encryption key out
  of Docker arguments and signed metadata, reject a running-service restore,
  reject mismatched keys and modified metadata, and leave a successful restore
  offline until the AI installer verifies both independently authenticated
  auditors. The release gate invokes the manifest verifier from the exact
  candidate image against both valid and post-signing-modified metadata; a
  source-only test or mocked Docker invocation cannot satisfy promotion.
- Every release after the first boots the previous published image digest,
  creates authenticated and encrypted tenant state, deploys a live stack, and
  stops the old controller against its persistent PostgreSQL volume. The
  candidate then validates every recorded migration checksum, authenticates,
  reads the preserved resources without exposing secrets, processes an
  interrupted queued deployment, verifies a pre-upgrade webhook secret, and
  reconciles the existing stack. Publication fails closed if a prior release
  lacks an immutable promotion manifest. The first release records an explicit
  `not_applicable` result rather than pretending an upgrade occurred.
- The exact public, signed candidate digest runs in a disposable Swarm through
  a configurable soak window (five minutes by default). Health, readiness,
  authenticated API access, Prometheus output, and replica convergence must
  remain healthy. The gate then deploys a deliberately failing health check and
  requires Swarm to report `rollback_completed`, restore the signed digest and
  original health configuration, and preserve the authenticated session. Its
  evidence records measured soak duration, baseline/failed/recovered task IDs,
  monotonic service versions, the failed task's terminal state, and matching
  local image IDs before and after rollback.
- `make test-lifecycle-conformance` drives the authenticated HTTP API and real
  PostgreSQL queue through successful, failed, cancelled, and rollback
  deployments. The successful deployment records Swarm-resolved image digests,
  and rollback must redeploy that immutable effective snapshot rather than the
  original mutable tag. It also verifies a signed provider webhook and replay defense,
  ordered commit-status delivery, a signed failure notification, remote-agent
  command encryption/completion, cancellation/completion serialization, and
  per-attempt fencing after worker takeover. The release attaches the resulting
  `lifecycle-conformance.json` evidence.
- `make test-reconciliation-conformance` removes a healthy local Swarm stack
  and requires two observations to queue and complete exactly one repair from
  the immutable effective snapshot without overwriting newer desired edits.
  It also proves maintenance, active deployments, stale remote heartbeats, and
  insufficient remote capacity suppress repair; verifies recovery when remote
  capacity returns; and checks reconciliation data in Prometheus and the
  redacted AI audit snapshot. The release attaches
  `reconciliation-conformance.json`.
- Verify service stop persists across controller restart, removes the stack on
  local and remote Swarm without deleting named volumes, suppresses drift
  repair, and emits `service.stop.failed` after retry exhaustion. Verify start,
  deploy hooks, manual deploy, and rollback restore `running` intent and are
  serialized behind any in-flight stop job.
  Confirm manual and scheduled database/named-volume data operations cannot be
  admitted after stopped intent commits and resume normally after start.
- `make test-agent-certificate-conformance` serves the agent API over a real
  TLS 1.3 listener that requires CA-verified client certificates. It proves
  two-phase replacement issuance, continued use of the old identity before
  confirmation, promotion by the replacement heartbeat, immediate rejection
  of the superseded serial, and rejection of wrong-cluster, untrusted,
  expired, and mismatched-key identities. It also verifies that active-expiry
  and pending-rotation metrics converge, and attaches
  `agent-certificate-conformance.json`.
- `make test-ai-audit-conformance` runs the built-in auditor through the real
  tenant API and PostgreSQL store against a disposable OpenAI-compatible
  endpoint. It proves snapshot secret redaction, prompt trust boundaries,
  durable deterministic and model findings, audited completion, and denial of
  normal workload APIs to the auditor identity. It distinguishes desired
  template tags from digest-pinned effective runtime snapshots, reports a
  mutable deployed image, and keeps runtime image identities outside the model
  boundary. It also proves deterministic detection of a managed database left
  in an error state, an expired custom TLS certificate, and a missing edge
  reconciliation target while keeping encrypted certificate and private-key
  material outside the model boundary. A failed managed network must also
  produce a deterministic finding without exposing its raw Docker/agent error.
  An active deployment-hook credential that remains unused after thirty days
  must produce a cleanup finding without exposing token material or identity.
  The same gate covers stale unused service-account credentials and raises
  their finding when the aggregate includes a privileged automation identity.
  It also detects an unreferenced Git/SSH/registry credential older than thirty
  days without exposing its name, authority, username, or encrypted material.
  A failed or thirty-minute-stalled offline named-volume recovery must produce
  a critical deterministic finding with service, volume, and target-node
  context while excluding the raw restore error from the model boundary.
  The gate additionally verifies audited administrator finding triage, atomic
  rollback when its audit write fails, denial of triage to the auditor identity,
  prevention of cross-tenant finding mutation, and durable notification for a
  new critical finding. The release attaches
  `ai-audit-conformance.json`.
- `make test-notification-conformance` drives encrypted provider records and
  durable jobs through signed webhook and Slack-compatible delivery,
  PagerDuty, Opsgenie, and authenticated implicit-TLS SMTP. It proves retry
  recovery, delivery/job completion, tenant isolation, event deduplication,
  encrypted-at-rest provider material, and offline recovery notifications with
  service, volume, mode, and target-node context. The release attaches
  `notification-conformance.json`; real provider credentials remain a staging
  requirement.
- `make test-migration-conformance` imports a representative Dokploy fixture
  into real PostgreSQL twice and proves dry-run secrecy, idempotent Compose and
  application conversion, routes, six managed-database mappings, backup and
  notification conversion, credential re-encryption, native transfer queueing,
  tenant ownership, explicit manual acknowledgements, and fail-closed
  operational verification. The release attaches `migration-conformance.json`;
  the final live Dokploy cutover remains a staging gate.

## Staging gates

- Upgrade a clone of production data from the previous supported release. The
  automated disposable-state conformance gate does not replace this staging
  exercise.
  Confirm migration checksums, login/SSO, secret decryption, resource counts,
  queue recovery, and existing stack reconciliation.
- Repeat deploy, cancellation, failed deploy, rollback, provider webhook and
  commit status against the production-equivalent topology. Exercise every
  enabled external notification provider with real provider credentials; CI
  exercises the signed generic-webhook path. Run one real remote-agent command.
  Kill a worker while a job is leased and verify fenced takeover. Hold
  the old attempt past lease expiry and verify it cannot regress a completed
  resource to running or commit any resource completion after takeover. Race a
  cancellation against completion and verify the job and resource both remain
  cancelled.
- Remove a healthy local stack and under-replicate a remote stack. Verify two
  consecutive observations queue exactly one repair from the last successful
  effective snapshot, preserve newer undeployed edits, and expose the state in
  both Prometheus metrics and the AI audit snapshot. Repeat during maintenance
  and an active deployment and verify repair is suppressed.
- Preserve the `make test-swarm-ha` evidence artifact, then repeat leader
  partition, minority-write rejection, quorum restoration, and workload
  convergence across the production-equivalent multi-host Swarm network. The
  nested-Docker gate records leader replacement, rescheduled task IDs,
  failed-manager reachability and recovery, service-version immutability while
  quorum is absent, and the first mutation committed after quorum returns. Its
  minority mutation is killed inside the isolated manager so it cannot remain
  pending and commit after the client-side deadline.
- Back up and restore each advertised backup-capable database engine. Record
  measured RPO/RTO and verify checksum, application-level data, retention, and
  restore-drill alerts. Race retention against queued manual restores and
  running verification drills; both references must prevent artifact deletion.
  Inject an object-store deletion failure and verify the durable cleanup record,
  retry backoff, destination protection, backlog metric, and eventual deletion.
  Rotate the destination credentials in place and verify queued cleanup resumes
  without replacing policy or backup references.
  On a Swarm manager, `make test-database-recovery`
  exercises the exact engine-specific readiness, backup, and restore commands
  against PostgreSQL, TimescaleDB, MySQL, MariaDB, MongoDB, Redis, Valkey,
  libSQL, ClickHouse, Qdrant, and Meilisearch and emits one `RECOVERY_EVIDENCE` JSON
  record per engine. Every case mounts the driver's production data path on a
  named volume, removes and recreates the database container after restore,
  and reads the restored application data again without reseeding it. Evidence
  records immutable local IDs and repository digests for the server, backup,
  and restore images and proves replacement used the same server image.
  The release workflow runs the same matrix, validates a machine-readable
  record for each engine, and publishes their aggregate as
  `database-recovery-evidence.json`; repeat on production-equivalent storage
  because CI timings are not SLOs.
- Run `make test-volume-recovery` with
  `DOCKYARD_TEST_VOLUME_HELPER_IMAGE` set to the exact immutable candidate
  image and `DOCKYARD_TEST_DATABASE_URL` set to a disposable PostgreSQL
  database. The release workflow runs this gate against its signed amd64 digest
  and publishes `volume-recovery-conformance.json`. The evidence must prove
  backup and restore quiescence, encrypted-artifact integrity, replacement of
  deliberately corrupted contents, preservation of permissions and safe
  symlinks, workload resumption, data survival after a service restart, and
  retention losing safely to a restore queued after candidate selection. The
  disposable gate also removes the workload, performs an offline restore with
  the candidate helper, proves no application service exists during transfer,
  and verifies recovered data before and after recreating the workload.
  Exercise the offline recovery path on a multi-node Swarm: stop and rebind a
  workload, restore its retained artifact onto the new node without starting
  application services, then start it and verify the pre-failure data. Evidence
  must identify the old backup node and the snapshotted restore target.
  Confirm the critical recent-failure and stalled-restore alerts fire for
  offline recovery and preserve their `mode`, service, and volume context.
  Repeat the measurement on every production storage driver because the CI
  RTO is not a production SLO.
- Test the configured OIDC/SAML/SCIM providers and mandatory-SSO break-glass
  procedure. `make test-keycloak-sso` provisions a real TLS-enabled Keycloak
  realm. Its OIDC flow verifies discovery, authorization-code login, PKCE,
  nonce binding, JIT provisioning, organization-scoped session isolation, and
  callback replay rejection. Its SAML flow imports the generated SP metadata into Keycloak and
  verifies a signed AuthnRequest, signed responses, SP- and IdP-initiated login,
  JIT provisioning, session authentication, and assertion replay rejection.
  The harness requires explicit PASS records from both named flows before CI
  may emit positive SSO evidence; an empty or stale test selector fails closed.
  Exercise two-phase SAML SP certificate rollover against each configured
  provider: publish the replacement, refresh IdP metadata, prove the old key
  remains active before promotion, promote, and verify a new login.
  Run the equivalent flow against Entra ID, Okta, and Google Workspace, and
  verify tenant isolation with users from two organizations.
- Rotate the agent listener certificate and CA secrets in a staging controller
  rollout by following `docs/agent-ca-rotation.md`. Preserve the phase-one
  dual-trust deployment, prove every active/draining cluster reports the new CA
  fingerprint, switch the listener identity, then remove old trust. Confirm
  startup rejects mismatched or expired credentials and all three
  control-plane expiry gauges move or disappear as expected. The automated
  real-TLS CA rollover gate does not replace this production-topology exercise.
- Restore the control plane from an authenticated format-2 PostgreSQL bundle,
  master-key/CA escrow, the independently stored Ed25519 recovery verification
  key, and artifact storage into an isolated Swarm. Confirm the manifest
  signature, staged database cutover, retained rollback database, and
  audit-chain continuity.
- Re-run the final non-dry-run Dokploy import, deploy the imported current
  revisions, complete database transfers, and preserve the JSON output from
  `dockyard verify-dokploy-import`. Every manual conversion must have its own
  documented `--acknowledge kind:source-id`; a blanket bypass is unavailable.
  Then validate application behavior, DNS cutover, and rollback independently.

## Promotion and rollback

- Push a protected stable `vMAJOR.MINOR.PATCH` tag without leading zeroes, or
  explicitly dispatch the `Release image` workflow with that version. It
  publishes amd64/arm64 to
  `ghcr.io/<owner>/<repository>`, attaches SLSA provenance and an SPDX SBOM,
  makes the package public, proves the version can be fetched with an anonymous
  registry token, signs the resulting digest with GitHub's OIDC identity, and
  verifies all three. Configure the `GHCR_ADMIN_TOKEN` repository secret with
  package-administration rights when the workflow `GITHUB_TOKEN` cannot change
  package visibility; publication fails closed instead of leaving an
  unusable private release. It also creates the matching immutable GitHub
  Release with a keyless-Sigstore-signed `promotion-manifest.json`, its
  `promotion-manifest.sigstore.json` bundle, `release-evidence.sha256`,
  independently signed `production-certification.json` and
  `production-certification.sigstore.json`,
  `image-digest.txt`,
  `image-platforms.json`, per-architecture `trivy-amd64.json` and
  `trivy-arm64.json`, a downloadable `sbom.spdx.json`, eleven-engine
  `database-recovery-evidence.json`,
  `volume-recovery-conformance.json`,
  `control-plane-recovery-conformance.json`,
  `template-conformance.json`,
  `sso-keycloak-evidence.json`, `swarm-ha-conformance.json`,
  `lifecycle-conformance.json`, `reconciliation-conformance.json`,
  `agent-certificate-conformance.json`, `ai-audit-conformance.json`,
  `ai-gateway-recovery-conformance.json`,
  `notification-conformance.json`, `migration-conformance.json`,
  `upgrade-conformance.json`, and
  `release-soak-evidence.json`; the same files
  remain available as a workflow artifact. AI gateway recovery evidence runs
  the orchestration failure cases and also executes an authenticated encrypted
  configuration backup/restore with the exact candidate image. Upgrade evidence records the
  previous immutable image and the authentication, migration, secret,
  resource-count, queue-recovery, and reconciliation assertions. Soak evidence
  records the exact promoted digest, measured duration, observation count,
  task and service-version transitions, immutable image identity, and automatic
  rollback result. The workflow initially pushes only a run-scoped candidate tag; the
  public semantic-version tag is assigned to that exact digest only after
  vulnerability scans, image and manifest signatures, checksum verification,
  soak, and all evidence validation pass. A later release verifies the prior
  manifest signature before trusting its recorded image digest.
  Releases are monotonic: the requested version must be greater than the
  highest published stable SemVer, regardless of publication order. The prior
  signed manifest must name the same repository, exact Git tag commit, and
  repository-owned GHCR digest before it can enter the upgrade test.
  Stable tagging runs only in the protected `production-release` environment
  after the exact candidate has a valid, unexpired certification from the
  protected `production-certification` environment. Configure required,
  distinct reviewers for both environments and follow
  `docs/production-certification.md`; an absent certification leaves only the
  run-scoped candidate tag.
  A published version cannot be rerun or have its evidence overwritten. Treat
  the manifest's `image` value—not its discovery tag—as the deployment input.
- Review schema changes for backward compatibility. Take and verify a
  PostgreSQL backup before promotion.
- Sign the image and catalog artifacts, publish their digests and SBOM, deploy
  by digest, then observe health, queue age, error rate, agents, backups, and
  alerts through the agreed soak window.
- Run `scripts/ci/check-image-digests.sh controller` (or `agent`) against the
  exact environment used for `docker stack deploy`; production manifests do
  not provide mutable-tag fallbacks.
- Repeat the automated healthy-update and failed-task rollback sequence on the
  production-equivalent topology before completing the real soak window.
- Roll forward for application defects. If schema rollback is required, stop
  all controllers/workers and restore the pre-upgrade database plus matching
  master key and artifacts before starting the previous image.

Production-ready status requires all items above. Provider conformance, full
Dokploy cutover, capacity/partition tests, and published recovery measurements
cannot be replaced by unit-test success.
