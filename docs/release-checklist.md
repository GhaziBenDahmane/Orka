# Release checklist

A release is a promoted immutable image digest, not a mutable tag. Record the
operator, UTC time, source commit, image digest, schema version, and evidence
links for every item below.

## Automated gates

- Release publication is blocked on the complete reusable CI, ten-engine
  database recovery, real Keycloak SSO, disposable three-manager Swarm HA, and
  previous-image upgrade conformance workflows. Tag pushes do not run detached
  copies: the release workflow invokes all gates directly and publishes only
  after every job succeeds.
- CI is green for race tests, vet, binary and web builds, generated assets,
  OpenAPI coverage/security classification, migration fresh-install and
  checkpoint-upgrade tests, high-contention exactly-once queue claiming across
  multiple workers, per-attempt fenced stale-worker takeover while the
  superseded worker is paused inside a scheduler call, Compose and Swarm
  parsing, and a clean-install workload converging to a live Swarm replica.
- `govulncheck` reports no reachable known vulnerability.
- License policy passes; the SPDX JSON SBOM is attached to the release.
- Build and runtime base images are pinned by manifest digest, and the runtime
  image verifies its Git client and CA trust store without downloading mutable
  operating-system packages during the release build.
- The final container has no unfixed high or critical finding allowed by the
  project's exception register. Exceptions identify owner and expiry date.
- A clean Compose installation bootstraps an owner, creates project,
  environment, and service records, deploys the service to Swarm, verifies its
  replica, persists an undeployed revision across a controller restart, and
  rolls back to the last successful immutable snapshot on the live Swarm. The
  smoke test then backs up the control plane, rejects active-controller,
  modified-dump, and wrong-key restores, deletes live data, restores the dump,
  and verifies the authenticated workload state after restart.
- Built-in PostgreSQL, Redis, BarkTrace SQLite, and BarkTrace PostgreSQL
  templates deploy through the public API and remain healthy across a forced
  Swarm task replacement. The data services also accept authenticated
  application-level writes and reads; the BarkTrace checks verify its SQLite
  file or PostgreSQL migration state survives replacement.
- Every release after the first boots the previous published image digest,
  creates authenticated and encrypted tenant state, deploys a live stack, and
  stops the old controller against its persistent PostgreSQL volume. The
  candidate then validates every recorded migration checksum, authenticates,
  reads the preserved resources without exposing secrets, processes an
  interrupted queued deployment, verifies a pre-upgrade webhook secret, and
  reconciles the existing stack. Publication fails closed if a prior release
  lacks an immutable promotion manifest. The first release records an explicit
  `not_applicable` result rather than pretending an upgrade occurred.

## Staging gates

- Upgrade a clone of production data from the previous supported release. The
  automated disposable-state conformance gate does not replace this staging
  exercise.
  Confirm migration checksums, login/SSO, secret decryption, resource counts,
  queue recovery, and existing stack reconciliation.
- Exercise deploy, cancellation, failed deploy, rollback, provider webhook and
  commit status, every enabled notification provider, and one remote-agent
  command. Kill a worker while a job is leased and verify fenced takeover. Hold
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
  convergence across the production-equivalent multi-host Swarm network.
- Back up and restore each advertised backup-capable database engine. Record
  measured RPO/RTO and verify checksum, application-level data, retention, and
  restore-drill alerts. On a Swarm manager, `make test-database-recovery`
  exercises the exact engine-specific readiness, backup, and restore commands
  against PostgreSQL, MySQL, MariaDB, MongoDB, Redis, Valkey, libSQL,
  ClickHouse, Qdrant, and Meilisearch and emits one `RECOVERY_EVIDENCE` JSON
  record per engine.
  The release workflow runs the same matrix, validates a machine-readable
  record for each engine, and publishes their aggregate as
  `database-recovery-evidence.json`; repeat on production-equivalent storage
  because CI timings are not SLOs.
- Test the configured OIDC/SAML/SCIM providers and mandatory-SSO break-glass
  procedure. `make test-keycloak-sso` provisions a real TLS-enabled Keycloak
  realm. Its OIDC flow verifies discovery, authorization-code login, PKCE,
  nonce binding, JIT provisioning, organization-scoped session isolation, and
  callback replay rejection. Its SAML flow imports the generated SP metadata into Keycloak and
  verifies a signed AuthnRequest, signed responses, SP- and IdP-initiated login,
  JIT provisioning, session authentication, and assertion replay rejection.
  Run the equivalent flow against Entra ID, Okta, and Google Workspace, and
  verify tenant isolation with users from two organizations.
- Rotate the agent listener certificate and CA secrets in a staging controller
  rollout. Confirm startup rejects a mismatched or expired credential, the
  replacement listener accepts existing agents, and both control-plane expiry
  gauges and seven-day alerts move to the new certificate deadlines.
- Restore the control plane from PostgreSQL, master-key/CA escrow, and artifact
  storage into an isolated Swarm. Confirm audit-chain continuity.
- Re-run the final non-dry-run Dokploy import, deploy the imported current
  revisions, complete database transfers, and preserve the JSON output from
  `dockyard verify-dokploy-import`. Every manual conversion must have its own
  documented `--acknowledge kind:source-id`; a blanket bypass is unavailable.
  Then validate application behavior, DNS cutover, and rollback independently.

## Promotion and rollback

- Push a protected `vMAJOR.MINOR.PATCH` tag, or explicitly dispatch the
  `Release image` workflow with that version. It publishes amd64/arm64 to
  `ghcr.io/<owner>/<repository>`, attaches SLSA provenance and an SPDX SBOM,
  makes the package public, proves the version can be fetched with an anonymous
  registry token, signs the resulting digest with GitHub's OIDC identity, and
  verifies all three. Configure the `GHCR_ADMIN_TOKEN` repository secret with
  package-administration rights when the workflow `GITHUB_TOKEN` cannot change
  package visibility; publication fails closed instead of leaving an
  unusable private release. It also creates the matching immutable GitHub
  Release with `promotion-manifest.json`, `image-digest.txt`, and a downloadable
  `sbom.spdx.json`, ten-engine `database-recovery-evidence.json`,
  `sso-keycloak-evidence.json`, and `swarm-ha-conformance.json`; the same files
  remain available as a workflow artifact. `upgrade-conformance.json` records
  the previous immutable image and the authentication, migration, secret,
  resource-count, queue-recovery, and reconciliation assertions.
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
- Confirm Swarm reports healthy replacement tasks and a completed update. Force
  one candidate task to fail its health check and verify automatic rollback
  before promoting the image digest.
- Roll forward for application defects. If schema rollback is required, stop
  all controllers/workers and restore the pre-upgrade database plus matching
  master key and artifacts before starting the previous image.

Production-ready status requires all items above. Provider conformance, full
Dokploy cutover, capacity/partition tests, and published recovery measurements
cannot be replaced by unit-test success.
