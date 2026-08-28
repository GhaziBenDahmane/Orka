# Release checklist

A release is a promoted immutable image digest, not a mutable tag. Record the
operator, UTC time, source commit, image digest, schema version, and evidence
links for every item below.

## Automated gates

- CI is green for race tests, vet, binary and web builds, generated assets,
  OpenAPI coverage/security classification, migration fresh-install and
  checkpoint-upgrade tests, per-attempt fenced stale-worker takeover, Compose
  and Swarm parsing, and a clean-install workload converging to a live Swarm
  replica.
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
  rolls back to the last successful immutable snapshot on the live Swarm.

## Staging gates

- Upgrade a clone of production data from the previous supported release.
  Confirm migration checksums, login/SSO, secret decryption, resource counts,
  queue recovery, and existing stack reconciliation.
- Exercise deploy, cancellation, failed deploy, rollback, provider webhook and
  commit status, every enabled notification provider, and one remote-agent
  command. Kill a worker while a job is leased and verify fenced takeover. Hold
  the old attempt past lease expiry and verify it cannot regress a completed
  resource to running or commit any resource completion after takeover.
- Back up and restore each advertised backup-capable database engine. Record
  measured RPO/RTO and verify checksum, application-level data, retention, and
  restore-drill alerts. On a Swarm manager, `make test-database-recovery`
  exercises the exact native readiness, backup, and restore commands against
  PostgreSQL, MySQL, MariaDB, and MongoDB and emits one `RECOVERY_EVIDENCE`
  JSON record per engine. Preserve the workflow artifact with the release;
  repeat on production-equivalent storage because CI timings are not SLOs.
- Test the configured OIDC/SAML/SCIM providers and mandatory-SSO break-glass
  procedure. Verify tenant isolation with users from two organizations.
- Restore the control plane from PostgreSQL, master-key/CA escrow, and artifact
  storage into an isolated Swarm. Confirm audit-chain continuity.

## Promotion and rollback

- Review schema changes for backward compatibility. Take and verify a
  PostgreSQL backup before promotion.
- Sign the image and catalog artifacts, publish their digests and SBOM, deploy
  by digest, then observe health, queue age, error rate, agents, backups, and
  alerts through the agreed soak window.
- Run `scripts/ci/check-image-digests.sh controller` (or `agent`) against the
  exact environment used for `docker stack deploy`; production manifests do
  not provide mutable-tag fallbacks.
- Roll forward for application defects. If schema rollback is required, stop
  all controllers/workers and restore the pre-upgrade database plus matching
  master key and artifacts before starting the previous image.

Production-ready status requires all items above. Provider conformance, full
Dokploy cutover, capacity/partition tests, and published recovery measurements
cannot be replaced by unit-test success.
