# Template repositories

An organization can register multiple public GitHub repositories as template
sources. Each repository has its own slug, URL, Git ref, optional catalog
subdirectory, and optional pinned Ed25519 signing key. Imported keys are
namespaced as `repository-slug/template-id`, so two repositories may publish
templates with the same upstream ID.

The repository format is intentionally Dokploy-compatible:

```text
blueprints/
  example/
    meta.json
    template.toml
    docker-compose.yml
```

`meta.json` requires `id`, `name`, and `version`; `description` is optional.
`template.toml` defines generated or operator-supplied variables, environment
mapping, domains, and managed files. `docker-compose.yml` remains the workload
definition and passes through the same Swarm safety compiler as every other
service. See `examples/template-repository` for a complete 9Router example.

Repository downloads accept only canonical HTTPS GitHub URLs and use GitHub's
archive endpoint rather than invoking a shell. Extraction rejects links,
special files, traversal, oversized files, oversized archives, and excessive
file counts. A sync records success or its bounded failure message. For a
production catalog, provide its PEM or base64 Ed25519 public key and enable
`requireSignature`. Dockyard then verifies `catalog.manifest.json` and
`catalog.manifest.sig` before importing any entry and records the signer
fingerprint in every imported template's provenance. A failed or tampered sync
leaves the previously imported versions intact. Valid snapshots are reconciled
in one database transaction, including removal of catalog versions no longer
published by the repository; existing services retain their copied provenance.
Each repository can be synchronized manually or on a controller-managed
schedule between five minutes and seven days. Scheduled work is claimed
atomically, protected by the controller singleton lease, and retried at the
next interval after either success or failure. Existing repositories remain
manual-only after upgrading; new repositories default to hourly refresh in the
console. Private repository credentials remain follow-up work; do not weaken
URL validation to add them.

Create signed catalog artifacts with:

```sh
go run ./cmd/dockyard sign-template-catalog \
  --private-key-file /secure/catalog-signing-key.pem /path/to/catalog
```

Keep the private key offline. Register only its public key with Dockyard.

API flow:

```text
POST   /v1/template-repositories
GET    /v1/template-repositories
PATCH  /v1/template-repositories/{repositoryID}  # signing and sync schedule
POST   /v1/template-repositories/{repositoryID}/sync
DELETE /v1/template-repositories/{repositoryID}
GET    /v1/templates
```

Deleting a repository also removes its catalog entries. Existing services keep
their immutable Compose revision and template provenance snapshot.

The controller seeds PostgreSQL, Redis, 9Router, and BarkTrace SQLite templates
at startup. To suggest another built-in product, use
`.github/ISSUE_TEMPLATE/template-request.yml`; to contribute it directly,
follow `CONTRIBUTING.md` and add a validated blueprint under
`internal/templates/builtin/blueprints`.
