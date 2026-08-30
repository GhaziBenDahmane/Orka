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
service. Random `password`, `base64`, `hash`, and `username` helpers accept at
most one length from 1 through 4096; numeric `jwt` helpers are limited to 256.
For Dokploy compatibility, their default lengths are 16, 32 bytes, 8, and 16
respectively, and `base64` uses padded standard encoding. A parameterless
`jwt` produces a signed token with Dokploy's standard issuer and expiry.
Signed JWT helpers must reference a declared, non-empty secret variable and may
reference one declared JSON payload variable. Malformed, missing, negative, or
unbounded parameters reject the complete catalog snapshot. `timestampms` and
`timestamps` accept an optional RFC3339 or `YYYY-MM-DD` date. Catalog admission
also bounds variable counts, source bytes, resolved bytes, and expression count
so chained substitutions cannot amplify a small repository into unbounded
memory use. Resolved managed-file contents are stored only inside the service's
encrypted deployment environment; persisted Compose and deployment snapshots
contain opaque references. The Swarm manager materializes mode-0600 temporary
files immediately before deployment, removes their internal values from
Compose interpolation, and accepts only bounded, read-only config mounts. See
`examples/template-repository` for a complete 9Router example.

Repository downloads accept only canonical HTTPS GitHub URLs and use GitHub's
archive endpoint rather than invoking a shell. Extraction rejects links,
special files, traversal, oversized files, oversized archives, and excessive
entry counts. It also requires one consistent archive root, bounds path length
and nesting depth, and fully consumes the gzip stream under separate compressed
and expanded-size limits before publishing anything. A sync records success or
its bounded failure message. For a
production catalog, provide its PEM or base64 Ed25519 public key and enable
`requireSignature`. Dockyard then verifies `catalog.manifest.json` and
`catalog.manifest.sig` before importing any entry and records the signer
fingerprint in every imported template's provenance. A failed or tampered sync
leaves the previously imported versions intact. Valid snapshots are reconciled
in one database transaction, including removal of catalog versions no longer
published by the repository; existing services retain their copied provenance.
Changing the pinned signer or signature requirement atomically fences any
in-flight sync, withdraws entries verified under the previous trust policy, and
queues a fresh sync. Changing the private-repository credential also fences the
old attempt and queues a refresh, but retains the last verified catalog while
the new credential is checked. Existing deployed services are unaffected.
Built-in startup seeding and the signed local catalog importer likewise parse
the complete catalog first and publish all template versions in one database
transaction, so an invalid sibling or storage failure cannot expose a partial
catalog.
Before publication, every candidate snapshot is instantiated with generated
validation values, its declared routes are checked against real Compose
services, and the rendered workload passes the safe Docker Compose compiler.
One invalid blueprint rejects the whole snapshot, and an empty snapshot cannot
silently withdraw every published version. Catalog authors must remove the
repository explicitly when they intend to retire its entire namespace.
Each repository can be synchronized manually or on a controller-managed
schedule between five minutes and seven days. Manual requests are durably
coalesced and return `202 Accepted`; the same HA-safe scheduler performs all
downloads and imports, so an API disconnect or controller replacement cannot
lose the request. A request received during an active sync schedules one
follow-up refresh. Scheduled work is claimed atomically, protected by the
controller singleton lease, and assigned a per-attempt fence. A stale
controller cannot publish or finalize a catalog after its attempt is replaced.
Interrupted manual-only syncs are reclaimed after five minutes; scheduled
repositories retry at the next interval after either success or failure.
Existing repositories remain manual-only after upgrading;
new repositories default to hourly refresh in the console. Private repositories
reuse an organization-scoped HTTPS Git source credential whose server is
`github.com`; its token is decrypted only for the
bounded archive request and is never copied into the repository record,
response, audit event, or sync error. Deleting the credential safely returns
the repository to unauthenticated access. Repository URLs remain restricted to
canonical GitHub HTTPS URLs.

Repository responses expose the pending request time, last attempt state, and
bounded error. Prometheus reports queued/running ages and failed attempts, and
the built-in AI auditor emits deterministic findings for refreshes that remain
unclaimed for five minutes or running for ten minutes. The supplied alert pack
covers the same conditions.

An administrator can also create a repository-specific GitHub webhook from the
console or with `POST /v1/template-repositories/{repositoryID}/webhook-secret`.
The response contains the webhook URL and secret exactly once. Configure that
URL in GitHub with JSON content, the returned secret, and only the `push` event.
Signed pushes matching the repository branch, tag, or pinned commit queue a
refresh for the controller scheduler. Delivery IDs are retained for 30 days to
reject replay; non-matching refs are ignored. Rotating the secret invalidates
the previous secret immediately. `DELETE` on the same endpoint disables
webhook refresh without removing the repository or its scheduled sync policy.

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
POST   /v1/template-repositories/{repositoryID}/webhook-secret
DELETE /v1/template-repositories/{repositoryID}/webhook-secret
POST   /v1/hooks/template-repositories/{repositoryID}  # public GitHub delivery
DELETE /v1/template-repositories/{repositoryID}
GET    /v1/templates
```

Set `credentialId` on `POST` or `PATCH` to the ID returned when creating a
`git` source credential for `github.com`. Omit it or send an empty string for a
public repository. `syncIntervalSeconds` accepts `0` for manual-only operation
or a value from `300` through `604800`.

Automation can use `dockyardctl template-repositories`,
`create-template-repository JSON`, `update-template-repository ID JSON`,
`sync-template-repository ID`, `rotate-template-repository-webhook ID`,
`disable-template-repository-webhook ID`, and `delete-template-repository ID`.
For declarative lifecycle management, use the
`dockyard_template_repository` Terraform/OpenTofu resource; its repository
location is replacement-oriented while trust, credential, and schedule
settings update in place.

Deleting a repository also removes its catalog entries. Existing services keep
their immutable Compose revision and template provenance snapshot.

The controller seeds PostgreSQL, Redis, 9Router, and BarkTrace
SQLite/PostgreSQL templates at startup. To suggest another built-in product,
use the public [Template request](https://github.com/GhaziBenDahmane/Orka/issues/new?template=template-request.yml)
form; to contribute it directly, follow `CONTRIBUTING.md` and add a validated blueprint under
`internal/templates/builtin/blueprints`.
