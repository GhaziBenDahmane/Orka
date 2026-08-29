# Template repositories

An organization can register multiple public GitHub repositories as template
sources. Each repository has its own slug, URL, Git ref, and optional catalog
subdirectory. Imported keys are namespaced as `repository-slug/template-id`, so
two repositories may publish templates with the same upstream ID.

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
file counts. A sync records success or its bounded failure message. Private
repositories and signed remote catalogs are follow-up work; do not weaken URL
validation to add them.

API flow:

```text
POST   /v1/template-repositories
GET    /v1/template-repositories
POST   /v1/template-repositories/{repositoryID}/sync
DELETE /v1/template-repositories/{repositoryID}
GET    /v1/templates
```

Deleting a repository also removes its catalog entries. Existing services keep
their immutable Compose revision and template provenance snapshot.

The controller seeds PostgreSQL, Redis, and 9Router templates at startup. To
suggest another built-in product, use `.github/ISSUE_TEMPLATE/template-request.yml`;
to contribute it directly, follow `CONTRIBUTING.md` and add a validated
blueprint under `internal/templates/builtin/blueprints`.
