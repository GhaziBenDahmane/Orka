# Contributing

## Suggest a template

Use the repository's
[template request form](https://github.com/GhaziBenDahmane/Orka/issues/new?template=template-request.yml)
to propose a product. Include its upstream project, stable container image,
official Docker Compose example, persistence requirements, health check, and
any Docker Swarm constraints. Never include credentials in an issue.

## Add a template

Built-in templates use the Dokploy-compatible layout documented in
[`docs/template-repositories.md`](docs/template-repositories.md):

```text
internal/templates/builtin/blueprints/<template-id>/
  meta.json
  template.toml
  docker-compose.yml
```

Keep images on stable release tags, declare generated secrets in
`template.toml`, add a health check where the product supports one, and persist
state in a named volume or an explicitly declared database service. Templates
must compile under the safe Swarm profile; privileged containers, Docker socket
mounts, host paths, direct published ports, and external networks are rejected.

The metadata `id` must be a lowercase slug containing only letters, digits,
dots, underscores, or hyphens. The `(id, version)` pair must be unique across
the catalog. Validation fails the entire contribution when any blueprint is
invalid; a valid sibling cannot hide a broken template. Declare HTTP exposure
through `[[config.domains]]`; every domain must name a Compose service.

Validate both built-in and example catalogs before opening a pull request:

```sh
go run ./cmd/dockyard validate-dokploy-templates internal/templates/builtin
go run ./cmd/dockyard validate-dokploy-templates examples/template-repository
go test ./internal/templates
```

If the product supports materially different persistence modes, submit each as
a separate template so operators can review its backup and placement behavior
explicitly.

With a local Docker daemon in Swarm mode, `make test-templates` exercises the
complete API and deployment path. Organizations can also publish their own
catalog with this layout and register its GitHub URL from the Templates screen.
