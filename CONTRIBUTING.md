# Contributing

## Suggest or publish a template

Use the public [Template request](https://github.com/GhaziBenDahmane/Orka/issues/new?template=template-request.yml)
GitHub form to suggest software for the built-in catalog. A request should
identify the upstream project, container images, exposed ports, persistent
data, required secrets, and health check.

To contribute an implementation, add a Dokploy-compatible blueprint under
`internal/templates/builtin/blueprints/<slug>` with:

- `meta.json` containing `id`, `name`, `version`, and `description`;
- `template.toml` declaring every configurable value and generated secret;
- `docker-compose.yml` using named volumes and Swarm-compatible services.

The metadata `id` must be a lowercase slug containing only letters, digits,
dots, underscores, or hyphens. The `(id, version)` pair must be unique across
the catalog. Validation fails the entire contribution when any blueprint is
invalid; a valid sibling cannot hide a broken template.

Run these checks before opening a pull request:

```sh
go test ./internal/templates
go run ./cmd/dockyard validate-dokploy-templates internal/templates/builtin
go test ./...
```

With a local Docker daemon in Swarm mode, run `make test-templates` to exercise
the complete template API and deployment path for the PostgreSQL and Redis
smoke products.

Templates must not request privileged mode, custom namespaces or runtimes,
device access, direct published ports, external networks or volumes, custom
volume drivers, controller-local files, the Docker socket, host bind mounts,
or undeclared credentials. Declare HTTP exposure through `[[config.domains]]`;
each domain must name a service present in the Compose file. Dockyard attaches
only routed services to its shared ingress network. Prefer
versioned image tags in development and publish the digest tested for a
release.

Organizations that do not need a built-in template can publish their own
catalog repository using the layout in `docs/template-repositories.md`, then
register its GitHub URL in the Templates screen.
