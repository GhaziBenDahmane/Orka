# Terraform and OpenTofu provider

The `terraform-provider-dockyard` binary manages the core hierarchy without
bypassing Dockyard policy, audit, or lifecycle checks. It currently provides:

- `dockyard_project`
- `dockyard_environment`
- `dockyard_service`

Configure `DOCKYARD_URL` and `DOCKYARD_TOKEN` in the runner environment. An
optional `DOCKYARD_ORGANIZATION_ID` selects an organization for owners with
more than one membership. Plain HTTP is rejected except for loopback URLs.

Build the provider with `make build`. For local development, point Terraform
or OpenTofu at `bin/terraform-provider-dockyard` using a CLI development
override for `registry.terraform.io/dockyard/dockyard`. A complete starter
configuration is in `examples/terraform/main.tf`.

Project and environment replacement/deletion is intentionally refused while
children remain. Terraform's dependency graph destroys managed services first.
Service deletion waits for Dockyard's asynchronous Swarm finalizer, so state is
not removed until the stack and owned backup artifacts are gone.
