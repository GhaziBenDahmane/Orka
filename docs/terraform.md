# Terraform and OpenTofu provider

The `terraform-provider-dockyard` binary manages the core hierarchy without
bypassing Dockyard policy, audit, or lifecycle checks. It currently provides:

- `dockyard_project`
- `dockyard_environment`
- `dockyard_service`
- `dockyard_route`
- `dockyard_database`
- `dockyard_source_credential`
- `dockyard_backup_destination`
- `dockyard_backup_policy`

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

An environment may set `cluster_id` directly, or use `placement_selector`,
`minimum_nodes`, `minimum_nano_cpus`, and `minimum_memory_bytes` for
capacity-aware placement. Placement inputs are immutable;
changing them replaces the environment so workloads cannot silently move
between Swarms.

`dockyard_backup_policy` manages the single native-backup policy associated
with a database. Its import ID is the database UUID (not the policy UUID), for
example `terraform import dockyard_backup_policy.primary DATABASE_UUID`.
Backup destinations verify bucket access during creation. Access keys, secret
keys, and optional session tokens are sensitive and are never returned by the
API, so the provider retains them from configuration in state.
Source credentials similarly retain secret material only in sensitive state;
use `secret` for Git HTTPS and registry credentials, or `private_key` plus
`known_hosts` for host-pinned SSH credentials.

Managed databases are replacement-oriented because changing an engine,
version, or credential-bearing driver configuration in place is unsafe.
`config_json` is sensitive: credentials are submitted once, remain encrypted
in Dockyard, and are retained only in Terraform's sensitive state on refresh.
