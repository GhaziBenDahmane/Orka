# Roadmap

## R1 — secure single-cluster control plane

- Bootstrap, login, sessions, organizations, roles, and audit events
- Projects, environments, Compose services, routes, and encrypted variables
- PostgreSQL job queue, Swarm stack deploy, convergence checks, logs, and rollback
- Traefik routing with automatic TLS

## R2 — templates and managed data services

- Native versioned catalog and Dokploy `template.toml` compatibility importer
- Template validation, generated secrets, previews, and upgrade metadata
- PostgreSQL, MySQL, MariaDB, MongoDB, Redis, Valkey, libSQL, ClickHouse,
  Qdrant, and Meilisearch drivers
- S3-compatible backup scheduling, restore verification, and retention

## R3 — enterprise identity and policy

- OIDC, SAML 2.0, JIT provisioning, domain discovery, and mandatory SSO
- SCIM users/groups and group-to-role mapping
- Project/environment custom roles, service accounts, and audit export
- Policy controls for unsafe Compose capabilities

## R4 — multi-cluster operations

- Outbound mTLS agents for multiple Swarm clusters
- Capacity-aware cluster selection, draining, and maintenance windows
- Highly available controllers, agent upgrades, and disaster-recovery tooling
- Prometheus/OpenTelemetry integration, alerts, and notification providers

## R5 — migration and ecosystem

- Dokploy resource and template importer
- CLI, Terraform/OpenTofu provider, documented REST/OpenAPI API
- Signed catalogs and external driver RPC SDK
- Conformance, chaos, upgrade, backup, and security test suites

## R6 — AI-first operations and catalog federation

- Isolated auditor service accounts and secret-free whole-platform snapshots
- Structured audit runs and deduplicated findings with immutable attribution
- Lightweight built-in OpenAI-compatible auditor; optional 9Router gateway
- Hermes-compatible auditor API for interactive investigations without Docker-socket access
- Multiple namespaced GitHub template repositories using Dokploy Compose format
- Signed remote catalogs with per-repository Ed25519 signer pinning
- Scheduled repository sync with singleton controller coordination
- Private GitHub catalogs using encrypted organization credentials
- Replay-safe GitHub push webhooks for immediate repository refresh
