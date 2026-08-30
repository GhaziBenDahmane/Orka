# Terraform and OpenTofu provider

The `terraform-provider-dockyard` binary manages the core hierarchy without
bypassing Dockyard policy, audit, or lifecycle checks. It currently provides:

- `dockyard_project`
- `dockyard_environment`
- `dockyard_service`
- `dockyard_route`
- `dockyard_tag`
- `dockyard_service_tags`
- `dockyard_database`
- `dockyard_source_credential`
- `dockyard_backup_destination`
- `dockyard_backup_policy`
- `dockyard_volume_backup_policy`
- `dockyard_template_repository`
- `dockyard_oidc_provider`
- `dockyard_saml_provider`
- `dockyard_scim_token`
- `dockyard_service_account`
- `dockyard_deploy_token`
- `dockyard_invitation`
- `dockyard_access_grant`
- `dockyard_resource_policy`
- `dockyard_cluster`
- `dockyard_notification_endpoint`
- `dockyard_audit_retention`
- `dockyard_audit_archive`
- `dockyard_auth_settings`

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

`dockyard_route` updates in place and supports `enabled`, `strip_path`,
`internal_path`, `redirect_regex`, `redirect_replacement`, and
`redirect_permanent`. Route changes become active with the service's next
deployment; redirect expressions use Go/Traefik RE2 syntax.
HTTP basic-auth identities deliberately remain outside Terraform state because
their write-only passwords require explicit rotation through the console, API,
or `dockyardctl`.

`dockyard_tag` manages a reusable organization tag. `dockyard_service_tags`
owns the complete set of tag assignments for one service, so define exactly one
such resource per service and reference `dockyard_tag.*.id` values. Import an
existing assignment set with the service UUID.

An environment may set `cluster_id` directly, or use `placement_selector`,
`minimum_nodes`, `minimum_nano_cpus`, and `minimum_memory_bytes` for
capacity-aware placement. Placement inputs are immutable;
changing them replaces the environment so workloads cannot silently move
between Swarms.

`dockyard_backup_policy` manages the single native-backup policy associated
with a database. Its import ID is the database UUID (not the policy UUID), for
example `terraform import dockyard_backup_policy.primary DATABASE_UUID`.
`dockyard_volume_backup_policy` manages one named volume on a Compose service.
Its import ID is `SERVICE_UUID/VOLUME_NAME`, for example
`terraform import dockyard_volume_backup_policy.uploads SERVICE_UUID/uploads`.
The service must declare and mount the volume, and must have a resolvable Swarm
storage node. Set `quiesce = true` unless the application has a separately
validated crash-consistent backup mechanism.
Backup destinations verify bucket access during creation and in-place updates.
Credential rotation does not replace policy or durable-cleanup references.
Access keys, secret keys, and optional session tokens are sensitive and are
never returned by the API, so the provider retains them from configuration in
state. Credentials and display names remain rotatable while a destination is
referenced. Endpoint, region, bucket, prefix, and TLS changes are rejected once
stored backup or audit artifacts depend on that location.
Source credentials similarly retain secret material only in sensitive state;
use `secret` for Git HTTPS and registry credentials, or `private_key` plus
`known_hosts` for host-pinned SSH credentials.

Managed databases are replacement-oriented because changing an engine,
version, or credential-bearing driver configuration in place is unsafe.
`config_json` is sensitive: credentials are submitted once, remain encrypted
in Dockyard, and are retained only in Terraform's sensitive state on refresh.

`dockyard_template_repository` manages a namespaced, Dokploy-compatible GitHub
catalog. Repository identity and location fields are replacement-oriented;
signing policy, the optional private-GitHub credential, and the automatic sync
interval update in place. Webhook secret rotation and immediate manual sync are
intentional one-shot operations and remain available through `dockyardctl`.

`dockyard_oidc_provider` manages OIDC discovery settings, allowed domains,
JIT-provisioned default role, enabled state, and encrypted client-secret
rotation. The API never returns the secret, so the provider retains it only in
sensitive Terraform state. Protect that state with an encrypted remote backend.
Destroy disables the provider and preserves its audit history; recreating the
resource provisions a new provider identity.

`dockyard_saml_provider` manages IdP metadata, domain and attribute mappings,
IdP-initiated policy, enabled state, and computed IdP/SP certificate posture.
The service-provider signing key is generated and encrypted by Dockyard. The
two-phase signing-certificate rotation remains an explicit `dockyardctl`
operation because promotion is safe only after the IdP imports the published
replacement certificate. Destroy disables the provider and retains its audit
history.

`dockyard_scim_token` issues a time-limited organization provisioning
credential and retains its one-time bearer value only in sensitive Terraform
state. All configuration changes replace and revoke the previous credential.
Refresh removes a token from state when it is revoked or enters the configured
`renew_before_days` window, so the same plan creates a usable replacement.
Protect state, pass the token to the identity provider through a sensitive
output or secret manager, and use `create_before_destroy` to overlap planned
configuration replacements. SCIM tokens cannot be imported because the API
never returns their bearer value.

`dockyard_service_account` creates a time-limited organization automation
identity with a `viewer`, `developer`, `admin`, or least-privilege `auditor`
role. Its bearer token is returned once and retained only in sensitive state.
When the token enters `renew_before_days`, the next plan replaces the identity
so apply creates a fresh credential and disables the previous account. Use
`create_before_destroy` to avoid a credential gap and deliver the new token to
the consuming secret store before removing the old value. Service accounts
cannot be imported because their bearer tokens are never returned by the API.

`dockyard_deploy_token` creates a time-limited CI deployment hook for exactly
one Compose service. Its complete hook URL and raw bearer token are returned
once and retained only in sensitive state. Refresh removes revoked or expired
hooks from state, while `renew_before_days` plans replacement before expiry.
Use `create_before_destroy` so the replacement can be installed in the CI
secret store before Terraform revokes the old hook. Deploy tokens cannot be
imported because their secret values are never returned by the API.

`dockyard_invitation` issues a one-time organization enrollment link for a
normalized lowercase email address. Pending invitations are replaced inside
the configured renewal window, while accepted invitations remain in state as
historical records and are never reissued. The token and acceptance URL are
sensitive one-time values. Destroy revokes only a still-pending invitation;
accepted invitations do not remove the resulting membership. Use
`dockyard_access_grant` for narrower project or environment permissions.

`dockyard_access_grant` manages an explicit `viewer`, `developer`, or `admin`
role for one organization member at project or environment scope. Organization
membership remains the lower access boundary, and inherited grants continue to
apply normally. Import an existing grant as
`project/PROJECT_UUID/USER_UUID` or
`environment/ENVIRONMENT_UUID/USER_UUID`.

`dockyard_resource_policy` manages maintenance mode and quotas at organization,
project, or environment scope. Omit `scope_id` for the provider organization;
use the matching resource UUID for narrower scopes. Destroy resets that scope
to maintenance-disabled, unlimited defaults because policies are virtual
singletons rather than deletable API objects. Import identifiers are
`organization`, `project/PROJECT_UUID`, and
`environment/ENVIRONMENT_UUID`.

`dockyard_cluster` registers a remote Docker Swarm and exposes its observed
agent, certificate, capacity, and heartbeat posture. Registration identity and
labels are immutable because the control-plane API does not rename clusters.
Enrollment tokens and active/draining/disabled transitions remain explicit
`dockyardctl` operations so a declarative apply cannot activate an unenrolled
agent or accidentally drain a live scheduler. Destroy queues the cluster
finalizer and waits for removal; every assigned environment must be moved or
destroyed first.

`dockyard_notification_endpoint` manages immutable webhook, Slack-compatible,
SMTP, PagerDuty, and Opsgenie delivery configuration. Provider material is a
sensitive `configuration_json` object using the REST API field names. For
example, webhook configuration is `jsonencode({ url = var.webhook_url })` and
PagerDuty configuration is
`jsonencode({ pagerDutyIntegrationKey = var.pagerduty_key })`. Changes replace
and disable the old endpoint. Webhook/Slack signing secrets are returned once
in the sensitive `signing_secret` attribute; protect state and deliver that
value to the receiver before enabling alerts. Disabled endpoints are treated
as drift and recreated. The resource is intentionally not importable because
the API never returns provider credentials or generated signing secrets.

`dockyard_audit_retention` manages the organization-wide 30–3650 day audit
event and completed AI-audit retention window. Destroy resets the singleton to
the documented 365-day default instead of deleting audit data.

`dockyard_audit_archive` configures a hash-chained immutable archive in an
existing `dockyard_backup_destination`. The destination must use TLS and its
bucket must have S3 Object Lock enabled; creation verifies that capability.
Archive location and COMPLIANCE retention are immutable, so every change
creates a separately verified destination and disables the previous one.
Destroy never deletes already retained archive objects. Manual archive runs
and delivery-history inspection remain available through `dockyardctl`. Import
an archive by its UUID; import the retention singleton with `organization`.

`dockyard_auth_settings` controls mandatory SSO for the selected organization.
Depend on at least one enabled OIDC or SAML provider before setting
`require_sso = true`. Destroying this singleton resource disables mandatory
SSO before identity-provider resources are removed.
