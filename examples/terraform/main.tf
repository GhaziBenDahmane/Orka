terraform {
  required_providers {
    dockyard = {
      source = "dockyard/dockyard"
    }
  }
}

provider "dockyard" {
  # Prefer DOCKYARD_URL and DOCKYARD_TOKEN in automation.
}

variable "backup_access_key" {
  type      = string
  sensitive = true
}

variable "backup_secret_key" {
  type      = string
  sensitive = true
}

variable "oidc_client_secret" {
  type      = string
  sensitive = true
}

variable "saml_metadata_xml" {
  type      = string
  sensitive = true
}

variable "developer_user_id" {
  type        = string
  description = "Organization member UUID receiving project-scoped access"
}

variable "invited_operator_email" {
  type        = string
  description = "Normalized lowercase email address to invite into the organization"
}

variable "notification_webhook_url" {
  type      = string
  sensitive = true
}

resource "dockyard_project" "example" {
  name        = "Example"
  description = "Managed by OpenTofu or Terraform"
}

resource "dockyard_template_repository" "orka_examples" {
  name                  = "Orka examples"
  slug                  = "orka-examples"
  repository_url        = "https://github.com/GhaziBenDahmane/Orka"
  git_ref               = "master"
  catalog_path          = "examples/template-repository"
  require_signature     = false
  sync_interval_seconds = 3600
}

resource "dockyard_oidc_provider" "workforce" {
  name          = "Workforce"
  issuer        = "https://identity.example.com"
  client_id     = "dockyard"
  client_secret = var.oidc_client_secret
  domains       = ["example.com"]
  scopes        = ["openid", "email", "profile"]
  default_role  = "developer"
  enabled       = true
}

resource "dockyard_saml_provider" "partners" {
  name                = "Partners"
  metadata_xml        = var.saml_metadata_xml
  domains             = ["partners.example.com"]
  email_attribute     = "email"
  name_attribute      = "name"
  default_role        = "viewer"
  allow_idp_initiated = false
  enabled             = true
}

resource "dockyard_scim_token" "workforce" {
  name              = "Workforce provisioning"
  default_role      = "developer"
  expires_in_days   = 90
  renew_before_days = 7

  lifecycle {
    create_before_destroy = true
  }
}

output "workforce_scim" {
  description = "Configure this endpoint and bearer token in the identity provider, then move the token to its secret store."
  sensitive   = true
  value = {
    base_url = dockyard_scim_token.workforce.base_url
    token    = dockyard_scim_token.workforce.token
  }
}

resource "dockyard_service_account" "deployment_automation" {
  name              = "Deployment automation"
  role              = "developer"
  expires_in_days   = 90
  renew_before_days = 7

  lifecycle {
    create_before_destroy = true
  }
}

output "deployment_automation_token" {
  description = "Store this one-time bearer token in the deployment system's secret manager."
  sensitive   = true
  value       = dockyard_service_account.deployment_automation.token
}

resource "dockyard_invitation" "operator" {
  email             = var.invited_operator_email
  role              = "developer"
  expires_in_days   = 7
  renew_before_days = 1

  lifecycle {
    create_before_destroy = true
  }
}

output "operator_invitation_url" {
  description = "Share this one-time enrollment URL through a secure channel."
  sensitive   = true
  value       = dockyard_invitation.operator.accept_url
}

resource "dockyard_auth_settings" "organization" {
  require_sso = true
  depends_on  = [dockyard_oidc_provider.workforce, dockyard_saml_provider.partners]
}

resource "dockyard_resource_policy" "organization" {
  scope_type       = "organization"
  maintenance      = false
  max_projects     = 25
  max_environments = 100
  max_services     = 500
  max_databases    = 100
}

resource "dockyard_audit_retention" "organization" {
  retention_days = 730
}

resource "dockyard_notification_endpoint" "operations" {
  name = "Operations webhook"
  kind = "webhook"
  events = [
    "deployment.failed",
    "backup.failed",
    "restore.failed",
    "ai.finding.critical",
  ]
  configuration_json = jsonencode({ url = var.notification_webhook_url })
}

output "notification_signing_secret" {
  description = "Install this secret in the webhook receiver before enabling production alerts."
  sensitive   = true
  value       = dockyard_notification_endpoint.operations.signing_secret
}

resource "dockyard_environment" "production" {
  project_id        = dockyard_project.example.id
  name              = "Production"
  placement_selector = { region = "eu-west" }
  minimum_nodes      = 3
  minimum_nano_cpus  = 8000000000
  minimum_memory_bytes = 17179869184
}

resource "dockyard_access_grant" "developer" {
  scope_type = "project"
  scope_id   = dockyard_project.example.id
  user_id    = var.developer_user_id
  role       = "developer"
}

resource "dockyard_service" "whoami" {
  environment_id = dockyard_environment.production.id
  name           = "Whoami"
  compose_yaml   = <<-YAML
    services:
      web:
        image: traefik/whoami:v1.11
        volumes:
          - uploads:/data
        deploy:
          replicas: 1
    volumes:
      uploads: {}
  YAML
}

resource "dockyard_tag" "production" {
  name  = "Production"
  color = "#DC2626"
}

resource "dockyard_tag" "frontend" {
  name  = "Frontend"
  color = "#2563EB"
}

resource "dockyard_service_tags" "whoami" {
  service_id = dockyard_service.whoami.id
  tag_ids     = [dockyard_tag.production.id, dockyard_tag.frontend.id]
}

resource "dockyard_project_tags" "example" {
  project_id = dockyard_project.example.id
  tag_ids    = [dockyard_tag.production.id]
}

resource "dockyard_deploy_token" "whoami_ci" {
  service_id        = dockyard_service.whoami.id
  name              = "Whoami CI"
  expires_in_days   = 90
  renew_before_days = 7

  lifecycle {
    create_before_destroy = true
  }
}

output "whoami_deploy_hook_url" {
  description = "Install this one-time URL in the CI secret store. Invoking it queues a deployment for only this service."
  sensitive   = true
  value       = dockyard_deploy_token.whoami_ci.url
}

resource "dockyard_backup_destination" "primary" {
  name       = "Primary backups"
  endpoint   = "https://s3.example.com"
  region     = "eu-west-1"
  bucket     = "example-backups"
  prefix     = "orka"
  use_tls    = true
  access_key = var.backup_access_key
  secret_key = var.backup_secret_key
}

# The bucket must have S3 Object Lock enabled before this resource is created.
resource "dockyard_audit_archive" "compliance" {
  name                  = "Compliance archive"
  backup_destination_id = dockyard_backup_destination.primary.id
  object_prefix         = "audit/production"
  retention_days        = 730
}

resource "dockyard_volume_backup_policy" "uploads" {
  service_id       = dockyard_service.whoami.id
  volume_name      = "uploads"
  destination_id   = dockyard_backup_destination.primary.id
  interval_seconds = 21600
  retention_count  = 28
  quiesce          = true
  enabled          = true
}

resource "dockyard_route" "whoami" {
  service_id           = dockyard_service.whoami.id
  service_name         = "web"
  host                 = "whoami.example.com"
  path_prefix          = "/"
  internal_path        = "/"
  strip_path           = false
  enabled              = true
  target_port          = 80
  tls                  = true
  certificate_resolver = "letsencrypt"
}

resource "dockyard_database" "postgres" {
  environment_id = dockyard_environment.production.id
  name           = "Primary PostgreSQL"
  engine         = "postgres"
  version        = "17"
  config_json = jsonencode({
    database = "app"
    username = "app"
  })
}

resource "dockyard_backup_policy" "postgres" {
  database_id      = dockyard_database.postgres.id
  interval_seconds = 86400
  retention_count  = 14
  enabled          = true
  verify_restore   = true
}
