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

resource "dockyard_environment" "production" {
  project_id        = dockyard_project.example.id
  name              = "Production"
  placement_selector = { region = "eu-west" }
  minimum_nodes      = 3
  minimum_nano_cpus  = 8000000000
  minimum_memory_bytes = 17179869184
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
