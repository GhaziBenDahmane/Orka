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

resource "dockyard_project" "example" {
  name        = "Example"
  description = "Managed by OpenTofu or Terraform"
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
        deploy:
          replicas: 1
  YAML
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
