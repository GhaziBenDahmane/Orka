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
  project_id = dockyard_project.example.id
  name       = "Production"
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
