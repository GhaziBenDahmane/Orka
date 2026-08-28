# Swarm installation

Run these commands on a Swarm manager after publishing the Dockyard image:

```sh
docker swarm init                         # skip if already active
docker network create --driver overlay --attachable dockyard-public
printf '%s' 'replace-with-a-long-password' | docker secret create dockyard_db_password -
printf '%s' 'postgres://dockyard:replace-with-a-long-password@postgres:5432/dockyard?sslmode=disable' | docker secret create dockyard_database_url -
openssl rand -base64 32 | docker secret create dockyard_master_key -
DOCKYARD_HOST=dockyard.example.com ACME_EMAIL=ops@example.com \
  DOCKYARD_IMAGE=ghcr.io/example/dockyard:latest \
  docker stack deploy -c deploy/swarm.yml dockyard
```

The controller is constrained to a manager because it uses the manager Docker
API to deploy stacks. A later multi-cluster agent keeps the same Swarm adapter
while removing the local socket requirement.
