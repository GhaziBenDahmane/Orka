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
API to deploy stacks. The outbound mTLS agent described below keeps the same
Swarm adapter while removing direct control-plane access to remote sockets.

Import `deploy/prometheus-alerts.yml` into Prometheus (or a compatible ruler)
and scrape `http://dockyard:8080/metrics`. The rules cover controller outage,
stale worker leases, queue backlog, failed operations, stale backups, and
maintenance mode left enabled. Route those alerts through Alertmanager to the
team's email, Slack, PagerDuty, or other incident receiver.

## Remote Swarm agent

Configure the controller with a dedicated TLS 1.3 listener and a private agent
CA. Create a cluster and one-time enrollment token through the API, then install
one outbound agent on a manager of that Swarm:

```sh
printf '%s' "$ENROLLMENT_TOKEN" | docker secret create dockyard_agent_enrollment_token -
DOCKYARD_CONTROL_PLANE_URL=https://dockyard.example.com \
  DOCKYARD_AGENT_URL=https://agents.dockyard.example.com:8444 \
  DOCKYARD_IMAGE=ghcr.io/example/dockyard:latest \
  docker stack deploy -c deploy/agent-swarm.yml dockyard-agent
```

The token is used once. The agent generates its private key locally, stores its
identity in the `agent-state` volume, verifies the controller using the
enrollment CA, and uses mTLS for heartbeat and command polling. No inbound port
or remote Docker socket is exposed on the managed cluster.

Managed-database backup and restore on remote clusters requires an
S3-compatible backup destination whose configured endpoint is reachable from
both the controller and agent. Transfers use one-hour presigned URLs. Backup
bytes are encrypted on the agent before upload; object-storage credentials and
plaintext backup data are never sent to the agent API or controller.
