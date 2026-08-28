# HTTP API

All request and response bodies use JSON. Except for health, bootstrap, login,
SSO discovery/callback, and deploy hooks, endpoints require
`Authorization: Bearer <session-token>`. Use `X-Organization-ID` to select an
organization when a user belongs to more than one.

## Identity

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/auth/bootstrap` | Create the first organization owner |
| POST | `/v1/auth/login` | Exchange local credentials for a session |
| POST | `/v1/auth/logout` | Revoke the current session |
| GET | `/v1/me` | Return the current principal and role |
| GET/POST | `/v1/sso/oidc-providers` | List or configure OIDC providers |
| GET | `/v1/auth/sso/discover?email=…` | Discover providers by email domain |
| GET | `/v1/auth/sso/{providerID}/start` | Start Authorization Code + PKCE |
| GET | `/v1/auth/sso/callback` | Verify the ID token and create a session |
| POST | `/v1/scim/tokens` | Create a one-time-visible SCIM bearer token |
| GET/POST/DELETE | `/v1/source-credentials…` | Manage encrypted Git and OCI registry credentials |
| GET/POST/PATCH/DELETE | `/scim/v2/Users…` | SCIM 2.0 user provisioning |
| GET/POST/PATCH/DELETE | `/scim/v2/Groups…` | SCIM groups and group-to-role mapping |

## Workloads

| Method | Path | Purpose |
|---|---|---|
| GET/POST | `/v1/projects` | List or create projects |
| GET/POST | `/v1/projects/{id}/environments` | List or create environments |
| GET/POST | `/v1/environments/{id}/services` | List or create Compose services |
| GET/PATCH/DELETE | `/v1/services/{id}` | Read, revise, or asynchronously remove a service and stack |
| PUT | `/v1/services/{id}/source` | Configure a Git/Dockerfile build, registry target, and credentials |
| POST | `/v1/services/{id}/routes` | Publish a service through Traefik |
| POST | `/v1/services/{id}/deployments` | Enqueue a Swarm deployment |
| GET | `/v1/services/{id}/deployments` | Read deployment history |
| POST | `/v1/deployments/{id}/cancel` | Cancel a queued or running deployment |
| POST | `/v1/services/{id}/rollback` | Redeploy the latest successful snapshot |
| GET | `/v1/services/{id}/logs` | Read aggregated Swarm service logs |
| POST | `/v1/services/{id}/deploy-tokens` | Create a CI deploy hook |
| POST | `/v1/hooks/deploy/{token}` | Trigger a deployment from CI |

## Catalog and databases

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/templates` | List global and organization templates |
| POST | `/v1/templates/import/dokploy` | Import `template.toml` plus Compose YAML |
| POST | `/v1/templates/{id}/instantiate` | Create a service, secrets, files and routes |
| GET | `/v1/database-engines` | List built-in database drivers |
| POST | `/v1/environments/{id}/databases` | Provision a managed data service definition |
| GET/POST/DELETE | `/v1/backup-destinations…` | Manage encrypted S3-compatible destinations |
| POST | `/v1/databases/{id}/backups` | Queue a verified native backup |
| GET/PUT/DELETE | `/v1/databases/{id}/backup-policy` | Manage interval scheduling and retention |
| POST | `/v1/database-backups/{id}/restore` | Restore after slug confirmation |

Database credentials are returned once on creation and encrypted at rest.
Creating a database produces a normal Compose service; deploy it through the
same deployment endpoint, preserving one audit and rollback model.
The engine response includes `backupCapable`; native verified backup/restore is
currently available for PostgreSQL, MySQL, MariaDB, and MongoDB.
Pass `destinationId` to a backup request or backup policy to upload through an
S3-compatible multipart client. Restores download to an isolated temporary
directory and verify the stored SHA-256 checksum before invoking native tools.
