export type Principal = {
  userId: string;
  organizationId: string;
  email: string;
  organization: string;
  role: "viewer" | "developer" | "admin" | "owner";
};
export type Role = Principal["role"];

export type Project = { id: string; name: string; slug: string; description: string };
export type Environment = { id: string; projectId: string; name: string; slug: string; clusterId?: string; placementSelector?: Record<string, string>; minimumNodes?: number; minimumNanoCpus?: number; minimumMemoryBytes?: number };
export type Service = { id: string; environmentId: string; name: string; slug: string; revision: number; status: string; composeYaml?: string };
export type ApplicationArtifact = { filename: string; sha256: string; compressedSize: number; updatedAt: string };
export type ApplicationSource = { composeServiceId: string; sourceType: "git" | "drop"; repositoryUrl: string; gitRef: string; contextDirectory: string; dockerfile: string; buildType: "dockerfile" | "static" | "nixpacks" | "railpack" | "buildpacks" | "heroku_buildpacks"; builderImage?: string; outputDirectory?: string; buildTarget?: string; enableSubmodules: boolean; hasBuildArguments: boolean; hasBuildSecrets: boolean; targetService: string; registryImage: string; gitCredentialId?: string; registryCredentialId?: string; statusProvider?: string; statusCredentialId?: string; statusContext?: string; artifact?: ApplicationArtifact; updatedAt: string };
export type Deployment = { id: string; revision: number; status: string; trigger: string; error?: string; output?: string; createdAt: string };
export type TemplateVariable = { name: string; default?: string; generated: boolean; sensitive: boolean };
export type Template = { id: string; key: string; version: string; name: string; description: string; source: string; variables: TemplateVariable[] };
export type TemplateRepository = { id: string; name: string; slug: string; repositoryUrl: string; gitRef: string; catalogPath: string; trustedPublicKey?: string; requireSignature: boolean; syncIntervalSeconds: number; nextSyncAt?: string; enabled: boolean; lastSyncStatus: string; lastSyncError?: string; lastSyncedAt?: string };
export type TemplatePreview = { services: { name: string; image?: string }[]; routes: { serviceName: string; host: string; path: string; targetPort: number }[]; environmentKeys: string[]; managedFiles: number };
export type TemplateInstance = { composeServiceId: string; templateId?: string; templateKey: string; templateVersion: string; templateChecksum: string; appliedComposeChecksum: string; baseDomain: string; drifted: boolean; createdAt: string; updatedAt: string };
export type Cluster = { id: string; name: string; slug: string; state: string; labels: Record<string, unknown>; capacity: Record<string, unknown>; agentVersion: string; dockerVersion: string; certificateNotAfter?: string; lastSeenAt?: string; maintenanceStartsAt?: string; maintenanceEndsAt?: string };
export type ClusterCommand = { id: string; clusterId: string; kind: string; status: string; attempts: number; lastError?: string; createdAt: string };
export type SourceCredential = { id: string; kind: "git" | "git-ssh" | "registry"; name: string; server: string; username: string };
export type BackupDestination = { id: string; name: string; endpoint: string; region: string; bucket: string; prefix: string; useTls: boolean };
export type OIDCProvider = { id: string; name: string; issuer: string; clientId: string; domains: string[]; scopes: string[]; defaultRole: string; enabled: boolean };
export type SAMLProvider = { id: string; name: string; domains: string[]; emailAttribute: string; nameAttribute: string; defaultRole: string; allowIdpInitiated: boolean; enabled: boolean };
export type Database = { id: string; environmentId: string; composeServiceId: string; name: string; slug: string; engine: string; version: string; status: string };
export type DatabaseMigration = { id: string; databaseInstanceId: string; sourceKind: string; sourceId: string; sourceEngine: string; sourceVersion: string; sourceHost: string; status: string; sizeBytes?: number; sha256?: string; output?: string; error?: string; createdAt: string; startedAt?: string; finishedAt?: string };
export type DatabaseBackup = { id: string; databaseInstanceId: string; status: string; format: string; sizeBytes?: number; sha256?: string; encrypted: boolean; destinationId?: string; error?: string; createdAt: string; startedAt?: string; finishedAt?: string };
export type DatabaseRestore = { id: string; databaseBackupId: string; status: string; kind: string; error?: string; createdAt: string; startedAt?: string; finishedAt?: string };
export type BackupPolicy = { id: string; databaseInstanceId: string; intervalSeconds: number; retentionCount: number; enabled: boolean; verifyRestore: boolean; destinationId?: string };
export type ResourcePolicy = { organizationId: string; scopeType: "organization" | "project" | "environment"; scopeId: string; maintenance: boolean; maintenanceReason: string; maxProjects: number | null; maxEnvironments: number | null; maxServices: number | null; maxDatabases: number | null; updatedAt: string };
export type AuthSettings = { organizationId: string; requireSso: boolean; updatedAt: string };
export type AuditEvent = { id: number; actorUserId?: string; actorServiceAccountId?: string; action: string; resourceType: string; resourceId: string; remoteAddr: string; metadata: Record<string, unknown> | null; createdAt: string };
export type AuditRetention = { organizationId: string; retentionDays: number; updatedAt: string };
export type AuditArchive = { id: string; backupDestinationId: string; name: string; objectPrefix: string; retentionDays: number; enabled: boolean; lastArchivedId: number; lastChainHash?: string; updatedAt: string };
export type NotificationEndpoint = { id: string; name: string; kind: "webhook" | "slack" | "smtp" | "pagerduty" | "opsgenie"; events: string[]; enabled: boolean; updatedAt: string };
export type ServiceAccount = { id: string; name: string; role: string; enabled: boolean; tokenExpiresAt?: string };
export type AIAuditRun = { id: string; serviceAccountId: string; agentName: string; agentVersion: string; model: string; status: string; scope: Record<string, unknown>; summary: string; startedAt: string; completedAt?: string };
export type AIAuditFinding = { id: string; runId: string; severity: string; category: string; title: string; description: string; resourceType?: string; resourceId?: string; evidence: Record<string, unknown>; remediation?: string; createdAt: string };

type Envelope<T> = { items: T[] };
type ErrorEnvelope = { error?: { code?: string; message?: string } };

export class APIError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
  }
}

const tokenKey = "dockyard.session";

export const session = {
  get: () => sessionStorage.getItem(tokenKey) ?? "",
  set: (token: string) => sessionStorage.setItem(tokenKey, token),
  clear: () => sessionStorage.removeItem(tokenKey),
};

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body && !(init.body instanceof FormData)) headers.set("content-type", "application/json");
  if (session.get()) headers.set("authorization", `Bearer ${session.get()}`);
  const response = await fetch(path, { ...init, headers });
  if (response.status === 401) session.clear();
  if (!response.ok) {
    const body = await response.json().catch(() => ({})) as ErrorEnvelope;
    throw new APIError(response.status, body.error?.code ?? "request_failed", body.error?.message ?? `Request failed (${response.status})`);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

async function download(path: string): Promise<{ blob: Blob; filename: string; sha256: string }> {
  const headers = new Headers();
  if (session.get()) headers.set("authorization", `Bearer ${session.get()}`);
  const response = await fetch(path, { headers });
  if (!response.ok) {
    const body = await response.json().catch(() => ({})) as ErrorEnvelope;
    throw new APIError(response.status, body.error?.code ?? "request_failed", body.error?.message ?? `Request failed (${response.status})`);
  }
  const disposition = response.headers.get("content-disposition") ?? "";
  return { blob: await response.blob(), filename: disposition.match(/filename="([^"]+)"/)?.[1] ?? "dockyard-audit.ndjson", sha256: response.headers.get("x-content-sha256") ?? "" };
}

export const api = {
  login: (email: string, password: string) => request<{ token: string }>("/v1/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }),
  logout: () => request<void>("/v1/auth/logout", { method: "POST" }),
  me: () => request<Principal>("/v1/me"),
  effectiveRole: (resourceType: string, resourceId: string) => request<{ role: Role }>(`/v1/authorization/effective-role?resourceType=${encodeURIComponent(resourceType)}&resourceId=${encodeURIComponent(resourceId)}`),
  discoverOIDC: (email: string) => request<Envelope<{ id: string; name: string }>>(`/v1/auth/sso/discover?email=${encodeURIComponent(email)}`),
  discoverSAML: (email: string) => request<Envelope<{ id: string; name: string }>>(`/v1/auth/saml/discover?email=${encodeURIComponent(email)}`),
  startOIDC: (providerId: string) => request<{ url: string }>(`/v1/auth/sso/${providerId}/start`),
  startSAML: (providerId: string) => request<{ url: string }>(`/v1/auth/saml/${providerId}/start`),
  projects: () => request<Envelope<Project>>("/v1/projects"),
  createProject: (body: { name: string; description: string }) => request<Project>("/v1/projects", { method: "POST", body: JSON.stringify(body) }),
  environments: (projectId: string) => request<Envelope<Environment>>(`/v1/projects/${projectId}/environments`),
  createEnvironment: (projectId: string, name: string, placement?: { clusterId?: string; placementSelector?: Record<string, string>; minimumNodes?: number; minimumNanoCpus?: number; minimumMemoryBytes?: number }) => request<Environment>(`/v1/projects/${projectId}/environments`, { method: "POST", body: JSON.stringify({ name, ...placement }) }),
  services: (environmentId: string) => request<Envelope<Service>>(`/v1/environments/${environmentId}/services`),
  service: (serviceId: string) => request<{ service: Service; routes: unknown[]; source: ApplicationSource | null; template: TemplateInstance | null }>(`/v1/services/${serviceId}`),
  templateVersions: (serviceId: string) => request<{ current: TemplateInstance; items: Template[] }>(`/v1/services/${serviceId}/template-versions`),
  upgradeTemplate: (serviceId: string, body: { templateId: string; allowDrift: boolean; variables: Record<string, string> }) => request<{ service: Service }>(`/v1/services/${serviceId}/template-upgrades`, { method: "POST", body: JSON.stringify(body) }),
  createService: (environmentId: string, body: { name: string; composeYaml: string }) => request<Service>(`/v1/environments/${environmentId}/services`, { method: "POST", body: JSON.stringify(body) }),
  updateService: (serviceId: string, composeYaml: string) => request<Service>(`/v1/services/${serviceId}`, { method: "PATCH", body: JSON.stringify({ composeYaml }) }),
  upsertSource: (serviceId: string, body: { sourceType: "git" | "drop"; repositoryUrl: string; gitRef: string; contextDirectory: string; dockerfile: string; buildType: "dockerfile" | "static" | "nixpacks" | "railpack" | "buildpacks" | "heroku_buildpacks"; builderImage?: string; outputDirectory?: string; buildTarget?: string; enableSubmodules: boolean; buildArguments?: Record<string, string>; buildSecrets?: Record<string, string>; targetService: string; registryImage: string; gitCredentialId?: string; registryCredentialId?: string; statusProvider?: string; statusCredentialId?: string; statusContext?: string }) => request<ApplicationSource>(`/v1/services/${serviceId}/source`, { method: "PUT", body: JSON.stringify(body) }),
  uploadArtifact: (serviceId: string, file: File) => { const body = new FormData(); body.append("file", file); return request<ApplicationArtifact>(`/v1/services/${serviceId}/artifact-source`, { method: "PUT", body }); },
  deploy: (serviceId: string) => request<Deployment>(`/v1/services/${serviceId}/deployments`, { method: "POST", body: "{}" }),
  deployments: (serviceId: string) => request<Envelope<Deployment>>(`/v1/services/${serviceId}/deployments`),
  logs: (serviceId: string) => request<{ logs: string }>(`/v1/services/${serviceId}/logs`),
  templates: () => request<Envelope<Template>>("/v1/templates"),
  templateRepositories: () => request<Envelope<TemplateRepository>>("/v1/template-repositories"),
  createTemplateRepository: (body: { name: string; slug: string; repositoryUrl: string; gitRef: string; catalogPath: string; trustedPublicKey: string; requireSignature: boolean; syncIntervalSeconds: number }) => request<TemplateRepository>("/v1/template-repositories", { method: "POST", body: JSON.stringify(body) }),
  updateTemplateRepository: (id: string, body: { trustedPublicKey: string; requireSignature: boolean; syncIntervalSeconds: number }) => request<void>(`/v1/template-repositories/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  syncTemplateRepository: (id: string) => request<{ imported: number; failed: Record<string, string> }>(`/v1/template-repositories/${id}/sync`, { method: "POST", body: "{}" }),
  deleteTemplateRepository: (id: string) => request<void>(`/v1/template-repositories/${id}`, { method: "DELETE" }),
  previewTemplate: (templateId: string, body: { baseDomain: string; variables: Record<string, string> }) => request<{ templateId: string; checksum: string; preview: TemplatePreview }>(`/v1/templates/${templateId}/preview`, { method: "POST", body: JSON.stringify(body) }),
  instantiateTemplate: (templateId: string, body: { environmentId: string; name: string; baseDomain: string; variables: Record<string, string> }) => request<{ service: Service }>(`/v1/templates/${templateId}/instantiate`, { method: "POST", body: JSON.stringify(body) }),
  databaseEngines: () => request<{ items: string[]; backupCapable: string[] }>("/v1/database-engines"),
  createDatabase: (environmentId: string, body: { name: string; engine: string; version: string; config: Record<string, unknown> }) => request<{ database: { id: string; name: string }; credentials: Record<string, string>; internalUrl: string }>(`/v1/environments/${environmentId}/databases`, { method: "POST", body: JSON.stringify(body) }),
  databases: (environmentId: string) => request<Envelope<Database>>(`/v1/environments/${environmentId}/databases`),
  databaseBackups: (databaseId: string) => request<Envelope<DatabaseBackup>>(`/v1/databases/${databaseId}/backups`),
  databaseRestores: (databaseId: string) => request<Envelope<DatabaseRestore>>(`/v1/databases/${databaseId}/restores`),
  databaseMigrations: (databaseId: string) => request<Envelope<DatabaseMigration>>(`/v1/databases/${databaseId}/migrations`),
  cancelDatabaseMigration: (migrationId: string) => request<{ status: string }>(`/v1/database-migrations/${migrationId}/cancel`, { method: "POST", body: "{}" }),
  deleteDatabase: (databaseId: string) => request<void>(`/v1/databases/${databaseId}`, { method: "DELETE" }),
  backupPolicy: (databaseId: string) => request<BackupPolicy>(`/v1/databases/${databaseId}/backup-policy`),
  putBackupPolicy: (databaseId: string, body: { intervalSeconds: number; retentionCount: number; enabled: boolean; verifyRestore: boolean; destinationId?: string }) => request<BackupPolicy>(`/v1/databases/${databaseId}/backup-policy`, { method: "PUT", body: JSON.stringify(body) }),
  deleteBackupPolicy: (databaseId: string) => request<void>(`/v1/databases/${databaseId}/backup-policy`, { method: "DELETE" }),
  backupDatabase: (databaseId: string, destinationId?: string) => request<{ id: string; status: string }>(`/v1/databases/${databaseId}/backups${destinationId ? `?destinationId=${encodeURIComponent(destinationId)}` : ""}`, { method: "POST", body: "{}" }),
  cancelDatabaseBackup: (backupId: string) => request<{ status: string }>(`/v1/database-backups/${backupId}/cancel`, { method: "POST", body: "{}" }),
  restoreDatabaseBackup: (backupId: string, confirm: string) => request<DatabaseRestore>(`/v1/database-backups/${backupId}/restore`, { method: "POST", body: JSON.stringify({ confirm }) }),
  cancelDatabaseRestore: (restoreId: string) => request<{ status: string }>(`/v1/database-restores/${restoreId}/cancel`, { method: "POST", body: "{}" }),
  clusters: () => request<Envelope<Cluster>>("/v1/clusters"),
  createCluster: (body: { name: string; labels: Record<string, string> }) => request<Cluster>("/v1/clusters", { method: "POST", body: JSON.stringify(body) }),
  updateCluster: (id: string, state: string) => request<Cluster>(`/v1/clusters/${id}`, { method: "PATCH", body: JSON.stringify({ state }) }),
  deleteCluster: (id: string) => request<{ status: string }>(`/v1/clusters/${id}`, { method: "DELETE" }),
  createEnrollmentToken: (id: string) => request<{ token: string; expiresAt: string }>(`/v1/clusters/${id}/enrollment-tokens`, { method: "POST", body: "{}" }),
  upgradeAgent: (id: string, image: string) => request<ClusterCommand>(`/v1/clusters/${id}/agent-upgrades`, { method: "POST", body: JSON.stringify({ image }) }),
  sourceCredentials: () => request<Envelope<SourceCredential>>("/v1/source-credentials"),
  createSourceCredential: (body: { kind: string; name: string; server: string; username: string; secret?: string; privateKey?: string; knownHosts?: string }) => request<SourceCredential>("/v1/source-credentials", { method: "POST", body: JSON.stringify(body) }),
  deleteSourceCredential: (id: string) => request<void>(`/v1/source-credentials/${id}`, { method: "DELETE" }),
  backupDestinations: () => request<Envelope<BackupDestination>>("/v1/backup-destinations"),
  createBackupDestination: (body: { name: string; endpoint: string; region: string; bucket: string; prefix: string; useTls: boolean; accessKey: string; secretKey: string; sessionToken?: string }) => request<BackupDestination>("/v1/backup-destinations", { method: "POST", body: JSON.stringify(body) }),
  deleteBackupDestination: (id: string) => request<void>(`/v1/backup-destinations/${id}`, { method: "DELETE" }),
  oidcProviders: () => request<Envelope<OIDCProvider>>("/v1/sso/oidc-providers"),
  createOIDCProvider: (body: { name: string; issuer: string; clientId: string; clientSecret: string; domains: string[]; scopes: string[]; defaultRole: string }) => request<OIDCProvider>("/v1/sso/oidc-providers", { method: "POST", body: JSON.stringify(body) }),
  updateOIDCProvider: (id: string, body: { name: string; issuer: string; clientId: string; clientSecret: string; domains: string[]; scopes: string[]; defaultRole: string }) => request<OIDCProvider>(`/v1/sso/oidc-providers/${id}`, { method: "PUT", body: JSON.stringify(body) }),
  disableOIDCProvider: (id: string) => request<void>(`/v1/sso/oidc-providers/${id}`, { method: "DELETE" }),
  enableOIDCProvider: (id: string) => request<void>(`/v1/sso/oidc-providers/${id}/enable`, { method: "POST", body: "{}" }),
  samlProviders: () => request<Envelope<SAMLProvider>>("/v1/sso/saml-providers"),
  createSAMLProvider: (body: { name: string; metadataXml: string; domains: string[]; emailAttribute: string; nameAttribute: string; defaultRole: string; allowIdpInitiated: boolean }) => request<SAMLProvider>("/v1/sso/saml-providers", { method: "POST", body: JSON.stringify(body) }),
  updateSAMLProvider: (id: string, body: { name: string; metadataXml: string; domains: string[]; emailAttribute: string; nameAttribute: string; defaultRole: string; allowIdpInitiated: boolean }) => request<SAMLProvider>(`/v1/sso/saml-providers/${id}`, { method: "PUT", body: JSON.stringify(body) }),
  disableSAMLProvider: (id: string) => request<void>(`/v1/sso/saml-providers/${id}`, { method: "DELETE" }),
  enableSAMLProvider: (id: string) => request<void>(`/v1/sso/saml-providers/${id}/enable`, { method: "POST", body: "{}" }),
  authSettings: () => request<AuthSettings>("/v1/sso/settings"),
  putAuthSettings: (requireSso: boolean) => request<AuthSettings>("/v1/sso/settings", { method: "PUT", body: JSON.stringify({ requireSso }) }),
  policy: (scope: "organization" | "project" | "environment", id = "") => request<ResourcePolicy>(scope === "organization" ? "/v1/policy" : `/v1/${scope === "project" ? "projects" : "environments"}/${id}/policy`),
  putPolicy: (scope: "organization" | "project" | "environment", id: string, body: Pick<ResourcePolicy, "maintenance" | "maintenanceReason" | "maxProjects" | "maxEnvironments" | "maxServices" | "maxDatabases">) => request<ResourcePolicy>(scope === "organization" ? "/v1/policy" : `/v1/${scope === "project" ? "projects" : "environments"}/${id}/policy`, { method: "PUT", body: JSON.stringify(body) }),
  auditEvents: (beforeId = 0, limit = 100) => request<Envelope<AuditEvent>>(`/v1/audit-events?limit=${limit}${beforeId ? `&beforeId=${beforeId}` : ""}`),
  auditRetention: () => request<AuditRetention>("/v1/audit-retention"),
  putAuditRetention: (retentionDays: number) => request<AuditRetention>("/v1/audit-retention", { method: "PUT", body: JSON.stringify({ retentionDays }) }),
  exportAudit: () => download("/v1/audit-events/export?limit=10000"),
  auditArchives: () => request<Envelope<AuditArchive>>("/v1/audit-archives"),
  createAuditArchive: (body: { name: string; backupDestinationId: string; objectPrefix: string; retentionDays: number }) => request<AuditArchive>("/v1/audit-archives", { method: "POST", body: JSON.stringify(body) }),
  runAuditArchive: (id: string) => request<unknown>(`/v1/audit-archives/${id}/run`, { method: "POST", body: "{}" }),
  disableAuditArchive: (id: string) => request<void>(`/v1/audit-archives/${id}`, { method: "DELETE" }),
  notificationEndpoints: () => request<Envelope<NotificationEndpoint>>("/v1/notification-endpoints"),
  createNotificationEndpoint: (body: Record<string, unknown>) => request<{ endpoint: NotificationEndpoint; signingSecret?: string }>("/v1/notification-endpoints", { method: "POST", body: JSON.stringify(body) }),
  disableNotificationEndpoint: (id: string) => request<void>(`/v1/notification-endpoints/${id}`, { method: "DELETE" }),
  createAuditorAccount: (name: string, expiresInDays: number) => request<{ serviceAccount: ServiceAccount; token: string }>("/v1/service-accounts", { method: "POST", body: JSON.stringify({ name, role: "auditor", expiresInDays }) }),
  aiAuditRuns: () => request<Envelope<AIAuditRun>>("/v1/ai/audit-runs"),
  aiAuditFindings: (runId: string) => request<Envelope<AIAuditFinding>>(`/v1/ai/audit-runs/${runId}/findings`),
};
