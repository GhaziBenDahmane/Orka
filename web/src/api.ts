export type Principal = {
  userId: string;
  organizationId: string;
  email: string;
  organization: string;
  role: "viewer" | "developer" | "admin" | "owner";
};
export type Role = Principal["role"];
export type SessionInfo = { id: string; organizationId?: string; authMethod: string; userAgent: string; ipAddress: string; expiresAt: string; createdAt: string; lastSeenAt: string; current: boolean };
export type MFAStatus = { enabled: boolean; enrollmentPending: boolean; recoveryCodesRemaining: number };

export type Project = { id: string; name: string; slug: string; description: string; tags: Tag[] };
export type Environment = { id: string; projectId: string; name: string; slug: string; clusterId?: string; placementSelector?: Record<string, string>; minimumNodes?: number; minimumNanoCpus?: number; minimumMemoryBytes?: number };
export type Tag = { id: string; organizationId: string; name: string; color: string; serviceCount: number; projectCount: number; createdAt: string; updatedAt: string };
export type Service = { id: string; environmentId: string; name: string; slug: string; stackName?: string; storageNodeId?: string; revision: number; desiredState: "running" | "stopped"; status: string; composeYaml?: string; tags: Tag[] };
export type ServiceVariableList = { items: { name: string }[]; revision: number };
export type Route = { id: string; composeServiceId: string; serviceName: string; host: string; pathPrefix: string; internalPath: string; stripPath: boolean; enabled: boolean; redirectRegex: string; redirectReplacement: string; redirectPermanent: boolean; targetPort: number; tls: boolean; certificateResolver: string; customCertificateId?: string; createdAt: string; updatedAt: string };
export type RouteInput = Pick<Route, "serviceName" | "host" | "pathPrefix" | "internalPath" | "stripPath" | "enabled" | "redirectRegex" | "redirectReplacement" | "redirectPermanent" | "targetPort" | "tls" | "certificateResolver" | "customCertificateId">;
export type RouteBasicAuthUser = { id: string; composeServiceId: string; username: string; createdAt: string; updatedAt: string };
export type CustomTLSCertificate = { id: string; organizationId: string; name: string; fingerprint: string; commonName: string; dnsNames: string[]; notBefore: string; notAfter: string; revision: number; createdAt: string; updatedAt: string };
export type ApplicationArtifact = { filename: string; sha256: string; compressedSize: number; updatedAt: string };
export type ApplicationSource = { composeServiceId: string; sourceType: "git" | "drop"; repositoryUrl: string; gitRef: string; contextDirectory: string; dockerfile: string; buildType: "dockerfile" | "static" | "nixpacks" | "railpack" | "buildpacks" | "heroku_buildpacks"; builderImage?: string; outputDirectory?: string; buildTarget?: string; enableSubmodules: boolean; hasBuildArguments: boolean; hasBuildSecrets: boolean; targetService: string; registryImage: string; gitCredentialId?: string; registryCredentialId?: string; statusProvider?: string; statusCredentialId?: string; statusContext?: string; artifact?: ApplicationArtifact; updatedAt: string };
export type Deployment = { id: string; revision: number; status: string; trigger: string; error?: string; output?: string; createdAt: string };
export type ServiceSchedule = { id: string; composeServiceId: string; name: string; description: string; cronExpression: string; timezone: string; targetService: string; shell: "sh" | "bash"; command: string; timeoutSeconds: number; enabled: boolean; nextRunAt: string; createdAt: string; updatedAt: string };
export type ServiceScheduleExecution = { id: string; scheduleId?: string; composeServiceId: string; scheduleName: string; targetService: string; shell: string; command: string; timeoutSeconds: number; trigger: string; actorUserId?: string; status: string; output: string; error: string; createdAt: string; startedAt?: string; finishedAt?: string };
export type ServiceScheduleInput = Pick<ServiceSchedule, "name" | "description" | "cronExpression" | "timezone" | "targetService" | "shell" | "command" | "timeoutSeconds" | "enabled">;
export type DeployToken = { id: string; composeServiceId: string; name: string; expiresAt: string; lastUsedAt?: string; revokedAt?: string; createdAt: string };
export type TemplateVariable = { name: string; default?: string; generated: boolean; sensitive: boolean };
export type Template = { id: string; key: string; version: string; name: string; description: string; source: string; variables: TemplateVariable[]; safetyClass: "safe" | "requires_unsafe" | "invalid"; safetyReason?: string; deployable: boolean };
export type TemplateRepository = { id: string; name: string; slug: string; repositoryUrl: string; gitRef: string; catalogPath: string; trustedPublicKey?: string; requireSignature: boolean; credentialId?: string; webhookConfigured: boolean; syncIntervalSeconds: number; nextSyncAt?: string; syncRequestedAt?: string; syncStartedAt?: string; enabled: boolean; lastSyncStatus: string; lastSyncError?: string; lastSyncedAt?: string };
export type TemplatePreview = { services: { name: string; image?: string }[]; routes: { serviceName: string; host: string; path: string; targetPort: number }[]; environmentKeys: string[]; managedFiles: number };
export type TemplateInstance = { composeServiceId: string; templateId?: string; templateKey: string; templateVersion: string; templateChecksum: string; appliedComposeChecksum: string; baseDomain: string; drifted: boolean; createdAt: string; updatedAt: string };
export type ServiceReconciliation = { composeServiceId: string; state: "healthy" | "missing" | "degraded" | "unknown" | "repairing"; consecutiveFailures: number; detail?: string; lastCheckedAt: string; lastRepairAt?: string };
export type EdgeProxyCapability = { provider: "traefik"; managementMode: "external"; serviceName: string; publicNetwork: string; dynamicConfigurationMode: "file"; dynamicConfigurationPath: string; ready: boolean; status: string; supportsCustomCertificates: boolean };
export type ClusterCapabilities = { protocolVersion?: number; dockerSwarm?: boolean; dockerCompose?: boolean; edgeProxy?: EdgeProxyCapability };
export type Cluster = { id: string; name: string; slug: string; state: string; labels: Record<string, unknown>; capacity: Record<string, unknown>; capabilities: ClusterCapabilities; agentVersion: string; agentImage: string; agentUpdateState: string; dockerVersion: string; certificateAuthorityFingerprint?: string; pendingCertificateAuthorityFingerprint?: string; certificateNotAfter?: string; lastSeenAt?: string; maintenanceStartsAt?: string; maintenanceEndsAt?: string };
export type ClusterCommand = { id: string; clusterId: string; kind: string; status: string; attempts: number; targetImage?: string; lastError?: string; createdAt: string };
export type ManagedNetwork = { id: string; organizationId: string; clusterId?: string; name: string; driver: "overlay" | "bridge"; internal: boolean; attachable: boolean; enableIpv4: boolean; enableIpv6: boolean; mtu?: number; ipam: { subnet?: string; gateway?: string; ipRange?: string }[]; dockerId?: string; status: "provisioning" | "ready" | "deleting" | "error"; lastError?: string; deletionRequestedAt?: string; createdAt: string; updatedAt: string };
export type SourceCredential = { id: string; kind: "git" | "git-ssh" | "registry"; name: string; server: string; username: string };
export type BackupDestination = { id: string; name: string; endpoint: string; region: string; bucket: string; prefix: string; useTls: boolean };
export type OIDCProvider = { id: string; name: string; issuer: string; clientId: string; domains: string[]; scopes: string[]; defaultRole: string; enabled: boolean };
export type SAMLProvider = { id: string; name: string; domains: string[]; emailAttribute: string; nameAttribute: string; defaultRole: string; allowIdpInitiated: boolean; enabled: boolean; spCertificateNotAfter?: string; idpCertificateNotAfter?: string; certificateConfigurationOk: boolean; pendingCertificateNotAfter?: string; pendingCertificateCreatedAt?: string };
export type Database = { id: string; environmentId: string; composeServiceId: string; name: string; slug: string; engine: string; version: string; driverSource: "built-in" | "external" | "unbound"; driverArtifactDigest?: string; storageNodeId?: string; status: string };
export type DatabaseEngine = { name: string; defaultVersion: string; source: "built-in" | "external"; artifactDigest?: string; backupCapable: boolean; backupExtension: string };
export type DatabaseMigration = { id: string; databaseInstanceId: string; sourceKind: string; sourceId: string; sourceEngine: string; sourceVersion: string; sourceHost: string; status: string; sizeBytes?: number; sha256?: string; output?: string; error?: string; createdAt: string; startedAt?: string; finishedAt?: string };
export type DatabaseBackup = { id: string; databaseInstanceId: string; status: string; format: string; sizeBytes?: number; sha256?: string; encrypted: boolean; destinationId?: string; error?: string; createdAt: string; startedAt?: string; finishedAt?: string };
export type DatabaseRestore = { id: string; databaseBackupId: string; status: string; kind: string; error?: string; createdAt: string; startedAt?: string; finishedAt?: string };
export type BackupPolicy = { id: string; databaseInstanceId: string; intervalSeconds: number; retentionCount: number; enabled: boolean; verifyRestore: boolean; destinationId?: string };
export type ServiceVolume = { name: string; dockerName: string; storageNodeId?: string };
export type VolumeBackupPolicy = { id: string; composeServiceId: string; volumeName: string; destinationId: string; intervalSeconds: number; retentionCount: number; quiesce: boolean; enabled: boolean; nextRunAt: string; lastRunAt?: string };
export type VolumeBackup = { id: string; composeServiceId: string; volumeName: string; storageNodeId: string; destinationId: string; quiesce: boolean; status: string; sizeBytes?: number; sha256?: string; plaintextSha256?: string; error?: string; createdAt: string; startedAt?: string; finishedAt?: string };
export type VolumeRestore = { id: string; volumeBackupId: string; status: string; error?: string; createdAt: string; startedAt?: string; finishedAt?: string };
export type ResourcePolicy = { organizationId: string; scopeType: "organization" | "project" | "environment"; scopeId: string; maintenance: boolean; maintenanceReason: string; maxProjects: number | null; maxEnvironments: number | null; maxServices: number | null; maxDatabases: number | null; updatedAt: string };
export type AuthSettings = { organizationId: string; requireSso: boolean; updatedAt: string };
export type AuditEvent = { id: number; actorUserId?: string; actorServiceAccountId?: string; action: string; resourceType: string; resourceId: string; remoteAddr: string; metadata: Record<string, unknown> | null; createdAt: string };
export type AuditRetention = { organizationId: string; retentionDays: number; updatedAt: string };
export type AuditArchive = { id: string; backupDestinationId: string; name: string; objectPrefix: string; retentionDays: number; enabled: boolean; lastArchivedId: number; lastChainHash?: string; updatedAt: string };
export type NotificationEndpoint = { id: string; name: string; kind: "webhook" | "slack" | "smtp" | "pagerduty" | "opsgenie"; events: string[]; enabled: boolean; updatedAt: string };
export type ServiceAccount = { id: string; name: string; role: string; enabled: boolean; tokenExpiresAt?: string; lastUsedAt?: string; createdAt: string; updatedAt: string };
export type SCIMToken = { id: string; organizationId: string; name: string; defaultRole: "admin" | "developer" | "viewer"; createdAt: string; expiresAt: string; revokedAt?: string };
export type OrganizationMember = { userId: string; email: string; displayName: string; role: Role; active: boolean; managedByScim: boolean; createdAt: string };
export type OrganizationInvitation = { id: string; organizationId: string; email: string; role: Role; expiresAt: string; acceptedAt?: string; revokedAt?: string; createdAt: string };
export type AIAuditRun = { id: string; serviceAccountId: string; agentName: string; agentVersion: string; model: string; status: string; scope: Record<string, unknown>; summary: string; startedAt: string; completedAt?: string };
export type AIAuditFinding = { id: string; runId: string; serviceAccountId: string; agentName: string; severity: string; category: string; title: string; description: string; resourceType?: string; resourceId?: string; evidence: Record<string, unknown>; remediation?: string; fingerprint: string; createdAt: string; disposition: "open" | "acknowledged" | "resolved"; triageNote?: string; triagedByUserId?: string; triagedByServiceAccountId?: string; triagedAt?: string; previousFindingId?: string; occurrenceNumber: number };

type Envelope<T> = { items: T[] };
type PaginatedEnvelope<T> = Envelope<T> & { nextCursor: string };
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
  login: (email: string, password: string, totpCode = "", recoveryCode = "") => request<{ token: string }>("/v1/auth/login", { method: "POST", body: JSON.stringify({ email, password, totpCode, recoveryCode }) }),
  logout: () => request<void>("/v1/auth/logout", { method: "POST" }),
  changePassword: (currentPassword: string, newPassword: string) => request<{ revoked: number }>("/v1/auth/password", { method: "PUT", body: JSON.stringify({ currentPassword, newPassword }) }),
  mfaStatus: () => request<MFAStatus>("/v1/auth/mfa"),
  beginMFAEnrollment: (currentPassword: string) => request<{ secret: string; otpauthUri: string }>("/v1/auth/mfa/enrollment", { method: "POST", body: JSON.stringify({ currentPassword }) }),
  confirmMFAEnrollment: (code: string) => request<{ recoveryCodes: string[]; revokedSessions: number }>("/v1/auth/mfa/enrollment/confirm", { method: "POST", body: JSON.stringify({ code }) }),
  disableMFA: (currentPassword: string, code: string, recoveryCode: string) => request<{ enabled: boolean; revokedSessions: number }>("/v1/auth/mfa", { method: "DELETE", body: JSON.stringify({ currentPassword, code, recoveryCode }) }),
  regenerateMFARecoveryCodes: (currentPassword: string, code: string, recoveryCode: string) => request<{ recoveryCodes: string[]; revokedSessions: number }>("/v1/auth/mfa/recovery-codes", { method: "POST", body: JSON.stringify({ currentPassword, code, recoveryCode }) }),
  me: () => request<Principal>("/v1/me"),
  sessions: () => request<Envelope<SessionInfo>>("/v1/sessions"),
  revokeSession: (sessionId: string) => request<void>(`/v1/sessions/${sessionId}`, { method: "DELETE" }),
  revokeOtherSessions: () => request<{ revoked: number }>("/v1/sessions/revoke-others", { method: "POST", body: "{}" }),
  effectiveRole: (resourceType: string, resourceId: string) => request<{ role: Role }>(`/v1/authorization/effective-role?resourceType=${encodeURIComponent(resourceType)}&resourceId=${encodeURIComponent(resourceId)}`),
  discoverOIDC: (email: string) => request<Envelope<{ id: string; name: string }>>(`/v1/auth/sso/discover?email=${encodeURIComponent(email)}`),
  discoverSAML: (email: string) => request<Envelope<{ id: string; name: string }>>(`/v1/auth/saml/discover?email=${encodeURIComponent(email)}`),
  startOIDC: (providerId: string) => request<{ url: string }>(`/v1/auth/sso/${providerId}/start`),
  startSAML: (providerId: string) => request<{ url: string }>(`/v1/auth/saml/${providerId}/start`),
  projects: () => request<Envelope<Project>>("/v1/projects"),
  createProject: (body: { name: string; description: string }) => request<Project>("/v1/projects", { method: "POST", body: JSON.stringify(body) }),
  projectTags: (projectId: string) => request<Envelope<Tag>>(`/v1/projects/${projectId}/tags`),
  setProjectTags: (projectId: string, tagIds: string[]) => request<Envelope<Tag>>(`/v1/projects/${projectId}/tags`, { method: "PUT", body: JSON.stringify({ tagIds }) }),
  environments: (projectId: string) => request<Envelope<Environment>>(`/v1/projects/${projectId}/environments`),
  allEnvironments: () => request<Envelope<Environment>>("/v1/environments"),
  createEnvironment: (projectId: string, name: string, placement?: { clusterId?: string; placementSelector?: Record<string, string>; minimumNodes?: number; minimumNanoCpus?: number; minimumMemoryBytes?: number }) => request<Environment>(`/v1/projects/${projectId}/environments`, { method: "POST", body: JSON.stringify({ name, ...placement }) }),
  services: (environmentId: string) => request<Envelope<Service>>(`/v1/environments/${environmentId}/services`),
  service: (serviceId: string) => request<{ service: Service; routes: Route[]; source: ApplicationSource | null; template: TemplateInstance | null; reconciliation: ServiceReconciliation | null }>(`/v1/services/${serviceId}`),
  tags: () => request<Envelope<Tag>>("/v1/tags"),
  createTag: (name: string, color: string) => request<Tag>("/v1/tags", { method: "POST", body: JSON.stringify({ name, color }) }),
  updateTag: (tagId: string, name: string, color: string) => request<Tag>(`/v1/tags/${tagId}`, { method: "PUT", body: JSON.stringify({ name, color }) }),
  deleteTag: (tagId: string) => request<void>(`/v1/tags/${tagId}`, { method: "DELETE" }),
  serviceTags: (serviceId: string) => request<Envelope<Tag>>(`/v1/services/${serviceId}/tags`),
  setServiceTags: (serviceId: string, tagIds: string[]) => request<Envelope<Tag>>(`/v1/services/${serviceId}/tags`, { method: "PUT", body: JSON.stringify({ tagIds }) }),
  networks: () => request<Envelope<ManagedNetwork>>("/v1/networks"),
  createNetwork: (body: { name: string; driver?: "overlay" | "bridge"; clusterId?: string; internal?: boolean; attachable?: boolean; enableIpv4?: boolean; enableIpv6?: boolean; mtu?: number; ipam?: { subnet?: string; gateway?: string; ipRange?: string }[] }) => request<ManagedNetwork>("/v1/networks", { method: "POST", body: JSON.stringify(body) }),
  retryNetwork: (networkId: string) => request<ManagedNetwork>(`/v1/networks/${networkId}/retry`, { method: "POST", body: "{}" }),
  deleteNetwork: (networkId: string) => request<void>(`/v1/networks/${networkId}`, { method: "DELETE" }),
  serviceNetworks: (serviceId: string) => request<Envelope<ManagedNetwork>>(`/v1/services/${serviceId}/networks`),
  setServiceNetworks: (serviceId: string, networkIds: string[]) => request<Envelope<ManagedNetwork>>(`/v1/services/${serviceId}/networks`, { method: "PUT", body: JSON.stringify({ networkIds }) }),
  templateVersions: (serviceId: string) => request<{ current: TemplateInstance; items: Template[] }>(`/v1/services/${serviceId}/template-versions`),
  upgradeTemplate: (serviceId: string, body: { templateId: string; allowDrift: boolean; variables: Record<string, string> }) => request<{ service: Service }>(`/v1/services/${serviceId}/template-upgrades`, { method: "POST", body: JSON.stringify(body) }),
  createService: (environmentId: string, body: { name: string; composeYaml: string }) => request<Service>(`/v1/environments/${environmentId}/services`, { method: "POST", body: JSON.stringify(body) }),
  updateService: (serviceId: string, composeYaml: string) => request<Service>(`/v1/services/${serviceId}`, { method: "PATCH", body: JSON.stringify({ composeYaml }) }),
  moveService: (serviceId: string, environmentId: string) => request<Service>(`/v1/services/${serviceId}/environment`, { method: "PUT", body: JSON.stringify({ environmentId }) }),
  serviceVariables: (serviceId: string) => request<ServiceVariableList>(`/v1/services/${serviceId}/variables`),
  putServiceVariables: (serviceId: string, values: Record<string, string>) => request<ServiceVariableList>(`/v1/services/${serviceId}/variables`, { method: "PUT", body: JSON.stringify({ values }) }),
  deleteServiceVariable: (serviceId: string, name: string) => request<void>(`/v1/services/${serviceId}/variables/${name}`, { method: "DELETE" }),
  customTLSCertificates: () => request<Envelope<CustomTLSCertificate>>("/v1/custom-tls-certificates"),
  createCustomTLSCertificate: (body: { name: string; certificatePem: string; privateKeyPem: string }) => request<CustomTLSCertificate>("/v1/custom-tls-certificates", { method: "POST", body: JSON.stringify(body) }),
  updateCustomTLSCertificate: (id: string, body: { name: string; certificatePem: string; privateKeyPem: string; revision: number }) => request<CustomTLSCertificate>(`/v1/custom-tls-certificates/${id}`, { method: "PUT", body: JSON.stringify(body) }),
  deleteCustomTLSCertificate: (id: string) => request<void>(`/v1/custom-tls-certificates/${id}`, { method: "DELETE" }),
  createRoute: (serviceId: string, body: RouteInput) => request<Route>(`/v1/services/${serviceId}/routes`, { method: "POST", body: JSON.stringify(body) }),
  updateRoute: (routeId: string, body: RouteInput) => request<Route>(`/v1/routes/${routeId}`, { method: "PUT", body: JSON.stringify(body) }),
  deleteRoute: (routeId: string) => request<void>(`/v1/routes/${routeId}`, { method: "DELETE" }),
  routeBasicAuthUsers: (serviceId: string) => request<Envelope<RouteBasicAuthUser>>(`/v1/services/${serviceId}/basic-auth-users`),
  createRouteBasicAuthUser: (serviceId: string, username: string, password: string) => request<RouteBasicAuthUser>(`/v1/services/${serviceId}/basic-auth-users`, { method: "POST", body: JSON.stringify({ username, password }) }),
  updateRouteBasicAuthUser: (serviceId: string, userId: string, username: string, password: string) => request<RouteBasicAuthUser>(`/v1/services/${serviceId}/basic-auth-users/${userId}`, { method: "PUT", body: JSON.stringify({ username, password }) }),
  deleteRouteBasicAuthUser: (serviceId: string, userId: string) => request<void>(`/v1/services/${serviceId}/basic-auth-users/${userId}`, { method: "DELETE" }),
  upsertSource: (serviceId: string, body: { sourceType: "git" | "drop"; repositoryUrl: string; gitRef: string; contextDirectory: string; dockerfile: string; buildType: "dockerfile" | "static" | "nixpacks" | "railpack" | "buildpacks" | "heroku_buildpacks"; builderImage?: string; outputDirectory?: string; buildTarget?: string; enableSubmodules: boolean; buildArguments?: Record<string, string>; buildSecrets?: Record<string, string>; targetService: string; registryImage: string; gitCredentialId?: string; registryCredentialId?: string; statusProvider?: string; statusCredentialId?: string; statusContext?: string }) => request<ApplicationSource>(`/v1/services/${serviceId}/source`, { method: "PUT", body: JSON.stringify(body) }),
  uploadArtifact: (serviceId: string, file: File) => { const body = new FormData(); body.append("file", file); return request<ApplicationArtifact>(`/v1/services/${serviceId}/artifact-source`, { method: "PUT", body }); },
  deploy: (serviceId: string) => request<Deployment>(`/v1/services/${serviceId}/deployments`, { method: "POST", body: "{}" }),
  stopService: (serviceId: string) => request<{ desiredState: "stopped"; jobId?: string; queued: boolean }>(`/v1/services/${serviceId}/stop`, { method: "POST", body: "{}" }),
  startService: (serviceId: string) => request<Deployment>(`/v1/services/${serviceId}/start`, { method: "POST", body: "{}" }),
  deployments: (serviceId: string) => request<Envelope<Deployment>>(`/v1/services/${serviceId}/deployments`),
  serviceSchedules: (serviceId: string) => request<Envelope<ServiceSchedule>>(`/v1/services/${serviceId}/schedules`),
  createServiceSchedule: (serviceId: string, body: ServiceScheduleInput) => request<ServiceSchedule>(`/v1/services/${serviceId}/schedules`, { method: "POST", body: JSON.stringify(body) }),
  updateServiceSchedule: (serviceId: string, scheduleId: string, body: ServiceScheduleInput) => request<ServiceSchedule>(`/v1/services/${serviceId}/schedules/${scheduleId}`, { method: "PUT", body: JSON.stringify(body) }),
  deleteServiceSchedule: (serviceId: string, scheduleId: string) => request<void>(`/v1/services/${serviceId}/schedules/${scheduleId}`, { method: "DELETE" }),
  runServiceSchedule: (serviceId: string, scheduleId: string) => request<ServiceScheduleExecution>(`/v1/services/${serviceId}/schedules/${scheduleId}/executions`, { method: "POST", body: "{}" }),
  serviceScheduleExecutions: (serviceId: string) => request<Envelope<ServiceScheduleExecution>>(`/v1/services/${serviceId}/schedule-executions`),
  cancelServiceScheduleExecution: (serviceId: string, executionId: string) => request<{ id: string; cancelRequested: boolean }>(`/v1/services/${serviceId}/schedule-executions/${executionId}/cancel`, { method: "POST", body: "{}" }),
  deployTokens: (serviceId: string) => request<Envelope<DeployToken>>(`/v1/services/${serviceId}/deploy-tokens`),
  createDeployToken: (serviceId: string, name: string, expiresInDays: number) => request<{ deployToken: DeployToken; token: string; url: string }>(`/v1/services/${serviceId}/deploy-tokens`, { method: "POST", body: JSON.stringify({ name, expiresInDays }) }),
  revokeDeployToken: (serviceId: string, tokenId: string) => request<void>(`/v1/services/${serviceId}/deploy-tokens/${tokenId}`, { method: "DELETE" }),
  logs: (serviceId: string) => request<{ logs: string }>(`/v1/services/${serviceId}/logs`),
  serviceVolumes: (serviceId: string) => request<Envelope<ServiceVolume>>(`/v1/services/${serviceId}/volumes`),
  volumeBackupPolicies: (serviceId: string) => request<Envelope<VolumeBackupPolicy>>(`/v1/services/${serviceId}/volume-backup-policies`),
  putVolumeBackupPolicy: (serviceId: string, volumeName: string, body: { destinationId: string; intervalSeconds: number; retentionCount: number; quiesce: boolean; enabled: boolean }) => request<VolumeBackupPolicy>(`/v1/services/${serviceId}/volume-backup-policies/${encodeURIComponent(volumeName)}`, { method: "PUT", body: JSON.stringify(body) }),
  deleteVolumeBackupPolicy: (serviceId: string, volumeName: string) => request<void>(`/v1/services/${serviceId}/volume-backup-policies/${encodeURIComponent(volumeName)}`, { method: "DELETE" }),
  volumeBackups: (serviceId: string) => request<Envelope<VolumeBackup>>(`/v1/services/${serviceId}/volume-backups`),
  volumeRestores: (serviceId: string) => request<Envelope<VolumeRestore>>(`/v1/services/${serviceId}/volume-restores`),
  backupVolume: (serviceId: string, volumeName: string) => request<VolumeBackup>(`/v1/services/${serviceId}/volume-backups/${encodeURIComponent(volumeName)}`, { method: "POST", body: "{}" }),
  volumeBackup: (backupId: string) => request<VolumeBackup>(`/v1/volume-backups/${backupId}`),
  cancelVolumeBackup: (backupId: string) => request<{ status: string }>(`/v1/volume-backups/${backupId}/cancel`, { method: "POST", body: "{}" }),
  restoreVolumeBackup: (backupId: string, confirm: string) => request<VolumeRestore>(`/v1/volume-backups/${backupId}/restore`, { method: "POST", body: JSON.stringify({ confirm }) }),
  volumeRestore: (restoreId: string) => request<VolumeRestore>(`/v1/volume-restores/${restoreId}`),
  cancelVolumeRestore: (restoreId: string) => request<{ status: string }>(`/v1/volume-restores/${restoreId}/cancel`, { method: "POST", body: "{}" }),
  templates: (cursor = "") => request<PaginatedEnvelope<Template>>(`/v1/templates?limit=100${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`),
  templateRepositories: () => request<Envelope<TemplateRepository>>("/v1/template-repositories"),
  createTemplateRepository: (body: { name: string; slug: string; repositoryUrl: string; gitRef: string; catalogPath: string; trustedPublicKey: string; requireSignature: boolean; credentialId: string; syncIntervalSeconds: number }) => request<TemplateRepository>("/v1/template-repositories", { method: "POST", body: JSON.stringify(body) }),
  updateTemplateRepository: (id: string, body: { trustedPublicKey: string; requireSignature: boolean; credentialId: string; syncIntervalSeconds: number }) => request<void>(`/v1/template-repositories/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  syncTemplateRepository: (id: string) => request<{ status: "queued"; requestedAt: string }>(`/v1/template-repositories/${id}/sync`, { method: "POST", body: "{}" }),
  rotateTemplateRepositoryWebhook: (id: string) => request<{ secret: string; url: string }>(`/v1/template-repositories/${id}/webhook-secret`, { method: "POST", body: "{}" }),
  disableTemplateRepositoryWebhook: (id: string) => request<void>(`/v1/template-repositories/${id}/webhook-secret`, { method: "DELETE" }),
  deleteTemplateRepository: (id: string) => request<void>(`/v1/template-repositories/${id}`, { method: "DELETE" }),
  previewTemplate: (templateId: string, body: { baseDomain: string; variables: Record<string, string> }) => request<{ templateId: string; checksum: string; preview: TemplatePreview }>(`/v1/templates/${templateId}/preview`, { method: "POST", body: JSON.stringify(body) }),
  instantiateTemplate: (templateId: string, body: { environmentId: string; name: string; baseDomain: string; variables: Record<string, string> }) => request<{ service: Service }>(`/v1/templates/${templateId}/instantiate`, { method: "POST", body: JSON.stringify(body) }),
  databaseEngines: () => request<{ items: string[]; backupCapable: string[]; engines: DatabaseEngine[] }>("/v1/database-engines"),
  createDatabase: (environmentId: string, body: { name: string; engine: string; version: string; config: Record<string, unknown> }) => request<{ database: { id: string; name: string }; credentials: Record<string, string>; internalUrl: string }>(`/v1/environments/${environmentId}/databases`, { method: "POST", body: JSON.stringify(body) }),
  databases: (environmentId: string) => request<Envelope<Database>>(`/v1/environments/${environmentId}/databases`),
  rebindDatabaseDriver: (databaseId: string, confirm: string) => request<Database>(`/v1/databases/${databaseId}/driver-rebind`, { method: "POST", body: JSON.stringify({ confirm }) }),
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
  agentUpgrades: () => request<Envelope<ClusterCommand>>("/v1/agent-upgrades?limit=200"),
  createCluster: (body: { name: string; labels: Record<string, string> }) => request<Cluster>("/v1/clusters", { method: "POST", body: JSON.stringify(body) }),
  updateCluster: (id: string, state: string) => request<Cluster>(`/v1/clusters/${id}`, { method: "PATCH", body: JSON.stringify({ state }) }),
  deleteCluster: (id: string) => request<{ status: string }>(`/v1/clusters/${id}`, { method: "DELETE" }),
  createEnrollmentToken: (id: string) => request<{ token: string; expiresAt: string }>(`/v1/clusters/${id}/enrollment-tokens`, { method: "POST", body: "{}" }),
  upgradeAgent: (id: string, image: string) => request<ClusterCommand>(`/v1/clusters/${id}/agent-upgrades`, { method: "POST", body: JSON.stringify({ image }) }),
  cancelAgentUpgrade: (clusterId: string, commandId: string) => request<{ status: string }>(`/v1/clusters/${clusterId}/agent-upgrades/${commandId}`, { method: "DELETE" }),
  sourceCredentials: () => request<Envelope<SourceCredential>>("/v1/source-credentials"),
  createSourceCredential: (body: { kind: string; name: string; server: string; username: string; secret?: string; privateKey?: string; knownHosts?: string }) => request<SourceCredential>("/v1/source-credentials", { method: "POST", body: JSON.stringify(body) }),
  deleteSourceCredential: (id: string) => request<void>(`/v1/source-credentials/${id}`, { method: "DELETE" }),
  backupDestinations: () => request<Envelope<BackupDestination>>("/v1/backup-destinations"),
  createBackupDestination: (body: { name: string; endpoint: string; region: string; bucket: string; prefix: string; useTls: boolean; accessKey: string; secretKey: string; sessionToken?: string }) => request<BackupDestination>("/v1/backup-destinations", { method: "POST", body: JSON.stringify(body) }),
  updateBackupDestination: (id: string, body: { name: string; endpoint: string; region: string; bucket: string; prefix: string; useTls: boolean; accessKey: string; secretKey: string; sessionToken?: string }) => request<BackupDestination>(`/v1/backup-destinations/${id}`, { method: "PUT", body: JSON.stringify(body) }),
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
  beginSAMLCertificateRotation: (id: string) => request<SAMLProvider>(`/v1/sso/saml-providers/${id}/certificate-rotation`, { method: "POST", body: "{}" }),
  promoteSAMLCertificateRotation: (id: string, confirm: string) => request<void>(`/v1/sso/saml-providers/${id}/certificate-rotation/promote`, { method: "POST", body: JSON.stringify({ confirm }) }),
  cancelSAMLCertificateRotation: (id: string) => request<void>(`/v1/sso/saml-providers/${id}/certificate-rotation`, { method: "DELETE" }),
  authSettings: () => request<AuthSettings>("/v1/sso/settings"),
  putAuthSettings: (requireSso: boolean) => request<AuthSettings>("/v1/sso/settings", { method: "PUT", body: JSON.stringify({ requireSso }) }),
  scimTokens: () => request<Envelope<SCIMToken>>("/v1/scim/tokens"),
  createSCIMToken: (name: string, defaultRole: SCIMToken["defaultRole"], expiresInDays: number) => request<{ scimToken: SCIMToken; token: string; baseUrl: string }>("/v1/scim/tokens", { method: "POST", body: JSON.stringify({ name, defaultRole, expiresInDays }) }),
  revokeSCIMToken: (id: string) => request<void>(`/v1/scim/tokens/${id}`, { method: "DELETE" }),
  members: () => request<Envelope<OrganizationMember>>("/v1/members"),
  updateMemberRole: (userId: string, role: Role) => request<OrganizationMember>(`/v1/members/${userId}`, { method: "PATCH", body: JSON.stringify({ role }) }),
  deleteMember: (userId: string) => request<void>(`/v1/members/${userId}`, { method: "DELETE" }),
  invitations: () => request<Envelope<OrganizationInvitation>>("/v1/invitations"),
  createInvitation: (email: string, role: Role, expiresInDays: number) => request<{ invitation: OrganizationInvitation; token: string; acceptUrl: string }>("/v1/invitations", { method: "POST", body: JSON.stringify({ email, role, expiresInDays }) }),
  revokeInvitation: (id: string) => request<void>(`/v1/invitations/${id}`, { method: "DELETE" }),
  acceptInvitation: (token: string, displayName: string, password: string) => request<{ userId: string; organizationId: string; organization: string; email: string; role: Role; requireSso: boolean }>("/v1/invitations/accept", { method: "POST", body: JSON.stringify({ token, displayName, password }) }),
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
  serviceAccounts: () => request<Envelope<ServiceAccount>>("/v1/service-accounts"),
  createServiceAccount: (name: string, role: "admin" | "developer" | "viewer", expiresInDays: number) => request<{ serviceAccount: ServiceAccount; token: string }>("/v1/service-accounts", { method: "POST", body: JSON.stringify({ name, role, expiresInDays }) }),
  createAuditorAccount: (name: string, expiresInDays: number) => request<{ serviceAccount: ServiceAccount; token: string }>("/v1/service-accounts", { method: "POST", body: JSON.stringify({ name, role: "auditor", expiresInDays }) }),
  rotateServiceAccount: (id: string, expiresInDays: number) => request<{ token: string; expiresAt: string }>(`/v1/service-accounts/${id}/rotate`, { method: "POST", body: JSON.stringify({ expiresInDays }) }),
  disableServiceAccount: (id: string) => request<void>(`/v1/service-accounts/${id}`, { method: "DELETE" }),
  aiAuditRuns: () => request<Envelope<AIAuditRun>>("/v1/ai/audit-runs"),
  currentAIAuditFindings: (disposition = "") => request<Envelope<AIAuditFinding>>(`/v1/ai/audit-findings${disposition ? `?disposition=${encodeURIComponent(disposition)}` : ""}`),
  aiAuditFindings: (runId: string) => request<Envelope<AIAuditFinding>>(`/v1/ai/audit-runs/${runId}/findings`),
  updateAIAuditFinding: (findingId: string, disposition: AIAuditFinding["disposition"], note: string) => request<AIAuditFinding>(`/v1/ai/audit-findings/${findingId}`, { method: "PATCH", body: JSON.stringify({ disposition, note }) }),
};
