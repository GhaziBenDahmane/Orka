export type Principal = {
  userId: string;
  organizationId: string;
  email: string;
  organization: string;
  role: "viewer" | "developer" | "admin" | "owner";
};

export type Project = { id: string; name: string; slug: string; description: string };
export type Environment = { id: string; projectId: string; name: string; slug: string; clusterId?: string };
export type Service = { id: string; environmentId: string; name: string; slug: string; revision: number; status: string; composeYaml?: string };
export type Deployment = { id: string; revision: number; status: string; trigger: string; error?: string; output?: string; createdAt: string };
export type Template = { id: string; key: string; version: string; name: string; description: string; source: string };
export type Cluster = { id: string; name: string; slug: string; state: string; agentVersion: string; dockerVersion: string; lastSeenAt?: string };

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
  if (init.body) headers.set("content-type", "application/json");
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

export const api = {
  login: (email: string, password: string) => request<{ token: string }>("/v1/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }),
  logout: () => request<void>("/v1/auth/logout", { method: "POST" }),
  me: () => request<Principal>("/v1/me"),
  discoverOIDC: (email: string) => request<Envelope<{ id: string; name: string }>>(`/v1/auth/sso/discover?email=${encodeURIComponent(email)}`),
  discoverSAML: (email: string) => request<Envelope<{ id: string; name: string }>>(`/v1/auth/saml/discover?email=${encodeURIComponent(email)}`),
  startOIDC: (providerId: string) => request<{ url: string }>(`/v1/auth/sso/${providerId}/start`),
  startSAML: (providerId: string) => request<{ url: string }>(`/v1/auth/saml/${providerId}/start`),
  projects: () => request<Envelope<Project>>("/v1/projects"),
  createProject: (body: { name: string; description: string }) => request<Project>("/v1/projects", { method: "POST", body: JSON.stringify(body) }),
  environments: (projectId: string) => request<Envelope<Environment>>(`/v1/projects/${projectId}/environments`),
  createEnvironment: (projectId: string, name: string) => request<Environment>(`/v1/projects/${projectId}/environments`, { method: "POST", body: JSON.stringify({ name }) }),
  services: (environmentId: string) => request<Envelope<Service>>(`/v1/environments/${environmentId}/services`),
  service: (serviceId: string) => request<{ service: Service; routes: unknown[] }>(`/v1/services/${serviceId}`),
  createService: (environmentId: string, body: { name: string; composeYaml: string }) => request<Service>(`/v1/environments/${environmentId}/services`, { method: "POST", body: JSON.stringify(body) }),
  updateService: (serviceId: string, composeYaml: string) => request<Service>(`/v1/services/${serviceId}`, { method: "PATCH", body: JSON.stringify({ composeYaml, environment: {} }) }),
  deploy: (serviceId: string) => request<Deployment>(`/v1/services/${serviceId}/deployments`, { method: "POST", body: "{}" }),
  deployments: (serviceId: string) => request<Envelope<Deployment>>(`/v1/services/${serviceId}/deployments`),
  logs: (serviceId: string) => request<{ logs: string }>(`/v1/services/${serviceId}/logs`),
  templates: () => request<Envelope<Template>>("/v1/templates"),
  instantiateTemplate: (templateId: string, body: { environmentId: string; name: string; baseDomain: string }) => request<{ service: Service }>(`/v1/templates/${templateId}/instantiate`, { method: "POST", body: JSON.stringify(body) }),
  databaseEngines: () => request<{ items: string[]; backupCapable: string[] }>("/v1/database-engines"),
  createDatabase: (environmentId: string, body: { name: string; engine: string; version: string; config: Record<string, unknown> }) => request<{ database: { id: string; name: string }; credentials: Record<string, string>; internalUrl: string }>(`/v1/environments/${environmentId}/databases`, { method: "POST", body: JSON.stringify(body) }),
  clusters: () => request<Envelope<Cluster>>("/v1/clusters"),
};
