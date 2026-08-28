import { FormEvent, useCallback, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { api, APIError, ApplicationSource, AuditArchive, AuditEvent, BackupDestination, Cluster, Database, Deployment, Environment, NotificationEndpoint, OIDCProvider, Principal, Project, ResourcePolicy, SAMLProvider, Service, SourceCredential, session, Template } from "./api";
import "./styles.css";

const starterCompose = `services:
  web:
    image: traefik/whoami:v1.11
    deploy:
      replicas: 1
`;

function message(error: unknown) {
  return error instanceof APIError || error instanceof Error ? error.message : "Something went wrong";
}

function App() {
  const [principal, setPrincipal] = useState<Principal | null>(null);
  const [checking, setChecking] = useState(Boolean(session.get()));

  useEffect(() => {
    const fragment = new URLSearchParams(window.location.hash.slice(1));
    const callbackToken = fragment.get("session");
    if (callbackToken) {
      session.set(callbackToken);
      history.replaceState(null, "", window.location.pathname + window.location.search);
    }
    if (!session.get()) return;
    api.me().then(setPrincipal).catch(() => session.clear()).finally(() => setChecking(false));
  }, []);

  if (checking) return <div className="center"><div className="spinner" /><span>Opening Dockyard…</span></div>;
  if (!principal) return <Login onLogin={setPrincipal} />;
  return <Console principal={principal} onLogout={() => { session.clear(); setPrincipal(null); }} />;
}

function Login({ onLogin }: { onLogin: (principal: Principal) => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [providers, setProviders] = useState<{ id: string; name: string; kind: "oidc" | "saml" }[]>([]);

  async function submit(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError("");
    try {
      const result = await api.login(email, password);
      session.set(result.token);
      onLogin(await api.me());
    } catch (reason) { setError(message(reason)); session.clear(); }
    finally { setBusy(false); }
  }

  async function discover() {
    setBusy(true); setError("");
    try {
      const [oidc, saml] = await Promise.all([api.discoverOIDC(email), api.discoverSAML(email)]);
      const found = [...oidc.items.map(x => ({ ...x, kind: "oidc" as const })), ...saml.items.map(x => ({ ...x, kind: "saml" as const }))];
      setProviders(found);
      if (!found.length) setError("No identity provider is configured for this email domain");
    } catch (reason) { setError(message(reason)); } finally { setBusy(false); }
  }

  async function start(provider: { id: string; kind: "oidc" | "saml" }) {
    setBusy(true); setError("");
    try { window.location.assign((provider.kind === "oidc" ? await api.startOIDC(provider.id) : await api.startSAML(provider.id)).url); }
    catch (reason) { setError(message(reason)); setBusy(false); }
  }

  return <main className="login-page">
    <section className="brand-panel">
      <div className="brand-mark">D</div>
      <p className="eyebrow">Compose, at fleet scale</p>
      <h1>Your infrastructure.<br />Clearly under control.</h1>
      <p className="lede">A focused control plane for applications and data services running on Docker Swarm.</p>
      <div className="signal"><i /><span>Control plane ready</span></div>
    </section>
    <section className="login-panel">
      <form className="card login-card" onSubmit={submit}>
        <p className="eyebrow">Dockyard Console</p><h2>Welcome back</h2>
        <p className="muted">Sign in with your local administrator account.</p>
        <label>Email<input autoFocus type="email" value={email} onChange={e => setEmail(e.target.value)} required /></label>
        <label>Password<input type="password" value={password} onChange={e => setPassword(e.target.value)} required /></label>
        {error && <p className="error" role="alert">{error}</p>}
        <button className="primary" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
        <div className="divider"><span>or</span></div>
        <button type="button" onClick={discover} disabled={busy || !email}>Continue with SSO</button>
        {providers.map(provider => <button type="button" key={`${provider.kind}-${provider.id}`} onClick={() => start(provider)}>Sign in with {provider.name}</button>)}
        <p className="hint">Enter your work email to discover OIDC and SAML providers.</p>
      </form>
    </section>
  </main>;
}

type View = "workloads" | "templates" | "databases" | "clusters" | "governance" | "audit" | "notifications" | "settings";

function Console({ principal, onLogout }: { principal: Principal; onLogout: () => void }) {
  const [view, setView] = useState<View>("workloads");
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectId, setProjectId] = useState("");
  const [environments, setEnvironments] = useState<Environment[]>([]);
  const [environmentId, setEnvironmentId] = useState("");
  const [services, setServices] = useState<Service[]>([]);
  const [selectedService, setSelectedService] = useState<Service | null>(null);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");

  const loadProjects = useCallback(async () => {
    try {
      const { items } = await api.projects(); setProjects(items);
      setProjectId(current => current || items[0]?.id || "");
    } catch (reason) { setError(message(reason)); }
  }, []);
  useEffect(() => { void loadProjects(); }, [loadProjects]);
  const loadServices = useCallback(async () => {
    if (!environmentId) { setServices([]); return; }
    try { const { items } = await api.services(environmentId); setServices(items); }
    catch (reason) { setError(message(reason)); }
  }, [environmentId]);
  const loadEnvironments = useCallback(async () => {
    if (!projectId) { setEnvironments([]); setEnvironmentId(""); return; }
    try { const { items } = await api.environments(projectId); setEnvironments(items); setEnvironmentId(current => items.some(x => x.id === current) ? current : items[0]?.id ?? ""); }
    catch (reason) { setError(message(reason)); }
  }, [projectId]);
  useEffect(() => { void loadEnvironments(); }, [loadEnvironments]);
  useEffect(() => { setSelectedService(null); void loadServices(); }, [loadServices]);

  async function logout() { try { await api.logout(); } finally { onLogout(); } }
  function flash(text: string) { setNotice(text); setError(""); window.setTimeout(() => setNotice(""), 3500); }

  return <div className="shell">
    <aside>
      <div className="wordmark"><span>D</span> Dockyard</div>
      <nav aria-label="Main navigation">
        <Nav active={view === "workloads"} onClick={() => setView("workloads")} icon="◫">Workloads</Nav>
        <Nav active={view === "templates"} onClick={() => setView("templates")} icon="◇">Templates</Nav>
        <Nav active={view === "databases"} onClick={() => setView("databases")} icon="◉">Databases</Nav>
        {(["admin", "owner"] as string[]).includes(principal.role) && <Nav active={view === "clusters"} onClick={() => setView("clusters")} icon="⌁">Clusters</Nav>}
        {(["admin", "owner"] as string[]).includes(principal.role) && <Nav active={view === "governance"} onClick={() => setView("governance")} icon="◈">Governance</Nav>}
        {(["admin", "owner"] as string[]).includes(principal.role) && <Nav active={view === "audit"} onClick={() => setView("audit")} icon="≡">Audit</Nav>}
        {(["admin", "owner"] as string[]).includes(principal.role) && <Nav active={view === "notifications"} onClick={() => setView("notifications")} icon="◌">Notifications</Nav>}
        {(["admin", "owner"] as string[]).includes(principal.role) && <Nav active={view === "settings"} onClick={() => setView("settings")} icon="⚙">Settings</Nav>}
      </nav>
      <div className="account"><div className="avatar">{principal.email.slice(0, 1).toUpperCase()}</div><div><strong>{principal.email}</strong><small>{principal.role}</small></div><button className="icon-button" onClick={logout} title="Sign out">↪</button></div>
    </aside>
    <main className="content">
      <header><div><p className="eyebrow">Organization workspace</p><h1>{view[0].toUpperCase() + view.slice(1)}</h1></div><div className="live"><i /> Live</div></header>
      {error && <div className="toast error" role="alert">{error}<button onClick={() => setError("")}>×</button></div>}
      {notice && <div className="toast success">{notice}</div>}
      {view === "workloads" && <Workloads {...{ projects, projectId, setProjectId, environments, environmentId, setEnvironmentId, services, selectedService, setSelectedService, reloadProjects: loadProjects, reloadEnvironments: loadEnvironments, reloadServices: loadServices, flash, setError }} />}
      {view === "templates" && <Templates environmentId={environmentId} reloadServices={loadServices} flash={flash} setError={setError} />}
      {view === "databases" && <Databases environmentId={environmentId} canAdmin={(["admin", "owner"] as string[]).includes(principal.role)} flash={flash} setError={setError} />}
      {view === "clusters" && <Clusters flash={flash} setError={setError} />}
      {view === "governance" && <Governance principal={principal} projects={projects} projectId={projectId} environments={environments} environmentId={environmentId} flash={flash} setError={setError} />}
      {view === "audit" && <Audit flash={flash} setError={setError} />}
      {view === "notifications" && <Notifications flash={flash} setError={setError} />}
      {view === "settings" && <Settings flash={flash} setError={setError} />}
    </main>
  </div>;
}

function Nav({ active, onClick, icon, children }: { active: boolean; onClick: () => void; icon: string; children: string }) {
  return <button className={active ? "active" : ""} onClick={onClick}><span>{icon}</span>{children}</button>;
}

type WorkloadProps = {
  projects: Project[]; projectId: string; setProjectId: (id: string) => void;
  environments: Environment[]; environmentId: string; setEnvironmentId: (id: string) => void;
  services: Service[]; selectedService: Service | null; setSelectedService: (item: Service | null) => void;
  reloadProjects: () => Promise<void>; reloadEnvironments: () => Promise<void>; reloadServices: () => Promise<void>; flash: (s: string) => void; setError: (s: string) => void;
};

function Workloads(props: WorkloadProps) {
  const [dialog, setDialog] = useState<"project" | "environment" | "service" | null>(null);
  if (props.selectedService) return <ServiceDetail service={props.selectedService} close={() => { props.setSelectedService(null); void props.reloadServices(); }} setError={props.setError} flash={props.flash} />;
  return <>
    <section className="toolbar card">
      <label>Project<select value={props.projectId} onChange={e => props.setProjectId(e.target.value)}><option value="">Select project</option>{props.projects.map(x => <option key={x.id} value={x.id}>{x.name}</option>)}</select></label>
      <button onClick={() => setDialog("project")}>+ Project</button>
      <label>Environment<select value={props.environmentId} onChange={e => props.setEnvironmentId(e.target.value)} disabled={!props.projectId}><option value="">Select environment</option>{props.environments.map(x => <option key={x.id} value={x.id}>{x.name}</option>)}</select></label>
      <button onClick={() => setDialog("environment")} disabled={!props.projectId}>+ Environment</button>
      <button className="primary push" onClick={() => setDialog("service")} disabled={!props.environmentId}>New service</button>
    </section>
    <section className="section-head"><div><h2>Compose services</h2><p className="muted">Immutable revisions deployed as Swarm stacks.</p></div><span className="count">{props.services.length} total</span></section>
    {props.services.length ? <div className="grid">{props.services.map(service => <button className="card service-card" key={service.id} onClick={() => props.setSelectedService(service)}><div className="service-icon">{service.name.slice(0, 2).toUpperCase()}</div><div><h3>{service.name}</h3><p>{service.slug}</p></div><Status value={service.status || "configured"} /><small>Revision {service.revision}</small><b>Open →</b></button>)}</div> : <Empty title="No services here yet" text="Create a Compose service or instantiate a template to get started." />}
    {dialog && <CreateDialog kind={dialog} projectId={props.projectId} environmentId={props.environmentId} close={() => setDialog(null)} done={async text => { setDialog(null); props.flash(text); if (dialog === "project") await props.reloadProjects(); else if (dialog === "environment") await props.reloadEnvironments(); else await props.reloadServices(); }} setError={props.setError} />}
  </>;
}

function CreateDialog({ kind, projectId, environmentId, close, done, setError }: { kind: "project" | "environment" | "service"; projectId: string; environmentId: string; close: () => void; done: (s: string) => void; setError: (s: string) => void }) {
  const [name, setName] = useState(""); const [description, setDescription] = useState(""); const [composeYaml, setCompose] = useState(starterCompose); const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent) {
    event.preventDefault(); setBusy(true);
    try {
      if (kind === "project") await api.createProject({ name, description });
      else if (kind === "environment") await api.createEnvironment(projectId, name);
      else await api.createService(environmentId, { name, composeYaml });
      done(`${kind[0].toUpperCase() + kind.slice(1)} created`);
    } catch (reason) { setError(message(reason)); } finally { setBusy(false); }
  }
  return <div className="modal-backdrop" onMouseDown={e => e.target === e.currentTarget && close()}><form className="modal card" onSubmit={submit}><div className="modal-head"><div><p className="eyebrow">New resource</p><h2>Create {kind}</h2></div><button type="button" className="icon-button" onClick={close}>×</button></div><label>Name<input autoFocus value={name} onChange={e => setName(e.target.value)} required /></label>{kind === "project" && <label>Description<textarea value={description} onChange={e => setDescription(e.target.value)} /></label>}{kind === "service" && <label>Compose YAML<textarea className="code-input" value={composeYaml} onChange={e => setCompose(e.target.value)} required /></label>}<div className="actions"><button type="button" onClick={close}>Cancel</button><button className="primary" disabled={busy}>{busy ? "Creating…" : "Create"}</button></div></form></div>;
}

type SourceDraft = {
  sourceType: "git" | "drop";
  repositoryUrl: string; gitRef: string; contextDirectory: string; dockerfile: string; buildType: "dockerfile" | "static" | "nixpacks" | "railpack" | "buildpacks" | "heroku_buildpacks"; builderImage: string; outputDirectory: string; buildTarget: string;
  enableSubmodules: boolean; buildArguments: string; buildSecrets: string; targetService: string; registryImage: string;
  gitCredentialId: string; registryCredentialId: string; statusProvider: string; statusCredentialId: string; statusContext: string;
  clearBuildArguments: boolean; clearBuildSecrets: boolean;
};

const emptySourceDraft: SourceDraft = { sourceType: "git", repositoryUrl: "", gitRef: "main", contextDirectory: ".", dockerfile: "Dockerfile", buildType: "dockerfile", builderImage: "", outputDirectory: "dist", buildTarget: "", enableSubmodules: false, buildArguments: "", buildSecrets: "", targetService: "web", registryImage: "", gitCredentialId: "", registryCredentialId: "", statusProvider: "", statusCredentialId: "", statusContext: "dockyard/deploy", clearBuildArguments: false, clearBuildSecrets: false };

function sourceDraft(source: ApplicationSource | null): SourceDraft {
  return source ? { sourceType: source.sourceType || "git", repositoryUrl: source.repositoryUrl, gitRef: source.gitRef, contextDirectory: source.contextDirectory, dockerfile: source.dockerfile, buildType: source.buildType || "dockerfile", builderImage: source.builderImage ?? "", outputDirectory: source.outputDirectory || "dist", buildTarget: source.buildTarget ?? "", enableSubmodules: source.enableSubmodules, buildArguments: "", buildSecrets: "", targetService: source.targetService, registryImage: source.registryImage, gitCredentialId: source.gitCredentialId ?? "", registryCredentialId: source.registryCredentialId ?? "", statusProvider: source.statusProvider ?? "", statusCredentialId: source.statusCredentialId ?? "", statusContext: source.statusContext ?? "dockyard/deploy", clearBuildArguments: false, clearBuildSecrets: false } : { ...emptySourceDraft };
}

function parseBuildValues(value: string, label: string) {
  const result: Record<string, string> = {};
  for (const [offset, raw] of value.split("\n").entries()) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const separator = line.indexOf("=");
    if (separator < 1) throw new Error(`${label} line ${offset + 1} must use NAME=value syntax`);
    const name = line.slice(0, separator).trim();
    if (Object.hasOwn(result, name)) throw new Error(`${label} contains duplicate name ${name}`);
    result[name] = line.slice(separator + 1);
  }
  return result;
}

function ServiceDetail({ service, close, setError, flash }: { service: Service; close: () => void; setError: (s: string) => void; flash: (s: string) => void }) {
  const [item, setItem] = useState(service); const [compose, setCompose] = useState(""); const [source, setSource] = useState<ApplicationSource | null>(null); const [sourceForm, setSourceForm] = useState<SourceDraft>(emptySourceDraft); const [artifactFile, setArtifactFile] = useState<File | null>(null); const [credentials, setCredentials] = useState<SourceCredential[]>([]); const [deployments, setDeployments] = useState<Deployment[]>([]); const [logs, setLogs] = useState(""); const [busy, setBusy] = useState(false);
  const refresh = useCallback(async () => { const [detail, history, credentialResult] = await Promise.all([api.service(service.id), api.deployments(service.id), api.sourceCredentials()]); setItem(detail.service); setCompose(detail.service.composeYaml ?? ""); setSource(detail.source); setSourceForm(sourceDraft(detail.source)); setCredentials(credentialResult.items); setDeployments(history.items); }, [service.id]);
  useEffect(() => { refresh().catch(reason => setError(message(reason))); }, [refresh, setError]);
  async function action(kind: "save" | "deploy" | "logs") { setBusy(true); try { if (kind === "save") { await api.updateService(item.id, compose); flash("New revision saved"); } if (kind === "deploy") { await api.deploy(item.id); flash("Deployment queued"); } if (kind === "logs") setLogs((await api.logs(item.id)).logs); await refresh(); } catch (reason) { setError(message(reason)); } finally { setBusy(false); } }
  async function saveSource(event: FormEvent) {
    event.preventDefault(); setBusy(true);
    try {
	  if (sourceForm.sourceType === "drop" && !artifactFile && !source?.artifact) throw new Error("Select a ZIP archive before saving an uploaded source");
      const buildArguments = sourceForm.buildType === "static" || sourceForm.clearBuildArguments ? {} : sourceForm.buildArguments.trim() ? parseBuildValues(sourceForm.buildArguments, "Build arguments") : undefined;
      const buildSecrets = sourceForm.buildType === "static" || sourceForm.buildType === "nixpacks" || sourceForm.buildType === "buildpacks" || sourceForm.buildType === "heroku_buildpacks" || sourceForm.clearBuildSecrets ? {} : sourceForm.buildSecrets.trim() ? parseBuildValues(sourceForm.buildSecrets, "Build secrets") : undefined;
	  if (sourceForm.sourceType === "drop" && artifactFile) await api.uploadArtifact(item.id, artifactFile);
      await api.upsertSource(item.id, { sourceType: sourceForm.sourceType, repositoryUrl: sourceForm.sourceType === "git" ? sourceForm.repositoryUrl : "", gitRef: sourceForm.gitRef, contextDirectory: sourceForm.contextDirectory, dockerfile: sourceForm.dockerfile, buildType: sourceForm.buildType, builderImage: sourceForm.builderImage || undefined, outputDirectory: sourceForm.buildType === "static" ? sourceForm.outputDirectory : undefined, buildTarget: sourceForm.buildType === "dockerfile" ? sourceForm.buildTarget || undefined : undefined, enableSubmodules: sourceForm.sourceType === "git" && sourceForm.enableSubmodules, buildArguments, buildSecrets, targetService: sourceForm.targetService, registryImage: sourceForm.registryImage, gitCredentialId: sourceForm.sourceType === "git" ? sourceForm.gitCredentialId || undefined : undefined, registryCredentialId: sourceForm.registryCredentialId || undefined, statusProvider: sourceForm.sourceType === "git" ? sourceForm.statusProvider || undefined : undefined, statusCredentialId: sourceForm.sourceType === "git" ? sourceForm.statusCredentialId || undefined : undefined, statusContext: sourceForm.sourceType === "git" ? sourceForm.statusContext || undefined : undefined });
	  setArtifactFile(null);
      await refresh(); flash("Application source saved");
    } catch (reason) { setError(message(reason)); } finally { setBusy(false); }
  }
  return <><button className="back" onClick={close}>← All services</button><section className="detail-title"><div className="service-icon large">{item.name.slice(0, 2).toUpperCase()}</div><div><h2>{item.name}</h2><p className="muted">{item.slug} · revision {item.revision}</p></div><Status value={item.status || "configured"} /><button className="primary push" onClick={() => action("deploy")} disabled={busy}>Deploy revision</button></section><div className="detail-grid"><section className="card editor"><div className="card-head"><h3>Compose definition</h3><button onClick={() => action("save")} disabled={busy}>Save revision</button></div><textarea aria-label="Compose YAML" value={compose} onChange={e => setCompose(e.target.value)} spellCheck={false} /></section><section className="card"><div className="card-head"><h3>Deployments</h3><button onClick={() => refresh()}>Refresh</button></div><div className="timeline">{deployments.length ? deployments.map(d => <article key={d.id}><i className={d.status} /><div><strong>Revision {d.revision}</strong><small>{new Date(d.createdAt).toLocaleString()} · {d.trigger}</small>{d.error && <p className="error">{d.error}</p>}</div><Status value={d.status} /></article>) : <p className="muted">No deployments yet.</p>}</div></section></div>
    <form className="card source-editor" onSubmit={saveSource}><div className="card-head"><div><h3>Application build</h3><p className="muted">Build an immutable image from Git or an uploaded ZIP, then deploy it through the Compose service.</p></div><button className="primary" disabled={busy}>{busy ? "Saving…" : "Save source"}</button></div><div className="source-fields">
      <label>Source type<select value={sourceForm.sourceType} onChange={e => setSourceForm({ ...sourceForm, sourceType: e.target.value as SourceDraft["sourceType"] })}><option value="git">Git repository</option><option value="drop">Uploaded ZIP</option></select></label>
      <label>Build type<select value={sourceForm.buildType} onChange={e => setSourceForm({ ...sourceForm, buildType: e.target.value as SourceDraft["buildType"], builderImage: "", buildTarget: "", buildArguments: "", buildSecrets: "", clearBuildArguments: false, clearBuildSecrets: false })}><option value="dockerfile">Dockerfile</option><option value="nixpacks">Nixpacks</option><option value="railpack">Railpack</option><option value="buildpacks">Paketo buildpacks</option><option value="heroku_buildpacks">Heroku Buildpacks</option><option value="static">Static files</option></select></label>
      {sourceForm.sourceType === "git" ? <><label className="wide">Repository URL<input type="url" value={sourceForm.repositoryUrl} onChange={e => setSourceForm({ ...sourceForm, repositoryUrl: e.target.value })} placeholder="https://github.com/acme/app.git" required /></label><label>Git ref<input value={sourceForm.gitRef} onChange={e => setSourceForm({ ...sourceForm, gitRef: e.target.value })} placeholder="main" /></label><label>Git credential<select value={sourceForm.gitCredentialId} onChange={e => setSourceForm({ ...sourceForm, gitCredentialId: e.target.value })}><option value="">Public repository</option>{credentials.filter(x => x.kind === "git" || x.kind === "git-ssh").map(x => <option key={x.id} value={x.id}>{x.name} · {x.server}</option>)}</select></label></> : <label className="wide">Source ZIP <span>{source?.artifact ? `${source.artifact.filename} · ${(source.artifact.compressedSize / 1048576).toFixed(1)} MiB · SHA-256 ${source.artifact.sha256.slice(0, 12)}…` : "Maximum 25 MiB compressed and 250 MiB expanded."}</span><input type="file" accept=".zip,application/zip" onChange={e => setArtifactFile(e.target.files?.[0] ?? null)} required={!source?.artifact} /></label>}
      <label>Context directory<input value={sourceForm.contextDirectory} onChange={e => setSourceForm({ ...sourceForm, contextDirectory: e.target.value })} placeholder="." /></label>{sourceForm.buildType === "dockerfile" ? <><label>Dockerfile<input value={sourceForm.dockerfile} onChange={e => setSourceForm({ ...sourceForm, dockerfile: e.target.value })} placeholder="Dockerfile" /></label><label>Target stage<input value={sourceForm.buildTarget} onChange={e => setSourceForm({ ...sourceForm, buildTarget: e.target.value })} placeholder="runtime (optional)" /></label></> : sourceForm.buildType === "static" ? <label className="wide">Static output directory<input value={sourceForm.outputDirectory} onChange={e => setSourceForm({ ...sourceForm, outputDirectory: e.target.value })} placeholder="dist" required /></label> : null}{(sourceForm.buildType === "buildpacks" || sourceForm.buildType === "heroku_buildpacks") && <label className="wide">Custom builder image <span>Optional. Must include an immutable @sha256 digest; the default {sourceForm.buildType === "heroku_buildpacks" ? "Heroku 24" : "Paketo Jammy base"} builder is already pinned.</span><input value={sourceForm.builderImage} onChange={e => setSourceForm({ ...sourceForm, builderImage: e.target.value })} placeholder="registry.example.com/builders/custom:v1@sha256:…" /></label>}<label>Compose target service<input value={sourceForm.targetService} onChange={e => setSourceForm({ ...sourceForm, targetService: e.target.value })} placeholder="web" required /></label><label className="wide">Registry image<input value={sourceForm.registryImage} onChange={e => setSourceForm({ ...sourceForm, registryImage: e.target.value })} placeholder="registry.example.com/team/app" required /></label><label>Registry credential<select value={sourceForm.registryCredentialId} onChange={e => setSourceForm({ ...sourceForm, registryCredentialId: e.target.value })}><option value="">Anonymous push</option>{credentials.filter(x => x.kind === "registry").map(x => <option key={x.id} value={x.id}>{x.name} · {x.server}</option>)}</select></label>{sourceForm.sourceType === "git" && <label className="check wide"><input type="checkbox" checked={sourceForm.enableSubmodules} onChange={e => setSourceForm({ ...sourceForm, enableSubmodules: e.target.checked })} /> Clone same-origin Git submodules recursively</label>}
      {sourceForm.buildType === "dockerfile" && <><label className="build-values">Build arguments <span>{source?.hasBuildArguments ? "Configured values are hidden; leave blank to preserve them." : "One NAME=value entry per line."}</span><textarea className="compact-code" value={sourceForm.buildArguments} disabled={sourceForm.clearBuildArguments} onChange={e => setSourceForm({ ...sourceForm, buildArguments: e.target.value })} placeholder="GO_VERSION=1.26" spellCheck={false} /></label><label className="build-values">BuildKit secrets <span>{source?.hasBuildSecrets ? "Configured values are hidden; leave blank to preserve them." : "Values are encrypted and never returned."}</span><textarea className="compact-code" value={sourceForm.buildSecrets} disabled={sourceForm.clearBuildSecrets} onChange={e => setSourceForm({ ...sourceForm, buildSecrets: e.target.value })} placeholder="NPM_TOKEN=…" spellCheck={false} /></label>
      {source?.hasBuildArguments && <label className="check clear-setting"><input type="checkbox" checked={sourceForm.clearBuildArguments} onChange={e => setSourceForm({ ...sourceForm, clearBuildArguments: e.target.checked, buildArguments: "" })} /> Clear configured build arguments</label>}{source?.hasBuildSecrets && <label className="check clear-setting"><input type="checkbox" checked={sourceForm.clearBuildSecrets} onChange={e => setSourceForm({ ...sourceForm, clearBuildSecrets: e.target.checked, buildSecrets: "" })} /> Clear configured build secrets</label>}</>}
      {(sourceForm.buildType === "nixpacks" || sourceForm.buildType === "buildpacks" || sourceForm.buildType === "heroku_buildpacks") && <label className="build-values wide">Build environment <span>Non-secret NAME=value entries passed to {sourceForm.buildType === "nixpacks" ? "Nixpacks" : sourceForm.buildType === "heroku_buildpacks" ? "Heroku Buildpacks" : "Paketo buildpacks"}; values may enter image metadata.</span><textarea className="compact-code" value={sourceForm.buildArguments} onChange={e => setSourceForm({ ...sourceForm, buildArguments: e.target.value })} placeholder="NODE_VERSION=24" spellCheck={false} /></label>}
      {sourceForm.buildType === "railpack" && <><label className="build-values">Build environment <span>{source?.hasBuildArguments ? "Configured values are hidden; leave blank to preserve them." : "Non-secret NAME=value entries."}</span><textarea className="compact-code" value={sourceForm.buildArguments} disabled={sourceForm.clearBuildArguments} onChange={e => setSourceForm({ ...sourceForm, buildArguments: e.target.value })} placeholder="NODE_VERSION=24" spellCheck={false} /></label><label className="build-values">BuildKit secrets <span>{source?.hasBuildSecrets ? "Configured values are hidden; leave blank to preserve them." : "Mounted only during Railpack build steps."}</span><textarea className="compact-code" value={sourceForm.buildSecrets} disabled={sourceForm.clearBuildSecrets} onChange={e => setSourceForm({ ...sourceForm, buildSecrets: e.target.value })} placeholder="NPM_TOKEN=…" spellCheck={false} /></label>{source?.hasBuildArguments && <label className="check clear-setting"><input type="checkbox" checked={sourceForm.clearBuildArguments} onChange={e => setSourceForm({ ...sourceForm, clearBuildArguments: e.target.checked, buildArguments: "" })} /> Clear configured build environment</label>}{source?.hasBuildSecrets && <label className="check clear-setting"><input type="checkbox" checked={sourceForm.clearBuildSecrets} onChange={e => setSourceForm({ ...sourceForm, clearBuildSecrets: e.target.checked, buildSecrets: "" })} /> Clear configured build secrets</label>}</>}
      {sourceForm.sourceType === "git" && <fieldset className="status-settings"><legend>Commit status callback (optional)</legend><label>Provider<select value={sourceForm.statusProvider} onChange={e => setSourceForm({ ...sourceForm, statusProvider: e.target.value, statusCredentialId: e.target.value ? sourceForm.statusCredentialId : "" })}><option value="">Disabled</option><option value="github">GitHub</option><option value="gitlab">GitLab</option><option value="gitea">Gitea</option><option value="bitbucket">Bitbucket</option></select></label><label>Provider token<select value={sourceForm.statusCredentialId} disabled={!sourceForm.statusProvider} required={Boolean(sourceForm.statusProvider)} onChange={e => setSourceForm({ ...sourceForm, statusCredentialId: e.target.value })}><option value="">Select credential</option>{credentials.filter(x => x.kind === "git").map(x => <option key={x.id} value={x.id}>{x.name} · {x.server}</option>)}</select></label><label>Status context<input value={sourceForm.statusContext} disabled={!sourceForm.statusProvider} onChange={e => setSourceForm({ ...sourceForm, statusContext: e.target.value })} placeholder="dockyard/deploy" /></label></fieldset>}
    </div></form><section className="card logs"><div className="card-head"><h3>Service logs</h3><button onClick={() => action("logs")}>Load logs</button></div><pre>{logs || "Logs are loaded on demand to avoid unnecessary manager traffic."}</pre></section></>;
}

function Templates({ environmentId, reloadServices, flash, setError }: { environmentId: string; reloadServices: () => Promise<void>; flash: (s: string) => void; setError: (s: string) => void }) {
  const [items, setItems] = useState<Template[]>([]); const [query, setQuery] = useState("");
  useEffect(() => { api.templates().then(x => setItems(x.items)).catch(reason => setError(message(reason))); }, [setError]);
  async function instantiate(template: Template) { if (!environmentId) { setError("Select an environment under Workloads first"); return; } const name = window.prompt("Service name", template.name); if (!name) return; const baseDomain = window.prompt("Base domain", "example.com"); if (!baseDomain) return; try { await api.instantiateTemplate(template.id, { environmentId, name, baseDomain }); await reloadServices(); flash(`${template.name} instantiated`); } catch (reason) { setError(message(reason)); } }
  const filtered = items.filter(x => `${x.name} ${x.description}`.toLowerCase().includes(query.toLowerCase()));
  return <><section className="toolbar card"><label className="grow">Search catalog<input placeholder="Postgres, analytics, monitoring…" value={query} onChange={e => setQuery(e.target.value)} /></label><span className="count">{filtered.length} templates</span></section><div className="grid template-grid">{filtered.map(x => <article className="card template-card" key={x.id}><span className="tag">{x.source}</span><h3>{x.name}</h3><p>{x.description || "Deploy this application from the shared catalog."}</p><small>{x.key} · {x.version}</small><button onClick={() => instantiate(x)}>Use template →</button></article>)}</div></>;
}

function Databases({ environmentId, canAdmin, flash, setError }: { environmentId: string; canAdmin: boolean; flash: (s: string) => void; setError: (s: string) => void }) {
  const [engines, setEngines] = useState<string[]>([]); const [backup, setBackup] = useState<string[]>([]); const [items, setItems] = useState<Database[]>([]); const [destinations, setDestinations] = useState<BackupDestination[]>([]); const [name, setName] = useState(""); const [engine, setEngine] = useState(""); const [result, setResult] = useState<{ credentials: Record<string, string>; internalUrl: string } | null>(null); const [selected, setSelected] = useState(""); const [interval, setInterval] = useState(86400); const [retention, setRetention] = useState(14); const [destinationId, setDestinationId] = useState(""); const [verifyRestore, setVerifyRestore] = useState(true);
  useEffect(() => { api.databaseEngines().then(x => { setEngines(x.items); setBackup(x.backupCapable); setEngine(x.items[0] ?? ""); }).catch(reason => setError(message(reason))); }, [setError]);
  const reload = useCallback(async () => { if (!environmentId) { setItems([]); return; } const response = await api.databases(environmentId); setItems(response.items); }, [environmentId]);
  useEffect(() => { void reload().catch(reason => setError(message(reason))); }, [reload, setError]);
  useEffect(() => { const eligible = items.filter(x => backup.includes(x.engine)); setSelected(current => eligible.some(x => x.id === current) ? current : eligible[0]?.id ?? ""); }, [items, backup]);
  useEffect(() => { if (canAdmin) void api.backupDestinations().then(x => setDestinations(x.items)).catch(reason => setError(message(reason))); }, [canAdmin, setError]);
  useEffect(() => { if (!selected || !canAdmin) return; api.backupPolicy(selected).then(policy => { setInterval(policy.intervalSeconds); setRetention(policy.retentionCount); setDestinationId(policy.destinationId ?? ""); setVerifyRestore(policy.verifyRestore); }).catch(reason => { if (reason instanceof APIError && reason.status === 404) { setInterval(86400); setRetention(14); setDestinationId(""); setVerifyRestore(true); } else setError(message(reason)); }); }, [selected, canAdmin, setError]);
  async function submit(event: FormEvent) { event.preventDefault(); if (!environmentId) return setError("Select an environment under Workloads first"); try { const created = await api.createDatabase(environmentId, { name, engine, version: "", config: {} }); setResult(created); await reload(); flash("Database provision queued"); } catch (reason) { setError(message(reason)); } }
  async function act(action: () => Promise<unknown>, success: string) { try { await action(); await reload(); flash(success); } catch (reason) { setError(message(reason)); } }
  return <><div className="database-layout"><form className="card database-form" onSubmit={submit}><p className="eyebrow">Managed service</p><h2>Create database</h2><p className="muted">Credentials are revealed once. Store them before leaving this screen.</p><label>Name<input value={name} onChange={e => setName(e.target.value)} required /></label><label>Engine<select value={engine} onChange={e => setEngine(e.target.value)}>{engines.map(x => <option key={x}>{x}</option>)}</select></label>{engine && <p className="capability">{backup.includes(engine) ? "✓ Native backups supported" : "Backups not yet supported for this engine"}</p>}<button className="primary" disabled={!engine}>Create database</button></form>{result ? <section className="card credential-card"><p className="eyebrow">Save now</p><h2>Connection details</h2><code>{result.internalUrl}</code>{Object.entries(result.credentials).map(([key, value]) => <div className="secret" key={key}><span>{key}</span><code>{value}</code></div>)}</section> : <Empty title="One-time credentials" text="New database connection details will appear here exactly once." />}</div>
    <section className="section-head spaced"><div><h2>Managed databases</h2><p className="muted">Backup, retention, and lifecycle controls.</p></div><span className="count">{items.length} total</span></section>
    <div className="grid">{items.map(item => <article className="card database-card" key={item.id}><div><h3>{item.name}</h3><p>{item.engine}:{item.version} · {item.slug}</p></div><Status value={item.status} /><div className="actions"><button disabled={!backup.includes(item.engine)} onClick={() => void act(() => api.backupDatabase(item.id, destinationId || undefined), "Backup queued")}>Back up now</button>{canAdmin && <button className="danger-button" onClick={() => window.confirm(`Delete ${item.name} and its stack?`) && void act(() => api.deleteDatabase(item.id), "Database deletion queued")}>Delete</button>}</div></article>)}</div>
    {canAdmin && selected && <form className="card policy-form" onSubmit={event => { event.preventDefault(); void act(() => api.putBackupPolicy(selected, { intervalSeconds: interval, retentionCount: retention, enabled: true, verifyRestore, destinationId: destinationId || undefined }), "Backup policy saved"); }}><div><p className="eyebrow">Scheduled protection</p><h2>Backup policy</h2></div><label>Database<select value={selected} onChange={e => setSelected(e.target.value)}>{items.filter(x => backup.includes(x.engine)).map(x => <option key={x.id} value={x.id}>{x.name}</option>)}</select></label><label>Interval (seconds)<input type="number" min="900" max="2678400" value={interval} onChange={e => setInterval(Number(e.target.value))} /></label><label>Retain<input type="number" min="1" max="100" value={retention} onChange={e => setRetention(Number(e.target.value))} /></label><label>Destination<select value={destinationId} onChange={e => setDestinationId(e.target.value)}><option value="">Controller storage</option>{destinations.map(x => <option key={x.id} value={x.id}>{x.name}</option>)}</select></label><label className="check"><input type="checkbox" checked={verifyRestore} onChange={e => setVerifyRestore(e.target.checked)} /> Verify each scheduled backup with a restore drill</label><button className="primary">Save policy</button></form>}
  </>;
}

function Clusters({ flash, setError }: { flash: (s: string) => void; setError: (s: string) => void }) {
  const [items, setItems] = useState<Cluster[]>([]);
  const [name, setName] = useState(""); const [labels, setLabels] = useState(""); const [upgradeImages, setUpgradeImages] = useState<Record<string, string>>({}); const [enrollment, setEnrollment] = useState<{ cluster: string; token: string; expiresAt: string } | null>(null); const [busy, setBusy] = useState(false);
  const refresh = useCallback(async () => setItems((await api.clusters()).items), []);
  useEffect(() => { refresh().catch(reason => setError(message(reason))); }, [refresh, setError]);
  async function run(action: () => Promise<unknown>, success: string) { setBusy(true); try { await action(); await refresh(); flash(success); return true; } catch (reason) { setError(message(reason)); return false; } finally { setBusy(false); } }
  function parsedLabels() { return Object.fromEntries(labels.split(",").map(x => x.trim()).filter(Boolean).map(pair => { const index = pair.indexOf("="); if (index < 1 || index === pair.length - 1) throw new Error("Labels must use key=value syntax"); return [pair.slice(0, index).trim(), pair.slice(index + 1).trim()]; })); }
  async function create(event: FormEvent) { event.preventDefault(); try { if (await run(() => api.createCluster({ name, labels: parsedLabels() }), "Cluster registered")) { setName(""); setLabels(""); } } catch (reason) { setError(message(reason)); } }
  async function issueToken(cluster: Cluster) { setBusy(true); try { const result = await api.createEnrollmentToken(cluster.id); setEnrollment({ cluster: cluster.name, ...result }); flash("One-time enrollment token issued"); } catch (reason) { setError(message(reason)); } finally { setBusy(false); } }
  return <><section className="section-head"><div><h2>Swarm clusters</h2><p className="muted">Outbound TLS 1.3 mTLS agents and capacity-aware placement.</p></div></section><form className="card cluster-create" onSubmit={create}><label>Name<input value={name} onChange={e => setName(e.target.value)} placeholder="Paris production" required /></label><label>Placement labels<input value={labels} onChange={e => setLabels(e.target.value)} placeholder="region=eu-west,tier=production" /></label><button className="primary" disabled={busy}>Register cluster</button></form>
    {enrollment && <section className="card credential-card enrollment"><p className="eyebrow">Save now · expires {new Date(enrollment.expiresAt).toLocaleString()}</p><h2>Enroll {enrollment.cluster}</h2><p className="muted">Pass this one-time token to the agent as <code>DOCKYARD_AGENT_ENROLLMENT_TOKEN</code>. It is never shown again.</p><code>{enrollment.token}</code><button onClick={() => navigator.clipboard.writeText(enrollment.token)}>Copy token</button></section>}
    <div className="grid spaced">{items.map(x => <article className="card cluster-card" key={x.id}><div className="cluster-top"><div className="service-icon">SW</div><Status value={x.state} /></div><h3>{x.name}</h3><p>{x.slug}{Object.keys(x.labels ?? {}).length ? ` · ${Object.entries(x.labels).map(([key, value]) => `${key}=${String(value)}`).join(", ")}` : ""}</p><dl><div><dt>Agent</dt><dd>{x.agentVersion || "Not connected"}</dd></div><div><dt>Docker</dt><dd>{x.dockerVersion || "—"}</dd></div><div><dt>Last seen</dt><dd>{x.lastSeenAt ? new Date(x.lastSeenAt).toLocaleString() : "Never"}</dd></div><div><dt>Certificate</dt><dd>{x.certificateNotAfter ? new Date(x.certificateNotAfter).toLocaleDateString() : "Not enrolled"}</dd></div></dl><div className="actions"><button disabled={busy} onClick={() => void issueToken(x)}>Enroll</button><button disabled={busy} onClick={() => void run(() => api.updateCluster(x.id, x.state === "active" ? "draining" : "active"), x.state === "active" ? "Cluster draining" : "Cluster activated")}>{x.state === "active" ? "Drain" : "Activate"}</button><button className="danger-button" disabled={busy} onClick={() => window.confirm(`Delete ${x.name}? Assigned environments must be moved first.`) && void run(() => api.deleteCluster(x.id), "Cluster deletion queued")}>Delete</button></div><form className="upgrade-form" onSubmit={event => { event.preventDefault(); void run(() => api.upgradeAgent(x.id, upgradeImages[x.id] ?? ""), "Digest-pinned agent upgrade queued"); }}><label>Agent image digest<input value={upgradeImages[x.id] ?? ""} onChange={e => setUpgradeImages({ ...upgradeImages, [x.id]: e.target.value })} placeholder="registry.example/dockyard@sha256:…" required /></label><button disabled={busy || x.state !== "active"}>Upgrade</button></form></article>)}</div>{!items.length && <Empty title="No remote clusters" text="The controller can still deploy to its local Swarm. Register a cluster and issue a one-time token to enroll its outbound agent." />}</>;
}

type PolicyScope = "organization" | "project" | "environment";
type PolicyDraft = { maintenance: boolean; maintenanceReason: string; maxProjects: string; maxEnvironments: string; maxServices: string; maxDatabases: string };

const emptyPolicy: PolicyDraft = { maintenance: false, maintenanceReason: "", maxProjects: "", maxEnvironments: "", maxServices: "", maxDatabases: "" };

function Governance({ principal, projects, projectId, environments, environmentId, flash, setError }: { principal: Principal; projects: Project[]; projectId: string; environments: Environment[]; environmentId: string; flash: (s: string) => void; setError: (s: string) => void }) {
  const [scope, setScope] = useState<PolicyScope>("organization");
  const [draft, setDraft] = useState<PolicyDraft>(emptyPolicy);
  const [requireSso, setRequireSso] = useState(false);
  const [busy, setBusy] = useState(false);
  const scopeId = scope === "organization" ? principal.organizationId : scope === "project" ? projectId : environmentId;

  const applyPolicy = (item: ResourcePolicy) => setDraft({ maintenance: item.maintenance, maintenanceReason: item.maintenanceReason, maxProjects: item.maxProjects?.toString() ?? "", maxEnvironments: item.maxEnvironments?.toString() ?? "", maxServices: item.maxServices?.toString() ?? "", maxDatabases: item.maxDatabases?.toString() ?? "" });
  useEffect(() => { api.authSettings().then(x => setRequireSso(x.requireSso)).catch(reason => setError(message(reason))); }, [setError]);
  useEffect(() => {
    if (!scopeId) { setDraft(emptyPolicy); return; }
    api.policy(scope, scopeId).then(applyPolicy).catch(reason => setError(message(reason)));
  }, [scope, scopeId, setError]);
  const limit = (value: string) => value.trim() ? Number(value) : null;
  async function savePolicy(event: FormEvent) {
    event.preventDefault(); setBusy(true);
    try {
      const item = await api.putPolicy(scope, scopeId, { maintenance: draft.maintenance, maintenanceReason: draft.maintenanceReason, maxProjects: limit(draft.maxProjects), maxEnvironments: limit(draft.maxEnvironments), maxServices: limit(draft.maxServices), maxDatabases: limit(draft.maxDatabases) });
      applyPolicy(item); flash(`${scope} policy saved`);
    } catch (reason) { setError(message(reason)); } finally { setBusy(false); }
  }
  return <div className="settings-grid">
    <section className="card settings-card"><p className="eyebrow">Resource guardrails</p><h2>Policy and quotas</h2><form onSubmit={savePolicy}>
      <label>Scope<select value={scope} onChange={e => setScope(e.target.value as PolicyScope)}><option value="organization">Organization · {principal.organization}</option><option value="project" disabled={!projectId}>Project · {projects.find(x => x.id === projectId)?.name ?? "select under Workloads"}</option><option value="environment" disabled={!environmentId}>Environment · {environments.find(x => x.id === environmentId)?.name ?? "select under Workloads"}</option></select></label>
      <label className="check"><input type="checkbox" checked={draft.maintenance} onChange={e => setDraft({ ...draft, maintenance: e.target.checked })} /> Block mutations for maintenance</label>
      <label>Maintenance reason<textarea value={draft.maintenanceReason} maxLength={500} onChange={e => setDraft({ ...draft, maintenanceReason: e.target.value })} /></label>
      <div className="field-row">{scope === "organization" && <label>Maximum projects<input type="number" min="1" max="1000000" placeholder="Unlimited" value={draft.maxProjects} onChange={e => setDraft({ ...draft, maxProjects: e.target.value })} /></label>} {scope !== "environment" && <label>Maximum environments<input type="number" min="1" max="1000000" placeholder="Unlimited" value={draft.maxEnvironments} onChange={e => setDraft({ ...draft, maxEnvironments: e.target.value })} /></label>}</div>
      <div className="field-row"><label>Maximum services<input type="number" min="1" max="1000000" placeholder="Unlimited" value={draft.maxServices} onChange={e => setDraft({ ...draft, maxServices: e.target.value })} /></label><label>Maximum databases<input type="number" min="1" max="1000000" placeholder="Unlimited" value={draft.maxDatabases} onChange={e => setDraft({ ...draft, maxDatabases: e.target.value })} /></label></div>
      <button className="primary" disabled={busy || !scopeId}>Save policy</button>
    </form></section>
    <section className="card settings-card"><p className="eyebrow">Authentication policy</p><h2>Mandatory SSO</h2><p className="muted">Require interactive users to authenticate through an enabled OIDC or SAML provider. Existing local sessions are revoked except for the owner break-glass account.</p><label className="check"><input type="checkbox" checked={requireSso} onChange={e => setRequireSso(e.target.checked)} /> Require SSO for this organization</label><button className="primary spaced-button" disabled={busy} onClick={() => { setBusy(true); api.putAuthSettings(requireSso).then(() => flash("Authentication policy saved")).catch(reason => setError(message(reason))).finally(() => setBusy(false)); }}>Save authentication policy</button></section>
  </div>;
}

function Audit({ flash, setError }: { flash: (s: string) => void; setError: (s: string) => void }) {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [retention, setRetention] = useState(365);
  const [archives, setArchives] = useState<AuditArchive[]>([]);
  const [destinations, setDestinations] = useState<BackupDestination[]>([]);
  const [archive, setArchive] = useState({ name: "", backupDestinationId: "", objectPrefix: "audit", retentionDays: 365 });
  const [busy, setBusy] = useState(false);
  const refresh = useCallback(async () => {
    const [eventResult, retentionResult, archiveResult, destinationResult] = await Promise.all([api.auditEvents(), api.auditRetention(), api.auditArchives(), api.backupDestinations()]);
    setEvents(eventResult.items); setRetention(retentionResult.retentionDays); setArchives(archiveResult.items); setDestinations(destinationResult.items.filter(x => x.useTls));
  }, []);
  useEffect(() => { refresh().catch(reason => setError(message(reason))); }, [refresh, setError]);
  async function run(action: () => Promise<unknown>, success: string) { setBusy(true); try { await action(); await refresh(); flash(success); } catch (reason) { setError(message(reason)); } finally { setBusy(false); } }
  async function exportEvents() {
    try { const file = await api.exportAudit(); const href = URL.createObjectURL(file.blob); const anchor = document.createElement("a"); anchor.href = href; anchor.download = file.filename; anchor.click(); URL.revokeObjectURL(href); flash(file.sha256 ? `Audit export downloaded · SHA-256 ${file.sha256.slice(0, 12)}…` : "Audit export downloaded"); } catch (reason) { setError(message(reason)); }
  }
  return <>
    <section className="toolbar card"><label>Retention (days)<input type="number" min="30" max="3650" value={retention} onChange={e => setRetention(Number(e.target.value))} /></label><button className="primary" disabled={busy} onClick={() => void run(() => api.putAuditRetention(retention), "Audit retention saved")}>Save retention</button><button className="push" onClick={() => void exportEvents()}>Export NDJSON</button></section>
    <section className="section-head"><div><h2>Audit events</h2><p className="muted">Tenant-scoped actions from users and service accounts.</p></div><span className="count">{events.length} loaded</span></section>
    <section className="card audit-table"><div className="table-scroll"><table><thead><tr><th>Time</th><th>Action</th><th>Resource</th><th>Actor</th><th>Origin</th></tr></thead><tbody>{events.map(event => <tr key={event.id}><td>{new Date(event.createdAt).toLocaleString()}</td><td><code>{event.action}</code></td><td>{event.resourceType}<small>{event.resourceId || "—"}</small></td><td>{event.actorUserId?.slice(0, 8) ?? event.actorServiceAccountId?.slice(0, 8) ?? "system"}</td><td>{event.remoteAddr || "—"}</td></tr>)}</tbody></table></div>{!events.length && <p className="muted padded">No audit events yet.</p>} {events.length > 0 && <button className="load-more" onClick={() => api.auditEvents(events[events.length - 1].id).then(x => setEvents([...events, ...x.items])).catch(reason => setError(message(reason)))}>Load older events</button>}</section>
    <section className="section-head spaced"><div><h2>Immutable archives</h2><p className="muted">Hash-chained batches stored in an S3 Object Lock bucket.</p></div></section>
    <form className="card policy-form archive-form" onSubmit={event => { event.preventDefault(); void run(() => api.createAuditArchive(archive), "Audit archive verified and enabled"); }}><label>Name<input value={archive.name} onChange={e => setArchive({ ...archive, name: e.target.value })} required /></label><label>Destination<select value={archive.backupDestinationId} onChange={e => setArchive({ ...archive, backupDestinationId: e.target.value })} required><option value="">Select TLS destination</option>{destinations.map(x => <option key={x.id} value={x.id}>{x.name}</option>)}</select></label><label>Object prefix<input value={archive.objectPrefix} onChange={e => setArchive({ ...archive, objectPrefix: e.target.value })} required /></label><label>Retention days<input type="number" min="30" max="3650" value={archive.retentionDays} onChange={e => setArchive({ ...archive, retentionDays: Number(e.target.value) })} /></label><button className="primary" disabled={busy}>Enable archive</button></form>
    <div className="grid spaced">{archives.map(item => <article className="card database-card" key={item.id}><div><h3>{item.name}</h3><p>{item.objectPrefix} · {item.retentionDays} days · checkpoint #{item.lastArchivedId}</p></div><Status value={item.enabled ? "active" : "disabled"} /><div className="actions"><button disabled={!item.enabled || busy} onClick={() => void run(() => api.runAuditArchive(item.id), "Archive batch queued")}>Archive now</button><button className="danger-button" disabled={!item.enabled || busy} onClick={() => window.confirm(`Disable ${item.name}?`) && void run(() => api.disableAuditArchive(item.id), "Audit archive disabled")}>Disable</button></div></article>)}</div>
  </>;
}

const notificationEvents = ["deployment.failed", "backup.failed", "restore.failed", "restore.drill.failed", "database.migration.failed", "audit.archive.failed"];

function Notifications({ flash, setError }: { flash: (s: string) => void; setError: (s: string) => void }) {
  const [items, setItems] = useState<NotificationEndpoint[]>([]);
  const [input, setInput] = useState({ name: "", kind: "webhook", url: "https://", pagerDutyIntegrationKey: "", opsgenieApiKey: "", opsgenieRegion: "us", smtpHost: "", smtpPort: 587, smtpMode: "starttls", smtpUsername: "", smtpPassword: "", from: "", to: "", events: [...notificationEvents] });
  const [signingSecret, setSigningSecret] = useState("");
  const [busy, setBusy] = useState(false);
  const refresh = useCallback(async () => setItems((await api.notificationEndpoints()).items), []);
  useEffect(() => { refresh().catch(reason => setError(message(reason))); }, [refresh, setError]);
  async function create(event: FormEvent) {
    event.preventDefault(); setBusy(true); setSigningSecret("");
    try { const result = await api.createNotificationEndpoint({ ...input, to: input.to.split(",").map(x => x.trim()).filter(Boolean) }); setSigningSecret(result.signingSecret ?? ""); await refresh(); flash("Notification endpoint enabled"); }
    catch (reason) { setError(message(reason)); } finally { setBusy(false); }
  }
  const toggleEvent = (value: string) => setInput({ ...input, events: input.events.includes(value) ? input.events.filter(x => x !== value) : [...input.events, value] });
  return <div className="notification-layout"><form className="card settings-card" onSubmit={create}><p className="eyebrow">Failure delivery</p><h2>Add notification endpoint</h2><label>Name<input value={input.name} onChange={e => setInput({ ...input, name: e.target.value })} required /></label><label>Provider<select value={input.kind} onChange={e => setInput({ ...input, kind: e.target.value })}><option value="webhook">Signed webhook</option><option value="slack">Slack-compatible webhook</option><option value="smtp">SMTP email</option><option value="pagerduty">PagerDuty</option><option value="opsgenie">Opsgenie</option></select></label>
    {(input.kind === "webhook" || input.kind === "slack") && <label>HTTPS URL<input type="url" value={input.url} onChange={e => setInput({ ...input, url: e.target.value })} required /></label>}
    {input.kind === "pagerduty" && <label>Integration key<input type="password" value={input.pagerDutyIntegrationKey} onChange={e => setInput({ ...input, pagerDutyIntegrationKey: e.target.value })} required /></label>}
    {input.kind === "opsgenie" && <><label>API key<input type="password" value={input.opsgenieApiKey} onChange={e => setInput({ ...input, opsgenieApiKey: e.target.value })} required /></label><label>Region<select value={input.opsgenieRegion} onChange={e => setInput({ ...input, opsgenieRegion: e.target.value })}><option value="us">US</option><option value="eu">EU</option></select></label></>}
    {input.kind === "smtp" && <><div className="field-row"><label>SMTP host<input value={input.smtpHost} onChange={e => setInput({ ...input, smtpHost: e.target.value })} required /></label><label>Port<input type="number" min="1" max="65535" value={input.smtpPort} onChange={e => setInput({ ...input, smtpPort: Number(e.target.value) })} /></label></div><label>TLS mode<select value={input.smtpMode} onChange={e => setInput({ ...input, smtpMode: e.target.value })}><option value="starttls">STARTTLS</option><option value="tls">Implicit TLS</option></select></label><div className="field-row"><label>Username<input value={input.smtpUsername} onChange={e => setInput({ ...input, smtpUsername: e.target.value })} /></label><label>Password<input type="password" value={input.smtpPassword} onChange={e => setInput({ ...input, smtpPassword: e.target.value })} /></label></div><label>From<input type="email" value={input.from} onChange={e => setInput({ ...input, from: e.target.value })} required /></label><label>Recipients<input placeholder="ops@example.com, oncall@example.com" value={input.to} onChange={e => setInput({ ...input, to: e.target.value })} required /></label></>}
    <fieldset><legend>Failure events</legend>{notificationEvents.map(value => <label className="check" key={value}><input type="checkbox" checked={input.events.includes(value)} onChange={() => toggleEvent(value)} /> {value}</label>)}</fieldset><button className="primary" disabled={busy || !input.events.length}>Add endpoint</button></form>
    <section><div className="grid">{items.map(item => <article className="card database-card" key={item.id}><div><h3>{item.name}</h3><p>{item.kind} · {item.events.join(", ")}</p></div><Status value={item.enabled ? "active" : "disabled"} />{item.enabled && <button className="danger-button" disabled={busy} onClick={() => window.confirm(`Disable ${item.name}?`) && void api.disableNotificationEndpoint(item.id).then(refresh).then(() => flash("Notification endpoint disabled")).catch(reason => setError(message(reason)))}>Disable</button>}</article>)}</div>{!items.length && <Empty title="No notification endpoints" text="Add a durable delivery target for deployment, backup, restore, and audit failures." />}{signingSecret && <section className="card credential-card signing-secret"><p className="eyebrow">Save now</p><h2>Webhook signing secret</h2><p className="muted">This secret is shown once and signs each request with HMAC-SHA256.</p><code>{signingSecret}</code></section>}</section>
  </div>;
}

function Settings({ flash, setError }: { flash: (s: string) => void; setError: (s: string) => void }) {
  const [credentials, setCredentials] = useState<SourceCredential[]>([]);
  const [destinations, setDestinations] = useState<BackupDestination[]>([]);
  const [oidc, setOIDC] = useState<OIDCProvider[]>([]);
  const [saml, setSAML] = useState<SAMLProvider[]>([]);
  const [credential, setCredential] = useState({ kind: "git", name: "", server: "", username: "", secret: "", privateKey: "", knownHosts: "" });
  const [destination, setDestination] = useState({ name: "", endpoint: "https://", region: "", bucket: "", prefix: "", useTls: true, accessKey: "", secretKey: "" });
  const [oidcInput, setOIDCInput] = useState({ name: "", issuer: "https://", clientId: "", clientSecret: "", domains: "", scopes: "openid,email,profile", defaultRole: "developer" });
  const [samlInput, setSAMLInput] = useState({ name: "", metadataXml: "", domains: "", emailAttribute: "email", nameAttribute: "name", defaultRole: "developer", allowIdpInitiated: false });
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    const [credentialResult, destinationResult, oidcResult, samlResult] = await Promise.all([api.sourceCredentials(), api.backupDestinations(), api.oidcProviders(), api.samlProviders()]);
    setCredentials(credentialResult.items); setDestinations(destinationResult.items); setOIDC(oidcResult.items); setSAML(samlResult.items);
  }, []);
  useEffect(() => { refresh().catch(reason => setError(message(reason))); }, [refresh, setError]);

  async function run(action: () => Promise<unknown>, success: string) {
    setBusy(true);
    try { await action(); await refresh(); flash(success); }
    catch (reason) { setError(message(reason)); }
    finally { setBusy(false); }
  }
  const domains = (value: string) => value.split(",").map(x => x.trim()).filter(Boolean);

  return <div className="settings-grid">
    <section className="card settings-card"><p className="eyebrow">Build access</p><h2>Source credentials</h2><form onSubmit={event => { event.preventDefault(); void run(() => api.createSourceCredential(credential), "Credential encrypted and saved"); }}>
      <label>Kind<select value={credential.kind} onChange={e => setCredential({ ...credential, kind: e.target.value })}><option value="git">Git HTTPS</option><option value="git-ssh">Git SSH deploy key</option><option value="registry">Container registry</option></select></label>
      <label>Name<input value={credential.name} onChange={e => setCredential({ ...credential, name: e.target.value })} required /></label>
      <label>Server<input placeholder="github.com" value={credential.server} onChange={e => setCredential({ ...credential, server: e.target.value })} required /></label>
      <label>Username<input value={credential.username} onChange={e => setCredential({ ...credential, username: e.target.value })} required /></label>
      {credential.kind === "git-ssh" ? <><label>Private key PEM<textarea className="compact-code" value={credential.privateKey} onChange={e => setCredential({ ...credential, privateKey: e.target.value })} required /></label><label>Pinned known_hosts entry<textarea className="compact-code" value={credential.knownHosts} onChange={e => setCredential({ ...credential, knownHosts: e.target.value })} required /></label></> : <label>Token or password<input type="password" value={credential.secret} onChange={e => setCredential({ ...credential, secret: e.target.value })} required /></label>}
      <button className="primary" disabled={busy}>Add credential</button>
    </form><AdminItems items={credentials.map(x => ({ id: x.id, title: x.name, detail: `${x.kind} · ${x.username}@${x.server}` }))} action="Remove" onAction={id => run(() => api.deleteSourceCredential(id), "Credential removed")} /></section>

    <section className="card settings-card"><p className="eyebrow">Off-site storage</p><h2>Backup destinations</h2><form onSubmit={event => { event.preventDefault(); void run(() => api.createBackupDestination(destination), "Backup destination verified and saved"); }}>
      <label>Name<input value={destination.name} onChange={e => setDestination({ ...destination, name: e.target.value })} required /></label>
      <label>Endpoint<input value={destination.endpoint} onChange={e => setDestination({ ...destination, endpoint: e.target.value, useTls: e.target.value.startsWith("https://") })} required /></label>
      <div className="field-row"><label>Region<input value={destination.region} onChange={e => setDestination({ ...destination, region: e.target.value })} /></label><label>Bucket<input value={destination.bucket} onChange={e => setDestination({ ...destination, bucket: e.target.value })} required /></label></div>
      <label>Object prefix<input value={destination.prefix} onChange={e => setDestination({ ...destination, prefix: e.target.value })} /></label>
      <label>Access key<input value={destination.accessKey} onChange={e => setDestination({ ...destination, accessKey: e.target.value })} required /></label>
      <label>Secret key<input type="password" value={destination.secretKey} onChange={e => setDestination({ ...destination, secretKey: e.target.value })} required /></label>
      <button className="primary" disabled={busy}>Verify and add</button>
    </form><AdminItems items={destinations.map(x => ({ id: x.id, title: x.name, detail: `${x.bucket} · ${x.endpoint}` }))} action="Remove" onAction={id => run(() => api.deleteBackupDestination(id), "Destination removed")} /></section>

    <section className="card settings-card"><p className="eyebrow">Single sign-on</p><h2>OIDC providers</h2><form onSubmit={event => { event.preventDefault(); void run(() => api.createOIDCProvider({ ...oidcInput, domains: domains(oidcInput.domains), scopes: domains(oidcInput.scopes) }), "OIDC provider enabled"); }}>
      <label>Name<input value={oidcInput.name} onChange={e => setOIDCInput({ ...oidcInput, name: e.target.value })} required /></label>
      <label>Issuer<input value={oidcInput.issuer} onChange={e => setOIDCInput({ ...oidcInput, issuer: e.target.value })} required /></label>
      <label>Client ID<input value={oidcInput.clientId} onChange={e => setOIDCInput({ ...oidcInput, clientId: e.target.value })} required /></label>
      <label>Client secret<input type="password" value={oidcInput.clientSecret} onChange={e => setOIDCInput({ ...oidcInput, clientSecret: e.target.value })} required /></label>
      <label>Email domains<input placeholder="example.com, subsidiary.test" value={oidcInput.domains} onChange={e => setOIDCInput({ ...oidcInput, domains: e.target.value })} required /></label>
      <label>Scopes<input value={oidcInput.scopes} onChange={e => setOIDCInput({ ...oidcInput, scopes: e.target.value })} /></label>
      <label>Default role<select value={oidcInput.defaultRole} onChange={e => setOIDCInput({ ...oidcInput, defaultRole: e.target.value })}><option>viewer</option><option>developer</option><option>admin</option></select></label>
      <button className="primary" disabled={busy}>Add OIDC provider</button>
    </form><AdminItems items={oidc.map(x => ({ id: x.id, title: x.name, detail: `${x.issuer} · ${x.defaultRole}${x.enabled ? "" : " · disabled"}` }))} action="Disable" onAction={id => run(() => api.disableOIDCProvider(id), "OIDC provider disabled")} /></section>

    <section className="card settings-card"><p className="eyebrow">Enterprise federation</p><h2>SAML providers</h2><form onSubmit={event => { event.preventDefault(); void run(() => api.createSAMLProvider({ ...samlInput, domains: domains(samlInput.domains) }), "SAML provider enabled"); }}>
      <label>Name<input value={samlInput.name} onChange={e => setSAMLInput({ ...samlInput, name: e.target.value })} required /></label>
      <label>IdP metadata XML<textarea className="compact-code" value={samlInput.metadataXml} onChange={e => setSAMLInput({ ...samlInput, metadataXml: e.target.value })} required /></label>
      <label>Email domains<input value={samlInput.domains} onChange={e => setSAMLInput({ ...samlInput, domains: e.target.value })} required /></label>
      <div className="field-row"><label>Email attribute<input value={samlInput.emailAttribute} onChange={e => setSAMLInput({ ...samlInput, emailAttribute: e.target.value })} /></label><label>Name attribute<input value={samlInput.nameAttribute} onChange={e => setSAMLInput({ ...samlInput, nameAttribute: e.target.value })} /></label></div>
      <label>Default role<select value={samlInput.defaultRole} onChange={e => setSAMLInput({ ...samlInput, defaultRole: e.target.value })}><option>viewer</option><option>developer</option><option>admin</option></select></label>
      <label className="check"><input type="checkbox" checked={samlInput.allowIdpInitiated} onChange={e => setSAMLInput({ ...samlInput, allowIdpInitiated: e.target.checked })} /> Allow IdP-initiated login</label>
      <button className="primary" disabled={busy}>Add SAML provider</button>
    </form><AdminItems items={saml.map(x => ({ id: x.id, title: x.name, detail: `${x.domains.join(", ")} · ${x.defaultRole}${x.enabled ? "" : " · disabled"}` }))} action="Disable" onAction={id => run(() => api.disableSAMLProvider(id), "SAML provider disabled")} /></section>
  </div>;
}

function AdminItems({ items, action, onAction }: { items: { id: string; title: string; detail: string }[]; action: string; onAction: (id: string) => Promise<unknown> }) {
  return <div className="admin-items">{items.map(item => <article key={item.id}><div><strong>{item.title}</strong><small>{item.detail}</small></div><button type="button" onClick={() => { if (window.confirm(`${action} ${item.title}?`)) void onAction(item.id); }}>{action}</button></article>)}{!items.length && <p className="muted">None configured.</p>}</div>;
}

function Status({ value }: { value: string }) { return <span className={`status ${value}`}>{value.replaceAll("_", " ")}</span>; }
function Empty({ title, text }: { title: string; text: string }) { return <section className="empty card"><div>⌁</div><h3>{title}</h3><p className="muted">{text}</p></section>; }

createRoot(document.getElementById("root")!).render(<App />);
