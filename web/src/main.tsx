import { FormEvent, useCallback, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { api, APIError, BackupDestination, Cluster, Database, Deployment, Environment, OIDCProvider, Principal, Project, SAMLProvider, Service, SourceCredential, session, Template } from "./api";
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

type View = "workloads" | "templates" | "databases" | "clusters" | "settings";

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
      {view === "clusters" && <Clusters setError={setError} />}
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

function ServiceDetail({ service, close, setError, flash }: { service: Service; close: () => void; setError: (s: string) => void; flash: (s: string) => void }) {
  const [item, setItem] = useState(service); const [compose, setCompose] = useState(""); const [deployments, setDeployments] = useState<Deployment[]>([]); const [logs, setLogs] = useState(""); const [busy, setBusy] = useState(false);
  const refresh = useCallback(async () => { const [detail, history] = await Promise.all([api.service(service.id), api.deployments(service.id)]); setItem(detail.service); setCompose(detail.service.composeYaml ?? ""); setDeployments(history.items); }, [service.id]);
  useEffect(() => { refresh().catch(reason => setError(message(reason))); }, [refresh, setError]);
  async function action(kind: "save" | "deploy" | "logs") { setBusy(true); try { if (kind === "save") { await api.updateService(item.id, compose); flash("New revision saved"); } if (kind === "deploy") { await api.deploy(item.id); flash("Deployment queued"); } if (kind === "logs") setLogs((await api.logs(item.id)).logs); await refresh(); } catch (reason) { setError(message(reason)); } finally { setBusy(false); } }
  return <><button className="back" onClick={close}>← All services</button><section className="detail-title"><div className="service-icon large">{item.name.slice(0, 2).toUpperCase()}</div><div><h2>{item.name}</h2><p className="muted">{item.slug} · revision {item.revision}</p></div><Status value={item.status || "configured"} /><button className="primary push" onClick={() => action("deploy")} disabled={busy}>Deploy revision</button></section><div className="detail-grid"><section className="card editor"><div className="card-head"><h3>Compose definition</h3><button onClick={() => action("save")} disabled={busy}>Save revision</button></div><textarea aria-label="Compose YAML" value={compose} onChange={e => setCompose(e.target.value)} spellCheck={false} /></section><section className="card"><div className="card-head"><h3>Deployments</h3><button onClick={() => refresh()}>Refresh</button></div><div className="timeline">{deployments.length ? deployments.map(d => <article key={d.id}><i className={d.status} /><div><strong>Revision {d.revision}</strong><small>{new Date(d.createdAt).toLocaleString()} · {d.trigger}</small>{d.error && <p className="error">{d.error}</p>}</div><Status value={d.status} /></article>) : <p className="muted">No deployments yet.</p>}</div></section></div><section className="card logs"><div className="card-head"><h3>Service logs</h3><button onClick={() => action("logs")}>Load logs</button></div><pre>{logs || "Logs are loaded on demand to avoid unnecessary manager traffic."}</pre></section></>;
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

function Clusters({ setError }: { setError: (s: string) => void }) {
  const [items, setItems] = useState<Cluster[]>([]);
  useEffect(() => { api.clusters().then(x => setItems(x.items)).catch(reason => setError(message(reason))); }, [setError]);
  return <><section className="section-head"><div><h2>Swarm clusters</h2><p className="muted">Outbound mTLS agents and local scheduler capacity.</p></div></section><div className="grid">{items.map(x => <article className="card cluster-card" key={x.id}><div className="cluster-top"><div className="service-icon">SW</div><Status value={x.state} /></div><h3>{x.name}</h3><p>{x.slug}</p><dl><div><dt>Agent</dt><dd>{x.agentVersion || "Not connected"}</dd></div><div><dt>Docker</dt><dd>{x.dockerVersion || "—"}</dd></div><div><dt>Last seen</dt><dd>{x.lastSeenAt ? new Date(x.lastSeenAt).toLocaleString() : "Never"}</dd></div></dl></article>)}</div>{!items.length && <Empty title="No remote clusters" text="The controller can still deploy to its local Swarm. Enroll an agent to add another cluster." />}</>;
}

function Settings({ flash, setError }: { flash: (s: string) => void; setError: (s: string) => void }) {
  const [credentials, setCredentials] = useState<SourceCredential[]>([]);
  const [destinations, setDestinations] = useState<BackupDestination[]>([]);
  const [oidc, setOIDC] = useState<OIDCProvider[]>([]);
  const [saml, setSAML] = useState<SAMLProvider[]>([]);
  const [credential, setCredential] = useState({ kind: "git", name: "", server: "", username: "", secret: "" });
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
      <label>Kind<select value={credential.kind} onChange={e => setCredential({ ...credential, kind: e.target.value })}><option value="git">Git HTTPS</option><option value="registry">Container registry</option></select></label>
      <label>Name<input value={credential.name} onChange={e => setCredential({ ...credential, name: e.target.value })} required /></label>
      <label>Server<input placeholder="github.com" value={credential.server} onChange={e => setCredential({ ...credential, server: e.target.value })} required /></label>
      <label>Username<input value={credential.username} onChange={e => setCredential({ ...credential, username: e.target.value })} required /></label>
      <label>Token or password<input type="password" value={credential.secret} onChange={e => setCredential({ ...credential, secret: e.target.value })} required /></label>
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
