import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { api, AIAuditFinding, AIAuditRun, APIError, ApplicationSource, AuditArchive, AuditEvent, BackupDestination, Cluster, ClusterCommand, Database, DatabaseBackup, DatabaseEngine, DatabaseMigration, DatabaseRestore, Deployment, DeployToken, Environment, ManagedNetwork, MFAStatus, NotificationEndpoint, OIDCProvider, OrganizationInvitation, OrganizationMember, Principal, Project, ResourcePolicy, Role, Route, RouteBasicAuthUser, RouteInput, SAMLProvider, SCIMToken, Service, ServiceAccount, ServiceReconciliation, ServiceSchedule, ServiceScheduleExecution, ServiceScheduleInput, ServiceVolume, SessionInfo, SourceCredential, session, Tag, Template, TemplateInstance, TemplatePreview, TemplateRepository, VolumeBackup, VolumeBackupPolicy, VolumeRestore } from "./api";
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

const roleRank = (role: Role | "") => ({ "": 0, viewer: 1, developer: 2, admin: 3, owner: 4 })[role];

function App() {
  const [principal, setPrincipal] = useState<Principal | null>(null);
  const [checking, setChecking] = useState(Boolean(session.get()));
  const [invitationToken, setInvitationToken] = useState(() => new URLSearchParams(window.location.hash.slice(1)).get("invitation") ?? "");

  useEffect(() => {
    const fragment = new URLSearchParams(window.location.hash.slice(1));
    const callbackToken = fragment.get("session");
    if (callbackToken) {
      session.set(callbackToken);
      history.replaceState(null, "", window.location.pathname + window.location.search);
    }
    if (fragment.get("invitation")) history.replaceState(null, "", window.location.pathname + window.location.search);
    if (!session.get()) return;
    api.me().then(setPrincipal).catch(() => session.clear()).finally(() => setChecking(false));
  }, []);

  if (checking) return <div className="center"><div className="spinner" /><span>Opening Dockyard…</span></div>;
  if (invitationToken) return <Login onLogin={setPrincipal} invitationToken={invitationToken} clearInvitation={() => setInvitationToken("")} />;
  if (!principal) return <Login onLogin={setPrincipal} invitationToken={invitationToken} clearInvitation={() => setInvitationToken("")} />;
  return <Console principal={principal} onLogout={() => { session.clear(); setPrincipal(null); }} />;
}

function Login({ onLogin, invitationToken, clearInvitation }: { onLogin: (principal: Principal) => void; invitationToken: string; clearInvitation: () => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [providers, setProviders] = useState<{ id: string; name: string; kind: "oidc" | "saml" }[]>([]);
  const [inviteName, setInviteName] = useState("");
  const [invitePassword, setInvitePassword] = useState("");
  const [inviteAccepted, setInviteAccepted] = useState("");
  const [mfaRequired, setMFARequired] = useState(false);
  const [mfaCode, setMFACode] = useState("");
  const [useRecoveryCode, setUseRecoveryCode] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError("");
    try {
      const result = await api.login(email, password, useRecoveryCode ? "" : mfaCode, useRecoveryCode ? mfaCode : "");
      session.set(result.token);
      onLogin(await api.me());
    } catch (reason) {
      if (reason instanceof APIError && reason.code === "mfa_required") { setMFARequired(true); setError(""); }
      else setError(message(reason));
      session.clear();
    }
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

  async function acceptInvitation() {
    setBusy(true); setError("");
    try {
      const accepted = await api.acceptInvitation(invitationToken, inviteName, invitePassword);
      setEmail(accepted.email); setInviteAccepted(`Invitation to ${accepted.organization} accepted as ${accepted.role}. ${accepted.requireSso ? "Continue with SSO." : "Sign in below."}`); clearInvitation();
    } catch (reason) { setError(message(reason)); } finally { setBusy(false); }
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
        {invitationToken && <section className="invitation-accept"><h3>Accept organization invitation</h3><p className="muted">Choose a display name and, for a new local account, a password of at least 12 characters. Existing and SSO accounts can leave the password empty.</p><label>Display name<input value={inviteName} onChange={event => setInviteName(event.target.value)} maxLength={120} /></label><label>New-account password<input type="password" value={invitePassword} onChange={event => setInvitePassword(event.target.value)} minLength={12} autoComplete="new-password" /></label><div className="actions"><button type="button" className="primary" disabled={busy} onClick={() => void acceptInvitation()}>Accept invitation</button><button type="button" disabled={busy} onClick={clearInvitation}>Dismiss</button></div></section>}
        {inviteAccepted && <p className="success-text">{inviteAccepted}</p>}
        <p className="muted">Sign in with your local administrator account.</p>
        <label>Email<input autoFocus type="email" value={email} onChange={e => { setEmail(e.target.value); setMFARequired(false); }} required /></label>
        <label>Password<input type="password" value={password} onChange={e => { setPassword(e.target.value); setMFARequired(false); }} required /></label>
        {mfaRequired && <><label>{useRecoveryCode ? "Recovery code" : "Authenticator code"}<input inputMode={useRecoveryCode ? "text" : "numeric"} autoComplete="one-time-code" value={mfaCode} onChange={e => setMFACode(e.target.value)} required autoFocus /></label><button type="button" className="link-button" onClick={() => { setUseRecoveryCode(value => !value); setMFACode(""); }}>{useRecoveryCode ? "Use authenticator code" : "Use a recovery code"}</button></>}
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

type View = "workloads" | "templates" | "databases" | "clusters" | "governance" | "ai" | "audit" | "notifications" | "settings" | "account";

function Console({ principal, onLogout }: { principal: Principal; onLogout: () => void }) {
  const [view, setView] = useState<View>("workloads");
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectId, setProjectId] = useState("");
  const [environments, setEnvironments] = useState<Environment[]>([]);
  const [environmentId, setEnvironmentId] = useState("");
  const [services, setServices] = useState<Service[]>([]);
  const [selectedService, setSelectedService] = useState<Service | null>(null);
  const [projectRole, setProjectRole] = useState<Role | "">("");
  const [environmentRole, setEnvironmentRole] = useState<Role | "">("");
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
  useEffect(() => {
    let active = true;
    setProjectRole("");
    if (projectId) void api.effectiveRole("project", projectId).then(result => { if (active) setProjectRole(result.role); }).catch(reason => { if (active) setError(message(reason)); });
    return () => { active = false; };
  }, [projectId]);
  useEffect(() => {
    let active = true;
    setEnvironmentRole("");
    if (environmentId) void api.effectiveRole("environment", environmentId).then(result => { if (active) setEnvironmentRole(result.role); }).catch(reason => { if (active) setError(message(reason)); });
    return () => { active = false; };
  }, [environmentId]);

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
        {(["admin", "owner"] as string[]).includes(principal.role) && <Nav active={view === "ai"} onClick={() => setView("ai")} icon="✦">AI audits</Nav>}
        {(["admin", "owner"] as string[]).includes(principal.role) && <Nav active={view === "audit"} onClick={() => setView("audit")} icon="≡">Audit</Nav>}
        {(["admin", "owner"] as string[]).includes(principal.role) && <Nav active={view === "notifications"} onClick={() => setView("notifications")} icon="◌">Notifications</Nav>}
        {(["admin", "owner"] as string[]).includes(principal.role) && <Nav active={view === "settings"} onClick={() => setView("settings")} icon="⚙">Settings</Nav>}
        <Nav active={view === "account"} onClick={() => setView("account")} icon="◎">Account</Nav>
      </nav>
      <div className="account"><div className="avatar">{principal.email.slice(0, 1).toUpperCase()}</div><div><strong>{principal.email}</strong><small>{principal.role}</small></div><button className="icon-button" onClick={logout} title="Sign out">↪</button></div>
    </aside>
    <main className="content">
      <header><div><p className="eyebrow">Organization workspace</p><h1>{view[0].toUpperCase() + view.slice(1)}</h1></div><div className="live"><i /> Live</div></header>
      {error && <div className="toast error" role="alert">{error}<button onClick={() => setError("")}>×</button></div>}
      {notice && <div className="toast success">{notice}</div>}
      {view === "workloads" && <Workloads {...{ projects, projectId, setProjectId, environments, environmentId, setEnvironmentId, services, selectedService, setSelectedService, reloadProjects: loadProjects, reloadEnvironments: loadEnvironments, reloadServices: loadServices, flash, setError }} canCreateProject={roleRank(principal.role) >= roleRank("developer")} projectRole={projectRole} environmentRole={environmentRole} canManageCredentials={roleRank(principal.role) >= roleRank("developer")} canManageTags={roleRank(principal.role) >= roleRank("admin")} />}
      {view === "templates" && <Templates environmentId={environmentId} canWrite={roleRank(environmentRole) >= roleRank("developer")} canAdmin={roleRank(principal.role) >= roleRank("admin")} reloadServices={loadServices} flash={flash} setError={setError} />}
      {view === "databases" && <Databases environmentId={environmentId} canWrite={roleRank(environmentRole) >= roleRank("developer")} canAdmin={roleRank(environmentRole) >= roleRank("admin")} canManageDestinations={roleRank(principal.role) >= roleRank("developer")} flash={flash} setError={setError} />}
      {view === "clusters" && <Clusters flash={flash} setError={setError} />}
      {view === "governance" && <Governance principal={principal} projects={projects} projectId={projectId} environments={environments} environmentId={environmentId} flash={flash} setError={setError} />}
      {view === "ai" && <AIAudits flash={flash} setError={setError} />}
      {view === "audit" && <Audit flash={flash} setError={setError} />}
      {view === "notifications" && <Notifications flash={flash} setError={setError} />}
      {view === "settings" && <Settings flash={flash} setError={setError} />}
      {view === "account" && <Account principal={principal} onSessionRevoked={onLogout} flash={flash} setError={setError} />}
    </main>
  </div>;
}

function Nav({ active, onClick, icon, children }: { active: boolean; onClick: () => void; icon: string; children: string }) {
  return <button className={active ? "active" : ""} onClick={onClick}><span>{icon}</span>{children}</button>;
}

function Account({ principal, onSessionRevoked, flash, setError }: { principal: Principal; onSessionRevoked: () => void; flash: (s: string) => void; setError: (s: string) => void }) {
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [busy, setBusy] = useState(false);
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [mfa, setMFA] = useState<MFAStatus | null>(null);
  const [mfaPassword, setMFAPassword] = useState("");
  const [mfaCode, setMFACode] = useState("");
  const [mfaRecoveryProof, setMFARecoveryProof] = useState("");
  const [enrollment, setEnrollment] = useState<{ secret: string; otpauthUri: string } | null>(null);
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const refresh = useCallback(async () => setSessions((await api.sessions()).items), []);
  const refreshMFA = useCallback(async () => setMFA(await api.mfaStatus()), []);
  useEffect(() => { void refresh().catch(reason => setError(message(reason))); }, [refresh, setError]);
  useEffect(() => { void refreshMFA().catch(reason => setError(message(reason))); }, [refreshMFA, setError]);

  async function revoke(item: SessionInfo) {
    if (!window.confirm(item.current ? "Revoke this session and sign out now?" : "Revoke this device session?")) return;
    setBusy(true);
    try {
      await api.revokeSession(item.id);
      if (item.current) { onSessionRevoked(); return; }
      await refresh();
      flash("Device session revoked");
    } catch (reason) { setError(message(reason)); } finally { setBusy(false); }
  }

  async function revokeOthers() {
    if (!window.confirm("Revoke every other active session for this account?")) return;
    setBusy(true);
    try {
      const result = await api.revokeOtherSessions();
      await refresh();
      flash(`${result.revoked} other session${result.revoked === 1 ? "" : "s"} revoked`);
    } catch (reason) { setError(message(reason)); } finally { setBusy(false); }
  }

  async function changePassword(event: FormEvent) {
    event.preventDefault();
    if (newPassword !== confirmPassword) { setError("New password confirmation does not match"); return; }
    setBusy(true);
    try {
      const result = await api.changePassword(currentPassword, newPassword);
      setCurrentPassword(""); setNewPassword(""); setConfirmPassword("");
      await refresh();
      flash(`Password changed; ${result.revoked} other session${result.revoked === 1 ? "" : "s"} revoked`);
    } catch (reason) { setError(message(reason)); } finally { setBusy(false); }
  }

  async function beginMFA(event: FormEvent) {
    event.preventDefault(); setBusy(true);
    try { setEnrollment(await api.beginMFAEnrollment(mfaPassword)); setMFACode(""); setRecoveryCodes([]); await refreshMFA(); flash("Authenticator enrollment started"); }
    catch (reason) { setError(message(reason)); } finally { setBusy(false); }
  }

  async function confirmMFA(event: FormEvent) {
    event.preventDefault(); setBusy(true);
    try { const result = await api.confirmMFAEnrollment(mfaCode); setRecoveryCodes(result.recoveryCodes); setEnrollment(null); setMFAPassword(""); setMFACode(""); await Promise.all([refreshMFA(), refresh()]); flash("Multi-factor authentication enabled"); }
    catch (reason) { setError(message(reason)); } finally { setBusy(false); }
  }

  async function regenerateRecoveryCodes() {
    if (!window.confirm("Replace every existing recovery code?")) return;
    setBusy(true);
    try { const result = await api.regenerateMFARecoveryCodes(mfaPassword, mfaCode, mfaRecoveryProof); setRecoveryCodes(result.recoveryCodes); setMFAPassword(""); setMFACode(""); setMFARecoveryProof(""); await Promise.all([refreshMFA(), refresh()]); flash("Recovery codes replaced"); }
    catch (reason) { setError(message(reason)); } finally { setBusy(false); }
  }

  async function disableMFA() {
    if (!window.confirm("Disable multi-factor authentication for this account?")) return;
    setBusy(true);
    try { await api.disableMFA(mfaPassword, mfaCode, mfaRecoveryProof); setRecoveryCodes([]); setMFAPassword(""); setMFACode(""); setMFARecoveryProof(""); await Promise.all([refreshMFA(), refresh()]); flash("Multi-factor authentication disabled"); }
    catch (reason) { setError(message(reason)); } finally { setBusy(false); }
  }

  return <div className="account-layout">
    <div className="account-security-column"><section className="card settings-card account-profile"><p className="eyebrow">Signed-in identity</p><h2>{principal.email}</h2><p className="muted">{principal.organization}</p><dl><div><dt>Organization role</dt><dd>{principal.role}</dd></div><div><dt>User ID</dt><dd><code>{principal.userId}</code></dd></div></dl></section><section className="card settings-card password-change"><p className="eyebrow">Local credential</p><h2>Change password</h2><p className="muted">Requires a local login. All other sessions are revoked after a successful change.</p><form onSubmit={changePassword}><label>Current password<input type="password" autoComplete="current-password" value={currentPassword} onChange={event => setCurrentPassword(event.target.value)} required /></label><label>New password<input type="password" autoComplete="new-password" minLength={12} value={newPassword} onChange={event => setNewPassword(event.target.value)} required /></label><label>Confirm new password<input type="password" autoComplete="new-password" minLength={12} value={confirmPassword} onChange={event => setConfirmPassword(event.target.value)} required /></label><button className="primary" disabled={busy}>Change password</button></form></section><section className="card settings-card"><p className="eyebrow">Multi-factor authentication</p><h2>{mfa?.enabled ? "Authenticator enabled" : "Protect local login"}</h2><p className="muted">{mfa?.enabled ? `${mfa.recoveryCodesRemaining} unused recovery codes remain.` : "Use a TOTP authenticator for local and break-glass sign-in."}</p>{!mfa?.enabled && !enrollment && <form onSubmit={beginMFA}><label>Current password<input type="password" autoComplete="current-password" value={mfaPassword} onChange={event => setMFAPassword(event.target.value)} required /></label><button className="primary" disabled={busy}>Set up authenticator</button></form>}{enrollment && <form onSubmit={confirmMFA}><p className="muted">Add this secret to your authenticator, then enter its current code.</p><code>{enrollment.secret}</code><details><summary>Authenticator URI</summary><code>{enrollment.otpauthUri}</code></details><label>Authenticator code<input inputMode="numeric" autoComplete="one-time-code" value={mfaCode} onChange={event => setMFACode(event.target.value)} required /></label><button className="primary" disabled={busy}>Verify and enable</button></form>}{mfa?.enabled && <div><label>Current password<input type="password" autoComplete="current-password" value={mfaPassword} onChange={event => setMFAPassword(event.target.value)} /></label><label>Authenticator code<input inputMode="numeric" autoComplete="one-time-code" value={mfaCode} onChange={event => { setMFACode(event.target.value); setMFARecoveryProof(""); }} /></label><label>Or recovery code<input value={mfaRecoveryProof} onChange={event => { setMFARecoveryProof(event.target.value); setMFACode(""); }} /></label><div className="actions"><button type="button" disabled={busy || !mfaPassword || (!mfaCode && !mfaRecoveryProof)} onClick={() => void regenerateRecoveryCodes()}>Replace recovery codes</button><button type="button" className="danger-button" disabled={busy || !mfaPassword || (!mfaCode && !mfaRecoveryProof)} onClick={() => void disableMFA()}>Disable MFA</button></div></div>}{recoveryCodes.length > 0 && <div className="credential-card spaced"><p className="eyebrow">Save these recovery codes now</p><p className="muted">Each code works once. They will not be shown again.</p><code>{recoveryCodes.join("\n")}</code><div className="actions"><button type="button" onClick={() => void navigator.clipboard.writeText(recoveryCodes.join("\n"))}>Copy codes</button><button type="button" onClick={() => setRecoveryCodes([])}>I saved them</button></div></div>}</section></div>
    <section className="card settings-card account-sessions"><div className="card-head"><div><p className="eyebrow">Security</p><h2>Device sessions</h2><p className="muted">Review where your account is signed in and revoke access you no longer recognize.</p></div><div className="actions"><button type="button" disabled={busy} onClick={() => void refresh().catch(reason => setError(message(reason)))}>Refresh</button><button type="button" className="danger-button" disabled={busy || sessions.filter(item => !item.current).length === 0} onClick={() => void revokeOthers()}>Revoke all others</button></div></div><div className="admin-items session-list">{sessions.map(item => <article key={item.id}><div><strong>{item.current ? "This device" : item.userAgent || "Unknown device"}</strong><small>{item.current && item.userAgent ? `${item.userAgent} · ` : ""}{item.authMethod.toUpperCase()} · {item.ipAddress || "unknown address"}</small><small>Last active {new Date(item.lastSeenAt).toLocaleString()} · expires {new Date(item.expiresAt).toLocaleString()}</small></div><Status value={item.current ? "current" : "active"} /><button type="button" className="danger-button" disabled={busy} onClick={() => void revoke(item)}>{item.current ? "Sign out" : "Revoke"}</button></article>)}{!sessions.length && <p className="muted">No active sessions were returned.</p>}</div></section>
  </div>;
}

type WorkloadProps = {
  projects: Project[]; projectId: string; setProjectId: (id: string) => void;
  environments: Environment[]; environmentId: string; setEnvironmentId: (id: string) => void;
  services: Service[]; selectedService: Service | null; setSelectedService: (item: Service | null) => void;
  reloadProjects: () => Promise<void>; reloadEnvironments: () => Promise<void>; reloadServices: () => Promise<void>; flash: (s: string) => void; setError: (s: string) => void;
  canCreateProject: boolean; projectRole: Role | ""; environmentRole: Role | ""; canManageCredentials: boolean; canManageTags: boolean;
};

function Workloads(props: WorkloadProps) {
  const [dialog, setDialog] = useState<"project" | "environment" | "service" | null>(null);
  const canCreateEnvironment = roleRank(props.projectRole) >= roleRank("developer");
  const canWriteEnvironment = roleRank(props.environmentRole) >= roleRank("developer");
  if (props.selectedService) return <ServiceDetail service={props.selectedService} canWrite={canWriteEnvironment} canAdmin={roleRank(props.environmentRole) >= roleRank("admin")} canManageCredentials={props.canManageCredentials} canManageTags={props.canManageTags} close={() => { props.setSelectedService(null); void props.reloadServices(); }} setError={props.setError} flash={props.flash} />;
  return <>
    <section className="toolbar card">
      <label>Project<select value={props.projectId} onChange={e => props.setProjectId(e.target.value)}><option value="">Select project</option>{props.projects.map(x => <option key={x.id} value={x.id}>{x.name}</option>)}</select></label>
      {props.canCreateProject && <button onClick={() => setDialog("project")}>+ Project</button>}
      <label>Environment<select value={props.environmentId} onChange={e => props.setEnvironmentId(e.target.value)} disabled={!props.projectId}><option value="">Select environment</option>{props.environments.map(x => <option key={x.id} value={x.id}>{x.name}</option>)}</select></label>
      {canCreateEnvironment && <button onClick={() => setDialog("environment")} disabled={!props.projectId}>+ Environment</button>}
      {canWriteEnvironment && <button className="primary push" onClick={() => setDialog("service")} disabled={!props.environmentId}>New service</button>}
    </section>
    {props.projectId && <ProjectTagPanel projectId={props.projectId} canWrite={canCreateEnvironment} canManageTags={props.canManageTags} refresh={props.reloadProjects} flash={props.flash} setError={props.setError} />}
    <section className="section-head"><div><h2>Compose services</h2><p className="muted">Immutable revisions deployed as Swarm stacks.</p></div><span className="count">{props.services.length} total</span></section>
    {props.services.length ? <div className="grid">{props.services.map(service => <button className="card service-card" key={service.id} onClick={() => props.setSelectedService(service)}><div className="service-icon">{service.name.slice(0, 2).toUpperCase()}</div><div><h3>{service.name}</h3><p>{service.slug}</p>{service.tags?.length > 0 && <span className="tag-row">{service.tags.map(tag => <i key={tag.id} style={{ borderColor: tag.color, color: tag.color }}>{tag.name}</i>)}</span>}</div><Status value={service.status || "configured"} /><small>Revision {service.revision}</small><b>Open →</b></button>)}</div> : <Empty title="No services here yet" text="Create a Compose service or instantiate a template to get started." />}
    {dialog && <CreateDialog kind={dialog} projectId={props.projectId} environmentId={props.environmentId} close={() => setDialog(null)} done={async text => { setDialog(null); props.flash(text); if (dialog === "project") await props.reloadProjects(); else if (dialog === "environment") await props.reloadEnvironments(); else await props.reloadServices(); }} setError={props.setError} />}
  </>;
}

function ProjectTagPanel({ projectId, canWrite, canManageTags, refresh, flash, setError }: { projectId: string; canWrite: boolean; canManageTags: boolean; refresh: () => Promise<void>; flash: (s: string) => void; setError: (s: string) => void }) {
  const [tags, setTags] = useState<Tag[]>([]); const [assigned, setAssigned] = useState<string[]>([]); const [name, setName] = useState(""); const [color, setColor] = useState("#64748B"); const [busy, setBusy] = useState(false);
  const load = useCallback(async () => { const [catalog, selected] = await Promise.all([api.tags(), api.projectTags(projectId)]); setTags(catalog.items); setAssigned(selected.items.map(tag => tag.id)); }, [projectId]);
  useEffect(() => { void load().catch(reason => setError(message(reason))); }, [load, setError]);
  async function create(event: FormEvent) { event.preventDefault(); setBusy(true); try { const tag = await api.createTag(name, color); await api.setProjectTags(projectId, [...assigned, tag.id]); setName(""); await load(); await refresh(); flash("Tag created and assigned to project"); } catch (reason) { setError(message(reason)); } finally { setBusy(false); } }
  async function toggle(tag: Tag) { const next = assigned.includes(tag.id) ? assigned.filter(id => id !== tag.id) : [...assigned, tag.id]; setBusy(true); try { await api.setProjectTags(projectId, next); setAssigned(next); await refresh(); flash("Project tags updated"); } catch (reason) { setError(message(reason)); } finally { setBusy(false); } }
  async function remove(tag: Tag) { if (!window.confirm(`Delete tag ${tag.name} from every project and service?`)) return; setBusy(true); try { await api.deleteTag(tag.id); await load(); await refresh(); flash("Tag deleted"); } catch (reason) { setError(message(reason)); } finally { setBusy(false); } }
  return <section className="card tag-panel project-tags"><div className="card-head"><div><p className="eyebrow">Project metadata</p><h3>Project tags</h3><p className="muted">Dokploy-compatible organization tags for grouping projects.</p></div></div>{canManageTags && <form onSubmit={create}><label>Name<input value={name} onChange={event => setName(event.target.value)} maxLength={64} required /></label><label>Color<input type="color" value={color} onChange={event => setColor(event.target.value.toUpperCase())} required /></label><button className="primary" disabled={busy}>Create and assign</button></form>}<div className="tag-options">{tags.map(tag => <span key={tag.id} className={assigned.includes(tag.id) ? "selected" : ""} style={{ borderColor: tag.color }}><button type="button" disabled={busy || !canWrite} onClick={() => void toggle(tag)}><i style={{ background: tag.color }} />{tag.name}<small>{tag.projectCount} project{tag.projectCount === 1 ? "" : "s"}</small></button>{canManageTags && <button type="button" className="tag-delete" aria-label={`Delete ${tag.name}`} disabled={busy} onClick={() => void remove(tag)}>×</button>}</span>)}{!tags.length && <p className="muted">No organization tags yet.</p>}</div></section>;
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

function ServiceDetail({ service, canWrite, canAdmin, canManageCredentials, canManageTags, close, setError, flash }: { service: Service; canWrite: boolean; canAdmin: boolean; canManageCredentials: boolean; canManageTags: boolean; close: () => void; setError: (s: string) => void; flash: (s: string) => void }) {
  const [item, setItem] = useState(service); const [compose, setCompose] = useState(""); const [routes, setRoutes] = useState<Route[]>([]); const [source, setSource] = useState<ApplicationSource | null>(null); const [templateInstance, setTemplateInstance] = useState<TemplateInstance | null>(null); const [reconciliation, setReconciliation] = useState<ServiceReconciliation | null>(null); const [templateVersions, setTemplateVersions] = useState<Template[]>([]); const [upgradeTemplateId, setUpgradeTemplateId] = useState(""); const [sourceForm, setSourceForm] = useState<SourceDraft>(emptySourceDraft); const [artifactFile, setArtifactFile] = useState<File | null>(null); const [credentials, setCredentials] = useState<SourceCredential[]>([]); const [deployments, setDeployments] = useState<Deployment[]>([]); const [logs, setLogs] = useState(""); const [busy, setBusy] = useState(false);
  const refresh = useCallback(async () => { const [detail, history, credentialResult] = await Promise.all([api.service(service.id), api.deployments(service.id), canManageCredentials ? api.sourceCredentials() : Promise.resolve({ items: [] })]); const versions = detail.template ? (await api.templateVersions(service.id)).items : []; setItem(detail.service); setCompose(detail.service.composeYaml ?? ""); setRoutes(detail.routes); setSource(detail.source); setTemplateInstance(detail.template); setReconciliation(detail.reconciliation); setTemplateVersions(versions); setUpgradeTemplateId(current => versions.some(version => version.id === current) ? current : versions[0]?.id ?? ""); setSourceForm(sourceDraft(detail.source)); setCredentials(credentialResult.items); setDeployments(history.items); }, [service.id, canManageCredentials]);
  useEffect(() => { refresh().catch(reason => setError(message(reason))); }, [refresh, setError]);
  async function action(kind: "save" | "deploy" | "start" | "stop" | "logs") { setBusy(true); try { if (kind === "save") { await api.updateService(item.id, compose); flash("New revision saved"); } if (kind === "deploy") { await api.deploy(item.id); flash("Deployment queued"); } if (kind === "start") { await api.startService(item.id); flash("Service start queued"); } if (kind === "stop") { await api.stopService(item.id); flash("Service stop queued"); } if (kind === "logs") setLogs((await api.logs(item.id)).logs); await refresh(); } catch (reason) { setError(message(reason)); } finally { setBusy(false); } }
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
  async function upgradeTemplate() { if (!templateInstance || !upgradeTemplateId) return; if (templateInstance.drifted && !window.confirm("This service has manual Compose changes. Replace them with the selected template version?")) return; setBusy(true); try { await api.upgradeTemplate(item.id, { templateId: upgradeTemplateId, allowDrift: templateInstance.drifted, variables: {} }); await refresh(); flash("Template revision applied; review and deploy the new service revision"); } catch (reason) { setError(message(reason)); } finally { setBusy(false); } }
  return <><button className="back" onClick={close}>← All services</button><section className="detail-title"><div className="service-icon large">{item.name.slice(0, 2).toUpperCase()}</div><div><h2>{item.name}</h2><p className="muted">{item.slug} · revision {item.revision}{templateInstance ? ` · ${templateInstance.templateKey}@${templateInstance.templateVersion}` : ""}</p></div><Status value={item.desiredState || "running"} />{canWrite && item.desiredState === "stopped" && <button className="primary push" onClick={() => action("start")} disabled={busy}>Start service</button>}{canWrite && item.desiredState !== "stopped" && <><button onClick={() => { if (window.confirm("Stop this service? Named volumes will be preserved.")) void action("stop"); }} disabled={busy}>Stop service</button><button className="primary" onClick={() => action("deploy")} disabled={busy}>Deploy revision</button></>}</section><div className="detail-grid"><section className="card editor"><div className="card-head"><h3>Compose definition</h3>{canWrite && <button onClick={() => action("save")} disabled={busy}>Save revision</button>}</div><textarea aria-label="Compose YAML" value={compose} readOnly={!canWrite} onChange={e => setCompose(e.target.value)} spellCheck={false} /></section><section className="card"><div className="card-head"><h3>Deployments</h3><button onClick={() => refresh()}>Refresh</button></div><div className="timeline">{deployments.length ? deployments.map(d => <article key={d.id}><i className={d.status} /><div><strong>Revision {d.revision}</strong><small>{new Date(d.createdAt).toLocaleString()} · {d.trigger}</small>{d.error && <p className="error">{d.error}</p>}</div><Status value={d.status} /></article>) : <p className="muted">No deployments yet.</p>}</div></section></div>
    <section className="card template-origin reconciliation-status"><div><p className="eyebrow">Runtime reconciliation</p><h3>{reconciliation ? "Last Swarm observation" : "Awaiting first observation"}</h3><p className="muted">{reconciliation ? `Checked ${new Date(reconciliation.lastCheckedAt).toLocaleString()}${reconciliation.consecutiveFailures ? ` · ${reconciliation.consecutiveFailures} consecutive failure${reconciliation.consecutiveFailures === 1 ? "" : "s"}` : ""}` : "The controller records runtime health after the service has a successful deployment."}</p>{reconciliation?.detail && <p className="muted">{reconciliation.detail}</p>}{reconciliation?.lastRepairAt && <small>Last automatic repair {new Date(reconciliation.lastRepairAt).toLocaleString()}</small>}</div><Status value={reconciliation?.state ?? "unknown"} /></section>
    <ServiceTagPanel service={item} canWrite={canWrite} canAdmin={canManageTags} refresh={refresh} flash={flash} setError={setError} />
    <ServiceNetworkPanel service={item} canWrite={canWrite} refresh={refresh} flash={flash} setError={setError} />
    <RoutePanel service={item} routes={routes} canWrite={canWrite} refresh={refresh} flash={flash} setError={setError} />
    {templateInstance && <section className="card template-origin"><div><p className="eyebrow">Template origin</p><h3>{templateInstance.templateKey}@{templateInstance.templateVersion}</h3><p className="muted">{templateInstance.drifted ? "Compose has local changes. Upgrading requires explicit confirmation." : "Compose still matches the applied template revision."}</p></div>{canWrite && templateVersions.length > 0 && <div className="template-upgrade"><label>Available revision<select value={upgradeTemplateId} onChange={event => setUpgradeTemplateId(event.target.value)}>{templateVersions.map(version => <option key={version.id} value={version.id}>{version.version}</option>)}</select></label><button type="button" className="primary" disabled={busy || !upgradeTemplateId} onClick={upgradeTemplate}>Apply revision</button></div>}{!templateVersions.length && <span className="status active">current</span>}</section>}
    {canWrite ? <form className="card source-editor" onSubmit={saveSource}><div className="card-head"><div><h3>Application build</h3><p className="muted">Build an immutable image from Git or an uploaded ZIP, then deploy it through the Compose service.</p></div><button className="primary" disabled={busy}>{busy ? "Saving…" : "Save source"}</button></div><div className="source-fields">
      <label>Source type<select value={sourceForm.sourceType} onChange={e => setSourceForm({ ...sourceForm, sourceType: e.target.value as SourceDraft["sourceType"] })}><option value="git">Git repository</option><option value="drop">Uploaded ZIP</option></select></label>
      <label>Build type<select value={sourceForm.buildType} onChange={e => setSourceForm({ ...sourceForm, buildType: e.target.value as SourceDraft["buildType"], builderImage: "", buildTarget: "", buildArguments: "", buildSecrets: "", clearBuildArguments: false, clearBuildSecrets: false })}><option value="dockerfile">Dockerfile</option><option value="nixpacks">Nixpacks</option><option value="railpack">Railpack</option><option value="buildpacks">Paketo buildpacks</option><option value="heroku_buildpacks">Heroku Buildpacks</option><option value="static">Static files</option></select></label>
      {sourceForm.sourceType === "git" ? <><label className="wide">Repository URL<input type="url" value={sourceForm.repositoryUrl} onChange={e => setSourceForm({ ...sourceForm, repositoryUrl: e.target.value })} placeholder="https://github.com/acme/app.git" required /></label><label>Git ref<input value={sourceForm.gitRef} onChange={e => setSourceForm({ ...sourceForm, gitRef: e.target.value })} placeholder="main" /></label><label>Git credential<select value={sourceForm.gitCredentialId} onChange={e => setSourceForm({ ...sourceForm, gitCredentialId: e.target.value })}><option value="">Public repository</option>{credentials.filter(x => x.kind === "git" || x.kind === "git-ssh").map(x => <option key={x.id} value={x.id}>{x.name} · {x.server}</option>)}</select></label></> : <label className="wide">Source ZIP <span>{source?.artifact ? `${source.artifact.filename} · ${(source.artifact.compressedSize / 1048576).toFixed(1)} MiB · SHA-256 ${source.artifact.sha256.slice(0, 12)}…` : "Maximum 25 MiB compressed and 250 MiB expanded."}</span><input type="file" accept=".zip,application/zip" onChange={e => setArtifactFile(e.target.files?.[0] ?? null)} required={!source?.artifact} /></label>}
      <label>Context directory<input value={sourceForm.contextDirectory} onChange={e => setSourceForm({ ...sourceForm, contextDirectory: e.target.value })} placeholder="." /></label>{sourceForm.buildType === "dockerfile" ? <><label>Dockerfile<input value={sourceForm.dockerfile} onChange={e => setSourceForm({ ...sourceForm, dockerfile: e.target.value })} placeholder="Dockerfile" /></label><label>Target stage<input value={sourceForm.buildTarget} onChange={e => setSourceForm({ ...sourceForm, buildTarget: e.target.value })} placeholder="runtime (optional)" /></label></> : sourceForm.buildType === "static" ? <label className="wide">Static output directory<input value={sourceForm.outputDirectory} onChange={e => setSourceForm({ ...sourceForm, outputDirectory: e.target.value })} placeholder="dist" required /></label> : null}{(sourceForm.buildType === "buildpacks" || sourceForm.buildType === "heroku_buildpacks") && <label className="wide">Custom builder image <span>Optional. Must include an immutable @sha256 digest; the default {sourceForm.buildType === "heroku_buildpacks" ? "Heroku 24" : "Paketo Jammy base"} builder is already pinned.</span><input value={sourceForm.builderImage} onChange={e => setSourceForm({ ...sourceForm, builderImage: e.target.value })} placeholder="registry.example.com/builders/custom:v1@sha256:…" /></label>}<label>Compose target service<input value={sourceForm.targetService} onChange={e => setSourceForm({ ...sourceForm, targetService: e.target.value })} placeholder="web" required /></label><label className="wide">Registry image<input value={sourceForm.registryImage} onChange={e => setSourceForm({ ...sourceForm, registryImage: e.target.value })} placeholder="registry.example.com/team/app" required /></label><label>Registry credential<select value={sourceForm.registryCredentialId} onChange={e => setSourceForm({ ...sourceForm, registryCredentialId: e.target.value })}><option value="">Anonymous push</option>{credentials.filter(x => x.kind === "registry").map(x => <option key={x.id} value={x.id}>{x.name} · {x.server}</option>)}</select></label>{sourceForm.sourceType === "git" && <label className="check wide"><input type="checkbox" checked={sourceForm.enableSubmodules} onChange={e => setSourceForm({ ...sourceForm, enableSubmodules: e.target.checked })} /> Clone same-origin Git submodules recursively</label>}
      {sourceForm.buildType === "dockerfile" && <><label className="build-values">Build arguments <span>{source?.hasBuildArguments ? "Configured values are hidden; leave blank to preserve them." : "One NAME=value entry per line."}</span><textarea className="compact-code" value={sourceForm.buildArguments} disabled={sourceForm.clearBuildArguments} onChange={e => setSourceForm({ ...sourceForm, buildArguments: e.target.value })} placeholder="GO_VERSION=1.26" spellCheck={false} /></label><label className="build-values">BuildKit secrets <span>{source?.hasBuildSecrets ? "Configured values are hidden; leave blank to preserve them." : "Values are encrypted and never returned."}</span><textarea className="compact-code" value={sourceForm.buildSecrets} disabled={sourceForm.clearBuildSecrets} onChange={e => setSourceForm({ ...sourceForm, buildSecrets: e.target.value })} placeholder="NPM_TOKEN=…" spellCheck={false} /></label>
      {source?.hasBuildArguments && <label className="check clear-setting"><input type="checkbox" checked={sourceForm.clearBuildArguments} onChange={e => setSourceForm({ ...sourceForm, clearBuildArguments: e.target.checked, buildArguments: "" })} /> Clear configured build arguments</label>}{source?.hasBuildSecrets && <label className="check clear-setting"><input type="checkbox" checked={sourceForm.clearBuildSecrets} onChange={e => setSourceForm({ ...sourceForm, clearBuildSecrets: e.target.checked, buildSecrets: "" })} /> Clear configured build secrets</label>}</>}
      {(sourceForm.buildType === "nixpacks" || sourceForm.buildType === "buildpacks" || sourceForm.buildType === "heroku_buildpacks") && <label className="build-values wide">Build environment <span>Non-secret NAME=value entries passed to {sourceForm.buildType === "nixpacks" ? "Nixpacks" : sourceForm.buildType === "heroku_buildpacks" ? "Heroku Buildpacks" : "Paketo buildpacks"}; values may enter image metadata.</span><textarea className="compact-code" value={sourceForm.buildArguments} onChange={e => setSourceForm({ ...sourceForm, buildArguments: e.target.value })} placeholder="NODE_VERSION=24" spellCheck={false} /></label>}
      {sourceForm.buildType === "railpack" && <><label className="build-values">Build environment <span>{source?.hasBuildArguments ? "Configured values are hidden; leave blank to preserve them." : "Non-secret NAME=value entries."}</span><textarea className="compact-code" value={sourceForm.buildArguments} disabled={sourceForm.clearBuildArguments} onChange={e => setSourceForm({ ...sourceForm, buildArguments: e.target.value })} placeholder="NODE_VERSION=24" spellCheck={false} /></label><label className="build-values">BuildKit secrets <span>{source?.hasBuildSecrets ? "Configured values are hidden; leave blank to preserve them." : "Mounted only during Railpack build steps."}</span><textarea className="compact-code" value={sourceForm.buildSecrets} disabled={sourceForm.clearBuildSecrets} onChange={e => setSourceForm({ ...sourceForm, buildSecrets: e.target.value })} placeholder="NPM_TOKEN=…" spellCheck={false} /></label>{source?.hasBuildArguments && <label className="check clear-setting"><input type="checkbox" checked={sourceForm.clearBuildArguments} onChange={e => setSourceForm({ ...sourceForm, clearBuildArguments: e.target.checked, buildArguments: "" })} /> Clear configured build environment</label>}{source?.hasBuildSecrets && <label className="check clear-setting"><input type="checkbox" checked={sourceForm.clearBuildSecrets} onChange={e => setSourceForm({ ...sourceForm, clearBuildSecrets: e.target.checked, buildSecrets: "" })} /> Clear configured build secrets</label>}</>}
      {sourceForm.sourceType === "git" && <fieldset className="status-settings"><legend>Commit status callback (optional)</legend><label>Provider<select value={sourceForm.statusProvider} onChange={e => setSourceForm({ ...sourceForm, statusProvider: e.target.value, statusCredentialId: e.target.value ? sourceForm.statusCredentialId : "" })}><option value="">Disabled</option><option value="github">GitHub</option><option value="gitlab">GitLab</option><option value="gitea">Gitea</option><option value="bitbucket">Bitbucket</option></select></label><label>Provider token<select value={sourceForm.statusCredentialId} disabled={!sourceForm.statusProvider} required={Boolean(sourceForm.statusProvider)} onChange={e => setSourceForm({ ...sourceForm, statusCredentialId: e.target.value })}><option value="">Select credential</option>{credentials.filter(x => x.kind === "git").map(x => <option key={x.id} value={x.id}>{x.name} · {x.server}</option>)}</select></label><label>Status context<input value={sourceForm.statusContext} disabled={!sourceForm.statusProvider} onChange={e => setSourceForm({ ...sourceForm, statusContext: e.target.value })} placeholder="dockyard/deploy" /></label></fieldset>}
    </div></form> : <section className="card source-editor"><div className="card-head"><div><h3>Application build</h3><p className="muted">Read-only access. A developer grant is required to change this source.</p></div></div><code>{source ? `${source.buildType} · ${source.repositoryUrl || source.artifact?.filename || "uploaded source"}` : "No application source configured."}</code></section>}<ServiceSchedulePanel service={item} canWrite={canWrite} flash={flash} setError={setError} />{canWrite && <DeployTokenPanel service={item} flash={flash} setError={setError} />}<VolumeProtection service={item} canWrite={canWrite} canAdmin={canAdmin} flash={flash} setError={setError} /><section className="card logs"><div className="card-head"><h3>Service logs</h3><button onClick={() => action("logs")}>Load logs</button></div><pre>{logs || "Logs are loaded on demand to avoid unnecessary manager traffic."}</pre></section></>;
}

function ServiceTagPanel({ service, canWrite, canAdmin, refresh, flash, setError }: { service: Service; canWrite: boolean; canAdmin: boolean; refresh: () => Promise<void>; flash: (s: string) => void; setError: (s: string) => void }) {
  const [tags, setTags] = useState<Tag[]>([]); const [assigned, setAssigned] = useState<string[]>(service.tags?.map(tag => tag.id) ?? []); const [name, setName] = useState(""); const [color, setColor] = useState("#64748B"); const [busy, setBusy] = useState(false);
  const load = useCallback(async () => { const [catalog, selected] = await Promise.all([api.tags(), api.serviceTags(service.id)]); setTags(catalog.items); setAssigned(selected.items.map(tag => tag.id)); }, [service.id]);
  useEffect(() => { void load().catch(reason => setError(message(reason))); }, [load, setError]);
  async function create(event: FormEvent) { event.preventDefault(); setBusy(true); try { const tag = await api.createTag(name, color); await api.setServiceTags(service.id, [...assigned, tag.id]); setName(""); await load(); await refresh(); flash("Tag created and assigned"); } catch (reason) { setError(message(reason)); } finally { setBusy(false); } }
  async function toggle(tag: Tag) { const next = assigned.includes(tag.id) ? assigned.filter(id => id !== tag.id) : [...assigned, tag.id]; setBusy(true); try { await api.setServiceTags(service.id, next); setAssigned(next); await refresh(); flash("Service tags updated"); } catch (reason) { setError(message(reason)); } finally { setBusy(false); } }
  async function remove(tag: Tag) { if (!window.confirm(`Delete tag ${tag.name} from every service?`)) return; setBusy(true); try { await api.deleteTag(tag.id); await load(); await refresh(); flash("Tag deleted"); } catch (reason) { setError(message(reason)); } finally { setBusy(false); } }
  return <section className="card tag-panel"><div className="card-head"><div><p className="eyebrow">Organization metadata</p><h3>Service tags</h3><p className="muted">Reusable labels for inventory filtering and automation.</p></div></div>{canAdmin && <form onSubmit={create}><label>Name<input value={name} onChange={event => setName(event.target.value)} maxLength={64} required /></label><label>Color<input type="color" value={color} onChange={event => setColor(event.target.value.toUpperCase())} required /></label><button className="primary" disabled={busy}>Create and assign</button></form>}<div className="tag-options">{tags.map(tag => <span key={tag.id} className={assigned.includes(tag.id) ? "selected" : ""} style={{ borderColor: tag.color }}><button type="button" disabled={busy || !canWrite} onClick={() => void toggle(tag)}><i style={{ background: tag.color }} />{tag.name}<small>{tag.serviceCount} service{tag.serviceCount === 1 ? "" : "s"}</small></button>{canAdmin && <button type="button" className="tag-delete" aria-label={`Delete ${tag.name}`} disabled={busy} onClick={() => void remove(tag)}>×</button>}</span>)}{!tags.length && <p className="muted">No organization tags yet.</p>}</div></section>;
}

function ServiceNetworkPanel({ service, canWrite, refresh, flash, setError }: { service: Service; canWrite: boolean; refresh: () => Promise<void>; flash: (s: string) => void; setError: (s: string) => void }) {
  const [networks, setNetworks] = useState<ManagedNetwork[]>([]); const [assigned, setAssigned] = useState<string[]>([]); const [busy, setBusy] = useState(false);
  const load = useCallback(async () => { const [catalog, selected] = await Promise.all([api.networks(), api.serviceNetworks(service.id)]); setNetworks(catalog.items.filter(network => network.driver === "overlay")); setAssigned(selected.items.map(network => network.id)); }, [service.id]);
  useEffect(() => { void load().catch(reason => setError(message(reason))); }, [load, setError]);
  async function toggle(network: ManagedNetwork) { const next = assigned.includes(network.id) ? assigned.filter(id => id !== network.id) : [...assigned, network.id]; setBusy(true); try { await api.setServiceNetworks(service.id, next); setAssigned(next); await refresh(); flash("Service networks updated; deploy the new revision to apply them"); } catch (reason) { setError(message(reason)); } finally { setBusy(false); } }
  return <section className="card tag-panel"><div className="card-head"><div><p className="eyebrow">Connectivity</p><h3>Managed networks</h3><p className="muted">Attach every workload in this Compose stack to selected encrypted overlay networks.</p></div></div><div className="tag-options">{networks.map(network => <span key={network.id} className={assigned.includes(network.id) ? "selected" : ""}><button type="button" disabled={busy || !canWrite || network.status !== "ready"} onClick={() => void toggle(network)}>{network.name}<small>{network.status} · {network.clusterId ? "remote" : "local"}</small></button></span>)}{!networks.length && <p className="muted">No managed overlay networks are available.</p>}</div></section>;
}

const emptyRoute: RouteInput = { serviceName: "web", host: "", pathPrefix: "/", internalPath: "/", stripPath: false, enabled: true, redirectRegex: "", redirectReplacement: "", redirectPermanent: false, targetPort: 80, tls: true, certificateResolver: "letsencrypt" };

function RoutePanel({ service, routes, canWrite, refresh, flash, setError }: { service: Service; routes: Route[]; canWrite: boolean; refresh: () => Promise<void>; flash: (s: string) => void; setError: (s: string) => void }) {
  const [draft, setDraft] = useState<RouteInput>(emptyRoute); const [editingId, setEditingId] = useState(""); const [busy, setBusy] = useState(false); const [authUsers, setAuthUsers] = useState<RouteBasicAuthUser[]>([]); const [authUsername, setAuthUsername] = useState(""); const [authPassword, setAuthPassword] = useState("");
  const refreshAuth = useCallback(async () => setAuthUsers((await api.routeBasicAuthUsers(service.id)).items), [service.id]);
  useEffect(() => { void refreshAuth().catch(reason => setError(message(reason))); }, [refreshAuth, setError]);
  function edit(item: Route) { setEditingId(item.id); setDraft({ serviceName: item.serviceName, host: item.host, pathPrefix: item.pathPrefix, internalPath: item.internalPath, stripPath: item.stripPath, enabled: item.enabled, redirectRegex: item.redirectRegex, redirectReplacement: item.redirectReplacement, redirectPermanent: item.redirectPermanent, targetPort: item.targetPort, tls: item.tls, certificateResolver: item.certificateResolver }); }
  function clear() { setEditingId(""); setDraft(emptyRoute); }
  async function save(event: FormEvent) { event.preventDefault(); setBusy(true); try { if (editingId) await api.updateRoute(editingId, draft); else await api.createRoute(service.id, draft); await refresh(); flash(editingId ? "Route updated; deploy the revision to apply it" : "Route created; deploy the revision to apply it"); clear(); } catch (reason) { setError(message(reason)); } finally { setBusy(false); } }
  async function remove(item: Route) { if (!window.confirm(`Delete route ${item.host}${item.pathPrefix}?`)) return; setBusy(true); try { await api.deleteRoute(item.id); await refresh(); flash("Route deleted; deploy the revision to apply it"); if (editingId === item.id) clear(); } catch (reason) { setError(message(reason)); } finally { setBusy(false); } }
  async function toggle(item: Route) { setBusy(true); try { await api.updateRoute(item.id, { serviceName: item.serviceName, host: item.host, pathPrefix: item.pathPrefix, internalPath: item.internalPath, stripPath: item.stripPath, enabled: !item.enabled, redirectRegex: item.redirectRegex, redirectReplacement: item.redirectReplacement, redirectPermanent: item.redirectPermanent, targetPort: item.targetPort, tls: item.tls, certificateResolver: item.certificateResolver }); await refresh(); flash(item.enabled ? "Route disabled" : "Route enabled"); } catch (reason) { setError(message(reason)); } finally { setBusy(false); } }
  async function addAuth(event: FormEvent) { event.preventDefault(); setBusy(true); try { await api.createRouteBasicAuthUser(service.id, authUsername, authPassword); setAuthUsername(""); setAuthPassword(""); await refreshAuth(); flash("Basic-auth user added; deploy the revision to apply it"); } catch (reason) { setError(message(reason)); } finally { setBusy(false); } }
  async function rotateAuth(item: RouteBasicAuthUser) { const password = window.prompt(`Enter a new password for ${item.username}.`); if (!password) return; setBusy(true); try { await api.updateRouteBasicAuthUser(service.id, item.id, item.username, password); await refreshAuth(); flash("Basic-auth password rotated; deploy the revision to apply it"); } catch (reason) { setError(message(reason)); } finally { setBusy(false); } }
  async function removeAuth(item: RouteBasicAuthUser) { if (!window.confirm(`Remove HTTP basic-auth user ${item.username}?`)) return; setBusy(true); try { await api.deleteRouteBasicAuthUser(service.id, item.id); await refreshAuth(); flash("Basic-auth user removed; deploy the revision to apply it"); } catch (reason) { setError(message(reason)); } finally { setBusy(false); } }
  return <section className="card route-panel"><div className="card-head"><div><p className="eyebrow">Ingress</p><h3>Domains and routes</h3><p className="muted">Expose Compose services through Traefik, rewrite paths, or attach a regex redirect.</p></div></div>
    {canWrite && <form className="route-form" onSubmit={save}><label>Compose service<input value={draft.serviceName} onChange={event => setDraft({ ...draft, serviceName: event.target.value })} required /></label><label>Hostname<input value={draft.host} onChange={event => setDraft({ ...draft, host: event.target.value })} placeholder="app.example.com" required /></label><label>Public path<input value={draft.pathPrefix} onChange={event => setDraft({ ...draft, pathPrefix: event.target.value })} required /></label><label>Target port<input type="number" min="1" max="65535" value={draft.targetPort} onChange={event => setDraft({ ...draft, targetPort: Number(event.target.value) })} required /></label><label>Internal path<input value={draft.internalPath} onChange={event => setDraft({ ...draft, internalPath: event.target.value })} required /></label><label>Certificate resolver<input value={draft.certificateResolver} disabled={!draft.tls} onChange={event => setDraft({ ...draft, certificateResolver: event.target.value })} required={draft.tls} /></label><label className="check"><input type="checkbox" checked={draft.tls} onChange={event => setDraft({ ...draft, tls: event.target.checked })} /> TLS</label><label className="check"><input type="checkbox" checked={draft.enabled} onChange={event => setDraft({ ...draft, enabled: event.target.checked })} /> Enabled</label><label className="check"><input type="checkbox" checked={draft.stripPath} disabled={draft.pathPrefix === "/"} onChange={event => setDraft({ ...draft, stripPath: event.target.checked })} /> Strip public path</label><label className="wide">Redirect regex<input value={draft.redirectRegex} onChange={event => setDraft({ ...draft, redirectRegex: event.target.value })} placeholder="^https://app.example.com/old/(.*)" /></label><label className="wide">Redirect replacement<input value={draft.redirectReplacement} onChange={event => setDraft({ ...draft, redirectReplacement: event.target.value })} placeholder={'https://app.example.com/new/${1}'} required={Boolean(draft.redirectRegex)} /></label><label className="check"><input type="checkbox" checked={draft.redirectPermanent} disabled={!draft.redirectRegex} onChange={event => setDraft({ ...draft, redirectPermanent: event.target.checked })} /> Permanent redirect</label><div className="actions">{editingId && <button type="button" onClick={clear}>Cancel edit</button>}<button className="primary" disabled={busy}>{editingId ? "Save route" : "Add route"}</button></div></form>}
    <div className="route-list">{routes.map(item => <article key={item.id}><div><strong>{item.tls ? "https" : "http"}://{item.host}{item.pathPrefix}</strong><small>→ {item.serviceName}:{item.targetPort}{item.stripPath ? " · strip public path" : ""}{item.internalPath !== "/" ? ` · prepend ${item.internalPath}` : ""}{item.redirectRegex ? ` · ${item.redirectPermanent ? "301" : "302"} redirect` : ""}{authUsers.length ? " · basic auth" : ""}</small></div><Status value={item.enabled ? "active" : "disabled"} />{canWrite && <div className="actions"><button disabled={busy} onClick={() => edit(item)}>Edit</button><button disabled={busy} onClick={() => void toggle(item)}>{item.enabled ? "Disable" : "Enable"}</button><button className="danger-button" disabled={busy} onClick={() => void remove(item)}>Delete</button></div>}</article>)}{!routes.length && <p className="muted">No public routes configured.</p>}</div>
    <div className="route-auth"><div><h4>HTTP basic auth</h4><p className="muted">Credentials protect every enabled route. Passwords are bcrypt-hashed and never returned.</p></div>{canWrite && <form onSubmit={addAuth}><label>Username<input value={authUsername} onChange={event => setAuthUsername(event.target.value)} required maxLength={128} /></label><label>Password<input type="password" value={authPassword} onChange={event => setAuthPassword(event.target.value)} required maxLength={72} autoComplete="new-password" /></label><button className="primary" disabled={busy}>Add user</button></form>}<div className="route-list">{authUsers.map(item => <article key={item.id}><div><strong>{item.username}</strong><small>Updated {new Date(item.updatedAt).toLocaleString()}</small></div><Status value="active" />{canWrite && <div className="actions"><button disabled={busy} onClick={() => void rotateAuth(item)}>Rotate password</button><button className="danger-button" disabled={busy} onClick={() => void removeAuth(item)}>Remove</button></div>}</article>)}{!authUsers.length && <p className="muted">No basic-auth users configured.</p>}</div></div>
  </section>;
}

const emptySchedule: ServiceScheduleInput = { name: "", description: "", cronExpression: "0 * * * *", timezone: "UTC", targetService: "", shell: "sh", command: "", timeoutSeconds: 900, enabled: true };

function ServiceSchedulePanel({ service, canWrite, flash, setError }: { service: Service; canWrite: boolean; flash: (s: string) => void; setError: (s: string) => void }) {
  const [schedules, setSchedules] = useState<ServiceSchedule[]>([]); const [executions, setExecutions] = useState<ServiceScheduleExecution[]>([]); const [draft, setDraft] = useState<ServiceScheduleInput>(emptySchedule); const [editingId, setEditingId] = useState(""); const [busy, setBusy] = useState(false);
  const refresh = useCallback(async () => { const [scheduleResult, executionResult] = await Promise.all([api.serviceSchedules(service.id), api.serviceScheduleExecutions(service.id)]); setSchedules(scheduleResult.items); setExecutions(executionResult.items); }, [service.id]);
  useEffect(() => { void refresh().catch(reason => setError(message(reason))); const timer = window.setInterval(() => void refresh().catch(() => undefined), 5000); return () => window.clearInterval(timer); }, [refresh, setError]);
  async function run(action: () => Promise<unknown>, success: string) { setBusy(true); try { await action(); await refresh(); flash(success); } catch (reason) { setError(message(reason)); } finally { setBusy(false); } }
  function edit(item: ServiceSchedule) { setEditingId(item.id); setDraft({ name: item.name, description: item.description, cronExpression: item.cronExpression, timezone: item.timezone, targetService: item.targetService, shell: item.shell, command: item.command, timeoutSeconds: item.timeoutSeconds, enabled: item.enabled }); }
  function clear() { setEditingId(""); setDraft(emptySchedule); }
  async function save(event: FormEvent) { event.preventDefault(); const editing = Boolean(editingId); await run(() => editing ? api.updateServiceSchedule(service.id, editingId, draft) : api.createServiceSchedule(service.id, draft), editing ? "Schedule updated" : "Schedule created"); clear(); }
  async function toggle(item: ServiceSchedule) { await run(() => api.updateServiceSchedule(service.id, item.id, { name: item.name, description: item.description, cronExpression: item.cronExpression, timezone: item.timezone, targetService: item.targetService, shell: item.shell, command: item.command, timeoutSeconds: item.timeoutSeconds, enabled: !item.enabled }), item.enabled ? "Schedule disabled" : "Schedule enabled"); }
  return <section className="card schedule-panel"><div className="card-head"><div><p className="eyebrow">Automation</p><h3>Scheduled commands</h3><p className="muted">Run bounded one-shot commands inside a cloned Swarm service definition.</p></div><button type="button" disabled={busy} onClick={() => void refresh().catch(reason => setError(message(reason)))}>Refresh</button></div>
    {canWrite && <form className="schedule-form" onSubmit={save}><label>Name<input value={draft.name} onChange={event => setDraft({ ...draft, name: event.target.value })} required maxLength={120} /></label><label>Target Compose service<input value={draft.targetService} onChange={event => setDraft({ ...draft, targetService: event.target.value })} placeholder="web" required /></label><label>Cron<input value={draft.cronExpression} onChange={event => setDraft({ ...draft, cronExpression: event.target.value })} placeholder="0 * * * *" required /></label><label>Timezone<input value={draft.timezone} onChange={event => setDraft({ ...draft, timezone: event.target.value })} placeholder="UTC" required /></label><label>Shell<select value={draft.shell} onChange={event => setDraft({ ...draft, shell: event.target.value as "sh" | "bash" })}><option value="sh">sh</option><option value="bash">bash</option></select></label><label>Timeout (seconds)<input type="number" min="1" max="86400" value={draft.timeoutSeconds} onChange={event => setDraft({ ...draft, timeoutSeconds: Number(event.target.value) })} /></label><label className="wide">Description<input value={draft.description} onChange={event => setDraft({ ...draft, description: event.target.value })} maxLength={1000} /></label><label className="wide">Command<textarea className="compact-code" value={draft.command} onChange={event => setDraft({ ...draft, command: event.target.value })} required maxLength={16384} spellCheck={false} /></label><label className="check"><input type="checkbox" checked={draft.enabled} onChange={event => setDraft({ ...draft, enabled: event.target.checked })} /> Enabled</label><div className="actions">{editingId && <button type="button" onClick={clear}>Cancel edit</button>}<button className="primary" disabled={busy}>{editingId ? "Save changes" : "Add schedule"}</button></div></form>}
    <div className="schedule-list"><h4>Schedules</h4>{schedules.map(item => <article key={item.id}><div><strong>{item.name}</strong><small>{item.cronExpression} · {item.timezone} · {item.targetService} · next {new Date(item.nextRunAt).toLocaleString()}</small><code>{item.shell} -c {item.command}</code></div><Status value={item.enabled ? "active" : "disabled"} />{canWrite && <div className="actions"><button disabled={busy} onClick={() => edit(item)}>Edit</button><button disabled={busy} onClick={() => void toggle(item)}>{item.enabled ? "Disable" : "Enable"}</button><button disabled={busy || service.desiredState === "stopped"} onClick={() => void run(() => api.runServiceSchedule(service.id, item.id), "Command queued")}>Run now</button><button className="danger-button" disabled={busy} onClick={() => window.confirm(`Delete ${item.name}? Pending executions will be cancelled.`) && void run(() => api.deleteServiceSchedule(service.id, item.id), "Schedule deleted")}>Delete</button></div>}</article>)}{!schedules.length && <p className="muted">No scheduled commands configured.</p>}</div>
    <div className="schedule-list execution-list"><h4>Recent executions</h4>{executions.map(item => <article key={item.id}><div><strong>{item.scheduleName}</strong><small>{new Date(item.createdAt).toLocaleString()} · {item.trigger} · {item.targetService}</small>{item.output && <pre>{item.output}</pre>}{item.error && <pre className="error">{item.error}</pre>}</div><Status value={item.status} />{canWrite && (item.status === "pending" || item.status === "running") && <button disabled={busy} onClick={() => void run(() => api.cancelServiceScheduleExecution(service.id, item.id), "Cancellation requested")}>Cancel</button>}</article>)}{!executions.length && <p className="muted">No command executions yet.</p>}</div>
  </section>;
}

type CreatedDeployToken = { name: string; token: string; url: string; expiresAt: string };

function DeployTokenPanel({ service, flash, setError }: { service: Service; flash: (s: string) => void; setError: (s: string) => void }) {
  const [tokens, setTokens] = useState<DeployToken[]>([]);
  const [name, setName] = useState("ci-release");
  const [expiresInDays, setExpiresInDays] = useState(90);
  const [created, setCreated] = useState<CreatedDeployToken | null>(null);
  const [busy, setBusy] = useState(false);
  const refresh = useCallback(async () => setTokens((await api.deployTokens(service.id)).items), [service.id]);

  useEffect(() => {
    setCreated(null);
    refresh().catch(reason => setError(message(reason)));
  }, [refresh, setError]);

  async function create(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      const result = await api.createDeployToken(service.id, name.trim(), expiresInDays);
      setCreated({ name: result.deployToken.name, token: result.token, url: result.url, expiresAt: result.deployToken.expiresAt });
      setName("ci-release");
      await refresh();
      flash("Deployment hook created");
    } catch (reason) { setError(message(reason)); } finally { setBusy(false); }
  }

  async function revoke(token: DeployToken) {
    if (!window.confirm(`Revoke the deployment hook “${token.name}”? CI jobs using it will stop working immediately.`)) return;
    setBusy(true);
    try {
      await api.revokeDeployToken(service.id, token.id);
      await refresh();
      flash("Deployment hook revoked");
    } catch (reason) { setError(message(reason)); } finally { setBusy(false); }
  }

  return <section className="card deploy-token-panel">
    <div className="card-head"><div><p className="eyebrow">CI/CD access</p><h3>Deployment hooks</h3><p className="muted">Issue expiring, revocable URLs that can only queue a deployment for this service.</p></div><button type="button" disabled={busy} onClick={() => void refresh().catch(reason => setError(message(reason)))}>Refresh</button></div>
    {created && <section className="credential-card deploy-token-secret"><p className="eyebrow">Copy now · shown once</p><h3>{created.name}</h3><p className="muted">Store this URL in your CI secret manager. It cannot be recovered after you dismiss or leave this page. Expires {new Date(created.expiresAt).toLocaleString()}.</p><code>{created.url}</code><div className="secret"><span>Bearer token (use the URL above unless your integration needs the raw value)</span><code>{created.token}</code></div><div className="actions"><button type="button" onClick={() => void navigator.clipboard.writeText(created.url)}>Copy URL</button><button type="button" onClick={() => void navigator.clipboard.writeText(created.token)}>Copy token</button><button type="button" onClick={() => setCreated(null)}>I saved it</button></div></section>}
    <form className="deploy-token-form" onSubmit={create}><label>Name<input value={name} maxLength={100} onChange={event => setName(event.target.value)} required autoComplete="off" /></label><label>Lifetime (days)<input type="number" min="1" max="365" value={expiresInDays} onChange={event => setExpiresInDays(Number(event.target.value))} required /></label><button className="primary" disabled={busy || expiresInDays < 1 || expiresInDays > 365}>{busy ? "Working…" : "Create hook"}</button></form>
    <div className="admin-items deploy-token-list">{tokens.map(token => { const expired = new Date(token.expiresAt) <= new Date(); const status = token.revokedAt ? "revoked" : expired ? "expired" : "active"; return <article key={token.id}><div><strong>{token.name}</strong><small>Created {new Date(token.createdAt).toLocaleString()} · expires {new Date(token.expiresAt).toLocaleString()}{token.lastUsedAt ? ` · last used ${new Date(token.lastUsedAt).toLocaleString()}` : " · never used"}</small></div><Status value={status} />{!token.revokedAt && <button type="button" className="danger-button" disabled={busy} onClick={() => void revoke(token)}>Revoke</button>}</article>; })}{!tokens.length && <p className="muted">No deployment hooks issued.</p>}</div>
  </section>;
}

function VolumeProtection({ service, canWrite, canAdmin, flash, setError }: { service: Service; canWrite: boolean; canAdmin: boolean; flash: (s: string) => void; setError: (s: string) => void }) {
  const [volumes, setVolumes] = useState<ServiceVolume[]>([]);
  const [policies, setPolicies] = useState<VolumeBackupPolicy[]>([]);
  const [backups, setBackups] = useState<VolumeBackup[]>([]);
  const [restores, setRestores] = useState<VolumeRestore[]>([]);
  const [destinations, setDestinations] = useState<BackupDestination[]>([]);
  const [volumeName, setVolumeName] = useState("");
  const [destinationId, setDestinationId] = useState("");
  const [intervalSeconds, setIntervalSeconds] = useState(86400);
  const [retentionCount, setRetentionCount] = useState(14);
  const [quiesce, setQuiesce] = useState(true);
  const [enabled, setEnabled] = useState(true);
  const [busy, setBusy] = useState(false);
  const refresh = useCallback(async () => {
    const [volumeResult, policyResult, backupResult, restoreResult, destinationResult] = await Promise.all([
      api.serviceVolumes(service.id), api.volumeBackupPolicies(service.id), api.volumeBackups(service.id), api.volumeRestores(service.id),
      canAdmin ? api.backupDestinations() : Promise.resolve({ items: [] as BackupDestination[] }),
    ]);
    setVolumes(volumeResult.items); setPolicies(policyResult.items); setBackups(backupResult.items); setRestores(restoreResult.items); setDestinations(destinationResult.items);
    setVolumeName(current => volumeResult.items.some(item => item.name === current) ? current : volumeResult.items[0]?.name ?? "");
  }, [service.id, canAdmin]);
  useEffect(() => { void refresh().catch(reason => setError(message(reason))); }, [refresh, setError]);
  useEffect(() => {
    const policy = policies.find(item => item.volumeName === volumeName);
    setDestinationId(policy?.destinationId ?? destinations[0]?.id ?? "");
    setIntervalSeconds(policy?.intervalSeconds ?? 86400); setRetentionCount(policy?.retentionCount ?? 14); setQuiesce(policy?.quiesce ?? true); setEnabled(policy?.enabled ?? true);
  }, [volumeName, policies, destinations]);
  async function run(task: () => Promise<unknown>, success: string) { setBusy(true); try { await task(); await refresh(); flash(success); } catch (reason) { setError(message(reason)); } finally { setBusy(false); } }
  async function savePolicy(event: FormEvent) { event.preventDefault(); if (!volumeName || !destinationId) return; await run(() => api.putVolumeBackupPolicy(service.id, volumeName, { destinationId, intervalSeconds, retentionCount, quiesce, enabled }), "Volume backup policy saved"); }
  async function restore(backup: VolumeBackup) {
    const confirmation = window.prompt(`Restore ${backup.volumeName}? This stops every service mounting the volume and replaces its contents. Type ${service.slug} to continue.`);
    if (confirmation !== service.slug) { if (confirmation !== null) setError("Restore confirmation did not match the service slug"); return; }
    await run(() => api.restoreVolumeBackup(backup.id, confirmation), "Volume restore queued");
  }
  if (!volumes.length) return <section className="card volume-protection"><div><p className="eyebrow">Persistent data</p><h3>No named volumes</h3><p className="muted">Add a top-level Compose volume and mount it from a service to enable encrypted backups.</p></div></section>;
  const selectedPolicy = policies.find(item => item.volumeName === volumeName);
  return <section className="card volume-protection"><div className="card-head"><div><p className="eyebrow">Persistent data</p><h3>Named-volume protection</h3><p className="muted">Encrypted S3 backups run on the Swarm node that owns the volume. Restores always stop mounting services first.</p></div><button type="button" disabled={busy} onClick={() => void refresh().catch(reason => setError(message(reason)))}>Refresh</button></div>
    <div className="volume-layout"><div><h3>Volumes</h3>{volumes.map(volume => <article className={volume.name === volumeName ? "selected" : ""} key={volume.name} onClick={() => setVolumeName(volume.name)}><div><strong>{volume.name}</strong><small>{volume.dockerName}{volume.storageNodeId ? ` · ${volume.storageNodeId}` : " · node assigned when protected"}</small></div><Status value={policies.find(policy => policy.volumeName === volume.name)?.enabled ? "active" : "unprotected"} />{canWrite && policies.some(policy => policy.volumeName === volume.name) && <button disabled={busy} onClick={event => { event.stopPropagation(); void run(() => api.backupVolume(service.id, volume.name), "Volume backup queued"); }}>Back up</button>}</article>)}</div>
      <div><h3>Backups</h3>{backups.map(backup => <article key={backup.id}><div><strong>{backup.volumeName}</strong><small>{new Date(backup.createdAt).toLocaleString()}{backup.sizeBytes ? ` · ${(backup.sizeBytes / 1048576).toFixed(1)} MiB` : ""}</small>{backup.sha256 && <small>SHA-256 {backup.sha256.slice(0, 12)}…</small>}{backup.error && <small className="error">{backup.error}</small>}</div><Status value={backup.status} />{canWrite && (backup.status === "queued" || backup.status === "running") && <button disabled={busy} onClick={() => void run(() => api.cancelVolumeBackup(backup.id), "Backup cancellation requested")}>Cancel</button>}{canAdmin && backup.status === "succeeded" && <button className="danger-button" disabled={busy} onClick={() => void restore(backup)}>Restore</button>}</article>)}{!backups.length && <p className="muted">No volume backups yet.</p>}</div>
      <div><h3>Restores</h3>{restores.map(restore => <article key={restore.id}><div><strong>{restore.volumeBackupId.slice(0, 12)}…</strong><small>{new Date(restore.createdAt).toLocaleString()}</small>{restore.error && <small className="error">{restore.error}</small>}</div><Status value={restore.status} />{canAdmin && (restore.status === "queued" || restore.status === "running") && <button disabled={busy} onClick={() => void run(() => api.cancelVolumeRestore(restore.id), "Restore cancellation requested")}>Cancel</button>}</article>)}{!restores.length && <p className="muted">No restore attempts yet.</p>}</div></div>
    {canAdmin && <form className="volume-policy" onSubmit={savePolicy}><label>Volume<select value={volumeName} onChange={event => setVolumeName(event.target.value)}>{volumes.map(volume => <option key={volume.name} value={volume.name}>{volume.name}</option>)}</select></label><label>Destination<select value={destinationId} onChange={event => setDestinationId(event.target.value)} required><option value="">Select S3 destination</option>{destinations.map(destination => <option key={destination.id} value={destination.id}>{destination.name}</option>)}</select></label><label>Interval (seconds)<input type="number" min="900" max="2678400" value={intervalSeconds} onChange={event => setIntervalSeconds(Number(event.target.value))} /></label><label>Retain<input type="number" min="1" max="100" value={retentionCount} onChange={event => setRetentionCount(Number(event.target.value))} /></label><label className="check"><input type="checkbox" checked={quiesce} onChange={event => setQuiesce(event.target.checked)} /> Pause writers during backup</label><label className="check"><input type="checkbox" checked={enabled} onChange={event => setEnabled(event.target.checked)} /> Scheduled backups enabled</label><div className="actions">{selectedPolicy && <button type="button" className="danger-button" disabled={busy} onClick={() => window.confirm(`Delete the backup policy for ${volumeName}? Existing backups are retained.`) && void run(() => api.deleteVolumeBackupPolicy(service.id, volumeName), "Volume backup policy deleted")}>Delete policy</button>}<button className="primary" disabled={busy || !destinationId}>Save policy</button></div></form>}
  </section>;
}

function Templates({ environmentId, canWrite, canAdmin, reloadServices, flash, setError }: { environmentId: string; canWrite: boolean; canAdmin: boolean; reloadServices: () => Promise<void>; flash: (s: string) => void; setError: (s: string) => void }) {
  const [items, setItems] = useState<Template[]>([]); const [query, setQuery] = useState("");
  const [nextCursor, setNextCursor] = useState(""); const [loadingMore, setLoadingMore] = useState(false);
  const emptyRepository = { name: "", slug: "", repositoryUrl: "https://github.com/", gitRef: "main", catalogPath: "", trustedPublicKey: "", requireSignature: true, credentialId: "", syncIntervalSeconds: 3600 };
  const [repositories, setRepositories] = useState<TemplateRepository[]>([]); const [credentials, setCredentials] = useState<SourceCredential[]>([]); const [repository, setRepository] = useState(emptyRepository);
  const [selected, setSelected] = useState<Template | null>(null); const [name, setName] = useState(""); const [baseDomain, setBaseDomain] = useState(""); const [values, setValues] = useState<Record<string, string>>({}); const [preview, setPreview] = useState<TemplatePreview | null>(null); const [webhook, setWebhook] = useState<{ repository: string; url: string; secret: string } | null>(null); const [busy, setBusy] = useState(false);
  const reloadCatalog = useCallback(async () => { const [templates, sources, credentialResult] = await Promise.all([api.templates(), canAdmin ? api.templateRepositories() : Promise.resolve({ items: [] }), canAdmin ? api.sourceCredentials() : Promise.resolve({ items: [] })]); setItems(templates.items); setNextCursor(templates.nextCursor); setRepositories(sources.items); setCredentials(credentialResult.items.filter(item => item.kind === "git" && item.server.split(":")[0] === "github.com")); }, [canAdmin]);
  useEffect(() => { void reloadCatalog().catch(reason => setError(message(reason))); }, [reloadCatalog, setError]);
  function open(template: Template) { if (!template.deployable) { setError(template.safetyClass === "invalid" ? `This catalog entry is not deployable: ${template.safetyReason || "invalid template"}` : `This template requires unsafe-workload mode: ${template.safetyReason || "restricted Compose capabilities"}`); return; } if (!environmentId) { setError("Select an environment under Workloads first"); return; } setSelected(template); setName(template.name); setBaseDomain(""); setPreview(null); setValues(Object.fromEntries(template.variables.filter(variable => variable.default !== undefined).map(variable => [variable.name, variable.default ?? ""]))); }
  function configuredVariables() { return Object.fromEntries(Object.entries(values).filter(([, value]) => value !== "")); }
  async function loadPreview() { if (!selected) return; setBusy(true); try { const result = await api.previewTemplate(selected.id, { baseDomain, variables: configuredVariables() }); setPreview(result.preview); } catch (reason) { setError(message(reason)); } finally { setBusy(false); } }
  async function instantiate(event: FormEvent) { event.preventDefault(); if (!selected || !environmentId) return; setBusy(true); try { await api.instantiateTemplate(selected.id, { environmentId, name, baseDomain, variables: configuredVariables() }); await reloadServices(); flash(`${selected.name} instantiated`); setSelected(null); } catch (reason) { setError(message(reason)); } finally { setBusy(false); } }
  async function addRepository(event: FormEvent) { event.preventDefault(); setBusy(true); try { await api.createTemplateRepository(repository); await reloadCatalog(); setRepository(emptyRepository); flash("Template repository registered"); } catch (reason) { setError(message(reason)); } finally { setBusy(false); } }
  async function syncRepository(id: string) { setBusy(true); try { await api.syncTemplateRepository(id); await reloadCatalog(); flash("Template repository sync queued"); } catch (reason) { setError(message(reason)); } finally { setBusy(false); } }
  async function updateRepository(item: TemplateRepository, changes: { credentialId?: string; syncIntervalSeconds?: number }) { setBusy(true); try { await api.updateTemplateRepository(item.id, { trustedPublicKey: item.trustedPublicKey ?? "", requireSignature: item.requireSignature, credentialId: changes.credentialId ?? item.credentialId ?? "", syncIntervalSeconds: changes.syncIntervalSeconds ?? item.syncIntervalSeconds }); await reloadCatalog(); flash("Template repository settings updated"); } catch (reason) { setError(message(reason)); } finally { setBusy(false); } }
  async function rotateRepositoryWebhook(item: TemplateRepository) { if (item.webhookConfigured && !window.confirm(`Rotate the webhook secret for ${item.name}? Existing deliveries will stop authenticating immediately.`)) return; setBusy(true); try { const created = await api.rotateTemplateRepositoryWebhook(item.id); setWebhook({ repository: item.name, ...created }); await reloadCatalog(); flash("Webhook secret created"); } catch (reason) { setError(message(reason)); } finally { setBusy(false); } }
  async function disableRepositoryWebhook(item: TemplateRepository) { if (!window.confirm(`Disable webhook refresh for ${item.name}?`)) return; setBusy(true); try { await api.disableTemplateRepositoryWebhook(item.id); setWebhook(null); await reloadCatalog(); flash("Webhook refresh disabled"); } catch (reason) { setError(message(reason)); } finally { setBusy(false); } }
  async function removeRepository(id: string) { setBusy(true); try { await api.deleteTemplateRepository(id); await reloadCatalog(); flash("Template repository removed"); } catch (reason) { setError(message(reason)); } finally { setBusy(false); } }
  async function loadMore() { if (!nextCursor || loadingMore) return; setLoadingMore(true); try { const page = await api.templates(nextCursor); setItems(current => [...current, ...page.items.filter(item => !current.some(existing => existing.id === item.id))]); setNextCursor(page.nextCursor); } catch (reason) { setError(message(reason)); } finally { setLoadingMore(false); } }
  const filtered = items.filter(x => `${x.name} ${x.description}`.toLowerCase().includes(query.toLowerCase()));
  return <>{canAdmin && <section className="card repository-panel"><div><p className="eyebrow">Catalog federation</p><h2>Template repositories</h2><p className="muted">Import namespaced Docker Compose templates from Dokploy-compatible GitHub repositories.</p></div>{webhook && <section className="credential-card"><p className="eyebrow">Save once · {webhook.repository}</p><h3>GitHub webhook</h3><p className="muted">Use JSON content and the push event. This secret is never shown again.</p><code>{webhook.url}</code><div className="secret"><span>Secret</span><code>{webhook.secret}</code></div><div className="actions"><button type="button" onClick={() => void navigator.clipboard.writeText(webhook.url)}>Copy URL</button><button type="button" onClick={() => void navigator.clipboard.writeText(webhook.secret)}>Copy secret</button><button type="button" onClick={() => setWebhook(null)}>Dismiss</button></div></section>}<form onSubmit={addRepository}><label>Name<input value={repository.name} onChange={e => setRepository({ ...repository, name: e.target.value })} required /></label><label>Slug<input value={repository.slug} onChange={e => setRepository({ ...repository, slug: e.target.value.toLowerCase() })} required pattern="[a-z0-9][a-z0-9-]{0,62}" /></label><label className="wide">GitHub URL<input type="url" value={repository.repositoryUrl} onChange={e => setRepository({ ...repository, repositoryUrl: e.target.value })} required /></label><label>Git ref<input value={repository.gitRef} onChange={e => setRepository({ ...repository, gitRef: e.target.value })} required /></label><label>Catalog path<input value={repository.catalogPath} onChange={e => setRepository({ ...repository, catalogPath: e.target.value })} placeholder="optional/subdirectory" /></label><label>Automatic sync<select value={repository.syncIntervalSeconds} onChange={e => setRepository({ ...repository, syncIntervalSeconds: Number(e.target.value) })}><option value={0}>Manual only</option><option value={900}>Every 15 minutes</option><option value={3600}>Hourly</option><option value={21600}>Every 6 hours</option><option value={86400}>Daily</option></select></label><label>GitHub credential<select value={repository.credentialId} onChange={e => setRepository({ ...repository, credentialId: e.target.value })}><option value="">Public repository</option>{credentials.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label><label className="wide">Trusted Ed25519 public key<textarea value={repository.trustedPublicKey} onChange={e => setRepository({ ...repository, trustedPublicKey: e.target.value })} placeholder="PEM or base64 public key" required={repository.requireSignature} /></label><label className="check wide"><input type="checkbox" checked={repository.requireSignature} onChange={e => setRepository({ ...repository, requireSignature: e.target.checked })} /> Require a valid signed catalog manifest</label><button className="primary" disabled={busy}>Add repository</button></form><div className="admin-items">{repositories.map(item => <article key={item.id}><div><strong>{item.name}</strong><small>{item.repositoryUrl}@{item.gitRef} · {item.requireSignature ? "signature required" : item.trustedPublicKey ? "signature verified when present" : "unsigned"} · {item.syncIntervalSeconds ? `sync every ${item.syncIntervalSeconds / 60} min` : "manual sync"} · {item.lastSyncStatus}{item.lastSyncError ? ` · ${item.lastSyncError}` : ""}</small></div><div className="actions"><select aria-label={`Credential for ${item.name}`} disabled={busy} value={item.credentialId ?? ""} onChange={event => void updateRepository(item, { credentialId: event.target.value })}><option value="">Public</option>{credentials.map(credential => <option key={credential.id} value={credential.id}>{credential.name}</option>)}</select><select aria-label={`Automatic sync for ${item.name}`} disabled={busy} value={item.syncIntervalSeconds} onChange={event => void updateRepository(item, { syncIntervalSeconds: Number(event.target.value) })}><option value={0}>Manual</option><option value={900}>15 min</option><option value={3600}>Hourly</option><option value={21600}>6 hours</option><option value={86400}>Daily</option></select><button disabled={busy} onClick={() => void syncRepository(item.id)}>Sync</button><button disabled={busy} onClick={() => void rotateRepositoryWebhook(item)}>{item.webhookConfigured ? "Rotate webhook" : "Add webhook"}</button>{item.webhookConfigured && <button disabled={busy} onClick={() => void disableRepositoryWebhook(item)}>Disable webhook</button>}<button className="danger-button" disabled={busy} onClick={() => window.confirm(`Remove ${item.name} and its catalog entries?`) && void removeRepository(item.id)}>Remove</button></div></article>)}</div></section>}<section className="toolbar card"><label className="grow">Search loaded catalog<input placeholder="Postgres, analytics, monitoring…" value={query} onChange={e => setQuery(e.target.value)} /></label><span className="count">{filtered.length} loaded{nextCursor ? "+" : ""}</span><a className="button-link" href="https://github.com/GhaziBenDahmane/Orka/issues/new?template=template-request.yml" target="_blank" rel="noreferrer">Suggest a template ↗</a></section><div className="grid template-grid">{filtered.map(x => <article className="card template-card" key={x.id}><span className="tag">{x.safetyClass === "requires_unsafe" ? "restricted" : x.source}</span><h3>{x.name}</h3><p>{x.description || "Deploy this application from the shared catalog."}</p><small>{x.key} · {x.version}{x.variables.length ? ` · ${x.variables.length} inputs` : ""}</small>{x.safetyClass === "requires_unsafe" && <small className="error">Requires unsafe-workload mode · {x.safetyReason}</small>}<button disabled={!canWrite || !environmentId || !x.deployable} title={!x.deployable ? x.safetyReason : undefined} onClick={() => open(x)}>Use template →</button></article>)}</div>{nextCursor && <section className="actions"><button disabled={loadingMore} onClick={() => void loadMore()}>{loadingMore ? "Loading…" : "Load more templates"}</button></section>}{selected && <div className="modal-backdrop" onMouseDown={event => event.target === event.currentTarget && !busy && setSelected(null)}><form className="modal card template-dialog" onSubmit={instantiate}><div className="modal-head"><div><p className="eyebrow">Template configuration</p><h2>{selected.name}</h2></div><button type="button" className="icon-button" disabled={busy} onClick={() => setSelected(null)}>×</button></div><p className="muted">Review catalog defaults and optionally replace generated values. Secret inputs remain encrypted and are never shown again.</p><div className="template-fields"><label>Service name<input autoFocus value={name} onChange={event => setName(event.target.value)} required maxLength={120} /></label><label>Base domain <span>Used by generated hostnames</span><input value={baseDomain} onChange={event => { setBaseDomain(event.target.value); setPreview(null); }} placeholder="apps.example.com" maxLength={253} /></label>{selected.variables.map(variable => <label key={variable.name}>{variable.name} {variable.sensitive && <span>Secret</span>}<input type={variable.sensitive ? "password" : "text"} value={values[variable.name] ?? ""} onChange={event => { setValues({ ...values, [variable.name]: event.target.value }); setPreview(null); }} placeholder={variable.generated ? "Leave blank to generate" : variable.sensitive ? "Leave blank to use catalog value" : "Optional override"} maxLength={8192} autoComplete="off" /><small>{variable.generated ? "Generated separately for this service when left blank." : variable.sensitive ? "The catalog value is hidden." : "Catalog default shown above; edit to override."}</small></label>)}</div>{preview && <section className="template-preview"><strong>Validated topology</strong><p>{preview.services.map(service => `${service.name}${service.image ? ` (${service.image})` : ""}`).join(", ")}</p>{preview.routes.map(route => <small key={`${route.host}${route.path}`}>https://{route.host}{route.path} → {route.serviceName}:{route.targetPort}</small>)}<small>Environment keys: {preview.environmentKeys.join(", ") || "none"}</small>{preview.managedFiles > 0 && <small>Managed files: {preview.managedFiles}</small>}</section>}<div className="actions"><button type="button" disabled={busy} onClick={() => setSelected(null)}>Cancel</button><button type="button" disabled={busy} onClick={() => void loadPreview()}>{busy ? "Validating…" : "Preview topology"}</button><button className="primary" disabled={busy}>{busy ? "Working…" : "Create from template"}</button></div></form></div>}</>;
}

function Databases({ environmentId, canWrite, canAdmin, canManageDestinations, flash, setError }: { environmentId: string; canWrite: boolean; canAdmin: boolean; canManageDestinations: boolean; flash: (s: string) => void; setError: (s: string) => void }) {
  const [engines, setEngines] = useState<DatabaseEngine[]>([]); const [items, setItems] = useState<Database[]>([]); const [destinations, setDestinations] = useState<BackupDestination[]>([]); const [name, setName] = useState(""); const [engine, setEngine] = useState(""); const [result, setResult] = useState<{ credentials: Record<string, string>; internalUrl: string } | null>(null); const [selected, setSelected] = useState(""); const [interval, setInterval] = useState(86400); const [retention, setRetention] = useState(14); const [destinationId, setDestinationId] = useState(""); const [verifyRestore, setVerifyRestore] = useState(true);
  const [migrations, setMigrations] = useState<DatabaseMigration[]>([]);
  const [backupHistory, setBackupHistory] = useState<DatabaseBackup[]>([]); const [restoreHistory, setRestoreHistory] = useState<DatabaseRestore[]>([]);
  const backup = useMemo(() => engines.filter(item => item.backupCapable).map(item => item.name), [engines]);
  const selectedEngine = engines.find(item => item.name === engine);
  useEffect(() => { api.databaseEngines().then(x => { setEngines(x.engines); setEngine(x.engines[0]?.name ?? ""); }).catch(reason => setError(message(reason))); }, [setError]);
  const reload = useCallback(async () => { if (!environmentId) { setItems([]); return; } const response = await api.databases(environmentId); setItems(response.items); }, [environmentId]);
  useEffect(() => { void reload().catch(reason => setError(message(reason))); }, [reload, setError]);
  useEffect(() => { const eligible = items.filter(x => backup.includes(x.engine)); setSelected(current => eligible.some(x => x.id === current) ? current : eligible[0]?.id ?? ""); }, [items, backup]);
  useEffect(() => { if (canAdmin && canManageDestinations) void api.backupDestinations().then(x => setDestinations(x.items)).catch(reason => setError(message(reason))); else setDestinations([]); }, [canAdmin, canManageDestinations, setError]);
  useEffect(() => { if (!selected || !canAdmin) return; api.backupPolicy(selected).then(policy => { setInterval(policy.intervalSeconds); setRetention(policy.retentionCount); setDestinationId(policy.destinationId ?? ""); setVerifyRestore(policy.verifyRestore); }).catch(reason => { if (reason instanceof APIError && reason.status === 404) { setInterval(86400); setRetention(14); setDestinationId(""); setVerifyRestore(true); } else setError(message(reason)); }); }, [selected, canAdmin, setError]);
  const reloadMigrations = useCallback(async () => { if (!selected) { setMigrations([]); return; } setMigrations((await api.databaseMigrations(selected)).items); }, [selected]);
  useEffect(() => { void reloadMigrations().catch(reason => setError(message(reason))); if (!selected) return; const timer = window.setInterval(() => void reloadMigrations().catch(() => undefined), 5000); return () => window.clearInterval(timer); }, [selected, reloadMigrations, setError]);
	const reloadProtection = useCallback(async () => { if (!selected) { setBackupHistory([]); setRestoreHistory([]); return; } const [backupResponse, restoreResponse] = await Promise.all([api.databaseBackups(selected), api.databaseRestores(selected)]); setBackupHistory(backupResponse.items); setRestoreHistory(restoreResponse.items); }, [selected]);
	useEffect(() => { void reloadProtection().catch(reason => setError(message(reason))); if (!selected) return; const timer = window.setInterval(() => void reloadProtection().catch(() => undefined), 5000); return () => window.clearInterval(timer); }, [selected, reloadProtection, setError]);
  async function submit(event: FormEvent) { event.preventDefault(); if (!environmentId) return setError("Select an environment under Workloads first"); try { const created = await api.createDatabase(environmentId, { name, engine, version: "", config: {} }); setResult(created); await reload(); flash("Database provision queued"); } catch (reason) { setError(message(reason)); } }
  async function act(action: () => Promise<unknown>, success: string) { try { await action(); await Promise.all([reload(), reloadProtection()]); flash(success); } catch (reason) { setError(message(reason)); } }
  async function restore(item: DatabaseBackup) { const database = items.find(value => value.id === selected); if (!database) return; const confirmation = window.prompt(`Restoring overwrites ${database.name}. Type its slug to continue:`, ""); if (confirmation === null) return; try { await api.restoreDatabaseBackup(item.id, confirmation); await reloadProtection(); flash("Database restore queued"); } catch (reason) { setError(message(reason)); } }
  function needsDriverRebind(item: Database) { const current = engines.find(value => value.name === item.engine); return !!current && (item.driverSource === "unbound" || item.driverSource !== current.source || (current.source === "external" && item.driverArtifactDigest !== current.artifactDigest)); }
  async function rebindDriver(item: Database) { const confirmation = window.prompt(`Rebind ${item.name} to the driver installed on this controller. Type ${item.slug} to continue:`, ""); if (confirmation === null) return; try { await api.rebindDatabaseDriver(item.id, confirmation); await reload(); flash("Database driver identity rebound"); } catch (reason) { setError(message(reason)); } }
  return <><div className="database-layout">{canWrite ? <form className="card database-form" onSubmit={submit}><p className="eyebrow">Managed service</p><h2>Create database</h2><p className="muted">Credentials are revealed once. Store them before leaving this screen.</p><label>Name<input value={name} onChange={e => setName(e.target.value)} required /></label><label>Engine<select value={engine} onChange={e => setEngine(e.target.value)}>{engines.map(item => <option key={item.name} value={item.name}>{item.name} · {item.defaultVersion} · {item.source}</option>)}</select></label>{selectedEngine && <p className="capability">{selectedEngine.backupCapable ? `✓ Native backup and restore · .${selectedEngine.backupExtension}` : "Backups not yet supported"} · {selectedEngine.source === "external" ? `trusted external driver · ${selectedEngine.artifactDigest?.slice(0, 19) ?? "unverified"}…` : "built-in driver"}</p>}<button className="primary" disabled={!engine}>Create database</button></form> : <Empty title="Read-only databases" text="A developer grant is required to provision or back up a database." />}{result ? <section className="card credential-card"><p className="eyebrow">Save now</p><h2>Connection details</h2><code>{result.internalUrl}</code>{Object.entries(result.credentials).map(([key, value]) => <div className="secret" key={key}><span>{key}</span><code>{value}</code></div>)}</section> : <Empty title="One-time credentials" text="New database connection details will appear here exactly once." />}</div>
    <section className="section-head spaced"><div><h2>Managed databases</h2><p className="muted">Backup, retention, and lifecycle controls.</p></div><span className="count">{items.length} total</span></section>
    <div className="grid">{items.map(item => <article className="card database-card" key={item.id}><div><h3>{item.name}</h3><p>{item.engine}:{item.version} · {item.slug}</p><p>{!engines.some(value => value.name === item.engine) ? "⚠ driver unavailable on this controller" : needsDriverRebind(item) ? "⚠ driver identity requires review" : item.driverSource === "external" ? `external · ${item.driverArtifactDigest?.slice(0, 19)}…` : item.driverSource === "unbound" ? "driver identity pending" : "built-in driver"}</p></div><Status value={item.status} /><div className="actions"><button disabled={!canWrite || !backup.includes(item.engine) || needsDriverRebind(item)} onClick={() => void act(() => api.backupDatabase(item.id, destinationId || undefined), "Backup queued")}>Back up now</button>{canAdmin && needsDriverRebind(item) && <button onClick={() => void rebindDriver(item)}>Review and rebind driver</button>}{canAdmin && <button className="danger-button" onClick={() => window.confirm(`Delete ${item.name} and its stack?`) && void act(() => api.deleteDatabase(item.id), "Database deletion queued")}>Delete</button>}</div></article>)}</div>
    {selected && <section className="card protection-history"><div className="card-head"><div><p className="eyebrow">Recovery</p><h2>Backup and restore history</h2><p className="muted">Successful backups can be restored only after typing the selected database slug.</p></div><button type="button" onClick={() => void reloadProtection().catch(reason => setError(message(reason)))}>Refresh</button></div><div className="history-columns"><div><h3>Backups</h3>{backupHistory.map(item => <article key={item.id}><div><strong>{item.format.toUpperCase()} · {item.encrypted ? "encrypted" : "legacy"}</strong><small>{new Date(item.createdAt).toLocaleString()}{item.sizeBytes ? ` · ${(item.sizeBytes / 1048576).toFixed(1)} MiB` : ""}</small>{item.sha256 && <small>SHA-256 {item.sha256.slice(0, 12)}…</small>}{item.error && <small className="error">{item.error}</small>}</div><Status value={item.status} />{canWrite && (item.status === "queued" || item.status === "running") && <button onClick={() => void api.cancelDatabaseBackup(item.id).then(reloadProtection).then(() => flash("Backup cancellation requested")).catch(reason => setError(message(reason)))}>Cancel</button>}{canAdmin && item.status === "succeeded" && <button className="danger-button" onClick={() => void restore(item)}>Restore</button>}</article>)}{!backupHistory.length && <p className="muted">No backups yet.</p>}</div><div><h3>Restores</h3>{restoreHistory.map(item => <article key={item.id}><div><strong>{item.kind}</strong><small>{new Date(item.createdAt).toLocaleString()}</small>{item.error && <small className="error">{item.error}</small>}</div><Status value={item.status} />{canAdmin && (item.status === "queued" || item.status === "running") && <button onClick={() => void api.cancelDatabaseRestore(item.id).then(reloadProtection).then(() => flash("Restore cancellation requested")).catch(reason => setError(message(reason)))}>Cancel</button>}</article>)}{!restoreHistory.length && <p className="muted">No restore attempts yet.</p>}</div></div></section>}
    {selected && <section className="card migration-history"><div className="card-head"><div><p className="eyebrow">Dokploy cutover</p><h2>Data transfer history</h2><p className="muted">Native transfers are queued with <code>dockyard migrate-dokploy-data</code>. This view refreshes while the console is open.</p></div><button type="button" onClick={() => void reloadMigrations().catch(reason => setError(message(reason)))}>Refresh</button></div>{migrations.map(item => <article key={item.id}><div><strong>{item.sourceEngine}:{item.sourceVersion}</strong><small>{item.sourceHost} · {new Date(item.createdAt).toLocaleString()}</small>{item.sizeBytes ? <small>{(item.sizeBytes / 1048576).toFixed(1)} MiB · SHA-256 {item.sha256?.slice(0, 12)}…</small> : null}{item.error && <small className="error">{item.error}</small>}</div><Status value={item.status} />{canAdmin && (item.status === "queued" || item.status === "running") && <button className="danger-button" onClick={() => window.confirm("Cancel this database transfer?") && void api.cancelDatabaseMigration(item.id).then(reloadMigrations).then(() => flash("Database transfer cancellation requested")).catch(reason => setError(message(reason)))}>Cancel</button>}</article>)}{!migrations.length && <p className="muted">No Dokploy data transfers have been queued for this database.</p>}</section>}
    {canAdmin && selected && <form className="card policy-form" onSubmit={event => { event.preventDefault(); void act(() => api.putBackupPolicy(selected, { intervalSeconds: interval, retentionCount: retention, enabled: true, verifyRestore, destinationId: destinationId || undefined }), "Backup policy saved"); }}><div><p className="eyebrow">Scheduled protection</p><h2>Backup policy</h2></div><label>Database<select value={selected} onChange={e => setSelected(e.target.value)}>{items.filter(x => backup.includes(x.engine)).map(x => <option key={x.id} value={x.id}>{x.name}</option>)}</select></label><label>Interval (seconds)<input type="number" min="900" max="2678400" value={interval} onChange={e => setInterval(Number(e.target.value))} /></label><label>Retain<input type="number" min="1" max="100" value={retention} onChange={e => setRetention(Number(e.target.value))} /></label><label>Destination<select value={destinationId} onChange={e => setDestinationId(e.target.value)}><option value="">Controller storage</option>{destinations.map(x => <option key={x.id} value={x.id}>{x.name}</option>)}</select></label><label className="check"><input type="checkbox" checked={verifyRestore} onChange={e => setVerifyRestore(e.target.checked)} /> Verify each scheduled backup with a restore drill</label><button className="primary">Save policy</button></form>}
  </>;
}

function Clusters({ flash, setError }: { flash: (s: string) => void; setError: (s: string) => void }) {
  const [items, setItems] = useState<Cluster[]>([]);
  const [upgrades, setUpgrades] = useState<ClusterCommand[]>([]);
  const [networks, setNetworks] = useState<ManagedNetwork[]>([]);
  const [name, setName] = useState(""); const [labels, setLabels] = useState(""); const [networkName, setNetworkName] = useState(""); const [networkCluster, setNetworkCluster] = useState(""); const [networkInternal, setNetworkInternal] = useState(false); const [upgradeImages, setUpgradeImages] = useState<Record<string, string>>({}); const [enrollment, setEnrollment] = useState<{ cluster: string; token: string; expiresAt: string } | null>(null); const [busy, setBusy] = useState(false);
  const refresh = useCallback(async () => {
    const [clusters, history, networkResult] = await Promise.all([api.clusters(), api.agentUpgrades(), api.networks()]);
    setItems(clusters.items);
    setUpgrades(history.items);
    setNetworks(networkResult.items);
  }, []);
  useEffect(() => {
    refresh().catch(reason => setError(message(reason)));
    const timer = window.setInterval(() => refresh().catch(reason => setError(message(reason))), 10_000);
    return () => window.clearInterval(timer);
  }, [refresh, setError]);
  async function run(action: () => Promise<unknown>, success: string) { setBusy(true); try { await action(); await refresh(); flash(success); return true; } catch (reason) { setError(message(reason)); return false; } finally { setBusy(false); } }
  function parsedLabels() { return Object.fromEntries(labels.split(",").map(x => x.trim()).filter(Boolean).map(pair => { const index = pair.indexOf("="); if (index < 1 || index === pair.length - 1) throw new Error("Labels must use key=value syntax"); return [pair.slice(0, index).trim(), pair.slice(index + 1).trim()]; })); }
  async function create(event: FormEvent) { event.preventDefault(); try { if (await run(() => api.createCluster({ name, labels: parsedLabels() }), "Cluster registered")) { setName(""); setLabels(""); } } catch (reason) { setError(message(reason)); } }
  async function createNetwork(event: FormEvent) { event.preventDefault(); if (await run(() => api.createNetwork({ name: networkName, driver: "overlay", clusterId: networkCluster || undefined, internal: networkInternal, attachable: true, enableIpv4: true, enableIpv6: false }), "Network provisioning queued")) setNetworkName(""); }
  async function issueToken(cluster: Cluster) { setBusy(true); try { const result = await api.createEnrollmentToken(cluster.id); setEnrollment({ cluster: cluster.name, ...result }); flash("One-time enrollment token issued"); } catch (reason) { setError(message(reason)); } finally { setBusy(false); } }
  return <><section className="section-head"><div><h2>Swarm clusters</h2><p className="muted">Outbound TLS 1.3 mTLS agents and capacity-aware placement.</p></div></section><form className="card cluster-create" onSubmit={create}><label>Name<input value={name} onChange={e => setName(e.target.value)} placeholder="Paris production" required /></label><label>Placement labels<input value={labels} onChange={e => setLabels(e.target.value)} placeholder="region=eu-west,tier=production" /></label><button className="primary" disabled={busy}>Register cluster</button></form>
    {enrollment && <section className="card credential-card enrollment"><p className="eyebrow">Save now · expires {new Date(enrollment.expiresAt).toLocaleString()}</p><h2>Enroll {enrollment.cluster}</h2><p className="muted">Pass this one-time token to the agent as <code>DOCKYARD_AGENT_ENROLLMENT_TOKEN</code>. It is never shown again.</p><code>{enrollment.token}</code><button onClick={() => navigator.clipboard.writeText(enrollment.token)}>Copy token</button></section>}
    <div className="grid spaced">{items.map(x => <article className="card cluster-card" key={x.id}><div className="cluster-top"><div className="service-icon">SW</div><Status value={x.state} /></div><h3>{x.name}</h3><p>{x.slug}{Object.keys(x.labels ?? {}).length ? ` · ${Object.entries(x.labels).map(([key, value]) => `${key}=${String(value)}`).join(", ")}` : ""}</p><dl><div><dt>Agent</dt><dd>{x.agentVersion || "Not connected"}</dd></div><div><dt>Agent image</dt><dd title={x.agentImage}>{x.agentImage ? x.agentImage.split("@sha256:")[1]?.slice(0, 12) ?? x.agentImage : "Not reported"}</dd></div><div><dt>Agent update</dt><dd>{x.agentUpdateState || "Not reported"}</dd></div><div><dt>Docker</dt><dd>{x.dockerVersion || "—"}</dd></div><div><dt>Last seen</dt><dd>{x.lastSeenAt ? new Date(x.lastSeenAt).toLocaleString() : "Never"}</dd></div><div><dt>Certificate</dt><dd>{x.certificateNotAfter ? new Date(x.certificateNotAfter).toLocaleDateString() : "Not enrolled"}</dd></div><div><dt>Signing CA</dt><dd title={x.certificateAuthorityFingerprint}>{x.certificateAuthorityFingerprint ? `sha256:${x.certificateAuthorityFingerprint.replace("sha256:", "").slice(0, 12)}…` : "Not reported"}</dd></div>{x.pendingCertificateAuthorityFingerprint && <div><dt>CA rotation</dt><dd title={x.pendingCertificateAuthorityFingerprint}>Pending sha256:{x.pendingCertificateAuthorityFingerprint.replace("sha256:", "").slice(0, 12)}…</dd></div>}</dl><AgentUpgradeSummary command={upgrades.find(command => command.clusterId === x.id)} busy={busy} cancel={command => void run(() => api.cancelAgentUpgrade(command.clusterId, command.id), "Pending agent upgrade cancelled")} /><div className="actions"><button disabled={busy} onClick={() => void issueToken(x)}>Enroll</button><button disabled={busy} onClick={() => void run(() => api.updateCluster(x.id, x.state === "active" ? "draining" : "active"), x.state === "active" ? "Cluster draining" : "Cluster activated")}>{x.state === "active" ? "Drain" : "Activate"}</button><button className="danger-button" disabled={busy} onClick={() => window.confirm(`Delete ${x.name}? Assigned environments and managed networks must be removed first.`) && void run(() => api.deleteCluster(x.id), "Cluster deletion queued")}>Delete</button></div><form className="upgrade-form" onSubmit={event => { event.preventDefault(); void run(() => api.upgradeAgent(x.id, upgradeImages[x.id] ?? ""), "Digest-pinned agent upgrade queued"); }}><label>Agent image digest<input value={upgradeImages[x.id] ?? ""} onChange={e => setUpgradeImages({ ...upgradeImages, [x.id]: e.target.value })} placeholder="registry.example/dockyard@sha256:…" required /></label><button disabled={busy || x.state !== "active"}>Upgrade</button></form></article>)}</div>{!items.length && <Empty title="No remote clusters" text="The controller can still deploy to its local Swarm. Register a cluster and issue a one-time token to enroll its outbound agent." />}
    <section className="section-head"><div><h2>Managed networks</h2><p className="muted">Encrypted overlay networks shared safely across selected Compose stacks.</p></div></section><form className="card cluster-create" onSubmit={createNetwork}><label>Name<input value={networkName} onChange={event => setNetworkName(event.target.value.toLowerCase())} pattern="[a-z0-9][a-z0-9_-]{0,62}" placeholder="shared_backend" required /></label><label>Swarm<select value={networkCluster} onChange={event => setNetworkCluster(event.target.value)}><option value="">Local controller Swarm</option>{items.map(cluster => <option key={cluster.id} value={cluster.id}>{cluster.name}</option>)}</select></label><label className="check"><input type="checkbox" checked={networkInternal} onChange={event => setNetworkInternal(event.target.checked)} /> Internal-only network</label><button className="primary" disabled={busy}>Create network</button></form><div className="grid spaced">{networks.map(network => <article className="card cluster-card" key={network.id}><div className="cluster-top"><div className="service-icon">NW</div><Status value={network.status} /></div><h3>{network.name}</h3><p>{network.driver} · {network.clusterId ? items.find(cluster => cluster.id === network.clusterId)?.name ?? "Remote Swarm" : "Local Swarm"}</p><small>{network.internal ? "Internal" : "Externally routed"} · {network.attachable ? "Attachable" : "Not attachable"} · {network.enableIpv6 ? "Dual stack" : "IPv4"}</small>{network.lastError && <p className="error">{network.lastError}</p>}<div className="actions">{network.status === "error" && !network.deletionRequestedAt && <button disabled={busy} onClick={() => void run(() => api.retryNetwork(network.id), "Network provisioning retried")}>Retry</button>}<button className="danger-button" disabled={busy} onClick={() => window.confirm(`Delete network ${network.name}? It must not be assigned to a service.`) && void run(() => api.deleteNetwork(network.id), network.deletionRequestedAt ? "Network deletion retried" : "Network deletion queued")}>{network.deletionRequestedAt ? "Retry deletion" : "Delete"}</button></div></article>)}</div></>;
}

function AgentUpgradeSummary({ command, busy, cancel }: { command?: ClusterCommand; busy: boolean; cancel: (command: ClusterCommand) => void }) {
  if (!command) return null;
  const digest = command.targetImage?.split("@sha256:")[1]?.slice(0, 12);
  return <section className="upgrade-result"><div><span>Latest upgrade</span><Status value={command.status} /></div><small title={command.targetImage}>{digest ? `sha256:${digest}…` : command.targetImage}</small>{command.lastError && <small className="error">{command.lastError}</small>}{command.status === "pending" && <button disabled={busy} onClick={() => cancel(command)}>Cancel pending upgrade</button>}</section>;
}

type PolicyScope = "organization" | "project" | "environment";
type PolicyDraft = { maintenance: boolean; maintenanceReason: string; maxProjects: string; maxEnvironments: string; maxServices: string; maxDatabases: string };
type AutomationRole = "admin" | "developer" | "viewer";

const emptyPolicy: PolicyDraft = { maintenance: false, maintenanceReason: "", maxProjects: "", maxEnvironments: "", maxServices: "", maxDatabases: "" };

function Governance({ principal, projects, projectId, environments, environmentId, flash, setError }: { principal: Principal; projects: Project[]; projectId: string; environments: Environment[]; environmentId: string; flash: (s: string) => void; setError: (s: string) => void }) {
  const [scope, setScope] = useState<PolicyScope>("organization");
  const [draft, setDraft] = useState<PolicyDraft>(emptyPolicy);
  const [requireSso, setRequireSso] = useState(false);
  const [members, setMembers] = useState<OrganizationMember[]>([]);
  const [invitations, setInvitations] = useState<OrganizationInvitation[]>([]);
  const [invitationEmail, setInvitationEmail] = useState("");
  const [invitationRole, setInvitationRole] = useState<Role>("developer");
  const [invitationDays, setInvitationDays] = useState(7);
  const [createdInvitation, setCreatedInvitation] = useState<{ token: string; acceptUrl: string } | null>(null);
  const [scimTokens, setSCIMTokens] = useState<SCIMToken[]>([]);
  const [scimName, setSCIMName] = useState("identity-provider");
  const [scimRole, setSCIMRole] = useState<SCIMToken["defaultRole"]>("developer");
  const [scimExpiryDays, setSCIMExpiryDays] = useState(90);
  const [createdSCIM, setCreatedSCIM] = useState<{ token: string; baseUrl: string } | null>(null);
  const [automationAccounts, setAutomationAccounts] = useState<ServiceAccount[]>([]);
  const [automationName, setAutomationName] = useState("deployment-automation");
  const [automationRole, setAutomationRole] = useState<AutomationRole>("developer");
  const [automationDays, setAutomationDays] = useState(90);
  const [createdAutomation, setCreatedAutomation] = useState<{ name: string; token: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const scopeId = scope === "organization" ? principal.organizationId : scope === "project" ? projectId : environmentId;

  const applyPolicy = (item: ResourcePolicy) => setDraft({ maintenance: item.maintenance, maintenanceReason: item.maintenanceReason, maxProjects: item.maxProjects?.toString() ?? "", maxEnvironments: item.maxEnvironments?.toString() ?? "", maxServices: item.maxServices?.toString() ?? "", maxDatabases: item.maxDatabases?.toString() ?? "" });
  const refreshMembers = useCallback(async () => setMembers((await api.members()).items), []);
  const refreshInvitations = useCallback(async () => setInvitations((await api.invitations()).items), []);
  const refreshSCIMTokens = useCallback(async () => setSCIMTokens((await api.scimTokens()).items), []);
  const refreshAutomationAccounts = useCallback(async () => setAutomationAccounts((await api.serviceAccounts()).items.filter(item => item.role !== "auditor")), []);
  useEffect(() => { api.authSettings().then(x => setRequireSso(x.requireSso)).catch(reason => setError(message(reason))); }, [setError]);
  useEffect(() => { void refreshMembers().catch(reason => setError(message(reason))); }, [refreshMembers, setError]);
  useEffect(() => { void refreshInvitations().catch(reason => setError(message(reason))); }, [refreshInvitations, setError]);
  useEffect(() => { void refreshSCIMTokens().catch(reason => setError(message(reason))); }, [refreshSCIMTokens, setError]);
  useEffect(() => { void refreshAutomationAccounts().catch(reason => setError(message(reason))); }, [refreshAutomationAccounts, setError]);
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
  async function createSCIMToken(event: FormEvent) {
    event.preventDefault(); setBusy(true); setCreatedSCIM(null);
    try { const result = await api.createSCIMToken(scimName, scimRole, scimExpiryDays); setCreatedSCIM({ token: result.token, baseUrl: result.baseUrl }); await refreshSCIMTokens(); flash("SCIM token created"); }
    catch (reason) { setError(message(reason)); } finally { setBusy(false); }
  }
  async function revokeSCIMToken(item: SCIMToken) {
    if (!window.confirm(`Revoke ${item.name}? Provisioning with this token will stop immediately.`)) return;
    setBusy(true); try { await api.revokeSCIMToken(item.id); await refreshSCIMTokens(); flash("SCIM token revoked"); }
    catch (reason) { setError(message(reason)); } finally { setBusy(false); }
  }
  async function updateMemberRole(item: OrganizationMember, role: Role) {
    setBusy(true); try { await api.updateMemberRole(item.userId, role); await refreshMembers(); flash(`${item.email} is now ${role}`); }
    catch (reason) { setError(message(reason)); } finally { setBusy(false); }
  }
  async function removeMember(item: OrganizationMember) {
    if (!window.confirm(`Remove ${item.email} from ${principal.organization}? Their project and environment grants will also be removed.`)) return;
    setBusy(true); try { await api.deleteMember(item.userId); await refreshMembers(); flash(`${item.email} removed`); }
    catch (reason) { setError(message(reason)); } finally { setBusy(false); }
  }
  async function createInvitation(event: FormEvent) {
    event.preventDefault(); setBusy(true); setCreatedInvitation(null);
    try { const result = await api.createInvitation(invitationEmail, invitationRole, invitationDays); setCreatedInvitation({ token: result.token, acceptUrl: result.acceptUrl }); setInvitationEmail(""); await refreshInvitations(); flash("Invitation created"); }
    catch (reason) { setError(message(reason)); } finally { setBusy(false); }
  }
  async function revokeInvitation(item: OrganizationInvitation) {
    if (!window.confirm(`Revoke the invitation for ${item.email}?`)) return;
    setBusy(true); try { await api.revokeInvitation(item.id); await refreshInvitations(); flash("Invitation revoked"); }
    catch (reason) { setError(message(reason)); } finally { setBusy(false); }
  }
  async function createAutomationAccount(event: FormEvent) {
    event.preventDefault(); setBusy(true); setCreatedAutomation(null);
    try { const result = await api.createServiceAccount(automationName, automationRole, automationDays); setCreatedAutomation({ name: result.serviceAccount.name, token: result.token }); await refreshAutomationAccounts(); flash("Automation identity created"); }
    catch (reason) { setError(message(reason)); } finally { setBusy(false); }
  }
  async function rotateAutomationAccount(item: ServiceAccount) {
    if (!window.confirm(`Rotate the token for ${item.name}? Its current token will stop working immediately.`)) return;
    setBusy(true); setCreatedAutomation(null);
    try { const result = await api.rotateServiceAccount(item.id, automationDays); setCreatedAutomation({ name: item.name, token: result.token }); await refreshAutomationAccounts(); flash("Automation token rotated"); }
    catch (reason) { setError(message(reason)); } finally { setBusy(false); }
  }
  async function disableAutomationAccount(item: ServiceAccount) {
    if (!window.confirm(`Disable ${item.name}? Its token will stop working immediately.`)) return;
    setBusy(true);
    try { await api.disableServiceAccount(item.id); await refreshAutomationAccounts(); flash("Automation identity disabled"); }
    catch (reason) { setError(message(reason)); } finally { setBusy(false); }
  }
  const activeOwners = members.filter(item => item.active && item.role === "owner").length;
  const canManageMember = (item: OrganizationMember) => !item.managedByScim && (principal.role === "owner" || item.role !== "owner") && !(item.userId === principal.userId && item.role === "owner" && activeOwners <= 1);
  return <div className="settings-grid">
    <section className="card settings-card"><p className="eyebrow">Organization access</p><h2>Members</h2><p className="muted">Manage organization roles and remove access. Directory-managed members must be changed in the identity provider.</p><div className="admin-items">{members.map(item => { const manageable = canManageMember(item); return <article key={item.userId}><div><strong>{item.displayName || item.email}{item.userId === principal.userId ? " · You" : ""}</strong><small>{item.email} · {item.active ? "active" : "disabled"}{item.managedByScim ? " · SCIM managed" : ""}</small></div><div className="actions">{manageable ? <select aria-label={`Role for ${item.email}`} value={item.role} disabled={busy} onChange={event => void updateMemberRole(item, event.target.value as Role)}>{principal.role === "owner" && <option value="owner">Owner</option>}<option value="admin">Admin</option><option value="developer">Developer</option><option value="viewer">Viewer</option></select> : <Status value={item.role} />}{manageable && <button type="button" className="danger-button" disabled={busy} onClick={() => void removeMember(item)}>Remove</button>}</div></article>; })}{!members.length && <p className="muted">No organization members.</p>}</div></section>
    <section className="card settings-card"><p className="eyebrow">Organization access</p><h2>Invitations</h2><p className="muted">Create a one-time enrollment link. Creating another invitation for the same email revokes the previous link.</p><form onSubmit={createInvitation}><label>Email<input type="email" value={invitationEmail} onChange={event => setInvitationEmail(event.target.value)} required /></label><label>Role<select value={invitationRole} onChange={event => setInvitationRole(event.target.value as Role)}>{principal.role === "owner" && <option value="owner">Owner</option>}<option value="admin">Admin</option><option value="developer">Developer</option><option value="viewer">Viewer</option></select></label><label>Lifetime (days)<input type="number" min="1" max="30" value={invitationDays} onChange={event => setInvitationDays(Number(event.target.value))} /></label><button className="primary" disabled={busy}>Create invitation</button></form>{createdInvitation && <div className="credential-card spaced"><p className="eyebrow">Share once</p><p className="muted">The invitation token is never shown again.</p><code>{createdInvitation.acceptUrl}</code><div className="actions"><button type="button" onClick={() => void navigator.clipboard.writeText(createdInvitation.acceptUrl)}>Copy link</button><button type="button" onClick={() => setCreatedInvitation(null)}>Dismiss</button></div></div>}<div className="admin-items">{invitations.map(item => { const status = item.acceptedAt ? "accepted" : item.revokedAt ? "revoked" : new Date(item.expiresAt) <= new Date() ? "expired" : "pending"; return <article key={item.id}><div><strong>{item.email}</strong><small>{item.role} · expires {new Date(item.expiresAt).toLocaleDateString()}</small></div><Status value={status} />{status === "pending" && <button type="button" className="danger-button" disabled={busy} onClick={() => void revokeInvitation(item)}>Revoke</button>}</article>; })}{!invitations.length && <p className="muted">No invitations issued.</p>}</div></section>
    <section className="card settings-card"><p className="eyebrow">Machine access</p><h2>Automation identities</h2><p className="muted">Issue scoped, expiring API credentials for CI/CD and infrastructure automation. Use the AI page for auditor-only identities.</p><form onSubmit={createAutomationAccount}><label>Name<input value={automationName} maxLength={120} onChange={event => setAutomationName(event.target.value)} required /></label><label>Role<select value={automationRole} onChange={event => setAutomationRole(event.target.value as AutomationRole)}><option value="viewer">Viewer</option><option value="developer">Developer</option><option value="admin">Admin</option></select></label><label>Token lifetime (days)<input type="number" min="1" max="365" value={automationDays} onChange={event => setAutomationDays(Number(event.target.value))} /></label><button className="primary" disabled={busy}>Create identity</button></form>{createdAutomation && <div className="credential-card spaced"><p className="eyebrow">Save now · {createdAutomation.name}</p><p className="muted">This token is shown once. Store it in your CI/CD secret manager.</p><code>{createdAutomation.token}</code><div className="actions"><button type="button" onClick={() => void navigator.clipboard.writeText(createdAutomation.token)}>Copy token</button><button type="button" onClick={() => setCreatedAutomation(null)}>Dismiss</button></div></div>}<div className="admin-items">{automationAccounts.map(item => { const expired = Boolean(item.tokenExpiresAt && new Date(item.tokenExpiresAt) <= new Date()); const status = !item.enabled ? "disabled" : expired ? "expired" : "active"; return <article key={item.id}><div><strong>{item.name}</strong><small>{item.role} · expires {item.tokenExpiresAt ? new Date(item.tokenExpiresAt).toLocaleString() : "without an active token"}{item.lastUsedAt ? ` · last used ${new Date(item.lastUsedAt).toLocaleString()}` : " · never used"}</small></div><Status value={status} /><div className="actions">{item.enabled && <button type="button" disabled={busy} onClick={() => void rotateAutomationAccount(item)}>Rotate</button>}{item.enabled && <button type="button" className="danger-button" disabled={busy} onClick={() => void disableAutomationAccount(item)}>Disable</button>}</div></article>; })}{!automationAccounts.length && <p className="muted">No automation identities created.</p>}</div></section>
    <section className="card settings-card"><p className="eyebrow">Resource guardrails</p><h2>Policy and quotas</h2><form onSubmit={savePolicy}>
      <label>Scope<select value={scope} onChange={e => setScope(e.target.value as PolicyScope)}><option value="organization">Organization · {principal.organization}</option><option value="project" disabled={!projectId}>Project · {projects.find(x => x.id === projectId)?.name ?? "select under Workloads"}</option><option value="environment" disabled={!environmentId}>Environment · {environments.find(x => x.id === environmentId)?.name ?? "select under Workloads"}</option></select></label>
      <label className="check"><input type="checkbox" checked={draft.maintenance} onChange={e => setDraft({ ...draft, maintenance: e.target.checked })} /> Block mutations for maintenance</label>
      <label>Maintenance reason<textarea value={draft.maintenanceReason} maxLength={500} onChange={e => setDraft({ ...draft, maintenanceReason: e.target.value })} /></label>
      <div className="field-row">{scope === "organization" && <label>Maximum projects<input type="number" min="1" max="1000000" placeholder="Unlimited" value={draft.maxProjects} onChange={e => setDraft({ ...draft, maxProjects: e.target.value })} /></label>} {scope !== "environment" && <label>Maximum environments<input type="number" min="1" max="1000000" placeholder="Unlimited" value={draft.maxEnvironments} onChange={e => setDraft({ ...draft, maxEnvironments: e.target.value })} /></label>}</div>
      <div className="field-row"><label>Maximum services<input type="number" min="1" max="1000000" placeholder="Unlimited" value={draft.maxServices} onChange={e => setDraft({ ...draft, maxServices: e.target.value })} /></label><label>Maximum databases<input type="number" min="1" max="1000000" placeholder="Unlimited" value={draft.maxDatabases} onChange={e => setDraft({ ...draft, maxDatabases: e.target.value })} /></label></div>
      <button className="primary" disabled={busy || !scopeId}>Save policy</button>
    </form></section>
    <section className="card settings-card"><p className="eyebrow">Authentication policy</p><h2>Mandatory SSO</h2><p className="muted">Require interactive users to authenticate through an enabled OIDC or SAML provider. Existing local sessions are revoked except for the owner break-glass account.</p><label className="check"><input type="checkbox" checked={requireSso} onChange={e => setRequireSso(e.target.checked)} /> Require SSO for this organization</label><button className="primary spaced-button" disabled={busy} onClick={() => { setBusy(true); api.putAuthSettings(requireSso).then(() => flash("Authentication policy saved")).catch(reason => setError(message(reason))).finally(() => setBusy(false)); }}>Save authentication policy</button></section>
    <section className="card settings-card"><p className="eyebrow">Directory provisioning</p><h2>SCIM tokens</h2><p className="muted">Issue a time-limited bearer token for one identity provider.</p><form onSubmit={createSCIMToken}><label>Name<input value={scimName} maxLength={120} onChange={e => setSCIMName(e.target.value)} required /></label><label>Default role<select value={scimRole} onChange={e => setSCIMRole(e.target.value as SCIMToken["defaultRole"])}><option value="viewer">Viewer</option><option value="developer">Developer</option><option value="admin">Admin</option></select></label><label>Lifetime (days)<input type="number" min="1" max="365" value={scimExpiryDays} onChange={e => setSCIMExpiryDays(Number(e.target.value))} /></label><button className="primary" disabled={busy}>Create token</button></form>{createdSCIM && <div className="credential-card spaced"><p className="eyebrow">Save now</p><p className="muted">Base URL: <code>{createdSCIM.baseUrl}</code></p><code>{createdSCIM.token}</code><button type="button" onClick={() => navigator.clipboard.writeText(createdSCIM.token)}>Copy token</button></div>}<div className="admin-items">{scimTokens.map(item => <article key={item.id}><div><strong>{item.name}</strong><small>{item.defaultRole} · expires {new Date(item.expiresAt).toLocaleDateString()}</small></div><Status value={item.revokedAt ? "revoked" : new Date(item.expiresAt) <= new Date() ? "expired" : "active"} />{!item.revokedAt && new Date(item.expiresAt) > new Date() && <button type="button" className="danger-button" disabled={busy} onClick={() => void revokeSCIMToken(item)}>Revoke</button>}</article>)}{!scimTokens.length && <p className="muted">No SCIM tokens issued.</p>}</div></section>
  </div>;
}

function AIAudits({ flash, setError }: { flash: (s: string) => void; setError: (s: string) => void }) {
  const [runs, setRuns] = useState<AIAuditRun[]>([]); const [accounts, setAccounts] = useState<ServiceAccount[]>([]); const [currentFindings, setCurrentFindings] = useState<AIAuditFinding[]>([]); const [findings, setFindings] = useState<AIAuditFinding[]>([]); const [selected, setSelected] = useState(""); const [name, setName] = useState("platform-auditors"); const [days, setDays] = useState(90); const [token, setToken] = useState(""); const [busy, setBusy] = useState(false);
  const refresh = useCallback(async () => { const [runResult, accountResult, findingResult] = await Promise.all([api.aiAuditRuns(), api.serviceAccounts(), api.currentAIAuditFindings("active")]); setRuns(runResult.items); setAccounts(accountResult.items.filter(item => item.role === "auditor")); setCurrentFindings(findingResult.items); }, []);
  useEffect(() => { void refresh().catch(reason => setError(message(reason))); }, [refresh, setError]);
  async function createIdentity(event: FormEvent) { event.preventDefault(); setBusy(true); try { const result = await api.createAuditorAccount(name, days); setToken(result.token); await refresh(); flash("Auditor identity created"); } catch (reason) { setError(message(reason)); } finally { setBusy(false); } }
  async function rotateIdentity(account: ServiceAccount) { if (!window.confirm(`Rotate the token for ${account.name}? Its current token will stop working immediately.`)) return; setBusy(true); try { const result = await api.rotateServiceAccount(account.id, days); setToken(result.token); await refresh(); flash("Auditor token rotated"); } catch (reason) { setError(message(reason)); } finally { setBusy(false); } }
  async function disableIdentity(account: ServiceAccount) { if (!window.confirm(`Disable ${account.name}? Its auditor token will stop working immediately.`)) return; setBusy(true); try { await api.disableServiceAccount(account.id); await refresh(); flash("Auditor identity disabled"); } catch (reason) { setError(message(reason)); } finally { setBusy(false); } }
  async function open(run: AIAuditRun) { setSelected(run.id); try { setFindings((await api.aiAuditFindings(run.id)).items); } catch (reason) { setError(message(reason)); } }
  async function triage(finding: AIAuditFinding, disposition: AIAuditFinding["disposition"]) { const note = window.prompt(`Optional operator note for ${disposition}`, finding.triageNote ?? ""); if (note === null) return; setBusy(true); try { const updated = await api.updateAIAuditFinding(finding.id, disposition, note); setFindings(items => items.map(item => item.id === updated.id ? updated : item)); setCurrentFindings(items => items.map(item => item.id === updated.id ? updated : item)); flash(`Finding marked ${disposition}`); } catch (reason) { setError(message(reason)); } finally { setBusy(false); } }
  return <>
    <div className="ai-layout"><form className="card settings-card" onSubmit={createIdentity}><p className="eyebrow">Least privilege</p><h2>Create auditor identity</h2><p className="muted">This token can read only the redacted AI snapshot and write findings. It cannot deploy or mutate resources.</p><label>Name<input value={name} onChange={e => setName(e.target.value)} required /></label><label>Token lifetime (days)<input type="number" min="1" max="365" value={days} onChange={e => setDays(Number(e.target.value))} /></label><button className="primary" disabled={busy}>Create one-time token</button></form>{token ? <section className="card credential-card"><p className="eyebrow">Save now</p><h2>Auditor token</h2><p className="muted">Store this as the <code>dockyard_ai_auditor_token</code> Swarm secret. It will not be shown again.</p><code>{token}</code><button onClick={() => navigator.clipboard.writeText(token)}>Copy token</button></section> : <Empty title="Deploy focused agents" text="Use the supplied Swarm overlay with 9Router or another OpenAI-compatible gateway." />}</div>
    <section className="card settings-card spaced"><div className="card-head"><div><p className="eyebrow">Credential lifecycle</p><h2>Auditor identities</h2></div><span className="count">{accounts.filter(item => item.enabled && (!item.tokenExpiresAt || new Date(item.tokenExpiresAt) > new Date())).length} active</span></div><p className="muted">Rotate tokens regularly and disable agents that no longer audit this organization. Rotation uses the lifetime selected above.</p><div className="admin-items">{accounts.map(account => { const expired = Boolean(account.tokenExpiresAt && new Date(account.tokenExpiresAt) <= new Date()); const status = !account.enabled ? "disabled" : expired ? "expired" : "active"; return <article key={account.id}><div><strong>{account.name}</strong><small>Expires {account.tokenExpiresAt ? new Date(account.tokenExpiresAt).toLocaleString() : "without an active token"}{account.lastUsedAt ? ` · last used ${new Date(account.lastUsedAt).toLocaleString()}` : " · never used"}</small></div><Status value={status} /><div className="actions">{account.enabled && <button type="button" disabled={busy} onClick={() => void rotateIdentity(account)}>Rotate</button>}{account.enabled && <button type="button" className="danger-button" disabled={busy} onClick={() => void disableIdentity(account)}>Disable</button>}</div></article>; })}{!accounts.length && <p className="muted">No auditor identities created.</p>}</div></section>
    <section className="card finding-list spaced"><div className="card-head"><div><p className="eyebrow">Latest per fingerprint</p><h2>Current findings</h2></div><span className="count">{currentFindings.length} active</span></div>{currentFindings.map(finding => <article key={finding.id}><Status value={finding.severity} /><div><strong>{finding.title}</strong><p>{finding.description}</p><small>{finding.agentName} · {finding.category}{finding.occurrenceNumber > 1 ? ` · seen ${finding.occurrenceNumber} times` : ""}</small>{finding.triageNote && <p className="muted">Operator note: {finding.triageNote}</p>}<div className="actions"><Status value={finding.disposition} />{finding.disposition === "open" && <button disabled={busy} onClick={() => void triage(finding, "acknowledged")}>Acknowledge</button>}<button disabled={busy} onClick={() => void triage(finding, "resolved")}>Resolve</button></div></div></article>)}{!currentFindings.length && <p className="muted">No active findings from the latest audit lineages.</p>}</section>
    <section className="section-head spaced"><div><h2>Agent audit runs</h2><p className="muted">Advisory findings only—remediation always requires an operator action.</p></div><button onClick={() => void refresh().catch(reason => setError(message(reason)))}>Refresh</button></section>
    <div className="grid">{runs.map(run => <button className="card service-card" key={run.id} onClick={() => void open(run)}><div className="service-icon">AI</div><div><h3>{run.agentName}</h3><p>{run.model || "model not reported"}</p></div><Status value={run.status} /><small>{new Date(run.startedAt).toLocaleString()}</small><b>Findings →</b></button>)}</div>
    {selected && <section className="card finding-list"><div className="card-head"><h3>Findings</h3><span className="count">{findings.length} total</span></div>{findings.map(finding => <article key={finding.id}><Status value={finding.severity} /><div><strong>{finding.title}</strong><p>{finding.description}</p><small>{finding.category}{finding.resourceType ? ` · ${finding.resourceType}:${finding.resourceId}` : ""}{finding.occurrenceNumber > 1 ? ` · seen ${finding.occurrenceNumber} times` : ""}</small>{finding.remediation && <p className="remediation">Remediation: {finding.remediation}</p>}{finding.triageNote && <p className="muted">Operator note: {finding.triageNote}</p>}<div className="actions"><Status value={finding.disposition} />{finding.disposition === "open" && <button disabled={busy} onClick={() => void triage(finding, "acknowledged")}>Acknowledge</button>}{finding.disposition !== "resolved" && <button disabled={busy} onClick={() => void triage(finding, "resolved")}>Resolve</button>}{finding.disposition !== "open" && <button disabled={busy} onClick={() => void triage(finding, "open")}>Reopen</button>}</div></div></article>)}{!findings.length && <p className="muted">This run reported no findings.</p>}</section>}
  </>;
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

const notificationEvents = ["deployment.failed", "service.stop.failed", "service.schedule.failed", "backup.failed", "restore.failed", "restore.drill.failed", "database.migration.failed", "audit.archive.failed", "ai.audit.failed", "ai.finding.critical"];

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
  const emptyDestination = { name: "", endpoint: "https://", region: "", bucket: "", prefix: "", useTls: true, accessKey: "", secretKey: "", sessionToken: "" };
  const [destination, setDestination] = useState(emptyDestination);
  const [oidcInput, setOIDCInput] = useState({ name: "", issuer: "https://", clientId: "", clientSecret: "", domains: "", scopes: "openid,email,profile", defaultRole: "developer" });
  const [samlInput, setSAMLInput] = useState({ name: "", metadataXml: "", domains: "", emailAttribute: "email", nameAttribute: "name", defaultRole: "developer", allowIdpInitiated: false });
  const [editingDestination, setEditingDestination] = useState(""); const [editingOIDC, setEditingOIDC] = useState(""); const [editingSAML, setEditingSAML] = useState("");
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

    <section className="card settings-card"><p className="eyebrow">Off-site storage</p><h2>Backup destinations</h2><form onSubmit={event => { event.preventDefault(); void run(async () => { if (editingDestination) await api.updateBackupDestination(editingDestination, destination); else await api.createBackupDestination(destination); setEditingDestination(""); setDestination(emptyDestination); }, editingDestination ? "Backup destination verified and credentials rotated" : "Backup destination verified and saved"); }}>
      <label>Name<input value={destination.name} onChange={e => setDestination({ ...destination, name: e.target.value })} required /></label>
      <label>Endpoint<input value={destination.endpoint} onChange={e => setDestination({ ...destination, endpoint: e.target.value, useTls: e.target.value.startsWith("https://") })} required /></label>
      <div className="field-row"><label>Region<input value={destination.region} onChange={e => setDestination({ ...destination, region: e.target.value })} /></label><label>Bucket<input value={destination.bucket} onChange={e => setDestination({ ...destination, bucket: e.target.value })} required /></label></div>
      <label>Object prefix<input value={destination.prefix} onChange={e => setDestination({ ...destination, prefix: e.target.value })} /></label>
      <label>Access key<input type="password" value={destination.accessKey} onChange={e => setDestination({ ...destination, accessKey: e.target.value })} required /></label>
      <label>Secret key<input type="password" value={destination.secretKey} onChange={e => setDestination({ ...destination, secretKey: e.target.value })} required /></label>
      <label>Session token (optional)<input type="password" value={destination.sessionToken} onChange={e => setDestination({ ...destination, sessionToken: e.target.value })} /></label>
      {editingDestination && <p className="muted">Enter replacement credentials. Stored credentials are never displayed.</p>}
      <button className="primary" disabled={busy}>{editingDestination ? "Verify and rotate" : "Verify and add"}</button>{editingDestination && <button type="button" onClick={() => { setEditingDestination(""); setDestination(emptyDestination); }}>Cancel edit</button>}
    </form><AdminItems items={destinations.map(x => ({ id: x.id, title: x.name, detail: `${x.bucket} · ${x.endpoint}` }))} action="Remove" onEdit={id => { const x = destinations.find(item => item.id === id); if (x) { setEditingDestination(id); setDestination({ name: x.name, endpoint: x.endpoint, region: x.region, bucket: x.bucket, prefix: x.prefix, useTls: x.useTls, accessKey: "", secretKey: "", sessionToken: "" }); } }} onAction={id => run(() => api.deleteBackupDestination(id), "Destination removed")} /></section>

    <section className="card settings-card"><p className="eyebrow">Single sign-on</p><h2>OIDC providers</h2><form onSubmit={event => { event.preventDefault(); const body = { ...oidcInput, domains: domains(oidcInput.domains), scopes: domains(oidcInput.scopes) }; void run(() => editingOIDC ? api.updateOIDCProvider(editingOIDC, body) : api.createOIDCProvider(body), editingOIDC ? "OIDC provider updated" : "OIDC provider enabled"); }}>
      <label>Name<input value={oidcInput.name} onChange={e => setOIDCInput({ ...oidcInput, name: e.target.value })} required /></label>
      <label>Issuer<input value={oidcInput.issuer} onChange={e => setOIDCInput({ ...oidcInput, issuer: e.target.value })} required /></label>
      <label>Client ID<input value={oidcInput.clientId} onChange={e => setOIDCInput({ ...oidcInput, clientId: e.target.value })} required /></label>
      <label>Client secret<input type="password" value={oidcInput.clientSecret} onChange={e => setOIDCInput({ ...oidcInput, clientSecret: e.target.value })} required={!editingOIDC} placeholder={editingOIDC ? "Leave blank to preserve current secret" : ""} /></label>
      <label>Email domains<input placeholder="example.com, subsidiary.test" value={oidcInput.domains} onChange={e => setOIDCInput({ ...oidcInput, domains: e.target.value })} required /></label>
      <label>Scopes<input value={oidcInput.scopes} onChange={e => setOIDCInput({ ...oidcInput, scopes: e.target.value })} /></label>
      <label>Default role<select value={oidcInput.defaultRole} onChange={e => setOIDCInput({ ...oidcInput, defaultRole: e.target.value })}><option>viewer</option><option>developer</option><option>admin</option></select></label>
      <button className="primary" disabled={busy}>{editingOIDC ? "Update / rotate" : "Add OIDC provider"}</button>{editingOIDC && <button type="button" onClick={() => setEditingOIDC("")}>Cancel edit</button>}
    </form><AdminItems items={oidc.map(x => ({ id: x.id, title: x.name, detail: `${x.issuer} · ${x.defaultRole}${x.enabled ? "" : " · disabled"}`, action: x.enabled ? "Disable" : "Enable" }))} action="Disable" onEdit={id => { const x = oidc.find(item => item.id === id); if (x) { setEditingOIDC(id); setOIDCInput({ name: x.name, issuer: x.issuer, clientId: x.clientId, clientSecret: "", domains: x.domains.join(", "), scopes: x.scopes.join(", "), defaultRole: x.defaultRole }); } }} onAction={id => { const x = oidc.find(item => item.id === id); return run(() => x?.enabled ? api.disableOIDCProvider(id) : api.enableOIDCProvider(id), x?.enabled ? "OIDC provider disabled" : "OIDC provider enabled"); }} /></section>

    <section className="card settings-card"><p className="eyebrow">Enterprise federation</p><h2>SAML providers</h2><form onSubmit={event => { event.preventDefault(); const body = { ...samlInput, domains: domains(samlInput.domains) }; void run(() => editingSAML ? api.updateSAMLProvider(editingSAML, body) : api.createSAMLProvider(body), editingSAML ? "SAML provider updated" : "SAML provider enabled"); }}>
      <label>Name<input value={samlInput.name} onChange={e => setSAMLInput({ ...samlInput, name: e.target.value })} required /></label>
      <label>IdP metadata XML<textarea className="compact-code" value={samlInput.metadataXml} onChange={e => setSAMLInput({ ...samlInput, metadataXml: e.target.value })} required /></label>
      <label>Email domains<input value={samlInput.domains} onChange={e => setSAMLInput({ ...samlInput, domains: e.target.value })} required /></label>
      <div className="field-row"><label>Email attribute<input value={samlInput.emailAttribute} onChange={e => setSAMLInput({ ...samlInput, emailAttribute: e.target.value })} /></label><label>Name attribute<input value={samlInput.nameAttribute} onChange={e => setSAMLInput({ ...samlInput, nameAttribute: e.target.value })} /></label></div>
      <label>Default role<select value={samlInput.defaultRole} onChange={e => setSAMLInput({ ...samlInput, defaultRole: e.target.value })}><option>viewer</option><option>developer</option><option>admin</option></select></label>
      <label className="check"><input type="checkbox" checked={samlInput.allowIdpInitiated} onChange={e => setSAMLInput({ ...samlInput, allowIdpInitiated: e.target.checked })} /> Allow IdP-initiated login</label>
      <button className="primary" disabled={busy}>{editingSAML ? "Update metadata" : "Add SAML provider"}</button>{editingSAML && <button type="button" onClick={() => setEditingSAML("")}>Cancel edit</button>}
    </form><div className="admin-items">{saml.map(x => <article key={x.id}><div><strong>{x.name}</strong><small>{x.domains.join(", ")} · {x.defaultRole}{x.enabled ? "" : " · disabled"}{x.certificateConfigurationOk && x.idpCertificateNotAfter && x.spCertificateNotAfter ? ` · IdP until ${new Date(x.idpCertificateNotAfter).toLocaleDateString()} · SP until ${new Date(x.spCertificateNotAfter).toLocaleDateString()}` : " · certificate attention required"}{x.pendingCertificateCreatedAt ? ` · rotation pending since ${new Date(x.pendingCertificateCreatedAt).toLocaleDateString()}` : ""}</small></div><div className="actions"><a className="button-link" href={`/v1/auth/saml/${x.id}/metadata`} target="_blank" rel="noreferrer">Metadata</a><button type="button" disabled={busy} onClick={() => { setEditingSAML(x.id); setSAMLInput({ name: x.name, metadataXml: "", domains: x.domains.join(", "), emailAttribute: x.emailAttribute, nameAttribute: x.nameAttribute, defaultRole: x.defaultRole, allowIdpInitiated: x.allowIdpInitiated }); }}>Edit</button>{x.pendingCertificateCreatedAt ? <><button type="button" disabled={busy} onClick={() => { const confirm = window.prompt(`Type ${x.name} to confirm that the IdP has imported the replacement certificate.`); if (confirm !== null) void run(() => api.promoteSAMLCertificateRotation(x.id, confirm), "SAML signing certificate promoted; in-flight logins were invalidated"); }}>Promote</button><button type="button" className="danger-button" disabled={busy} onClick={() => window.confirm(`Cancel the pending certificate rotation for ${x.name}?`) && void run(() => api.cancelSAMLCertificateRotation(x.id), "SAML certificate rotation cancelled")}>Cancel rotation</button></> : <button type="button" disabled={busy || !x.enabled} onClick={() => window.confirm(`Publish a replacement signing certificate for ${x.name}? Active requests continue using the current key until promotion.`) && void run(() => api.beginSAMLCertificateRotation(x.id), "Replacement certificate published in SAML metadata")}>Rotate certificate</button>}<button type="button" className={x.enabled ? "danger-button" : ""} disabled={busy} onClick={() => window.confirm(`${x.enabled ? "Disable" : "Enable"} ${x.name}?`) && void run(() => x.enabled ? api.disableSAMLProvider(x.id) : api.enableSAMLProvider(x.id), x.enabled ? "SAML provider disabled" : "SAML provider enabled")}>{x.enabled ? "Disable" : "Enable"}</button></div></article>)}{!saml.length && <p className="muted">None configured.</p>}</div></section>
  </div>;
}

function AdminItems({ items, action, onAction, onEdit }: { items: { id: string; title: string; detail: string; action?: string }[]; action: string; onAction: (id: string) => Promise<unknown>; onEdit?: (id: string) => void }) {
  return <div className="admin-items">{items.map(item => <article key={item.id}><div><strong>{item.title}</strong><small>{item.detail}</small></div><div className="actions">{onEdit && <button type="button" onClick={() => onEdit(item.id)}>Edit</button>}<button type="button" onClick={() => { const label = item.action ?? action; if (window.confirm(`${label} ${item.title}?`)) void onAction(item.id); }}>{item.action ?? action}</button></div></article>)}{!items.length && <p className="muted">None configured.</p>}</div>;
}

function Status({ value }: { value: string }) { return <span className={`status ${value}`}>{value.replaceAll("_", " ")}</span>; }
function Empty({ title, text }: { title: string; text: string }) { return <section className="empty card"><div>⌁</div><h3>{title}</h3><p className="muted">{text}</p></section>; }

createRoot(document.getElementById("root")!).render(<App />);
