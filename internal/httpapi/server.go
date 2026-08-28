package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/bendahma/dokploy-go/internal/auth"
	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/database"
	"github.com/bendahma/dokploy-go/internal/deploy"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/bendahma/dokploy-go/internal/templates"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type Server struct {
	Store      *store.Store
	Box        *cryptox.Box
	Compiler   deploy.Compiler
	Databases  *database.Registry
	Swarm      deploy.Swarm
	SessionTTL time.Duration
	Logger     *slog.Logger
	PublicURL  string
}

type contextKey string

const principalKey contextKey = "principal"

var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /metrics", s.metrics)
	mux.HandleFunc("POST /v1/auth/bootstrap", s.bootstrap)
	mux.HandleFunc("POST /v1/auth/login", s.login)
	mux.HandleFunc("GET /v1/auth/sso/discover", s.discoverOIDC)
	mux.HandleFunc("GET /v1/auth/sso/{providerID}/start", s.startOIDC)
	mux.HandleFunc("GET /v1/auth/sso/callback", s.callbackOIDC)
	mux.HandleFunc("POST /v1/hooks/deploy/{token}", s.deployWebhook)
	mux.Handle("POST /v1/auth/logout", s.requireAuth(http.HandlerFunc(s.logout)))
	mux.Handle("GET /v1/me", s.requireAuth(http.HandlerFunc(s.me)))
	mux.Handle("GET /v1/audit-events", s.requireRole("admin", http.HandlerFunc(s.auditEvents)))
	mux.Handle("GET /v1/swarm/nodes", s.requireRole("admin", http.HandlerFunc(s.swarmNodes)))
	mux.Handle("POST /v1/sso/oidc-providers", s.requireRole("admin", http.HandlerFunc(s.createOIDCProvider)))
	mux.Handle("GET /v1/sso/oidc-providers", s.requireRole("admin", http.HandlerFunc(s.listOIDCProviders)))
	mux.Handle("DELETE /v1/sso/oidc-providers/{providerID}", s.requireRole("admin", http.HandlerFunc(s.deleteOIDCProvider)))
	mux.Handle("POST /v1/scim/tokens", s.requireRole("admin", http.HandlerFunc(s.createSCIMToken)))
	mux.HandleFunc("GET /scim/v2/ServiceProviderConfig", s.scimServiceProviderConfig)
	mux.HandleFunc("GET /scim/v2/Users", s.scimUsers)
	mux.HandleFunc("POST /scim/v2/Users", s.scimUsers)
	mux.HandleFunc("GET /scim/v2/Users/{userID}", s.scimUser)
	mux.HandleFunc("PATCH /scim/v2/Users/{userID}", s.scimUser)
	mux.HandleFunc("DELETE /scim/v2/Users/{userID}", s.scimUser)
	mux.HandleFunc("GET /scim/v2/Groups", s.scimGroups)
	mux.HandleFunc("POST /scim/v2/Groups", s.scimGroups)
	mux.HandleFunc("GET /scim/v2/Groups/{groupID}", s.scimGroup)
	mux.HandleFunc("PATCH /scim/v2/Groups/{groupID}", s.scimGroup)
	mux.HandleFunc("DELETE /scim/v2/Groups/{groupID}", s.scimGroup)
	mux.Handle("GET /v1/projects", s.requireAuth(http.HandlerFunc(s.listProjects)))
	mux.Handle("POST /v1/projects", s.requireRole("developer", http.HandlerFunc(s.createProject)))
	mux.Handle("POST /v1/projects/{projectID}/environments", s.requireRole("developer", http.HandlerFunc(s.createEnvironment)))
	mux.Handle("GET /v1/projects/{projectID}/environments", s.requireAuth(http.HandlerFunc(s.listEnvironments)))
	mux.Handle("POST /v1/environments/{environmentID}/services", s.requireRole("developer", http.HandlerFunc(s.createService)))
	mux.Handle("GET /v1/environments/{environmentID}/services", s.requireAuth(http.HandlerFunc(s.listServices)))
	mux.Handle("GET /v1/database-engines", s.requireAuth(http.HandlerFunc(s.databaseEngines)))
	mux.Handle("POST /v1/environments/{environmentID}/databases", s.requireRole("developer", http.HandlerFunc(s.createDatabase)))
	mux.Handle("POST /v1/databases/{databaseID}/backups", s.requireRole("developer", http.HandlerFunc(s.createDatabaseBackup)))
	mux.Handle("GET /v1/databases/{databaseID}/backup-policy", s.requireAuth(http.HandlerFunc(s.getBackupPolicy)))
	mux.Handle("PUT /v1/databases/{databaseID}/backup-policy", s.requireRole("admin", http.HandlerFunc(s.putBackupPolicy)))
	mux.Handle("DELETE /v1/databases/{databaseID}/backup-policy", s.requireRole("admin", http.HandlerFunc(s.deleteBackupPolicy)))
	mux.Handle("GET /v1/database-backups/{backupID}", s.requireAuth(http.HandlerFunc(s.getDatabaseBackup)))
	mux.Handle("POST /v1/database-backups/{backupID}/restore", s.requireRole("admin", http.HandlerFunc(s.restoreDatabaseBackup)))
	mux.Handle("GET /v1/database-restores/{restoreID}", s.requireAuth(http.HandlerFunc(s.getDatabaseRestore)))
	mux.Handle("GET /v1/templates", s.requireAuth(http.HandlerFunc(s.listTemplates)))
	mux.Handle("POST /v1/templates/import/dokploy", s.requireRole("developer", http.HandlerFunc(s.importDokployTemplate)))
	mux.Handle("POST /v1/templates/{templateID}/instantiate", s.requireRole("developer", http.HandlerFunc(s.instantiateTemplate)))
	mux.Handle("GET /v1/services/{serviceID}", s.requireAuth(http.HandlerFunc(s.getService)))
	mux.Handle("DELETE /v1/services/{serviceID}", s.requireRole("admin", http.HandlerFunc(s.deleteService)))
	mux.Handle("PATCH /v1/services/{serviceID}", s.requireRole("developer", http.HandlerFunc(s.updateService)))
	mux.Handle("PUT /v1/services/{serviceID}/source", s.requireRole("developer", http.HandlerFunc(s.upsertSource)))
	mux.Handle("POST /v1/services/{serviceID}/routes", s.requireRole("developer", http.HandlerFunc(s.addRoute)))
	mux.Handle("POST /v1/services/{serviceID}/deployments", s.requireRole("developer", http.HandlerFunc(s.deployService)))
	mux.Handle("GET /v1/services/{serviceID}/deployments", s.requireAuth(http.HandlerFunc(s.listDeployments)))
	mux.Handle("GET /v1/services/{serviceID}/logs", s.requireAuth(http.HandlerFunc(s.serviceLogs)))
	mux.Handle("POST /v1/services/{serviceID}/rollback", s.requireRole("developer", http.HandlerFunc(s.rollbackService)))
	mux.Handle("POST /v1/services/{serviceID}/deploy-tokens", s.requireRole("developer", http.HandlerFunc(s.createDeployToken)))
	mux.Handle("GET /v1/deployments/{deploymentID}", s.requireAuth(http.HandlerFunc(s.getDeployment)))
	mux.Handle("POST /v1/deployments/{deploymentID}/cancel", s.requireRole("developer", http.HandlerFunc(s.cancelDeployment)))
	return s.middleware(mux)
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		defer func() {
			if recovered := recover(); recovered != nil {
				s.Logger.Error("panic", "error", recovered)
				writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if token == "" {
			writeError(w, 401, "unauthorized", "bearer token required")
			return
		}
		var orgID *uuid.UUID
		if raw := r.Header.Get("X-Organization-ID"); raw != "" {
			id, err := uuid.Parse(raw)
			if err != nil {
				writeError(w, 400, "invalid_organization", "invalid organization id")
				return
			}
			orgID = &id
		}
		p, err := s.Store.Authenticate(r.Context(), cryptox.Digest(token), orgID)
		if err != nil {
			writeError(w, 401, "unauthorized", "invalid or expired session")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey, p)))
	})
}

func (s *Server) requireRole(minimum string, next http.Handler) http.Handler {
	return s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := principal(r)
		if roleRank(p.Role) < roleRank(minimum) {
			writeError(w, 403, "forbidden", "insufficient role")
			return
		}
		next.ServeHTTP(w, r)
	}))
}
func roleRank(role string) int {
	return map[string]int{"viewer": 1, "developer": 2, "admin": 3, "owner": 4}[role]
}
func principal(r *http.Request) store.Principal {
	return r.Context().Value(principalKey).(store.Principal)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.Store.Pool.Ping(ctx); err != nil {
		writeError(w, 503, "database_unavailable", err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	rows, err := s.Store.Pool.Query(ctx, `SELECT status,count(*) FROM jobs GROUP BY status`)
	if err != nil {
		http.Error(w, "metrics unavailable", 503)
		return
	}
	defer rows.Close()
	fmt.Fprintln(w, "# HELP dockyard_jobs Number of durable jobs by state.")
	fmt.Fprintln(w, "# TYPE dockyard_jobs gauge")
	for rows.Next() {
		var status string
		var count int64
		if err := rows.Scan(&status, &count); err == nil {
			fmt.Fprintf(w, "dockyard_jobs{status=%q} %d\n", status, count)
		}
	}
	fmt.Fprintln(w, "dockyard_up 1")
}

func (s *Server) auditEvents(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	rows, err := s.Store.Pool.Query(r.Context(), `SELECT id,actor_user_id,action,resource_type,resource_id,remote_addr,metadata,created_at FROM audit_events WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 200`, p.OrganizationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id int64
		var actor *uuid.UUID
		var action, resourceType, resourceID, remoteAddr string
		var metadata json.RawMessage
		var created time.Time
		if err := rows.Scan(&id, &actor, &action, &resourceType, &resourceID, &remoteAddr, &metadata, &created); err != nil {
			writeStoreError(w, err)
			return
		}
		items = append(items, map[string]any{"id": id, "actorUserId": actor, "action": action, "resourceType": resourceType, "resourceId": resourceID, "remoteAddr": remoteAddr, "metadata": metadata, "createdAt": created})
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) swarmNodes(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	items, err := s.Swarm.Nodes(ctx)
	if err != nil {
		writeError(w, 502, "swarm_unavailable", err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) bootstrap(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email        string `json:"email"`
		Password     string `json:"password"`
		Organization string `json:"organization"`
	}
	if !decode(w, r, &in) {
		return
	}
	if _, err := mail.ParseAddress(in.Email); err != nil {
		writeError(w, 400, "invalid_email", "valid email required")
		return
	}
	slug := slugify(in.Organization)
	if slug == "" {
		writeError(w, 400, "invalid_organization", "organization name required")
		return
	}
	hash, err := auth.HashPassword(in.Password)
	if err != nil {
		writeError(w, 400, "invalid_password", err.Error())
		return
	}
	p, err := s.Store.Bootstrap(r.Context(), in.Email, hash, in.Organization, slug)
	if err != nil {
		writeError(w, 409, "bootstrap_failed", err.Error())
		return
	}
	token, err := s.newSession(r.Context(), p.UserID)
	if err != nil {
		writeError(w, 500, "session_failed", err.Error())
		return
	}
	s.Store.Audit(r.Context(), &p, "auth.bootstrap", "organization", p.OrganizationID.String(), r.RemoteAddr, nil)
	writeJSON(w, 201, map[string]any{"token": token, "principal": p})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	userID, hash, err := s.Store.PasswordLogin(r.Context(), in.Email)
	if err != nil || !auth.VerifyPassword(hash, in.Password) {
		time.Sleep(150 * time.Millisecond)
		writeError(w, 401, "invalid_credentials", "email or password is incorrect")
		return
	}
	token, err := s.newSession(r.Context(), userID)
	if err != nil {
		writeError(w, 500, "session_failed", err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"token": token})
}

func (s *Server) newSession(ctx context.Context, userID uuid.UUID) (string, error) {
	token, err := auth.NewToken()
	if err != nil {
		return "", err
	}
	if err = s.Store.CreateSession(ctx, userID, cryptox.Digest(token), time.Now().Add(s.SessionTTL)); err != nil {
		return "", err
	}
	return token, nil
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	_ = s.Store.DeleteSession(r.Context(), cryptox.Digest(token))
	w.WriteHeader(204)
}
func (s *Server) me(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, principal(r)) }

func (s *Server) listProjects(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	items, err := s.Store.ListProjects(r.Context(), p.OrganizationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
func (s *Server) createProject(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name        string `json:"name"`
		Slug        string `json:"slug"`
		Description string `json:"description"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Slug == "" {
		in.Slug = slugify(in.Name)
	}
	if !slugPattern.MatchString(in.Slug) || strings.TrimSpace(in.Name) == "" {
		writeError(w, 400, "invalid_project", "valid name and slug required")
		return
	}
	p := principal(r)
	item, err := s.Store.CreateProject(r.Context(), p.OrganizationID, in.Name, in.Slug, in.Description)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "project.create", "project", item.ID.String(), r.RemoteAddr, nil)
	writeJSON(w, 201, item)
}
func (s *Server) createEnvironment(w http.ResponseWriter, r *http.Request) {
	projectID, err := uuid.Parse(r.PathValue("projectID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid project id")
		return
	}
	var in struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Slug == "" {
		in.Slug = slugify(in.Name)
	}
	if !slugPattern.MatchString(in.Slug) {
		writeError(w, 400, "invalid_slug", "invalid slug")
		return
	}
	p := principal(r)
	item, err := s.Store.CreateEnvironment(r.Context(), p.OrganizationID, projectID, in.Name, in.Slug)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "environment.create", "environment", item.ID.String(), r.RemoteAddr, nil)
	writeJSON(w, 201, item)
}

func (s *Server) listEnvironments(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("projectID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid project id")
		return
	}
	items, err := s.Store.ListEnvironments(r.Context(), principal(r).OrganizationID, id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) createService(w http.ResponseWriter, r *http.Request) {
	environmentID, err := uuid.Parse(r.PathValue("environmentID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid environment id")
		return
	}
	var in struct {
		Name        string            `json:"name"`
		Slug        string            `json:"slug"`
		ComposeYAML string            `json:"composeYaml"`
		Environment map[string]string `json:"environment"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Slug == "" {
		in.Slug = slugify(in.Name)
	}
	if !slugPattern.MatchString(in.Slug) || len(in.ComposeYAML) > 2<<20 {
		writeError(w, 400, "invalid_service", "invalid slug or compose document too large")
		return
	}
	if _, err = s.Compiler.Compile(in.ComposeYAML, nil); err != nil {
		writeError(w, 400, "invalid_compose", err.Error())
		return
	}
	encrypted := ""
	if len(in.Environment) > 0 {
		plain, _ := json.Marshal(in.Environment)
		encrypted, err = s.Box.Encrypt(plain, "compose-env")
		if err != nil {
			writeError(w, 500, "encryption_failed", err.Error())
			return
		}
	}
	p := principal(r)
	id := uuid.New()
	item, err := s.Store.CreateComposeService(r.Context(), p.OrganizationID, store.ComposeService{ID: id, EnvironmentID: environmentID, Name: in.Name, Slug: in.Slug, StackName: "dy-" + in.Slug + "-" + strings.Split(id.String(), "-")[0], ComposeYAML: in.ComposeYAML, EncryptedEnv: encrypted})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "service.create", "compose_service", item.ID.String(), r.RemoteAddr, nil)
	writeJSON(w, 201, item)
}

func (s *Server) listServices(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("environmentID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid environment id")
		return
	}
	items, err := s.Store.ListComposeServices(r.Context(), principal(r).OrganizationID, id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) databaseEngines(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"items": s.Databases.Names()})
}
func (s *Server) createDatabase(w http.ResponseWriter, r *http.Request) {
	environmentID, err := uuid.Parse(r.PathValue("environmentID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid environment id")
		return
	}
	var in struct {
		Name    string         `json:"name"`
		Slug    string         `json:"slug"`
		Engine  string         `json:"engine"`
		Version string         `json:"version"`
		Config  map[string]any `json:"config"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Slug == "" {
		in.Slug = slugify(in.Name)
	}
	if !slugPattern.MatchString(in.Slug) {
		writeError(w, 400, "invalid_slug", "invalid slug")
		return
	}
	rendered, err := s.Databases.Render(in.Engine, database.Request{Name: in.Slug, Version: in.Version, Config: in.Config})
	if err != nil {
		writeError(w, 400, "invalid_database", err.Error())
		return
	}
	envJSON, _ := json.Marshal(rendered.Environment)
	encryptedEnv, err := s.Box.Encrypt(envJSON, "compose-env")
	if err != nil {
		writeError(w, 500, "encryption_failed", err.Error())
		return
	}
	credentialJSON, _ := json.Marshal(rendered.Credentials)
	encryptedCredentials, err := s.Box.Encrypt(credentialJSON, "database-credentials")
	if err != nil {
		writeError(w, 500, "encryption_failed", err.Error())
		return
	}
	p := principal(r)
	shortID := strings.Split(uuid.NewString(), "-")[0]
	stackName := "db-" + in.Slug + "-" + shortID
	instance, err := s.Store.CreateDatabase(r.Context(), p.OrganizationID, store.DatabaseInstance{EnvironmentID: environmentID, Name: in.Name, Slug: in.Slug, Engine: in.Engine, Version: rendered.Version, Config: in.Config}, store.ComposeService{Name: in.Name, Slug: "db-" + in.Slug, StackName: stackName, ComposeYAML: rendered.ComposeYAML, EncryptedEnv: encryptedEnv}, encryptedCredentials)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "database.create", "database", instance.ID.String(), r.RemoteAddr, map[string]any{"engine": in.Engine})
	writeJSON(w, 201, map[string]any{"database": instance, "credentials": rendered.Credentials, "internalUrl": rendered.InternalURL})
}

func (s *Server) createDatabaseBackup(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("databaseID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid database id")
		return
	}
	p := principal(r)
	backup, err := s.Store.QueueDatabaseBackup(r.Context(), p.OrganizationID, id, p.UserID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "database.backup.create", "database_backup", backup.ID.String(), r.RemoteAddr, nil)
	writeJSON(w, 202, backup)
}

func (s *Server) getBackupPolicy(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("databaseID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid database id")
		return
	}
	item, err := s.Store.GetBackupPolicy(r.Context(), principal(r).OrganizationID, id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, item)
}

func (s *Server) putBackupPolicy(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("databaseID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid database id")
		return
	}
	var in struct {
		IntervalSeconds int  `json:"intervalSeconds"`
		RetentionCount  int  `json:"retentionCount"`
		Enabled         bool `json:"enabled"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.IntervalSeconds < 900 || in.IntervalSeconds > 2678400 || in.RetentionCount < 1 || in.RetentionCount > 100 {
		writeError(w, 400, "invalid_backup_policy", "intervalSeconds must be 900..2678400 and retentionCount must be 1..100")
		return
	}
	p := principal(r)
	item, err := s.Store.UpsertBackupPolicy(r.Context(), p.OrganizationID, id, in.IntervalSeconds, in.RetentionCount, in.Enabled)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "backup_policy.update", "database", id.String(), r.RemoteAddr, map[string]any{"intervalSeconds": in.IntervalSeconds, "retentionCount": in.RetentionCount, "enabled": in.Enabled})
	writeJSON(w, 200, item)
}

func (s *Server) deleteBackupPolicy(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("databaseID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid database id")
		return
	}
	p := principal(r)
	if err = s.Store.DeleteBackupPolicy(r.Context(), p.OrganizationID, id); err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "backup_policy.delete", "database", id.String(), r.RemoteAddr, nil)
	w.WriteHeader(204)
}
func (s *Server) getDatabaseBackup(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("backupID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid backup id")
		return
	}
	backup, err := s.Store.GetDatabaseBackup(r.Context(), principal(r).OrganizationID, id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, backup)
}

func (s *Server) restoreDatabaseBackup(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("backupID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid backup id")
		return
	}
	var in struct {
		Confirm string `json:"confirm"`
	}
	if !decode(w, r, &in) {
		return
	}
	p := principal(r)
	restore, err := s.Store.QueueDatabaseRestore(r.Context(), p.OrganizationID, id, p.UserID, in.Confirm)
	if err != nil {
		if strings.Contains(err.Error(), "confirmation") || strings.Contains(err.Error(), "not restorable") {
			writeError(w, 409, "restore_rejected", err.Error())
			return
		}
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "database.restore.create", "database_restore", restore.ID.String(), r.RemoteAddr, map[string]any{"backupId": id})
	writeJSON(w, 202, restore)
}
func (s *Server) getDatabaseRestore(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("restoreID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid restore id")
		return
	}
	restore, err := s.Store.GetDatabaseRestore(r.Context(), principal(r).OrganizationID, id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, restore)
}

func (s *Server) listTemplates(w http.ResponseWriter, r *http.Request) {
	items, err := s.Store.ListTemplates(r.Context(), principal(r).OrganizationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) importDokployTemplate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Key          string `json:"key"`
		Version      string `json:"version"`
		Name         string `json:"name"`
		Description  string `json:"description"`
		TemplateTOML string `json:"templateToml"`
		ComposeYAML  string `json:"composeYaml"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !slugPattern.MatchString(in.Key) || in.Version == "" || in.Name == "" {
		writeError(w, 400, "invalid_template", "key, version and name are required")
		return
	}
	template, err := templates.ParseDokploy([]byte(in.TemplateTOML))
	if err != nil {
		writeError(w, 400, "invalid_template", err.Error())
		return
	}
	instance, err := templates.Instantiate(template, in.ComposeYAML, "example.invalid")
	if err == nil {
		instance.ComposeYAML, err = templates.ApplyMounts(instance.ComposeYAML, instance.Mounts)
	}
	if err == nil {
		_, err = s.Compiler.Compile(instance.ComposeYAML, nil)
	}
	if err != nil {
		writeError(w, 400, "invalid_template", err.Error())
		return
	}
	config, _ := json.Marshal(map[string]string{"templateToml": in.TemplateTOML})
	sum := sha256.Sum256(append([]byte(in.TemplateTOML), []byte(in.ComposeYAML)...))
	p := principal(r)
	item, err := s.Store.CreateTemplate(r.Context(), store.Template{OrganizationID: &p.OrganizationID, Key: in.Key, Version: in.Version, Name: in.Name, Description: in.Description, ComposeYAML: in.ComposeYAML, Config: config, Source: "dokploy", Checksum: hex.EncodeToString(sum[:])})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "template.import", "template", item.ID.String(), r.RemoteAddr, nil)
	writeJSON(w, 201, item)
}

func (s *Server) instantiateTemplate(w http.ResponseWriter, r *http.Request) {
	templateID, err := uuid.Parse(r.PathValue("templateID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid template id")
		return
	}
	var in struct {
		EnvironmentID uuid.UUID `json:"environmentId"`
		Name          string    `json:"name"`
		Slug          string    `json:"slug"`
		BaseDomain    string    `json:"baseDomain"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Slug == "" {
		in.Slug = slugify(in.Name)
	}
	if !slugPattern.MatchString(in.Slug) {
		writeError(w, 400, "invalid_slug", "invalid slug")
		return
	}
	p := principal(r)
	item, err := s.Store.GetTemplate(r.Context(), p.OrganizationID, templateID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	var config map[string]string
	if err = json.Unmarshal(item.Config, &config); err != nil {
		writeError(w, 500, "invalid_template", "stored template config is invalid")
		return
	}
	template, err := templates.ParseDokploy([]byte(config["templateToml"]))
	if err != nil {
		writeError(w, 500, "invalid_template", err.Error())
		return
	}
	instance, err := templates.Instantiate(template, item.ComposeYAML, in.BaseDomain)
	if err == nil {
		instance.ComposeYAML, err = templates.ApplyMounts(instance.ComposeYAML, instance.Mounts)
	}
	if err == nil {
		_, err = s.Compiler.Compile(instance.ComposeYAML, nil)
	}
	if err != nil {
		writeError(w, 400, "invalid_template", err.Error())
		return
	}
	envJSON, _ := json.Marshal(instance.Environment)
	encryptedEnv, err := s.Box.Encrypt(envJSON, "compose-env")
	if err != nil {
		writeError(w, 500, "encryption_failed", err.Error())
		return
	}
	shortID := strings.Split(uuid.NewString(), "-")[0]
	service, err := s.Store.CreateComposeService(r.Context(), p.OrganizationID, store.ComposeService{EnvironmentID: in.EnvironmentID, Name: in.Name, Slug: in.Slug, StackName: "tpl-" + in.Slug + "-" + shortID, ComposeYAML: instance.ComposeYAML, EncryptedEnv: encryptedEnv})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	routes := []store.Route{}
	for _, domain := range instance.Domains {
		port, portErr := templates.PortNumber(domain.Port)
		if portErr != nil {
			writeError(w, 400, "invalid_template", portErr.Error())
			return
		}
		route, routeErr := s.Store.AddRoute(r.Context(), p.OrganizationID, store.Route{ComposeServiceID: service.ID, ServiceName: domain.ServiceName, Host: domain.Host, PathPrefix: domain.Path, TargetPort: port, TLS: true, CertificateResolver: "letsencrypt"})
		if routeErr != nil {
			writeStoreError(w, routeErr)
			return
		}
		routes = append(routes, route)
	}
	s.Store.Audit(r.Context(), &p, "template.instantiate", "compose_service", service.ID.String(), r.RemoteAddr, map[string]any{"templateId": templateID})
	writeJSON(w, 201, map[string]any{"service": service, "routes": routes})
}

func (s *Server) getService(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid service id")
		return
	}
	item, routes, err := s.Store.GetComposeService(r.Context(), principal(r).OrganizationID, id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"service": item, "routes": routes})
}

func (s *Server) deleteService(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid service id")
		return
	}
	p := principal(r)
	if err = s.Store.QueueServiceDeletion(r.Context(), p.OrganizationID, id); err != nil {
		if errors.Is(err, store.ErrBusy) {
			writeError(w, 409, "service_busy", "cancel or wait for active deployments before deleting the service")
			return
		}
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "service.delete", "compose_service", id.String(), r.RemoteAddr, nil)
	writeJSON(w, 202, map[string]string{"status": "deletion_queued"})
}

func (s *Server) updateService(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid service id")
		return
	}
	var in struct {
		ComposeYAML string            `json:"composeYaml"`
		Environment map[string]string `json:"environment"`
	}
	if !decode(w, r, &in) {
		return
	}
	if _, err = s.Compiler.Compile(in.ComposeYAML, nil); err != nil {
		writeError(w, 400, "invalid_compose", err.Error())
		return
	}
	encrypted := ""
	if len(in.Environment) > 0 {
		plain, _ := json.Marshal(in.Environment)
		encrypted, err = s.Box.Encrypt(plain, "compose-env")
		if err != nil {
			writeError(w, 500, "encryption_failed", err.Error())
			return
		}
	}
	p := principal(r)
	item, err := s.Store.UpdateComposeService(r.Context(), p.OrganizationID, id, in.ComposeYAML, encrypted)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "service.update", "compose_service", id.String(), r.RemoteAddr, map[string]any{"revision": item.Revision})
	writeJSON(w, 200, item)
}

func (s *Server) upsertSource(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid service id")
		return
	}
	var in struct {
		RepositoryURL    string `json:"repositoryUrl"`
		GitRef           string `json:"gitRef"`
		ContextDirectory string `json:"contextDirectory"`
		Dockerfile       string `json:"dockerfile"`
		TargetService    string `json:"targetService"`
		RegistryImage    string `json:"registryImage"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.GitRef == "" {
		in.GitRef = "main"
	}
	if in.ContextDirectory == "" {
		in.ContextDirectory = "."
	}
	if in.Dockerfile == "" {
		in.Dockerfile = "Dockerfile"
	}
	if in.RepositoryURL == "" || in.TargetService == "" || in.RegistryImage == "" {
		writeError(w, 400, "invalid_source", "repositoryUrl, targetService and registryImage are required")
		return
	}
	p := principal(r)
	item, err := s.Store.UpsertApplicationSource(r.Context(), p.OrganizationID, store.ApplicationSource{ComposeServiceID: id, RepositoryURL: in.RepositoryURL, GitRef: in.GitRef, ContextDirectory: in.ContextDirectory, Dockerfile: in.Dockerfile, TargetService: in.TargetService, RegistryImage: in.RegistryImage})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "source.update", "compose_service", id.String(), r.RemoteAddr, map[string]any{"repository": in.RepositoryURL, "ref": in.GitRef})
	writeJSON(w, 200, item)
}
func (s *Server) addRoute(w http.ResponseWriter, r *http.Request) {
	serviceID, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid service id")
		return
	}
	var in struct {
		ServiceName         string `json:"serviceName"`
		Host                string `json:"host"`
		PathPrefix          string `json:"pathPrefix"`
		TargetPort          int    `json:"targetPort"`
		TLS                 *bool  `json:"tls"`
		CertificateResolver string `json:"certificateResolver"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Host = strings.ToLower(strings.TrimSpace(in.Host))
	if in.PathPrefix == "" {
		in.PathPrefix = "/"
	}
	if in.CertificateResolver == "" {
		in.CertificateResolver = "letsencrypt"
	}
	tls := true
	if in.TLS != nil {
		tls = *in.TLS
	}
	if in.ServiceName == "" || !strings.Contains(in.Host, ".") || in.TargetPort < 1 || in.TargetPort > 65535 || !strings.HasPrefix(in.PathPrefix, "/") {
		writeError(w, 400, "invalid_route", "invalid route")
		return
	}
	p := principal(r)
	item, err := s.Store.AddRoute(r.Context(), p.OrganizationID, store.Route{ComposeServiceID: serviceID, ServiceName: in.ServiceName, Host: in.Host, PathPrefix: in.PathPrefix, TargetPort: in.TargetPort, TLS: tls, CertificateResolver: in.CertificateResolver})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "route.create", "route", item.ID.String(), r.RemoteAddr, nil)
	writeJSON(w, 201, item)
}
func (s *Server) deployService(w http.ResponseWriter, r *http.Request) {
	serviceID, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid service id")
		return
	}
	p := principal(r)
	item, err := s.Store.QueueDeployment(r.Context(), p.OrganizationID, serviceID, p.UserID, "manual")
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "deployment.create", "deployment", item.ID.String(), r.RemoteAddr, nil)
	writeJSON(w, 202, item)
}

func (s *Server) listDeployments(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid service id")
		return
	}
	items, err := s.Store.ListDeployments(r.Context(), principal(r).OrganizationID, id, 50)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
func (s *Server) serviceLogs(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid service id")
		return
	}
	item, _, err := s.Store.GetComposeService(r.Context(), principal(r).OrganizationID, id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	logs, err := s.Swarm.Logs(ctx, item.StackName, 500)
	if err != nil {
		writeError(w, 502, "logs_failed", err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"logs": logs})
}

func (s *Server) rollbackService(w http.ResponseWriter, r *http.Request) {
	serviceID, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid service id")
		return
	}
	p := principal(r)
	item, err := s.Store.QueueRollback(r.Context(), p.OrganizationID, serviceID, p.UserID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "deployment.rollback", "deployment", item.ID.String(), r.RemoteAddr, nil)
	writeJSON(w, 202, item)
}

func (s *Server) createDeployToken(w http.ResponseWriter, r *http.Request) {
	serviceID, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid service id")
		return
	}
	var in struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.Name) == "" {
		in.Name = "default"
	}
	token, err := auth.NewToken()
	if err != nil {
		writeError(w, 500, "token_failed", err.Error())
		return
	}
	p := principal(r)
	if err = s.Store.CreateDeployToken(r.Context(), p.OrganizationID, serviceID, p.UserID, in.Name, cryptox.Digest(token)); err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "deploy_token.create", "compose_service", serviceID.String(), r.RemoteAddr, nil)
	writeJSON(w, 201, map[string]string{"token": token, "url": s.PublicURL + "/v1/hooks/deploy/" + token})
}
func (s *Server) deployWebhook(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if token == "" {
		writeError(w, 404, "not_found", "deployment token not found")
		return
	}
	deployment, err := s.Store.QueueDeploymentByToken(r.Context(), cryptox.Digest(token))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, 404, "not_found", "deployment token not found")
			return
		}
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 202, deployment)
}
func (s *Server) getDeployment(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("deploymentID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid deployment id")
		return
	}
	p := principal(r)
	var d store.Deployment
	err = s.Store.Pool.QueryRow(r.Context(), `SELECT d.id,d.compose_service_id,d.revision,d.status,d.trigger,d.error,d.output,d.created_at,d.started_at,d.finished_at FROM deployments d JOIN compose_services s ON s.id=d.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE d.id=$1 AND p.organization_id=$2`, id, p.OrganizationID).Scan(&d.ID, &d.ComposeServiceID, &d.Revision, &d.Status, &d.Trigger, &d.Error, &d.Output, &d.CreatedAt, &d.StartedAt, &d.FinishedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = store.ErrNotFound
	}
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, d)
}

func (s *Server) cancelDeployment(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("deploymentID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid deployment id")
		return
	}
	p := principal(r)
	if err = s.Store.CancelDeployment(r.Context(), p.OrganizationID, id); err != nil {
		if errors.Is(err, store.ErrNotCancellable) {
			writeError(w, 409, "not_cancellable", err.Error())
			return
		}
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "deployment.cancel", "deployment", id.String(), r.RemoteAddr, nil)
	writeJSON(w, 202, map[string]string{"status": "cancellation_requested"})
}

func decode(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 3<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, 400, "invalid_json", err.Error())
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, 400, "invalid_json", "request must contain one JSON value")
		return false
	}
	return true
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}
func writeStoreError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 404, "not_found", "resource not found")
		return
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		writeError(w, 409, "conflict", "resource already exists")
		return
	}
	if errors.As(err, &pgErr) && strings.HasPrefix(pgErr.Code, "23") {
		writeError(w, 400, "constraint_violation", "request violates a resource constraint")
		return
	}
	writeError(w, 500, "internal_error", "database operation failed")
}
func slugify(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(value, "-")
	return strings.Trim(value, "-")
}

var _ = fmt.Sprintf
