package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type AIAuditSnapshot struct {
	GeneratedAt          time.Time                       `json:"generatedAt"`
	Organization         uuid.UUID                       `json:"organizationId"`
	Projects             []Project                       `json:"projects"`
	Environments         []Environment                   `json:"environments"`
	Services             []ComposeService                `json:"services"`
	Routes               []Route                         `json:"routes"`
	Databases            []DatabaseInstance              `json:"databases"`
	Clusters             []Cluster                       `json:"clusters"`
	BackupPosture        []AIAuditBackupPosture          `json:"backupPosture"`
	IdentityPosture      AIAuditIdentityPosture          `json:"identityPosture"`
	NotificationPosture  []AIAuditNotificationPosture    `json:"notificationPosture"`
	TemplateRepositories []AIAuditTemplateRepositoryInfo `json:"templateRepositories"`
	ServiceDeployments   []AIAuditServiceDeployment      `json:"serviceDeployments"`
	QueuePosture         AIAuditQueuePosture             `json:"queuePosture"`
	Reconciliation       []ServiceReconciliation         `json:"reconciliation"`
	Signals              []AIAuditSignal                 `json:"signals30d"`
	AuditEvents          []AuditEvent                    `json:"recentAuditEvents"`
}

type AIAuditSignal struct {
	Kind   string `json:"kind"`
	Status string `json:"status"`
	Count  int64  `json:"count"`
}

type AIAuditBackupPosture struct {
	DatabaseID             uuid.UUID  `json:"databaseId"`
	Name                   string     `json:"name"`
	Engine                 string     `json:"engine"`
	Status                 string     `json:"status"`
	PolicyConfigured       bool       `json:"policyConfigured"`
	PolicyEnabled          bool       `json:"policyEnabled"`
	IntervalSeconds        int        `json:"intervalSeconds"`
	RetentionCount         int        `json:"retentionCount"`
	VerifyRestore          bool       `json:"verifyRestore"`
	RemoteDestination      bool       `json:"remoteDestination"`
	LastBackupStatus       string     `json:"lastBackupStatus,omitempty"`
	LastBackupAt           *time.Time `json:"lastBackupAt,omitempty"`
	LastRestoreDrillStatus string     `json:"lastRestoreDrillStatus,omitempty"`
	LastRestoreDrillAt     *time.Time `json:"lastRestoreDrillAt,omitempty"`
}

type AIAuditIdentityPosture struct {
	RequireSSO           bool  `json:"requireSso"`
	EnabledOIDCProviders int64 `json:"enabledOidcProviders"`
	EnabledSAMLProviders int64 `json:"enabledSamlProviders"`
}

type AIAuditNotificationPosture struct {
	ID      uuid.UUID `json:"id"`
	Name    string    `json:"name"`
	Kind    string    `json:"kind"`
	Events  []string  `json:"events"`
	Enabled bool      `json:"enabled"`
}

type AIAuditTemplateRepositoryInfo struct {
	ID                   uuid.UUID  `json:"id"`
	Name                 string     `json:"name"`
	GitRef               string     `json:"gitRef"`
	RequireSignature     bool       `json:"requireSignature"`
	CredentialConfigured bool       `json:"credentialConfigured"`
	WebhookConfigured    bool       `json:"webhookConfigured"`
	SyncIntervalSeconds  int        `json:"syncIntervalSeconds"`
	Enabled              bool       `json:"enabled"`
	LastSyncStatus       string     `json:"lastSyncStatus"`
	LastSyncedAt         *time.Time `json:"lastSyncedAt,omitempty"`
}

type AIAuditServiceDeployment struct {
	ServiceID                uuid.UUID  `json:"serviceId"`
	Name                     string     `json:"name"`
	DesiredRevision          int64      `json:"desiredRevision"`
	LatestDeploymentStatus   string     `json:"latestDeploymentStatus,omitempty"`
	LatestDeploymentRevision int64      `json:"latestDeploymentRevision,omitempty"`
	LatestDeploymentAt       *time.Time `json:"latestDeploymentAt,omitempty"`
	CurrentRevisionDeployed  bool       `json:"currentRevisionDeployed"`
}

type AIAuditQueuePosture struct {
	Coverage            string     `json:"coverage"`
	PendingServiceJobs  int64      `json:"pendingServiceJobs"`
	RunningServiceJobs  int64      `json:"runningServiceJobs"`
	PendingDatabaseJobs int64      `json:"pendingDatabaseJobs"`
	RunningDatabaseJobs int64      `json:"runningDatabaseJobs"`
	OldestPendingAt     *time.Time `json:"oldestPendingAt,omitempty"`
}

// BuildAIAuditSnapshot deliberately uses the list projections: Compose source,
// environment values, credentials, and backup contents never enter the agent
// context. The snapshot is broad but remains read-only and secret-free.
func (s *Store) BuildAIAuditSnapshot(ctx context.Context, organizationID uuid.UUID) (AIAuditSnapshot, error) {
	snapshot := AIAuditSnapshot{GeneratedAt: time.Now().UTC(), Organization: organizationID, Projects: []Project{}, Environments: []Environment{}, Services: []ComposeService{}, Routes: []Route{}, Databases: []DatabaseInstance{}, Clusters: []Cluster{}, BackupPosture: []AIAuditBackupPosture{}, NotificationPosture: []AIAuditNotificationPosture{}, TemplateRepositories: []AIAuditTemplateRepositoryInfo{}, ServiceDeployments: []AIAuditServiceDeployment{}, QueuePosture: AIAuditQueuePosture{Coverage: "resource-keyed-service-and-database-jobs"}, Reconciliation: []ServiceReconciliation{}, Signals: []AIAuditSignal{}, AuditEvents: []AuditEvent{}}
	projects, err := s.ListProjects(ctx, organizationID)
	if err != nil {
		return snapshot, err
	}
	snapshot.Projects = projects
	for _, project := range projects {
		environments, listErr := s.ListEnvironments(ctx, organizationID, project.ID)
		if listErr != nil {
			return snapshot, listErr
		}
		snapshot.Environments = append(snapshot.Environments, environments...)
		for _, environment := range environments {
			services, serviceErr := s.ListComposeServices(ctx, organizationID, environment.ID)
			if serviceErr != nil {
				return snapshot, serviceErr
			}
			snapshot.Services = append(snapshot.Services, services...)
			for _, service := range services {
				_, routes, routeErr := s.GetComposeService(ctx, organizationID, service.ID)
				if routeErr != nil {
					return snapshot, routeErr
				}
				snapshot.Routes = append(snapshot.Routes, routes...)
			}
			databases, databaseErr := s.ListDatabases(ctx, organizationID, environment.ID)
			if databaseErr != nil {
				return snapshot, databaseErr
			}
			for index := range databases {
				// Drivers may accept credentials in their input config even though
				// built-ins normally store only non-secret settings here.
				databases[index].Config = nil
			}
			snapshot.Databases = append(snapshot.Databases, databases...)
		}
	}
	clusters, err := s.ListClusters(ctx, organizationID)
	if err != nil {
		return snapshot, err
	}
	snapshot.Clusters = clusters
	reconciliation, err := s.ListServiceReconciliations(ctx, organizationID)
	if err != nil {
		return snapshot, err
	}
	snapshot.Reconciliation = reconciliation
	if err = s.loadAIAuditOperationalPosture(ctx, organizationID, &snapshot); err != nil {
		return snapshot, err
	}
	events, err := s.ListAuditEvents(ctx, organizationID, 0, 500, false)
	if err != nil {
		return snapshot, err
	}
	for index := range events {
		events[index].Metadata = nil
		events[index].RemoteAddr = ""
	}
	snapshot.AuditEvents = events
	rows, err := s.Pool.Query(ctx, `
		SELECT kind,status,count(*) FROM (
			SELECT 'deployment' AS kind,d.status,d.created_at FROM deployments d JOIN compose_services s ON s.id=d.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE p.organization_id=$1
			UNION ALL SELECT 'backup',b.status,b.created_at FROM database_backups b JOIN database_instances d ON d.id=b.database_instance_id JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE p.organization_id=$1
			UNION ALL SELECT 'restore',r.status,r.created_at FROM database_restores r JOIN database_backups b ON b.id=r.database_backup_id JOIN database_instances d ON d.id=b.database_instance_id JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE p.organization_id=$1
			UNION ALL SELECT 'notification',d.status,d.created_at FROM notification_deliveries d JOIN notification_endpoints n ON n.id=d.endpoint_id WHERE n.organization_id=$1
		) activity WHERE created_at>=now()-interval '30 days' GROUP BY kind,status ORDER BY kind,status`, organizationID)
	if err != nil {
		return snapshot, err
	}
	defer rows.Close()
	for rows.Next() {
		var signal AIAuditSignal
		if err = rows.Scan(&signal.Kind, &signal.Status, &signal.Count); err != nil {
			return snapshot, err
		}
		snapshot.Signals = append(snapshot.Signals, signal)
	}
	if err = rows.Err(); err != nil {
		return snapshot, err
	}
	return snapshot, nil
}

func (s *Store) loadAIAuditOperationalPosture(ctx context.Context, organizationID uuid.UUID, snapshot *AIAuditSnapshot) error {
	rows, err := s.Pool.Query(ctx, `
		SELECT d.id,d.name,d.engine,d.status,
			bp.id IS NOT NULL,COALESCE(bp.enabled,false),COALESCE(bp.interval_seconds,0),COALESCE(bp.retention_count,0),COALESCE(bp.verify_restore,false),bp.destination_id IS NOT NULL,
			COALESCE(last_backup.status,''),last_backup.created_at,COALESCE(last_drill.status,''),last_drill.created_at
		FROM database_instances d
		JOIN environments e ON e.id=d.environment_id
		JOIN projects p ON p.id=e.project_id
		LEFT JOIN backup_policies bp ON bp.database_instance_id=d.id
		LEFT JOIN LATERAL (SELECT b.status,b.created_at FROM database_backups b WHERE b.database_instance_id=d.id ORDER BY b.created_at DESC LIMIT 1) last_backup ON true
		LEFT JOIN LATERAL (SELECT r.status,r.created_at FROM database_restores r JOIN database_backups b ON b.id=r.database_backup_id WHERE b.database_instance_id=d.id AND r.kind='drill' ORDER BY r.created_at DESC LIMIT 1) last_drill ON true
		WHERE p.organization_id=$1 ORDER BY d.name,d.id`, organizationID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var item AIAuditBackupPosture
		if err = rows.Scan(&item.DatabaseID, &item.Name, &item.Engine, &item.Status, &item.PolicyConfigured, &item.PolicyEnabled, &item.IntervalSeconds, &item.RetentionCount, &item.VerifyRestore, &item.RemoteDestination, &item.LastBackupStatus, &item.LastBackupAt, &item.LastRestoreDrillStatus, &item.LastRestoreDrillAt); err != nil {
			rows.Close()
			return err
		}
		snapshot.BackupPosture = append(snapshot.BackupPosture, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	rows, err = s.Pool.Query(ctx, `
		SELECT s.id,s.name,s.revision,COALESCE(latest.status,''),COALESCE(latest.revision,0),latest.created_at,
			EXISTS(SELECT 1 FROM deployments deployed WHERE deployed.compose_service_id=s.id AND deployed.revision=s.revision AND deployed.status='succeeded')
		FROM compose_services s
		JOIN environments e ON e.id=s.environment_id
		JOIN projects p ON p.id=e.project_id
		LEFT JOIN LATERAL (
			SELECT d.status,d.revision,d.created_at
			FROM deployments d
			WHERE d.compose_service_id=s.id
			ORDER BY d.created_at DESC,d.id DESC
			LIMIT 1
		) latest ON true
		WHERE p.organization_id=$1 AND s.deletion_requested_at IS NULL
		ORDER BY s.name,s.id`, organizationID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var item AIAuditServiceDeployment
		if err = rows.Scan(&item.ServiceID, &item.Name, &item.DesiredRevision, &item.LatestDeploymentStatus, &item.LatestDeploymentRevision, &item.LatestDeploymentAt, &item.CurrentRevisionDeployed); err != nil {
			rows.Close()
			return err
		}
		snapshot.ServiceDeployments = append(snapshot.ServiceDeployments, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	err = s.Pool.QueryRow(ctx, `
		WITH scoped_jobs AS (
			SELECT j.status,j.created_at,'service'::text AS resource_type
			FROM jobs j
			JOIN compose_services s ON j.resource_key='service:' || s.id::text
			JOIN environments e ON e.id=s.environment_id
			JOIN projects p ON p.id=e.project_id
			WHERE p.organization_id=$1 AND j.status IN ('pending','running')
			UNION ALL
			SELECT j.status,j.created_at,'database'::text AS resource_type
			FROM jobs j
			JOIN database_instances d ON j.resource_key='database:' || d.id::text
			JOIN environments e ON e.id=d.environment_id
			JOIN projects p ON p.id=e.project_id
			WHERE p.organization_id=$1 AND j.status IN ('pending','running')
		)
		SELECT
			count(*) FILTER (WHERE resource_type='service' AND status='pending'),
			count(*) FILTER (WHERE resource_type='service' AND status='running'),
			count(*) FILTER (WHERE resource_type='database' AND status='pending'),
			count(*) FILTER (WHERE resource_type='database' AND status='running'),
			min(created_at) FILTER (WHERE status='pending')
		FROM scoped_jobs`, organizationID).Scan(&snapshot.QueuePosture.PendingServiceJobs, &snapshot.QueuePosture.RunningServiceJobs, &snapshot.QueuePosture.PendingDatabaseJobs, &snapshot.QueuePosture.RunningDatabaseJobs, &snapshot.QueuePosture.OldestPendingAt)
	if err != nil {
		return err
	}

	err = s.Pool.QueryRow(ctx, `SELECT
		COALESCE((SELECT require_sso FROM organization_auth_settings WHERE organization_id=$1),false),
		(SELECT count(*) FROM oidc_providers WHERE organization_id=$1 AND enabled),
		(SELECT count(*) FROM saml_providers WHERE organization_id=$1 AND enabled)`, organizationID).Scan(&snapshot.IdentityPosture.RequireSSO, &snapshot.IdentityPosture.EnabledOIDCProviders, &snapshot.IdentityPosture.EnabledSAMLProviders)
	if err != nil {
		return err
	}

	endpoints, err := s.ListNotificationEndpoints(ctx, organizationID)
	if err != nil {
		return err
	}
	for _, endpoint := range endpoints {
		snapshot.NotificationPosture = append(snapshot.NotificationPosture, AIAuditNotificationPosture{ID: endpoint.ID, Name: endpoint.Name, Kind: endpoint.Kind, Events: endpoint.Events, Enabled: endpoint.Enabled})
	}
	repositories, err := s.ListTemplateRepositories(ctx, organizationID)
	if err != nil {
		return err
	}
	for _, repository := range repositories {
		snapshot.TemplateRepositories = append(snapshot.TemplateRepositories, AIAuditTemplateRepositoryInfo{ID: repository.ID, Name: repository.Name, GitRef: repository.GitRef, RequireSignature: repository.RequireSignature, CredentialConfigured: repository.CredentialID != nil, WebhookConfigured: repository.WebhookConfigured, SyncIntervalSeconds: repository.SyncIntervalSeconds, Enabled: repository.Enabled, LastSyncStatus: repository.LastSyncStatus, LastSyncedAt: repository.LastSyncedAt})
	}
	return nil
}

type AIAuditRun struct {
	ID               uuid.UUID       `json:"id"`
	OrganizationID   uuid.UUID       `json:"organizationId"`
	ServiceAccountID uuid.UUID       `json:"serviceAccountId"`
	AgentName        string          `json:"agentName"`
	AgentVersion     string          `json:"agentVersion"`
	Model            string          `json:"model"`
	Status           string          `json:"status"`
	Scope            json.RawMessage `json:"scope"`
	Summary          string          `json:"summary"`
	StartedAt        time.Time       `json:"startedAt"`
	CompletedAt      *time.Time      `json:"completedAt,omitempty"`
}

type AIAuditFinding struct {
	ID           uuid.UUID       `json:"id"`
	RunID        uuid.UUID       `json:"runId"`
	Severity     string          `json:"severity"`
	Category     string          `json:"category"`
	Title        string          `json:"title"`
	Description  string          `json:"description"`
	ResourceType string          `json:"resourceType,omitempty"`
	ResourceID   string          `json:"resourceId,omitempty"`
	Evidence     json.RawMessage `json:"evidence"`
	Remediation  string          `json:"remediation,omitempty"`
	Fingerprint  string          `json:"fingerprint"`
	CreatedAt    time.Time       `json:"createdAt"`
}

func (s *Store) CreateAIAuditRun(ctx context.Context, organizationID, accountID uuid.UUID, agentName, agentVersion, model string, scope json.RawMessage) (AIAuditRun, error) {
	if len(scope) == 0 {
		scope = json.RawMessage(`{}`)
	}
	item := AIAuditRun{ID: uuid.New(), OrganizationID: organizationID, ServiceAccountID: accountID, AgentName: agentName, AgentVersion: agentVersion, Model: model, Status: "running", Scope: scope}
	err := s.Pool.QueryRow(ctx, `INSERT INTO ai_audit_runs(id,organization_id,service_account_id,agent_name,agent_version,model,scope) SELECT $1,a.organization_id,a.id,$4,$5,$6,$7 FROM service_accounts a WHERE a.id=$2 AND a.organization_id=$3 AND a.enabled AND a.role='auditor' RETURNING started_at`, item.ID, accountID, organizationID, agentName, agentVersion, model, scope).Scan(&item.StartedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return AIAuditRun{}, ErrNotFound
	}
	return item, err
}

func (s *Store) AddAIAuditFinding(ctx context.Context, organizationID, accountID uuid.UUID, item AIAuditFinding) (AIAuditFinding, error) {
	item.ID = uuid.New()
	err := s.Pool.QueryRow(ctx, `INSERT INTO ai_audit_findings(id,run_id,severity,category,title,description,resource_type,resource_id,evidence,remediation,fingerprint) SELECT $1,r.id,$4,$5,$6,$7,$8,$9,$10,$11,$12 FROM ai_audit_runs r WHERE r.id=$2 AND r.organization_id=$3 AND r.service_account_id=$13 AND r.status='running' ON CONFLICT(run_id,fingerprint) DO UPDATE SET severity=excluded.severity,category=excluded.category,title=excluded.title,description=excluded.description,resource_type=excluded.resource_type,resource_id=excluded.resource_id,evidence=excluded.evidence,remediation=excluded.remediation RETURNING id,created_at`, item.ID, item.RunID, organizationID, item.Severity, item.Category, item.Title, item.Description, item.ResourceType, item.ResourceID, item.Evidence, item.Remediation, item.Fingerprint, accountID).Scan(&item.ID, &item.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return AIAuditFinding{}, ErrNotFound
	}
	return item, err
}

func (s *Store) FinishAIAuditRun(ctx context.Context, organizationID, accountID, runID uuid.UUID, status, summary string) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE ai_audit_runs SET status=$4,summary=$5,completed_at=now() WHERE id=$1 AND organization_id=$2 AND service_account_id=$3 AND status='running'`, runID, organizationID, accountID, status, summary)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *Store) ListAIAuditRuns(ctx context.Context, organizationID uuid.UUID) ([]AIAuditRun, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id,organization_id,service_account_id,agent_name,agent_version,model,status,scope,summary,started_at,completed_at FROM ai_audit_runs WHERE organization_id=$1 ORDER BY started_at DESC LIMIT 200`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []AIAuditRun{}
	for rows.Next() {
		var item AIAuditRun
		if err = rows.Scan(&item.ID, &item.OrganizationID, &item.ServiceAccountID, &item.AgentName, &item.AgentVersion, &item.Model, &item.Status, &item.Scope, &item.Summary, &item.StartedAt, &item.CompletedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) ListAIAuditFindings(ctx context.Context, organizationID, runID uuid.UUID) ([]AIAuditFinding, error) {
	rows, err := s.Pool.Query(ctx, `SELECT f.id,f.run_id,f.severity,f.category,f.title,f.description,f.resource_type,f.resource_id,f.evidence,f.remediation,f.fingerprint,f.created_at FROM ai_audit_findings f JOIN ai_audit_runs r ON r.id=f.run_id WHERE f.run_id=$1 AND r.organization_id=$2 ORDER BY CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,f.created_at`, runID, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []AIAuditFinding{}
	for rows.Next() {
		var item AIAuditFinding
		if err = rows.Scan(&item.ID, &item.RunID, &item.Severity, &item.Category, &item.Title, &item.Description, &item.ResourceType, &item.ResourceID, &item.Evidence, &item.Remediation, &item.Fingerprint, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
