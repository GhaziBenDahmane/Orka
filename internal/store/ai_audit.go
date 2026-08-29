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
	GeneratedAt  time.Time          `json:"generatedAt"`
	Organization uuid.UUID          `json:"organizationId"`
	Projects     []Project          `json:"projects"`
	Environments []Environment      `json:"environments"`
	Services     []ComposeService   `json:"services"`
	Routes       []Route            `json:"routes"`
	Databases    []DatabaseInstance `json:"databases"`
	Clusters     []Cluster          `json:"clusters"`
	Signals      []AIAuditSignal    `json:"signals30d"`
	AuditEvents  []AuditEvent       `json:"recentAuditEvents"`
}

type AIAuditSignal struct {
	Kind   string `json:"kind"`
	Status string `json:"status"`
	Count  int64  `json:"count"`
}

// BuildAIAuditSnapshot deliberately uses the list projections: Compose source,
// environment values, credentials, and backup contents never enter the agent
// context. The snapshot is broad but remains read-only and secret-free.
func (s *Store) BuildAIAuditSnapshot(ctx context.Context, organizationID uuid.UUID) (AIAuditSnapshot, error) {
	snapshot := AIAuditSnapshot{GeneratedAt: time.Now().UTC(), Organization: organizationID, Projects: []Project{}, Environments: []Environment{}, Services: []ComposeService{}, Routes: []Route{}, Databases: []DatabaseInstance{}, Clusters: []Cluster{}, Signals: []AIAuditSignal{}, AuditEvents: []AuditEvent{}}
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
