package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const MaxAIAuditFindingsPerRun = 100

var ErrAIAuditFindingLimit = errors.New("AI audit run finding limit reached")

type AIAuditSnapshot struct {
	GeneratedAt          time.Time                       `json:"generatedAt"`
	Organization         uuid.UUID                       `json:"organizationId"`
	Projects             []Project                       `json:"projects"`
	Environments         []Environment                   `json:"environments"`
	Services             []ComposeService                `json:"services"`
	Routes               []Route                         `json:"routes"`
	Databases            []DatabaseInstance              `json:"databases"`
	DatabaseEngines      []AIAuditDatabaseEngineInfo     `json:"databaseEngines"`
	Clusters             []Cluster                       `json:"clusters"`
	AgentCAPosture       AIAuditAgentCAPosture           `json:"agentCertificateAuthorityPosture"`
	AgentUpgradePosture  []AIAuditAgentUpgradePosture    `json:"agentUpgradePosture"`
	BackupPosture        []AIAuditBackupPosture          `json:"backupPosture"`
	IdentityPosture      AIAuditIdentityPosture          `json:"identityPosture"`
	NotificationPosture  []AIAuditNotificationPosture    `json:"notificationPosture"`
	TemplateRepositories []AIAuditTemplateRepositoryInfo `json:"templateRepositories"`
	MigrationPosture     []AIAuditMigrationPosture       `json:"migrationPosture"`
	MigrationBlockers    []AIAuditMigrationBlocker       `json:"migrationBlockers"`
	ServiceDeployments   []AIAuditServiceDeployment      `json:"serviceDeployments"`
	QueuePosture         AIAuditQueuePosture             `json:"queuePosture"`
	Reconciliation       []ServiceReconciliation         `json:"reconciliation"`
	Signals              []AIAuditSignal                 `json:"signals30d"`
	AuditEvents          []AuditEvent                    `json:"recentAuditEvents"`
}

type AIAuditAgentCAPosture struct {
	Configured          bool   `json:"configured"`
	ActiveFingerprint   string `json:"activeFingerprint,omitempty"`
	PreviousFingerprint string `json:"previousFingerprint,omitempty"`
	RolloverActive      bool   `json:"rolloverActive"`
}

type AIAuditMigrationPosture struct {
	SourceOrganizationID        string    `json:"sourceOrganizationId"`
	Resources                   int64     `json:"resources"`
	Imported                    int64     `json:"imported"`
	Unresolved                  int64     `json:"unresolved"`
	Databases                   int64     `json:"databases"`
	SuccessfulDatabaseTransfers int64     `json:"successfulDatabaseTransfers"`
	LastUpdatedAt               time.Time `json:"lastUpdatedAt"`
}

type AIAuditMigrationBlocker struct {
	SourceOrganizationID string    `json:"sourceOrganizationId"`
	SourceKind           string    `json:"sourceKind"`
	SourceID             string    `json:"sourceId"`
	Reason               string    `json:"reason"`
	UpdatedAt            time.Time `json:"updatedAt"`
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

type AIAuditDatabaseEngineInfo struct {
	Name            string `json:"name"`
	DefaultVersion  string `json:"defaultVersion"`
	Source          string `json:"source"`
	ArtifactDigest  string `json:"artifactDigest,omitempty"`
	BackupCapable   bool   `json:"backupCapable"`
	BackupExtension string `json:"backupExtension"`
}

type AIAuditAgentUpgradePosture struct {
	ClusterID            uuid.UUID  `json:"clusterId"`
	ClusterName          string     `json:"clusterName"`
	CommandID            uuid.UUID  `json:"commandId"`
	Status               string     `json:"status"`
	TargetImage          string     `json:"targetImage"`
	Attempts             int        `json:"attempts"`
	LastError            string     `json:"lastError,omitempty"`
	VerificationOverdue  bool       `json:"verificationOverdue"`
	VerificationDeadline *time.Time `json:"verificationDeadline,omitempty"`
	CreatedAt            time.Time  `json:"createdAt"`
	FinishedAt           *time.Time `json:"finishedAt,omitempty"`
}

type AIAuditIdentityPosture struct {
	RequireSSO                      bool       `json:"requireSso"`
	EnabledOIDCProviders            int64      `json:"enabledOidcProviders"`
	EnabledSAMLProviders            int64      `json:"enabledSamlProviders"`
	ActiveMembers                   int64      `json:"activeMembers"`
	ActiveOwners                    int64      `json:"activeOwners"`
	ActiveAdmins                    int64      `json:"activeAdmins"`
	ActiveDevelopers                int64      `json:"activeDevelopers"`
	ActiveViewers                   int64      `json:"activeViewers"`
	DisabledMembers                 int64      `json:"disabledMembers"`
	ActiveLocalSessions             int64      `json:"activeLocalSessions"`
	ActiveOIDCSessions              int64      `json:"activeOidcSessions"`
	ActiveSAMLSessions              int64      `json:"activeSamlSessions"`
	ActiveServiceAccounts           int64      `json:"activeServiceAccounts"`
	ActivePrivilegedServiceAccounts int64      `json:"activePrivilegedServiceAccounts"`
	ExpiringServiceAccounts         int64      `json:"expiringServiceAccounts7d"`
	ActiveAuditorServiceAccounts    int64      `json:"activeAuditorServiceAccounts"`
	ActiveSCIMTokens                int64      `json:"activeScimTokens"`
	OldestActiveSCIMTokenCreatedAt  *time.Time `json:"oldestActiveScimTokenCreatedAt,omitempty"`
	PendingSAMLCertificateRotations int64      `json:"pendingSamlCertificateRotations"`
	OldestPendingSAMLRotationAt     *time.Time `json:"oldestPendingSamlRotationAt,omitempty"`
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
	snapshot := AIAuditSnapshot{GeneratedAt: time.Now().UTC(), Organization: organizationID, Projects: []Project{}, Environments: []Environment{}, Services: []ComposeService{}, Routes: []Route{}, Databases: []DatabaseInstance{}, DatabaseEngines: []AIAuditDatabaseEngineInfo{}, Clusters: []Cluster{}, AgentUpgradePosture: []AIAuditAgentUpgradePosture{}, BackupPosture: []AIAuditBackupPosture{}, NotificationPosture: []AIAuditNotificationPosture{}, TemplateRepositories: []AIAuditTemplateRepositoryInfo{}, MigrationPosture: []AIAuditMigrationPosture{}, MigrationBlockers: []AIAuditMigrationBlocker{}, ServiceDeployments: []AIAuditServiceDeployment{}, QueuePosture: AIAuditQueuePosture{Coverage: "resource-keyed-service-and-database-jobs"}, Reconciliation: []ServiceReconciliation{}, Signals: []AIAuditSignal{}, AuditEvents: []AuditEvent{}}
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
		SELECT c.id,c.name,latest.id,latest.status,latest.target_image,latest.attempts,latest.last_error,
			latest.status='verifying' AND latest.run_after<=now(),
			CASE WHEN latest.status='verifying' THEN latest.run_after END,latest.created_at,latest.finished_at
		FROM clusters c
		JOIN LATERAL (
			SELECT command.id,command.status,command.target_image,command.attempts,command.last_error,command.run_after,command.created_at,command.finished_at
			FROM cluster_commands command
			WHERE command.cluster_id=c.id AND command.kind='agent.upgrade'
			ORDER BY command.created_at DESC,command.id DESC
			LIMIT 1
		) latest ON true
		WHERE c.organization_id=$1
		ORDER BY c.name,c.id`, organizationID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var item AIAuditAgentUpgradePosture
		if err = rows.Scan(&item.ClusterID, &item.ClusterName, &item.CommandID, &item.Status, &item.TargetImage, &item.Attempts, &item.LastError, &item.VerificationOverdue, &item.VerificationDeadline, &item.CreatedAt, &item.FinishedAt); err != nil {
			rows.Close()
			return err
		}
		snapshot.AgentUpgradePosture = append(snapshot.AgentUpgradePosture, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	rows, err = s.Pool.Query(ctx, `
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
		(SELECT count(*) FROM saml_providers WHERE organization_id=$1 AND enabled),
		(SELECT count(*) FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.organization_id=$1 AND u.disabled_at IS NULL),
		(SELECT count(*) FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.organization_id=$1 AND m.role='owner' AND u.disabled_at IS NULL),
		(SELECT count(*) FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.organization_id=$1 AND m.role='admin' AND u.disabled_at IS NULL),
		(SELECT count(*) FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.organization_id=$1 AND m.role='developer' AND u.disabled_at IS NULL),
		(SELECT count(*) FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.organization_id=$1 AND m.role='viewer' AND u.disabled_at IS NULL),
		(SELECT count(*) FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.organization_id=$1 AND u.disabled_at IS NOT NULL),
		(SELECT count(*) FROM sessions session JOIN memberships m ON m.user_id=session.user_id JOIN users u ON u.id=session.user_id WHERE m.organization_id=$1 AND session.organization_id IS NULL AND session.auth_method='local' AND session.expires_at>now() AND u.disabled_at IS NULL AND (m.role='owner' OR NOT COALESCE((SELECT require_sso FROM organization_auth_settings WHERE organization_id=$1),false))),
		(SELECT count(*) FROM sessions session JOIN memberships m ON m.user_id=session.user_id AND m.organization_id=session.organization_id JOIN users u ON u.id=session.user_id WHERE session.organization_id=$1 AND session.auth_method='oidc' AND session.expires_at>now() AND u.disabled_at IS NULL),
		(SELECT count(*) FROM sessions session JOIN memberships m ON m.user_id=session.user_id AND m.organization_id=session.organization_id JOIN users u ON u.id=session.user_id WHERE session.organization_id=$1 AND session.auth_method='saml' AND session.expires_at>now() AND u.disabled_at IS NULL),
		(SELECT count(*) FROM service_accounts account WHERE account.organization_id=$1 AND account.enabled AND EXISTS(SELECT 1 FROM service_account_tokens token WHERE token.service_account_id=account.id AND token.revoked_at IS NULL AND token.expires_at>now())),
		(SELECT count(*) FROM service_accounts account WHERE account.organization_id=$1 AND account.enabled AND account.role IN ('admin','developer') AND EXISTS(SELECT 1 FROM service_account_tokens token WHERE token.service_account_id=account.id AND token.revoked_at IS NULL AND token.expires_at>now())),
		(SELECT count(*) FROM service_accounts account WHERE account.organization_id=$1 AND account.enabled AND EXISTS(SELECT 1 FROM service_account_tokens token WHERE token.service_account_id=account.id AND token.revoked_at IS NULL AND token.expires_at>now() AND token.expires_at<=now()+interval '7 days')),
		(SELECT count(*) FROM service_accounts account WHERE account.organization_id=$1 AND account.enabled AND account.role='auditor' AND EXISTS(SELECT 1 FROM service_account_tokens token WHERE token.service_account_id=account.id AND token.revoked_at IS NULL AND token.expires_at>now())),
		(SELECT count(*) FROM scim_tokens WHERE organization_id=$1 AND revoked_at IS NULL AND expires_at>now()),
		(SELECT min(created_at) FROM scim_tokens WHERE organization_id=$1 AND revoked_at IS NULL AND expires_at>now()),
		(SELECT count(*) FROM saml_providers WHERE organization_id=$1 AND pending_certificate_created_at IS NOT NULL),
		(SELECT min(pending_certificate_created_at) FROM saml_providers WHERE organization_id=$1 AND pending_certificate_created_at IS NOT NULL)`, organizationID).Scan(
		&snapshot.IdentityPosture.RequireSSO,
		&snapshot.IdentityPosture.EnabledOIDCProviders,
		&snapshot.IdentityPosture.EnabledSAMLProviders,
		&snapshot.IdentityPosture.ActiveMembers,
		&snapshot.IdentityPosture.ActiveOwners,
		&snapshot.IdentityPosture.ActiveAdmins,
		&snapshot.IdentityPosture.ActiveDevelopers,
		&snapshot.IdentityPosture.ActiveViewers,
		&snapshot.IdentityPosture.DisabledMembers,
		&snapshot.IdentityPosture.ActiveLocalSessions,
		&snapshot.IdentityPosture.ActiveOIDCSessions,
		&snapshot.IdentityPosture.ActiveSAMLSessions,
		&snapshot.IdentityPosture.ActiveServiceAccounts,
		&snapshot.IdentityPosture.ActivePrivilegedServiceAccounts,
		&snapshot.IdentityPosture.ExpiringServiceAccounts,
		&snapshot.IdentityPosture.ActiveAuditorServiceAccounts,
		&snapshot.IdentityPosture.ActiveSCIMTokens,
		&snapshot.IdentityPosture.OldestActiveSCIMTokenCreatedAt,
		&snapshot.IdentityPosture.PendingSAMLCertificateRotations,
		&snapshot.IdentityPosture.OldestPendingSAMLRotationAt,
	)
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

	rows, err = s.Pool.Query(ctx, `
		SELECT resource.source_organization_id,
			count(*),
			count(*) FILTER (WHERE resource.status='imported'),
			count(*) FILTER (WHERE resource.status<>'imported'),
			count(*) FILTER (WHERE resource.source_kind='database' AND resource.status='imported'),
			count(*) FILTER (WHERE resource.source_kind='database' AND resource.status='imported' AND EXISTS (
				SELECT 1 FROM database_migrations migration
				WHERE migration.database_instance_id=resource.target_id
					AND migration.source_kind='dokploy'
					AND migration.source_id=split_part(resource.source_id,':',2)
					AND migration.status='succeeded'
					AND migration.created_at>=resource.updated_at
			)),
			max(resource.updated_at)
		FROM dokploy_migration_resources resource
		WHERE resource.target_organization_id=$1
		GROUP BY resource.source_organization_id
		ORDER BY resource.source_organization_id`, organizationID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var item AIAuditMigrationPosture
		if err = rows.Scan(&item.SourceOrganizationID, &item.Resources, &item.Imported, &item.Unresolved, &item.Databases, &item.SuccessfulDatabaseTransfers, &item.LastUpdatedAt); err != nil {
			rows.Close()
			return err
		}
		snapshot.MigrationPosture = append(snapshot.MigrationPosture, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	rows, err = s.Pool.Query(ctx, `SELECT source_organization_id,source_kind,source_id,reason,updated_at
		FROM dokploy_migration_resources
		WHERE target_organization_id=$1 AND status<>'imported'
		ORDER BY updated_at DESC,source_organization_id,source_kind,source_id
		LIMIT 200`, organizationID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var item AIAuditMigrationBlocker
		if err = rows.Scan(&item.SourceOrganizationID, &item.SourceKind, &item.SourceID, &item.Reason, &item.UpdatedAt); err != nil {
			rows.Close()
			return err
		}
		snapshot.MigrationBlockers = append(snapshot.MigrationBlockers, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
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
	ID                      uuid.UUID       `json:"id"`
	RunID                   uuid.UUID       `json:"runId"`
	ServiceAccountID        uuid.UUID       `json:"serviceAccountId"`
	AgentName               string          `json:"agentName"`
	Severity                string          `json:"severity"`
	Category                string          `json:"category"`
	Title                   string          `json:"title"`
	Description             string          `json:"description"`
	ResourceType            string          `json:"resourceType,omitempty"`
	ResourceID              string          `json:"resourceId,omitempty"`
	Evidence                json.RawMessage `json:"evidence"`
	Remediation             string          `json:"remediation,omitempty"`
	Fingerprint             string          `json:"fingerprint"`
	CreatedAt               time.Time       `json:"createdAt"`
	Disposition             string          `json:"disposition"`
	TriageNote              string          `json:"triageNote,omitempty"`
	TriagedByUser           *uuid.UUID      `json:"triagedByUserId,omitempty"`
	TriagedByServiceAccount *uuid.UUID      `json:"triagedByServiceAccountId,omitempty"`
	TriagedAt               *time.Time      `json:"triagedAt,omitempty"`
	PreviousFindingID       *uuid.UUID      `json:"previousFindingId,omitempty"`
	OccurrenceNumber        int             `json:"occurrenceNumber"`
}

func (s *Store) CreateAIAuditRun(ctx context.Context, organizationID, accountID uuid.UUID, agentName, agentVersion, model string, scope json.RawMessage) (AIAuditRun, error) {
	if len(scope) == 0 {
		scope = json.RawMessage(`{}`)
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return AIAuditRun{}, err
	}
	defer tx.Rollback(ctx)
	var accountOrganizationID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT organization_id FROM service_accounts WHERE id=$1 AND organization_id=$2 AND enabled AND role='auditor' FOR UPDATE`, accountID, organizationID).Scan(&accountOrganizationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return AIAuditRun{}, ErrNotFound
	}
	if err != nil {
		return AIAuditRun{}, err
	}
	const supersededSummary = "superseded by a newer run for the same auditor identity"
	rows, err := tx.Query(ctx, `UPDATE ai_audit_runs SET status='failed',summary=$3,completed_at=now() WHERE service_account_id=$1 AND agent_name=$2 AND status='running' RETURNING id`, accountID, agentName, supersededSummary)
	if err != nil {
		return AIAuditRun{}, err
	}
	var supersededIDs []uuid.UUID
	for rows.Next() {
		var supersededID uuid.UUID
		if err = rows.Scan(&supersededID); err != nil {
			rows.Close()
			return AIAuditRun{}, err
		}
		supersededIDs = append(supersededIDs, supersededID)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return AIAuditRun{}, err
	}
	rows.Close()
	for _, supersededID := range supersededIDs {
		if err = queueAIAuditFailureNotifications(ctx, tx, organizationID, supersededID, agentName, supersededSummary); err != nil {
			return AIAuditRun{}, err
		}
	}
	item := AIAuditRun{ID: uuid.New(), OrganizationID: organizationID, ServiceAccountID: accountID, AgentName: agentName, AgentVersion: agentVersion, Model: model, Status: "running", Scope: scope}
	err = tx.QueryRow(ctx, `INSERT INTO ai_audit_runs(id,organization_id,service_account_id,agent_name,agent_version,model,scope) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING started_at`, item.ID, accountOrganizationID, accountID, agentName, agentVersion, model, scope).Scan(&item.StartedAt)
	if err != nil {
		return AIAuditRun{}, err
	}
	return item, tx.Commit(ctx)
}

func (s *Store) AddAIAuditFinding(ctx context.Context, organizationID, accountID uuid.UUID, item AIAuditFinding) (AIAuditFinding, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return AIAuditFinding{}, err
	}
	defer tx.Rollback(ctx)
	var runID uuid.UUID
	var agentName string
	err = tx.QueryRow(ctx, `SELECT id,agent_name FROM ai_audit_runs WHERE id=$1 AND organization_id=$2 AND service_account_id=$3 AND status='running' FOR UPDATE`, item.RunID, organizationID, accountID).Scan(&runID, &agentName)
	if errors.Is(err, pgx.ErrNoRows) {
		return AIAuditFinding{}, ErrNotFound
	}
	if err != nil {
		return AIAuditFinding{}, err
	}
	var findingCount int
	var fingerprintExists bool
	var currentSeverity string
	if err = tx.QueryRow(ctx, `SELECT count(*),COALESCE(bool_or(fingerprint=$2),false),COALESCE(max(severity) FILTER (WHERE fingerprint=$2),'') FROM ai_audit_findings WHERE run_id=$1`, runID, item.Fingerprint).Scan(&findingCount, &fingerprintExists, &currentSeverity); err != nil {
		return AIAuditFinding{}, err
	}
	if !fingerprintExists && findingCount >= MaxAIAuditFindingsPerRun {
		return AIAuditFinding{}, ErrAIAuditFindingLimit
	}
	item.ServiceAccountID = accountID
	item.AgentName = agentName
	item.Disposition = "open"
	item.TriageNote = ""
	item.TriagedByUser = nil
	item.TriagedByServiceAccount = nil
	item.TriagedAt = nil
	item.PreviousFindingID = nil
	item.OccurrenceNumber = 1
	previousFound := false
	previousSeverity, previousDisposition := "", ""
	if !fingerprintExists {
		var previous AIAuditFinding
		err = tx.QueryRow(ctx, `SELECT f.id,f.occurrence_number,f.severity,f.disposition,f.triage_note,f.triaged_by_user_id,f.triaged_by_service_account_id,f.triaged_at FROM ai_audit_findings f JOIN ai_audit_runs r ON r.id=f.run_id WHERE r.organization_id=$1 AND r.service_account_id=$2 AND r.agent_name=$3 AND f.run_id<>$4 AND f.fingerprint=$5 ORDER BY r.started_at DESC,f.created_at DESC LIMIT 1`, organizationID, accountID, agentName, runID, item.Fingerprint).Scan(&previous.ID, &previous.OccurrenceNumber, &previous.Severity, &previous.Disposition, &previous.TriageNote, &previous.TriagedByUser, &previous.TriagedByServiceAccount, &previous.TriagedAt)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return AIAuditFinding{}, err
		}
		if err == nil {
			previousFound = true
			previousSeverity, previousDisposition = previous.Severity, previous.Disposition
			item.PreviousFindingID = &previous.ID
			item.OccurrenceNumber = previous.OccurrenceNumber + 1
			if previous.Disposition == "acknowledged" {
				item.Disposition = previous.Disposition
				item.TriageNote = previous.TriageNote
				item.TriagedByUser = previous.TriagedByUser
				item.TriagedByServiceAccount = previous.TriagedByServiceAccount
				item.TriagedAt = previous.TriagedAt
			}
		}
	}
	item.ID = uuid.New()
	err = tx.QueryRow(ctx, `INSERT INTO ai_audit_findings(id,run_id,severity,category,title,description,resource_type,resource_id,evidence,remediation,fingerprint,disposition,triage_note,triaged_by_user_id,triaged_by_service_account_id,triaged_at,previous_finding_id,occurrence_number) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18) ON CONFLICT(run_id,fingerprint) DO UPDATE SET severity=excluded.severity,category=excluded.category,title=excluded.title,description=excluded.description,resource_type=excluded.resource_type,resource_id=excluded.resource_id,evidence=excluded.evidence,remediation=excluded.remediation RETURNING id,created_at,disposition,triage_note,triaged_by_user_id,triaged_by_service_account_id,triaged_at,previous_finding_id,occurrence_number`, item.ID, runID, item.Severity, item.Category, item.Title, item.Description, item.ResourceType, item.ResourceID, item.Evidence, item.Remediation, item.Fingerprint, item.Disposition, item.TriageNote, item.TriagedByUser, item.TriagedByServiceAccount, item.TriagedAt, item.PreviousFindingID, item.OccurrenceNumber).Scan(&item.ID, &item.CreatedAt, &item.Disposition, &item.TriageNote, &item.TriagedByUser, &item.TriagedByServiceAccount, &item.TriagedAt, &item.PreviousFindingID, &item.OccurrenceNumber)
	if err != nil {
		return AIAuditFinding{}, err
	}
	shouldNotifyCritical := item.Severity == "critical" && ((fingerprintExists && currentSeverity != "critical") || (!fingerprintExists && (!previousFound || previousSeverity != "critical" || previousDisposition == "resolved")))
	if shouldNotifyCritical {
		payload, _ := json.Marshal(map[string]any{"event": "ai.finding.critical", "resourceType": "ai_audit_finding", "resourceId": item.ID.String(), "runId": runID, "agentName": agentName, "category": item.Category, "title": item.Title, "occurredAt": time.Now().UTC(), "text": "Dockyard ai.finding.critical: " + item.Title})
		if err = queueNotificationDeliveries(ctx, tx, organizationID, "ai.finding.critical", "ai_audit_finding", item.ID.String(), payload); err != nil {
			return AIAuditFinding{}, err
		}
	}
	return item, tx.Commit(ctx)
}

func (s *Store) FinishAIAuditRun(ctx context.Context, organizationID, accountID, runID uuid.UUID, status, summary string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var agentName string
	err = tx.QueryRow(ctx, `UPDATE ai_audit_runs SET status=$4,summary=$5,completed_at=now() WHERE id=$1 AND organization_id=$2 AND service_account_id=$3 AND status='running' RETURNING agent_name`, runID, organizationID, accountID, status, summary).Scan(&agentName)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if status == "failed" {
		if err = queueAIAuditFailureNotifications(ctx, tx, organizationID, runID, agentName, summary); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func queueAIAuditFailureNotifications(ctx context.Context, tx pgx.Tx, organizationID, runID uuid.UUID, agentName, summary string) error {
	payload, _ := json.Marshal(map[string]any{"event": "ai.audit.failed", "resourceType": "ai_audit_run", "resourceId": runID.String(), "agentName": agentName, "error": truncateStore(summary, 8192), "occurredAt": time.Now().UTC(), "text": "Dockyard ai.audit.failed for AI audit run " + runID.String()})
	return queueNotificationDeliveries(ctx, tx, organizationID, "ai.audit.failed", "ai_audit_run", runID.String(), payload)
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
	rows, err := s.Pool.Query(ctx, `SELECT f.id,f.run_id,r.service_account_id,r.agent_name,f.severity,f.category,f.title,f.description,f.resource_type,f.resource_id,f.evidence,f.remediation,f.fingerprint,f.created_at,f.disposition,f.triage_note,f.triaged_by_user_id,f.triaged_by_service_account_id,f.triaged_at,f.previous_finding_id,f.occurrence_number FROM ai_audit_findings f JOIN ai_audit_runs r ON r.id=f.run_id WHERE f.run_id=$1 AND r.organization_id=$2 ORDER BY CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,f.created_at`, runID, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []AIAuditFinding{}
	for rows.Next() {
		var item AIAuditFinding
		if err = rows.Scan(&item.ID, &item.RunID, &item.ServiceAccountID, &item.AgentName, &item.Severity, &item.Category, &item.Title, &item.Description, &item.ResourceType, &item.ResourceID, &item.Evidence, &item.Remediation, &item.Fingerprint, &item.CreatedAt, &item.Disposition, &item.TriageNote, &item.TriagedByUser, &item.TriagedByServiceAccount, &item.TriagedAt, &item.PreviousFindingID, &item.OccurrenceNumber); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) ListCurrentAIAuditFindings(ctx context.Context, organizationID uuid.UUID, disposition, severity string, limit int) ([]AIAuditFinding, error) {
	if limit < 1 || limit > 200 {
		limit = 100
	}
	rows, err := s.Pool.Query(ctx, `WITH latest AS (
		SELECT DISTINCT ON (r.service_account_id,r.agent_name,f.fingerprint)
			f.id,f.run_id,r.service_account_id,r.agent_name,f.severity,f.category,f.title,f.description,f.resource_type,f.resource_id,f.evidence,f.remediation,f.fingerprint,f.created_at,f.disposition,f.triage_note,f.triaged_by_user_id,f.triaged_by_service_account_id,f.triaged_at,f.previous_finding_id,f.occurrence_number,r.started_at
		FROM ai_audit_findings f JOIN ai_audit_runs r ON r.id=f.run_id
		WHERE r.organization_id=$1
		ORDER BY r.service_account_id,r.agent_name,f.fingerprint,r.started_at DESC,f.created_at DESC
	)
	SELECT id,run_id,service_account_id,agent_name,severity,category,title,description,resource_type,resource_id,evidence,remediation,fingerprint,created_at,disposition,triage_note,triaged_by_user_id,triaged_by_service_account_id,triaged_at,previous_finding_id,occurrence_number
	FROM latest
	WHERE ($2='' OR ($2='active' AND disposition<>'resolved') OR disposition=$2) AND ($3='' OR severity=$3)
	ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,started_at DESC,created_at DESC
	LIMIT $4`, organizationID, disposition, severity, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []AIAuditFinding{}
	for rows.Next() {
		var item AIAuditFinding
		if err = rows.Scan(&item.ID, &item.RunID, &item.ServiceAccountID, &item.AgentName, &item.Severity, &item.Category, &item.Title, &item.Description, &item.ResourceType, &item.ResourceID, &item.Evidence, &item.Remediation, &item.Fingerprint, &item.CreatedAt, &item.Disposition, &item.TriageNote, &item.TriagedByUser, &item.TriagedByServiceAccount, &item.TriagedAt, &item.PreviousFindingID, &item.OccurrenceNumber); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) UpdateAIAuditFindingDisposition(ctx context.Context, principal Principal, findingID uuid.UUID, disposition, note, remoteAddr string) (AIAuditFinding, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return AIAuditFinding{}, err
	}
	defer tx.Rollback(ctx)
	var item AIAuditFinding
	var serviceAccountID any
	if principal.ServiceAccountID != nil {
		serviceAccountID = *principal.ServiceAccountID
	}
	err = tx.QueryRow(ctx, `UPDATE ai_audit_findings f SET disposition=$4,triage_note=$5,triaged_by_user_id=$3,triaged_by_service_account_id=$6,triaged_at=now() FROM ai_audit_runs r WHERE f.id=$1 AND f.run_id=r.id AND r.organization_id=$2 RETURNING f.id,f.run_id,r.service_account_id,r.agent_name,f.severity,f.category,f.title,f.description,f.resource_type,f.resource_id,f.evidence,f.remediation,f.fingerprint,f.created_at,f.disposition,f.triage_note,f.triaged_by_user_id,f.triaged_by_service_account_id,f.triaged_at,f.previous_finding_id,f.occurrence_number`, findingID, principal.OrganizationID, nullableUUID(principal.UserID), disposition, note, serviceAccountID).Scan(&item.ID, &item.RunID, &item.ServiceAccountID, &item.AgentName, &item.Severity, &item.Category, &item.Title, &item.Description, &item.ResourceType, &item.ResourceID, &item.Evidence, &item.Remediation, &item.Fingerprint, &item.CreatedAt, &item.Disposition, &item.TriageNote, &item.TriagedByUser, &item.TriagedByServiceAccount, &item.TriagedAt, &item.PreviousFindingID, &item.OccurrenceNumber)
	if errors.Is(err, pgx.ErrNoRows) {
		return AIAuditFinding{}, ErrNotFound
	}
	if err != nil {
		return AIAuditFinding{}, err
	}
	metadata, err := json.Marshal(map[string]any{"runId": item.RunID})
	if err != nil {
		return AIAuditFinding{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_events(organization_id,actor_user_id,actor_service_account_id,action,resource_type,resource_id,remote_addr,metadata) VALUES($1,$2,$3,$4,'ai_audit_finding',$5,$6,$7)`, principal.OrganizationID, nullableUUID(principal.UserID), serviceAccountID, "ai_audit_finding."+disposition, findingID.String(), remoteAddr, metadata); err != nil {
		return AIAuditFinding{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return AIAuditFinding{}, err
	}
	return item, nil
}
