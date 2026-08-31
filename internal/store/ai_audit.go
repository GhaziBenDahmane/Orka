package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/bendahma/dokploy-go/internal/auth"
	"github.com/bendahma/dokploy-go/internal/ociref"
	"github.com/crewjam/saml/samlsp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"gopkg.in/yaml.v3"
)

const MaxAIAuditFindingsPerRun = 100

var ErrAIAuditFindingLimit = errors.New("AI audit run finding limit reached")

var aiAuditGitCommit = regexp.MustCompile(`^(?:[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$`)

type AIAuditSnapshot struct {
	GeneratedAt          time.Time                        `json:"generatedAt"`
	Organization         uuid.UUID                        `json:"organizationId"`
	Projects             []AIAuditProjectInfo             `json:"projects"`
	Environments         []AIAuditEnvironmentInfo         `json:"environments"`
	Services             []AIAuditServiceInfo             `json:"services"`
	Routes               []AIAuditRouteInfo               `json:"routes"`
	Databases            []AIAuditDatabaseInfo            `json:"databases"`
	DatabaseEngines      []AIAuditDatabaseEngineInfo      `json:"databaseEngines"`
	Clusters             []AIAuditClusterInfo             `json:"clusters"`
	ManagedNetworks      []AIAuditManagedNetworkInfo      `json:"managedNetworks"`
	CustomTLSPosture     []AIAuditCustomTLSPosture        `json:"customTlsPosture"`
	EdgeTLSPosture       []AIAuditEdgeTLSPosture          `json:"edgeTlsPosture"`
	AgentCAPosture       AIAuditAgentCAPosture            `json:"agentCertificateAuthorityPosture"`
	AgentUpgradePosture  []AIAuditAgentUpgradePosture     `json:"agentUpgradePosture"`
	AgentCommandPosture  []AIAuditAgentCommandPosture     `json:"agentCommandPosture"`
	BackupPosture        []AIAuditBackupPosture           `json:"backupPosture"`
	VolumeBackupPosture  []AIAuditVolumeBackupPosture     `json:"volumeBackupPosture"`
	ResourcePolicies     []AIAuditResourcePolicyPosture   `json:"resourcePolicies"`
	WorkloadPosture      []AIAuditWorkloadPosture         `json:"workloadPosture"`
	SourceBuildPosture   []AIAuditSourceBuildPosture      `json:"sourceBuildPosture"`
	SourceCredentials    []AIAuditSourceCredentialPosture `json:"sourceCredentialPosture"`
	AuditLogPosture      AIAuditLogPosture                `json:"auditLogPosture"`
	IdentityPosture      AIAuditIdentityPosture           `json:"identityPosture"`
	DeployTokenPosture   AIAuditDeployTokenPosture        `json:"deployTokenPosture"`
	SAMLPosture          []AIAuditSAMLProviderPosture     `json:"samlPosture"`
	NotificationPosture  []AIAuditNotificationPosture     `json:"notificationPosture"`
	WebhookPosture       []AIAuditWebhookPosture          `json:"webhookPosture"`
	BackupDestinations   []AIAuditBackupDestinationInfo   `json:"backupDestinations"`
	TemplateRepositories []AIAuditTemplateRepositoryInfo  `json:"templateRepositories"`
	MigrationPosture     []AIAuditMigrationPosture        `json:"migrationPosture"`
	MigrationBlockers    []AIAuditMigrationBlocker        `json:"migrationBlockers"`
	ServiceDeployments   []AIAuditServiceDeployment       `json:"serviceDeployments"`
	ServiceSchedules     []AIAuditServiceSchedulePosture  `json:"serviceSchedules"`
	QueuePosture         AIAuditQueuePosture              `json:"queuePosture"`
	FinalizerPosture     AIAuditFinalizerPosture          `json:"finalizerPosture"`
	Reconciliation       []AIAuditReconciliationPosture   `json:"reconciliation"`
	Signals              []AIAuditSignal                  `json:"signals30d"`
	AuditEvents          []AIAuditEventInfo               `json:"recentAuditEvents"`
}

// Inventory types are explicit allowlists rather than aliases of the normal
// API records. Adding an operational field to a normal record must never make
// it model-visible without a separate review of the AI trust boundary.
type AIAuditProjectInfo struct {
	ID             uuid.UUID `json:"id"`
	OrganizationID uuid.UUID `json:"organizationId"`
	Name           string    `json:"name"`
	Slug           string    `json:"slug"`
	Tags           []string  `json:"tags"`
	CreatedAt      time.Time `json:"createdAt"`
}

type AIAuditEnvironmentInfo struct {
	ID                          uuid.UUID  `json:"id"`
	ProjectID                   uuid.UUID  `json:"projectId"`
	ClusterID                   *uuid.UUID `json:"clusterId,omitempty"`
	PlacementSelectorConfigured bool       `json:"placementSelectorConfigured"`
	MinimumNodes                int        `json:"minimumNodes,omitempty"`
	MinimumNanoCPUs             int64      `json:"minimumNanoCpus,omitempty"`
	MinimumMemoryBytes          int64      `json:"minimumMemoryBytes,omitempty"`
	Name                        string     `json:"name"`
	Slug                        string     `json:"slug"`
	CreatedAt                   time.Time  `json:"createdAt"`
}

type AIAuditServiceInfo struct {
	ID            uuid.UUID `json:"id"`
	EnvironmentID uuid.UUID `json:"environmentId"`
	Name          string    `json:"name"`
	Slug          string    `json:"slug"`
	StackName     string    `json:"stackName"`
	StorageNodeID string    `json:"storageNodeId,omitempty"`
	Revision      int64     `json:"revision"`
	DesiredState  string    `json:"desiredState"`
	Tags          []string  `json:"tags"`
	Networks      []string  `json:"networks"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

type AIAuditManagedNetworkInfo struct {
	ID         uuid.UUID  `json:"id"`
	ClusterID  *uuid.UUID `json:"clusterId,omitempty"`
	Name       string     `json:"name"`
	Driver     string     `json:"driver"`
	Internal   bool       `json:"internal"`
	Attachable bool       `json:"attachable"`
	EnableIPv4 bool       `json:"enableIpv4"`
	EnableIPv6 bool       `json:"enableIpv6"`
	Status     string     `json:"status"`
	UpdatedAt  time.Time  `json:"updatedAt"`
}

type AIAuditRouteInfo struct {
	ID                  uuid.UUID  `json:"id"`
	ComposeServiceID    uuid.UUID  `json:"composeServiceId"`
	ServiceName         string     `json:"serviceName"`
	Host                string     `json:"host"`
	PathPrefix          string     `json:"pathPrefix"`
	InternalPath        string     `json:"internalPath"`
	StripPath           bool       `json:"stripPath"`
	Enabled             bool       `json:"enabled"`
	Disabled            bool       `json:"-"`
	RedirectConfigured  bool       `json:"redirectConfigured"`
	RedirectPermanent   bool       `json:"redirectPermanent"`
	BasicAuthEnabled    bool       `json:"basicAuthEnabled"`
	TargetPort          int        `json:"targetPort"`
	TLS                 bool       `json:"tls"`
	CertificateResolver string     `json:"certificateResolver"`
	CustomCertificateID *uuid.UUID `json:"customCertificateId,omitempty"`
}

type AIAuditCustomTLSPosture struct {
	ID             uuid.UUID `json:"id"`
	NotBefore      time.Time `json:"notBefore"`
	NotAfter       time.Time `json:"notAfter"`
	Revision       int64     `json:"revision"`
	AttachedRoutes int64     `json:"attachedRoutes"`
	EnabledRoutes  int64     `json:"enabledRoutes"`
}

type AIAuditEdgeTLSPosture struct {
	TargetKey         string     `json:"targetKey"`
	ClusterID         *uuid.UUID `json:"clusterId,omitempty"`
	Generation        int64      `json:"generation"`
	AppliedGeneration int64      `json:"appliedGeneration"`
	Status            string     `json:"status"`
	UpdatedAt         time.Time  `json:"updatedAt"`
}

type AIAuditServiceSchedulePosture struct {
	ID             uuid.UUID  `json:"id"`
	ServiceID      uuid.UUID  `json:"serviceId"`
	Name           string     `json:"name"`
	Enabled        bool       `json:"enabled"`
	DesiredState   string     `json:"desiredState"`
	Timezone       string     `json:"timezone"`
	NextRunAt      time.Time  `json:"nextRunAt"`
	LastStatus     string     `json:"lastStatus,omitempty"`
	LastFinishedAt *time.Time `json:"lastFinishedAt,omitempty"`
	Failures24h    int64      `json:"failures24h"`
}

type AIAuditDatabaseInfo struct {
	ID               uuid.UUID `json:"id"`
	EnvironmentID    uuid.UUID `json:"environmentId"`
	Name             string    `json:"name"`
	Slug             string    `json:"slug"`
	Engine           string    `json:"engine"`
	Version          string    `json:"version"`
	DriverSource     string    `json:"driverSource"`
	DriverDigest     string    `json:"driverArtifactDigest,omitempty"`
	StorageNodeID    string    `json:"storageNodeId,omitempty"`
	ComposeServiceID uuid.UUID `json:"composeServiceId"`
	Status           string    `json:"status"`
	CreatedAt        time.Time `json:"createdAt"`
}

type AIAuditClusterInfo struct {
	ID                                     uuid.UUID  `json:"id"`
	OrganizationID                         uuid.UUID  `json:"organizationId"`
	Name                                   string     `json:"name"`
	Slug                                   string     `json:"slug"`
	State                                  string     `json:"state"`
	AgentVersion                           string     `json:"agentVersion"`
	AgentImage                             string     `json:"agentImage"`
	AgentUpdateState                       string     `json:"agentUpdateState"`
	DockerVersion                          string     `json:"dockerVersion"`
	CertificateAuthorityFingerprint        string     `json:"certificateAuthorityFingerprint,omitempty"`
	PendingCertificateAuthorityFingerprint string     `json:"pendingCertificateAuthorityFingerprint,omitempty"`
	CertificateNotAfter                    *time.Time `json:"certificateNotAfter,omitempty"`
	LastSeenAt                             *time.Time `json:"lastSeenAt,omitempty"`
	MaintenanceStartsAt                    *time.Time `json:"maintenanceStartsAt,omitempty"`
	MaintenanceEndsAt                      *time.Time `json:"maintenanceEndsAt,omitempty"`
	CreatedAt                              time.Time  `json:"createdAt"`
	UpdatedAt                              time.Time  `json:"updatedAt"`
}

type AIAuditEventInfo struct {
	ID                    int64      `json:"id"`
	ActorUserID           *uuid.UUID `json:"actorUserId,omitempty"`
	ActorServiceAccountID *uuid.UUID `json:"actorServiceAccountId,omitempty"`
	Action                string     `json:"action"`
	ResourceType          string     `json:"resourceType"`
	ResourceID            string     `json:"resourceId"`
	CreatedAt             time.Time  `json:"createdAt"`
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

type AIAuditVolumeBackupPosture struct {
	ServiceID         uuid.UUID  `json:"serviceId"`
	ServiceName       string     `json:"serviceName"`
	VolumeName        string     `json:"volumeName"`
	StorageNodeID     string     `json:"storageNodeId,omitempty"`
	PolicyEnabled     bool       `json:"policyEnabled"`
	IntervalSeconds   int        `json:"intervalSeconds"`
	RetentionCount    int        `json:"retentionCount"`
	Quiesce           bool       `json:"quiesce"`
	LastBackupStatus  string     `json:"lastBackupStatus,omitempty"`
	LastBackupAt      *time.Time `json:"lastBackupAt,omitempty"`
	LastRestoreStatus string     `json:"lastRestoreStatus,omitempty"`
	LastRestoreAt     *time.Time `json:"lastRestoreAt,omitempty"`
}

type AIAuditResourcePolicyPosture struct {
	ScopeType           string    `json:"scopeType"`
	ScopeID             uuid.UUID `json:"scopeId"`
	Maintenance         bool      `json:"maintenance"`
	MaxProjects         *int      `json:"maxProjects"`
	MaxEnvironments     *int      `json:"maxEnvironments"`
	MaxServices         *int      `json:"maxServices"`
	MaxDatabases        *int      `json:"maxDatabases"`
	CurrentProjects     int       `json:"currentProjects"`
	CurrentEnvironments int       `json:"currentEnvironments"`
	CurrentServices     int       `json:"currentServices"`
	CurrentDatabases    int       `json:"currentDatabases"`
	UpdatedAt           time.Time `json:"updatedAt"`
}

type AIAuditWorkloadPosture struct {
	ServiceID                  uuid.UUID `json:"serviceId"`
	DefinitionParseable        bool      `json:"definitionParseable"`
	ContainerCount             int       `json:"containerCount"`
	DigestPinnedImages         int       `json:"digestPinnedImages"`
	MutableImages              int       `json:"mutableImages"`
	BuildOnlyServices          int       `json:"buildOnlyServices"`
	MissingImageOrBuild        int       `json:"missingImageOrBuild"`
	SuccessfulDeployment       bool      `json:"successfulDeployment"`
	RuntimeSnapshotAvailable   bool      `json:"runtimeSnapshotAvailable"`
	RuntimeDefinitionParseable bool      `json:"runtimeDefinitionParseable"`
	RuntimeContainerCount      int       `json:"runtimeContainerCount"`
	RuntimeDigestPinnedImages  int       `json:"runtimeDigestPinnedImages"`
	RuntimeMutableImages       int       `json:"runtimeMutableImages"`
	RuntimeBuildOnlyServices   int       `json:"runtimeBuildOnlyServices"`
	RuntimeMissingImageOrBuild int       `json:"runtimeMissingImageOrBuild"`
	NamedVolumes               []string  `json:"namedVolumes"`
}

type AIAuditSourceBuildPosture struct {
	ServiceID                    uuid.UUID `json:"serviceId"`
	SourceType                   string    `json:"sourceType"`
	BuildType                    string    `json:"buildType"`
	RepositoryTransport          string    `json:"repositoryTransport,omitempty"`
	GitRefPinned                 bool      `json:"gitRefPinned"`
	GitCredentialConfigured      bool      `json:"gitCredentialConfigured"`
	RegistryCredentialConfigured bool      `json:"registryCredentialConfigured"`
	StatusReportingConfigured    bool      `json:"statusReportingConfigured"`
	SubmodulesEnabled            bool      `json:"submodulesEnabled"`
	BuildConfigurationConfigured bool      `json:"buildConfigurationConfigured"`
	ArtifactPresent              bool      `json:"artifactPresent"`
	ArtifactChecksumRecorded     bool      `json:"artifactChecksumRecorded"`
	CurrentSourceDeployed        bool      `json:"currentSourceDeployed"`
	DeploymentCommitRecorded     bool      `json:"deploymentCommitRecorded"`
}

// AIAuditSourceCredentialPosture exposes only an opaque credential identity,
// its class, age, and reference counts. Names, authorities, usernames, and
// encrypted secret material stay outside the model boundary.
type AIAuditSourceCredentialPosture struct {
	ID                           uuid.UUID `json:"id"`
	Kind                         string    `json:"kind"`
	GitReferences                int64     `json:"gitReferences"`
	RegistryReferences           int64     `json:"registryReferences"`
	StatusReferences             int64     `json:"statusReferences"`
	TemplateRepositoryReferences int64     `json:"templateRepositoryReferences"`
	CreatedAt                    time.Time `json:"createdAt"`
	LastRotatedAt                time.Time `json:"lastRotatedAt"`
}

type AIAuditLogPosture struct {
	RetentionDays     int                     `json:"retentionDays"`
	CurrentMaxEventID int64                   `json:"currentMaxEventId"`
	EnabledArchives   int64                   `json:"enabledArchives"`
	DisabledArchives  int64                   `json:"disabledArchives"`
	Destinations      []AIAuditArchivePosture `json:"destinations"`
}

type AIAuditArchivePosture struct {
	ID                    uuid.UUID  `json:"id"`
	Enabled               bool       `json:"enabled"`
	RetentionDays         int        `json:"retentionDays"`
	LastArchivedID        int64      `json:"lastArchivedId"`
	UnarchivedEvents      int64      `json:"unarchivedEvents"`
	OldestUnarchivedAt    *time.Time `json:"oldestUnarchivedAt,omitempty"`
	LatestBatchStatus     string     `json:"latestBatchStatus,omitempty"`
	LatestBatchCreatedAt  *time.Time `json:"latestBatchCreatedAt,omitempty"`
	LatestBatchFinishedAt *time.Time `json:"latestBatchFinishedAt,omitempty"`
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
	VerificationOverdue  bool       `json:"verificationOverdue"`
	VerificationDeadline *time.Time `json:"verificationDeadline,omitempty"`
	CreatedAt            time.Time  `json:"createdAt"`
	FinishedAt           *time.Time `json:"finishedAt,omitempty"`
}

type AIAuditAgentCommandPosture struct {
	ClusterID            uuid.UUID  `json:"clusterId"`
	ClusterName          string     `json:"clusterName"`
	Kind                 string     `json:"kind"`
	PendingCommands      int64      `json:"pendingCommands"`
	LeasedCommands       int64      `json:"leasedCommands"`
	DueCommands          int64      `json:"dueCommands"`
	ExpiredLeases        int64      `json:"expiredLeases"`
	OldestDueAt          *time.Time `json:"oldestDueAt,omitempty"`
	OldestExpiredLeaseAt *time.Time `json:"oldestExpiredLeaseAt,omitempty"`
}

// AIAuditReconciliationPosture deliberately excludes Detail. Reconciliation
// detail is produced from Docker/agent errors and may echo workload-controlled
// strings or secret values that must not cross the model trust boundary.
type AIAuditReconciliationPosture struct {
	ComposeServiceID    uuid.UUID  `json:"composeServiceId"`
	State               string     `json:"state"`
	ConsecutiveFailures int        `json:"consecutiveFailures"`
	LastCheckedAt       time.Time  `json:"lastCheckedAt"`
	LastRepairAt        *time.Time `json:"lastRepairAt,omitempty"`
}

type AIAuditIdentityPosture struct {
	RequireSSO                         bool       `json:"requireSso"`
	EnabledOIDCProviders               int64      `json:"enabledOidcProviders"`
	EnabledSAMLProviders               int64      `json:"enabledSamlProviders"`
	ActiveMembers                      int64      `json:"activeMembers"`
	ActiveOwners                       int64      `json:"activeOwners"`
	ActiveAdmins                       int64      `json:"activeAdmins"`
	ActiveDevelopers                   int64      `json:"activeDevelopers"`
	ActiveViewers                      int64      `json:"activeViewers"`
	DisabledMembers                    int64      `json:"disabledMembers"`
	ActiveLocalMembers                 int64      `json:"activeLocalMembers"`
	MFAEnabledLocalMembers             int64      `json:"mfaEnabledLocalMembers"`
	PrivilegedLocalMembers             int64      `json:"privilegedLocalMembers"`
	MFAEnabledPrivilegedLocalMembers   int64      `json:"mfaEnabledPrivilegedLocalMembers"`
	ActiveLocalSessions                int64      `json:"activeLocalSessions"`
	ActiveOIDCSessions                 int64      `json:"activeOidcSessions"`
	ActiveSAMLSessions                 int64      `json:"activeSamlSessions"`
	ActiveServiceAccounts              int64      `json:"activeServiceAccounts"`
	ActivePrivilegedServiceAccounts    int64      `json:"activePrivilegedServiceAccounts"`
	ExpiringServiceAccounts            int64      `json:"expiringServiceAccounts7d"`
	ActiveAuditorServiceAccounts       int64      `json:"activeAuditorServiceAccounts"`
	UnusedServiceAccounts30d           int64      `json:"unusedServiceAccounts30d"`
	UnusedPrivilegedServiceAccounts30d int64      `json:"unusedPrivilegedServiceAccounts30d"`
	OldestUnusedServiceAccountTokenAt  *time.Time `json:"oldestUnusedServiceAccountTokenAt,omitempty"`
	ActiveSCIMTokens                   int64      `json:"activeScimTokens"`
	OldestActiveSCIMTokenCreatedAt     *time.Time `json:"oldestActiveScimTokenCreatedAt,omitempty"`
	PendingInvitations                 int64      `json:"pendingInvitations"`
	PendingPrivilegedInvitations       int64      `json:"pendingPrivilegedInvitations"`
	InvitationsExpiringSoon            int64      `json:"invitationsExpiring24h"`
	ExpiredInvitations                 int64      `json:"expiredInvitations"`
	ProjectScopedGrants                int64      `json:"projectScopedGrants"`
	EnvironmentScopedGrants            int64      `json:"environmentScopedGrants"`
	AdminScopedGrants                  int64      `json:"adminScopedGrants"`
	RedundantScopedGrants              int64      `json:"redundantScopedGrants"`
	SCIMGroups                         int64      `json:"scimGroups"`
	WriteCapableSCIMGroups             int64      `json:"writeCapableScimGroups"`
	SCIMGroupMemberships               int64      `json:"scimGroupMemberships"`
	PendingSAMLCertificateRotations    int64      `json:"pendingSamlCertificateRotations"`
	OldestPendingSAMLRotationAt        *time.Time `json:"oldestPendingSamlRotationAt,omitempty"`
}

type AIAuditDeployTokenPosture struct {
	ActiveTokens                      int64      `json:"activeTokens"`
	ExpiringTokens                    int64      `json:"expiringTokens7d"`
	ExpiredUnrevokedTokens            int64      `json:"expiredUnrevokedTokens"`
	UnusedActiveTokens                int64      `json:"unusedActiveTokens"`
	UnusedActiveTokensOlderThan30Days int64      `json:"unusedActiveTokensOlderThan30Days"`
	OldestActiveTokenCreatedAt        *time.Time `json:"oldestActiveTokenCreatedAt,omitempty"`
	OldestUnusedActiveTokenCreatedAt  *time.Time `json:"oldestUnusedActiveTokenCreatedAt,omitempty"`
}

type AIAuditSAMLProviderPosture struct {
	ID                         uuid.UUID  `json:"id"`
	CertificateConfigurationOK bool       `json:"certificateConfigurationOk"`
	SPCertificateNotAfter      *time.Time `json:"spCertificateNotAfter,omitempty"`
	IDPCertificateNotAfter     *time.Time `json:"idpCertificateNotAfter,omitempty"`
}

type AIAuditNotificationPosture struct {
	ID      uuid.UUID `json:"id"`
	Name    string    `json:"name"`
	Kind    string    `json:"kind"`
	Events  []string  `json:"events"`
	Enabled bool      `json:"enabled"`
}

type AIAuditWebhookPosture struct {
	ID               uuid.UUID `json:"id"`
	ComposeServiceID uuid.UUID `json:"composeServiceId"`
	Provider         string    `json:"provider"`
	Enabled          bool      `json:"enabled"`
}

type AIAuditBackupDestinationInfo struct {
	ID               uuid.UUID `json:"id"`
	UseTLS           bool      `json:"useTls"`
	DatabasePolicies int64     `json:"databasePolicyReferences"`
	VolumePolicies   int64     `json:"volumePolicyReferences"`
	AuditArchives    int64     `json:"auditArchiveReferences"`
	CreatedAt        time.Time `json:"createdAt"`
	LastRotatedAt    time.Time `json:"lastRotatedAt"`
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
	SyncRequestedAt      *time.Time `json:"syncRequestedAt,omitempty"`
	SyncStartedAt        *time.Time `json:"syncStartedAt,omitempty"`
}

type AIAuditServiceDeployment struct {
	ServiceID                uuid.UUID  `json:"serviceId"`
	Name                     string     `json:"name"`
	DesiredState             string     `json:"desiredState"`
	DesiredRevision          int64      `json:"desiredRevision"`
	LatestDeploymentStatus   string     `json:"latestDeploymentStatus,omitempty"`
	LatestDeploymentRevision int64      `json:"latestDeploymentRevision,omitempty"`
	LatestDeploymentAt       *time.Time `json:"latestDeploymentAt,omitempty"`
	CurrentRevisionDeployed  bool       `json:"currentRevisionDeployed"`
}

type AIAuditQueuePosture struct {
	Coverage                 string                    `json:"coverage"`
	PendingJobs              int64                     `json:"pendingJobs"`
	RunningJobs              int64                     `json:"runningJobs"`
	PendingServiceJobs       int64                     `json:"pendingServiceJobs"`
	RunningServiceJobs       int64                     `json:"runningServiceJobs"`
	PendingDatabaseJobs      int64                     `json:"pendingDatabaseJobs"`
	RunningDatabaseJobs      int64                     `json:"runningDatabaseJobs"`
	OldestPendingAt          *time.Time                `json:"oldestPendingAt,omitempty"`
	OldestRunningHeartbeatAt *time.Time                `json:"oldestRunningHeartbeatAt,omitempty"`
	Kinds                    []AIAuditQueueKindPosture `json:"kinds"`
}

type AIAuditQueueKindPosture struct {
	Kind                     string     `json:"kind"`
	PendingJobs              int64      `json:"pendingJobs"`
	RunningJobs              int64      `json:"runningJobs"`
	OldestPendingAt          *time.Time `json:"oldestPendingAt,omitempty"`
	OldestRunningHeartbeatAt *time.Time `json:"oldestRunningHeartbeatAt,omitempty"`
}

type AIAuditFinalizerPosture struct {
	DeletingProjects          int64      `json:"deletingProjects"`
	DeletingEnvironments      int64      `json:"deletingEnvironments"`
	DeletingServices          int64      `json:"deletingServices"`
	DeletingClusters          int64      `json:"deletingClusters"`
	DeletingNetworks          int64      `json:"deletingNetworks"`
	PendingJobs               int64      `json:"pendingJobs"`
	RunningJobs               int64      `json:"runningJobs"`
	FailedJobs                int64      `json:"failedJobs"`
	ResourcesWithoutActiveJob int64      `json:"resourcesWithoutActiveJob"`
	OldestRequestedAt         *time.Time `json:"oldestRequestedAt,omitempty"`
}

// BuildAIAuditSnapshot deliberately uses the list projections: Compose source,
// environment values, credentials, and backup contents never enter the agent
// context. The snapshot is broad but remains read-only and secret-free.
func (s *Store) BuildAIAuditSnapshot(ctx context.Context, organizationID uuid.UUID) (AIAuditSnapshot, error) {
	snapshot := AIAuditSnapshot{GeneratedAt: time.Now().UTC(), Organization: organizationID, Projects: []AIAuditProjectInfo{}, Environments: []AIAuditEnvironmentInfo{}, Services: []AIAuditServiceInfo{}, Routes: []AIAuditRouteInfo{}, Databases: []AIAuditDatabaseInfo{}, DatabaseEngines: []AIAuditDatabaseEngineInfo{}, Clusters: []AIAuditClusterInfo{}, ManagedNetworks: []AIAuditManagedNetworkInfo{}, CustomTLSPosture: []AIAuditCustomTLSPosture{}, EdgeTLSPosture: []AIAuditEdgeTLSPosture{}, AgentUpgradePosture: []AIAuditAgentUpgradePosture{}, AgentCommandPosture: []AIAuditAgentCommandPosture{}, BackupPosture: []AIAuditBackupPosture{}, VolumeBackupPosture: []AIAuditVolumeBackupPosture{}, ResourcePolicies: []AIAuditResourcePolicyPosture{}, WorkloadPosture: []AIAuditWorkloadPosture{}, SourceBuildPosture: []AIAuditSourceBuildPosture{}, SourceCredentials: []AIAuditSourceCredentialPosture{}, AuditLogPosture: AIAuditLogPosture{Destinations: []AIAuditArchivePosture{}}, SAMLPosture: []AIAuditSAMLProviderPosture{}, NotificationPosture: []AIAuditNotificationPosture{}, WebhookPosture: []AIAuditWebhookPosture{}, BackupDestinations: []AIAuditBackupDestinationInfo{}, TemplateRepositories: []AIAuditTemplateRepositoryInfo{}, MigrationPosture: []AIAuditMigrationPosture{}, MigrationBlockers: []AIAuditMigrationBlocker{}, ServiceDeployments: []AIAuditServiceDeployment{}, ServiceSchedules: []AIAuditServiceSchedulePosture{}, QueuePosture: AIAuditQueuePosture{Coverage: "all-supported-tenant-jobs", Kinds: []AIAuditQueueKindPosture{}}, Reconciliation: []AIAuditReconciliationPosture{}, Signals: []AIAuditSignal{}, AuditEvents: []AIAuditEventInfo{}}
	projects, err := s.ListProjects(ctx, organizationID)
	if err != nil {
		return snapshot, err
	}
	for _, item := range projects {
		tagNames := make([]string, 0, len(item.Tags))
		for _, tag := range item.Tags {
			tagNames = append(tagNames, tag.Name)
		}
		snapshot.Projects = append(snapshot.Projects, AIAuditProjectInfo{ID: item.ID, OrganizationID: item.OrganizationID, Name: item.Name, Slug: item.Slug, Tags: tagNames, CreatedAt: item.CreatedAt})
	}
	if err = s.loadAIAuditInventory(ctx, organizationID, &snapshot); err != nil {
		return snapshot, err
	}
	clusters, err := s.ListClusters(ctx, organizationID)
	if err != nil {
		return snapshot, err
	}
	for _, item := range clusters {
		snapshot.Clusters = append(snapshot.Clusters, AIAuditClusterInfo{
			ID: item.ID, OrganizationID: item.OrganizationID, Name: item.Name, Slug: item.Slug, State: item.State,
			AgentVersion: item.AgentVersion, AgentImage: item.AgentImage, AgentUpdateState: item.AgentUpdateState, DockerVersion: item.DockerVersion,
			CertificateAuthorityFingerprint: item.CertificateAuthorityFingerprint, PendingCertificateAuthorityFingerprint: item.PendingCertificateAuthorityFingerprint,
			CertificateNotAfter: item.CertificateNotAfter, LastSeenAt: item.LastSeenAt, MaintenanceStartsAt: item.MaintenanceStartsAt,
			MaintenanceEndsAt: item.MaintenanceEndsAt, CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt,
		})
	}
	networks, err := s.ListManagedNetworks(ctx, organizationID)
	if err != nil {
		return snapshot, err
	}
	for _, item := range networks {
		snapshot.ManagedNetworks = append(snapshot.ManagedNetworks, AIAuditManagedNetworkInfo{ID: item.ID, ClusterID: item.ClusterID, Name: item.Name, Driver: item.Driver, Internal: item.Internal, Attachable: item.Attachable, EnableIPv4: item.EnableIPv4, EnableIPv6: item.EnableIPv6, Status: item.Status, UpdatedAt: item.UpdatedAt})
	}
	reconciliation, err := s.ListServiceReconciliations(ctx, organizationID)
	if err != nil {
		return snapshot, err
	}
	for _, item := range reconciliation {
		snapshot.Reconciliation = append(snapshot.Reconciliation, AIAuditReconciliationPosture{
			ComposeServiceID: item.ComposeServiceID, State: item.State,
			ConsecutiveFailures: item.ConsecutiveFailures,
			LastCheckedAt:       item.LastCheckedAt, LastRepairAt: item.LastRepairAt,
		})
	}
	if err = s.loadAIAuditOperationalPosture(ctx, organizationID, &snapshot); err != nil {
		return snapshot, err
	}
	events, err := s.ListAuditEvents(ctx, organizationID, 0, 500, false)
	if err != nil {
		return snapshot, err
	}
	for _, item := range events {
		snapshot.AuditEvents = append(snapshot.AuditEvents, AIAuditEventInfo{
			ID: item.ID, ActorUserID: item.ActorUserID, ActorServiceAccountID: item.ActorServiceAccountID,
			Action: item.Action, ResourceType: item.ResourceType, ResourceID: item.ResourceID, CreatedAt: item.CreatedAt,
		})
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT kind,status,count(*) FROM (
			SELECT 'deployment' AS kind,d.status,d.created_at FROM deployments d JOIN compose_services s ON s.id=d.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE p.organization_id=$1
			UNION ALL SELECT 'backup',b.status,b.created_at FROM database_backups b JOIN database_instances d ON d.id=b.database_instance_id JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE p.organization_id=$1
			UNION ALL SELECT 'restore',r.status,r.created_at FROM database_restores r JOIN database_backups b ON b.id=r.database_backup_id JOIN database_instances d ON d.id=b.database_instance_id JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE p.organization_id=$1
			UNION ALL SELECT 'volume_backup',b.status,b.created_at FROM volume_backups b JOIN compose_services s ON s.id=b.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE p.organization_id=$1
			UNION ALL SELECT 'volume_restore',r.status,r.created_at FROM volume_restores r JOIN volume_backups b ON b.id=r.volume_backup_id JOIN compose_services s ON s.id=b.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE p.organization_id=$1
			UNION ALL SELECT 'notification',d.status,d.created_at FROM notification_deliveries d JOIN notification_endpoints n ON n.id=d.endpoint_id WHERE n.organization_id=$1
			UNION ALL SELECT 'database_migration',m.status,m.created_at FROM database_migrations m JOIN database_instances d ON d.id=m.database_instance_id JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE p.organization_id=$1
			UNION ALL SELECT 'audit_archive',b.status,b.created_at FROM audit_archive_batches b JOIN audit_archive_destinations a ON a.id=b.destination_id WHERE a.organization_id=$1
			UNION ALL SELECT 'agent_command',command.status,command.created_at FROM cluster_commands command JOIN clusters cluster ON cluster.id=command.cluster_id WHERE cluster.organization_id=$1
			UNION ALL SELECT 'commit_status',delivery.status,delivery.created_at FROM commit_status_deliveries delivery JOIN deployments d ON d.id=delivery.deployment_id JOIN compose_services s ON s.id=d.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE p.organization_id=$1
			UNION ALL SELECT 'ai_audit',CASE run.status WHEN 'completed' THEN 'succeeded' ELSE run.status END,run.started_at FROM ai_audit_runs run WHERE run.organization_id=$1
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

// loadAIAuditInventory uses a fixed number of tenant-scoped queries. In
// particular, it never loads each service and its routes independently, which
// keeps audit latency bounded by result size rather than workload count.
func (s *Store) loadAIAuditInventory(ctx context.Context, organizationID uuid.UUID, snapshot *AIAuditSnapshot) error {
	rows, err := s.Pool.Query(ctx, `SELECT environment.id,environment.project_id,environment.cluster_id,environment.placement_selector,
		environment.minimum_nodes,environment.minimum_nano_cpus,environment.minimum_memory_bytes,environment.name,environment.slug,environment.created_at
		FROM environments environment JOIN projects project ON project.id=environment.project_id
		WHERE project.organization_id=$1
		ORDER BY project.name,project.id,environment.name,environment.id`, organizationID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var item AIAuditEnvironmentInfo
		var placementSelector map[string]string
		if err = rows.Scan(&item.ID, &item.ProjectID, &item.ClusterID, &placementSelector, &item.MinimumNodes, &item.MinimumNanoCPUs, &item.MinimumMemoryBytes, &item.Name, &item.Slug, &item.CreatedAt); err != nil {
			rows.Close()
			return err
		}
		item.PlacementSelectorConfigured = len(placementSelector) > 0
		snapshot.Environments = append(snapshot.Environments, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	rows, err = s.Pool.Query(ctx, `SELECT service.id,service.environment_id,service.name,service.slug,service.stack_name,service.storage_node_id,
		service.revision,service.desired_state,ARRAY(SELECT tag.name FROM compose_service_tags assignment JOIN tags tag ON tag.id=assignment.tag_id WHERE assignment.compose_service_id=service.id ORDER BY lower(tag.name),tag.id),ARRAY(SELECT network.name FROM compose_service_networks assignment JOIN managed_networks network ON network.id=assignment.network_id WHERE assignment.compose_service_id=service.id ORDER BY lower(network.name),network.id),service.created_at,service.updated_at,service.compose_yaml,runtime.id IS NOT NULL,COALESCE(runtime.effective_compose,'')
		FROM compose_services service
		JOIN environments environment ON environment.id=service.environment_id
		JOIN projects project ON project.id=environment.project_id
		LEFT JOIN LATERAL (
			SELECT deployment.id,deployment.effective_compose
			FROM deployments deployment
			WHERE deployment.compose_service_id=service.id AND deployment.status='succeeded'
			ORDER BY deployment.finished_at DESC NULLS LAST,deployment.created_at DESC,deployment.id DESC
			LIMIT 1
		) runtime ON true
		WHERE project.organization_id=$1 AND service.deletion_requested_at IS NULL
		ORDER BY project.name,project.id,environment.name,environment.id,service.name,service.id`, organizationID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var item AIAuditServiceInfo
		var composeYAML, runtimeCompose string
		var successfulDeployment bool
		if err = rows.Scan(&item.ID, &item.EnvironmentID, &item.Name, &item.Slug, &item.StackName, &item.StorageNodeID, &item.Revision, &item.DesiredState, &item.Tags, &item.Networks, &item.CreatedAt, &item.UpdatedAt, &composeYAML, &successfulDeployment, &runtimeCompose); err != nil {
			rows.Close()
			return err
		}
		snapshot.Services = append(snapshot.Services, item)
		posture := analyzeAIAuditWorkload(item.ID, composeYAML)
		posture.SuccessfulDeployment = successfulDeployment
		if runtimeCompose != "" {
			runtime := analyzeAIAuditWorkload(item.ID, runtimeCompose)
			posture.RuntimeSnapshotAvailable = true
			posture.RuntimeDefinitionParseable = runtime.DefinitionParseable
			posture.RuntimeContainerCount = runtime.ContainerCount
			posture.RuntimeDigestPinnedImages = runtime.DigestPinnedImages
			posture.RuntimeMutableImages = runtime.MutableImages
			posture.RuntimeBuildOnlyServices = runtime.BuildOnlyServices
			posture.RuntimeMissingImageOrBuild = runtime.MissingImageOrBuild
		}
		snapshot.WorkloadPosture = append(snapshot.WorkloadPosture, posture)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	rows, err = s.Pool.Query(ctx, `SELECT route.id,route.compose_service_id,route.service_name,route.host,route.path_prefix,route.internal_path,route.strip_path,NOT route.enabled,route.redirect_regex<>'',route.redirect_permanent,EXISTS(SELECT 1 FROM route_basic_auth_users auth WHERE auth.compose_service_id=route.compose_service_id),route.target_port,route.tls,route.certificate_resolver,route.custom_certificate_id
		FROM routes route
		JOIN compose_services service ON service.id=route.compose_service_id
		JOIN environments environment ON environment.id=service.environment_id
		JOIN projects project ON project.id=environment.project_id
		WHERE project.organization_id=$1 AND service.deletion_requested_at IS NULL
		ORDER BY project.name,project.id,environment.name,environment.id,service.name,service.id,route.host,route.path_prefix,route.id`, organizationID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var item AIAuditRouteInfo
		if err = rows.Scan(&item.ID, &item.ComposeServiceID, &item.ServiceName, &item.Host, &item.PathPrefix, &item.InternalPath, &item.StripPath, &item.Disabled, &item.RedirectConfigured, &item.RedirectPermanent, &item.BasicAuthEnabled, &item.TargetPort, &item.TLS, &item.CertificateResolver, &item.CustomCertificateID); err != nil {
			rows.Close()
			return err
		}
		item.Enabled = !item.Disabled
		snapshot.Routes = append(snapshot.Routes, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	rows, err = s.Pool.Query(ctx, `SELECT certificate.id,certificate.not_before,certificate.not_after,certificate.revision,count(route.id),count(route.id) FILTER (WHERE route.enabled AND route.tls)
		FROM custom_tls_certificates certificate
		LEFT JOIN routes route ON route.custom_certificate_id=certificate.id
		WHERE certificate.organization_id=$1
		GROUP BY certificate.id
		ORDER BY certificate.id`, organizationID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var item AIAuditCustomTLSPosture
		if err = rows.Scan(&item.ID, &item.NotBefore, &item.NotAfter, &item.Revision, &item.AttachedRoutes, &item.EnabledRoutes); err != nil {
			rows.Close()
			return err
		}
		snapshot.CustomTLSPosture = append(snapshot.CustomTLSPosture, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	rows, err = s.Pool.Query(ctx, `SELECT target.target_key,target.cluster_id,target.generation,target.applied_generation,target.status,target.updated_at
		FROM edge_certificate_targets target
		WHERE EXISTS (
			SELECT 1 FROM routes route
			JOIN custom_tls_certificates certificate ON certificate.id=route.custom_certificate_id
			JOIN compose_services service ON service.id=route.compose_service_id
			JOIN environments environment ON environment.id=service.environment_id
			WHERE certificate.organization_id=$1
			AND ((target.cluster_id IS NULL AND environment.cluster_id IS NULL) OR target.cluster_id=environment.cluster_id)
		)
		ORDER BY target.target_key`, organizationID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var item AIAuditEdgeTLSPosture
		if err = rows.Scan(&item.TargetKey, &item.ClusterID, &item.Generation, &item.AppliedGeneration, &item.Status, &item.UpdatedAt); err != nil {
			rows.Close()
			return err
		}
		snapshot.EdgeTLSPosture = append(snapshot.EdgeTLSPosture, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	rows, err = s.Pool.Query(ctx, `SELECT database.id,database.environment_id,database.name,database.slug,database.engine,database.version,
		database.driver_source,database.driver_artifact_digest,database.storage_node_id,database.compose_service_id,database.status,database.created_at
		FROM database_instances database
		JOIN environments environment ON environment.id=database.environment_id
		JOIN projects project ON project.id=environment.project_id
		WHERE project.organization_id=$1
		ORDER BY project.name,project.id,environment.name,environment.id,database.name,database.id`, organizationID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var item AIAuditDatabaseInfo
		if err = rows.Scan(&item.ID, &item.EnvironmentID, &item.Name, &item.Slug, &item.Engine, &item.Version, &item.DriverSource, &item.DriverDigest, &item.StorageNodeID, &item.ComposeServiceID, &item.Status, &item.CreatedAt); err != nil {
			return err
		}
		snapshot.Databases = append(snapshot.Databases, item)
	}
	return rows.Err()
}

func analyzeAIAuditWorkload(serviceID uuid.UUID, composeYAML string) AIAuditWorkloadPosture {
	posture := AIAuditWorkloadPosture{ServiceID: serviceID, NamedVolumes: []string{}}
	var document map[string]any
	if err := yaml.Unmarshal([]byte(composeYAML), &document); err != nil {
		return posture
	}
	services, ok := document["services"].(map[string]any)
	if !ok || len(services) == 0 {
		return posture
	}
	posture.NamedVolumes, ok = mountedNamedVolumes(document, services)
	if !ok {
		return posture
	}
	for _, raw := range services {
		service, valid := raw.(map[string]any)
		if !valid {
			return posture
		}
		posture.ContainerCount++
		if image, exists := service["image"]; exists {
			imageName, valid := image.(string)
			if !valid || strings.TrimSpace(imageName) == "" {
				return posture
			}
			if ociref.IsDigestPinned(strings.TrimSpace(imageName)) {
				posture.DigestPinnedImages++
			} else {
				posture.MutableImages++
			}
		} else if _, builds := service["build"]; builds {
			posture.BuildOnlyServices++
		} else {
			posture.MissingImageOrBuild++
		}
	}
	posture.DefinitionParseable = true
	return posture
}

func mountedNamedVolumes(document, services map[string]any) ([]string, bool) {
	declaredVolumes := map[string]any{}
	var ok bool
	if document["volumes"] != nil {
		declaredVolumes, ok = document["volumes"].(map[string]any)
		if !ok {
			return nil, false
		}
	}
	usedVolumes := map[string]bool{}
	for _, raw := range services {
		service, valid := raw.(map[string]any)
		if !valid {
			return nil, false
		}
		if service["volumes"] == nil {
			continue
		}
		volumes, valid := service["volumes"].([]any)
		if !valid {
			return nil, false
		}
		for _, rawVolume := range volumes {
			var source string
			if spec, valid := rawVolume.(map[string]any); valid {
				kind, _ := spec["type"].(string)
				source, _ = spec["source"].(string)
				if kind != "volume" {
					continue
				}
			} else if text, valid := rawVolume.(string); valid {
				parts := strings.SplitN(text, ":", 2)
				if len(parts) != 2 {
					continue
				}
				source = parts[0]
			} else {
				return nil, false
			}
			if _, declared := declaredVolumes[source]; source != "" && declared {
				usedVolumes[source] = true
			}
		}
	}
	names := make([]string, 0, len(usedVolumes))
	for name := range usedVolumes {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, true
}

func ensureProtectedVolumesDeclared(ctx context.Context, tx pgx.Tx, serviceID uuid.UUID, composeYAML string) error {
	volumes, err := mountedNamedVolumesFromCompose(composeYAML)
	if err != nil {
		return err
	}
	declared := make(map[string]bool, len(volumes))
	for _, name := range volumes {
		declared[name] = true
	}
	rows, err := tx.Query(ctx, `SELECT volume_name FROM volume_backup_policies WHERE compose_service_id=$1 ORDER BY volume_name`, serviceID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			return err
		}
		if !declared[name] {
			return fmt.Errorf("%w: %s", ErrProtectedVolumeRemoved, name)
		}
	}
	return rows.Err()
}

func mountedNamedVolumesFromCompose(composeYAML string) ([]string, error) {
	var document map[string]any
	if err := yaml.Unmarshal([]byte(composeYAML), &document); err != nil {
		return nil, err
	}
	services, ok := document["services"].(map[string]any)
	if !ok || len(services) == 0 {
		return nil, errors.New("compose document must define services")
	}
	volumes, ok := mountedNamedVolumes(document, services)
	if !ok {
		return nil, errors.New("compose volume definitions are invalid")
	}
	return volumes, nil
}

func (s *Store) loadAIAuditOperationalPosture(ctx context.Context, organizationID uuid.UUID, snapshot *AIAuditSnapshot) error {
	if err := s.loadAIAuditServiceSchedulePosture(ctx, organizationID, &snapshot.ServiceSchedules); err != nil {
		return err
	}
	if err := s.loadAIAuditLogPosture(ctx, organizationID, &snapshot.AuditLogPosture); err != nil {
		return err
	}
	if err := s.loadAIAuditSourceBuildPosture(ctx, organizationID, &snapshot.SourceBuildPosture); err != nil {
		return err
	}
	if err := s.loadAIAuditSourceCredentialPosture(ctx, organizationID, &snapshot.SourceCredentials); err != nil {
		return err
	}
	if err := s.loadAIAuditIntegrationPosture(ctx, organizationID, &snapshot.WebhookPosture, &snapshot.BackupDestinations); err != nil {
		return err
	}
	if err := s.loadAIAuditFinalizerPosture(ctx, organizationID, &snapshot.FinalizerPosture); err != nil {
		return err
	}
	if err := s.loadAIAuditDeployTokenPosture(ctx, organizationID, &snapshot.DeployTokenPosture); err != nil {
		return err
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT scope_type,scope_id,maintenance_enabled,max_projects,max_environments,max_services,max_databases,updated_at
		FROM resource_policies WHERE organization_id=$1 ORDER BY scope_type,scope_id`, organizationID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var item AIAuditResourcePolicyPosture
		if err = rows.Scan(&item.ScopeType, &item.ScopeID, &item.Maintenance, &item.MaxProjects, &item.MaxEnvironments, &item.MaxServices, &item.MaxDatabases, &item.UpdatedAt); err != nil {
			rows.Close()
			return err
		}
		snapshot.ResourcePolicies = append(snapshot.ResourcePolicies, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	populateAIAuditPolicyUsage(snapshot)

	rows, err = s.Pool.Query(ctx, `
		SELECT c.id,c.name,latest.id,latest.status,latest.target_image,latest.attempts,
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
		if err = rows.Scan(&item.ClusterID, &item.ClusterName, &item.CommandID, &item.Status, &item.TargetImage, &item.Attempts, &item.VerificationOverdue, &item.VerificationDeadline, &item.CreatedAt, &item.FinishedAt); err != nil {
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
		SELECT cluster.id,cluster.name,command.kind,
			count(*) FILTER (WHERE command.status='pending'),
			count(*) FILTER (WHERE command.status='leased'),
			count(*) FILTER (WHERE command.status='pending' AND command.run_after<=now()),
			count(*) FILTER (WHERE command.status='leased' AND command.lease_expires_at<=now()),
			min(command.run_after) FILTER (WHERE command.status='pending' AND command.run_after<=now()),
			min(command.lease_expires_at) FILTER (WHERE command.status='leased' AND command.lease_expires_at<=now())
		FROM cluster_commands command
		JOIN clusters cluster ON cluster.id=command.cluster_id
		WHERE cluster.organization_id=$1 AND command.status IN ('pending','leased')
		GROUP BY cluster.id,cluster.name,command.kind
		ORDER BY cluster.name,cluster.id,command.kind`, organizationID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var item AIAuditAgentCommandPosture
		if err = rows.Scan(&item.ClusterID, &item.ClusterName, &item.Kind, &item.PendingCommands, &item.LeasedCommands, &item.DueCommands, &item.ExpiredLeases, &item.OldestDueAt, &item.OldestExpiredLeaseAt); err != nil {
			rows.Close()
			return err
		}
		snapshot.AgentCommandPosture = append(snapshot.AgentCommandPosture, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	rows, err = s.Pool.Query(ctx, `
		SELECT service.id,service.name,policy.volume_name,service.storage_node_id,policy.enabled,policy.interval_seconds,policy.retention_count,policy.quiesce,
			COALESCE(last_backup.status,''),last_backup.finished_at,COALESCE(last_restore.status,''),last_restore.finished_at
		FROM volume_backup_policies policy
		JOIN compose_services service ON service.id=policy.compose_service_id
		JOIN environments environment ON environment.id=service.environment_id
		JOIN projects project ON project.id=environment.project_id
		LEFT JOIN LATERAL (SELECT backup.id,backup.status,backup.finished_at,backup.created_at FROM volume_backups backup WHERE backup.compose_service_id=service.id AND backup.volume_name=policy.volume_name ORDER BY backup.created_at DESC LIMIT 1) last_backup ON true
		LEFT JOIN LATERAL (SELECT restore.status,restore.finished_at,restore.created_at FROM volume_restores restore JOIN volume_backups backup ON backup.id=restore.volume_backup_id WHERE backup.compose_service_id=service.id AND backup.volume_name=policy.volume_name ORDER BY restore.created_at DESC LIMIT 1) last_restore ON true
		WHERE project.organization_id=$1 AND service.deletion_requested_at IS NULL
		ORDER BY service.name,policy.volume_name`, organizationID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var item AIAuditVolumeBackupPosture
		if err = rows.Scan(&item.ServiceID, &item.ServiceName, &item.VolumeName, &item.StorageNodeID, &item.PolicyEnabled, &item.IntervalSeconds, &item.RetentionCount, &item.Quiesce, &item.LastBackupStatus, &item.LastBackupAt, &item.LastRestoreStatus, &item.LastRestoreAt); err != nil {
			rows.Close()
			return err
		}
		snapshot.VolumeBackupPosture = append(snapshot.VolumeBackupPosture, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	rows, err = s.Pool.Query(ctx, `
		SELECT d.id,d.name,d.engine,d.status,
			bp.id IS NOT NULL,COALESCE(bp.enabled,false),COALESCE(bp.interval_seconds,0),COALESCE(bp.retention_count,0),COALESCE(bp.verify_restore,false),bp.destination_id IS NOT NULL,
			COALESCE(last_backup.status,''),last_backup.finished_at,COALESCE(last_drill.status,''),last_drill.finished_at
		FROM database_instances d
		JOIN environments e ON e.id=d.environment_id
		JOIN projects p ON p.id=e.project_id
		LEFT JOIN backup_policies bp ON bp.database_instance_id=d.id
		LEFT JOIN LATERAL (SELECT b.status,b.finished_at,b.created_at FROM database_backups b WHERE b.database_instance_id=d.id ORDER BY b.created_at DESC LIMIT 1) last_backup ON true
		LEFT JOIN LATERAL (SELECT r.status,r.finished_at,r.created_at FROM database_restores r JOIN database_backups b ON b.id=r.database_backup_id WHERE b.database_instance_id=d.id AND r.kind='drill' ORDER BY r.created_at DESC LIMIT 1) last_drill ON true
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
		SELECT s.id,s.name,s.desired_state,s.revision,COALESCE(latest.status,''),COALESCE(latest.revision,0),latest.created_at,
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
		if err = rows.Scan(&item.ServiceID, &item.Name, &item.DesiredState, &item.DesiredRevision, &item.LatestDeploymentStatus, &item.LatestDeploymentRevision, &item.LatestDeploymentAt, &item.CurrentRevisionDeployed); err != nil {
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

	rows, err = s.Pool.Query(ctx, `
		WITH scoped_job_ids AS (
			SELECT job.id FROM jobs job
			JOIN compose_services service ON job.resource_key='service:' || service.id::text
			JOIN environments environment ON environment.id=service.environment_id
			JOIN projects project ON project.id=environment.project_id
			WHERE project.organization_id=$1
			UNION
			SELECT job.id FROM jobs job
			JOIN database_instances database ON job.resource_key='database:' || database.id::text
			JOIN environments environment ON environment.id=database.environment_id
			JOIN projects project ON project.id=environment.project_id
			WHERE project.organization_id=$1
			UNION
			SELECT job.id FROM jobs job
			JOIN deployments deployment ON deployment.id::text=job.payload->>'deploymentId'
			JOIN compose_services service ON service.id=deployment.compose_service_id
			JOIN environments environment ON environment.id=service.environment_id
			JOIN projects project ON project.id=environment.project_id
			WHERE job.kind='deploy.compose' AND project.organization_id=$1
			UNION
			SELECT job.id FROM jobs job
			JOIN notification_deliveries delivery ON delivery.id::text=job.payload->>'deliveryId'
			JOIN notification_endpoints endpoint ON endpoint.id=delivery.endpoint_id
			WHERE job.kind='notify.webhook' AND endpoint.organization_id=$1
			UNION
			SELECT job.id FROM jobs job
			JOIN commit_status_deliveries delivery ON delivery.id::text=job.payload->>'deliveryId'
			JOIN deployments deployment ON deployment.id=delivery.deployment_id
			JOIN compose_services service ON service.id=deployment.compose_service_id
			JOIN environments environment ON environment.id=service.environment_id
			JOIN projects project ON project.id=environment.project_id
			WHERE job.kind='commit.status' AND project.organization_id=$1
			UNION
			SELECT job.id FROM jobs job
			JOIN audit_archive_batches batch ON batch.id::text=job.payload->>'batchId'
			JOIN audit_archive_destinations destination ON destination.id=batch.destination_id
			WHERE job.kind='audit.archive' AND destination.organization_id=$1
			UNION
			SELECT job.id FROM jobs job
			JOIN compose_services service ON service.id::text=job.payload->>'serviceId'
			JOIN environments environment ON environment.id=service.environment_id
			JOIN projects project ON project.id=environment.project_id
			WHERE job.kind='delete.compose' AND project.organization_id=$1
			UNION
			SELECT job.id FROM jobs job
			JOIN environments environment ON environment.id::text=job.payload->>'environmentId'
			JOIN projects project ON project.id=environment.project_id
			WHERE job.kind='delete.environment' AND project.organization_id=$1
			UNION
			SELECT job.id FROM jobs job
			JOIN projects project ON project.id::text=job.payload->>'projectId'
			WHERE job.kind='delete.project' AND project.organization_id=$1
			UNION
			SELECT job.id FROM jobs job
			JOIN clusters cluster ON cluster.id::text=job.payload->>'clusterId'
			WHERE job.kind='delete.cluster' AND cluster.organization_id=$1
		)
		SELECT job.kind,
			count(*) FILTER (WHERE job.status='pending'),
			count(*) FILTER (WHERE job.status='running'),
			min(job.created_at) FILTER (WHERE job.status='pending'),
			min(COALESCE(job.locked_at,job.created_at)) FILTER (WHERE job.status='running')
		FROM jobs job
		JOIN scoped_job_ids scoped ON scoped.id=job.id
		WHERE job.status IN ('pending','running')
		GROUP BY job.kind
		ORDER BY job.kind`, organizationID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var item AIAuditQueueKindPosture
		if err = rows.Scan(&item.Kind, &item.PendingJobs, &item.RunningJobs, &item.OldestPendingAt, &item.OldestRunningHeartbeatAt); err != nil {
			rows.Close()
			return err
		}
		snapshot.QueuePosture.Kinds = append(snapshot.QueuePosture.Kinds, item)
		snapshot.QueuePosture.PendingJobs += item.PendingJobs
		snapshot.QueuePosture.RunningJobs += item.RunningJobs
		if item.OldestPendingAt != nil && (snapshot.QueuePosture.OldestPendingAt == nil || item.OldestPendingAt.Before(*snapshot.QueuePosture.OldestPendingAt)) {
			snapshot.QueuePosture.OldestPendingAt = item.OldestPendingAt
		}
		if item.OldestRunningHeartbeatAt != nil && (snapshot.QueuePosture.OldestRunningHeartbeatAt == nil || item.OldestRunningHeartbeatAt.Before(*snapshot.QueuePosture.OldestRunningHeartbeatAt)) {
			snapshot.QueuePosture.OldestRunningHeartbeatAt = item.OldestRunningHeartbeatAt
		}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

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
		(SELECT count(*) FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.organization_id=$1 AND u.disabled_at IS NULL AND u.password_hash LIKE '$argon2id$%'),
		(SELECT count(*) FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.organization_id=$1 AND u.disabled_at IS NULL AND u.password_hash LIKE '$argon2id$%' AND u.encrypted_totp_secret IS NOT NULL),
		(SELECT count(*) FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.organization_id=$1 AND m.role IN ('owner','admin') AND u.disabled_at IS NULL AND u.password_hash LIKE '$argon2id$%'),
		(SELECT count(*) FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.organization_id=$1 AND m.role IN ('owner','admin') AND u.disabled_at IS NULL AND u.password_hash LIKE '$argon2id$%' AND u.encrypted_totp_secret IS NOT NULL),
		(SELECT count(*) FROM sessions session JOIN memberships m ON m.user_id=session.user_id JOIN users u ON u.id=session.user_id WHERE m.organization_id=$1 AND session.organization_id IS NULL AND session.auth_method='local' AND session.expires_at>now() AND u.disabled_at IS NULL AND (m.role='owner' OR NOT COALESCE((SELECT require_sso FROM organization_auth_settings WHERE organization_id=$1),false))),
		(SELECT count(*) FROM sessions session JOIN memberships m ON m.user_id=session.user_id AND m.organization_id=session.organization_id JOIN users u ON u.id=session.user_id WHERE session.organization_id=$1 AND session.auth_method='oidc' AND session.expires_at>now() AND u.disabled_at IS NULL),
		(SELECT count(*) FROM sessions session JOIN memberships m ON m.user_id=session.user_id AND m.organization_id=session.organization_id JOIN users u ON u.id=session.user_id WHERE session.organization_id=$1 AND session.auth_method='saml' AND session.expires_at>now() AND u.disabled_at IS NULL),
		(SELECT count(*) FROM service_accounts account WHERE account.organization_id=$1 AND account.enabled AND EXISTS(SELECT 1 FROM service_account_tokens token WHERE token.service_account_id=account.id AND token.revoked_at IS NULL AND token.expires_at>now())),
		(SELECT count(*) FROM service_accounts account WHERE account.organization_id=$1 AND account.enabled AND account.role IN ('admin','developer') AND EXISTS(SELECT 1 FROM service_account_tokens token WHERE token.service_account_id=account.id AND token.revoked_at IS NULL AND token.expires_at>now())),
		(SELECT count(*) FROM service_accounts account WHERE account.organization_id=$1 AND account.enabled AND EXISTS(SELECT 1 FROM service_account_tokens token WHERE token.service_account_id=account.id AND token.revoked_at IS NULL AND token.expires_at>now() AND token.expires_at<=now()+interval '7 days')),
		(SELECT count(*) FROM service_accounts account WHERE account.organization_id=$1 AND account.enabled AND account.role='auditor' AND EXISTS(SELECT 1 FROM service_account_tokens token WHERE token.service_account_id=account.id AND token.revoked_at IS NULL AND token.expires_at>now())),
		(SELECT count(*) FROM service_accounts account WHERE account.organization_id=$1 AND account.enabled AND EXISTS(SELECT 1 FROM service_account_tokens token WHERE token.service_account_id=account.id AND token.revoked_at IS NULL AND token.expires_at>now() AND token.last_used_at IS NULL AND token.created_at<=now()-interval '30 days')),
		(SELECT count(*) FROM service_accounts account WHERE account.organization_id=$1 AND account.enabled AND account.role IN ('admin','developer') AND EXISTS(SELECT 1 FROM service_account_tokens token WHERE token.service_account_id=account.id AND token.revoked_at IS NULL AND token.expires_at>now() AND token.last_used_at IS NULL AND token.created_at<=now()-interval '30 days')),
		(SELECT min(token.created_at) FROM service_account_tokens token JOIN service_accounts account ON account.id=token.service_account_id WHERE account.organization_id=$1 AND account.enabled AND token.revoked_at IS NULL AND token.expires_at>now() AND token.last_used_at IS NULL),
		(SELECT count(*) FROM scim_tokens WHERE organization_id=$1 AND revoked_at IS NULL AND expires_at>now()),
		(SELECT min(created_at) FROM scim_tokens WHERE organization_id=$1 AND revoked_at IS NULL AND expires_at>now()),
		(SELECT count(*) FROM organization_invitations WHERE organization_id=$1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at>now()),
		(SELECT count(*) FROM organization_invitations WHERE organization_id=$1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at>now() AND role IN ('owner','admin')),
		(SELECT count(*) FROM organization_invitations WHERE organization_id=$1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at>now() AND expires_at<=now()+interval '24 hours'),
		(SELECT count(*) FROM organization_invitations WHERE organization_id=$1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at<=now()),
		(SELECT count(*) FROM project_grants scoped_grant JOIN projects project ON project.id=scoped_grant.project_id WHERE project.organization_id=$1),
		(SELECT count(*) FROM environment_grants scoped_grant JOIN environments environment ON environment.id=scoped_grant.environment_id JOIN projects project ON project.id=environment.project_id WHERE project.organization_id=$1),
		(SELECT count(*) FROM (
			SELECT scoped_grant.role FROM project_grants scoped_grant JOIN projects project ON project.id=scoped_grant.project_id WHERE project.organization_id=$1
			UNION ALL
			SELECT scoped_grant.role FROM environment_grants scoped_grant JOIN environments environment ON environment.id=scoped_grant.environment_id JOIN projects project ON project.id=environment.project_id WHERE project.organization_id=$1
		) scoped WHERE scoped.role='admin'),
		(SELECT count(*) FROM (
			SELECT scoped_grant.role AS grant_role,membership.role AS member_role FROM project_grants scoped_grant JOIN projects project ON project.id=scoped_grant.project_id JOIN memberships membership ON membership.organization_id=project.organization_id AND membership.user_id=scoped_grant.user_id WHERE project.organization_id=$1
			UNION ALL
			SELECT scoped_grant.role AS grant_role,membership.role AS member_role FROM environment_grants scoped_grant JOIN environments environment ON environment.id=scoped_grant.environment_id JOIN projects project ON project.id=environment.project_id JOIN memberships membership ON membership.organization_id=project.organization_id AND membership.user_id=scoped_grant.user_id WHERE project.organization_id=$1
		) scoped WHERE (CASE scoped.grant_role WHEN 'admin' THEN 3 WHEN 'developer' THEN 2 ELSE 1 END)<=(CASE scoped.member_role WHEN 'owner' THEN 4 WHEN 'admin' THEN 3 WHEN 'developer' THEN 2 ELSE 1 END)),
		(SELECT count(*) FROM scim_groups WHERE organization_id=$1),
		(SELECT count(*) FROM scim_groups WHERE organization_id=$1 AND role IN ('admin','developer')),
		(SELECT count(*) FROM scim_group_members member JOIN scim_groups group_record ON group_record.id=member.group_id WHERE group_record.organization_id=$1),
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
		&snapshot.IdentityPosture.ActiveLocalMembers,
		&snapshot.IdentityPosture.MFAEnabledLocalMembers,
		&snapshot.IdentityPosture.PrivilegedLocalMembers,
		&snapshot.IdentityPosture.MFAEnabledPrivilegedLocalMembers,
		&snapshot.IdentityPosture.ActiveLocalSessions,
		&snapshot.IdentityPosture.ActiveOIDCSessions,
		&snapshot.IdentityPosture.ActiveSAMLSessions,
		&snapshot.IdentityPosture.ActiveServiceAccounts,
		&snapshot.IdentityPosture.ActivePrivilegedServiceAccounts,
		&snapshot.IdentityPosture.ExpiringServiceAccounts,
		&snapshot.IdentityPosture.ActiveAuditorServiceAccounts,
		&snapshot.IdentityPosture.UnusedServiceAccounts30d,
		&snapshot.IdentityPosture.UnusedPrivilegedServiceAccounts30d,
		&snapshot.IdentityPosture.OldestUnusedServiceAccountTokenAt,
		&snapshot.IdentityPosture.ActiveSCIMTokens,
		&snapshot.IdentityPosture.OldestActiveSCIMTokenCreatedAt,
		&snapshot.IdentityPosture.PendingInvitations,
		&snapshot.IdentityPosture.PendingPrivilegedInvitations,
		&snapshot.IdentityPosture.InvitationsExpiringSoon,
		&snapshot.IdentityPosture.ExpiredInvitations,
		&snapshot.IdentityPosture.ProjectScopedGrants,
		&snapshot.IdentityPosture.EnvironmentScopedGrants,
		&snapshot.IdentityPosture.AdminScopedGrants,
		&snapshot.IdentityPosture.RedundantScopedGrants,
		&snapshot.IdentityPosture.SCIMGroups,
		&snapshot.IdentityPosture.WriteCapableSCIMGroups,
		&snapshot.IdentityPosture.SCIMGroupMemberships,
		&snapshot.IdentityPosture.PendingSAMLCertificateRotations,
		&snapshot.IdentityPosture.OldestPendingSAMLRotationAt,
	)
	if err != nil {
		return err
	}
	if err = s.loadAIAuditSAMLPosture(ctx, organizationID, &snapshot.SAMLPosture); err != nil {
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
		snapshot.TemplateRepositories = append(snapshot.TemplateRepositories, AIAuditTemplateRepositoryInfo{ID: repository.ID, Name: repository.Name, GitRef: repository.GitRef, RequireSignature: repository.RequireSignature, CredentialConfigured: repository.CredentialID != nil, WebhookConfigured: repository.WebhookConfigured, SyncIntervalSeconds: repository.SyncIntervalSeconds, Enabled: repository.Enabled, LastSyncStatus: repository.LastSyncStatus, LastSyncedAt: repository.LastSyncedAt, SyncRequestedAt: repository.SyncRequestedAt, SyncStartedAt: repository.SyncStartedAt})
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

func (s *Store) loadAIAuditServiceSchedulePosture(ctx context.Context, organizationID uuid.UUID, posture *[]AIAuditServiceSchedulePosture) error {
	rows, err := s.Pool.Query(ctx, `SELECT schedule.id,service.id,schedule.name,schedule.enabled,service.desired_state,schedule.timezone,schedule.next_run_at,COALESCE(latest.status,''),latest.finished_at,
		(SELECT count(*) FROM service_schedule_executions failed WHERE failed.schedule_id=schedule.id AND failed.status='failed' AND failed.created_at>=now()-interval '24 hours')
		FROM service_schedules schedule
		JOIN compose_services service ON service.id=schedule.compose_service_id
		JOIN environments environment ON environment.id=service.environment_id
		JOIN projects project ON project.id=environment.project_id
		LEFT JOIN LATERAL (SELECT execution.status,execution.finished_at FROM service_schedule_executions execution WHERE execution.schedule_id=schedule.id ORDER BY execution.created_at DESC,execution.id DESC LIMIT 1) latest ON true
		WHERE project.organization_id=$1 ORDER BY service.id,schedule.name,schedule.id`, organizationID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var item AIAuditServiceSchedulePosture
		if err = rows.Scan(&item.ID, &item.ServiceID, &item.Name, &item.Enabled, &item.DesiredState, &item.Timezone, &item.NextRunAt, &item.LastStatus, &item.LastFinishedAt, &item.Failures24h); err != nil {
			return err
		}
		*posture = append(*posture, item)
	}
	return rows.Err()
}

func (s *Store) loadAIAuditSourceCredentialPosture(ctx context.Context, organizationID uuid.UUID, posture *[]AIAuditSourceCredentialPosture) error {
	rows, err := s.Pool.Query(ctx, `
		WITH tenant_sources AS (
			SELECT source.git_credential_id,source.registry_credential_id,source.status_credential_id
			FROM application_sources source
			JOIN compose_services service ON service.id=source.compose_service_id
			JOIN environments environment ON environment.id=service.environment_id
			JOIN projects project ON project.id=environment.project_id
			WHERE project.organization_id=$1
		), application_references AS (
			SELECT reference.credential_id,
				count(*) FILTER (WHERE reference.kind='git') AS git_references,
				count(*) FILTER (WHERE reference.kind='registry') AS registry_references,
				count(*) FILTER (WHERE reference.kind='status') AS status_references
			FROM tenant_sources source
			CROSS JOIN LATERAL (VALUES (source.git_credential_id,'git'),(source.registry_credential_id,'registry'),(source.status_credential_id,'status')) reference(credential_id,kind)
			WHERE reference.credential_id IS NOT NULL
			GROUP BY reference.credential_id
		), catalog_references AS (
			SELECT repository.credential_id,count(*) AS references
			FROM template_repositories repository
			WHERE repository.organization_id=$1 AND repository.credential_id IS NOT NULL
			GROUP BY repository.credential_id
		)
		SELECT credential.id,credential.kind,
			COALESCE(application.git_references,0),
			COALESCE(application.registry_references,0),
			COALESCE(application.status_references,0),
			COALESCE(catalog.references,0),
			credential.created_at,
			credential.updated_at
		FROM source_credentials credential
		LEFT JOIN application_references application ON application.credential_id=credential.id
		LEFT JOIN catalog_references catalog ON catalog.credential_id=credential.id
		WHERE credential.organization_id=$1
		ORDER BY credential.id`, organizationID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var item AIAuditSourceCredentialPosture
		if err = rows.Scan(&item.ID, &item.Kind, &item.GitReferences, &item.RegistryReferences, &item.StatusReferences, &item.TemplateRepositoryReferences, &item.CreatedAt, &item.LastRotatedAt); err != nil {
			return err
		}
		*posture = append(*posture, item)
	}
	return rows.Err()
}

func (s *Store) loadAIAuditIntegrationPosture(ctx context.Context, organizationID uuid.UUID, webhooks *[]AIAuditWebhookPosture, destinations *[]AIAuditBackupDestinationInfo) error {
	rows, err := s.Pool.Query(ctx, `
		SELECT integration.id,integration.compose_service_id,integration.provider,integration.enabled
		FROM webhook_integrations integration
		JOIN compose_services service ON service.id=integration.compose_service_id
		JOIN environments environment ON environment.id=service.environment_id
		JOIN projects project ON project.id=environment.project_id
		WHERE project.organization_id=$1
		ORDER BY integration.provider,integration.id`, organizationID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var item AIAuditWebhookPosture
		if err = rows.Scan(&item.ID, &item.ComposeServiceID, &item.Provider, &item.Enabled); err != nil {
			rows.Close()
			return err
		}
		*webhooks = append(*webhooks, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	rows, err = s.Pool.Query(ctx, `
		SELECT destination.id,destination.use_tls,
			(SELECT count(*) FROM backup_policies policy WHERE policy.destination_id=destination.id),
			(SELECT count(*) FROM volume_backup_policies policy WHERE policy.destination_id=destination.id),
			(SELECT count(*) FROM audit_archive_destinations archive WHERE archive.backup_destination_id=destination.id),
			destination.created_at,destination.updated_at
		FROM backup_destinations destination
		WHERE destination.organization_id=$1
		ORDER BY destination.id`, organizationID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var item AIAuditBackupDestinationInfo
		if err = rows.Scan(&item.ID, &item.UseTLS, &item.DatabasePolicies, &item.VolumePolicies, &item.AuditArchives, &item.CreatedAt, &item.LastRotatedAt); err != nil {
			return err
		}
		*destinations = append(*destinations, item)
	}
	return rows.Err()
}

func (s *Store) loadAIAuditFinalizerPosture(ctx context.Context, organizationID uuid.UUID, posture *AIAuditFinalizerPosture) error {
	return s.Pool.QueryRow(ctx, `
		WITH deleting_resources AS (
			SELECT 'project'::text AS resource_type,project.id::text AS resource_id,project.deletion_requested_at AS requested_at
			FROM projects project WHERE project.organization_id=$1 AND project.deletion_requested_at IS NOT NULL
			UNION ALL
			SELECT 'environment',environment.id::text,environment.deletion_requested_at
			FROM environments environment JOIN projects project ON project.id=environment.project_id
			WHERE project.organization_id=$1 AND environment.deletion_requested_at IS NOT NULL
			UNION ALL
			SELECT 'service',service.id::text,service.deletion_requested_at
			FROM compose_services service JOIN environments environment ON environment.id=service.environment_id JOIN projects project ON project.id=environment.project_id
			WHERE project.organization_id=$1 AND service.deletion_requested_at IS NOT NULL
			UNION ALL
			SELECT 'cluster',cluster.id::text,cluster.deletion_requested_at
			FROM clusters cluster WHERE cluster.organization_id=$1 AND cluster.deletion_requested_at IS NOT NULL
			UNION ALL
			SELECT 'network',network.id::text,network.deletion_requested_at
			FROM managed_networks network WHERE network.organization_id=$1 AND network.deletion_requested_at IS NOT NULL
		), deletion_jobs AS (
			SELECT CASE job.kind
					WHEN 'delete.project' THEN 'project'
					WHEN 'delete.environment' THEN 'environment'
					WHEN 'delete.compose' THEN 'service'
					WHEN 'delete.cluster' THEN 'cluster'
					WHEN 'network.delete' THEN 'network'
				END AS resource_type,
				CASE job.kind
					WHEN 'delete.project' THEN job.payload->>'projectId'
					WHEN 'delete.environment' THEN job.payload->>'environmentId'
					WHEN 'delete.compose' THEN job.payload->>'serviceId'
					WHEN 'delete.cluster' THEN job.payload->>'clusterId'
					WHEN 'network.delete' THEN job.payload->>'networkId'
				END AS resource_id,
				job.status
			FROM jobs job
			WHERE job.kind IN ('delete.project','delete.environment','delete.compose','delete.cluster','network.delete')
		), scoped_jobs AS (
			SELECT job.status FROM deletion_jobs job JOIN deleting_resources resource USING(resource_type,resource_id)
		)
		SELECT
			count(*) FILTER (WHERE resource_type='project'),
			count(*) FILTER (WHERE resource_type='environment'),
			count(*) FILTER (WHERE resource_type='service'),
			count(*) FILTER (WHERE resource_type='cluster'),
			count(*) FILTER (WHERE resource_type='network'),
			(SELECT count(*) FROM scoped_jobs WHERE status='pending'),
			(SELECT count(*) FROM scoped_jobs WHERE status='running'),
			(SELECT count(*) FROM scoped_jobs WHERE status='failed'),
			count(*) FILTER (WHERE NOT EXISTS (
				SELECT 1 FROM deletion_jobs job
				WHERE job.resource_type=deleting_resources.resource_type AND job.resource_id=deleting_resources.resource_id AND job.status IN ('pending','running')
			)),
			min(requested_at)
		FROM deleting_resources`, organizationID).Scan(
		&posture.DeletingProjects,
		&posture.DeletingEnvironments,
		&posture.DeletingServices,
		&posture.DeletingClusters,
		&posture.DeletingNetworks,
		&posture.PendingJobs,
		&posture.RunningJobs,
		&posture.FailedJobs,
		&posture.ResourcesWithoutActiveJob,
		&posture.OldestRequestedAt,
	)
}

func (s *Store) loadAIAuditDeployTokenPosture(ctx context.Context, organizationID uuid.UUID, posture *AIAuditDeployTokenPosture) error {
	return s.Pool.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE token.revoked_at IS NULL AND token.expires_at>now()),
		count(*) FILTER (WHERE token.revoked_at IS NULL AND token.expires_at>now() AND token.expires_at<=now()+interval '7 days'),
		count(*) FILTER (WHERE token.revoked_at IS NULL AND token.expires_at<=now()),
		count(*) FILTER (WHERE token.revoked_at IS NULL AND token.expires_at>now() AND token.last_used_at IS NULL),
		count(*) FILTER (WHERE token.revoked_at IS NULL AND token.expires_at>now() AND token.last_used_at IS NULL AND token.created_at<=now()-interval '30 days'),
		min(token.created_at) FILTER (WHERE token.revoked_at IS NULL AND token.expires_at>now()),
		min(token.created_at) FILTER (WHERE token.revoked_at IS NULL AND token.expires_at>now() AND token.last_used_at IS NULL)
		FROM deploy_tokens token
		JOIN compose_services service ON service.id=token.compose_service_id
		JOIN environments environment ON environment.id=service.environment_id
		JOIN projects project ON project.id=environment.project_id
		WHERE project.organization_id=$1`, organizationID).Scan(
		&posture.ActiveTokens,
		&posture.ExpiringTokens,
		&posture.ExpiredUnrevokedTokens,
		&posture.UnusedActiveTokens,
		&posture.UnusedActiveTokensOlderThan30Days,
		&posture.OldestActiveTokenCreatedAt,
		&posture.OldestUnusedActiveTokenCreatedAt,
	)
}

func (s *Store) loadAIAuditSourceBuildPosture(ctx context.Context, organizationID uuid.UUID, posture *[]AIAuditSourceBuildPosture) error {
	rows, err := s.Pool.Query(ctx, `SELECT source.compose_service_id,source.source_type,source.build_type,source.repository_url,source.git_ref,
		source.git_credential_id IS NOT NULL,source.registry_credential_id IS NOT NULL,
		source.status_provider<>'' AND source.status_credential_id IS NOT NULL,source.enable_submodules,
		source.encrypted_build_config<>'',artifact.compose_service_id IS NOT NULL,COALESCE(artifact.sha256,'')<>'',
		deployment.id IS NOT NULL,COALESCE(deployment.commit_sha,'')<>''
		FROM application_sources source
		JOIN compose_services service ON service.id=source.compose_service_id
		JOIN environments environment ON environment.id=service.environment_id
		JOIN projects project ON project.id=environment.project_id
		LEFT JOIN application_artifacts artifact ON artifact.compose_service_id=source.compose_service_id
		LEFT JOIN LATERAL (
			SELECT candidate.id,candidate.commit_sha
			FROM deployments candidate
			WHERE candidate.compose_service_id=source.compose_service_id AND candidate.status='succeeded'
				AND candidate.created_at>=GREATEST(source.updated_at,COALESCE(artifact.updated_at,source.updated_at))
			ORDER BY candidate.created_at DESC,candidate.id DESC
			LIMIT 1
		) deployment ON true
		WHERE project.organization_id=$1 AND service.deletion_requested_at IS NULL
		ORDER BY source.compose_service_id`, organizationID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var item AIAuditSourceBuildPosture
		var repositoryURL, gitRef string
		if err = rows.Scan(&item.ServiceID, &item.SourceType, &item.BuildType, &repositoryURL, &gitRef, &item.GitCredentialConfigured, &item.RegistryCredentialConfigured, &item.StatusReportingConfigured, &item.SubmodulesEnabled, &item.BuildConfigurationConfigured, &item.ArtifactPresent, &item.ArtifactChecksumRecorded, &item.CurrentSourceDeployed, &item.DeploymentCommitRecorded); err != nil {
			return err
		}
		if item.SourceType == "git" {
			parsed, parseErr := url.Parse(repositoryURL)
			if parseErr == nil && parsed.Host != "" && (parsed.Scheme == "https" || parsed.Scheme == "ssh") {
				item.RepositoryTransport = parsed.Scheme
			} else {
				item.RepositoryTransport = "invalid"
			}
			item.GitRefPinned = aiAuditGitCommit.MatchString(gitRef)
		}
		*posture = append(*posture, item)
	}
	return rows.Err()
}

func (s *Store) loadAIAuditSAMLPosture(ctx context.Context, organizationID uuid.UUID, posture *[]AIAuditSAMLProviderPosture) error {
	rows, err := s.Pool.Query(ctx, `SELECT id,idp_metadata,certificate_pem FROM saml_providers WHERE organization_id=$1 AND enabled ORDER BY id`, organizationID)
	if err != nil {
		return err
	}
	defer rows.Close()
	now := time.Now()
	for rows.Next() {
		var item AIAuditSAMLProviderPosture
		var metadataXML, certificatePEM string
		if err = rows.Scan(&item.ID, &metadataXML, &certificatePEM); err != nil {
			return err
		}
		spExpiry, spErr := auth.SAMLServiceProviderCertificateExpiry(certificatePEM, now)
		if !spExpiry.IsZero() {
			item.SPCertificateNotAfter = &spExpiry
		}
		metadata, parseErr := samlsp.ParseMetadata([]byte(metadataXML))
		var idpExpiry time.Time
		var idpErr error
		if parseErr != nil {
			idpErr = parseErr
		} else {
			idpExpiry, idpErr = auth.SAMLIdentityProviderCertificateExpiry(metadata, now)
		}
		if !idpExpiry.IsZero() {
			item.IDPCertificateNotAfter = &idpExpiry
		}
		item.CertificateConfigurationOK = spErr == nil && idpErr == nil
		*posture = append(*posture, item)
	}
	return rows.Err()
}

func (s *Store) loadAIAuditLogPosture(ctx context.Context, organizationID uuid.UUID, posture *AIAuditLogPosture) error {
	if err := s.Pool.QueryRow(ctx, `SELECT
		COALESCE((SELECT retention_days FROM audit_retention_policies WHERE organization_id=$1),365),
		COALESCE((SELECT max(id) FROM audit_events WHERE organization_id=$1),0),
		(SELECT count(*) FROM audit_archive_destinations WHERE organization_id=$1 AND enabled),
		(SELECT count(*) FROM audit_archive_destinations WHERE organization_id=$1 AND NOT enabled)`, organizationID).Scan(
		&posture.RetentionDays,
		&posture.CurrentMaxEventID,
		&posture.EnabledArchives,
		&posture.DisabledArchives,
	); err != nil {
		return err
	}
	rows, err := s.Pool.Query(ctx, `SELECT destination.id,destination.enabled,destination.retention_days,destination.last_archived_id,
		(SELECT count(*) FROM audit_events event WHERE event.organization_id=$1 AND event.id>destination.last_archived_id),
		(SELECT min(event.created_at) FROM audit_events event WHERE event.organization_id=$1 AND event.id>destination.last_archived_id),
		COALESCE(latest.status,''),latest.created_at,latest.finished_at
		FROM audit_archive_destinations destination
		LEFT JOIN LATERAL (
			SELECT batch.status,batch.created_at,batch.finished_at
			FROM audit_archive_batches batch
			WHERE batch.destination_id=destination.id
			ORDER BY batch.created_at DESC,batch.id DESC
			LIMIT 1
		) latest ON true
		WHERE destination.organization_id=$1
		ORDER BY destination.id`, organizationID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var item AIAuditArchivePosture
		if err = rows.Scan(&item.ID, &item.Enabled, &item.RetentionDays, &item.LastArchivedID, &item.UnarchivedEvents, &item.OldestUnarchivedAt, &item.LatestBatchStatus, &item.LatestBatchCreatedAt, &item.LatestBatchFinishedAt); err != nil {
			return err
		}
		posture.Destinations = append(posture.Destinations, item)
	}
	return rows.Err()
}

func populateAIAuditPolicyUsage(snapshot *AIAuditSnapshot) {
	environmentProjects := make(map[uuid.UUID]uuid.UUID, len(snapshot.Environments))
	projectEnvironments := make(map[uuid.UUID]int)
	environmentServices := make(map[uuid.UUID]int)
	projectServices := make(map[uuid.UUID]int)
	environmentDatabases := make(map[uuid.UUID]int)
	projectDatabases := make(map[uuid.UUID]int)
	for _, environment := range snapshot.Environments {
		environmentProjects[environment.ID] = environment.ProjectID
		projectEnvironments[environment.ProjectID]++
	}
	for _, service := range snapshot.Services {
		environmentServices[service.EnvironmentID]++
		projectServices[environmentProjects[service.EnvironmentID]]++
	}
	for _, database := range snapshot.Databases {
		environmentDatabases[database.EnvironmentID]++
		projectDatabases[environmentProjects[database.EnvironmentID]]++
	}
	for index := range snapshot.ResourcePolicies {
		policy := &snapshot.ResourcePolicies[index]
		switch policy.ScopeType {
		case "organization":
			policy.CurrentProjects = len(snapshot.Projects)
			policy.CurrentEnvironments = len(snapshot.Environments)
			policy.CurrentServices = len(snapshot.Services)
			policy.CurrentDatabases = len(snapshot.Databases)
		case "project":
			policy.CurrentEnvironments = projectEnvironments[policy.ScopeID]
			policy.CurrentServices = projectServices[policy.ScopeID]
			policy.CurrentDatabases = projectDatabases[policy.ScopeID]
		case "environment":
			policy.CurrentServices = environmentServices[policy.ScopeID]
			policy.CurrentDatabases = environmentDatabases[policy.ScopeID]
		}
	}
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
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return AIAuditRun{}, err
	}
	defer tx.Rollback(ctx)
	item, err := createAIAuditRunTx(ctx, tx, organizationID, accountID, agentName, agentVersion, model, scope)
	if err != nil {
		return AIAuditRun{}, err
	}
	return item, tx.Commit(ctx)
}

func (s *Store) CreateAIAuditRunWithAudit(ctx context.Context, principal Principal, agentName, agentVersion, model string, scope json.RawMessage, remoteAddr string) (AIAuditRun, error) {
	if principal.ServiceAccountID == nil {
		return AIAuditRun{}, ErrNotFound
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return AIAuditRun{}, err
	}
	defer tx.Rollback(ctx)
	item, err := createAIAuditRunTx(ctx, tx, principal.OrganizationID, *principal.ServiceAccountID, agentName, agentVersion, model, scope)
	if err != nil {
		return AIAuditRun{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "ai_audit.start", "ai_audit_run", item.ID.String(), remoteAddr, nil); err != nil {
		return AIAuditRun{}, err
	}
	return item, tx.Commit(ctx)
}

func createAIAuditRunTx(ctx context.Context, tx pgx.Tx, organizationID, accountID uuid.UUID, agentName, agentVersion, model string, scope json.RawMessage) (AIAuditRun, error) {
	if len(scope) == 0 {
		scope = json.RawMessage(`{}`)
	}
	var accountOrganizationID uuid.UUID
	err := tx.QueryRow(ctx, `SELECT organization_id FROM service_accounts WHERE id=$1 AND organization_id=$2 AND enabled AND role='auditor' FOR UPDATE`, accountID, organizationID).Scan(&accountOrganizationID)
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
	return item, nil
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
	if err = finishAIAuditRunTx(ctx, tx, organizationID, accountID, runID, status, summary); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) FinishAIAuditRunWithAudit(ctx context.Context, principal Principal, runID uuid.UUID, status, summary, remoteAddr string) error {
	if principal.ServiceAccountID == nil {
		return ErrNotFound
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = finishAIAuditRunTx(ctx, tx, principal.OrganizationID, *principal.ServiceAccountID, runID, status, summary); err != nil {
		return err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "ai_audit."+status, "ai_audit_run", runID.String(), remoteAddr, nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func finishAIAuditRunTx(ctx context.Context, tx pgx.Tx, organizationID, accountID, runID uuid.UUID, status, summary string) error {
	var agentName string
	err := tx.QueryRow(ctx, `UPDATE ai_audit_runs SET status=$4,summary=$5,completed_at=now() WHERE id=$1 AND organization_id=$2 AND service_account_id=$3 AND status='running' RETURNING agent_name`, runID, organizationID, accountID, status, summary).Scan(&agentName)
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
	return nil
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
