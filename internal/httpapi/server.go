package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bendahma/dokploy-go/internal/auth"
	backupstore "github.com/bendahma/dokploy-go/internal/backup"
	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/database"
	"github.com/bendahma/dokploy-go/internal/deploy"
	"github.com/bendahma/dokploy-go/internal/observability"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/bendahma/dokploy-go/internal/templates"
	"github.com/bendahma/dokploy-go/internal/webui"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type Server struct {
	Store                      *store.Store
	Box                        *cryptox.Box
	Compiler                   deploy.Compiler
	Databases                  *database.Registry
	Swarm                      deploy.Scheduler
	SessionTTL                 time.Duration
	Logger                     *slog.Logger
	PublicURL                  string
	OIDCHTTPClient             *http.Client
	EgressTransport            http.RoundTripper
	Metrics                    *observability.Metrics
	MetricsTokenHash           []byte
	AgentCACertificate         []byte
	AgentPreviousCACertificate []byte
	AgentCATrustBundle         []byte
	AgentCAKey                 []byte
	AgentCertificateTTL        time.Duration
	ReadinessCheck             func(context.Context) error
	TrustedProxyCIDRs          []*net.IPNet
}

type contextKey string

const (
	principalKey      contextKey = "principal"
	requestIDKey      contextKey = "request-id"
	forwardedHTTPSKey contextKey = "forwarded-https"
)

var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func (s *Server) Handler() http.Handler {
	if s.Metrics == nil {
		s.Metrics = observability.NewMetrics()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.ready)
	mux.Handle("GET /metrics", s.requireMetricsAuth(http.HandlerFunc(s.metrics)))
	mux.HandleFunc("POST /v1/auth/bootstrap", s.bootstrap)
	mux.HandleFunc("POST /v1/auth/login", s.login)
	mux.HandleFunc("POST /v1/invitations/accept", s.acceptOrganizationInvitation)
	mux.HandleFunc("GET /v1/auth/sso/discover", s.discoverOIDC)
	mux.HandleFunc("GET /v1/auth/sso/{providerID}/start", s.startOIDC)
	mux.HandleFunc("GET /v1/auth/sso/callback", s.callbackOIDC)
	mux.HandleFunc("GET /v1/auth/saml/discover", s.discoverSAML)
	mux.HandleFunc("GET /v1/auth/saml/{providerID}/metadata", s.samlMetadata)
	mux.HandleFunc("GET /v1/auth/saml/{providerID}/start", s.startSAML)
	mux.HandleFunc("POST /v1/auth/saml/{providerID}/acs", s.callbackSAML)
	mux.HandleFunc("POST /v1/hooks/deploy/{token}", s.deployWebhook)
	mux.HandleFunc("POST /v1/hooks/provider/{integrationID}", s.providerWebhook)
	mux.HandleFunc("POST /v1/hooks/template-repositories/{repositoryID}", s.templateRepositoryWebhook)
	mux.HandleFunc("POST /v1/agent/enroll", s.enrollClusterAgent)
	mux.Handle("POST /v1/auth/logout", s.requireAuth(http.HandlerFunc(s.logout)))
	mux.Handle("PUT /v1/auth/password", s.requireAuth(http.HandlerFunc(s.changePassword)))
	mux.Handle("GET /v1/auth/mfa", s.requireAuth(http.HandlerFunc(s.getMFAStatus)))
	mux.Handle("POST /v1/auth/mfa/enrollment", s.requireAuth(http.HandlerFunc(s.beginMFAEnrollment)))
	mux.Handle("POST /v1/auth/mfa/enrollment/confirm", s.requireAuth(http.HandlerFunc(s.confirmMFAEnrollment)))
	mux.Handle("DELETE /v1/auth/mfa", s.requireAuth(http.HandlerFunc(s.disableMFA)))
	mux.Handle("POST /v1/auth/mfa/recovery-codes", s.requireAuth(http.HandlerFunc(s.regenerateMFARecoveryCodes)))
	mux.Handle("GET /v1/me", s.requireAuth(http.HandlerFunc(s.me)))
	mux.Handle("GET /v1/authorization/effective-role", s.requireAuth(http.HandlerFunc(s.getEffectiveRole)))
	mux.Handle("GET /v1/sessions", s.requireAuth(http.HandlerFunc(s.listSessions)))
	mux.Handle("DELETE /v1/sessions/{sessionID}", s.requireAuth(http.HandlerFunc(s.revokeSession)))
	mux.Handle("POST /v1/sessions/revoke-others", s.requireAuth(http.HandlerFunc(s.revokeOtherSessions)))
	mux.Handle("GET /v1/members", s.requireRole("admin", http.HandlerFunc(s.listOrganizationMembers)))
	mux.Handle("PATCH /v1/members/{userID}", s.requireRole("admin", http.HandlerFunc(s.updateOrganizationMember)))
	mux.Handle("DELETE /v1/members/{userID}", s.requireRole("admin", http.HandlerFunc(s.deleteOrganizationMember)))
	mux.Handle("GET /v1/invitations", s.requireRole("admin", http.HandlerFunc(s.listOrganizationInvitations)))
	mux.Handle("POST /v1/invitations", s.requireRole("admin", http.HandlerFunc(s.createOrganizationInvitation)))
	mux.Handle("GET /v1/invitations/{invitationID}", s.requireRole("admin", http.HandlerFunc(s.getOrganizationInvitation)))
	mux.Handle("DELETE /v1/invitations/{invitationID}", s.requireRole("admin", http.HandlerFunc(s.revokeOrganizationInvitation)))
	mux.Handle("GET /v1/sso/settings", s.requireRole("admin", http.HandlerFunc(s.getAuthSettings)))
	mux.Handle("PUT /v1/sso/settings", s.requireRole("admin", http.HandlerFunc(s.putAuthSettings)))
	mux.Handle("GET /v1/service-accounts", s.requireRole("admin", http.HandlerFunc(s.listServiceAccounts)))
	mux.Handle("POST /v1/service-accounts", s.requireRole("admin", http.HandlerFunc(s.createServiceAccount)))
	mux.Handle("POST /v1/service-accounts/{accountID}/rotate", s.requireRole("admin", http.HandlerFunc(s.rotateServiceAccountToken)))
	mux.Handle("DELETE /v1/service-accounts/{accountID}", s.requireRole("admin", http.HandlerFunc(s.deleteServiceAccount)))
	mux.Handle("GET /v1/ai/audit-snapshot", s.requireAuditor(http.HandlerFunc(s.aiAuditSnapshot)))
	mux.Handle("POST /v1/ai/audit-runs", s.requireAuditor(http.HandlerFunc(s.createAIAuditRun)))
	mux.Handle("POST /v1/ai/audit-runs/{runID}/findings", s.requireAuditor(http.HandlerFunc(s.createAIAuditFinding)))
	mux.Handle("PATCH /v1/ai/audit-runs/{runID}", s.requireAuditor(http.HandlerFunc(s.finishAIAuditRun)))
	mux.Handle("GET /v1/ai/audit-runs", s.requireRole("admin", http.HandlerFunc(s.listAIAuditRuns)))
	mux.Handle("GET /v1/ai/audit-runs/{runID}/findings", s.requireRole("admin", http.HandlerFunc(s.listAIAuditFindings)))
	mux.Handle("GET /v1/ai/audit-findings", s.requireRole("admin", http.HandlerFunc(s.listCurrentAIAuditFindings)))
	mux.Handle("PATCH /v1/ai/audit-findings/{findingID}", s.requireRole("admin", http.HandlerFunc(s.updateAIAuditFindingDisposition)))
	mux.Handle("GET /v1/audit-events", s.requireRole("admin", http.HandlerFunc(s.auditEvents)))
	mux.Handle("GET /v1/audit-events/export", s.requireRole("admin", http.HandlerFunc(s.exportAuditEvents)))
	mux.Handle("GET /v1/audit-retention", s.requireRole("admin", http.HandlerFunc(s.getAuditRetention)))
	mux.Handle("PUT /v1/audit-retention", s.requireRole("admin", http.HandlerFunc(s.putAuditRetention)))
	mux.Handle("GET /v1/audit-archives", s.requireRole("admin", http.HandlerFunc(s.listAuditArchives)))
	mux.Handle("POST /v1/audit-archives", s.requireRole("admin", http.HandlerFunc(s.createAuditArchive)))
	mux.Handle("GET /v1/audit-archives/{archiveID}", s.requireRole("admin", http.HandlerFunc(s.getAuditArchive)))
	mux.Handle("DELETE /v1/audit-archives/{archiveID}", s.requireRole("admin", http.HandlerFunc(s.deleteAuditArchive)))
	mux.Handle("POST /v1/audit-archives/{archiveID}/run", s.requireRole("admin", http.HandlerFunc(s.runAuditArchive)))
	mux.Handle("GET /v1/audit-archives/{archiveID}/batches", s.requireRole("admin", http.HandlerFunc(s.listAuditArchiveBatches)))
	mux.Handle("GET /v1/policy", s.requireRole("admin", http.HandlerFunc(s.getOrganizationPolicy)))
	mux.Handle("PUT /v1/policy", s.requireRole("admin", http.HandlerFunc(s.putOrganizationPolicy)))
	mux.Handle("GET /v1/source-credentials", s.requireRole("developer", http.HandlerFunc(s.listSourceCredentials)))
	mux.Handle("POST /v1/source-credentials", s.requireRole("admin", http.HandlerFunc(s.createSourceCredential)))
	mux.Handle("PUT /v1/source-credentials/{credentialID}", s.requireRole("admin", http.HandlerFunc(s.rotateSourceCredential)))
	mux.Handle("DELETE /v1/source-credentials/{credentialID}", s.requireRole("admin", http.HandlerFunc(s.deleteSourceCredential)))
	mux.Handle("GET /v1/custom-tls-certificates", s.requireRole("viewer", http.HandlerFunc(s.listCustomTLSCertificates)))
	mux.Handle("POST /v1/custom-tls-certificates", s.requireRole("admin", http.HandlerFunc(s.createCustomTLSCertificate)))
	mux.Handle("PUT /v1/custom-tls-certificates/{certificateID}", s.requireRole("admin", http.HandlerFunc(s.updateCustomTLSCertificate)))
	mux.Handle("DELETE /v1/custom-tls-certificates/{certificateID}", s.requireRole("admin", http.HandlerFunc(s.deleteCustomTLSCertificate)))
	mux.Handle("GET /v1/notification-endpoints", s.requireRole("admin", http.HandlerFunc(s.listNotificationEndpoints)))
	mux.Handle("POST /v1/notification-endpoints", s.requireRole("admin", http.HandlerFunc(s.createNotificationEndpoint)))
	mux.Handle("DELETE /v1/notification-endpoints/{endpointID}", s.requireRole("admin", http.HandlerFunc(s.deleteNotificationEndpoint)))
	mux.Handle("GET /v1/migration-resources", s.requireRole("admin", http.HandlerFunc(s.listMigrationResources)))
	mux.Handle("GET /v1/swarm/nodes", s.requireRole("admin", http.HandlerFunc(s.swarmNodes)))
	mux.Handle("GET /v1/clusters", s.requireRole("admin", http.HandlerFunc(s.listClusters)))
	mux.Handle("GET /v1/agent-upgrades", s.requireRole("admin", http.HandlerFunc(s.listAgentUpgrades)))
	mux.Handle("POST /v1/clusters", s.requireRole("admin", http.HandlerFunc(s.createCluster)))
	mux.Handle("PATCH /v1/clusters/{clusterID}", s.requireRole("admin", http.HandlerFunc(s.updateCluster)))
	mux.Handle("DELETE /v1/clusters/{clusterID}", s.requireRole("admin", http.HandlerFunc(s.deleteCluster)))
	mux.Handle("POST /v1/clusters/{clusterID}/enrollment-tokens", s.requireRole("admin", http.HandlerFunc(s.createClusterEnrollmentToken)))
	mux.Handle("POST /v1/clusters/{clusterID}/agent-upgrades", s.requireRole("admin", http.HandlerFunc(s.upgradeClusterAgent)))
	mux.Handle("DELETE /v1/clusters/{clusterID}/agent-upgrades/{commandID}", s.requireRole("admin", http.HandlerFunc(s.cancelAgentUpgrade)))
	mux.Handle("GET /v1/clusters/{clusterID}/commands/{commandID}", s.requireRole("admin", http.HandlerFunc(s.getClusterCommand)))
	mux.Handle("GET /v1/clusters/{clusterID}/nodes", s.requireRole("admin", http.HandlerFunc(s.clusterNodes)))
	mux.Handle("POST /v1/sso/oidc-providers", s.requireRole("admin", http.HandlerFunc(s.createOIDCProvider)))
	mux.Handle("GET /v1/sso/oidc-providers", s.requireRole("admin", http.HandlerFunc(s.listOIDCProviders)))
	mux.Handle("PUT /v1/sso/oidc-providers/{providerID}", s.requireRole("admin", http.HandlerFunc(s.updateOIDCProvider)))
	mux.Handle("POST /v1/sso/oidc-providers/{providerID}/enable", s.requireRole("admin", http.HandlerFunc(s.enableOIDCProvider)))
	mux.Handle("DELETE /v1/sso/oidc-providers/{providerID}", s.requireRole("admin", http.HandlerFunc(s.deleteOIDCProvider)))
	mux.Handle("POST /v1/sso/saml-providers", s.requireRole("admin", http.HandlerFunc(s.createSAMLProvider)))
	mux.Handle("GET /v1/sso/saml-providers", s.requireRole("admin", http.HandlerFunc(s.listSAMLProviders)))
	mux.Handle("PUT /v1/sso/saml-providers/{providerID}", s.requireRole("admin", http.HandlerFunc(s.updateSAMLProvider)))
	mux.Handle("POST /v1/sso/saml-providers/{providerID}/enable", s.requireRole("admin", http.HandlerFunc(s.enableSAMLProvider)))
	mux.Handle("POST /v1/sso/saml-providers/{providerID}/certificate-rotation", s.requireRole("admin", http.HandlerFunc(s.beginSAMLCertificateRotation)))
	mux.Handle("POST /v1/sso/saml-providers/{providerID}/certificate-rotation/promote", s.requireRole("admin", http.HandlerFunc(s.promoteSAMLCertificateRotation)))
	mux.Handle("DELETE /v1/sso/saml-providers/{providerID}/certificate-rotation", s.requireRole("admin", http.HandlerFunc(s.cancelSAMLCertificateRotation)))
	mux.Handle("DELETE /v1/sso/saml-providers/{providerID}", s.requireRole("admin", http.HandlerFunc(s.deleteSAMLProvider)))
	mux.Handle("GET /v1/scim/tokens", s.requireRole("admin", http.HandlerFunc(s.listSCIMTokens)))
	mux.Handle("POST /v1/scim/tokens", s.requireRole("admin", http.HandlerFunc(s.createSCIMToken)))
	mux.Handle("DELETE /v1/scim/tokens/{tokenID}", s.requireRole("admin", http.HandlerFunc(s.revokeSCIMToken)))
	mux.HandleFunc("GET /scim/v2/ServiceProviderConfig", s.scimServiceProviderConfig)
	mux.HandleFunc("GET /scim/v2/Schemas", s.scimSchemas)
	mux.HandleFunc("GET /scim/v2/Schemas/{schemaID}", s.scimSchema)
	mux.HandleFunc("GET /scim/v2/ResourceTypes", s.scimResourceTypes)
	mux.HandleFunc("GET /scim/v2/ResourceTypes/{resourceTypeID}", s.scimResourceType)
	mux.HandleFunc("GET /scim/v2/Users", s.scimUsers)
	mux.HandleFunc("POST /scim/v2/Users", s.scimUsers)
	mux.HandleFunc("GET /scim/v2/Users/{userID}", s.scimUser)
	mux.HandleFunc("PUT /scim/v2/Users/{userID}", s.scimUser)
	mux.HandleFunc("PATCH /scim/v2/Users/{userID}", s.scimUser)
	mux.HandleFunc("DELETE /scim/v2/Users/{userID}", s.scimUser)
	mux.HandleFunc("GET /scim/v2/Groups", s.scimGroups)
	mux.HandleFunc("POST /scim/v2/Groups", s.scimGroups)
	mux.HandleFunc("GET /scim/v2/Groups/{groupID}", s.scimGroup)
	mux.HandleFunc("PUT /scim/v2/Groups/{groupID}", s.scimGroup)
	mux.HandleFunc("PATCH /scim/v2/Groups/{groupID}", s.scimGroup)
	mux.HandleFunc("DELETE /scim/v2/Groups/{groupID}", s.scimGroup)
	mux.Handle("GET /v1/projects", s.requireAuth(http.HandlerFunc(s.listProjects)))
	mux.Handle("GET /v1/environments", s.requireAuth(http.HandlerFunc(s.listOrganizationEnvironments)))
	mux.Handle("GET /v1/tags", s.requireAuth(http.HandlerFunc(s.listTags)))
	mux.Handle("POST /v1/tags", s.requireRole("admin", http.HandlerFunc(s.createTag)))
	mux.Handle("GET /v1/tags/{tagID}", s.requireAuth(http.HandlerFunc(s.getTag)))
	mux.Handle("PUT /v1/tags/{tagID}", s.requireRole("admin", http.HandlerFunc(s.updateTag)))
	mux.Handle("DELETE /v1/tags/{tagID}", s.requireRole("admin", http.HandlerFunc(s.deleteTag)))
	mux.Handle("GET /v1/networks", s.requireAuth(http.HandlerFunc(s.listManagedNetworks)))
	mux.Handle("POST /v1/networks", s.requireRole("admin", http.HandlerFunc(s.createManagedNetwork)))
	mux.Handle("GET /v1/networks/{networkID}", s.requireAuth(http.HandlerFunc(s.getManagedNetwork)))
	mux.Handle("POST /v1/networks/{networkID}/retry", s.requireRole("admin", http.HandlerFunc(s.retryManagedNetwork)))
	mux.Handle("DELETE /v1/networks/{networkID}", s.requireRole("admin", http.HandlerFunc(s.deleteManagedNetwork)))
	mux.Handle("POST /v1/projects", s.requireRole("developer", http.HandlerFunc(s.createProject)))
	mux.Handle("GET /v1/projects/{projectID}", s.requireResourceRole("viewer", "project", "projectID", http.HandlerFunc(s.getProject)))
	mux.Handle("GET /v1/projects/{projectID}/tags", s.requireResourceRole("viewer", "project", "projectID", http.HandlerFunc(s.listProjectTags)))
	mux.Handle("PUT /v1/projects/{projectID}/tags", s.requireResourceRole("developer", "project", "projectID", http.HandlerFunc(s.replaceProjectTags)))
	mux.Handle("DELETE /v1/projects/{projectID}", s.requireResourceRole("admin", "project", "projectID", http.HandlerFunc(s.deleteProject)))
	mux.Handle("GET /v1/projects/{projectID}/grants", s.requireRole("admin", http.HandlerFunc(s.listProjectGrants)))
	mux.Handle("PUT /v1/projects/{projectID}/grants/{userID}", s.requireRole("admin", http.HandlerFunc(s.putProjectGrant)))
	mux.Handle("DELETE /v1/projects/{projectID}/grants/{userID}", s.requireRole("admin", http.HandlerFunc(s.deleteProjectGrant)))
	mux.Handle("GET /v1/projects/{projectID}/policy", s.requireResourceRole("admin", "project", "projectID", http.HandlerFunc(s.getProjectPolicy)))
	mux.Handle("PUT /v1/projects/{projectID}/policy", s.requireResourceRole("admin", "project", "projectID", http.HandlerFunc(s.putProjectPolicy)))
	mux.Handle("GET /v1/environments/{environmentID}/grants", s.requireRole("admin", http.HandlerFunc(s.listEnvironmentGrants)))
	mux.Handle("PUT /v1/environments/{environmentID}/grants/{userID}", s.requireRole("admin", http.HandlerFunc(s.putEnvironmentGrant)))
	mux.Handle("DELETE /v1/environments/{environmentID}/grants/{userID}", s.requireRole("admin", http.HandlerFunc(s.deleteEnvironmentGrant)))
	mux.Handle("GET /v1/environments/{environmentID}/policy", s.requireResourceRole("admin", "environment", "environmentID", http.HandlerFunc(s.getEnvironmentPolicy)))
	mux.Handle("PUT /v1/environments/{environmentID}/policy", s.requireResourceRole("admin", "environment", "environmentID", http.HandlerFunc(s.putEnvironmentPolicy)))
	mux.Handle("POST /v1/projects/{projectID}/environments", s.requireResourceRole("developer", "project", "projectID", http.HandlerFunc(s.createEnvironment)))
	mux.Handle("GET /v1/projects/{projectID}/environments", s.requireResourceRole("viewer", "project", "projectID", http.HandlerFunc(s.listEnvironments)))
	mux.Handle("GET /v1/environments/{environmentID}", s.requireResourceRole("viewer", "environment", "environmentID", http.HandlerFunc(s.getEnvironment)))
	mux.Handle("DELETE /v1/environments/{environmentID}", s.requireResourceRole("admin", "environment", "environmentID", http.HandlerFunc(s.deleteEnvironment)))
	mux.Handle("POST /v1/environments/{environmentID}/services", s.requireResourceRole("developer", "environment", "environmentID", http.HandlerFunc(s.createService)))
	mux.Handle("GET /v1/environments/{environmentID}/services", s.requireResourceRole("viewer", "environment", "environmentID", http.HandlerFunc(s.listServices)))
	mux.Handle("GET /v1/database-engines", s.requireAuth(http.HandlerFunc(s.databaseEngines)))
	mux.Handle("POST /v1/environments/{environmentID}/databases", s.requireResourceRole("developer", "environment", "environmentID", http.HandlerFunc(s.createDatabase)))
	mux.Handle("GET /v1/environments/{environmentID}/databases", s.requireResourceRole("viewer", "environment", "environmentID", http.HandlerFunc(s.listDatabases)))
	mux.Handle("GET /v1/databases/{databaseID}", s.requireResourceRole("viewer", "database", "databaseID", http.HandlerFunc(s.getDatabase)))
	mux.Handle("POST /v1/databases/{databaseID}/driver-rebind", s.requireResourceRole("admin", "database", "databaseID", http.HandlerFunc(s.rebindDatabaseDriver)))
	mux.Handle("GET /v1/databases/{databaseID}/backups", s.requireResourceRole("viewer", "database", "databaseID", http.HandlerFunc(s.listDatabaseBackups)))
	mux.Handle("GET /v1/databases/{databaseID}/migrations", s.requireResourceRole("viewer", "database", "databaseID", http.HandlerFunc(s.listDatabaseMigrations)))
	mux.Handle("GET /v1/databases/{databaseID}/restores", s.requireResourceRole("viewer", "database", "databaseID", http.HandlerFunc(s.listDatabaseRestores)))
	mux.Handle("DELETE /v1/databases/{databaseID}", s.requireResourceRole("admin", "database", "databaseID", http.HandlerFunc(s.deleteDatabase)))
	mux.Handle("POST /v1/databases/{databaseID}/backups", s.requireResourceRole("developer", "database", "databaseID", http.HandlerFunc(s.createDatabaseBackup)))
	mux.Handle("GET /v1/backup-destinations", s.requireRole("developer", http.HandlerFunc(s.listBackupDestinations)))
	mux.Handle("POST /v1/backup-destinations", s.requireRole("admin", http.HandlerFunc(s.createBackupDestination)))
	mux.Handle("PUT /v1/backup-destinations/{destinationID}", s.requireRole("admin", http.HandlerFunc(s.updateBackupDestination)))
	mux.Handle("DELETE /v1/backup-destinations/{destinationID}", s.requireRole("admin", http.HandlerFunc(s.deleteBackupDestination)))
	mux.Handle("GET /v1/databases/{databaseID}/backup-policy", s.requireResourceRole("viewer", "database", "databaseID", http.HandlerFunc(s.getBackupPolicy)))
	mux.Handle("PUT /v1/databases/{databaseID}/backup-policy", s.requireResourceRole("admin", "database", "databaseID", http.HandlerFunc(s.putBackupPolicy)))
	mux.Handle("DELETE /v1/databases/{databaseID}/backup-policy", s.requireResourceRole("admin", "database", "databaseID", http.HandlerFunc(s.deleteBackupPolicy)))
	mux.Handle("GET /v1/database-backups/{backupID}", s.requireResourceRole("viewer", "backup", "backupID", http.HandlerFunc(s.getDatabaseBackup)))
	mux.Handle("POST /v1/database-backups/{backupID}/cancel", s.requireResourceRole("developer", "backup", "backupID", http.HandlerFunc(s.cancelDatabaseBackup)))
	mux.Handle("POST /v1/database-backups/{backupID}/restore", s.requireResourceRole("admin", "backup", "backupID", http.HandlerFunc(s.restoreDatabaseBackup)))
	mux.Handle("GET /v1/database-restores/{restoreID}", s.requireResourceRole("viewer", "restore", "restoreID", http.HandlerFunc(s.getDatabaseRestore)))
	mux.Handle("POST /v1/database-restores/{restoreID}/cancel", s.requireResourceRole("admin", "restore", "restoreID", http.HandlerFunc(s.cancelDatabaseRestore)))
	mux.Handle("GET /v1/database-migrations/{migrationID}", s.requireResourceRole("viewer", "migration", "migrationID", http.HandlerFunc(s.getDatabaseMigration)))
	mux.Handle("POST /v1/database-migrations/{migrationID}/cancel", s.requireResourceRole("admin", "migration", "migrationID", http.HandlerFunc(s.cancelDatabaseMigration)))
	mux.Handle("GET /v1/templates", s.requireAuth(http.HandlerFunc(s.listTemplates)))
	mux.Handle("GET /v1/template-repositories", s.requireRole("developer", http.HandlerFunc(s.listTemplateRepositories)))
	mux.Handle("POST /v1/template-repositories", s.requireRole("admin", http.HandlerFunc(s.createTemplateRepository)))
	mux.Handle("POST /v1/template-repositories/{repositoryID}/sync", s.requireRole("developer", http.HandlerFunc(s.syncTemplateRepository)))
	mux.Handle("POST /v1/template-repositories/{repositoryID}/webhook-secret", s.requireRole("admin", http.HandlerFunc(s.rotateTemplateRepositoryWebhookSecret)))
	mux.Handle("DELETE /v1/template-repositories/{repositoryID}/webhook-secret", s.requireRole("admin", http.HandlerFunc(s.disableTemplateRepositoryWebhook)))
	mux.Handle("PATCH /v1/template-repositories/{repositoryID}", s.requireRole("admin", http.HandlerFunc(s.updateTemplateRepositorySettings)))
	mux.Handle("DELETE /v1/template-repositories/{repositoryID}", s.requireRole("admin", http.HandlerFunc(s.deleteTemplateRepository)))
	mux.Handle("POST /v1/templates/import/dokploy", s.requireRole("developer", http.HandlerFunc(s.importDokployTemplate)))
	mux.Handle("POST /v1/templates/{templateID}/preview", s.requireAuth(http.HandlerFunc(s.previewTemplate)))
	mux.Handle("POST /v1/templates/{templateID}/instantiate", s.requireAuth(http.HandlerFunc(s.instantiateTemplate)))
	mux.Handle("GET /v1/services/{serviceID}", s.requireResourceRole("viewer", "service", "serviceID", http.HandlerFunc(s.getService)))
	mux.Handle("GET /v1/services/{serviceID}/variables", s.requireResourceRole("viewer", "service", "serviceID", http.HandlerFunc(s.getServiceVariables)))
	mux.Handle("PUT /v1/services/{serviceID}/variables", s.requireResourceRole("developer", "service", "serviceID", http.HandlerFunc(s.putServiceVariables)))
	mux.Handle("DELETE /v1/services/{serviceID}/variables/{name}", s.requireResourceRole("developer", "service", "serviceID", http.HandlerFunc(s.deleteServiceVariable)))
	mux.Handle("GET /v1/services/{serviceID}/tags", s.requireResourceRole("viewer", "service", "serviceID", http.HandlerFunc(s.listServiceTags)))
	mux.Handle("PUT /v1/services/{serviceID}/tags", s.requireResourceRole("developer", "service", "serviceID", http.HandlerFunc(s.replaceServiceTags)))
	mux.Handle("GET /v1/services/{serviceID}/networks", s.requireResourceRole("viewer", "service", "serviceID", http.HandlerFunc(s.listServiceNetworks)))
	mux.Handle("PUT /v1/services/{serviceID}/networks", s.requireResourceRole("developer", "service", "serviceID", http.HandlerFunc(s.replaceServiceNetworks)))
	mux.Handle("GET /v1/services/{serviceID}/template-versions", s.requireResourceRole("viewer", "service", "serviceID", http.HandlerFunc(s.listTemplateVersions)))
	mux.Handle("POST /v1/services/{serviceID}/template-upgrades", s.requireResourceRole("developer", "service", "serviceID", http.HandlerFunc(s.upgradeTemplateService)))
	mux.Handle("DELETE /v1/services/{serviceID}", s.requireResourceRole("admin", "service", "serviceID", http.HandlerFunc(s.deleteService)))
	mux.Handle("PATCH /v1/services/{serviceID}", s.requireResourceRole("developer", "service", "serviceID", http.HandlerFunc(s.updateService)))
	mux.Handle("PUT /v1/services/{serviceID}/environment", s.requireResourceRole("developer", "service", "serviceID", http.HandlerFunc(s.moveService)))
	mux.Handle("POST /v1/services/{serviceID}/storage-node-rebind", s.requireResourceRole("admin", "service", "serviceID", http.HandlerFunc(s.rebindServiceStorageNode)))
	mux.Handle("PUT /v1/services/{serviceID}/source", s.requireResourceRole("developer", "service", "serviceID", http.HandlerFunc(s.upsertSource)))
	mux.Handle("PUT /v1/services/{serviceID}/artifact-source", s.requireResourceRole("developer", "service", "serviceID", http.HandlerFunc(s.upsertArtifactSource)))
	mux.Handle("POST /v1/services/{serviceID}/routes", s.requireResourceRole("developer", "service", "serviceID", http.HandlerFunc(s.addRoute)))
	mux.Handle("GET /v1/routes/{routeID}", s.requireResourceRole("viewer", "route", "routeID", http.HandlerFunc(s.getRoute)))
	mux.Handle("PUT /v1/routes/{routeID}", s.requireResourceRole("developer", "route", "routeID", http.HandlerFunc(s.updateRoute)))
	mux.Handle("DELETE /v1/routes/{routeID}", s.requireResourceRole("developer", "route", "routeID", http.HandlerFunc(s.deleteRoute)))
	mux.Handle("GET /v1/services/{serviceID}/basic-auth-users", s.requireResourceRole("viewer", "service", "serviceID", http.HandlerFunc(s.listRouteBasicAuthUsers)))
	mux.Handle("POST /v1/services/{serviceID}/basic-auth-users", s.requireResourceRole("developer", "service", "serviceID", http.HandlerFunc(s.createRouteBasicAuthUser)))
	mux.Handle("PUT /v1/services/{serviceID}/basic-auth-users/{userID}", s.requireResourceRole("developer", "service", "serviceID", http.HandlerFunc(s.updateRouteBasicAuthUser)))
	mux.Handle("DELETE /v1/services/{serviceID}/basic-auth-users/{userID}", s.requireResourceRole("developer", "service", "serviceID", http.HandlerFunc(s.deleteRouteBasicAuthUser)))
	mux.Handle("POST /v1/services/{serviceID}/deployments", s.requireResourceRole("developer", "service", "serviceID", http.HandlerFunc(s.deployService)))
	mux.Handle("POST /v1/services/{serviceID}/stop", s.requireResourceRole("developer", "service", "serviceID", http.HandlerFunc(s.stopService)))
	mux.Handle("POST /v1/services/{serviceID}/start", s.requireResourceRole("developer", "service", "serviceID", http.HandlerFunc(s.startService)))
	mux.Handle("GET /v1/services/{serviceID}/schedules", s.requireResourceRole("viewer", "service", "serviceID", http.HandlerFunc(s.listServiceSchedules)))
	mux.Handle("POST /v1/services/{serviceID}/schedules", s.requireResourceRole("developer", "service", "serviceID", http.HandlerFunc(s.createServiceSchedule)))
	mux.Handle("GET /v1/services/{serviceID}/schedules/{scheduleID}", s.requireResourceRole("viewer", "service", "serviceID", http.HandlerFunc(s.getServiceSchedule)))
	mux.Handle("PUT /v1/services/{serviceID}/schedules/{scheduleID}", s.requireResourceRole("developer", "service", "serviceID", http.HandlerFunc(s.updateServiceSchedule)))
	mux.Handle("DELETE /v1/services/{serviceID}/schedules/{scheduleID}", s.requireResourceRole("developer", "service", "serviceID", http.HandlerFunc(s.deleteServiceSchedule)))
	mux.Handle("POST /v1/services/{serviceID}/schedules/{scheduleID}/executions", s.requireResourceRole("developer", "service", "serviceID", http.HandlerFunc(s.runServiceSchedule)))
	mux.Handle("GET /v1/services/{serviceID}/schedule-executions", s.requireResourceRole("viewer", "service", "serviceID", http.HandlerFunc(s.listServiceScheduleExecutions)))
	mux.Handle("POST /v1/services/{serviceID}/schedule-executions/{executionID}/cancel", s.requireResourceRole("developer", "service", "serviceID", http.HandlerFunc(s.cancelServiceScheduleExecution)))
	mux.Handle("GET /v1/services/{serviceID}/deployments", s.requireResourceRole("viewer", "service", "serviceID", http.HandlerFunc(s.listDeployments)))
	mux.Handle("GET /v1/services/{serviceID}/logs", s.requireResourceRole("viewer", "service", "serviceID", http.HandlerFunc(s.serviceLogs)))
	mux.Handle("GET /v1/services/{serviceID}/volumes", s.requireResourceRole("viewer", "service", "serviceID", http.HandlerFunc(s.listServiceVolumes)))
	mux.Handle("GET /v1/services/{serviceID}/volume-backup-policies", s.requireResourceRole("viewer", "service", "serviceID", http.HandlerFunc(s.listVolumeBackupPolicies)))
	mux.Handle("PUT /v1/services/{serviceID}/volume-backup-policies/{volumeName}", s.requireResourceRole("admin", "service", "serviceID", http.HandlerFunc(s.putVolumeBackupPolicy)))
	mux.Handle("DELETE /v1/services/{serviceID}/volume-backup-policies/{volumeName}", s.requireResourceRole("admin", "service", "serviceID", http.HandlerFunc(s.deleteVolumeBackupPolicy)))
	mux.Handle("GET /v1/services/{serviceID}/volume-backups", s.requireResourceRole("viewer", "service", "serviceID", http.HandlerFunc(s.listVolumeBackups)))
	mux.Handle("POST /v1/services/{serviceID}/volume-backups/{volumeName}", s.requireResourceRole("developer", "service", "serviceID", http.HandlerFunc(s.createVolumeBackup)))
	mux.Handle("GET /v1/services/{serviceID}/volume-restores", s.requireResourceRole("viewer", "service", "serviceID", http.HandlerFunc(s.listVolumeRestores)))
	mux.Handle("POST /v1/services/{serviceID}/rollback", s.requireResourceRole("developer", "service", "serviceID", http.HandlerFunc(s.rollbackService)))
	mux.Handle("GET /v1/services/{serviceID}/deploy-tokens", s.requireResourceRole("developer", "service", "serviceID", http.HandlerFunc(s.listDeployTokens)))
	mux.Handle("POST /v1/services/{serviceID}/deploy-tokens", s.requireResourceRole("developer", "service", "serviceID", http.HandlerFunc(s.createDeployToken)))
	mux.Handle("DELETE /v1/services/{serviceID}/deploy-tokens/{tokenID}", s.requireResourceRole("developer", "service", "serviceID", http.HandlerFunc(s.revokeDeployToken)))
	mux.Handle("GET /v1/services/{serviceID}/webhooks", s.requireResourceRole("developer", "service", "serviceID", http.HandlerFunc(s.listWebhookIntegrations)))
	mux.Handle("POST /v1/services/{serviceID}/webhooks", s.requireResourceRole("developer", "service", "serviceID", http.HandlerFunc(s.createWebhookIntegration)))
	mux.Handle("DELETE /v1/webhooks/{integrationID}", s.requireResourceRole("developer", "webhook", "integrationID", http.HandlerFunc(s.deleteWebhookIntegration)))
	mux.Handle("GET /v1/deployments/{deploymentID}", s.requireResourceRole("viewer", "deployment", "deploymentID", http.HandlerFunc(s.getDeployment)))
	mux.Handle("POST /v1/deployments/{deploymentID}/cancel", s.requireResourceRole("developer", "deployment", "deploymentID", http.HandlerFunc(s.cancelDeployment)))
	mux.Handle("GET /v1/volume-backups/{backupID}", s.requireResourceRole("viewer", "volume_backup", "backupID", http.HandlerFunc(s.getVolumeBackup)))
	mux.Handle("POST /v1/volume-backups/{backupID}/cancel", s.requireResourceRole("developer", "volume_backup", "backupID", http.HandlerFunc(s.cancelVolumeBackup)))
	mux.Handle("POST /v1/volume-backups/{backupID}/restore", s.requireResourceRole("admin", "volume_backup", "backupID", http.HandlerFunc(s.restoreVolumeBackup)))
	mux.Handle("GET /v1/volume-restores/{restoreID}", s.requireResourceRole("viewer", "volume_restore", "restoreID", http.HandlerFunc(s.getVolumeRestore)))
	mux.Handle("POST /v1/volume-restores/{restoreID}/cancel", s.requireResourceRole("admin", "volume_restore", "restoreID", http.HandlerFunc(s.cancelVolumeRestore)))
	mux.Handle("GET /", webui.Handler())
	instrumented := otelhttp.NewHandler(s.middleware(mux), "dockyard.http")
	return s.requestIDMiddleware(s.trustedProxyMiddleware(instrumented))
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		if strings.HasPrefix(r.URL.Path, "/v1/") || strings.HasPrefix(r.URL.Path, "/scim/") || r.URL.Path == "/metrics" || r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			w.Header().Set("Cache-Control", "no-store")
		}
		forwardedHTTPS, _ := r.Context().Value(forwardedHTTPSKey).(bool)
		if r.TLS != nil || forwardedHTTPS {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		defer func() {
			if recovered := recover(); recovered != nil {
				recorder.status = http.StatusInternalServerError
				s.logger().ErrorContext(r.Context(), "request panic", "panic_type", fmt.Sprintf("%T", recovered), "request_id", requestID(r))
				writeError(recorder, http.StatusInternalServerError, "internal_error", "internal server error")
			}
			route := r.Pattern
			s.Metrics.ObserveHTTP(r.Method, route, recorder.status, time.Since(started))
			attrs := []any{"request_id", requestID(r), "method", r.Method, "route", route, "status", recorder.status, "duration_ms", time.Since(started).Milliseconds()}
			if span := trace.SpanContextFromContext(r.Context()); span.IsValid() {
				attrs = append(attrs, "trace_id", span.TraceID().String())
			}
			s.logger().InfoContext(r.Context(), "http request", attrs...)
		}()
		next.ServeHTTP(recorder, r)
	})
}

func (s *Server) trustedProxyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer := remoteIPAddress(r.RemoteAddr)
		if peer == nil || !s.trustedProxy(peer) {
			next.ServeHTTP(w, r)
			return
		}
		ctx := r.Context()
		protoParts := strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")
		if len(protoParts) > 0 && strings.EqualFold(strings.TrimSpace(protoParts[len(protoParts)-1]), "https") {
			ctx = context.WithValue(ctx, forwardedHTTPSKey, true)
		}
		forwarded := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
		if len(forwarded) <= 32 && !(len(forwarded) == 1 && strings.TrimSpace(forwarded[0]) == "") {
			addresses := make([]net.IP, 0, len(forwarded))
			for _, raw := range forwarded {
				address := net.ParseIP(strings.TrimSpace(raw))
				if address == nil {
					addresses = nil
					break
				}
				addresses = append(addresses, address)
			}
			if len(addresses) > 0 {
				client := addresses[0]
				for i := len(addresses) - 1; i >= 0; i-- {
					if !s.trustedProxy(addresses[i]) {
						client = addresses[i]
						break
					}
				}
				r = r.Clone(ctx)
				r.RemoteAddr = client.String()
				next.ServeHTTP(w, r)
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) trustedProxy(address net.IP) bool {
	for _, network := range s.TrustedProxyCIDRs {
		if network != nil && network.Contains(address) {
			return true
		}
	}
	return false
}

func remoteIPAddress(remoteAddress string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err == nil {
		return net.ParseIP(host)
	}
	return net.ParseIP(remoteAddress)
}

func (s *Server) requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if !validRequestID(id) {
			id = uuid.NewString()
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, id)))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusRecorder) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.status = status
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func validRequestID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

func requestID(r *http.Request) string {
	id, _ := r.Context().Value(requestIDKey).(string)
	return id
}

func (s *Server) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if !ok {
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
		if p.Role == "auditor" && !strings.HasPrefix(r.URL.Path, "/v1/ai/") {
			writeError(w, 403, "auditor_scope", "auditor identities may only use AI audit endpoints")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey, p)))
	})
}

func (s *Server) requireMetricsAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if !ok || len(s.MetricsTokenHash) != sha256.Size || subtle.ConstantTimeCompare(cryptox.Digest(token), s.MetricsTokenHash) != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized", "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bearerToken(r *http.Request) (string, bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", false
	}
	return parts[1], true
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

func (s *Server) requireResourceRole(minimum, resourceType, pathParameter string, next http.Handler) http.Handler {
	return s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue(pathParameter))
		if err != nil {
			writeError(w, 400, "invalid_id", "invalid resource id")
			return
		}
		role, err := s.Store.EffectiveResourceRole(r.Context(), principal(r), resourceType, id)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		if roleRank(role) < roleRank(minimum) {
			writeError(w, 403, "forbidden", "insufficient resource role")
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
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	check := s.ReadinessCheck
	if check == nil {
		check = func(ctx context.Context) error {
			if s.Store == nil || s.Store.Pool == nil {
				return errors.New("database is not configured")
			}
			return s.Store.Pool.Ping(ctx)
		}
	}
	if err := check(ctx); err != nil {
		s.logger().WarnContext(r.Context(), "readiness check failed", "dependency", "database", "error_type", fmt.Sprintf("%T", err))
		writeError(w, http.StatusServiceUnavailable, "database_unavailable", "database is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	s.Metrics.Handler(s.Store.Pool).ServeHTTP(w, r)
}

func (s *Server) getOrganizationPolicy(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	s.getPolicy(w, r, "organization", p.OrganizationID)
}

func (s *Server) putOrganizationPolicy(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	s.putPolicy(w, r, "organization", p.OrganizationID)
}

func (s *Server) getProjectPolicy(w http.ResponseWriter, r *http.Request) {
	s.getPathPolicy(w, r, "project", "projectID", false)
}

func (s *Server) putProjectPolicy(w http.ResponseWriter, r *http.Request) {
	s.getPathPolicy(w, r, "project", "projectID", true)
}

func (s *Server) getEnvironmentPolicy(w http.ResponseWriter, r *http.Request) {
	s.getPathPolicy(w, r, "environment", "environmentID", false)
}

func (s *Server) putEnvironmentPolicy(w http.ResponseWriter, r *http.Request) {
	s.getPathPolicy(w, r, "environment", "environmentID", true)
}

func (s *Server) getPathPolicy(w http.ResponseWriter, r *http.Request, scopeType, parameter string, put bool) {
	id, err := uuid.Parse(r.PathValue(parameter))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid policy scope id")
		return
	}
	if put {
		s.putPolicy(w, r, scopeType, id)
		return
	}
	s.getPolicy(w, r, scopeType, id)
}

func (s *Server) getPolicy(w http.ResponseWriter, r *http.Request, scopeType string, scopeID uuid.UUID) {
	item, err := s.Store.GetResourcePolicy(r.Context(), principal(r).OrganizationID, scopeType, scopeID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, item)
}

func (s *Server) putPolicy(w http.ResponseWriter, r *http.Request, scopeType string, scopeID uuid.UUID) {
	var input struct {
		Maintenance       bool   `json:"maintenance"`
		MaintenanceReason string `json:"maintenanceReason"`
		MaxProjects       *int   `json:"maxProjects"`
		MaxEnvironments   *int   `json:"maxEnvironments"`
		MaxServices       *int   `json:"maxServices"`
		MaxDatabases      *int   `json:"maxDatabases"`
	}
	if !decode(w, r, &input) {
		return
	}
	if scopeType != "organization" && input.MaxProjects != nil {
		writeError(w, 400, "invalid_policy", "maxProjects is only valid at organization scope")
		return
	}
	if scopeType == "environment" && input.MaxEnvironments != nil {
		writeError(w, 400, "invalid_policy", "maxEnvironments is not valid at environment scope")
		return
	}
	for _, limit := range []*int{input.MaxProjects, input.MaxEnvironments, input.MaxServices, input.MaxDatabases} {
		if limit != nil && (*limit < 1 || *limit > 1000000) {
			writeError(w, 400, "invalid_policy", "quota values must be between 1 and 1000000")
			return
		}
	}
	input.MaintenanceReason = strings.TrimSpace(input.MaintenanceReason)
	if len(input.MaintenanceReason) > 500 {
		writeError(w, 400, "invalid_policy", "maintenanceReason is too long")
		return
	}
	p := principal(r)
	item, err := s.Store.PutResourcePolicyWithAudit(r.Context(), p, store.ResourcePolicy{ScopeType: scopeType, ScopeID: scopeID, Maintenance: input.Maintenance, MaintenanceReason: input.MaintenanceReason, MaxProjects: input.MaxProjects, MaxEnvironments: input.MaxEnvironments, MaxServices: input.MaxServices, MaxDatabases: input.MaxDatabases}, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, item)
}

func (s *Server) auditEvents(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	beforeID, limit, err := auditPage(r, false)
	if err != nil {
		writeError(w, 400, "invalid_cursor", err.Error())
		return
	}
	items, err := s.Store.ListAuditEvents(r.Context(), p.OrganizationID, beforeID, limit, false)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) swarmNodes(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	items, err := s.Swarm.Nodes(ctx)
	if err != nil {
		s.writeInternalError(w, r, 502, "swarm_unavailable", "Swarm node inventory is unavailable", err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) bootstrap(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var in struct {
		Email        string `json:"email"`
		Password     string `json:"password"`
		Organization string `json:"organization"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !s.allowAuthenticationAttempt(w, r, "bootstrap", cryptox.Digest("instance"), 5) {
		return
	}
	email, _, validEmail := canonicalEmail(in.Email)
	if !validEmail {
		writeError(w, 400, "invalid_email", "valid email required")
		return
	}
	in.Email = email
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
	p, err := s.Store.BootstrapWithAudit(r.Context(), in.Email, hash, in.Organization, slug, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	token, err := s.newSession(r, p.UserID, nil, "local", hash, map[string]any{"bootstrap": true})
	if err != nil {
		s.writeInternalError(w, r, 500, "session_failed", "session could not be created", err)
		return
	}
	writeJSON(w, 201, map[string]any{"token": token, "principal": p})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var in struct {
		Email        string `json:"email"`
		Password     string `json:"password"`
		TOTPCode     string `json:"totpCode"`
		RecoveryCode string `json:"recoveryCode"`
	}
	if !decode(w, r, &in) {
		return
	}
	if len(in.TOTPCode) > maxMFAProofBytes || len(in.RecoveryCode) > maxMFAProofBytes {
		writeError(w, http.StatusBadRequest, "invalid_mfa", store.ErrInvalidMFAProof.Error())
		return
	}
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	if !s.allowAuthenticationAttempt(w, r, "login-global", cryptox.Digest("instance"), 300) {
		return
	}
	credential, err := s.Store.PasswordLoginCredential(r.Context(), in.Email)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			writeStoreError(w, err)
			return
		}
		time.Sleep(150 * time.Millisecond)
		writeError(w, 401, "invalid_credentials", "email or password is incorrect")
		return
	}
	if !s.allowAuthenticationAttempt(w, r, "login", cryptox.Digest(in.Email), 10) {
		return
	}
	if !auth.VerifyPassword(credential.PasswordHash, in.Password) {
		time.Sleep(150 * time.Millisecond)
		writeError(w, 401, "invalid_credentials", "email or password is incorrect")
		return
	}
	allowed, err := s.Store.LocalLoginAllowed(r.Context(), credential.UserID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if !allowed {
		writeError(w, 403, "sso_required", "this account must sign in through its identity provider")
		return
	}
	var token string
	if credential.EncryptedTOTPSecret != "" {
		if in.TOTPCode == "" && in.RecoveryCode == "" {
			writeError(w, http.StatusUnauthorized, "mfa_required", store.ErrMFARequired.Error())
			return
		}
		counter, recoveryDigest, valid, proofErr := s.verifyMFAProof(credential.UserID.String(), credential.EncryptedTOTPSecret, in.TOTPCode, in.RecoveryCode)
		if proofErr != nil {
			s.writeInternalError(w, r, 500, "mfa_secret_invalid", "stored MFA material could not be authenticated", proofErr)
			return
		}
		if !valid {
			writeError(w, http.StatusUnauthorized, "invalid_mfa", store.ErrInvalidMFAProof.Error())
			return
		}
		token, err = s.newMFASession(r, credential, counter, recoveryDigest)
	} else {
		token, err = s.newSession(r, credential.UserID, nil, "local", credential.PasswordHash, nil)
	}
	if err != nil {
		if errors.Is(err, store.ErrAuthenticationStateChanged) {
			writeError(w, http.StatusUnauthorized, "invalid_credentials", "email or password is incorrect")
			return
		}
		if errors.Is(err, store.ErrInvalidMFAProof) {
			writeError(w, http.StatusUnauthorized, "invalid_mfa", store.ErrInvalidMFAProof.Error())
			return
		}
		s.writeInternalError(w, r, 500, "session_failed", "session could not be created", err)
		return
	}
	writeJSON(w, 200, map[string]string{"token": token})
}

func (s *Server) allowAuthenticationAttempt(w http.ResponseWriter, r *http.Request, bucket string, keyHash []byte, limit int) bool {
	allowed, retryAfter, err := s.Store.ConsumeRateLimit(r.Context(), bucket, keyHash, limit, time.Minute)
	if err != nil {
		writeStoreError(w, err)
		return false
	}
	if !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many authentication attempts")
		return false
	}
	return true
}

func (s *Server) newSession(r *http.Request, userID uuid.UUID, organizationID *uuid.UUID, method, expectedPasswordHash string, metadata any) (string, error) {
	token, err := auth.NewToken()
	if err != nil {
		return "", err
	}
	ipAddress := r.RemoteAddr
	if host, _, splitErr := net.SplitHostPort(r.RemoteAddr); splitErr == nil {
		ipAddress = host
	}
	if _, err = s.Store.CreateSessionWithAudit(r.Context(), userID, organizationID, cryptox.Digest(token), time.Now().Add(s.SessionTTL), method, expectedPasswordHash, truncateText(r.UserAgent(), 512), truncateText(ipAddress, 128), r.RemoteAddr, metadata); err != nil {
		return "", err
	}
	return token, nil
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if p.ServiceAccountID != nil {
		writeError(w, http.StatusForbidden, "forbidden", "service accounts do not have interactive sessions")
		return
	}
	if err := s.Store.LogoutSessionWithAudit(r.Context(), p, r.RemoteAddr); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusUnauthorized, "unauthorized", "session is no longer active")
			return
		}
		s.writeInternalError(w, r, http.StatusInternalServerError, "logout_failed", "session could not be revoked", err)
		return
	}
	w.WriteHeader(204)
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	p := principal(r)
	if p.ServiceAccountID != nil {
		writeError(w, http.StatusForbidden, "local_session_required", store.ErrLocalSessionRequired.Error())
		return
	}
	var in struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !s.allowAuthenticationAttempt(w, r, "password-change", cryptox.Digest(p.UserID.String()), 5) {
		return
	}
	if in.CurrentPassword == in.NewPassword {
		writeError(w, http.StatusBadRequest, "password_reused", "new password must differ from the current password")
		return
	}
	newHash, err := auth.HashPassword(in.NewPassword)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_password", err.Error())
		return
	}
	revoked, err := s.Store.ChangeLocalPassword(r.Context(), p, in.CurrentPassword, newHash, r.RemoteAddr)
	if errors.Is(err, store.ErrInvalidCurrentPassword) {
		writeError(w, http.StatusUnauthorized, "invalid_current_password", store.ErrInvalidCurrentPassword.Error())
		return
	}
	if errors.Is(err, store.ErrLocalSessionRequired) {
		writeError(w, http.StatusForbidden, "local_session_required", store.ErrLocalSessionRequired.Error())
		return
	}
	if err != nil {
		s.writeInternalError(w, r, http.StatusInternalServerError, "password_change_failed", "password could not be changed", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"revoked": revoked})
}
func (s *Server) me(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, principal(r)) }

func (s *Server) getEffectiveRole(w http.ResponseWriter, r *http.Request) {
	resourceType := strings.TrimSpace(r.URL.Query().Get("resourceType"))
	validResourceTypes := map[string]bool{"project": true, "environment": true, "service": true, "database": true, "deployment": true, "backup": true, "restore": true, "migration": true, "webhook": true, "route": true, "volume_backup": true, "volume_restore": true}
	if !validResourceTypes[resourceType] {
		writeError(w, http.StatusBadRequest, "invalid_resource_type", "invalid resource type")
		return
	}
	resourceID, err := uuid.Parse(r.URL.Query().Get("resourceId"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid resource id")
		return
	}
	role, err := s.Store.EffectiveResourceRole(r.Context(), principal(r), resourceType, resourceID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"role": role})
}

func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if p.ServiceAccountID != nil {
		writeError(w, 403, "forbidden", "service accounts do not have interactive sessions")
		return
	}
	items, err := s.Store.ListSessions(r.Context(), p.UserID, p.SessionID, p.SessionOrganizationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) revokeSession(w http.ResponseWriter, r *http.Request) {
	if principal(r).ServiceAccountID != nil {
		writeError(w, 403, "forbidden", "service accounts do not have interactive sessions")
		return
	}
	id, err := uuid.Parse(r.PathValue("sessionID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid session id")
		return
	}
	p := principal(r)
	if err = s.Store.RevokeSessionWithAudit(r.Context(), p, id, r.RemoteAddr); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) revokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if p.ServiceAccountID != nil {
		writeError(w, 403, "forbidden", "service accounts do not have interactive sessions")
		return
	}
	count, err := s.Store.RevokeOtherSessionsWithAudit(r.Context(), p, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, map[string]int64{"revoked": count})
}

func (s *Server) getAuthSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := s.Store.GetOrganizationAuthSettings(r.Context(), principal(r).OrganizationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, settings)
}

func (s *Server) putAuthSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RequireSSO bool `json:"requireSso"`
	}
	if !decode(w, r, &in) {
		return
	}
	p := principal(r)
	settings, err := s.Store.SetOrganizationAuthSettingsWithAudit(r.Context(), p, in.RequireSSO, r.RemoteAddr)
	if errors.Is(err, store.ErrSSOProviderRequired) {
		writeError(w, 409, "sso_provider_required", err.Error())
		return
	}
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, settings)
}

func truncateText(value string, limit int) string {
	if len(value) > limit {
		return value[:limit]
	}
	return value
}

func (s *Server) listProjects(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	items, err := s.Store.ListProjects(r.Context(), p.OrganizationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
func (s *Server) getProject(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("projectID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid project id")
		return
	}
	item, err := s.Store.GetProject(r.Context(), principal(r).OrganizationID, id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, item)
}
func (s *Server) deleteProject(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("projectID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid project id")
		return
	}
	p := principal(r)
	if err = s.Store.DeleteProjectWithAudit(r.Context(), p, id, r.RemoteAddr); err != nil {
		if errors.Is(err, store.ErrBusy) {
			writeError(w, http.StatusConflict, "project_busy", "cancel or wait for active deployments or an existing deletion")
			return
		}
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "deletion_queued"})
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
	item, err := s.Store.CreateProjectWithAudit(r.Context(), p, in.Name, in.Slug, in.Description, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 201, item)
}
func (s *Server) createEnvironment(w http.ResponseWriter, r *http.Request) {
	projectID, err := uuid.Parse(r.PathValue("projectID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid project id")
		return
	}
	var in struct {
		Name               string            `json:"name"`
		Slug               string            `json:"slug"`
		ClusterID          *uuid.UUID        `json:"clusterId"`
		PlacementSelector  map[string]string `json:"placementSelector"`
		MinimumNodes       int               `json:"minimumNodes"`
		MinimumNanoCPUs    int64             `json:"minimumNanoCpus"`
		MinimumMemoryBytes int64             `json:"minimumMemoryBytes"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Slug == "" {
		in.Slug = slugify(in.Name)
	}
	if !slugPattern.MatchString(in.Slug) || len(in.PlacementSelector) > 32 || in.MinimumNodes < 0 || in.MinimumNodes > 10_000 || in.MinimumNanoCPUs < 0 || in.MinimumNanoCPUs > 1_000_000_000_000 || in.MinimumMemoryBytes < 0 || in.MinimumMemoryBytes > 1_125_899_906_842_624 {
		writeError(w, 400, "invalid_environment", "valid slug, at most 32 placement labels, minimumNodes between 0 and 10000, minimumNanoCpus up to 1000000000000, and minimumMemoryBytes up to 1125899906842624 are required")
		return
	}
	for key, value := range in.PlacementSelector {
		if strings.TrimSpace(key) == "" || len(key) > 128 || len(value) > 256 {
			writeError(w, 400, "invalid_environment", "placement label keys and values exceed limits")
			return
		}
	}
	p := principal(r)
	item, err := s.Store.CreateEnvironmentWithPlacementAndAudit(r.Context(), p, projectID, in.Name, in.Slug, in.ClusterID, in.PlacementSelector, in.MinimumNodes, in.MinimumNanoCPUs, in.MinimumMemoryBytes, r.RemoteAddr)
	if err != nil {
		if errors.Is(err, store.ErrNoCapacity) {
			writeError(w, http.StatusConflict, "no_cluster_capacity", err.Error())
			return
		}
		writeStoreError(w, err)
		return
	}
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

func (s *Server) listOrganizationEnvironments(w http.ResponseWriter, r *http.Request) {
	items, err := s.Store.ListOrganizationEnvironments(r.Context(), principal(r).OrganizationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) getEnvironment(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("environmentID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid environment id")
		return
	}
	item, err := s.Store.GetEnvironment(r.Context(), principal(r).OrganizationID, id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, item)
}

func (s *Server) deleteEnvironment(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("environmentID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid environment id")
		return
	}
	p := principal(r)
	if err = s.Store.DeleteEnvironmentWithAudit(r.Context(), p, id, r.RemoteAddr); err != nil {
		if errors.Is(err, store.ErrBusy) {
			writeError(w, http.StatusConflict, "environment_busy", "cancel or wait for active deployments or an existing deletion")
			return
		}
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "deletion_queued"})
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
	if err = validateServiceVariables(in.Environment); err != nil {
		writeError(w, 400, "invalid_variables", err.Error())
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
	id := uuid.New()
	encrypted := ""
	if len(in.Environment) > 0 {
		plain, _ := json.Marshal(in.Environment)
		encrypted, err = s.Box.Encrypt(plain, composeEnvironmentContext(id))
		if err != nil {
			s.writeInternalError(w, r, 500, "encryption_failed", "service environment could not be encrypted", err)
			return
		}
	}
	p := principal(r)
	item, err := s.Store.CreateComposeServiceWithAudit(r.Context(), p, store.ComposeService{ID: id, EnvironmentID: environmentID, Name: in.Name, Slug: in.Slug, StackName: "dy-" + in.Slug + "-" + strings.Split(id.String(), "-")[0], ComposeYAML: in.ComposeYAML, EncryptedEnv: encrypted}, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
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
	engines := s.Databases.Engines()
	items := make([]string, 0, len(engines))
	backupCapable := []string{}
	for _, engine := range engines {
		items = append(items, engine.Name)
		if engine.BackupCapable {
			backupCapable = append(backupCapable, engine.Name)
		}
	}
	writeJSON(w, 200, map[string]any{"items": items, "backupCapable": backupCapable, "engines": engines})
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
	driver, ok := s.Databases.Engine(in.Engine)
	if !ok {
		writeError(w, 400, "invalid_database", "unsupported database engine")
		return
	}
	rendered, err := s.Databases.Render(in.Engine, database.Request{Name: in.Slug, Version: in.Version, Config: in.Config})
	if err != nil {
		writeError(w, 400, "invalid_database", err.Error())
		return
	}
	if _, err = s.Compiler.Compile(rendered.ComposeYAML, nil); err != nil {
		writeError(w, 400, "invalid_database", "database driver returned an invalid compose document")
		return
	}
	serviceID, databaseID := uuid.New(), uuid.New()
	envJSON, _ := json.Marshal(rendered.Environment)
	encryptedEnv, err := s.Box.Encrypt(envJSON, composeEnvironmentContext(serviceID))
	if err != nil {
		s.writeInternalError(w, r, 500, "encryption_failed", "database environment could not be encrypted", err)
		return
	}
	credentialJSON, _ := json.Marshal(rendered.Credentials)
	encryptedCredentials, err := s.Box.Encrypt(credentialJSON, cryptox.ResourceContext("database-credentials", databaseID.String()))
	if err != nil {
		s.writeInternalError(w, r, 500, "encryption_failed", "database credentials could not be encrypted", err)
		return
	}
	p := principal(r)
	shortID := strings.Split(serviceID.String(), "-")[0]
	stackName := "db-" + in.Slug + "-" + shortID
	instance, err := s.Store.CreateDatabaseWithAudit(r.Context(), p, store.DatabaseInstance{ID: databaseID, EnvironmentID: environmentID, Name: in.Name, Slug: in.Slug, Engine: in.Engine, Version: rendered.Version, DriverSource: driver.Source, DriverDigest: driver.ArtifactDigest, Config: database.StoredConfig(in.Config)}, store.ComposeService{ID: serviceID, Name: in.Name, Slug: "db-" + in.Slug, StackName: stackName, ComposeYAML: rendered.ComposeYAML, EncryptedEnv: encryptedEnv}, encryptedCredentials, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 201, map[string]any{"database": instance, "credentials": rendered.Credentials, "internalUrl": rendered.InternalURL})
}

func (s *Server) listDatabases(w http.ResponseWriter, r *http.Request) {
	environmentID, err := uuid.Parse(r.PathValue("environmentID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid environment id")
		return
	}
	items, err := s.Store.ListDatabases(r.Context(), principal(r).OrganizationID, environmentID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) getDatabase(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("databaseID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid database id")
		return
	}
	item, err := s.Store.GetDatabase(r.Context(), principal(r).OrganizationID, id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, item)
}

func (s *Server) rebindDatabaseDriver(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("databaseID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid database id")
		return
	}
	var in struct {
		Confirm string `json:"confirm"`
	}
	if !decode(w, r, &in) {
		return
	}
	p := principal(r)
	item, err := s.Store.GetDatabase(r.Context(), p.OrganizationID, id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if s.Databases == nil {
		writeError(w, http.StatusConflict, "database_driver_unavailable", "database registry is not configured")
		return
	}
	driver, exists := s.Databases.Engine(item.Engine)
	if !exists {
		writeError(w, http.StatusConflict, "database_driver_unavailable", "database engine is not registered on this controller")
		return
	}
	item, err = s.Store.RebindDatabaseDriverIdentity(r.Context(), p, id, in.Confirm, driver.Source, driver.ArtifactDigest, r.RemoteAddr)
	if err != nil {
		if errors.Is(err, store.ErrDatabaseDriverConfirmation) {
			writeError(w, http.StatusBadRequest, "confirmation_mismatch", err.Error())
			return
		}
		if errors.Is(err, store.ErrBusy) {
			writeError(w, http.StatusConflict, "database_busy", "wait for active database operations before rebinding the driver")
			return
		}
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) deleteDatabase(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("databaseID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid database id")
		return
	}
	p := principal(r)
	if err = s.Store.QueueDatabaseDeletionWithAudit(r.Context(), p, id, r.RemoteAddr); err != nil {
		if errors.Is(err, store.ErrBusy) {
			writeError(w, http.StatusConflict, "database_busy", "cancel or wait for active database operations or an existing deletion")
			return
		}
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "deletion_queued"})
}

func (s *Server) createDatabaseBackup(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("databaseID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid database id")
		return
	}
	p := principal(r)
	var destinationID *uuid.UUID
	if raw := r.URL.Query().Get("destinationId"); raw != "" {
		parsed, parseErr := uuid.Parse(raw)
		if parseErr != nil {
			writeError(w, 400, "invalid_id", "invalid destination id")
			return
		}
		destinationID = &parsed
	}
	backup, err := s.Store.QueueDatabaseBackupWithAudit(r.Context(), p, id, destinationID, r.RemoteAddr)
	if err != nil {
		if errors.Is(err, store.ErrBusy) {
			writeError(w, http.StatusConflict, "backup_in_progress", "wait for the active database backup to finish before starting another")
			return
		}
		writeStoreError(w, err)
		return
	}
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
		IntervalSeconds int        `json:"intervalSeconds"`
		RetentionCount  int        `json:"retentionCount"`
		Enabled         bool       `json:"enabled"`
		VerifyRestore   bool       `json:"verifyRestore"`
		DestinationID   *uuid.UUID `json:"destinationId"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.IntervalSeconds < 900 || in.IntervalSeconds > 2678400 || in.RetentionCount < 1 || in.RetentionCount > 100 {
		writeError(w, 400, "invalid_backup_policy", "intervalSeconds must be 900..2678400 and retentionCount must be 1..100")
		return
	}
	p := principal(r)
	item, err := s.Store.UpsertBackupPolicyWithAudit(r.Context(), p, id, in.IntervalSeconds, in.RetentionCount, in.Enabled, in.VerifyRestore, in.DestinationID, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, item)
}

type backupDestinationInput struct {
	Name         string `json:"name"`
	Endpoint     string `json:"endpoint"`
	Region       string `json:"region"`
	Bucket       string `json:"bucket"`
	Prefix       string `json:"prefix"`
	UseTLS       bool   `json:"useTls"`
	AccessKey    string `json:"accessKey"`
	SecretKey    string `json:"secretKey"`
	SessionToken string `json:"sessionToken"`
}

const maxBackupDestinationNameBytes = 120

func normalizedBackupDestinationName(raw string) (string, bool) {
	name := strings.TrimSpace(raw)
	return name, name != "" && len(name) <= maxBackupDestinationNameBytes && !strings.ContainsAny(name, "\x00\r\n")
}

func (s *Server) createBackupDestination(w http.ResponseWriter, r *http.Request) {
	var in backupDestinationInput
	if !decode(w, r, &in) {
		return
	}
	name, validName := normalizedBackupDestinationName(in.Name)
	if !validName || in.AccessKey == "" || in.SecretKey == "" {
		writeError(w, 400, "invalid_destination", "name, accessKey, and secretKey are required")
		return
	}
	client, err := backupstore.NewS3(backupstore.S3Config{Endpoint: in.Endpoint, Region: in.Region, Bucket: in.Bucket, Prefix: in.Prefix, AccessKey: in.AccessKey, SecretKey: in.SecretKey, SessionToken: in.SessionToken, UseTLS: in.UseTLS, Transport: s.EgressTransport})
	if err != nil {
		writeError(w, 400, "invalid_destination", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err = client.Check(ctx); err != nil {
		writeError(w, 400, "destination_unreachable", err.Error())
		return
	}
	destinationID := uuid.New()
	secretJSON, _ := json.Marshal(map[string]string{"accessKey": in.AccessKey, "secretKey": in.SecretKey, "sessionToken": in.SessionToken})
	encrypted, err := s.Box.Encrypt(secretJSON, cryptox.ResourceContext("backup-destination", destinationID.String()))
	if err != nil {
		s.writeInternalError(w, r, 500, "encryption_failed", "backup destination credentials could not be encrypted", err)
		return
	}
	p := principal(r)
	item, err := s.Store.CreateBackupDestinationWithAudit(r.Context(), p, store.BackupDestination{ID: destinationID, Name: name, Endpoint: in.Endpoint, Region: in.Region, Bucket: in.Bucket, Prefix: in.Prefix, UseTLS: in.UseTLS, EncryptedCredentials: encrypted}, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 201, item)
}

func (s *Server) updateBackupDestination(w http.ResponseWriter, r *http.Request) {
	destinationID, err := uuid.Parse(r.PathValue("destinationID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid destination id")
		return
	}
	var in backupDestinationInput
	if !decode(w, r, &in) {
		return
	}
	name, validName := normalizedBackupDestinationName(in.Name)
	if !validName || in.AccessKey == "" || in.SecretKey == "" {
		writeError(w, http.StatusBadRequest, "invalid_destination", "name, accessKey, and secretKey are required")
		return
	}
	p := principal(r)
	if _, err = s.Store.GetBackupDestination(r.Context(), p.OrganizationID, destinationID); err != nil {
		writeStoreError(w, err)
		return
	}
	client, err := backupstore.NewS3(backupstore.S3Config{Endpoint: in.Endpoint, Region: in.Region, Bucket: in.Bucket, Prefix: in.Prefix, AccessKey: in.AccessKey, SecretKey: in.SecretKey, SessionToken: in.SessionToken, UseTLS: in.UseTLS, Transport: s.EgressTransport})
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_destination", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err = client.Check(ctx); err != nil {
		writeError(w, http.StatusBadRequest, "destination_unreachable", err.Error())
		return
	}
	secretJSON, _ := json.Marshal(map[string]string{"accessKey": in.AccessKey, "secretKey": in.SecretKey, "sessionToken": in.SessionToken})
	encrypted, err := s.Box.Encrypt(secretJSON, cryptox.ResourceContext("backup-destination", destinationID.String()))
	if err != nil {
		s.writeInternalError(w, r, http.StatusInternalServerError, "encryption_failed", "backup destination credentials could not be encrypted", err)
		return
	}
	item, err := s.Store.UpdateBackupDestinationWithAudit(r.Context(), p, store.BackupDestination{ID: destinationID, Name: name, Endpoint: in.Endpoint, Region: in.Region, Bucket: in.Bucket, Prefix: in.Prefix, UseTLS: in.UseTLS, EncryptedCredentials: encrypted}, r.RemoteAddr)
	if err != nil {
		if errors.Is(err, store.ErrBusy) {
			writeError(w, http.StatusConflict, "resource_busy", "wait for active backup, restore, or audit-archive operations before rotating this destination")
			return
		}
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) listBackupDestinations(w http.ResponseWriter, r *http.Request) {
	items, err := s.Store.ListBackupDestinations(r.Context(), principal(r).OrganizationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) deleteBackupDestination(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("destinationID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid destination id")
		return
	}
	p := principal(r)
	if err = s.Store.DeleteBackupDestinationWithAudit(r.Context(), p, id, r.RemoteAddr); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(204)
}

func (s *Server) deleteBackupPolicy(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("databaseID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid database id")
		return
	}
	p := principal(r)
	if err = s.Store.DeleteBackupPolicyWithAudit(r.Context(), p, id, r.RemoteAddr); err != nil {
		writeStoreError(w, err)
		return
	}
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
	restore, err := s.Store.QueueDatabaseRestoreWithAudit(r.Context(), p, id, in.Confirm, r.RemoteAddr)
	if err != nil {
		if errors.Is(err, store.ErrBusy) {
			writeError(w, http.StatusConflict, "restore_in_progress", "wait for the active database restore to finish before starting another")
			return
		}
		if strings.Contains(err.Error(), "confirmation") || strings.Contains(err.Error(), "not restorable") {
			writeError(w, 409, "restore_rejected", err.Error())
			return
		}
		writeStoreError(w, err)
		return
	}
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
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 200 {
			writeError(w, 400, "invalid_page", "limit must be between 1 and 200")
			return
		}
		limit = parsed
	}
	var cursor *store.TemplatePageCursor
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		if len(raw) > 2048 {
			writeError(w, 400, "invalid_cursor", "template cursor is invalid")
			return
		}
		decoded, err := base64.RawURLEncoding.DecodeString(raw)
		var payload struct {
			Name    string    `json:"n"`
			Version string    `json:"v"`
			ID      uuid.UUID `json:"i"`
		}
		if err != nil || json.Unmarshal(decoded, &payload) != nil || payload.Name == "" || payload.Version == "" || payload.ID == uuid.Nil {
			writeError(w, 400, "invalid_cursor", "template cursor is invalid")
			return
		}
		cursor = &store.TemplatePageCursor{Name: payload.Name, Version: payload.Version, ID: payload.ID}
	}
	items, hasMore, err := s.Store.ListTemplatesPage(r.Context(), principal(r).OrganizationID, cursor, limit)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	type catalogItem struct {
		store.Template
		Variables    []templates.VariableDescriptor `json:"variables"`
		SafetyClass  string                         `json:"safetyClass"`
		SafetyReason string                         `json:"safetyReason,omitempty"`
		Deployable   bool                           `json:"deployable"`
	}
	response := make([]catalogItem, 0, len(items))
	for _, item := range items {
		var config map[string]string
		if err = json.Unmarshal(item.Config, &config); err != nil {
			writeError(w, 500, "invalid_template", "stored template config is invalid")
			return
		}
		template, parseErr := templates.ParseDokploy([]byte(config["templateToml"]))
		if parseErr != nil {
			writeError(w, 500, "invalid_template", "stored template definition is invalid")
			return
		}
		safetyClass := config["safetyClass"]
		if safetyClass == "" {
			safetyClass = templates.SafetyClassSafe
		}
		response = append(response, catalogItem{
			Template: item, Variables: templates.DescribeVariables(template),
			SafetyClass: safetyClass, SafetyReason: config["safetyReason"],
			Deployable: safetyClass == templates.SafetyClassSafe || (safetyClass == templates.SafetyClassRequiresUnsafe && s.Compiler.AllowUnsafe),
		})
	}
	nextCursor := ""
	if hasMore && len(items) > 0 {
		last := items[len(items)-1]
		payload, marshalErr := json.Marshal(struct {
			Name    string    `json:"n"`
			Version string    `json:"v"`
			ID      uuid.UUID `json:"i"`
		}{Name: last.Name, Version: last.Version, ID: last.ID})
		if marshalErr != nil {
			s.writeInternalError(w, r, 500, "cursor_failed", "template page cursor could not be created", marshalErr)
			return
		}
		nextCursor = base64.RawURLEncoding.EncodeToString(payload)
	}
	writeJSON(w, 200, map[string]any{"items": response, "nextCursor": nextCursor})
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
		instance.ComposeYAML, err = templates.ApplyMounts(instance.ComposeYAML, instance.Mounts, instance.Environment)
	}
	var routes []store.Route
	if err == nil {
		routes, err = templateRoutes(uuid.Nil, instance.Domains)
	}
	safetyClass, safetyReason := "", ""
	if err == nil {
		safetyClass, safetyReason, err = templates.ClassifyComposeSafety(instance.ComposeYAML, routes, s.Compiler.PublicNetwork)
	}
	if err != nil {
		writeError(w, 400, "invalid_template", err.Error())
		return
	}
	config, _ := json.Marshal(map[string]string{"templateToml": in.TemplateTOML, "safetyClass": safetyClass, "safetyReason": safetyReason})
	sum := sha256.Sum256(append([]byte(in.TemplateTOML), []byte(in.ComposeYAML)...))
	p := principal(r)
	item, err := s.Store.CreateTemplateWithAudit(r.Context(), p, store.Template{Key: in.Key, Version: in.Version, Name: in.Name, Description: in.Description, ComposeYAML: in.ComposeYAML, Config: config, Source: "dokploy", Checksum: hex.EncodeToString(sum[:])}, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 201, item)
}

func (s *Server) previewTemplate(w http.ResponseWriter, r *http.Request) {
	templateID, err := uuid.Parse(r.PathValue("templateID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid template id")
		return
	}
	var in struct {
		BaseDomain string            `json:"baseDomain"`
		Variables  map[string]string `json:"variables"`
	}
	if !decode(w, r, &in) {
		return
	}
	item, err := s.Store.GetTemplate(r.Context(), principal(r).OrganizationID, templateID)
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
		writeError(w, 500, "invalid_template", "stored template definition is invalid")
		return
	}
	instance, err := templates.InstantiateWithOverrides(template, item.ComposeYAML, in.BaseDomain, in.Variables)
	if err == nil {
		instance.ComposeYAML, err = templates.ApplyMounts(instance.ComposeYAML, instance.Mounts, instance.Environment)
	}
	if err != nil {
		writeError(w, 400, "invalid_template", err.Error())
		return
	}
	preview, err := templates.DescribeInstance(instance)
	if err != nil {
		writeError(w, 400, "invalid_template", err.Error())
		return
	}
	previewRoutes, err := templateRoutes(uuid.Nil, instance.Domains)
	if err != nil {
		writeError(w, 400, "invalid_template", err.Error())
		return
	}
	if _, err = s.Compiler.Compile(instance.ComposeYAML, previewRoutes); err != nil {
		writeError(w, 400, "invalid_template", err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"templateId": item.ID, "checksum": item.Checksum, "preview": preview})
}

func (s *Server) instantiateTemplate(w http.ResponseWriter, r *http.Request) {
	templateID, err := uuid.Parse(r.PathValue("templateID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid template id")
		return
	}
	var in struct {
		EnvironmentID uuid.UUID         `json:"environmentId"`
		Name          string            `json:"name"`
		Slug          string            `json:"slug"`
		BaseDomain    string            `json:"baseDomain"`
		Variables     map[string]string `json:"variables"`
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
	effectiveRole, err := s.Store.EffectiveResourceRole(r.Context(), p, "environment", in.EnvironmentID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if roleRank(effectiveRole) < roleRank("developer") {
		writeError(w, 403, "forbidden", "insufficient resource role")
		return
	}
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
		s.writeInternalError(w, r, 500, "invalid_template", "stored template definition is invalid", err)
		return
	}
	instance, err := templates.InstantiateWithOverrides(template, item.ComposeYAML, in.BaseDomain, in.Variables)
	if err == nil {
		instance.ComposeYAML, err = templates.ApplyMounts(instance.ComposeYAML, instance.Mounts, instance.Environment)
	}
	if err != nil {
		writeError(w, 400, "invalid_template", err.Error())
		return
	}
	serviceID := uuid.New()
	envJSON, _ := json.Marshal(instance.Environment)
	encryptedEnv, err := s.Box.Encrypt(envJSON, composeEnvironmentContext(serviceID))
	if err != nil {
		s.writeInternalError(w, r, 500, "encryption_failed", "template environment could not be encrypted", err)
		return
	}
	variablesJSON, _ := json.Marshal(instance.Variables)
	encryptedVariables, err := s.Box.Encrypt(variablesJSON, cryptox.ResourceContext("template-variables", serviceID.String()))
	if err != nil {
		s.writeInternalError(w, r, 500, "encryption_failed", "template variables could not be encrypted", err)
		return
	}
	overridesJSON, _ := json.Marshal(in.Variables)
	encryptedOverrides, err := s.Box.Encrypt(overridesJSON, cryptox.ResourceContext("template-overrides", serviceID.String()))
	if err != nil {
		s.writeInternalError(w, r, 500, "encryption_failed", "template overrides could not be encrypted", err)
		return
	}
	shortID := strings.Split(serviceID.String(), "-")[0]
	composeSum := sha256.Sum256([]byte(instance.ComposeYAML))
	routes, err := templateRoutes(serviceID, instance.Domains)
	if err != nil {
		writeError(w, 400, "invalid_template", err.Error())
		return
	}
	if _, err = s.Compiler.Compile(instance.ComposeYAML, routes); err != nil {
		writeError(w, 400, "invalid_template", err.Error())
		return
	}
	templateRef := item.ID
	service, routes, err := s.Store.CreateTemplateServiceWithAudit(r.Context(), p, store.ComposeService{ID: serviceID, EnvironmentID: in.EnvironmentID, Name: in.Name, Slug: in.Slug, StackName: "tpl-" + in.Slug + "-" + shortID, ComposeYAML: instance.ComposeYAML, EncryptedEnv: encryptedEnv}, routes, store.TemplateInstance{TemplateID: &templateRef, TemplateKey: item.Key, TemplateVersion: item.Version, TemplateChecksum: item.Checksum, AppliedComposeChecksum: hex.EncodeToString(composeSum[:]), BaseDomain: in.BaseDomain, EncryptedVariables: encryptedVariables, EncryptedOverrides: encryptedOverrides, ManagedEnvironmentKeys: environmentKeys(instance.Environment)}, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
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
	var source *store.ApplicationSource
	applicationSource, sourceErr := s.Store.GetApplicationSource(r.Context(), principal(r).OrganizationID, id)
	if sourceErr == nil {
		if err = s.redactApplicationBuildConfig(&applicationSource); err != nil {
			s.writeInternalError(w, r, 500, "decryption_failed", "stored build configuration could not be read", err)
			return
		}
		source = &applicationSource
	} else if !errors.Is(sourceErr, store.ErrNotFound) {
		writeStoreError(w, sourceErr)
		return
	}
	var templateInstance *store.TemplateInstance
	provenance, provenanceErr := s.Store.GetTemplateInstance(r.Context(), principal(r).OrganizationID, id)
	if provenanceErr == nil {
		composeSum := sha256.Sum256([]byte(item.ComposeYAML))
		provenance.Drifted = provenance.AppliedComposeChecksum != hex.EncodeToString(composeSum[:])
		templateInstance = &provenance
	} else if !errors.Is(provenanceErr, store.ErrNotFound) {
		writeStoreError(w, provenanceErr)
		return
	}
	reconciliation, err := s.Store.GetServiceReconciliation(r.Context(), principal(r).OrganizationID, id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"service": item, "routes": routes, "source": source, "template": templateInstance, "reconciliation": reconciliation})
}

func (s *Server) listTemplateVersions(w http.ResponseWriter, r *http.Request) {
	serviceID, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid service id")
		return
	}
	p := principal(r)
	instance, err := s.Store.GetTemplateInstance(r.Context(), p.OrganizationID, serviceID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	service, _, err := s.Store.GetComposeService(r.Context(), p.OrganizationID, serviceID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	composeSum := sha256.Sum256([]byte(service.ComposeYAML))
	instance.Drifted = instance.AppliedComposeChecksum != hex.EncodeToString(composeSum[:])
	items, err := s.Store.ListTemplateVersions(r.Context(), p.OrganizationID, instance.TemplateKey, instance.TemplateChecksum)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"current": instance, "items": items})
}

func (s *Server) upgradeTemplateService(w http.ResponseWriter, r *http.Request) {
	serviceID, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid service id")
		return
	}
	var in struct {
		TemplateID uuid.UUID         `json:"templateId"`
		AllowDrift bool              `json:"allowDrift"`
		Variables  map[string]string `json:"variables"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.TemplateID == uuid.Nil {
		writeError(w, 400, "invalid_template", "templateId is required")
		return
	}
	p := principal(r)
	service, _, err := s.Store.GetComposeService(r.Context(), p.OrganizationID, serviceID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	provenance, err := s.Store.GetTemplateInstance(r.Context(), p.OrganizationID, serviceID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	currentSum := sha256.Sum256([]byte(service.ComposeYAML))
	if provenance.AppliedComposeChecksum != hex.EncodeToString(currentSum[:]) && !in.AllowDrift {
		writeError(w, 409, "template_drift", "service Compose has local changes; set allowDrift to replace them")
		return
	}
	target, err := s.Store.GetTemplate(r.Context(), p.OrganizationID, in.TemplateID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if target.Key != provenance.TemplateKey || target.Checksum == provenance.TemplateChecksum {
		writeError(w, 409, "invalid_template_upgrade", "target must be a different revision of the same template")
		return
	}
	var config map[string]string
	if err = json.Unmarshal(target.Config, &config); err != nil {
		writeError(w, 500, "invalid_template", "stored template config is invalid")
		return
	}
	template, err := templates.ParseDokploy([]byte(config["templateToml"]))
	if err != nil {
		writeError(w, 500, "invalid_template", "stored template definition is invalid")
		return
	}
	preserved := map[string]string{}
	if provenance.EncryptedVariables != "" {
		plain, decryptErr := s.Box.Decrypt(provenance.EncryptedVariables, cryptox.ResourceContext("template-variables", serviceID.String()))
		if decryptErr != nil || json.Unmarshal(plain, &preserved) != nil {
			writeError(w, 500, "decryption_failed", "template variables cannot be decrypted")
			return
		}
	}
	storedOverrides := map[string]string{}
	if provenance.EncryptedOverrides != "" {
		plain, decryptErr := s.Box.Decrypt(provenance.EncryptedOverrides, cryptox.ResourceContext("template-overrides", serviceID.String()))
		if decryptErr != nil || json.Unmarshal(plain, &storedOverrides) != nil {
			writeError(w, 500, "decryption_failed", "template overrides cannot be decrypted")
			return
		}
	}
	currentEnvironment, err := s.decryptServiceVariables(service)
	if err != nil {
		s.writeInternalError(w, r, 500, "decryption_failed", "service environment cannot be decrypted", err)
		return
	}
	managedEnvironmentKeys := provenance.ManagedEnvironmentKeys
	if len(currentEnvironment) > 0 && !provenance.EnvironmentOwnershipRecorded {
		managedEnvironmentKeys, err = s.legacyTemplateEnvironmentKeys(r.Context(), p.OrganizationID, provenance, preserved)
		if err != nil {
			writeError(w, 409, "template_environment_provenance_missing", "current template environment ownership cannot be reconstructed; reinstantiate the service before upgrading")
			return
		}
	}
	overrides := templates.UpgradeOverrides(template, preserved, storedOverrides, in.Variables)
	upgraded, err := templates.InstantiateWithOverrides(template, target.ComposeYAML, provenance.BaseDomain, overrides)
	if err == nil {
		upgraded.ComposeYAML, err = templates.ApplyMounts(upgraded.ComposeYAML, upgraded.Mounts, upgraded.Environment)
	}
	if err != nil {
		writeError(w, 400, "invalid_template", err.Error())
		return
	}
	newManagedEnvironmentKeys := environmentKeys(upgraded.Environment)
	managedSet := make(map[string]bool, len(managedEnvironmentKeys))
	for _, name := range managedEnvironmentKeys {
		managedSet[name] = true
	}
	operatorManagedSet := map[string]bool{}
	for name, value := range currentEnvironment {
		if !managedSet[name] {
			operatorManagedSet[name] = true
			upgraded.Environment[name] = value
		}
	}
	filteredManagedKeys := newManagedEnvironmentKeys[:0]
	for _, name := range newManagedEnvironmentKeys {
		if !operatorManagedSet[name] {
			filteredManagedKeys = append(filteredManagedKeys, name)
		}
	}
	newManagedEnvironmentKeys = filteredManagedKeys
	environmentJSON, _ := json.Marshal(upgraded.Environment)
	encryptedEnvironment, err := s.Box.Encrypt(environmentJSON, composeEnvironmentContext(serviceID))
	if err != nil {
		s.writeInternalError(w, r, 500, "encryption_failed", "template environment could not be encrypted", err)
		return
	}
	variablesJSON, _ := json.Marshal(upgraded.Variables)
	encryptedVariables, err := s.Box.Encrypt(variablesJSON, cryptox.ResourceContext("template-variables", serviceID.String()))
	if err != nil {
		s.writeInternalError(w, r, 500, "encryption_failed", "template variables could not be encrypted", err)
		return
	}
	overridesJSON, _ := json.Marshal(overrides)
	encryptedOverrides, err := s.Box.Encrypt(overridesJSON, cryptox.ResourceContext("template-overrides", serviceID.String()))
	if err != nil {
		s.writeInternalError(w, r, 500, "encryption_failed", "template overrides could not be encrypted", err)
		return
	}
	routes, err := templateRoutes(serviceID, upgraded.Domains)
	if err != nil {
		writeError(w, 400, "invalid_template", err.Error())
		return
	}
	if _, err = s.Compiler.Compile(upgraded.ComposeYAML, routes); err != nil {
		writeError(w, 400, "invalid_template", err.Error())
		return
	}
	upgradedSum := sha256.Sum256([]byte(upgraded.ComposeYAML))
	targetRef := target.ID
	service.ComposeYAML, service.EncryptedEnv = upgraded.ComposeYAML, encryptedEnvironment
	service, routes, err = s.Store.UpgradeTemplateServiceWithAudit(r.Context(), p, service.Revision, service, routes, store.TemplateInstance{TemplateID: &targetRef, TemplateKey: target.Key, TemplateVersion: target.Version, TemplateChecksum: target.Checksum, AppliedComposeChecksum: hex.EncodeToString(upgradedSum[:]), BaseDomain: provenance.BaseDomain, EncryptedVariables: encryptedVariables, EncryptedOverrides: encryptedOverrides, ManagedEnvironmentKeys: newManagedEnvironmentKeys}, r.RemoteAddr, map[string]any{"fromTemplateId": provenance.TemplateID, "toTemplateId": target.ID, "fromVersion": provenance.TemplateVersion, "toVersion": target.Version, "replacedDrift": in.AllowDrift})
	if err != nil {
		if errors.Is(err, store.ErrBusy) {
			writeError(w, 409, "concurrent_update", "service changed while the template upgrade was prepared")
			return
		}
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"service": service, "routes": routes})
}

func templateRoutes(serviceID uuid.UUID, domains []templates.Domain) ([]store.Route, error) {
	routes := make([]store.Route, 0, len(domains))
	for _, domain := range domains {
		port, err := templates.PortNumber(domain.Port)
		if err != nil {
			return nil, err
		}
		route := store.Route{ComposeServiceID: serviceID, ServiceName: domain.ServiceName, Host: strings.ToLower(strings.TrimSpace(domain.Host)), PathPrefix: domain.Path, TargetPort: port, TLS: true, CertificateResolver: "letsencrypt"}
		if err = deploy.ValidateRoute(route); err != nil {
			return nil, err
		}
		routes = append(routes, route)
	}
	return routes, nil
}

func environmentKeys(environment map[string]string) []string {
	keys := make([]string, 0, len(environment))
	for name := range environment {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	return keys
}

func (s *Server) legacyTemplateEnvironmentKeys(ctx context.Context, organizationID uuid.UUID, provenance store.TemplateInstance, resolved map[string]string) ([]string, error) {
	if provenance.TemplateID == nil {
		return nil, store.ErrNotFound
	}
	item, err := s.Store.GetTemplate(ctx, organizationID, *provenance.TemplateID)
	if err != nil || item.Checksum != provenance.TemplateChecksum {
		return nil, errors.New("current template revision is unavailable")
	}
	var config map[string]string
	if err = json.Unmarshal(item.Config, &config); err != nil {
		return nil, err
	}
	definition, err := templates.ParseDokploy([]byte(config["templateToml"]))
	if err != nil {
		return nil, err
	}
	instance, err := templates.InstantiateWithOverrides(definition, item.ComposeYAML, provenance.BaseDomain, resolved)
	if err == nil {
		instance.ComposeYAML, err = templates.ApplyMounts(instance.ComposeYAML, instance.Mounts, instance.Environment)
	}
	if err != nil {
		return nil, err
	}
	return environmentKeys(instance.Environment), nil
}

func (s *Server) deleteService(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid service id")
		return
	}
	p := principal(r)
	deleteVolumes, err := strconv.ParseBool(r.URL.Query().Get("deleteVolumes"))
	if err != nil && r.URL.Query().Get("deleteVolumes") != "" {
		writeError(w, 400, "invalid_delete_option", "deleteVolumes must be true or false")
		return
	}
	if err = s.Store.QueueServiceDeletionWithAudit(r.Context(), p, id, deleteVolumes, r.RemoteAddr); err != nil {
		if errors.Is(err, store.ErrBusy) {
			writeError(w, 409, "service_busy", "cancel or wait for active deployments before deleting the service")
			return
		}
		writeStoreError(w, err)
		return
	}
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
	if in.Environment != nil {
		if err = validateServiceVariables(in.Environment); err != nil {
			writeError(w, 400, "invalid_variables", err.Error())
			return
		}
	}
	if _, err = s.Compiler.Compile(in.ComposeYAML, nil); err != nil {
		writeError(w, 400, "invalid_compose", err.Error())
		return
	}
	p := principal(r)
	var encrypted *string
	if len(in.Environment) > 0 {
		plain, _ := json.Marshal(in.Environment)
		value, encryptErr := s.Box.Encrypt(plain, composeEnvironmentContext(id))
		err = encryptErr
		if err != nil {
			s.writeInternalError(w, r, 500, "encryption_failed", "service environment could not be encrypted", err)
			return
		}
		encrypted = &value
	} else if in.Environment != nil {
		value := ""
		encrypted = &value
	}
	item, err := s.Store.UpdateComposeServiceConfigurationWithAudit(r.Context(), p, id, in.ComposeYAML, encrypted, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, item)
}

func (s *Server) upsertSource(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid service id")
		return
	}
	var in struct {
		SourceType           string             `json:"sourceType"`
		RepositoryURL        string             `json:"repositoryUrl"`
		GitRef               string             `json:"gitRef"`
		ContextDirectory     string             `json:"contextDirectory"`
		Dockerfile           string             `json:"dockerfile"`
		BuildType            string             `json:"buildType"`
		BuilderImage         string             `json:"builderImage"`
		OutputDirectory      string             `json:"outputDirectory"`
		BuildTarget          string             `json:"buildTarget"`
		EnableSubmodules     bool               `json:"enableSubmodules"`
		BuildArguments       *map[string]string `json:"buildArguments"`
		BuildSecrets         *map[string]string `json:"buildSecrets"`
		TargetService        string             `json:"targetService"`
		RegistryImage        string             `json:"registryImage"`
		GitCredentialID      *uuid.UUID         `json:"gitCredentialId"`
		RegistryCredentialID *uuid.UUID         `json:"registryCredentialId"`
		StatusProvider       string             `json:"statusProvider"`
		StatusCredentialID   *uuid.UUID         `json:"statusCredentialId"`
		StatusContext        string             `json:"statusContext"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.SourceType == "" {
		in.SourceType = "git"
	}
	if in.SourceType != "git" && in.SourceType != "drop" {
		writeError(w, 400, "invalid_source", "sourceType must be git or drop")
		return
	}
	if in.GitRef == "" {
		in.GitRef = "main"
	}
	in.RepositoryURL = strings.TrimSpace(in.RepositoryURL)
	in.GitRef = strings.TrimSpace(in.GitRef)
	if in.ContextDirectory == "" {
		in.ContextDirectory = "."
	}
	if in.Dockerfile == "" {
		in.Dockerfile = "Dockerfile"
	}
	if in.BuildType == "" {
		in.BuildType = "dockerfile"
	}
	in.BuilderImage = strings.TrimSpace(in.BuilderImage)
	buildConfig := store.ApplicationBuildConfig{}
	if in.BuildArguments == nil || in.BuildSecrets == nil {
		existing, existingErr := s.Store.GetApplicationSource(r.Context(), principal(r).OrganizationID, id)
		if existingErr == nil && existing.EncryptedBuildConfig != "" {
			plain, decryptErr := s.Box.Decrypt(existing.EncryptedBuildConfig, "application-build-config:"+id.String())
			if decryptErr != nil || json.Unmarshal(plain, &buildConfig) != nil {
				writeError(w, 500, "decryption_failed", "stored build configuration is invalid")
				return
			}
		} else if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			writeStoreError(w, existingErr)
			return
		}
	}
	if in.BuildArguments != nil {
		buildConfig.Arguments = *in.BuildArguments
	}
	if in.BuildSecrets != nil {
		buildConfig.Secrets = *in.BuildSecrets
	}
	if err = deploy.ValidateBuildMode(in.BuildType, in.OutputDirectory, in.BuildTarget, buildConfig); err != nil {
		writeError(w, 400, "invalid_build_settings", err.Error())
		return
	}
	if err = deploy.ValidateBuildpackBuilder(in.BuildType, in.BuilderImage); err != nil {
		writeError(w, 400, "invalid_builder_image", err.Error())
		return
	}
	encryptedBuildConfig := ""
	if len(buildConfig.Arguments) > 0 || len(buildConfig.Secrets) > 0 {
		plain, _ := json.Marshal(buildConfig)
		encryptedBuildConfig, err = s.Box.Encrypt(plain, "application-build-config:"+id.String())
		if err != nil {
			s.writeInternalError(w, r, 500, "encryption_failed", "build configuration could not be encrypted", err)
			return
		}
	}
	in.StatusProvider = strings.ToLower(strings.TrimSpace(in.StatusProvider))
	if in.StatusContext == "" {
		in.StatusContext = "dockyard/deploy"
	}
	if in.TargetService == "" || in.RegistryImage == "" || (in.SourceType == "git" && in.RepositoryURL == "") {
		writeError(w, 400, "invalid_source", "targetService, registryImage, and a repositoryUrl for Git sources are required")
		return
	}
	if in.SourceType == "drop" {
		hasArtifact, artifactErr := s.Store.ApplicationArtifactExists(r.Context(), principal(r).OrganizationID, id)
		if artifactErr != nil {
			writeStoreError(w, artifactErr)
			return
		}
		if !hasArtifact {
			writeError(w, 400, "artifact_missing", "upload a ZIP artifact before selecting the drop source type")
			return
		}
		in.RepositoryURL, in.GitRef, in.EnableSubmodules, in.GitCredentialID = "", "", false, nil
		in.StatusProvider, in.StatusCredentialID, in.StatusContext = "", nil, ""
	}
	var repository *url.URL
	if in.SourceType == "git" {
		if repository, err = deploy.ValidateGitSource(in.RepositoryURL, in.GitRef); err != nil {
			writeError(w, 400, "invalid_source", err.Error())
			return
		}
	}
	if err = deploy.ValidateRegistryImage(in.RegistryImage); err != nil {
		writeError(w, 400, "invalid_source", err.Error())
		return
	}
	if in.SourceType == "git" && ((in.StatusProvider == "") != (in.StatusCredentialID == nil) || (in.StatusProvider != "" && !contains([]string{"github", "gitlab", "gitea", "bitbucket"}, in.StatusProvider)) || len(in.StatusContext) > 100 || !webhookBranchPattern.MatchString(in.StatusContext)) {
		writeError(w, 400, "invalid_source_status", "status provider and Git token credential must be configured together with a valid context")
		return
	}
	p := principal(r)
	if err = s.validateApplicationCredentialBindings(r.Context(), p.OrganizationID, repository, in.RegistryImage, in.StatusProvider, in.GitCredentialID, in.RegistryCredentialID, in.StatusCredentialID); err != nil {
		writeError(w, 400, "invalid_source_credential", err.Error())
		return
	}
	item, err := s.Store.UpsertApplicationSourceWithAudit(r.Context(), p, store.ApplicationSource{ComposeServiceID: id, SourceType: in.SourceType, RepositoryURL: in.RepositoryURL, GitRef: in.GitRef, ContextDirectory: in.ContextDirectory, Dockerfile: in.Dockerfile, BuildType: in.BuildType, BuilderImage: in.BuilderImage, OutputDirectory: in.OutputDirectory, BuildTarget: in.BuildTarget, EnableSubmodules: in.EnableSubmodules, HasBuildArguments: len(buildConfig.Arguments) > 0, HasBuildSecrets: len(buildConfig.Secrets) > 0, EncryptedBuildConfig: encryptedBuildConfig, TargetService: in.TargetService, RegistryImage: in.RegistryImage, GitCredentialID: in.GitCredentialID, RegistryCredentialID: in.RegistryCredentialID, StatusProvider: in.StatusProvider, StatusCredentialID: in.StatusCredentialID, StatusContext: in.StatusContext}, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, item)
}

func (s *Server) validateApplicationCredentialBindings(ctx context.Context, organizationID uuid.UUID, repository *url.URL, registryImage, statusProvider string, gitCredentialID, registryCredentialID, statusCredentialID *uuid.UUID) error {
	load := func(id *uuid.UUID) (store.SourceCredential, error) {
		if id == nil {
			return store.SourceCredential{}, nil
		}
		credential, err := s.Store.GetSourceCredential(ctx, organizationID, *id)
		if err != nil {
			return store.SourceCredential{}, errors.New("credential must reference an organization source credential")
		}
		return credential, nil
	}
	if gitCredentialID != nil {
		credential, loadErr := load(gitCredentialID)
		expectedKind := "git"
		if repository != nil && repository.Scheme == "ssh" {
			expectedKind = "git-ssh"
		}
		if loadErr != nil || repository == nil || !credentialMatchesRepository(credential, repository, expectedKind, "") {
			return errors.New("Git credential kind and server must match the repository URL")
		}
	}
	if registryCredentialID != nil {
		credential, loadErr := load(registryCredentialID)
		server, serverErr := normalizeCredentialServer(strings.ToLower(strings.TrimSpace(credential.Server)))
		if loadErr != nil || serverErr != nil || credential.Kind != "registry" || !strings.EqualFold(server, deploy.RegistryHost(registryImage)) {
			return errors.New("registry credential kind and server must match the image registry")
		}
	}
	if statusCredentialID != nil {
		credential, loadErr := load(statusCredentialID)
		fixedAuthority := ""
		if statusProvider == "github" {
			fixedAuthority = "github.com"
		} else if statusProvider == "bitbucket" {
			fixedAuthority = "bitbucket.org"
		}
		if loadErr != nil || repository == nil || !credentialMatchesRepository(credential, repository, "git", fixedAuthority) {
			return errors.New("status credential kind and server must match the repository provider")
		}
	}
	return nil
}

func credentialMatchesRepository(credential store.SourceCredential, repository *url.URL, expectedKind, fixedAuthority string) bool {
	if repository == nil || credential.Kind != expectedKind {
		return false
	}
	server, err := normalizeCredentialServer(strings.ToLower(strings.TrimSpace(credential.Server)))
	if err != nil || !strings.EqualFold(server, repository.Host) {
		return false
	}
	if fixedAuthority != "" {
		return strings.EqualFold(server, fixedAuthority) && strings.EqualFold(repository.Host, fixedAuthority)
	}
	return true
}

func (s *Server) upsertArtifactSource(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid service id")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, deploy.MaxArchiveSize+(1<<20))
	if err = r.ParseMultipartForm(deploy.MaxArchiveSize); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, 413, "artifact_too_large", "multipart upload exceeds the 25 MiB ZIP limit")
		} else {
			writeError(w, 400, "invalid_multipart", "request must be multipart/form-data with a file field")
		}
		return
	}
	defer r.MultipartForm.RemoveAll()
	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, 400, "artifact_missing", "multipart field file must contain a ZIP archive")
		return
	}
	defer file.Close()
	filename := strings.TrimSpace(header.Filename)
	if filename == "" || len(filename) > 255 || strings.ContainsAny(filename, "/\\\x00\r\n") || !strings.HasSuffix(strings.ToLower(filename), ".zip") {
		writeError(w, 400, "invalid_artifact_name", "artifact filename must be a simple .zip filename of at most 255 characters")
		return
	}
	archive, err := io.ReadAll(io.LimitReader(file, deploy.MaxArchiveSize+1))
	if err != nil {
		writeError(w, 400, "artifact_read_failed", "could not read uploaded ZIP archive")
		return
	}
	if len(archive) > deploy.MaxArchiveSize {
		writeError(w, 413, "artifact_too_large", "ZIP archive exceeds 25 MiB")
		return
	}
	if err = deploy.ValidateArchive(archive); err != nil {
		writeError(w, 400, "invalid_artifact", err.Error())
		return
	}
	encrypted, err := s.Box.Encrypt(archive, "application-artifact:"+id.String())
	if err != nil {
		s.writeInternalError(w, r, 500, "encryption_failed", "application artifact could not be encrypted", err)
		return
	}
	digest := sha256.Sum256(archive)
	p := principal(r)
	item, err := s.Store.UpsertApplicationArtifactWithAudit(r.Context(), p, store.ApplicationArtifact{ComposeServiceID: id, EncryptedArchive: encrypted, Filename: filename, SHA256: hex.EncodeToString(digest[:]), CompressedSize: int64(len(archive))}, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, item)
}

func (s *Server) redactApplicationBuildConfig(source *store.ApplicationSource) error {
	if source.EncryptedBuildConfig == "" {
		return nil
	}
	plain, err := s.Box.Decrypt(source.EncryptedBuildConfig, "application-build-config:"+source.ComposeServiceID.String())
	if err != nil {
		return err
	}
	var config store.ApplicationBuildConfig
	if err = json.Unmarshal(plain, &config); err != nil {
		return err
	}
	source.HasBuildArguments = len(config.Arguments) > 0
	source.HasBuildSecrets = len(config.Secrets) > 0
	source.EncryptedBuildConfig = ""
	return nil
}

type sourceCredentialSecretInput struct {
	Secret     string `json:"secret"`
	PrivateKey string `json:"privateKey"`
	KnownHosts string `json:"knownHosts"`
}

type sourceCredentialInput struct {
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Server     string `json:"server"`
	Username   string `json:"username"`
	Secret     string `json:"secret"`
	PrivateKey string `json:"privateKey"`
	KnownHosts string `json:"knownHosts"`
}

func (s *Server) createSourceCredential(w http.ResponseWriter, r *http.Request) {
	var in sourceCredentialInput
	if !decode(w, r, &in) {
		return
	}
	in.Kind = strings.ToLower(strings.TrimSpace(in.Kind))
	in.Name = strings.TrimSpace(in.Name)
	in.Server = strings.ToLower(strings.TrimSpace(in.Server))
	normalizedServer, validationErr := normalizeCredentialServer(in.Server)
	if validationErr != nil || !validSourceCredentialIdentity(in.Kind, in.Name, in.Username) {
		writeError(w, 400, "invalid_credential", "kind, name, server, and username are required")
		return
	}
	in.Server = normalizedServer
	secret, validationErr := validateSourceCredentialSecret(in.Kind, in.Server, sourceCredentialSecretInput{Secret: in.Secret, PrivateKey: in.PrivateKey, KnownHosts: in.KnownHosts})
	if validationErr != nil {
		writeError(w, 400, "invalid_credential", validationErr.Error())
		return
	}
	credentialID := uuid.New()
	encrypted, err := s.Box.Encrypt([]byte(secret), cryptox.ResourceContext("source-credential", credentialID.String()))
	if err != nil {
		s.writeInternalError(w, r, 500, "encryption_failed", "source credential could not be encrypted", err)
		return
	}
	p := principal(r)
	item, err := s.Store.CreateSourceCredentialWithAudit(r.Context(), p, store.SourceCredential{ID: credentialID, Kind: in.Kind, Name: in.Name, Server: in.Server, Username: in.Username, EncryptedSecret: encrypted}, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 201, item)
}

func validateSourceCredentialSecret(kind, server string, in sourceCredentialSecretInput) (string, error) {
	secret := in.Secret
	if kind == "git-ssh" {
		if len(in.PrivateKey) > 64<<10 || len(in.KnownHosts) > 1<<20 || strings.TrimSpace(in.KnownHosts) == "" {
			return "", errors.New("SSH private key and pinned known-hosts entries are required")
		}
		if _, err := ssh.ParsePrivateKey([]byte(in.PrivateKey)); err != nil {
			return "", errors.New("SSH private key is invalid or encrypted")
		}
		if !validKnownHosts(server, in.KnownHosts) {
			return "", errors.New("known-hosts must contain a valid pinned key for the credential server")
		}
		encoded, _ := json.Marshal(map[string]string{"privateKey": in.PrivateKey, "knownHosts": in.KnownHosts})
		secret = string(encoded)
	}
	invalidSecret := secret == ""
	if kind == "git-ssh" {
		invalidSecret = invalidSecret || len(secret) > maxSourceCredentialSSHMaterialBytes
	} else {
		invalidSecret = invalidSecret || len(secret) > maxSourceCredentialSecretBytes || strings.ContainsAny(secret, "\x00\r\n")
	}
	if invalidSecret {
		return "", errors.New("credential secret is required")
	}
	return secret, nil
}

func (s *Server) rotateSourceCredential(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("credentialID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid credential id")
		return
	}
	var in sourceCredentialSecretInput
	if !decode(w, r, &in) {
		return
	}
	p := principal(r)
	current, err := s.Store.GetSourceCredential(r.Context(), p.OrganizationID, id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	secret, validationErr := validateSourceCredentialSecret(current.Kind, current.Server, in)
	if validationErr != nil {
		writeError(w, 400, "invalid_credential", validationErr.Error())
		return
	}
	encrypted, err := s.Box.Encrypt([]byte(secret), cryptox.ResourceContext("source-credential", id.String()))
	if err != nil {
		s.writeInternalError(w, r, 500, "encryption_failed", "source credential could not be encrypted", err)
		return
	}
	item, err := s.Store.RotateSourceCredentialWithAudit(r.Context(), p, id, encrypted, r.RemoteAddr)
	if err != nil {
		if errors.Is(err, store.ErrBusy) {
			writeError(w, http.StatusConflict, "resource_busy", "wait for active deployments or template synchronization before rotating this credential")
			return
		}
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, item)
}

func validKnownHosts(server, contents string) bool {
	target := knownhosts.Normalize(server)
	for _, line := range strings.Split(contents, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		marker, hosts, _, _, rest, err := ssh.ParseKnownHosts([]byte(line))
		if err != nil || len(strings.TrimSpace(string(rest))) != 0 || marker == "revoked" {
			continue
		}
		for _, host := range hosts {
			if knownHostMatches(host, target) {
				return true
			}
		}
	}
	return false
}

func knownHostMatches(pattern, target string) bool {
	if strings.EqualFold(pattern, target) {
		return true
	}
	parts := strings.Split(pattern, "|")
	if len(parts) != 4 || parts[0] != "" || parts[1] != "1" {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(salt) == 0 {
		return false
	}
	want, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil || len(want) != sha1.Size {
		return false
	}
	// OpenSSH's version-1 hashed-host format is fixed to HMAC-SHA1.
	mac := hmac.New(sha1.New, salt)
	_, _ = mac.Write([]byte(target))
	return hmac.Equal(mac.Sum(nil), want)
}

func (s *Server) listSourceCredentials(w http.ResponseWriter, r *http.Request) {
	items, err := s.Store.ListSourceCredentials(r.Context(), principal(r).OrganizationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) deleteSourceCredential(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("credentialID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid credential id")
		return
	}
	p := principal(r)
	if err = s.Store.DeleteSourceCredentialWithAudit(r.Context(), p, id, r.RemoteAddr); err != nil {
		if errors.Is(err, store.ErrBusy) {
			writeError(w, http.StatusConflict, "resource_busy", "wait for template synchronization to finish before deleting this credential")
			return
		}
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(204)
}

type routeInput struct {
	ServiceName         string     `json:"serviceName"`
	Host                string     `json:"host"`
	PathPrefix          string     `json:"pathPrefix"`
	InternalPath        string     `json:"internalPath"`
	StripPath           bool       `json:"stripPath"`
	Enabled             *bool      `json:"enabled"`
	RedirectRegex       string     `json:"redirectRegex"`
	RedirectReplacement string     `json:"redirectReplacement"`
	RedirectPermanent   bool       `json:"redirectPermanent"`
	TargetPort          int        `json:"targetPort"`
	TLS                 *bool      `json:"tls"`
	CertificateResolver string     `json:"certificateResolver"`
	CustomCertificateID *uuid.UUID `json:"customCertificateId"`
}

func (in routeInput) route(serviceID uuid.UUID) store.Route {
	in.Host = strings.ToLower(strings.TrimSpace(in.Host))
	if in.PathPrefix == "" {
		in.PathPrefix = "/"
	}
	if in.InternalPath == "" {
		in.InternalPath = "/"
	}
	if in.CertificateResolver == "" && in.CustomCertificateID == nil {
		in.CertificateResolver = "letsencrypt"
	}
	tls, enabled := true, true
	if in.TLS != nil {
		tls = *in.TLS
	}
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	return store.Route{ComposeServiceID: serviceID, ServiceName: in.ServiceName, Host: in.Host, PathPrefix: in.PathPrefix, InternalPath: in.InternalPath, StripPath: in.StripPath, Enabled: enabled, Disabled: !enabled, RedirectRegex: in.RedirectRegex, RedirectReplacement: in.RedirectReplacement, RedirectPermanent: in.RedirectPermanent, TargetPort: in.TargetPort, TLS: tls, CertificateResolver: in.CertificateResolver, CustomCertificateID: in.CustomCertificateID}
}

func (s *Server) addRoute(w http.ResponseWriter, r *http.Request) {
	serviceID, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid service id")
		return
	}
	var in routeInput
	if !decode(w, r, &in) {
		return
	}
	item := in.route(serviceID)
	if err = deploy.ValidateRoute(item); err != nil {
		writeError(w, 400, "invalid_route", "invalid route")
		return
	}
	p := principal(r)
	item, err = s.Store.AddRouteWithAudit(r.Context(), p, item, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 201, item)
}

func (s *Server) updateRoute(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("routeID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid route id")
		return
	}
	var in routeInput
	if !decode(w, r, &in) {
		return
	}
	item := in.route(uuid.Nil)
	item.ID = id
	if err = deploy.ValidateRoute(item); err != nil {
		writeError(w, 400, "invalid_route", "invalid route")
		return
	}
	p := principal(r)
	item, err = s.Store.UpdateRouteWithAudit(r.Context(), p, item, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) getRoute(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("routeID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid route id")
		return
	}
	item, err := s.Store.GetRoute(r.Context(), principal(r).OrganizationID, id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, item)
}

func (s *Server) deleteRoute(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("routeID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid route id")
		return
	}
	p := principal(r)
	if err = s.Store.DeleteRouteWithAudit(r.Context(), p, id, r.RemoteAddr); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deployService(w http.ResponseWriter, r *http.Request) {
	serviceID, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid service id")
		return
	}
	p := principal(r)
	item, err := s.Store.QueueDeploymentWithAudit(r.Context(), p, serviceID, "manual", r.RemoteAddr)
	if err != nil {
		if errors.Is(err, store.ErrBusy) {
			writeError(w, http.StatusConflict, "service_busy", "wait for the active offline restore before deploying the service")
			return
		}
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 202, item)
}

func (s *Server) stopService(w http.ResponseWriter, r *http.Request) {
	serviceID, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid service id")
		return
	}
	p := principal(r)
	jobID, queued, err := s.Store.QueueServiceStopWithAudit(r.Context(), p, serviceID, r.RemoteAddr)
	if err != nil {
		if errors.Is(err, store.ErrBusy) {
			writeError(w, http.StatusConflict, "service_busy", "wait for active scheduled command, backup, restore, or migration work before stopping the service")
			return
		}
		writeStoreError(w, err)
		return
	}
	status := http.StatusOK
	if queued {
		status = http.StatusAccepted
	}
	writeJSON(w, status, map[string]any{"desiredState": "stopped", "jobId": jobID, "queued": queued})
}

func (s *Server) startService(w http.ResponseWriter, r *http.Request) {
	serviceID, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid service id")
		return
	}
	p := principal(r)
	item, err := s.Store.QueueServiceStartWithAudit(r.Context(), p, serviceID, r.RemoteAddr)
	if err != nil {
		if errors.Is(err, store.ErrBusy) {
			writeError(w, http.StatusConflict, "service_busy", "wait for the active restore or data operation before starting the service")
			return
		}
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, item)
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
	scheduler := s.Swarm
	var clusterID *uuid.UUID
	if err = s.Store.Pool.QueryRow(ctx, `SELECT cluster_id FROM environments WHERE id=$1`, item.EnvironmentID).Scan(&clusterID); err != nil {
		writeStoreError(w, err)
		return
	}
	if clusterID != nil {
		scheduler = deploy.RemoteSwarm{Store: s.Store, Box: s.Box, ClusterID: *clusterID, Timeout: 30 * time.Second}
	}
	logs, err := scheduler.Logs(ctx, item.StackName, 500)
	if err != nil {
		s.writeInternalError(w, r, 502, "logs_failed", "service logs are unavailable", err)
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
	item, err := s.Store.QueueRollbackWithAudit(r.Context(), p, serviceID, r.RemoteAddr)
	if err != nil {
		if errors.Is(err, store.ErrBusy) {
			writeError(w, http.StatusConflict, "service_busy", "wait for the active offline restore before rolling back the service")
			return
		}
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 202, item)
}

func (s *Server) createDeployToken(w http.ResponseWriter, r *http.Request) {
	serviceID, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid service id")
		return
	}
	var in struct {
		Name          string `json:"name"`
		ExpiresInDays int    `json:"expiresInDays"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		in.Name = "default"
	}
	if in.ExpiresInDays == 0 {
		in.ExpiresInDays = 90
	}
	if len(in.Name) > 100 {
		writeError(w, http.StatusBadRequest, "invalid_deploy_token", "name must not exceed 100 characters")
		return
	}
	if in.ExpiresInDays < 1 || in.ExpiresInDays > 365 {
		writeError(w, http.StatusBadRequest, "invalid_expiry", "expiry must be from 1 to 365 days")
		return
	}
	token, err := auth.NewToken()
	if err != nil {
		s.writeInternalError(w, r, 500, "token_failed", "deployment token could not be generated", err)
		return
	}
	p := principal(r)
	expiresAt := time.Now().UTC().Add(time.Duration(in.ExpiresInDays) * 24 * time.Hour)
	item, err := s.Store.CreateDeployTokenWithAudit(r.Context(), p, serviceID, in.Name, cryptox.Digest(token), expiresAt, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 201, map[string]any{"deployToken": item, "token": token, "url": s.PublicURL + "/v1/hooks/deploy/" + token})
}

func (s *Server) listDeployTokens(w http.ResponseWriter, r *http.Request) {
	serviceID, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid service id")
		return
	}
	items, err := s.Store.ListDeployTokens(r.Context(), principal(r).OrganizationID, serviceID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) revokeDeployToken(w http.ResponseWriter, r *http.Request) {
	serviceID, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid service id")
		return
	}
	tokenID, err := uuid.Parse(r.PathValue("tokenID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid deploy token id")
		return
	}
	p := principal(r)
	if err = s.Store.RevokeDeployTokenWithAudit(r.Context(), p, serviceID, tokenID, r.RemoteAddr); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
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
	err = s.Store.Pool.QueryRow(r.Context(), `SELECT d.id,d.compose_service_id,d.revision,d.status,d.trigger,d.commit_sha,d.error,d.output,d.created_at,d.started_at,d.finished_at FROM deployments d JOIN compose_services s ON s.id=d.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE d.id=$1 AND p.organization_id=$2`, id, p.OrganizationID).Scan(&d.ID, &d.ComposeServiceID, &d.Revision, &d.Status, &d.Trigger, &d.CommitSHA, &d.Error, &d.Output, &d.CreatedAt, &d.StartedAt, &d.FinishedAt)
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
	if err = s.Store.CancelDeploymentWithAudit(r.Context(), p, id, r.RemoteAddr); err != nil {
		if errors.Is(err, store.ErrNotCancellable) {
			writeError(w, 409, "not_cancellable", err.Error())
			return
		}
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 202, map[string]string{"status": "cancellation_requested"})
}

func decode(w http.ResponseWriter, r *http.Request, target any) bool {
	return decodeLimit(w, r, target, 3<<20)
}

func decodeLimit(w http.ResponseWriter, r *http.Request, target any, limit int64) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	validMediaType := mediaType == "application/json" || strings.HasPrefix(mediaType, "application/") && strings.HasSuffix(mediaType, "+json")
	if err != nil || !validMediaType {
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "request Content-Type must be application/json or application/*+json")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "request_too_large", "JSON request body exceeds the endpoint limit")
			return false
		}
		writeError(w, 400, "invalid_json", "request body must contain one valid JSON object")
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "request_too_large", "JSON request body exceeds the endpoint limit")
			return false
		}
		writeError(w, 400, "invalid_json", "request must contain one JSON value")
		return false
	}
	return true
}

func composeEnvironmentContext(serviceID uuid.UUID) string {
	return cryptox.ResourceContext("compose-env", serviceID.String())
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

// writeLoginSuccess keeps the JSON API stable while allowing browser-based
// OIDC and SAML flows to hand the short-lived bearer token to the console. The
// fragment is never sent in subsequent HTTP requests and the console removes
// it from browser history immediately after storing it in sessionStorage.
func writeLoginSuccess(w http.ResponseWriter, r *http.Request, token string) {
	w.Header().Set("Cache-Control", "no-store")
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		http.Redirect(w, r, "/#session="+url.QueryEscape(token), http.StatusSeeOther)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func (s *Server) writeInternalError(w http.ResponseWriter, r *http.Request, status int, code, message string, err error) {
	s.logger().ErrorContext(r.Context(), "request operation failed", "request_id", requestID(r), "operation", code, "error_type", fmt.Sprintf("%T", err))
	writeError(w, status, code, message)
}
func writeStoreError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrAlreadyBootstrapped) {
		writeError(w, http.StatusConflict, "already_bootstrapped", store.ErrAlreadyBootstrapped.Error())
		return
	}
	if errors.Is(err, store.ErrOwnerRequired) {
		writeError(w, http.StatusForbidden, "owner_required", err.Error())
		return
	}
	if errors.Is(err, store.ErrLastOwner) {
		writeError(w, http.StatusConflict, "last_owner", err.Error())
		return
	}
	if errors.Is(err, store.ErrSCIMManaged) {
		writeError(w, http.StatusConflict, "scim_managed", err.Error())
		return
	}
	if errors.Is(err, store.ErrAlreadyMember) {
		writeError(w, http.StatusConflict, "already_member", err.Error())
		return
	}
	if errors.Is(err, store.ErrPasswordRequired) {
		writeError(w, http.StatusBadRequest, "password_required", err.Error())
		return
	}
	if errors.Is(err, store.ErrUserDisabled) {
		writeError(w, http.StatusConflict, "user_disabled", err.Error())
		return
	}
	if errors.Is(err, store.ErrSAMLCertificateRotationPending) {
		writeError(w, http.StatusConflict, "saml_certificate_rotation_pending", err.Error())
		return
	}
	if errors.Is(err, store.ErrSSOProviderRequired) {
		writeError(w, http.StatusConflict, "sso_provider_required", err.Error())
		return
	}
	if errors.Is(err, store.ErrProtectedVolumeRemoved) {
		writeError(w, http.StatusConflict, "protected_volume_removed", err.Error())
		return
	}
	if errors.Is(err, store.ErrVolumeNotDeclared) {
		writeError(w, http.StatusConflict, "volume_not_declared", err.Error())
		return
	}
	if errors.Is(err, store.ErrDeleting) {
		writeError(w, http.StatusConflict, "resource_deleting", err.Error())
		return
	}
	if errors.Is(err, store.ErrMaintenance) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusServiceUnavailable, "maintenance_mode", "resource is in maintenance mode")
		return
	}
	if errors.Is(err, store.ErrClusterUnavailable) {
		w.Header().Set("Retry-After", "30")
		writeError(w, http.StatusServiceUnavailable, "cluster_unavailable", err.Error())
		return
	}
	if errors.Is(err, store.ErrNoCapacity) {
		writeError(w, http.StatusConflict, "no_cluster_capacity", err.Error())
		return
	}
	if errors.Is(err, store.ErrAIAuditFindingLimit) {
		writeError(w, http.StatusConflict, "ai_audit_finding_limit", err.Error())
		return
	}
	if errors.Is(err, store.ErrRollbackUnavailable) {
		writeError(w, http.StatusConflict, "rollback_unavailable", err.Error())
		return
	}
	var quota *store.QuotaExceededError
	if errors.As(err, &quota) {
		writeError(w, http.StatusConflict, "quota_exceeded", quota.Error())
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 404, "not_found", "resource not found")
		return
	}
	if errors.Is(err, store.ErrDeploymentActive) {
		writeError(w, http.StatusConflict, "deployment_active", err.Error())
		return
	}
	if errors.Is(err, store.ErrServiceAlreadyRunning) {
		writeError(w, http.StatusConflict, "service_already_running", err.Error())
		return
	}
	if errors.Is(err, store.ErrServiceStopped) {
		writeError(w, http.StatusConflict, "service_stopped", "start the service before running this operation")
		return
	}
	if errors.Is(err, store.ErrInvalidSchedule) {
		writeError(w, http.StatusBadRequest, "invalid_schedule", err.Error())
		return
	}
	if errors.Is(err, store.ErrInvalidRouteBasicAuth) {
		writeError(w, http.StatusBadRequest, "invalid_route_basic_auth", err.Error())
		return
	}
	if errors.Is(err, store.ErrInvalidRouteCertificate) {
		writeError(w, http.StatusBadRequest, "invalid_route_certificate", err.Error())
		return
	}
	if errors.Is(err, store.ErrRevisionConflict) {
		writeError(w, http.StatusConflict, "revision_conflict", err.Error())
		return
	}
	if errors.Is(err, store.ErrCrossClusterMove) {
		writeError(w, http.StatusConflict, "cross_cluster_move", err.Error())
		return
	}
	if errors.Is(err, store.ErrManagedDatabaseMove) {
		writeError(w, http.StatusConflict, "managed_database_move", err.Error())
		return
	}
	if errors.Is(err, store.ErrNotCancellable) {
		writeError(w, http.StatusConflict, "not_cancellable", err.Error())
		return
	}
	if errors.Is(err, store.ErrBusy) {
		writeError(w, http.StatusConflict, "resource_not_empty", "delete child resources first")
		return
	}
	if errors.Is(err, store.ErrRemoteBackupRequired) {
		writeError(w, http.StatusBadRequest, "remote_backup_required", err.Error())
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

func canonicalEmail(raw string) (string, string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 320 || strings.Count(raw, "@") != 1 {
		return "", "", false
	}
	parsed, err := mail.ParseAddress(raw)
	if err != nil || parsed.Address != raw {
		return "", "", false
	}
	email := strings.ToLower(parsed.Address)
	parts := strings.SplitN(email, "@", 2)
	if parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return email, parts[1], true
}

func canonicalDisplayName(raw string) (string, bool) {
	name := strings.TrimSpace(raw)
	return name, len(name) <= 120
}

func validFederatedIdentifier(value string) bool {
	return value != "" && len(value) <= 1024
}

var _ = fmt.Sprintf
