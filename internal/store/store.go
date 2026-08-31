package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNotFound = errors.New("not found")
var ErrAlreadyBootstrapped = errors.New("instance is already bootstrapped")
var ErrNotCancellable = errors.New("resource is not cancellable")
var ErrBusy = errors.New("resource has an operation in progress")
var ErrDeploymentActive = errors.New("service has a queued or running deployment")
var ErrServiceAlreadyRunning = errors.New("service is already intended to run")
var ErrServiceStopped = errors.New("service is stopped")
var ErrDeleting = errors.New("resource is being deleted")
var ErrDuplicateDelivery = errors.New("webhook delivery already processed")
var ErrSSOProviderRequired = errors.New("an enabled SSO provider is required")
var ErrNoCapacity = errors.New("no eligible cluster has the requested placement capacity")
var ErrClusterUnavailable = errors.New("assigned remote cluster has no fresh heartbeat")
var ErrRemoteBackupRequired = errors.New("a remote backup destination is required")
var ErrLastOwner = errors.New("organization must retain an active owner")
var ErrSCIMManaged = errors.New("membership is managed by SCIM")
var ErrOwnerRequired = errors.New("organization owner role is required")
var ErrAlreadyMember = errors.New("user is already an organization member")
var ErrPasswordRequired = errors.New("a password is required for a new local account")
var ErrInvalidCurrentPassword = errors.New("current password is incorrect")
var ErrLocalSessionRequired = errors.New("a local interactive session is required")
var ErrAuthenticationStateChanged = errors.New("authentication state changed")
var ErrMFARequired = errors.New("multi-factor authentication is required")
var ErrInvalidMFAProof = errors.New("multi-factor authentication proof is invalid")
var ErrMFAAlreadyEnabled = errors.New("multi-factor authentication is already enabled")
var ErrMFANotEnabled = errors.New("multi-factor authentication is not enabled")
var ErrMFAEnrollmentMissing = errors.New("multi-factor authentication enrollment is not pending")
var ErrUserDisabled = errors.New("user account is disabled")
var ErrSAMLCertificateRotationPending = errors.New("a SAML certificate rotation is already pending")
var ErrRollbackUnavailable = errors.New("no successful immutable deployment is available for rollback")
var ErrProtectedVolumeRemoved = errors.New("a protected named volume cannot be removed while its backup policy exists")
var ErrVolumeNotDeclared = errors.New("named volume is not mounted by the service")
var ErrInvalidSchedule = errors.New("invalid service schedule")
var ErrInvalidRouteBasicAuth = errors.New("invalid route basic-auth user")
var ErrInvalidRouteCertificate = errors.New("custom TLS certificate is unavailable, expired, or does not cover the route host")
var ErrRevisionConflict = errors.New("resource revision changed; reload and retry")
var ErrCrossClusterMove = errors.New("service can only move between environments assigned to the same cluster")
var ErrManagedDatabaseMove = errors.New("managed database services must be moved through a database migration")

type Store struct {
	Pool                 *pgxpool.Pool
	RequireRemoteBackups bool
}

func Open(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := openPool(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	if err := Migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{Pool: pool}, nil
}

// OpenVerified authenticates an existing master-key verifier before applying
// migrations, then creates or rechecks it after the schema is current.
func OpenVerified(ctx context.Context, databaseURL string, box *cryptox.Box) (*Store, error) {
	pool, err := openPool(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	if err = prepareVerifiedStore(ctx, pool, box); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{Pool: pool}, nil
}

// OpenReadOnlyVerified opens an existing, current schema with PostgreSQL-level
// write protection. It is used by dry-run tooling so future code changes
// cannot accidentally mutate the target database.
func OpenReadOnlyVerified(ctx context.Context, databaseURL string, box *cryptox.Box) (*Store, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database URL: %w", err)
	}
	pool, err := openReadOnlyConfiguredPool(ctx, config)
	if err != nil {
		return nil, err
	}
	if err = verifyMasterKeyRequired(ctx, pool, box); err != nil {
		pool.Close()
		return nil, fmt.Errorf("verify master key for read-only operation: %w", err)
	}
	if err = ValidateMigrationState(ctx, pool); err != nil {
		pool.Close()
		return nil, fmt.Errorf("validate database schema for read-only operation: %w", err)
	}
	return &Store{Pool: pool}, nil
}

func openReadOnlyConfiguredPool(ctx context.Context, config *pgxpool.Config) (*pgxpool.Pool, error) {
	config.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
	return openConfiguredPool(ctx, config)
}

func prepareVerifiedStore(ctx context.Context, pool *pgxpool.Pool, box *cryptox.Box) error {
	if err := verifyMasterKeyIfInitialized(ctx, pool, box); err != nil {
		return fmt.Errorf("verify master key before migrations: %w", err)
	}
	if err := Migrate(ctx, pool); err != nil {
		return err
	}
	if err := VerifyOrInitializeMasterKey(ctx, pool, box); err != nil {
		return fmt.Errorf("verify master key after migrations: %w", err)
	}
	return nil
}

func openPool(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database URL: %w", err)
	}
	return openConfiguredPool(ctx, config)
}

func openConfiguredPool(ctx context.Context, config *pgxpool.Config) (*pgxpool.Pool, error) {
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return pool, nil
}

type Principal struct {
	UserID                uuid.UUID  `json:"userId"`
	SessionID             uuid.UUID  `json:"-"`
	SessionOrganizationID *uuid.UUID `json:"-"`
	ServiceAccountID      *uuid.UUID `json:"serviceAccountId,omitempty"`
	Email                 string     `json:"email"`
	OrganizationID        uuid.UUID  `json:"organizationId"`
	Organization          string     `json:"organization"`
	Role                  string     `json:"role"`
}

type Session struct {
	ID             uuid.UUID  `json:"id"`
	OrganizationID *uuid.UUID `json:"organizationId,omitempty"`
	AuthMethod     string     `json:"authMethod"`
	UserAgent      string     `json:"userAgent"`
	IPAddress      string     `json:"ipAddress"`
	ExpiresAt      time.Time  `json:"expiresAt"`
	CreatedAt      time.Time  `json:"createdAt"`
	LastSeenAt     time.Time  `json:"lastSeenAt"`
	Current        bool       `json:"current"`
}

type OrganizationAuthSettings struct {
	RequireSSO bool      `json:"requireSso"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

type Project struct {
	ID             uuid.UUID `json:"id"`
	OrganizationID uuid.UUID `json:"organizationId"`
	Name           string    `json:"name"`
	Slug           string    `json:"slug"`
	Description    string    `json:"description"`
	Tags           []Tag     `json:"tags"`
	CreatedAt      time.Time `json:"createdAt"`
}

type Environment struct {
	ID                 uuid.UUID         `json:"id"`
	ProjectID          uuid.UUID         `json:"projectId"`
	ClusterID          *uuid.UUID        `json:"clusterId,omitempty"`
	PlacementSelector  map[string]string `json:"placementSelector,omitempty"`
	MinimumNodes       int               `json:"minimumNodes,omitempty"`
	MinimumNanoCPUs    int64             `json:"minimumNanoCpus,omitempty"`
	MinimumMemoryBytes int64             `json:"minimumMemoryBytes,omitempty"`
	Name               string            `json:"name"`
	Slug               string            `json:"slug"`
	CreatedAt          time.Time         `json:"createdAt"`
}

type ComposeService struct {
	ID            uuid.UUID `json:"id"`
	EnvironmentID uuid.UUID `json:"environmentId"`
	Name          string    `json:"name"`
	Slug          string    `json:"slug"`
	StackName     string    `json:"stackName"`
	StorageNodeID string    `json:"storageNodeId,omitempty"`
	ComposeYAML   string    `json:"composeYaml,omitempty"`
	EncryptedEnv  string    `json:"-"`
	Revision      int64     `json:"revision"`
	DesiredState  string    `json:"desiredState"`
	Tags          []Tag     `json:"tags"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

type Route struct {
	ID                  uuid.UUID  `json:"id"`
	ComposeServiceID    uuid.UUID  `json:"composeServiceId"`
	ServiceName         string     `json:"serviceName"`
	Host                string     `json:"host"`
	PathPrefix          string     `json:"pathPrefix"`
	InternalPath        string     `json:"internalPath"`
	StripPath           bool       `json:"stripPath"`
	Enabled             bool       `json:"enabled"`
	Disabled            bool       `json:"-"`
	RedirectRegex       string     `json:"redirectRegex"`
	RedirectReplacement string     `json:"redirectReplacement"`
	RedirectPermanent   bool       `json:"redirectPermanent"`
	TargetPort          int        `json:"targetPort"`
	TLS                 bool       `json:"tls"`
	CertificateResolver string     `json:"certificateResolver"`
	CustomCertificateID *uuid.UUID `json:"customCertificateId,omitempty"`
	CreatedAt           time.Time  `json:"createdAt"`
	UpdatedAt           time.Time  `json:"updatedAt"`
	BasicAuthUsers      []string   `json:"-"`
}

type Deployment struct {
	ID               uuid.UUID  `json:"id"`
	ComposeServiceID uuid.UUID  `json:"composeServiceId"`
	Revision         int64      `json:"revision"`
	Status           string     `json:"status"`
	Trigger          string     `json:"trigger"`
	CommitSHA        string     `json:"commitSha,omitempty"`
	Error            string     `json:"error,omitempty"`
	Output           string     `json:"output,omitempty"`
	CreatedAt        time.Time  `json:"createdAt"`
	StartedAt        *time.Time `json:"startedAt,omitempty"`
	FinishedAt       *time.Time `json:"finishedAt,omitempty"`
}

type DatabaseInstance struct {
	ID               uuid.UUID      `json:"id"`
	EnvironmentID    uuid.UUID      `json:"environmentId"`
	Name             string         `json:"name"`
	Slug             string         `json:"slug"`
	Engine           string         `json:"engine"`
	Version          string         `json:"version"`
	DriverSource     string         `json:"driverSource"`
	DriverDigest     string         `json:"driverArtifactDigest,omitempty"`
	StorageNodeID    string         `json:"storageNodeId,omitempty"`
	ComposeServiceID uuid.UUID      `json:"composeServiceId"`
	Config           map[string]any `json:"config"`
	Status           string         `json:"status"`
	CreatedAt        time.Time      `json:"createdAt"`
}

type Template struct {
	ID             uuid.UUID       `json:"id"`
	OrganizationID *uuid.UUID      `json:"organizationId,omitempty"`
	RepositoryID   *uuid.UUID      `json:"repositoryId,omitempty"`
	Key            string          `json:"key"`
	Version        string          `json:"version"`
	Name           string          `json:"name"`
	Description    string          `json:"description"`
	ComposeYAML    string          `json:"composeYaml,omitempty"`
	Config         json.RawMessage `json:"-"`
	Source         string          `json:"source"`
	SourcePath     string          `json:"sourcePath,omitempty"`
	Checksum       string          `json:"checksum"`
	CreatedAt      time.Time       `json:"createdAt"`
}

type TemplatePageCursor struct {
	Name    string
	Version string
	ID      uuid.UUID
}

type TemplateInstance struct {
	ComposeServiceID             uuid.UUID  `json:"composeServiceId"`
	TemplateID                   *uuid.UUID `json:"templateId,omitempty"`
	TemplateKey                  string     `json:"templateKey"`
	TemplateVersion              string     `json:"templateVersion"`
	TemplateChecksum             string     `json:"templateChecksum"`
	AppliedComposeChecksum       string     `json:"appliedComposeChecksum"`
	BaseDomain                   string     `json:"baseDomain"`
	EncryptedVariables           string     `json:"-"`
	EncryptedOverrides           string     `json:"-"`
	ManagedEnvironmentKeys       []string   `json:"-"`
	EnvironmentOwnershipRecorded bool       `json:"-"`
	Drifted                      bool       `json:"drifted"`
	CreatedAt                    time.Time  `json:"createdAt"`
	UpdatedAt                    time.Time  `json:"updatedAt"`
}

type OIDCProvider struct {
	ID                    uuid.UUID `json:"id"`
	OrganizationID        uuid.UUID `json:"organizationId"`
	Name                  string    `json:"name"`
	Issuer                string    `json:"issuer"`
	ClientID              string    `json:"clientId"`
	EncryptedClientSecret string    `json:"-"`
	Domains               []string  `json:"domains"`
	Scopes                []string  `json:"scopes"`
	DefaultRole           string    `json:"defaultRole"`
	Enabled               bool      `json:"enabled"`
}

type SAMLProvider struct {
	ID                          uuid.UUID  `json:"id"`
	OrganizationID              uuid.UUID  `json:"organizationId"`
	Name                        string     `json:"name"`
	IDPMetadata                 string     `json:"-"`
	CertificatePEM              string     `json:"-"`
	EncryptedPrivateKey         string     `json:"-"`
	PendingCertificatePEM       string     `json:"-"`
	PendingEncryptedPrivateKey  string     `json:"-"`
	Domains                     []string   `json:"domains"`
	EmailAttribute              string     `json:"emailAttribute"`
	NameAttribute               string     `json:"nameAttribute"`
	DefaultRole                 string     `json:"defaultRole"`
	AllowIDPInitiated           bool       `json:"allowIdpInitiated"`
	Enabled                     bool       `json:"enabled"`
	SPCertificateNotAfter       *time.Time `json:"spCertificateNotAfter,omitempty"`
	IDPCertificateNotAfter      *time.Time `json:"idpCertificateNotAfter,omitempty"`
	CertificateConfigurationOK  bool       `json:"certificateConfigurationOk"`
	PendingCertificateNotAfter  *time.Time `json:"pendingCertificateNotAfter,omitempty"`
	PendingCertificateCreatedAt *time.Time `json:"pendingCertificateCreatedAt,omitempty"`
}

type DatabaseBackup struct {
	ID                 uuid.UUID  `json:"id"`
	DatabaseInstanceID uuid.UUID  `json:"databaseInstanceId"`
	Status             string     `json:"status"`
	Format             string     `json:"format"`
	Path               string     `json:"-"`
	SizeBytes          *int64     `json:"sizeBytes,omitempty"`
	SHA256             string     `json:"sha256,omitempty"`
	Encrypted          bool       `json:"encrypted"`
	PlaintextSHA256    string     `json:"plaintextSha256,omitempty"`
	EncryptedDataKey   string     `json:"-"`
	DestinationID      *uuid.UUID `json:"destinationId,omitempty"`
	ObjectKey          string     `json:"objectKey,omitempty"`
	Error              string     `json:"error,omitempty"`
	CreatedAt          time.Time  `json:"createdAt"`
	StartedAt          *time.Time `json:"startedAt,omitempty"`
	FinishedAt         *time.Time `json:"finishedAt,omitempty"`
}
type DatabaseRestore struct {
	ID               uuid.UUID  `json:"id"`
	DatabaseBackupID uuid.UUID  `json:"databaseBackupId"`
	Status           string     `json:"status"`
	Kind             string     `json:"kind"`
	Error            string     `json:"error,omitempty"`
	CreatedAt        time.Time  `json:"createdAt"`
	StartedAt        *time.Time `json:"startedAt,omitempty"`
	FinishedAt       *time.Time `json:"finishedAt,omitempty"`
}
type BackupPolicy struct {
	ID                 uuid.UUID  `json:"id"`
	DatabaseInstanceID uuid.UUID  `json:"databaseInstanceId"`
	IntervalSeconds    int        `json:"intervalSeconds"`
	RetentionCount     int        `json:"retentionCount"`
	Enabled            bool       `json:"enabled"`
	VerifyRestore      bool       `json:"verifyRestore"`
	DestinationID      *uuid.UUID `json:"destinationId,omitempty"`
	NextRunAt          time.Time  `json:"nextRunAt"`
	LastRunAt          *time.Time `json:"lastRunAt,omitempty"`
	CreatedAt          time.Time  `json:"createdAt"`
	UpdatedAt          time.Time  `json:"updatedAt"`
}
type BackupDestination struct {
	ID                   uuid.UUID `json:"id"`
	OrganizationID       uuid.UUID `json:"organizationId"`
	Name                 string    `json:"name"`
	Endpoint             string    `json:"endpoint"`
	Region               string    `json:"region"`
	Bucket               string    `json:"bucket"`
	Prefix               string    `json:"prefix"`
	UseTLS               bool      `json:"useTls"`
	EncryptedCredentials string    `json:"-"`
	CreatedAt            time.Time `json:"createdAt"`
	UpdatedAt            time.Time `json:"updatedAt"`
}
type ApplicationSource struct {
	ComposeServiceID     uuid.UUID            `json:"composeServiceId"`
	SourceType           string               `json:"sourceType"`
	RepositoryURL        string               `json:"repositoryUrl"`
	GitRef               string               `json:"gitRef"`
	ContextDirectory     string               `json:"contextDirectory"`
	Dockerfile           string               `json:"dockerfile"`
	BuildType            string               `json:"buildType"`
	BuilderImage         string               `json:"builderImage,omitempty"`
	OutputDirectory      string               `json:"outputDirectory,omitempty"`
	BuildTarget          string               `json:"buildTarget,omitempty"`
	EnableSubmodules     bool                 `json:"enableSubmodules"`
	HasBuildArguments    bool                 `json:"hasBuildArguments"`
	HasBuildSecrets      bool                 `json:"hasBuildSecrets"`
	EncryptedBuildConfig string               `json:"-"`
	BuildArguments       map[string]string    `json:"-"`
	BuildSecrets         map[string]string    `json:"-"`
	TargetService        string               `json:"targetService"`
	RegistryImage        string               `json:"registryImage"`
	GitCredentialID      *uuid.UUID           `json:"gitCredentialId,omitempty"`
	RegistryCredentialID *uuid.UUID           `json:"registryCredentialId,omitempty"`
	StatusProvider       string               `json:"statusProvider,omitempty"`
	StatusCredentialID   *uuid.UUID           `json:"statusCredentialId,omitempty"`
	StatusContext        string               `json:"statusContext,omitempty"`
	Artifact             *ApplicationArtifact `json:"artifact,omitempty"`
	UpdatedAt            time.Time            `json:"updatedAt"`
}

type ApplicationArtifact struct {
	ComposeServiceID uuid.UUID `json:"-"`
	EncryptedArchive string    `json:"-"`
	Filename         string    `json:"filename"`
	SHA256           string    `json:"sha256"`
	CompressedSize   int64     `json:"compressedSize"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

type ApplicationBuildConfig struct {
	Arguments map[string]string `json:"arguments,omitempty"`
	Secrets   map[string]string `json:"secrets,omitempty"`
}
type SourceCredential struct {
	ID              uuid.UUID `json:"id"`
	OrganizationID  uuid.UUID `json:"organizationId"`
	Kind            string    `json:"kind"`
	Name            string    `json:"name"`
	Server          string    `json:"server"`
	Username        string    `json:"username"`
	EncryptedSecret string    `json:"-"`
	CreatedAt       time.Time `json:"createdAt"`
	UpdatedAt       time.Time `json:"updatedAt"`
}

type WebhookIntegration struct {
	ID               uuid.UUID `json:"id"`
	OrganizationID   uuid.UUID `json:"organizationId"`
	ComposeServiceID uuid.UUID `json:"composeServiceId"`
	Name             string    `json:"name"`
	Provider         string    `json:"provider"`
	Branch           string    `json:"branch"`
	EncryptedSecret  string    `json:"-"`
	Enabled          bool      `json:"enabled"`
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

type DeployToken struct {
	ID               uuid.UUID  `json:"id"`
	ComposeServiceID uuid.UUID  `json:"composeServiceId"`
	Name             string     `json:"name"`
	ExpiresAt        time.Time  `json:"expiresAt"`
	LastUsedAt       *time.Time `json:"lastUsedAt,omitempty"`
	RevokedAt        *time.Time `json:"revokedAt,omitempty"`
	CreatedAt        time.Time  `json:"createdAt"`
}

type ServiceAccount struct {
	ID             uuid.UUID  `json:"id"`
	OrganizationID uuid.UUID  `json:"organizationId"`
	Name           string     `json:"name"`
	Role           string     `json:"role"`
	Enabled        bool       `json:"enabled"`
	TokenExpiresAt *time.Time `json:"tokenExpiresAt,omitempty"`
	LastUsedAt     *time.Time `json:"lastUsedAt,omitempty"`
	CreatedAt      time.Time  `json:"createdAt"`
	UpdatedAt      time.Time  `json:"updatedAt"`
}

func (s *Store) HasUsers(ctx context.Context) (bool, error) {
	var exists bool
	err := s.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users)`).Scan(&exists)
	return exists, err
}

func (s *Store) Bootstrap(ctx context.Context, email, passwordHash, orgName, slug string) (Principal, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Principal{}, err
	}
	defer tx.Rollback(ctx)
	var count int
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(721046139)`); err != nil {
		return Principal{}, err
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&count); err != nil {
		return Principal{}, err
	}
	if count != 0 {
		return Principal{}, ErrAlreadyBootstrapped
	}
	userID, orgID := uuid.New(), uuid.New()
	if _, err := tx.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,$3)`, userID, strings.ToLower(email), passwordHash); err != nil {
		return Principal{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,$2,$3)`, orgID, orgName, slug); err != nil {
		return Principal{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')`, orgID, userID); err != nil {
		return Principal{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Principal{}, err
	}
	return Principal{UserID: userID, Email: strings.ToLower(email), OrganizationID: orgID, Organization: orgName, Role: "owner"}, nil
}

func (s *Store) PasswordLogin(ctx context.Context, email string) (uuid.UUID, string, error) {
	var id uuid.UUID
	var hash string
	err := s.Pool.QueryRow(ctx, `SELECT id,password_hash FROM users WHERE email=$1 AND disabled_at IS NULL`, strings.ToLower(email)).Scan(&id, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, "", ErrNotFound
	}
	return id, hash, err
}

func (s *Store) LocalLoginAllowed(ctx context.Context, userID uuid.UUID) (bool, error) {
	var allowed bool
	err := s.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM memberships m LEFT JOIN organization_auth_settings a ON a.organization_id=m.organization_id WHERE m.user_id=$1 AND (m.role='owner' OR NOT COALESCE(a.require_sso,false)))`, userID).Scan(&allowed)
	return allowed, err
}

func (s *Store) CreateSession(ctx context.Context, userID uuid.UUID, tokenHash []byte, expires time.Time) error {
	_, err := s.CreateSessionWithMetadata(ctx, userID, nil, tokenHash, expires, "local", "", "")
	return err
}

func (s *Store) CreateSessionWithMetadata(ctx context.Context, userID uuid.UUID, organizationID *uuid.UUID, tokenHash []byte, expires time.Time, authMethod, userAgent, ipAddress string) (uuid.UUID, error) {
	id := uuid.New()
	_, err := s.Pool.Exec(ctx, `INSERT INTO sessions(id,user_id,organization_id,token_hash,expires_at,auth_method,user_agent,ip_address) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, id, userID, organizationID, tokenHash, expires, authMethod, userAgent, ipAddress)
	return id, err
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash []byte) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM sessions WHERE token_hash=$1`, tokenHash)
	return err
}

func (s *Store) Authenticate(ctx context.Context, tokenHash []byte, organizationID *uuid.UUID) (Principal, error) {
	query := `SELECT u.id,s.id,s.organization_id,u.email,o.id,o.name,m.role FROM sessions s JOIN users u ON u.id=s.user_id JOIN memberships m ON m.user_id=u.id JOIN organizations o ON o.id=m.organization_id LEFT JOIN organization_auth_settings a ON a.organization_id=o.id WHERE s.token_hash=$1 AND s.expires_at>now() AND u.disabled_at IS NULL AND (s.organization_id IS NULL OR s.organization_id=o.id) AND (m.role='owner' OR NOT COALESCE(a.require_sso,false) OR s.auth_method<>'local')`
	args := []any{tokenHash}
	if organizationID != nil {
		query += ` AND o.id=$2`
		args = append(args, *organizationID)
	}
	query += ` ORDER BY m.created_at LIMIT 1`
	var p Principal
	if err := s.Pool.QueryRow(ctx, query, args...).Scan(&p.UserID, &p.SessionID, &p.SessionOrganizationID, &p.Email, &p.OrganizationID, &p.Organization, &p.Role); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return Principal{}, err
		}
		serviceQuery := `SELECT a.id,a.name,o.id,o.name,a.role FROM service_account_tokens t JOIN service_accounts a ON a.id=t.service_account_id JOIN organizations o ON o.id=a.organization_id WHERE t.token_hash=$1 AND t.revoked_at IS NULL AND t.expires_at>now() AND a.enabled`
		serviceArgs := []any{tokenHash}
		if organizationID != nil {
			serviceQuery += ` AND o.id=$2`
			serviceArgs = append(serviceArgs, *organizationID)
		}
		var serviceAccountID uuid.UUID
		if err = s.Pool.QueryRow(ctx, serviceQuery, serviceArgs...).Scan(&serviceAccountID, &p.Email, &p.OrganizationID, &p.Organization, &p.Role); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return Principal{}, ErrNotFound
			}
			return Principal{}, err
		}
		p.Email = "service-account:" + p.Email
		p.ServiceAccountID = &serviceAccountID
		_, _ = s.Pool.Exec(ctx, `UPDATE service_account_tokens SET last_used_at=now() WHERE token_hash=$1`, tokenHash)
		return p, nil
	}
	_, _ = s.Pool.Exec(ctx, `UPDATE sessions SET last_seen_at=now() WHERE token_hash=$1`, tokenHash)
	return p, nil
}

func (s *Store) CreateServiceAccount(ctx context.Context, organizationID, creatorID uuid.UUID, name, role string, tokenHash []byte, expiresAt time.Time) (ServiceAccount, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ServiceAccount{}, err
	}
	defer tx.Rollback(ctx)
	item, err := createServiceAccountTx(ctx, tx, organizationID, &creatorID, name, role, tokenHash, expiresAt)
	if err != nil {
		return ServiceAccount{}, err
	}
	return item, tx.Commit(ctx)
}

func (s *Store) CreateServiceAccountWithAudit(ctx context.Context, principal Principal, name, role string, tokenHash []byte, expiresAt time.Time, remoteAddr string) (ServiceAccount, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ServiceAccount{}, err
	}
	defer tx.Rollback(ctx)
	var creatorID *uuid.UUID
	if principal.UserID != uuid.Nil {
		creatorID = &principal.UserID
	}
	item, err := createServiceAccountTx(ctx, tx, principal.OrganizationID, creatorID, name, role, tokenHash, expiresAt)
	if err != nil {
		return ServiceAccount{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "service_account.create", "service_account", item.ID.String(), remoteAddr, map[string]any{"role": item.Role, "expiresAt": expiresAt}); err != nil {
		return ServiceAccount{}, err
	}
	return item, tx.Commit(ctx)
}

func createServiceAccountTx(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, creatorID *uuid.UUID, name, role string, tokenHash []byte, expiresAt time.Time) (ServiceAccount, error) {
	item := ServiceAccount{ID: uuid.New(), OrganizationID: organizationID, Name: name, Role: role, Enabled: true, TokenExpiresAt: &expiresAt}
	err := tx.QueryRow(ctx, `INSERT INTO service_accounts(id,organization_id,name,role,created_by) SELECT $1,o.id,$3,$4,$5 FROM organizations o WHERE o.id=$2 RETURNING created_at,updated_at`, item.ID, organizationID, name, role, creatorID).Scan(&item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ServiceAccount{}, ErrNotFound
	}
	if err != nil {
		return ServiceAccount{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO service_account_tokens(id,service_account_id,token_hash,expires_at) VALUES($1,$2,$3,$4)`, uuid.New(), item.ID, tokenHash, expiresAt); err != nil {
		return ServiceAccount{}, err
	}
	return item, nil
}

func (s *Store) ListServiceAccounts(ctx context.Context, organizationID uuid.UUID) ([]ServiceAccount, error) {
	rows, err := s.Pool.Query(ctx, `SELECT a.id,a.organization_id,a.name,a.role,a.enabled,t.expires_at,t.last_used_at,a.created_at,a.updated_at FROM service_accounts a LEFT JOIN LATERAL (SELECT expires_at,last_used_at FROM service_account_tokens WHERE service_account_id=a.id AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1) t ON true WHERE a.organization_id=$1 ORDER BY a.name`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ServiceAccount{}
	for rows.Next() {
		var item ServiceAccount
		if err = rows.Scan(&item.ID, &item.OrganizationID, &item.Name, &item.Role, &item.Enabled, &item.TokenExpiresAt, &item.LastUsedAt, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) RotateServiceAccountToken(ctx context.Context, organizationID, id uuid.UUID, tokenHash []byte, expiresAt time.Time) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = rotateServiceAccountTokenTx(ctx, tx, organizationID, id, tokenHash, expiresAt); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) RotateServiceAccountTokenWithAudit(ctx context.Context, principal Principal, id uuid.UUID, tokenHash []byte, expiresAt time.Time, remoteAddr string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = rotateServiceAccountTokenTx(ctx, tx, principal.OrganizationID, id, tokenHash, expiresAt); err != nil {
		return err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "service_account.rotate", "service_account", id.String(), remoteAddr, map[string]any{"expiresAt": expiresAt}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func rotateServiceAccountTokenTx(ctx context.Context, tx pgx.Tx, organizationID, id uuid.UUID, tokenHash []byte, expiresAt time.Time) error {
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT true FROM service_accounts WHERE id=$1 AND organization_id=$2 AND enabled FOR UPDATE`, id, organizationID).Scan(&exists); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE service_account_tokens SET revoked_at=now() WHERE service_account_id=$1 AND revoked_at IS NULL`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO service_account_tokens(id,service_account_id,token_hash,expires_at) VALUES($1,$2,$3,$4)`, uuid.New(), id, tokenHash, expiresAt); err != nil {
		return err
	}
	return nil
}

func (s *Store) DisableServiceAccount(ctx context.Context, organizationID, id uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = disableServiceAccountTx(ctx, tx, organizationID, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) DisableServiceAccountWithAudit(ctx context.Context, principal Principal, id uuid.UUID, remoteAddr string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = disableServiceAccountTx(ctx, tx, principal.OrganizationID, id); err != nil {
		return err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "service_account.disable", "service_account", id.String(), remoteAddr, nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func disableServiceAccountTx(ctx context.Context, tx pgx.Tx, organizationID, id uuid.UUID) error {
	tag, err := tx.Exec(ctx, `UPDATE service_accounts SET enabled=false,updated_at=now() WHERE id=$1 AND organization_id=$2`, id, organizationID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err = tx.Exec(ctx, `UPDATE service_account_tokens SET revoked_at=now() WHERE service_account_id=$1 AND revoked_at IS NULL`, id); err != nil {
		return err
	}
	return nil
}

func (s *Store) ListSessions(ctx context.Context, userID, currentID uuid.UUID, organizationID *uuid.UUID) ([]Session, error) {
	query := `SELECT id,organization_id,auth_method,user_agent,ip_address,expires_at,created_at,last_seen_at,id=$2 FROM sessions WHERE user_id=$1 AND expires_at>now()`
	args := []any{userID, currentID}
	if organizationID != nil {
		query += ` AND organization_id=$3`
		args = append(args, *organizationID)
	}
	query += ` ORDER BY last_seen_at DESC`
	rows, err := s.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Session{}
	for rows.Next() {
		var item Session
		if err = rows.Scan(&item.ID, &item.OrganizationID, &item.AuthMethod, &item.UserAgent, &item.IPAddress, &item.ExpiresAt, &item.CreatedAt, &item.LastSeenAt, &item.Current); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) RevokeSession(ctx context.Context, userID, sessionID uuid.UUID, organizationID *uuid.UUID) error {
	query := `DELETE FROM sessions WHERE id=$1 AND user_id=$2`
	args := []any{sessionID, userID}
	if organizationID != nil {
		query += ` AND organization_id=$3`
		args = append(args, *organizationID)
	}
	tag, err := s.Pool.Exec(ctx, query, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) RevokeOtherSessions(ctx context.Context, userID, currentID uuid.UUID, organizationID *uuid.UUID) (int64, error) {
	query := `DELETE FROM sessions WHERE user_id=$1 AND id<>$2`
	args := []any{userID, currentID}
	if organizationID != nil {
		query += ` AND organization_id=$3`
		args = append(args, *organizationID)
	}
	tag, err := s.Pool.Exec(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (s *Store) GetOrganizationAuthSettings(ctx context.Context, organizationID uuid.UUID) (OrganizationAuthSettings, error) {
	var settings OrganizationAuthSettings
	err := s.Pool.QueryRow(ctx, `SELECT COALESCE(a.require_sso,false),COALESCE(a.updated_at,o.created_at) FROM organizations o LEFT JOIN organization_auth_settings a ON a.organization_id=o.id WHERE o.id=$1`, organizationID).Scan(&settings.RequireSSO, &settings.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return OrganizationAuthSettings{}, ErrNotFound
	}
	return settings, err
}

func (s *Store) SetOrganizationAuthSettings(ctx context.Context, organizationID uuid.UUID, requireSSO bool) (OrganizationAuthSettings, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return OrganizationAuthSettings{}, err
	}
	defer tx.Rollback(ctx)
	settings, err := setOrganizationAuthSettingsTx(ctx, tx, organizationID, requireSSO)
	if err != nil {
		return OrganizationAuthSettings{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return OrganizationAuthSettings{}, err
	}
	return settings, nil
}

func (s *Store) SetOrganizationAuthSettingsWithAudit(ctx context.Context, principal Principal, requireSSO bool, remoteAddr string) (OrganizationAuthSettings, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return OrganizationAuthSettings{}, err
	}
	defer tx.Rollback(ctx)
	settings, err := setOrganizationAuthSettingsTx(ctx, tx, principal.OrganizationID, requireSSO)
	if err != nil {
		return OrganizationAuthSettings{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "sso.policy.update", "organization", principal.OrganizationID.String(), remoteAddr, map[string]any{"requireSso": settings.RequireSSO}); err != nil {
		return OrganizationAuthSettings{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return OrganizationAuthSettings{}, err
	}
	return settings, nil
}

func setOrganizationAuthSettingsTx(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, requireSSO bool) (OrganizationAuthSettings, error) {
	var organizationExists bool
	if err := tx.QueryRow(ctx, `SELECT true FROM organizations WHERE id=$1 FOR UPDATE`, organizationID).Scan(&organizationExists); errors.Is(err, pgx.ErrNoRows) {
		return OrganizationAuthSettings{}, ErrNotFound
	} else if err != nil {
		return OrganizationAuthSettings{}, err
	}
	var settings OrganizationAuthSettings
	err := tx.QueryRow(ctx, `INSERT INTO organization_auth_settings(organization_id,require_sso)
		SELECT o.id,$2 FROM organizations o WHERE o.id=$1 AND (NOT $2 OR EXISTS(SELECT 1 FROM oidc_providers WHERE organization_id=$1 AND enabled) OR EXISTS(SELECT 1 FROM saml_providers WHERE organization_id=$1 AND enabled))
		ON CONFLICT(organization_id) DO UPDATE SET require_sso=excluded.require_sso,updated_at=now()
		RETURNING require_sso,updated_at`, organizationID, requireSSO).Scan(&settings.RequireSSO, &settings.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		if requireSSO {
			return OrganizationAuthSettings{}, ErrSSOProviderRequired
		}
		return OrganizationAuthSettings{}, ErrNotFound
	}
	if err != nil {
		return OrganizationAuthSettings{}, err
	}
	return settings, nil
}

func (s *Store) CreateProject(ctx context.Context, organizationID uuid.UUID, name, slug, description string) (Project, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Project{}, err
	}
	defer tx.Rollback(ctx)
	if err = s.enforcePolicy(ctx, tx, organizationID, nil, nil, "projects"); err != nil {
		return Project{}, err
	}
	p := Project{ID: uuid.New(), OrganizationID: organizationID, Name: name, Slug: slug, Description: description}
	p.Tags = []Tag{}
	err = tx.QueryRow(ctx, `INSERT INTO projects(id,organization_id,name,slug,description) VALUES($1,$2,$3,$4,$5) RETURNING created_at`, p.ID, p.OrganizationID, p.Name, p.Slug, p.Description).Scan(&p.CreatedAt)
	if err != nil {
		return Project{}, err
	}
	return p, tx.Commit(ctx)
}

func (s *Store) ListProjects(ctx context.Context, organizationID uuid.UUID) ([]Project, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id,organization_id,name,slug,description,created_at FROM projects WHERE organization_id=$1 ORDER BY name`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Project{}
	for rows.Next() {
		var p Project
		if err := rows.Scan(&p.ID, &p.OrganizationID, &p.Name, &p.Slug, &p.Description, &p.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, p)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return items, nil
	}
	byID := make(map[uuid.UUID]*Project, len(items))
	projectIDs := make([]uuid.UUID, 0, len(items))
	for index := range items {
		items[index].Tags = []Tag{}
		byID[items[index].ID] = &items[index]
		projectIDs = append(projectIDs, items[index].ID)
	}
	tagRows, err := s.Pool.Query(ctx, `SELECT pt.project_id,t.id,t.organization_id,t.name,t.color,t.created_at,t.updated_at
		FROM project_tags pt JOIN tags t ON t.id=pt.tag_id
		WHERE pt.project_id=ANY($1::uuid[]) AND t.organization_id=$2 ORDER BY lower(t.name),t.id`, projectIDs, organizationID)
	if err != nil {
		return nil, err
	}
	defer tagRows.Close()
	for tagRows.Next() {
		var projectID uuid.UUID
		var tag Tag
		if err = tagRows.Scan(&projectID, &tag.ID, &tag.OrganizationID, &tag.Name, &tag.Color, &tag.CreatedAt, &tag.UpdatedAt); err != nil {
			return nil, err
		}
		if project := byID[projectID]; project != nil {
			project.Tags = append(project.Tags, tag)
		}
	}
	return items, tagRows.Err()
}

func (s *Store) GetProject(ctx context.Context, organizationID, projectID uuid.UUID) (Project, error) {
	var item Project
	err := s.Pool.QueryRow(ctx, `SELECT id,organization_id,name,slug,description,created_at FROM projects WHERE id=$1 AND organization_id=$2`, projectID, organizationID).Scan(&item.ID, &item.OrganizationID, &item.Name, &item.Slug, &item.Description, &item.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Project{}, ErrNotFound
	}
	if err == nil {
		item.Tags, err = s.ListProjectTags(ctx, organizationID, projectID)
	}
	return item, err
}

type deletionServiceChild struct {
	id       uuid.UUID
	stack    string
	deleting bool
}

func activeChildOperations(ctx context.Context, tx pgx.Tx, serviceIDs, databaseIDs []uuid.UUID) (bool, error) {
	if len(serviceIDs) == 0 && len(databaseIDs) == 0 {
		return false, nil
	}
	serviceKeys := make([]string, 0, len(serviceIDs))
	for _, serviceID := range serviceIDs {
		serviceKeys = append(serviceKeys, "service:"+serviceID.String())
	}
	databaseKeys := make([]string, 0, len(databaseIDs))
	for _, databaseID := range databaseIDs {
		databaseKeys = append(databaseKeys, "database:"+databaseID.String())
	}
	var busy bool
	err := tx.QueryRow(ctx, `SELECT
		EXISTS(SELECT 1 FROM jobs job WHERE job.status IN ('pending','running') AND (job.resource_key=ANY($2) OR job.resource_key=ANY($4) OR job.resource_key IN (SELECT 'database:' || database.id::text FROM database_instances database WHERE database.compose_service_id=ANY($1))))
		OR EXISTS(SELECT 1 FROM deployments deployment WHERE deployment.compose_service_id=ANY($1) AND deployment.status IN ('queued','running'))
		OR EXISTS(SELECT 1 FROM volume_backups backup WHERE backup.compose_service_id=ANY($1) AND backup.status IN ('queued','running'))
		OR EXISTS(SELECT 1 FROM volume_restores restore JOIN volume_backups backup ON backup.id=restore.volume_backup_id WHERE backup.compose_service_id=ANY($1) AND restore.status IN ('queued','running'))
		OR EXISTS(SELECT 1 FROM database_backups backup JOIN database_instances database ON database.id=backup.database_instance_id WHERE (database.compose_service_id=ANY($1) OR database.id=ANY($3)) AND backup.status IN ('queued','running'))
		OR EXISTS(SELECT 1 FROM database_restores restore JOIN database_backups backup ON backup.id=restore.database_backup_id JOIN database_instances database ON database.id=backup.database_instance_id WHERE (database.compose_service_id=ANY($1) OR database.id=ANY($3)) AND restore.status IN ('queued','running'))
		OR EXISTS(SELECT 1 FROM database_migrations migration JOIN database_instances database ON database.id=migration.database_instance_id WHERE (database.compose_service_id=ANY($1) OR database.id=ANY($3)) AND migration.status IN ('queued','running'))`, serviceIDs, serviceKeys, databaseIDs, databaseKeys).Scan(&busy)
	return busy, err
}

func activeServiceOperations(ctx context.Context, tx pgx.Tx, serviceIDs []uuid.UUID) (bool, error) {
	return activeChildOperations(ctx, tx, serviceIDs, nil)
}

func (s *Store) DeleteProject(ctx context.Context, organizationID, projectID uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var deleting bool
	err = tx.QueryRow(ctx, `SELECT deletion_requested_at IS NOT NULL FROM projects WHERE id=$1 AND organization_id=$2 FOR UPDATE`, projectID, organizationID).Scan(&deleting)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT id,deletion_requested_at IS NOT NULL FROM environments WHERE project_id=$1 ORDER BY id FOR UPDATE`, projectID)
	if err != nil {
		return err
	}
	environments := map[uuid.UUID]bool{}
	environmentIDs := []uuid.UUID{}
	for rows.Next() {
		var environmentID uuid.UUID
		var environmentDeleting bool
		if err = rows.Scan(&environmentID, &environmentDeleting); err != nil {
			rows.Close()
			return err
		}
		environments[environmentID] = environmentDeleting
		environmentIDs = append(environmentIDs, environmentID)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	databaseIDs := []uuid.UUID{}
	if len(environmentIDs) > 0 {
		rows, err = tx.Query(ctx, `SELECT id FROM database_instances WHERE environment_id=ANY($1) ORDER BY environment_id,id FOR UPDATE`, environmentIDs)
		if err != nil {
			return err
		}
		for rows.Next() {
			var databaseID uuid.UUID
			if err = rows.Scan(&databaseID); err != nil {
				rows.Close()
				return err
			}
			databaseIDs = append(databaseIDs, databaseID)
		}
		rows.Close()
		if err = rows.Err(); err != nil {
			return err
		}
	}
	services := []deletionServiceChild{}
	serviceIDs := []uuid.UUID{}
	if len(environmentIDs) > 0 {
		rows, err = tx.Query(ctx, `SELECT id,stack_name,deletion_requested_at IS NOT NULL FROM compose_services WHERE environment_id=ANY($1) ORDER BY environment_id,id FOR UPDATE`, environmentIDs)
		if err != nil {
			return err
		}
		for rows.Next() {
			var child deletionServiceChild
			if err = rows.Scan(&child.id, &child.stack, &child.deleting); err != nil {
				rows.Close()
				return err
			}
			services = append(services, child)
			serviceIDs = append(serviceIDs, child.id)
		}
		rows.Close()
		if err = rows.Err(); err != nil {
			return err
		}
	}
	busy, err := activeChildOperations(ctx, tx, serviceIDs, databaseIDs)
	if err != nil {
		return err
	}
	if busy {
		return ErrBusy
	}
	if !deleting {
		_, err = tx.Exec(ctx, `UPDATE projects SET deletion_requested_at=now() WHERE id=$1`, projectID)
	}
	if err != nil {
		return err
	}
	for _, child := range services {
		if !child.deleting {
			_, err = tx.Exec(ctx, `UPDATE compose_services SET deletion_requested_at=now() WHERE id=$1`, child.id)
		}
		if err != nil {
			return err
		}
		payload, _ := json.Marshal(map[string]string{"serviceId": child.id.String(), "stackName": child.stack})
		if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,max_attempts) SELECT $1,'delete.compose',$2,10 WHERE NOT EXISTS(SELECT 1 FROM jobs WHERE kind='delete.compose' AND payload->>'serviceId'=$3 AND status IN ('pending','running'))`, uuid.New(), payload, child.id.String()); err != nil {
			return err
		}
	}
	for environmentID, environmentDeleting := range environments {
		if !environmentDeleting {
			_, err = tx.Exec(ctx, `UPDATE environments SET deletion_requested_at=now() WHERE id=$1`, environmentID)
		}
		if err != nil {
			return err
		}
		payload, _ := json.Marshal(map[string]string{"environmentId": environmentID.String()})
		if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,max_attempts) SELECT $1,'delete.environment',$2,50 WHERE NOT EXISTS(SELECT 1 FROM jobs WHERE kind='delete.environment' AND payload->>'environmentId'=$3 AND status IN ('pending','running'))`, uuid.New(), payload, environmentID.String()); err != nil {
			return err
		}
	}
	payload, _ := json.Marshal(map[string]string{"projectId": projectID.String()})
	if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,max_attempts) SELECT $1,'delete.project',$2,50 WHERE NOT EXISTS(SELECT 1 FROM jobs WHERE kind='delete.project' AND payload->>'projectId'=$3 AND status IN ('pending','running'))`, uuid.New(), payload, projectID.String()); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) CreateEnvironment(ctx context.Context, organizationID, projectID uuid.UUID, name, slug string) (Environment, error) {
	return s.CreateEnvironmentWithPlacement(ctx, organizationID, projectID, name, slug, nil, nil, 0, 0, 0)
}

func (s *Store) CreateEnvironmentOnCluster(ctx context.Context, organizationID, projectID uuid.UUID, name, slug string, clusterID *uuid.UUID) (Environment, error) {
	return s.CreateEnvironmentWithPlacement(ctx, organizationID, projectID, name, slug, clusterID, nil, 0, 0, 0)
}

func (s *Store) CreateEnvironmentWithPlacement(ctx context.Context, organizationID, projectID uuid.UUID, name, slug string, clusterID *uuid.UUID, selector map[string]string, minimumNodes int, minimumNanoCPUs, minimumMemoryBytes int64) (Environment, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Environment{}, err
	}
	defer tx.Rollback(ctx)
	var lockedProjectID uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT id FROM projects WHERE id=$1 AND organization_id=$2 AND deletion_requested_at IS NULL FOR UPDATE`, projectID, organizationID).Scan(&lockedProjectID); errors.Is(err, pgx.ErrNoRows) {
		return Environment{}, ErrNotFound
	} else if err != nil {
		return Environment{}, err
	}
	if err = s.validatePolicyScope(ctx, tx, organizationID, "project", projectID); err != nil {
		return Environment{}, err
	}
	if err = s.enforcePolicy(ctx, tx, organizationID, &projectID, nil, "environments"); err != nil {
		return Environment{}, err
	}
	selectorJSON, err := json.Marshal(selector)
	if err != nil {
		return Environment{}, err
	}
	if clusterID == nil && (len(selector) > 0 || minimumNodes > 0 || minimumNanoCPUs > 0 || minimumMemoryBytes > 0) {
		var selected uuid.UUID
		err = tx.QueryRow(ctx, `SELECT c.id FROM clusters c WHERE c.organization_id=$1 AND c.state='active' AND c.last_seen_at>now()-interval '2 minutes' AND NOT COALESCE(now()>=c.maintenance_starts_at AND now()<c.maintenance_ends_at,false) AND c.labels@>$2::jsonb AND CASE WHEN jsonb_typeof(c.capacity->'schedulableNodes')='number' THEN (c.capacity->>'schedulableNodes')::integer WHEN jsonb_typeof(c.capacity->'nodes')='number' THEN (c.capacity->>'nodes')::integer ELSE 0 END >=$3 AND CASE WHEN jsonb_typeof(c.capacity->'nanoCpus')='number' THEN (c.capacity->>'nanoCpus')::bigint ELSE 0 END >=$4 AND CASE WHEN jsonb_typeof(c.capacity->'memoryBytes')='number' THEN (c.capacity->>'memoryBytes')::bigint ELSE 0 END >=$5 ORDER BY (SELECT count(*) FROM environments assigned WHERE assigned.cluster_id=c.id),CASE WHEN jsonb_typeof(c.capacity->'schedulableNodes')='number' THEN (c.capacity->>'schedulableNodes')::integer WHEN jsonb_typeof(c.capacity->'nodes')='number' THEN (c.capacity->>'nodes')::integer ELSE 0 END DESC,c.id LIMIT 1 FOR UPDATE OF c`, organizationID, selectorJSON, minimumNodes, minimumNanoCPUs, minimumMemoryBytes).Scan(&selected)
		if errors.Is(err, pgx.ErrNoRows) {
			return Environment{}, ErrNoCapacity
		}
		if err != nil {
			return Environment{}, err
		}
		clusterID = &selected
	}
	if clusterID != nil {
		var clusterExists bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM clusters WHERE id=$1 AND organization_id=$2 AND state='active' AND last_seen_at>now()-interval '2 minutes' AND NOT COALESCE(now()>=maintenance_starts_at AND now()<maintenance_ends_at,false) AND ($3::jsonb='{}'::jsonb OR labels@>$3::jsonb) AND CASE WHEN jsonb_typeof(capacity->'schedulableNodes')='number' THEN (capacity->>'schedulableNodes')::integer WHEN jsonb_typeof(capacity->'nodes')='number' THEN (capacity->>'nodes')::integer ELSE 0 END >=$4 AND CASE WHEN jsonb_typeof(capacity->'nanoCpus')='number' THEN (capacity->>'nanoCpus')::bigint ELSE 0 END >=$5 AND CASE WHEN jsonb_typeof(capacity->'memoryBytes')='number' THEN (capacity->>'memoryBytes')::bigint ELSE 0 END >=$6)`, *clusterID, organizationID, selectorJSON, minimumNodes, minimumNanoCPUs, minimumMemoryBytes).Scan(&clusterExists); err != nil {
			return Environment{}, err
		}
		if !clusterExists {
			return Environment{}, ErrNoCapacity
		}
	}
	e := Environment{ID: uuid.New(), ProjectID: projectID, ClusterID: clusterID, PlacementSelector: selector, MinimumNodes: minimumNodes, MinimumNanoCPUs: minimumNanoCPUs, MinimumMemoryBytes: minimumMemoryBytes, Name: name, Slug: slug}
	err = tx.QueryRow(ctx, `INSERT INTO environments(id,project_id,cluster_id,name,slug,placement_selector,minimum_nodes,minimum_nano_cpus,minimum_memory_bytes) SELECT $1,p.id,$3,$4,$5,$7,$8,$9,$10 FROM projects p WHERE p.id=$2 AND p.organization_id=$6 AND p.deletion_requested_at IS NULL RETURNING created_at`, e.ID, projectID, clusterID, name, slug, organizationID, selectorJSON, minimumNodes, minimumNanoCPUs, minimumMemoryBytes).Scan(&e.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Environment{}, ErrNotFound
	}
	if err != nil {
		return Environment{}, err
	}
	return e, tx.Commit(ctx)
}

func (s *Store) ListEnvironments(ctx context.Context, organizationID, projectID uuid.UUID) ([]Environment, error) {
	rows, err := s.Pool.Query(ctx, `SELECT e.id,e.project_id,e.cluster_id,e.placement_selector,e.minimum_nodes,e.minimum_nano_cpus,e.minimum_memory_bytes,e.name,e.slug,e.created_at FROM environments e JOIN projects p ON p.id=e.project_id WHERE e.project_id=$1 AND p.organization_id=$2 ORDER BY e.name`, projectID, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Environment{}
	for rows.Next() {
		var item Environment
		if err := rows.Scan(&item.ID, &item.ProjectID, &item.ClusterID, &item.PlacementSelector, &item.MinimumNodes, &item.MinimumNanoCPUs, &item.MinimumMemoryBytes, &item.Name, &item.Slug, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) ListOrganizationEnvironments(ctx context.Context, organizationID uuid.UUID) ([]Environment, error) {
	rows, err := s.Pool.Query(ctx, `SELECT e.id,e.project_id,e.cluster_id,e.placement_selector,e.minimum_nodes,e.minimum_nano_cpus,e.minimum_memory_bytes,e.name,e.slug,e.created_at
		FROM environments e JOIN projects p ON p.id=e.project_id
		WHERE p.organization_id=$1 AND p.deletion_requested_at IS NULL AND e.deletion_requested_at IS NULL
		ORDER BY lower(p.name),lower(e.name),e.id`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Environment{}
	for rows.Next() {
		var item Environment
		if err = rows.Scan(&item.ID, &item.ProjectID, &item.ClusterID, &item.PlacementSelector, &item.MinimumNodes, &item.MinimumNanoCPUs, &item.MinimumMemoryBytes, &item.Name, &item.Slug, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) GetEnvironment(ctx context.Context, organizationID, environmentID uuid.UUID) (Environment, error) {
	var item Environment
	err := s.Pool.QueryRow(ctx, `SELECT e.id,e.project_id,e.cluster_id,e.placement_selector,e.minimum_nodes,e.minimum_nano_cpus,e.minimum_memory_bytes,e.name,e.slug,e.created_at FROM environments e JOIN projects p ON p.id=e.project_id WHERE e.id=$1 AND p.organization_id=$2`, environmentID, organizationID).Scan(&item.ID, &item.ProjectID, &item.ClusterID, &item.PlacementSelector, &item.MinimumNodes, &item.MinimumNanoCPUs, &item.MinimumMemoryBytes, &item.Name, &item.Slug, &item.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Environment{}, ErrNotFound
	}
	return item, err
}

func (s *Store) DeleteEnvironment(ctx context.Context, organizationID, environmentID uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var deleting bool
	err = tx.QueryRow(ctx, `SELECT e.deletion_requested_at IS NOT NULL FROM environments e JOIN projects p ON p.id=e.project_id WHERE e.id=$1 AND p.organization_id=$2 FOR UPDATE OF e`, environmentID, organizationID).Scan(&deleting)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	databaseIDs := []uuid.UUID{}
	rows, err := tx.Query(ctx, `SELECT id FROM database_instances WHERE environment_id=$1 ORDER BY id FOR UPDATE`, environmentID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var databaseID uuid.UUID
		if err = rows.Scan(&databaseID); err != nil {
			rows.Close()
			return err
		}
		databaseIDs = append(databaseIDs, databaseID)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	rows, err = tx.Query(ctx, `SELECT id,stack_name,deletion_requested_at IS NOT NULL FROM compose_services WHERE environment_id=$1 ORDER BY id FOR UPDATE`, environmentID)
	if err != nil {
		return err
	}
	services := []deletionServiceChild{}
	serviceIDs := []uuid.UUID{}
	for rows.Next() {
		var child deletionServiceChild
		if err = rows.Scan(&child.id, &child.stack, &child.deleting); err != nil {
			rows.Close()
			return err
		}
		services = append(services, child)
		serviceIDs = append(serviceIDs, child.id)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	busy, err := activeChildOperations(ctx, tx, serviceIDs, databaseIDs)
	if err != nil {
		return err
	}
	if busy {
		return ErrBusy
	}
	if !deleting {
		_, err = tx.Exec(ctx, `UPDATE environments SET deletion_requested_at=now() WHERE id=$1`, environmentID)
	}
	if err != nil {
		return err
	}
	for _, child := range services {
		if !child.deleting {
			_, err = tx.Exec(ctx, `UPDATE compose_services SET deletion_requested_at=now() WHERE id=$1`, child.id)
		}
		if err != nil {
			return err
		}
		payload, _ := json.Marshal(map[string]string{"serviceId": child.id.String(), "stackName": child.stack})
		if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,max_attempts) SELECT $1,'delete.compose',$2,10 WHERE NOT EXISTS(SELECT 1 FROM jobs WHERE kind='delete.compose' AND payload->>'serviceId'=$3 AND status IN ('pending','running'))`, uuid.New(), payload, child.id.String()); err != nil {
			return err
		}
	}
	payload, _ := json.Marshal(map[string]string{"environmentId": environmentID.String()})
	if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,max_attempts) SELECT $1,'delete.environment',$2,50 WHERE NOT EXISTS(SELECT 1 FROM jobs WHERE kind='delete.environment' AND payload->>'environmentId'=$3 AND status IN ('pending','running'))`, uuid.New(), payload, environmentID.String()); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func lockEnvironmentForServiceCreation(ctx context.Context, tx pgx.Tx, organizationID, environmentID uuid.UUID) (uuid.UUID, error) {
	var projectID uuid.UUID
	err := tx.QueryRow(ctx, `SELECT project.id FROM projects project JOIN environments environment ON environment.project_id=project.id WHERE environment.id=$1 AND project.organization_id=$2 AND project.deletion_requested_at IS NULL FOR UPDATE OF project`, environmentID, organizationID).Scan(&projectID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrNotFound
	}
	if err != nil {
		return uuid.Nil, err
	}
	var lockedEnvironmentID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT id FROM environments WHERE id=$1 AND deletion_requested_at IS NULL FOR UPDATE`, environmentID).Scan(&lockedEnvironmentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrNotFound
	}
	return projectID, err
}

func (s *Store) CreateComposeService(ctx context.Context, organizationID uuid.UUID, service ComposeService) (ComposeService, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ComposeService{}, err
	}
	defer tx.Rollback(ctx)
	projectID, err := lockEnvironmentForServiceCreation(ctx, tx, organizationID, service.EnvironmentID)
	if err != nil {
		return ComposeService{}, err
	}
	if err = s.enforcePolicy(ctx, tx, organizationID, &projectID, &service.EnvironmentID, "services"); err != nil {
		return ComposeService{}, err
	}
	if service.ID == uuid.Nil {
		service.ID = uuid.New()
	}
	service.Revision = 1
	service.DesiredState = "running"
	service.Tags = []Tag{}
	err = tx.QueryRow(ctx, `INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml,encrypted_env) SELECT $1,e.id,$3,$4,$5,$6,$7 FROM environments e JOIN projects p ON p.id=e.project_id WHERE e.id=$2 AND e.deletion_requested_at IS NULL AND p.deletion_requested_at IS NULL AND p.organization_id=$8 RETURNING created_at,updated_at`, service.ID, service.EnvironmentID, service.Name, service.Slug, service.StackName, service.ComposeYAML, service.EncryptedEnv, organizationID).Scan(&service.CreatedAt, &service.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ComposeService{}, ErrNotFound
	}
	if err != nil {
		return ComposeService{}, err
	}
	return service, tx.Commit(ctx)
}

func (s *Store) UpdateComposeService(ctx context.Context, organizationID, id uuid.UUID, composeYAML, encryptedEnv string) (ComposeService, error) {
	return s.updateComposeService(ctx, organizationID, id, composeYAML, true, encryptedEnv)
}

// UpdateComposeServiceConfiguration preserves the encrypted environment when
// encryptedEnv is nil. Preservation happens under the same row lock as the
// Compose update so a concurrent variable rotation cannot be lost.
func (s *Store) UpdateComposeServiceConfiguration(ctx context.Context, organizationID, id uuid.UUID, composeYAML string, encryptedEnv *string) (ComposeService, error) {
	if encryptedEnv == nil {
		return s.updateComposeService(ctx, organizationID, id, composeYAML, false, "")
	}
	return s.updateComposeService(ctx, organizationID, id, composeYAML, true, *encryptedEnv)
}

func (s *Store) updateComposeService(ctx context.Context, organizationID, id uuid.UUID, composeYAML string, replaceEnvironment bool, encryptedEnv string) (ComposeService, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ComposeService{}, err
	}
	defer tx.Rollback(ctx)
	projectID, environmentID, err := lockActiveServiceForMutation(ctx, tx, organizationID, id)
	if err != nil {
		return ComposeService{}, err
	}
	if err = s.enforcePolicy(ctx, tx, organizationID, &projectID, &environmentID, "deployment"); err != nil {
		return ComposeService{}, err
	}
	if err = ensureNoActiveDeploymentTx(ctx, tx, id); err != nil {
		return ComposeService{}, err
	}
	if err = ensureProtectedVolumesDeclared(ctx, tx, id, composeYAML); err != nil {
		return ComposeService{}, err
	}
	if err = ensureScheduledTargetsDeclared(ctx, tx, id, composeYAML); err != nil {
		return ComposeService{}, err
	}
	var service ComposeService
	err = tx.QueryRow(ctx, `UPDATE compose_services s SET compose_yaml=$3,encrypted_env=CASE WHEN $4 THEN $5 ELSE s.encrypted_env END,revision=revision+1,updated_at=now() FROM environments e,projects p WHERE s.id=$1 AND s.deletion_requested_at IS NULL AND e.id=s.environment_id AND p.id=e.project_id AND p.organization_id=$2 RETURNING s.id,s.environment_id,s.name,s.slug,s.stack_name,s.storage_node_id,s.compose_yaml,s.encrypted_env,s.revision,s.desired_state,s.created_at,s.updated_at`, id, organizationID, composeYAML, replaceEnvironment, encryptedEnv).Scan(&service.ID, &service.EnvironmentID, &service.Name, &service.Slug, &service.StackName, &service.StorageNodeID, &service.ComposeYAML, &service.EncryptedEnv, &service.Revision, &service.DesiredState, &service.CreatedAt, &service.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ComposeService{}, ErrNotFound
	}
	if err != nil {
		return ComposeService{}, err
	}
	if replaceEnvironment {
		if _, err = tx.Exec(ctx, `UPDATE template_instances SET managed_environment_keys='{}',environment_ownership_recorded=true,updated_at=now() WHERE compose_service_id=$1`, id); err != nil {
			return ComposeService{}, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return ComposeService{}, err
	}
	service.Tags, err = s.ListServiceTags(ctx, organizationID, id)
	return service, err
}

func (s *Store) UpsertApplicationSource(ctx context.Context, organizationID uuid.UUID, source ApplicationSource) (ApplicationSource, error) {
	if source.SourceType == "" {
		source.SourceType = "git"
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ApplicationSource{}, err
	}
	defer tx.Rollback(ctx)
	projectID, environmentID, err := lockActiveServiceForMutation(ctx, tx, organizationID, source.ComposeServiceID)
	if err != nil {
		return ApplicationSource{}, err
	}
	if err = s.enforcePolicy(ctx, tx, organizationID, &projectID, &environmentID, "deployment"); err != nil {
		return ApplicationSource{}, err
	}
	if err = ensureNoActiveDeploymentTx(ctx, tx, source.ComposeServiceID); err != nil {
		return ApplicationSource{}, err
	}
	err = tx.QueryRow(ctx, `INSERT INTO application_sources(compose_service_id,source_type,repository_url,git_ref,context_directory,dockerfile,build_type,builder_image,output_directory,build_target,enable_submodules,encrypted_build_config,target_service,registry_image,git_credential_id,registry_credential_id,status_provider,status_credential_id,status_context)
		SELECT s.id,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20 FROM compose_services s JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id
		WHERE s.id=$1 AND s.deletion_requested_at IS NULL AND p.organization_id=$2
		AND ($16::uuid IS NULL OR EXISTS(SELECT 1 FROM source_credentials c WHERE c.id=$16 AND c.organization_id=$2 AND c.kind IN ('git','git-ssh')))
		AND ($17::uuid IS NULL OR EXISTS(SELECT 1 FROM source_credentials c WHERE c.id=$17 AND c.organization_id=$2 AND c.kind='registry'))
		AND ($19::uuid IS NULL OR EXISTS(SELECT 1 FROM source_credentials c WHERE c.id=$19 AND c.organization_id=$2 AND c.kind='git'))
		ON CONFLICT(compose_service_id) DO UPDATE SET source_type=excluded.source_type,repository_url=excluded.repository_url,git_ref=excluded.git_ref,context_directory=excluded.context_directory,dockerfile=excluded.dockerfile,build_type=excluded.build_type,builder_image=excluded.builder_image,output_directory=excluded.output_directory,build_target=excluded.build_target,enable_submodules=excluded.enable_submodules,encrypted_build_config=excluded.encrypted_build_config,target_service=excluded.target_service,registry_image=excluded.registry_image,git_credential_id=excluded.git_credential_id,registry_credential_id=excluded.registry_credential_id,status_provider=excluded.status_provider,status_credential_id=excluded.status_credential_id,status_context=excluded.status_context,updated_at=now()
		RETURNING updated_at`, source.ComposeServiceID, organizationID, source.SourceType, source.RepositoryURL, source.GitRef, source.ContextDirectory, source.Dockerfile, source.BuildType, source.BuilderImage, source.OutputDirectory, source.BuildTarget, source.EnableSubmodules, source.EncryptedBuildConfig, source.TargetService, source.RegistryImage, source.GitCredentialID, source.RegistryCredentialID, source.StatusProvider, source.StatusCredentialID, source.StatusContext).Scan(&source.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ApplicationSource{}, ErrNotFound
	}
	if err != nil {
		return ApplicationSource{}, err
	}
	return source, tx.Commit(ctx)
}

func (s *Store) GetApplicationSource(ctx context.Context, organizationID, serviceID uuid.UUID) (ApplicationSource, error) {
	var source ApplicationSource
	var artifact ApplicationArtifact
	var artifactFilename, artifactSHA *string
	var artifactSize *int64
	var artifactUpdatedAt *time.Time
	err := s.Pool.QueryRow(ctx, `SELECT a.compose_service_id,a.source_type,a.repository_url,a.git_ref,a.context_directory,a.dockerfile,a.build_type,a.builder_image,a.output_directory,a.build_target,a.enable_submodules,a.encrypted_build_config,a.target_service,a.registry_image,a.git_credential_id,a.registry_credential_id,a.status_provider,a.status_credential_id,a.status_context,a.updated_at,x.filename,x.sha256,x.compressed_size,x.updated_at
		FROM application_sources a JOIN compose_services s ON s.id=a.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id LEFT JOIN application_artifacts x ON x.compose_service_id=a.compose_service_id
		WHERE a.compose_service_id=$1 AND p.organization_id=$2`, serviceID, organizationID).Scan(&source.ComposeServiceID, &source.SourceType, &source.RepositoryURL, &source.GitRef, &source.ContextDirectory, &source.Dockerfile, &source.BuildType, &source.BuilderImage, &source.OutputDirectory, &source.BuildTarget, &source.EnableSubmodules, &source.EncryptedBuildConfig, &source.TargetService, &source.RegistryImage, &source.GitCredentialID, &source.RegistryCredentialID, &source.StatusProvider, &source.StatusCredentialID, &source.StatusContext, &source.UpdatedAt, &artifactFilename, &artifactSHA, &artifactSize, &artifactUpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ApplicationSource{}, ErrNotFound
	}
	if err == nil && artifactFilename != nil {
		artifact.ComposeServiceID, artifact.Filename, artifact.SHA256, artifact.CompressedSize, artifact.UpdatedAt = serviceID, *artifactFilename, *artifactSHA, *artifactSize, *artifactUpdatedAt
		source.Artifact = &artifact
	}
	return source, err
}

func (s *Store) UpsertApplicationArtifact(ctx context.Context, organizationID uuid.UUID, artifact ApplicationArtifact) (ApplicationArtifact, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ApplicationArtifact{}, err
	}
	defer tx.Rollback(ctx)
	projectID, environmentID, err := lockActiveServiceForMutation(ctx, tx, organizationID, artifact.ComposeServiceID)
	if err != nil {
		return ApplicationArtifact{}, err
	}
	if err = s.enforcePolicy(ctx, tx, organizationID, &projectID, &environmentID, "deployment"); err != nil {
		return ApplicationArtifact{}, err
	}
	if err = ensureNoActiveDeploymentTx(ctx, tx, artifact.ComposeServiceID); err != nil {
		return ApplicationArtifact{}, err
	}
	err = tx.QueryRow(ctx, `INSERT INTO application_artifacts(compose_service_id,encrypted_archive,filename,sha256,compressed_size)
		SELECT s.id,$3,$4,$5,$6 FROM compose_services s JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE s.id=$1 AND s.deletion_requested_at IS NULL AND p.organization_id=$2
		ON CONFLICT(compose_service_id) DO UPDATE SET encrypted_archive=excluded.encrypted_archive,filename=excluded.filename,sha256=excluded.sha256,compressed_size=excluded.compressed_size,updated_at=now() RETURNING updated_at`, artifact.ComposeServiceID, organizationID, artifact.EncryptedArchive, artifact.Filename, artifact.SHA256, artifact.CompressedSize).Scan(&artifact.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ApplicationArtifact{}, ErrNotFound
	}
	if err != nil {
		return ApplicationArtifact{}, err
	}
	artifact.EncryptedArchive = ""
	return artifact, tx.Commit(ctx)
}

func (s *Store) ApplicationArtifactExists(ctx context.Context, organizationID, serviceID uuid.UUID) (bool, error) {
	var exists bool
	err := s.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM application_artifacts a JOIN compose_services s ON s.id=a.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE a.compose_service_id=$1 AND p.organization_id=$2)`, serviceID, organizationID).Scan(&exists)
	return exists, err
}

func (s *Store) CreateSourceCredential(ctx context.Context, item SourceCredential) (SourceCredential, error) {
	if item.ID == uuid.Nil {
		item.ID = uuid.New()
	}
	err := s.Pool.QueryRow(ctx, `INSERT INTO source_credentials(id,organization_id,kind,name,server,username,encrypted_secret) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING created_at,updated_at`, item.ID, item.OrganizationID, item.Kind, item.Name, item.Server, item.Username, item.EncryptedSecret).Scan(&item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s *Store) CreateSourceCredentialWithAudit(ctx context.Context, principal Principal, item SourceCredential, remoteAddr string) (SourceCredential, error) {
	if item.ID == uuid.Nil {
		item.ID = uuid.New()
	}
	item.OrganizationID = principal.OrganizationID
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return SourceCredential{}, err
	}
	defer tx.Rollback(ctx)
	if err = tx.QueryRow(ctx, `INSERT INTO source_credentials(id,organization_id,kind,name,server,username,encrypted_secret) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING created_at,updated_at`, item.ID, item.OrganizationID, item.Kind, item.Name, item.Server, item.Username, item.EncryptedSecret).Scan(&item.CreatedAt, &item.UpdatedAt); err != nil {
		return SourceCredential{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "source_credential.create", "source_credential", item.ID.String(), remoteAddr, map[string]any{"kind": item.Kind, "server": item.Server}); err != nil {
		return SourceCredential{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return SourceCredential{}, err
	}
	return item, nil
}

func (s *Store) ListSourceCredentials(ctx context.Context, organizationID uuid.UUID) ([]SourceCredential, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id,organization_id,kind,name,server,username,created_at,updated_at FROM source_credentials WHERE organization_id=$1 ORDER BY kind,name`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []SourceCredential{}
	for rows.Next() {
		var item SourceCredential
		if err = rows.Scan(&item.ID, &item.OrganizationID, &item.Kind, &item.Name, &item.Server, &item.Username, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) DeleteSourceCredential(ctx context.Context, organizationID, id uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = deleteSourceCredentialTx(ctx, tx, organizationID, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) DeleteSourceCredentialWithAudit(ctx context.Context, principal Principal, id uuid.UUID, remoteAddr string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = deleteSourceCredentialTx(ctx, tx, principal.OrganizationID, id); err != nil {
		return err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "source_credential.delete", "source_credential", id.String(), remoteAddr, nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func deleteSourceCredentialTx(ctx context.Context, tx pgx.Tx, organizationID, id uuid.UUID) error {
	if err := lockSourceCredentialConsumers(ctx, tx, organizationID, id); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM source_credentials WHERE id=$1 AND organization_id=$2`, id, organizationID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) RotateSourceCredential(ctx context.Context, organizationID, id uuid.UUID, encryptedSecret string) (SourceCredential, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return SourceCredential{}, err
	}
	defer tx.Rollback(ctx)
	item, err := rotateSourceCredentialTx(ctx, tx, organizationID, id, encryptedSecret)
	if err != nil {
		return SourceCredential{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return SourceCredential{}, err
	}
	return item, nil
}

func (s *Store) RotateSourceCredentialWithAudit(ctx context.Context, principal Principal, id uuid.UUID, encryptedSecret, remoteAddr string) (SourceCredential, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return SourceCredential{}, err
	}
	defer tx.Rollback(ctx)
	item, err := rotateSourceCredentialTx(ctx, tx, principal.OrganizationID, id, encryptedSecret)
	if err != nil {
		return SourceCredential{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "source_credential.rotate", "source_credential", item.ID.String(), remoteAddr, map[string]any{"kind": item.Kind, "server": item.Server}); err != nil {
		return SourceCredential{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return SourceCredential{}, err
	}
	return item, nil
}

func rotateSourceCredentialTx(ctx context.Context, tx pgx.Tx, organizationID, id uuid.UUID, encryptedSecret string) (SourceCredential, error) {
	if err := lockSourceCredentialConsumers(ctx, tx, organizationID, id); err != nil {
		return SourceCredential{}, err
	}
	var item SourceCredential
	err := tx.QueryRow(ctx, `UPDATE source_credentials SET encrypted_secret=$3,updated_at=now() WHERE id=$1 AND organization_id=$2 RETURNING id,organization_id,kind,name,server,username,encrypted_secret,created_at,updated_at`, id, organizationID, encryptedSecret).Scan(&item.ID, &item.OrganizationID, &item.Kind, &item.Name, &item.Server, &item.Username, &item.EncryptedSecret, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return SourceCredential{}, ErrNotFound
	}
	return item, err
}

func lockSourceCredentialConsumers(ctx context.Context, tx pgx.Tx, organizationID, id uuid.UUID) error {
	rows, err := tx.Query(ctx, `SELECT service.id FROM application_sources source JOIN compose_services service ON service.id=source.compose_service_id JOIN environments environment ON environment.id=service.environment_id JOIN projects project ON project.id=environment.project_id WHERE project.organization_id=$2 AND (source.git_credential_id=$1 OR source.registry_credential_id=$1 OR source.status_credential_id=$1) ORDER BY service.id FOR UPDATE OF service`, id, organizationID)
	if err != nil {
		return err
	}
	serviceIDs := []uuid.UUID{}
	for rows.Next() {
		var serviceID uuid.UUID
		if err = rows.Scan(&serviceID); err != nil {
			rows.Close()
			return err
		}
		serviceIDs = append(serviceIDs, serviceID)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	for _, serviceID := range serviceIDs {
		if err = ensureNoActiveDeploymentTx(ctx, tx, serviceID); err != nil {
			return err
		}
	}
	repositories, err := tx.Query(ctx, `SELECT last_sync_status FROM template_repositories WHERE credential_id=$1 AND organization_id=$2 ORDER BY id FOR UPDATE`, id, organizationID)
	if err != nil {
		return err
	}
	for repositories.Next() {
		var status string
		if err = repositories.Scan(&status); err != nil {
			repositories.Close()
			return err
		}
		if status == "running" {
			repositories.Close()
			return ErrBusy
		}
	}
	repositories.Close()
	if err = repositories.Err(); err != nil {
		return err
	}
	return nil
}

func (s *Store) GetComposeService(ctx context.Context, organizationID, id uuid.UUID) (ComposeService, []Route, error) {
	var v ComposeService
	err := s.Pool.QueryRow(ctx, `SELECT s.id,s.environment_id,s.name,s.slug,s.stack_name,s.storage_node_id,s.compose_yaml,s.encrypted_env,s.revision,s.desired_state,s.created_at,s.updated_at FROM compose_services s JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE s.id=$1 AND p.organization_id=$2`, id, organizationID).Scan(&v.ID, &v.EnvironmentID, &v.Name, &v.Slug, &v.StackName, &v.StorageNodeID, &v.ComposeYAML, &v.EncryptedEnv, &v.Revision, &v.DesiredState, &v.CreatedAt, &v.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ComposeService{}, nil, ErrNotFound
	}
	if err != nil {
		return ComposeService{}, nil, err
	}
	v.Tags, err = s.ListServiceTags(ctx, organizationID, id)
	if err != nil {
		return ComposeService{}, nil, err
	}
	rows, err := s.Pool.Query(ctx, `SELECT id,compose_service_id,service_name,host,path_prefix,internal_path,strip_path,NOT enabled,redirect_regex,redirect_replacement,redirect_permanent,target_port,tls,certificate_resolver,custom_certificate_id,created_at,updated_at FROM routes WHERE compose_service_id=$1 ORDER BY host,path_prefix`, id)
	if err != nil {
		return ComposeService{}, nil, err
	}
	defer rows.Close()
	routes := []Route{}
	for rows.Next() {
		var r Route
		if err := rows.Scan(&r.ID, &r.ComposeServiceID, &r.ServiceName, &r.Host, &r.PathPrefix, &r.InternalPath, &r.StripPath, &r.Disabled, &r.RedirectRegex, &r.RedirectReplacement, &r.RedirectPermanent, &r.TargetPort, &r.TLS, &r.CertificateResolver, &r.CustomCertificateID, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return ComposeService{}, nil, err
		}
		r.Enabled = !r.Disabled
		routes = append(routes, r)
	}
	return v, routes, rows.Err()
}

func (s *Store) ListComposeServices(ctx context.Context, organizationID, environmentID uuid.UUID) ([]ComposeService, error) {
	rows, err := s.Pool.Query(ctx, `SELECT s.id,s.environment_id,s.name,s.slug,s.stack_name,s.storage_node_id,s.revision,s.desired_state,s.created_at,s.updated_at FROM compose_services s JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE s.environment_id=$1 AND s.deletion_requested_at IS NULL AND p.organization_id=$2 ORDER BY s.name`, environmentID, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ComposeService{}
	for rows.Next() {
		var item ComposeService
		if err := rows.Scan(&item.ID, &item.EnvironmentID, &item.Name, &item.Slug, &item.StackName, &item.StorageNodeID, &item.Revision, &item.DesiredState, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return items, nil
	}
	byID := make(map[uuid.UUID]*ComposeService, len(items))
	serviceIDs := make([]uuid.UUID, 0, len(items))
	for index := range items {
		items[index].Tags = []Tag{}
		byID[items[index].ID] = &items[index]
		serviceIDs = append(serviceIDs, items[index].ID)
	}
	tagRows, err := s.Pool.Query(ctx, `SELECT st.compose_service_id,t.id,t.organization_id,t.name,t.color,t.created_at,t.updated_at
		FROM compose_service_tags st JOIN tags t ON t.id=st.tag_id
		WHERE st.compose_service_id=ANY($1::uuid[]) AND t.organization_id=$2 ORDER BY lower(t.name),t.id`, serviceIDs, organizationID)
	if err != nil {
		return nil, err
	}
	defer tagRows.Close()
	for tagRows.Next() {
		var serviceID uuid.UUID
		var tag Tag
		if err = tagRows.Scan(&serviceID, &tag.ID, &tag.OrganizationID, &tag.Name, &tag.Color, &tag.CreatedAt, &tag.UpdatedAt); err != nil {
			return nil, err
		}
		if service := byID[serviceID]; service != nil {
			service.Tags = append(service.Tags, tag)
		}
	}
	return items, tagRows.Err()
}

func (s *Store) AddRoute(ctx context.Context, organizationID uuid.UUID, r Route) (Route, error) {
	if r.InternalPath == "" {
		r.InternalPath = "/"
	}
	r.Enabled = !r.Disabled
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Route{}, err
	}
	defer tx.Rollback(ctx)
	projectID, environmentID, err := lockActiveServiceForMutation(ctx, tx, organizationID, r.ComposeServiceID)
	if err != nil {
		return Route{}, err
	}
	if err = s.enforcePolicy(ctx, tx, organizationID, &projectID, &environmentID, "deployment"); err != nil {
		return Route{}, err
	}
	if err = ensureNoActiveDeploymentTx(ctx, tx, r.ComposeServiceID); err != nil {
		return Route{}, err
	}
	if err = validateRouteCertificateTx(ctx, tx, organizationID, r.CustomCertificateID, r.Host); err != nil {
		return Route{}, err
	}
	r.ID = uuid.New()
	err = tx.QueryRow(ctx, `INSERT INTO routes(id,compose_service_id,service_name,host,path_prefix,internal_path,strip_path,enabled,redirect_regex,redirect_replacement,redirect_permanent,target_port,tls,certificate_resolver,custom_certificate_id) SELECT $1,s.id,$3,$4,$5,$6,$7,NOT $8,$9,$10,$11,$12,$13,$14,$15 FROM compose_services s JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE s.id=$2 AND s.deletion_requested_at IS NULL AND p.organization_id=$16 RETURNING created_at,updated_at`, r.ID, r.ComposeServiceID, r.ServiceName, r.Host, r.PathPrefix, r.InternalPath, r.StripPath, r.Disabled, r.RedirectRegex, r.RedirectReplacement, r.RedirectPermanent, r.TargetPort, r.TLS, r.CertificateResolver, r.CustomCertificateID, organizationID).Scan(&r.CreatedAt, &r.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Route{}, ErrNotFound
	}
	if err != nil {
		return Route{}, err
	}
	if r.CustomCertificateID != nil {
		if err = queueEdgeCertificateReconciliationForEnvironmentTx(ctx, tx, environmentID); err != nil {
			return Route{}, err
		}
	}
	return r, tx.Commit(ctx)
}

func (s *Store) GetRoute(ctx context.Context, organizationID, id uuid.UUID) (Route, error) {
	var item Route
	err := s.Pool.QueryRow(ctx, `SELECT r.id,r.compose_service_id,r.service_name,r.host,r.path_prefix,r.internal_path,r.strip_path,NOT r.enabled,r.redirect_regex,r.redirect_replacement,r.redirect_permanent,r.target_port,r.tls,r.certificate_resolver,r.custom_certificate_id,r.created_at,r.updated_at FROM routes r JOIN compose_services s ON s.id=r.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE r.id=$1 AND p.organization_id=$2`, id, organizationID).Scan(&item.ID, &item.ComposeServiceID, &item.ServiceName, &item.Host, &item.PathPrefix, &item.InternalPath, &item.StripPath, &item.Disabled, &item.RedirectRegex, &item.RedirectReplacement, &item.RedirectPermanent, &item.TargetPort, &item.TLS, &item.CertificateResolver, &item.CustomCertificateID, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Route{}, ErrNotFound
	}
	item.Enabled = !item.Disabled
	return item, err
}

func (s *Store) UpdateRoute(ctx context.Context, organizationID uuid.UUID, item Route) (Route, error) {
	if item.InternalPath == "" {
		item.InternalPath = "/"
	}
	item.Enabled = !item.Disabled
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Route{}, err
	}
	defer tx.Rollback(ctx)
	var serviceID uuid.UUID
	var oldCertificateID *uuid.UUID
	err = tx.QueryRow(ctx, `SELECT r.compose_service_id,r.custom_certificate_id FROM routes r JOIN compose_services s ON s.id=r.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE r.id=$1 AND p.organization_id=$2`, item.ID, organizationID).Scan(&serviceID, &oldCertificateID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Route{}, ErrNotFound
	}
	if err != nil {
		return Route{}, err
	}
	projectID, environmentID, err := lockActiveServiceForMutation(ctx, tx, organizationID, serviceID)
	if err != nil {
		return Route{}, err
	}
	if err = s.enforcePolicy(ctx, tx, organizationID, &projectID, &environmentID, "deployment"); err != nil {
		return Route{}, err
	}
	if err = ensureNoActiveDeploymentTx(ctx, tx, serviceID); err != nil {
		return Route{}, err
	}
	if err = validateRouteCertificateTx(ctx, tx, organizationID, item.CustomCertificateID, item.Host); err != nil {
		return Route{}, err
	}
	item.ComposeServiceID = serviceID
	err = tx.QueryRow(ctx, `UPDATE routes SET service_name=$3,host=$4,path_prefix=$5,internal_path=$6,strip_path=$7,enabled=NOT $8,redirect_regex=$9,redirect_replacement=$10,redirect_permanent=$11,target_port=$12,tls=$13,certificate_resolver=$14,custom_certificate_id=$15,updated_at=now() WHERE id=$1 AND compose_service_id=$2 RETURNING created_at,updated_at`, item.ID, serviceID, item.ServiceName, item.Host, item.PathPrefix, item.InternalPath, item.StripPath, item.Disabled, item.RedirectRegex, item.RedirectReplacement, item.RedirectPermanent, item.TargetPort, item.TLS, item.CertificateResolver, item.CustomCertificateID).Scan(&item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Route{}, ErrNotFound
	}
	if err != nil {
		return Route{}, err
	}
	if oldCertificateID != nil || item.CustomCertificateID != nil {
		if err = queueEdgeCertificateReconciliationForEnvironmentTx(ctx, tx, environmentID); err != nil {
			return Route{}, err
		}
	}
	return item, tx.Commit(ctx)
}

func (s *Store) DeleteRoute(ctx context.Context, organizationID, id uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var serviceID uuid.UUID
	var certificateID *uuid.UUID
	err = tx.QueryRow(ctx, `SELECT r.compose_service_id,r.custom_certificate_id FROM routes r JOIN compose_services s ON s.id=r.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE r.id=$1 AND p.organization_id=$2`, id, organizationID).Scan(&serviceID, &certificateID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	_, environmentID, err := lockActiveServiceForMutation(ctx, tx, organizationID, serviceID)
	if err != nil {
		return err
	}
	if err = ensureNoActiveDeploymentTx(ctx, tx, serviceID); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM routes WHERE id=$1 AND compose_service_id=$2`, id, serviceID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if certificateID != nil {
		if err = queueEdgeCertificateReconciliationForEnvironmentTx(ctx, tx, environmentID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) QueueDeployment(ctx context.Context, organizationID, serviceID, actorID uuid.UUID, trigger string) (Deployment, error) {
	return s.queueDeployment(ctx, organizationID, serviceID, actorID, trigger, false)
}

func (s *Store) QueueServiceStart(ctx context.Context, organizationID, serviceID, actorID uuid.UUID) (Deployment, error) {
	return s.queueDeployment(ctx, organizationID, serviceID, actorID, "start", true)
}

func (s *Store) queueDeployment(ctx context.Context, organizationID, serviceID, actorID uuid.UUID, trigger string, requireStopped bool) (Deployment, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Deployment{}, err
	}
	defer tx.Rollback(ctx)
	var d Deployment
	d.ID = uuid.New()
	d.ComposeServiceID = serviceID
	d.Status = "queued"
	d.Trigger = trigger
	var compose, env, desiredState string
	var projectID, environmentID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT s.revision,s.compose_yaml,s.encrypted_env,s.desired_state,p.id,e.id FROM compose_services s JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE s.id=$1 AND s.deletion_requested_at IS NULL AND e.deletion_requested_at IS NULL AND p.deletion_requested_at IS NULL AND p.organization_id=$2 FOR UPDATE OF s`, serviceID, organizationID).Scan(&d.Revision, &compose, &env, &desiredState, &projectID, &environmentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Deployment{}, ErrNotFound
	}
	if err != nil {
		return Deployment{}, err
	}
	if requireStopped && desiredState != "stopped" {
		return Deployment{}, ErrServiceAlreadyRunning
	}
	if err = s.enforcePolicy(ctx, tx, organizationID, &projectID, &environmentID, "deployment"); err != nil {
		return Deployment{}, err
	}
	if err = ensureEnvironmentClusterWritable(ctx, tx, environmentID); err != nil {
		return Deployment{}, err
	}
	if err = cancelQueuedReconciliationTx(ctx, tx, serviceID, "superseded by a requested deployment"); err != nil {
		return Deployment{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE compose_services SET desired_state='running',updated_at=now() WHERE id=$1`, serviceID); err != nil {
		return Deployment{}, err
	}
	err = tx.QueryRow(ctx, `INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,env_snapshot,status,trigger,actor_user_id) VALUES($1,$2,$3,$4,$5,'queued',$6,$7) RETURNING created_at`, d.ID, serviceID, d.Revision, compose, env, trigger, nullableUUID(actorID)).Scan(&d.CreatedAt)
	if err != nil {
		return Deployment{}, err
	}
	if err = snapshotDeploymentRegistryCredentialTx(ctx, tx, d.ID, serviceID); err != nil {
		return Deployment{}, err
	}
	payload, _ := json.Marshal(map[string]string{"deploymentId": d.ID.String()})
	if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,resource_key) VALUES($1,'deploy.compose',$2,$3)`, uuid.New(), payload, "service:"+serviceID.String()); err != nil {
		return Deployment{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Deployment{}, err
	}
	return d, nil
}

// QueueServiceStop persists operator intent before scheduling stack removal.
// Named volumes remain intact so start can replay the current revision.
func (s *Store) QueueServiceStop(ctx context.Context, organizationID, serviceID uuid.UUID) (uuid.UUID, bool, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, false, err
	}
	defer tx.Rollback(ctx)
	var stackName, desiredState string
	var projectID, environmentID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT s.stack_name,s.desired_state,p.id,e.id FROM compose_services s JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE s.id=$1 AND p.organization_id=$2 AND s.deletion_requested_at IS NULL AND e.deletion_requested_at IS NULL AND p.deletion_requested_at IS NULL FOR UPDATE OF s`, serviceID, organizationID).Scan(&stackName, &desiredState, &projectID, &environmentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false, ErrNotFound
	}
	if err != nil {
		return uuid.Nil, false, err
	}
	if err = s.enforcePolicy(ctx, tx, organizationID, &projectID, &environmentID, "deployment"); err != nil {
		return uuid.Nil, false, err
	}
	if err = cancelQueuedReconciliationTx(ctx, tx, serviceID, "service stop requested"); err != nil {
		return uuid.Nil, false, err
	}
	if err = ensureNoActiveDeploymentTx(ctx, tx, serviceID); err != nil {
		return uuid.Nil, false, err
	}
	resourceKey := "service:" + serviceID.String()
	var existingID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT id FROM jobs WHERE kind='stop.compose' AND resource_key=$1 AND status IN ('pending','running') ORDER BY created_at,id LIMIT 1`, resourceKey).Scan(&existingID)
	if err == nil {
		if desiredState != "stopped" {
			if _, err = tx.Exec(ctx, `UPDATE compose_services SET desired_state='stopped',updated_at=now() WHERE id=$1`, serviceID); err != nil {
				return uuid.Nil, false, err
			}
		}
		return existingID, false, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false, err
	}
	busy, err := activeServiceOperations(ctx, tx, []uuid.UUID{serviceID})
	if err != nil {
		return uuid.Nil, false, err
	}
	if busy {
		return uuid.Nil, false, ErrBusy
	}
	if desiredState == "stopped" {
		var lastStatus string
		err = tx.QueryRow(ctx, `SELECT status FROM jobs WHERE kind='stop.compose' AND resource_key=$1 ORDER BY created_at DESC,id DESC LIMIT 1`, resourceKey).Scan(&lastStatus)
		if err == nil && lastStatus == "succeeded" {
			return uuid.Nil, false, tx.Commit(ctx)
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, false, err
		}
	}
	jobID := uuid.New()
	payload, _ := json.Marshal(map[string]string{"serviceId": serviceID.String(), "stackName": stackName, "organizationId": organizationID.String()})
	if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,resource_key,max_attempts) VALUES($1,'stop.compose',$2,$3,10)`, jobID, payload, resourceKey); err != nil {
		return uuid.Nil, false, err
	}
	if _, err = tx.Exec(ctx, `UPDATE compose_services SET desired_state='stopped',updated_at=now() WHERE id=$1`, serviceID); err != nil {
		return uuid.Nil, false, err
	}
	return jobID, true, tx.Commit(ctx)
}

// snapshotDeploymentRegistryCredentialTx retains the exact encrypted registry
// credential selected while the service is locked. Rollback and reconciliation
// can then replay an immutable image snapshot even if the mutable application
// source is changed or its credential is later deleted.
func snapshotDeploymentRegistryCredentialTx(ctx context.Context, tx pgx.Tx, deploymentID, serviceID uuid.UUID) error {
	_, err := tx.Exec(ctx, `UPDATE deployments deployment
		SET registry_credential_id=credential.id,
			registry_credential_server=credential.server,
			registry_credential_username=credential.username,
			encrypted_registry_credential=credential.encrypted_secret
		FROM application_sources source
		JOIN source_credentials credential ON credential.id=source.registry_credential_id AND credential.kind='registry'
		WHERE deployment.id=$1 AND source.compose_service_id=$2`, deploymentID, serviceID)
	return err
}

func (s *Store) QueueServiceDeletion(ctx context.Context, organizationID, serviceID uuid.UUID, deleteVolumes ...bool) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var stackName string
	var deleting bool
	err = tx.QueryRow(ctx, `SELECT s.stack_name,s.deletion_requested_at IS NOT NULL FROM compose_services s JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE s.id=$1 AND p.organization_id=$2 FOR UPDATE OF s`, serviceID, organizationID).Scan(&stackName, &deleting)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if deleting {
		payload, _ := json.Marshal(map[string]any{"serviceId": serviceID.String(), "stackName": stackName, "deleteVolumes": len(deleteVolumes) > 0 && deleteVolumes[0]})
		if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,resource_key,max_attempts) SELECT $1,'delete.compose',$2,$4,10 WHERE NOT EXISTS(SELECT 1 FROM jobs WHERE kind='delete.compose' AND payload->>'serviceId'=$3 AND status IN ('pending','running'))`, uuid.New(), payload, serviceID.String(), "service:"+serviceID.String()); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	projectID, environmentID, err := servicePolicyScope(ctx, tx, organizationID, serviceID)
	if err != nil {
		return err
	}
	if err = s.enforcePolicy(ctx, tx, organizationID, &projectID, &environmentID, "deployment"); err != nil {
		return err
	}
	busy, err := activeServiceOperations(ctx, tx, []uuid.UUID{serviceID})
	if err != nil {
		return err
	}
	if busy {
		return ErrBusy
	}
	if _, err = tx.Exec(ctx, `UPDATE compose_services SET deletion_requested_at=now() WHERE id=$1`, serviceID); err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]any{"serviceId": serviceID.String(), "stackName": stackName, "deleteVolumes": len(deleteVolumes) > 0 && deleteVolumes[0]})
	if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,resource_key,max_attempts) VALUES($1,'delete.compose',$2,$3,10)`, uuid.New(), payload, "service:"+serviceID.String()); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) CancelDeployment(ctx context.Context, organizationID, deploymentID uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var jobID uuid.UUID
	var status string
	err = tx.QueryRow(ctx, `SELECT j.id,j.status FROM jobs j JOIN deployments d ON d.id=(j.payload->>'deploymentId')::uuid JOIN compose_services s ON s.id=d.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE j.kind='deploy.compose' AND d.id=$1 AND p.organization_id=$2 FOR UPDATE OF j`, deploymentID, organizationID).Scan(&jobID, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	switch status {
	case "pending":
		if _, err = tx.Exec(ctx, `UPDATE jobs SET status='cancelled',cancel_requested_at=now(),finished_at=now() WHERE id=$1`, jobID); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE deployments SET status='cancelled',error='cancelled by user',finished_at=now() WHERE id=$1`, deploymentID); err != nil {
			return err
		}
		if err = queueCommitStatusTx(ctx, tx, deploymentID, "error"); err != nil {
			return err
		}
	case "running":
		if _, err = tx.Exec(ctx, `UPDATE jobs SET cancel_requested_at=COALESCE(cancel_requested_at,now()) WHERE id=$1`, jobID); err != nil {
			return err
		}
	default:
		return ErrNotCancellable
	}
	return tx.Commit(ctx)
}

func (s *Store) CreateDeployToken(ctx context.Context, organizationID, serviceID, userID uuid.UUID, name string, tokenHash []byte, expiresAt time.Time) (DeployToken, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return DeployToken{}, err
	}
	defer tx.Rollback(ctx)
	var creatorID *uuid.UUID
	if userID != uuid.Nil {
		creatorID = &userID
	}
	item, err := createDeployTokenTx(ctx, tx, organizationID, serviceID, creatorID, name, tokenHash, expiresAt)
	if err != nil {
		return DeployToken{}, err
	}
	return item, tx.Commit(ctx)
}

func (s *Store) CreateDeployTokenWithAudit(ctx context.Context, principal Principal, serviceID uuid.UUID, name string, tokenHash []byte, expiresAt time.Time, remoteAddr string) (DeployToken, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return DeployToken{}, err
	}
	defer tx.Rollback(ctx)
	var creatorID *uuid.UUID
	if principal.UserID != uuid.Nil {
		creatorID = &principal.UserID
	}
	item, err := createDeployTokenTx(ctx, tx, principal.OrganizationID, serviceID, creatorID, name, tokenHash, expiresAt)
	if err != nil {
		return DeployToken{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "deploy_token.create", "deploy_token", item.ID.String(), remoteAddr, map[string]any{"composeServiceId": serviceID, "expiresAt": expiresAt}); err != nil {
		return DeployToken{}, err
	}
	return item, tx.Commit(ctx)
}

func createDeployTokenTx(ctx context.Context, tx pgx.Tx, organizationID, serviceID uuid.UUID, creatorID *uuid.UUID, name string, tokenHash []byte, expiresAt time.Time) (DeployToken, error) {
	if _, _, err := lockActiveServiceForMutation(ctx, tx, organizationID, serviceID); err != nil {
		return DeployToken{}, err
	}
	item := DeployToken{ID: uuid.New(), ComposeServiceID: serviceID, Name: name, ExpiresAt: expiresAt}
	err := tx.QueryRow(ctx, `INSERT INTO deploy_tokens(id,compose_service_id,token_hash,name,created_by,expires_at)
		SELECT $1,s.id,$3,$4,$5,$6 FROM compose_services s JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id
		WHERE s.id=$2 AND s.deletion_requested_at IS NULL AND e.deletion_requested_at IS NULL AND p.deletion_requested_at IS NULL AND p.organization_id=$7
		RETURNING created_at`, item.ID, serviceID, tokenHash, name, creatorID, expiresAt, organizationID).Scan(&item.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return DeployToken{}, ErrNotFound
	}
	if err != nil {
		return DeployToken{}, err
	}
	return item, nil
}

func (s *Store) ListDeployTokens(ctx context.Context, organizationID, serviceID uuid.UUID) ([]DeployToken, error) {
	rows, err := s.Pool.Query(ctx, `SELECT token.id,token.compose_service_id,token.name,token.expires_at,token.last_used_at,token.revoked_at,token.created_at
		FROM deploy_tokens token JOIN compose_services service ON service.id=token.compose_service_id JOIN environments environment ON environment.id=service.environment_id JOIN projects project ON project.id=environment.project_id
		WHERE token.compose_service_id=$1 AND project.organization_id=$2 ORDER BY token.created_at DESC,token.id`, serviceID, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []DeployToken{}
	for rows.Next() {
		var item DeployToken
		if err = rows.Scan(&item.ID, &item.ComposeServiceID, &item.Name, &item.ExpiresAt, &item.LastUsedAt, &item.RevokedAt, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) RevokeDeployToken(ctx context.Context, organizationID, serviceID, tokenID uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = revokeDeployTokenTx(ctx, tx, organizationID, serviceID, tokenID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) RevokeDeployTokenWithAudit(ctx context.Context, principal Principal, serviceID, tokenID uuid.UUID, remoteAddr string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = revokeDeployTokenTx(ctx, tx, principal.OrganizationID, serviceID, tokenID); err != nil {
		return err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "deploy_token.revoke", "deploy_token", tokenID.String(), remoteAddr, map[string]any{"composeServiceId": serviceID}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func revokeDeployTokenTx(ctx context.Context, tx pgx.Tx, organizationID, serviceID, tokenID uuid.UUID) error {
	tag, err := tx.Exec(ctx, `UPDATE deploy_tokens token SET revoked_at=COALESCE(revoked_at,now())
		FROM compose_services service JOIN environments environment ON environment.id=service.environment_id JOIN projects project ON project.id=environment.project_id
		WHERE token.id=$1 AND token.compose_service_id=$2 AND service.id=token.compose_service_id AND project.organization_id=$3`, tokenID, serviceID, organizationID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) CreateWebhookIntegration(ctx context.Context, organizationID uuid.UUID, item WebhookIntegration) (WebhookIntegration, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return WebhookIntegration{}, err
	}
	defer tx.Rollback(ctx)
	item, err = s.createWebhookIntegrationTx(ctx, tx, organizationID, item)
	if err != nil {
		return WebhookIntegration{}, err
	}
	return item, tx.Commit(ctx)
}

func (s *Store) CreateWebhookIntegrationWithAudit(ctx context.Context, principal Principal, item WebhookIntegration, remoteAddr string) (WebhookIntegration, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return WebhookIntegration{}, err
	}
	defer tx.Rollback(ctx)
	item, err = s.createWebhookIntegrationTx(ctx, tx, principal.OrganizationID, item)
	if err != nil {
		return WebhookIntegration{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "webhook.create", "webhook_integration", item.ID.String(), remoteAddr, map[string]any{"provider": item.Provider, "branch": item.Branch}); err != nil {
		return WebhookIntegration{}, err
	}
	return item, tx.Commit(ctx)
}

func (s *Store) createWebhookIntegrationTx(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, item WebhookIntegration) (WebhookIntegration, error) {
	if _, _, err := lockActiveServiceForMutation(ctx, tx, organizationID, item.ComposeServiceID); err != nil {
		return WebhookIntegration{}, err
	}
	if item.ID == uuid.Nil {
		item.ID = uuid.New()
	}
	err := tx.QueryRow(ctx, `INSERT INTO webhook_integrations(id,compose_service_id,name,provider,branch,encrypted_secret)
		SELECT $1,s.id,$3,$4,$5,$6 FROM compose_services s JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE s.id=$2 AND s.deletion_requested_at IS NULL AND e.deletion_requested_at IS NULL AND p.deletion_requested_at IS NULL AND p.organization_id=$7
		RETURNING enabled,created_at,updated_at`, item.ID, item.ComposeServiceID, item.Name, item.Provider, item.Branch, item.EncryptedSecret, organizationID).Scan(&item.Enabled, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return WebhookIntegration{}, ErrNotFound
	}
	item.OrganizationID = organizationID
	if err != nil {
		return WebhookIntegration{}, err
	}
	return item, nil
}

func (s *Store) ListWebhookIntegrations(ctx context.Context, organizationID, serviceID uuid.UUID) ([]WebhookIntegration, error) {
	rows, err := s.Pool.Query(ctx, `SELECT i.id,p.organization_id,i.compose_service_id,i.name,i.provider,i.branch,i.enabled,i.created_at,i.updated_at FROM webhook_integrations i JOIN compose_services s ON s.id=i.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE i.compose_service_id=$1 AND p.organization_id=$2 ORDER BY i.name`, serviceID, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []WebhookIntegration{}
	for rows.Next() {
		var item WebhookIntegration
		if err = rows.Scan(&item.ID, &item.OrganizationID, &item.ComposeServiceID, &item.Name, &item.Provider, &item.Branch, &item.Enabled, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) GetWebhookIntegration(ctx context.Context, id uuid.UUID) (WebhookIntegration, error) {
	var item WebhookIntegration
	err := s.Pool.QueryRow(ctx, `SELECT i.id,p.organization_id,i.compose_service_id,i.name,i.provider,i.branch,i.encrypted_secret,i.enabled,i.created_at,i.updated_at FROM webhook_integrations i JOIN compose_services s ON s.id=i.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE i.id=$1 AND i.enabled`, id).Scan(&item.ID, &item.OrganizationID, &item.ComposeServiceID, &item.Name, &item.Provider, &item.Branch, &item.EncryptedSecret, &item.Enabled, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return WebhookIntegration{}, ErrNotFound
	}
	return item, err
}

func (s *Store) DisableWebhookIntegration(ctx context.Context, organizationID, id uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = disableWebhookIntegrationTx(ctx, tx, organizationID, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) DisableWebhookIntegrationWithAudit(ctx context.Context, principal Principal, id uuid.UUID, remoteAddr string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = disableWebhookIntegrationTx(ctx, tx, principal.OrganizationID, id); err != nil {
		return err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "webhook.disable", "webhook_integration", id.String(), remoteAddr, nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func disableWebhookIntegrationTx(ctx context.Context, tx pgx.Tx, organizationID, id uuid.UUID) error {
	tag, err := tx.Exec(ctx, `UPDATE webhook_integrations i SET enabled=false,updated_at=now() FROM compose_services s,environments e,projects p WHERE i.id=$1 AND s.id=i.compose_service_id AND e.id=s.environment_id AND p.id=e.project_id AND p.organization_id=$2`, id, organizationID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) QueueWebhookDeployment(ctx context.Context, integrationID uuid.UUID, deliveryID, commitSHA string) (Deployment, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Deployment{}, err
	}
	defer tx.Rollback(ctx)
	var serviceID, organizationID, projectID, environmentID uuid.UUID
	var revision int64
	var compose, environment, provider string
	err = tx.QueryRow(ctx, `SELECT s.id,s.revision,s.compose_yaml,s.encrypted_env,i.provider,p.organization_id,p.id,e.id FROM webhook_integrations i JOIN compose_services s ON s.id=i.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE i.id=$1 AND i.enabled AND s.deletion_requested_at IS NULL AND e.deletion_requested_at IS NULL AND p.deletion_requested_at IS NULL FOR UPDATE OF i,s`, integrationID).Scan(&serviceID, &revision, &compose, &environment, &provider, &organizationID, &projectID, &environmentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Deployment{}, ErrNotFound
	}
	if err != nil {
		return Deployment{}, err
	}
	if err = s.enforcePolicy(ctx, tx, organizationID, &projectID, &environmentID, "deployment"); err != nil {
		return Deployment{}, err
	}
	if err = ensureEnvironmentClusterWritable(ctx, tx, environmentID); err != nil {
		return Deployment{}, err
	}
	if err = cancelQueuedReconciliationTx(ctx, tx, serviceID, "superseded by a requested deployment"); err != nil {
		return Deployment{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE compose_services SET desired_state='running',updated_at=now() WHERE id=$1`, serviceID); err != nil {
		return Deployment{}, err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM webhook_deliveries WHERE received_at<now()-interval '30 days'`); err != nil {
		return Deployment{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO webhook_deliveries(integration_id,delivery_id) VALUES($1,$2)`, integrationID, deliveryID); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return Deployment{}, ErrDuplicateDelivery
		}
		return Deployment{}, err
	}
	d := Deployment{ID: uuid.New(), ComposeServiceID: serviceID, Revision: revision, Status: "queued", Trigger: provider + "-webhook", CommitSHA: commitSHA}
	if err = tx.QueryRow(ctx, `INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,env_snapshot,status,trigger,commit_sha) VALUES($1,$2,$3,$4,$5,'queued',$6,$7) RETURNING created_at`, d.ID, serviceID, revision, compose, environment, d.Trigger, commitSHA).Scan(&d.CreatedAt); err != nil {
		return Deployment{}, err
	}
	if err = snapshotDeploymentRegistryCredentialTx(ctx, tx, d.ID, serviceID); err != nil {
		return Deployment{}, err
	}
	payload, _ := json.Marshal(map[string]string{"deploymentId": d.ID.String()})
	if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,resource_key) VALUES($1,'deploy.compose',$2,$3)`, uuid.New(), payload, "service:"+serviceID.String()); err != nil {
		return Deployment{}, err
	}
	if commitSHA != "" {
		if err = queueCommitStatusTx(ctx, tx, d.ID, "pending"); err != nil {
			return Deployment{}, err
		}
	}
	return d, tx.Commit(ctx)
}

func (s *Store) QueueDatabaseBackup(ctx context.Context, organizationID, databaseID, actorID uuid.UUID, destinationID *uuid.UUID) (DatabaseBackup, error) {
	if s.RequireRemoteBackups && destinationID == nil {
		return DatabaseBackup{}, ErrRemoteBackupRequired
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return DatabaseBackup{}, err
	}
	defer tx.Rollback(ctx)
	backup, err := queueDatabaseBackupTx(ctx, tx, organizationID, databaseID, actorID, destinationID)
	if err != nil {
		return DatabaseBackup{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return DatabaseBackup{}, err
	}
	return backup, nil
}

func (s *Store) QueueDatabaseBackupWithAudit(ctx context.Context, principal Principal, databaseID uuid.UUID, destinationID *uuid.UUID, remoteAddr string) (DatabaseBackup, error) {
	if s.RequireRemoteBackups && destinationID == nil {
		return DatabaseBackup{}, ErrRemoteBackupRequired
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return DatabaseBackup{}, err
	}
	defer tx.Rollback(ctx)
	backup, err := queueDatabaseBackupTx(ctx, tx, principal.OrganizationID, databaseID, principal.UserID, destinationID)
	if err != nil {
		return DatabaseBackup{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "database.backup.create", "database_backup", backup.ID.String(), remoteAddr, nil); err != nil {
		return DatabaseBackup{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return DatabaseBackup{}, err
	}
	return backup, nil
}

func queueDatabaseBackupTx(ctx context.Context, tx pgx.Tx, organizationID, databaseID, actorID uuid.UUID, destinationID *uuid.UUID) (DatabaseBackup, error) {
	var lockedID uuid.UUID
	var composeServiceID *uuid.UUID
	var err error
	if err = tx.QueryRow(ctx, `SELECT d.id,d.compose_service_id FROM database_instances d JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE d.id=$1 AND p.organization_id=$2 FOR UPDATE OF d`, databaseID, organizationID).Scan(&lockedID, &composeServiceID); errors.Is(err, pgx.ErrNoRows) {
		return DatabaseBackup{}, ErrNotFound
	} else if err != nil {
		return DatabaseBackup{}, err
	}
	if err = lockDatabaseServiceForOperation(ctx, tx, databaseID, composeServiceID); err != nil {
		return DatabaseBackup{}, err
	}
	if err = requireDatabaseServiceRunning(ctx, tx, composeServiceID); err != nil {
		return DatabaseBackup{}, err
	}
	var active bool
	if err = tx.QueryRow(ctx, `SELECT
		EXISTS(SELECT 1 FROM database_backups WHERE database_instance_id=$1 AND status IN ('queued','running'))
		OR EXISTS(SELECT 1 FROM jobs WHERE resource_key=$2 AND kind='backup.database' AND status IN ('pending','running'))`, databaseID, "database:"+databaseID.String()).Scan(&active); err != nil {
		return DatabaseBackup{}, err
	}
	if active {
		return DatabaseBackup{}, ErrBusy
	}
	if destinationID != nil {
		var destinationAllowed bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM backup_destinations WHERE id=$1 AND organization_id=$2)`, destinationID, organizationID).Scan(&destinationAllowed); err != nil {
			return DatabaseBackup{}, err
		}
		if !destinationAllowed {
			return DatabaseBackup{}, ErrNotFound
		}
	}
	backup := DatabaseBackup{ID: uuid.New(), DatabaseInstanceID: databaseID, Status: "queued", Format: "native", DestinationID: destinationID}
	if err = tx.QueryRow(ctx, `INSERT INTO database_backups(id,database_instance_id,status,format,actor_user_id,destination_id) VALUES($1,$2,'queued','native',$3,$4) RETURNING created_at`, backup.ID, databaseID, nullableUUID(actorID), destinationID).Scan(&backup.CreatedAt); err != nil {
		return DatabaseBackup{}, err
	}
	payload, _ := json.Marshal(map[string]string{"backupId": backup.ID.String()})
	if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,resource_key) VALUES($1,'backup.database',$2,$3)`, uuid.New(), payload, "database:"+databaseID.String()); err != nil {
		return DatabaseBackup{}, err
	}
	return backup, nil
}

func (s *Store) ValidateBackupConfiguration(ctx context.Context) error {
	if !s.RequireRemoteBackups {
		return nil
	}
	var count int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM backup_policies WHERE enabled AND destination_id IS NULL`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return fmt.Errorf("%w: %d enabled backup policies use node-local storage", ErrRemoteBackupRequired, count)
	}
	return nil
}

func (s *Store) UpsertBackupPolicy(ctx context.Context, organizationID, databaseID uuid.UUID, intervalSeconds, retentionCount int, enabled, verifyRestore bool, destinationID *uuid.UUID) (BackupPolicy, error) {
	if s.RequireRemoteBackups && enabled && destinationID == nil {
		return BackupPolicy{}, ErrRemoteBackupRequired
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return BackupPolicy{}, err
	}
	defer tx.Rollback(ctx)
	item, err := upsertBackupPolicyTx(ctx, tx, organizationID, databaseID, intervalSeconds, retentionCount, enabled, verifyRestore, destinationID)
	if err != nil {
		return BackupPolicy{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return BackupPolicy{}, err
	}
	return item, nil
}

func (s *Store) UpsertBackupPolicyWithAudit(ctx context.Context, principal Principal, databaseID uuid.UUID, intervalSeconds, retentionCount int, enabled, verifyRestore bool, destinationID *uuid.UUID, remoteAddr string) (BackupPolicy, error) {
	if s.RequireRemoteBackups && enabled && destinationID == nil {
		return BackupPolicy{}, ErrRemoteBackupRequired
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return BackupPolicy{}, err
	}
	defer tx.Rollback(ctx)
	item, err := upsertBackupPolicyTx(ctx, tx, principal.OrganizationID, databaseID, intervalSeconds, retentionCount, enabled, verifyRestore, destinationID)
	if err != nil {
		return BackupPolicy{}, err
	}
	metadata := map[string]any{"intervalSeconds": intervalSeconds, "retentionCount": retentionCount, "enabled": enabled, "verifyRestore": verifyRestore}
	if err = appendPrincipalAudit(ctx, tx, principal, "backup_policy.update", "database", databaseID.String(), remoteAddr, metadata); err != nil {
		return BackupPolicy{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return BackupPolicy{}, err
	}
	return item, nil
}

func upsertBackupPolicyTx(ctx context.Context, tx pgx.Tx, organizationID, databaseID uuid.UUID, intervalSeconds, retentionCount int, enabled, verifyRestore bool, destinationID *uuid.UUID) (BackupPolicy, error) {
	var lockedID uuid.UUID
	var composeServiceID *uuid.UUID
	var err error
	if err = tx.QueryRow(ctx, `SELECT database.id,database.compose_service_id FROM database_instances database JOIN environments environment ON environment.id=database.environment_id JOIN projects project ON project.id=environment.project_id WHERE database.id=$1 AND project.organization_id=$2 FOR UPDATE OF database`, databaseID, organizationID).Scan(&lockedID, &composeServiceID); errors.Is(err, pgx.ErrNoRows) {
		return BackupPolicy{}, ErrNotFound
	} else if err != nil {
		return BackupPolicy{}, err
	}
	if err = lockDatabaseServiceForOperation(ctx, tx, databaseID, composeServiceID); err != nil {
		return BackupPolicy{}, err
	}
	if destinationID != nil {
		var destinationAllowed bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM backup_destinations WHERE id=$1 AND organization_id=$2)`, *destinationID, organizationID).Scan(&destinationAllowed); err != nil {
			return BackupPolicy{}, err
		}
		if !destinationAllowed {
			return BackupPolicy{}, ErrNotFound
		}
	}
	var item BackupPolicy
	err = tx.QueryRow(ctx, `INSERT INTO backup_policies(id,database_instance_id,interval_seconds,retention_count,enabled,next_run_at,destination_id,verify_restore)
		VALUES($1,$2,$3,$4,$5,now()+($3::int * interval '1 second'),$6,$7)
		ON CONFLICT(database_instance_id) DO UPDATE SET interval_seconds=excluded.interval_seconds,retention_count=excluded.retention_count,enabled=excluded.enabled,destination_id=excluded.destination_id,verify_restore=excluded.verify_restore,next_run_at=CASE WHEN backup_policies.enabled=false AND excluded.enabled=true THEN now()+(excluded.interval_seconds * interval '1 second') ELSE backup_policies.next_run_at END,updated_at=now()
		RETURNING id,database_instance_id,interval_seconds,retention_count,enabled,verify_restore,destination_id,next_run_at,last_run_at,created_at,updated_at`, uuid.New(), databaseID, intervalSeconds, retentionCount, enabled, destinationID, verifyRestore).Scan(&item.ID, &item.DatabaseInstanceID, &item.IntervalSeconds, &item.RetentionCount, &item.Enabled, &item.VerifyRestore, &item.DestinationID, &item.NextRunAt, &item.LastRunAt, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return BackupPolicy{}, err
	}
	return item, nil
}

func (s *Store) GetBackupPolicy(ctx context.Context, organizationID, databaseID uuid.UUID) (BackupPolicy, error) {
	var item BackupPolicy
	err := s.Pool.QueryRow(ctx, `SELECT b.id,b.database_instance_id,b.interval_seconds,b.retention_count,b.enabled,b.verify_restore,b.destination_id,b.next_run_at,b.last_run_at,b.created_at,b.updated_at FROM backup_policies b JOIN database_instances d ON d.id=b.database_instance_id JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE b.database_instance_id=$1 AND p.organization_id=$2`, databaseID, organizationID).Scan(&item.ID, &item.DatabaseInstanceID, &item.IntervalSeconds, &item.RetentionCount, &item.Enabled, &item.VerifyRestore, &item.DestinationID, &item.NextRunAt, &item.LastRunAt, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return BackupPolicy{}, ErrNotFound
	}
	return item, err
}

func (s *Store) DeleteBackupPolicy(ctx context.Context, organizationID, databaseID uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = deleteBackupPolicyTx(ctx, tx, organizationID, databaseID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) DeleteBackupPolicyWithAudit(ctx context.Context, principal Principal, databaseID uuid.UUID, remoteAddr string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = deleteBackupPolicyTx(ctx, tx, principal.OrganizationID, databaseID); err != nil {
		return err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "backup_policy.delete", "database", databaseID.String(), remoteAddr, nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func deleteBackupPolicyTx(ctx context.Context, tx pgx.Tx, organizationID, databaseID uuid.UUID) error {
	var policyID uuid.UUID
	var composeServiceID *uuid.UUID
	err := tx.QueryRow(ctx, `SELECT policy.id,database.compose_service_id FROM backup_policies policy JOIN database_instances database ON database.id=policy.database_instance_id JOIN environments environment ON environment.id=database.environment_id JOIN projects project ON project.id=environment.project_id WHERE policy.database_instance_id=$1 AND project.organization_id=$2 FOR UPDATE OF database,policy`, databaseID, organizationID).Scan(&policyID, &composeServiceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if err = lockDatabaseServiceForOperation(ctx, tx, databaseID, composeServiceID); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM backup_policies WHERE id=$1`, policyID); err != nil {
		return err
	}
	return nil
}

func (s *Store) CreateBackupDestination(ctx context.Context, item BackupDestination) (BackupDestination, error) {
	if item.ID == uuid.Nil {
		item.ID = uuid.New()
	}
	err := s.Pool.QueryRow(ctx, `INSERT INTO backup_destinations(id,organization_id,name,endpoint,region,bucket,prefix,use_tls,encrypted_credentials) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING created_at,updated_at`, item.ID, item.OrganizationID, item.Name, item.Endpoint, item.Region, item.Bucket, item.Prefix, item.UseTLS, item.EncryptedCredentials).Scan(&item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s *Store) CreateBackupDestinationWithAudit(ctx context.Context, principal Principal, item BackupDestination, remoteAddr string) (BackupDestination, error) {
	if item.ID == uuid.Nil {
		item.ID = uuid.New()
	}
	item.OrganizationID = principal.OrganizationID
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return BackupDestination{}, err
	}
	defer tx.Rollback(ctx)
	if err = tx.QueryRow(ctx, `INSERT INTO backup_destinations(id,organization_id,name,endpoint,region,bucket,prefix,use_tls,encrypted_credentials) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING created_at,updated_at`, item.ID, item.OrganizationID, item.Name, item.Endpoint, item.Region, item.Bucket, item.Prefix, item.UseTLS, item.EncryptedCredentials).Scan(&item.CreatedAt, &item.UpdatedAt); err != nil {
		return BackupDestination{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "backup_destination.create", "backup_destination", item.ID.String(), remoteAddr, map[string]any{"endpoint": item.Endpoint, "bucket": item.Bucket}); err != nil {
		return BackupDestination{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return BackupDestination{}, err
	}
	return item, nil
}

func (s *Store) UpdateBackupDestination(ctx context.Context, organizationID uuid.UUID, item BackupDestination) (BackupDestination, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return BackupDestination{}, err
	}
	defer tx.Rollback(ctx)
	item, err = updateBackupDestinationTx(ctx, tx, organizationID, item)
	if err != nil {
		return BackupDestination{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return BackupDestination{}, err
	}
	return item, nil
}

func (s *Store) UpdateBackupDestinationWithAudit(ctx context.Context, principal Principal, item BackupDestination, remoteAddr string) (BackupDestination, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return BackupDestination{}, err
	}
	defer tx.Rollback(ctx)
	item, err = updateBackupDestinationTx(ctx, tx, principal.OrganizationID, item)
	if err != nil {
		return BackupDestination{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "backup_destination.update", "backup_destination", item.ID.String(), remoteAddr, map[string]any{"endpoint": item.Endpoint, "bucket": item.Bucket}); err != nil {
		return BackupDestination{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return BackupDestination{}, err
	}
	return item, nil
}

func updateBackupDestinationTx(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, item BackupDestination) (BackupDestination, error) {
	var endpoint, region, bucket, prefix string
	var useTLS bool
	if err := tx.QueryRow(ctx, `SELECT endpoint,region,bucket,prefix,use_tls FROM backup_destinations WHERE id=$1 AND organization_id=$2 FOR UPDATE`, item.ID, organizationID).Scan(&endpoint, &region, &bucket, &prefix, &useTLS); errors.Is(err, pgx.ErrNoRows) {
		return BackupDestination{}, ErrNotFound
	} else if err != nil {
		return BackupDestination{}, err
	}
	if err := LockBackupDestinationForOperation(ctx, tx, item.ID); err != nil {
		return BackupDestination{}, err
	}
	var active bool
	if err := tx.QueryRow(ctx, `SELECT
		EXISTS(SELECT 1 FROM database_backups WHERE destination_id=$1 AND status='running') OR
		EXISTS(SELECT 1 FROM database_restores restore JOIN database_backups backup ON backup.id=restore.database_backup_id WHERE backup.destination_id=$1 AND restore.status='running') OR
		EXISTS(SELECT 1 FROM volume_backups WHERE destination_id=$1 AND status='running') OR
		EXISTS(SELECT 1 FROM volume_restores restore JOIN volume_backups backup ON backup.id=restore.volume_backup_id WHERE backup.destination_id=$1 AND restore.status='running') OR
		EXISTS(SELECT 1 FROM audit_archive_batches batch JOIN audit_archive_destinations archive ON archive.id=batch.destination_id WHERE archive.backup_destination_id=$1 AND batch.status='running')`, item.ID).Scan(&active); err != nil {
		return BackupDestination{}, err
	}
	if active {
		return BackupDestination{}, ErrBusy
	}
	if endpoint != item.Endpoint || region != item.Region || bucket != item.Bucket || prefix != item.Prefix || useTLS != item.UseTLS {
		var referenced bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM database_backups WHERE destination_id=$1) OR EXISTS(SELECT 1 FROM volume_backups WHERE destination_id=$1) OR EXISTS(SELECT 1 FROM backup_artifact_deletions WHERE destination_id=$1) OR EXISTS(SELECT 1 FROM audit_archive_destinations WHERE backup_destination_id=$1)`, item.ID).Scan(&referenced); err != nil {
			return BackupDestination{}, err
		}
		if referenced {
			return BackupDestination{}, ErrBusy
		}
	}
	err := tx.QueryRow(ctx, `UPDATE backup_destinations SET name=$3,endpoint=$4,region=$5,bucket=$6,prefix=$7,use_tls=$8,encrypted_credentials=$9,updated_at=now() WHERE id=$1 AND organization_id=$2 RETURNING id,organization_id,name,endpoint,region,bucket,prefix,use_tls,created_at,updated_at`, item.ID, organizationID, item.Name, item.Endpoint, item.Region, item.Bucket, item.Prefix, item.UseTLS, item.EncryptedCredentials).Scan(&item.ID, &item.OrganizationID, &item.Name, &item.Endpoint, &item.Region, &item.Bucket, &item.Prefix, &item.UseTLS, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return BackupDestination{}, err
	}
	return item, nil
}

// LockBackupDestinationForOperation serializes the point where a worker makes
// an operation running with destination mutation. Workers release the lock
// after committing the running state; mutators then either observe that state
// and fail busy, or commit first so the worker loads the new credentials.
func LockBackupDestinationForOperation(ctx context.Context, tx pgx.Tx, id uuid.UUID) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('dockyard:backup-destination:' || $1::text,0))`, id)
	return err
}

func (s *Store) ListBackupDestinations(ctx context.Context, organizationID uuid.UUID) ([]BackupDestination, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id,organization_id,name,endpoint,region,bucket,prefix,use_tls,created_at,updated_at FROM backup_destinations WHERE organization_id=$1 ORDER BY name`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []BackupDestination{}
	for rows.Next() {
		var item BackupDestination
		if err = rows.Scan(&item.ID, &item.OrganizationID, &item.Name, &item.Endpoint, &item.Region, &item.Bucket, &item.Prefix, &item.UseTLS, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) GetBackupDestination(ctx context.Context, organizationID, id uuid.UUID) (BackupDestination, error) {
	var item BackupDestination
	err := s.Pool.QueryRow(ctx, `SELECT id,organization_id,name,endpoint,region,bucket,prefix,use_tls,encrypted_credentials,created_at,updated_at FROM backup_destinations WHERE id=$1 AND organization_id=$2`, id, organizationID).Scan(&item.ID, &item.OrganizationID, &item.Name, &item.Endpoint, &item.Region, &item.Bucket, &item.Prefix, &item.UseTLS, &item.EncryptedCredentials, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return BackupDestination{}, ErrNotFound
	}
	return item, err
}

func (s *Store) DeleteBackupDestination(ctx context.Context, organizationID, id uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = deleteBackupDestinationTx(ctx, tx, organizationID, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) DeleteBackupDestinationWithAudit(ctx context.Context, principal Principal, id uuid.UUID, remoteAddr string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = deleteBackupDestinationTx(ctx, tx, principal.OrganizationID, id); err != nil {
		return err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "backup_destination.delete", "backup_destination", id.String(), remoteAddr, nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func deleteBackupDestinationTx(ctx context.Context, tx pgx.Tx, organizationID, id uuid.UUID) error {
	var found bool
	if err := tx.QueryRow(ctx, `SELECT true FROM backup_destinations WHERE id=$1 AND organization_id=$2 FOR UPDATE`, id, organizationID).Scan(&found); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if err := LockBackupDestinationForOperation(ctx, tx, id); err != nil {
		return err
	}
	var referenced bool
	if err := tx.QueryRow(ctx, `SELECT
		EXISTS(SELECT 1 FROM backup_policies WHERE destination_id=$1) OR
		EXISTS(SELECT 1 FROM database_backups WHERE destination_id=$1) OR
		EXISTS(SELECT 1 FROM volume_backup_policies WHERE destination_id=$1) OR
		EXISTS(SELECT 1 FROM volume_backups WHERE destination_id=$1) OR
		EXISTS(SELECT 1 FROM backup_artifact_deletions WHERE destination_id=$1) OR
		EXISTS(SELECT 1 FROM audit_archive_destinations WHERE backup_destination_id=$1)`, id).Scan(&referenced); err != nil {
		return err
	}
	if referenced {
		return ErrBusy
	}
	tag, err := tx.Exec(ctx, `DELETE FROM backup_destinations WHERE id=$1 AND organization_id=$2`, id, organizationID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) GetDatabaseBackup(ctx context.Context, organizationID, id uuid.UUID) (DatabaseBackup, error) {
	var b DatabaseBackup
	err := s.Pool.QueryRow(ctx, `SELECT b.id,b.database_instance_id,b.status,b.format,b.path,b.size_bytes,b.sha256,b.encrypted,b.plaintext_sha256,b.encrypted_data_key,b.destination_id,b.object_key,b.error,b.created_at,b.started_at,b.finished_at FROM database_backups b JOIN database_instances d ON d.id=b.database_instance_id JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE b.id=$1 AND p.organization_id=$2`, id, organizationID).Scan(&b.ID, &b.DatabaseInstanceID, &b.Status, &b.Format, &b.Path, &b.SizeBytes, &b.SHA256, &b.Encrypted, &b.PlaintextSHA256, &b.EncryptedDataKey, &b.DestinationID, &b.ObjectKey, &b.Error, &b.CreatedAt, &b.StartedAt, &b.FinishedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return DatabaseBackup{}, ErrNotFound
	}
	return b, err
}

func (s *Store) QueueDatabaseRestore(ctx context.Context, organizationID, backupID, actorID uuid.UUID, confirmation string) (DatabaseRestore, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return DatabaseRestore{}, err
	}
	defer tx.Rollback(ctx)
	restore, err := queueDatabaseRestoreTx(ctx, tx, organizationID, backupID, actorID, confirmation)
	if err != nil {
		return DatabaseRestore{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return DatabaseRestore{}, err
	}
	return restore, nil
}

func (s *Store) QueueDatabaseRestoreWithAudit(ctx context.Context, principal Principal, backupID uuid.UUID, confirmation, remoteAddr string) (DatabaseRestore, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return DatabaseRestore{}, err
	}
	defer tx.Rollback(ctx)
	restore, err := queueDatabaseRestoreTx(ctx, tx, principal.OrganizationID, backupID, principal.UserID, confirmation)
	if err != nil {
		return DatabaseRestore{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "database.restore.create", "database_restore", restore.ID.String(), remoteAddr, map[string]any{"backupId": backupID}); err != nil {
		return DatabaseRestore{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return DatabaseRestore{}, err
	}
	return restore, nil
}

func queueDatabaseRestoreTx(ctx context.Context, tx pgx.Tx, organizationID, backupID, actorID uuid.UUID, confirmation string) (DatabaseRestore, error) {
	var slug, status string
	var backupDatabaseID uuid.UUID
	var composeServiceID *uuid.UUID
	err := tx.QueryRow(ctx, `SELECT d.id,d.slug,b.status,d.compose_service_id FROM database_backups b JOIN database_instances d ON d.id=b.database_instance_id JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE b.id=$1 AND p.organization_id=$2 FOR UPDATE OF d,b`, backupID, organizationID).Scan(&backupDatabaseID, &slug, &status, &composeServiceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return DatabaseRestore{}, ErrNotFound
	}
	if err != nil {
		return DatabaseRestore{}, err
	}
	if err = lockDatabaseServiceForOperation(ctx, tx, backupDatabaseID, composeServiceID); err != nil {
		return DatabaseRestore{}, err
	}
	if err = requireDatabaseServiceRunning(ctx, tx, composeServiceID); err != nil {
		return DatabaseRestore{}, err
	}
	if status != "succeeded" {
		return DatabaseRestore{}, errors.New("backup is not restorable")
	}
	if confirmation != slug {
		return DatabaseRestore{}, errors.New("restore confirmation must match database slug")
	}
	var active bool
	if err = tx.QueryRow(ctx, `SELECT
		EXISTS(SELECT 1 FROM database_restores restore JOIN database_backups backup ON backup.id=restore.database_backup_id WHERE backup.database_instance_id=$1 AND restore.status IN ('queued','running'))
		OR EXISTS(SELECT 1 FROM jobs WHERE resource_key=$2 AND kind='restore.database' AND status IN ('pending','running'))`, backupDatabaseID, "database:"+backupDatabaseID.String()).Scan(&active); err != nil {
		return DatabaseRestore{}, err
	}
	if active {
		return DatabaseRestore{}, ErrBusy
	}
	restore := DatabaseRestore{ID: uuid.New(), DatabaseBackupID: backupID, Status: "queued"}
	restore.Kind = "manual"
	if err = tx.QueryRow(ctx, `INSERT INTO database_restores(id,database_backup_id,status,kind,actor_user_id) VALUES($1,$2,'queued','manual',$3) RETURNING created_at`, restore.ID, backupID, nullableUUID(actorID)).Scan(&restore.CreatedAt); err != nil {
		return DatabaseRestore{}, err
	}
	payload, _ := json.Marshal(map[string]string{"restoreId": restore.ID.String()})
	if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,resource_key) VALUES($1,'restore.database',$2,$3)`, uuid.New(), payload, "database:"+backupDatabaseID.String()); err != nil {
		return DatabaseRestore{}, err
	}
	return restore, nil
}

func lockDatabaseServiceForOperation(ctx context.Context, tx pgx.Tx, databaseID uuid.UUID, composeServiceID *uuid.UUID) error {
	if composeServiceID != nil {
		var lockedID uuid.UUID
		err := tx.QueryRow(ctx, `SELECT id FROM compose_services WHERE id=$1 AND deletion_requested_at IS NULL FOR UPDATE`, *composeServiceID).Scan(&lockedID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrDeleting
		}
		if err != nil {
			return err
		}
	}
	var parentsActive bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM database_instances database JOIN environments environment ON environment.id=database.environment_id JOIN projects project ON project.id=environment.project_id WHERE database.id=$1 AND environment.deletion_requested_at IS NULL AND project.deletion_requested_at IS NULL)`, databaseID).Scan(&parentsActive); err != nil {
		return err
	}
	if !parentsActive {
		return ErrDeleting
	}
	return nil
}

func requireDatabaseServiceRunning(ctx context.Context, tx pgx.Tx, composeServiceID *uuid.UUID) error {
	if composeServiceID == nil {
		return nil
	}
	var desiredState string
	if err := tx.QueryRow(ctx, `SELECT desired_state FROM compose_services WHERE id=$1`, *composeServiceID).Scan(&desiredState); err != nil {
		return err
	}
	if desiredState != "running" {
		return ErrServiceStopped
	}
	return nil
}

func (s *Store) GetDatabaseRestore(ctx context.Context, organizationID, id uuid.UUID) (DatabaseRestore, error) {
	var item DatabaseRestore
	err := s.Pool.QueryRow(ctx, `SELECT r.id,r.database_backup_id,r.status,r.kind,r.error,r.created_at,r.started_at,r.finished_at FROM database_restores r JOIN database_backups b ON b.id=r.database_backup_id JOIN database_instances d ON d.id=b.database_instance_id JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE r.id=$1 AND p.organization_id=$2`, id, organizationID).Scan(&item.ID, &item.DatabaseBackupID, &item.Status, &item.Kind, &item.Error, &item.CreatedAt, &item.StartedAt, &item.FinishedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return DatabaseRestore{}, ErrNotFound
	}
	return item, err
}

func (s *Store) QueueDeploymentByToken(ctx context.Context, tokenHash []byte) (Deployment, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Deployment{}, err
	}
	defer tx.Rollback(ctx)
	var tokenID, serviceID, organizationID, projectID, environmentID uuid.UUID
	var revision int64
	var compose, env string
	err = tx.QueryRow(ctx, `SELECT t.id,s.id,s.revision,s.compose_yaml,s.encrypted_env,p.organization_id,p.id,e.id FROM deploy_tokens t JOIN compose_services s ON s.id=t.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE t.token_hash=$1 AND t.revoked_at IS NULL AND t.expires_at>now() AND s.deletion_requested_at IS NULL AND e.deletion_requested_at IS NULL AND p.deletion_requested_at IS NULL FOR UPDATE OF t,s`, tokenHash).Scan(&tokenID, &serviceID, &revision, &compose, &env, &organizationID, &projectID, &environmentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Deployment{}, ErrNotFound
	}
	if err != nil {
		return Deployment{}, err
	}
	if err = s.enforcePolicy(ctx, tx, organizationID, &projectID, &environmentID, "deployment"); err != nil {
		return Deployment{}, err
	}
	if err = ensureEnvironmentClusterWritable(ctx, tx, environmentID); err != nil {
		return Deployment{}, err
	}
	if err = cancelQueuedReconciliationTx(ctx, tx, serviceID, "superseded by a requested deployment"); err != nil {
		return Deployment{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE compose_services SET desired_state='running',updated_at=now() WHERE id=$1`, serviceID); err != nil {
		return Deployment{}, err
	}
	d := Deployment{ID: uuid.New(), ComposeServiceID: serviceID, Revision: revision, Status: "queued", Trigger: "webhook"}
	if err = tx.QueryRow(ctx, `INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,env_snapshot,status,trigger) VALUES($1,$2,$3,$4,$5,'queued','webhook') RETURNING created_at`, d.ID, serviceID, revision, compose, env).Scan(&d.CreatedAt); err != nil {
		return Deployment{}, err
	}
	if err = snapshotDeploymentRegistryCredentialTx(ctx, tx, d.ID, serviceID); err != nil {
		return Deployment{}, err
	}
	payload, _ := json.Marshal(map[string]string{"deploymentId": d.ID.String()})
	if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,resource_key) VALUES($1,'deploy.compose',$2,$3)`, uuid.New(), payload, "service:"+serviceID.String()); err != nil {
		return Deployment{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE deploy_tokens SET last_used_at=now() WHERE id=$1`, tokenID); err != nil {
		return Deployment{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Deployment{}, err
	}
	return d, nil
}

func (s *Store) ListDeployments(ctx context.Context, organizationID, serviceID uuid.UUID, limit int) ([]Deployment, error) {
	if limit < 1 || limit > 100 {
		limit = 50
	}
	rows, err := s.Pool.Query(ctx, `SELECT d.id,d.compose_service_id,d.revision,d.status,d.trigger,d.commit_sha,d.error,d.output,d.created_at,d.started_at,d.finished_at FROM deployments d JOIN compose_services s ON s.id=d.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE d.compose_service_id=$1 AND p.organization_id=$2 ORDER BY d.created_at DESC LIMIT $3`, serviceID, organizationID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Deployment{}
	for rows.Next() {
		var item Deployment
		if err := rows.Scan(&item.ID, &item.ComposeServiceID, &item.Revision, &item.Status, &item.Trigger, &item.CommitSHA, &item.Error, &item.Output, &item.CreatedAt, &item.StartedAt, &item.FinishedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) QueueRollback(ctx context.Context, organizationID, serviceID, actorID uuid.UUID) (Deployment, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Deployment{}, err
	}
	defer tx.Rollback(ctx)
	var projectID, environmentID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT p.id,e.id FROM compose_services s JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE s.id=$1 AND s.deletion_requested_at IS NULL AND e.deletion_requested_at IS NULL AND p.deletion_requested_at IS NULL AND p.organization_id=$2 FOR UPDATE OF s`, serviceID, organizationID).Scan(&projectID, &environmentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Deployment{}, ErrNotFound
	}
	if err != nil {
		return Deployment{}, err
	}
	if err = s.enforcePolicy(ctx, tx, organizationID, &projectID, &environmentID, "deployment"); err != nil {
		return Deployment{}, err
	}
	if err = ensureEnvironmentClusterWritable(ctx, tx, environmentID); err != nil {
		return Deployment{}, err
	}
	var desiredCompose, effectiveCompose, encrypted string
	var registryCredentialID *uuid.UUID
	var registryServer, registryUsername, encryptedRegistryCredential string
	err = tx.QueryRow(ctx, `SELECT d.compose_snapshot,d.effective_compose,d.env_snapshot,d.registry_credential_id,d.registry_credential_server,d.registry_credential_username,d.encrypted_registry_credential FROM deployments d WHERE d.compose_service_id=$1 AND d.status='succeeded' AND d.effective_compose<>'' ORDER BY d.finished_at DESC,d.created_at DESC LIMIT 1`, serviceID).Scan(&desiredCompose, &effectiveCompose, &encrypted, &registryCredentialID, &registryServer, &registryUsername, &encryptedRegistryCredential)
	if errors.Is(err, pgx.ErrNoRows) {
		return Deployment{}, ErrRollbackUnavailable
	}
	if err != nil {
		return Deployment{}, err
	}
	if err = cancelQueuedReconciliationTx(ctx, tx, serviceID, "superseded by a requested deployment"); err != nil {
		return Deployment{}, err
	}
	var revision int64
	if err = tx.QueryRow(ctx, `UPDATE compose_services SET compose_yaml=$2,encrypted_env=$3,revision=revision+1,desired_state='running',updated_at=now() WHERE id=$1 RETURNING revision`, serviceID, desiredCompose, encrypted).Scan(&revision); err != nil {
		return Deployment{}, err
	}
	d := Deployment{ID: uuid.New(), ComposeServiceID: serviceID, Revision: revision, Status: "queued", Trigger: "rollback"}
	if err = tx.QueryRow(ctx, `INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,effective_compose,env_snapshot,status,trigger,actor_user_id,registry_credential_id,registry_credential_server,registry_credential_username,encrypted_registry_credential) VALUES($1,$2,$3,$4,$4,$5,'queued','rollback',$6,$7,$8,$9,$10) RETURNING created_at`, d.ID, serviceID, revision, effectiveCompose, encrypted, nullableUUID(actorID), registryCredentialID, registryServer, registryUsername, encryptedRegistryCredential).Scan(&d.CreatedAt); err != nil {
		return Deployment{}, err
	}
	payload, _ := json.Marshal(map[string]string{"deploymentId": d.ID.String()})
	if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,resource_key) VALUES($1,'deploy.compose',$2,$3)`, uuid.New(), payload, "service:"+serviceID.String()); err != nil {
		return Deployment{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Deployment{}, err
	}
	return d, nil
}

func (s *Store) CreateDatabase(ctx context.Context, organizationID uuid.UUID, instance DatabaseInstance, service ComposeService, encryptedCredentials string) (DatabaseInstance, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return DatabaseInstance{}, err
	}
	defer tx.Rollback(ctx)
	projectID, err := lockEnvironmentForServiceCreation(ctx, tx, organizationID, instance.EnvironmentID)
	if err != nil {
		return DatabaseInstance{}, err
	}
	if err = s.enforcePolicy(ctx, tx, organizationID, &projectID, &instance.EnvironmentID, "services"); err != nil {
		return DatabaseInstance{}, err
	}
	if err = s.enforcePolicy(ctx, tx, organizationID, &projectID, &instance.EnvironmentID, "databases"); err != nil {
		return DatabaseInstance{}, err
	}
	if service.ID == uuid.Nil {
		service.ID = uuid.New()
	}
	service.EnvironmentID = instance.EnvironmentID
	service.Revision = 1
	if err = tx.QueryRow(ctx, `INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml,encrypted_env) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING created_at,updated_at`, service.ID, service.EnvironmentID, service.Name, service.Slug, service.StackName, service.ComposeYAML, service.EncryptedEnv).Scan(&service.CreatedAt, &service.UpdatedAt); err != nil {
		return DatabaseInstance{}, err
	}
	if instance.ID == uuid.Nil {
		instance.ID = uuid.New()
	}
	instance.ComposeServiceID = service.ID
	instance.Status = "pending"
	if instance.DriverSource == "" {
		instance.DriverSource = "unbound"
	}
	config, _ := json.Marshal(instance.Config)
	if err = tx.QueryRow(ctx, `INSERT INTO database_instances(id,environment_id,name,slug,engine,version,driver_source,driver_artifact_digest,compose_service_id,encrypted_credentials,config) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING created_at`, instance.ID, instance.EnvironmentID, instance.Name, instance.Slug, instance.Engine, instance.Version, instance.DriverSource, instance.DriverDigest, instance.ComposeServiceID, encryptedCredentials, config).Scan(&instance.CreatedAt); err != nil {
		return DatabaseInstance{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return DatabaseInstance{}, err
	}
	return instance, nil
}

func (s *Store) GetDatabase(ctx context.Context, organizationID, id uuid.UUID) (DatabaseInstance, error) {
	var item DatabaseInstance
	err := s.Pool.QueryRow(ctx, `SELECT d.id,d.environment_id,d.name,d.slug,d.engine,d.version,d.driver_source,d.driver_artifact_digest,d.storage_node_id,d.compose_service_id,d.config,d.status,d.created_at FROM database_instances d JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE d.id=$1 AND p.organization_id=$2`, id, organizationID).Scan(&item.ID, &item.EnvironmentID, &item.Name, &item.Slug, &item.Engine, &item.Version, &item.DriverSource, &item.DriverDigest, &item.StorageNodeID, &item.ComposeServiceID, &item.Config, &item.Status, &item.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return DatabaseInstance{}, ErrNotFound
	}
	return item, err
}

var (
	ErrDatabaseDriverIdentityMismatch = errors.New("database driver identity does not match the managed database")
	ErrDatabaseDriverConfirmation     = errors.New("confirmation must match database slug")
	ErrStorageNodeMismatch            = errors.New("storage node does not match the persisted assignment")
	ErrDatabaseStorageNodeMismatch    = ErrStorageNodeMismatch
)

func (s *Store) BindPersistentStorageNode(ctx context.Context, serviceID uuid.UUID, databaseID *uuid.UUID, nodeID string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE compose_services SET storage_node_id=$2,updated_at=now() WHERE id=$1 AND (storage_node_id='' OR storage_node_id=$2)`, serviceID, nodeID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrStorageNodeMismatch
	}
	if databaseID != nil {
		tag, err = tx.Exec(ctx, `UPDATE database_instances SET storage_node_id=$2,updated_at=now() WHERE id=$1 AND compose_service_id=$3 AND (storage_node_id='' OR storage_node_id=$2)`, *databaseID, nodeID, serviceID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrStorageNodeMismatch
		}
	}
	return tx.Commit(ctx)
}

// BindDatabaseStorageNode makes the first successful placement durable and
// verifies subsequent workers selected the same node. A database is never
// silently moved to an empty node-local Docker volume.
func (s *Store) BindDatabaseStorageNode(ctx context.Context, id uuid.UUID, nodeID string) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE database_instances SET storage_node_id=$2,updated_at=now() WHERE id=$1 AND (storage_node_id='' OR storage_node_id=$2)`, id, nodeID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrDatabaseStorageNodeMismatch
	}
	return nil
}

// BindDatabaseDriverIdentity atomically upgrades a legacy unbound database or
// verifies that another controller already bound it to the same driver. This
// prevents HA workers with different external artifacts from processing the
// same database.
func (s *Store) BindDatabaseDriverIdentity(ctx context.Context, id uuid.UUID, source, digest string) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE database_instances SET driver_source=$2,driver_artifact_digest=$3,updated_at=now() WHERE id=$1 AND (driver_source='unbound' OR (driver_source=$2 AND driver_artifact_digest=$3))`, id, source, digest)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrDatabaseDriverIdentityMismatch
	}
	return nil
}

func (s *Store) RebindDatabaseDriverIdentity(ctx context.Context, principal Principal, id uuid.UUID, confirmation, source, digest, remoteAddr string) (DatabaseInstance, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return DatabaseInstance{}, err
	}
	defer tx.Rollback(ctx)
	var item DatabaseInstance
	var composeServiceID *uuid.UUID
	err = tx.QueryRow(ctx, `SELECT d.id,d.environment_id,d.name,d.slug,d.engine,d.version,d.driver_source,d.driver_artifact_digest,d.storage_node_id,d.compose_service_id,d.config,d.status,d.created_at FROM database_instances d JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE d.id=$1 AND p.organization_id=$2 FOR UPDATE OF d`, id, principal.OrganizationID).Scan(&item.ID, &item.EnvironmentID, &item.Name, &item.Slug, &item.Engine, &item.Version, &item.DriverSource, &item.DriverDigest, &item.StorageNodeID, &composeServiceID, &item.Config, &item.Status, &item.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return DatabaseInstance{}, ErrNotFound
	}
	if err != nil {
		return DatabaseInstance{}, err
	}
	if composeServiceID != nil {
		item.ComposeServiceID = *composeServiceID
	}
	if err = lockDatabaseServiceForOperation(ctx, tx, id, composeServiceID); err != nil {
		return DatabaseInstance{}, err
	}
	if confirmation != item.Slug {
		return DatabaseInstance{}, ErrDatabaseDriverConfirmation
	}
	var busy bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM jobs WHERE resource_key=$1 AND status IN ('pending','running'))`, "database:"+id.String()).Scan(&busy); err != nil {
		return DatabaseInstance{}, err
	}
	if busy {
		return DatabaseInstance{}, ErrBusy
	}
	previousSource, previousDigest := item.DriverSource, item.DriverDigest
	if _, err = tx.Exec(ctx, `UPDATE database_instances SET driver_source=$2,driver_artifact_digest=$3,updated_at=now() WHERE id=$1`, id, source, digest); err != nil {
		return DatabaseInstance{}, err
	}
	metadata, err := json.Marshal(map[string]any{"engine": item.Engine, "previousSource": previousSource, "previousDigest": previousDigest, "source": source, "digest": digest})
	if err != nil {
		return DatabaseInstance{}, err
	}
	var serviceAccountID any
	if principal.ServiceAccountID != nil {
		serviceAccountID = *principal.ServiceAccountID
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_events(organization_id,actor_user_id,actor_service_account_id,action,resource_type,resource_id,remote_addr,metadata) VALUES($1,$2,$3,'database.driver_rebind','database',$4,$5,$6)`, principal.OrganizationID, nullableUUID(principal.UserID), serviceAccountID, id.String(), remoteAddr, metadata); err != nil {
		return DatabaseInstance{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return DatabaseInstance{}, err
	}
	item.DriverSource, item.DriverDigest = source, digest
	return item, nil
}

func (s *Store) ListDatabases(ctx context.Context, organizationID, environmentID uuid.UUID) ([]DatabaseInstance, error) {
	rows, err := s.Pool.Query(ctx, `SELECT d.id,d.environment_id,d.name,d.slug,d.engine,d.version,d.driver_source,d.driver_artifact_digest,d.storage_node_id,d.compose_service_id,d.config,d.status,d.created_at FROM database_instances d JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE d.environment_id=$1 AND p.organization_id=$2 ORDER BY d.name`, environmentID, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []DatabaseInstance{}
	for rows.Next() {
		var item DatabaseInstance
		if err = rows.Scan(&item.ID, &item.EnvironmentID, &item.Name, &item.Slug, &item.Engine, &item.Version, &item.DriverSource, &item.DriverDigest, &item.StorageNodeID, &item.ComposeServiceID, &item.Config, &item.Status, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) CreateTemplate(ctx context.Context, item Template) (Template, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Template{}, err
	}
	defer tx.Rollback(ctx)
	item, err = createTemplateTx(ctx, tx, item)
	if err != nil {
		return Template{}, err
	}
	return item, tx.Commit(ctx)
}

func (s *Store) CreateTemplateWithAudit(ctx context.Context, principal Principal, item Template, remoteAddr string) (Template, error) {
	item.OrganizationID = &principal.OrganizationID
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Template{}, err
	}
	defer tx.Rollback(ctx)
	item, err = createTemplateTx(ctx, tx, item)
	if err != nil {
		return Template{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "template.import", "template", item.ID.String(), remoteAddr, nil); err != nil {
		return Template{}, err
	}
	return item, tx.Commit(ctx)
}

func createTemplateTx(ctx context.Context, tx pgx.Tx, item Template) (Template, error) {
	item.ID = uuid.New()
	err := tx.QueryRow(ctx, `INSERT INTO templates(id,organization_id,repository_id,template_key,version,name,description,compose_yaml,config,source,source_path,checksum) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING created_at`, item.ID, item.OrganizationID, item.RepositoryID, item.Key, item.Version, item.Name, item.Description, item.ComposeYAML, item.Config, item.Source, item.SourcePath, item.Checksum).Scan(&item.CreatedAt)
	return item, err
}

func (s *Store) UpsertGlobalTemplate(ctx context.Context, item Template) (Template, error) {
	item.OrganizationID = nil
	var existing uuid.UUID
	err := s.Pool.QueryRow(ctx, `SELECT id FROM templates WHERE organization_id IS NULL AND template_key=$1 AND version=$2`, item.Key, item.Version).Scan(&existing)
	if err == nil {
		item.ID = existing
		err = s.Pool.QueryRow(ctx, `UPDATE templates SET name=$2,description=$3,compose_yaml=$4,config=$5,source=$6,checksum=$7 WHERE id=$1 RETURNING created_at`, item.ID, item.Name, item.Description, item.ComposeYAML, item.Config, item.Source, item.Checksum).Scan(&item.CreatedAt)
		return item, err
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Template{}, err
	}
	return s.CreateTemplate(ctx, item)
}

// UpsertGlobalTemplates publishes a complete validated catalog as one
// transaction. A database error cannot expose only the prefix of a catalog.
func (s *Store) UpsertGlobalTemplates(ctx context.Context, items []Template) error {
	if len(items) == 0 {
		return errors.New("global template catalog must contain at least one template")
	}
	source := items[0].Source
	if source == "" {
		return errors.New("global template catalog source is required")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	ids := make([]uuid.UUID, 0, len(items))
	for _, item := range items {
		if item.OrganizationID != nil || item.RepositoryID != nil {
			return errors.New("global template catalog contains a scoped template")
		}
		if item.Source != source {
			return errors.New("global template catalog contains mixed sources")
		}
		item.ID = uuid.New()
		var id uuid.UUID
		if err = tx.QueryRow(ctx, `INSERT INTO templates(id,organization_id,repository_id,template_key,version,name,description,compose_yaml,config,source,source_path,checksum)
			VALUES($1,NULL,NULL,$2,$3,$4,$5,$6,$7,$8,$9,$10)
			ON CONFLICT (organization_id,template_key,version) DO UPDATE SET repository_id=NULL,name=excluded.name,description=excluded.description,compose_yaml=excluded.compose_yaml,config=excluded.config,source=excluded.source,source_path=excluded.source_path,checksum=excluded.checksum
			RETURNING id`, item.ID, item.Key, item.Version, item.Name, item.Description, item.ComposeYAML, item.Config, item.Source, item.SourcePath, item.Checksum).Scan(&id); err != nil {
			return err
		}
		ids = append(ids, id)
	}
	if _, err = tx.Exec(ctx, `DELETE FROM templates WHERE organization_id IS NULL AND source=$1 AND NOT (id=ANY($2::uuid[]))`, source, ids); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) ListTemplatesPage(ctx context.Context, organizationID uuid.UUID, after *TemplatePageCursor, limit int) ([]Template, bool, error) {
	if limit < 1 || limit > 200 {
		return nil, false, errors.New("template page limit must be between 1 and 200")
	}
	query := `SELECT id,organization_id,repository_id,template_key,version,name,description,config,source,source_path,checksum,created_at
		FROM templates
		WHERE (organization_id IS NULL OR organization_id=$1)`
	args := []any{organizationID}
	if after != nil {
		query += ` AND (name>$2 OR (name=$2 AND version<$3) OR (name=$2 AND version=$3 AND id>$4))`
		args = append(args, after.Name, after.Version, after.ID)
	}
	args = append(args, limit+1)
	query += fmt.Sprintf(` ORDER BY name,version DESC,id LIMIT $%d`, len(args))
	rows, err := s.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	items := make([]Template, 0, limit+1)
	for rows.Next() {
		var item Template
		if err := rows.Scan(&item.ID, &item.OrganizationID, &item.RepositoryID, &item.Key, &item.Version, &item.Name, &item.Description, &item.Config, &item.Source, &item.SourcePath, &item.Checksum, &item.CreatedAt); err != nil {
			return nil, false, err
		}
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		return nil, false, err
	}
	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}
	return items, hasMore, nil
}

// ListTemplates is retained for bounded internal catalog checks. API clients
// should use ListTemplatesPage so every visible entry remains retrievable.
func (s *Store) ListTemplates(ctx context.Context, organizationID uuid.UUID) ([]Template, error) {
	items, _, err := s.ListTemplatesPage(ctx, organizationID, nil, 200)
	return items, err
}

func (s *Store) ListTemplateVersions(ctx context.Context, organizationID uuid.UUID, key, excludedChecksum string) ([]Template, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id,organization_id,repository_id,template_key,version,name,description,config,source,source_path,checksum,created_at FROM templates WHERE (organization_id IS NULL OR organization_id=$1) AND template_key=$2 AND checksum<>$3 ORDER BY version DESC,id LIMIT 200`, organizationID, key, excludedChecksum)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Template{}
	for rows.Next() {
		var item Template
		if err = rows.Scan(&item.ID, &item.OrganizationID, &item.RepositoryID, &item.Key, &item.Version, &item.Name, &item.Description, &item.Config, &item.Source, &item.SourcePath, &item.Checksum, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) GetTemplate(ctx context.Context, organizationID, id uuid.UUID) (Template, error) {
	var item Template
	err := s.Pool.QueryRow(ctx, `SELECT id,organization_id,repository_id,template_key,version,name,description,compose_yaml,config,source,source_path,checksum,created_at FROM templates WHERE id=$1 AND (organization_id IS NULL OR organization_id=$2)`, id, organizationID).Scan(&item.ID, &item.OrganizationID, &item.RepositoryID, &item.Key, &item.Version, &item.Name, &item.Description, &item.ComposeYAML, &item.Config, &item.Source, &item.SourcePath, &item.Checksum, &item.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Template{}, ErrNotFound
	}
	return item, err
}

// CreateTemplateService commits the service, its routes, and the catalog
// provenance as one unit so failed route or provenance validation cannot leave
// a partially instantiated workload behind.
func (s *Store) CreateTemplateService(ctx context.Context, organizationID uuid.UUID, service ComposeService, routes []Route, instance TemplateInstance) (ComposeService, []Route, error) {
	if instance.ManagedEnvironmentKeys == nil {
		instance.ManagedEnvironmentKeys = []string{}
	}
	instance.EnvironmentOwnershipRecorded = true
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ComposeService{}, nil, err
	}
	defer tx.Rollback(ctx)
	service, routes, err = s.createTemplateServiceTx(ctx, tx, organizationID, service, routes, instance)
	if err != nil {
		return ComposeService{}, nil, err
	}
	return service, routes, tx.Commit(ctx)
}

func (s *Store) CreateTemplateServiceWithAudit(ctx context.Context, principal Principal, service ComposeService, routes []Route, instance TemplateInstance, remoteAddr string) (ComposeService, []Route, error) {
	if instance.ManagedEnvironmentKeys == nil {
		instance.ManagedEnvironmentKeys = []string{}
	}
	instance.EnvironmentOwnershipRecorded = true
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ComposeService{}, nil, err
	}
	defer tx.Rollback(ctx)
	service, routes, err = s.createTemplateServiceTx(ctx, tx, principal.OrganizationID, service, routes, instance)
	if err != nil {
		return ComposeService{}, nil, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "template.instantiate", "compose_service", service.ID.String(), remoteAddr, map[string]any{"templateId": instance.TemplateID}); err != nil {
		return ComposeService{}, nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return ComposeService{}, nil, err
	}
	return service, routes, nil
}

func (s *Store) createTemplateServiceTx(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, service ComposeService, routes []Route, instance TemplateInstance) (ComposeService, []Route, error) {
	projectID, err := lockEnvironmentForServiceCreation(ctx, tx, organizationID, service.EnvironmentID)
	if err != nil {
		return ComposeService{}, nil, err
	}
	if err = s.enforcePolicy(ctx, tx, organizationID, &projectID, &service.EnvironmentID, "services"); err != nil {
		return ComposeService{}, nil, err
	}
	if len(routes) > 0 {
		if err = s.enforcePolicy(ctx, tx, organizationID, &projectID, &service.EnvironmentID, "deployment"); err != nil {
			return ComposeService{}, nil, err
		}
	}
	if service.ID == uuid.Nil {
		service.ID = uuid.New()
	}
	service.Revision = 1
	service.DesiredState = "running"
	service.Tags = []Tag{}
	if err = tx.QueryRow(ctx, `INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml,encrypted_env) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING created_at,updated_at`, service.ID, service.EnvironmentID, service.Name, service.Slug, service.StackName, service.ComposeYAML, service.EncryptedEnv).Scan(&service.CreatedAt, &service.UpdatedAt); err != nil {
		return ComposeService{}, nil, err
	}
	for index := range routes {
		if routes[index].InternalPath == "" {
			routes[index].InternalPath = "/"
		}
		routes[index].Enabled = !routes[index].Disabled
		routes[index].ID = uuid.New()
		routes[index].ComposeServiceID = service.ID
		if _, err = tx.Exec(ctx, `INSERT INTO routes(id,compose_service_id,service_name,host,path_prefix,internal_path,strip_path,enabled,redirect_regex,redirect_replacement,redirect_permanent,target_port,tls,certificate_resolver) VALUES($1,$2,$3,$4,$5,$6,$7,NOT $8,$9,$10,$11,$12,$13,$14)`, routes[index].ID, service.ID, routes[index].ServiceName, routes[index].Host, routes[index].PathPrefix, routes[index].InternalPath, routes[index].StripPath, routes[index].Disabled, routes[index].RedirectRegex, routes[index].RedirectReplacement, routes[index].RedirectPermanent, routes[index].TargetPort, routes[index].TLS, routes[index].CertificateResolver); err != nil {
			return ComposeService{}, nil, err
		}
	}
	instance.ComposeServiceID = service.ID
	if err = tx.QueryRow(ctx, `INSERT INTO template_instances(compose_service_id,template_id,template_key,template_version,template_checksum,applied_compose_checksum,base_domain,encrypted_variables,encrypted_overrides,managed_environment_keys,environment_ownership_recorded) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING created_at,updated_at`, instance.ComposeServiceID, instance.TemplateID, instance.TemplateKey, instance.TemplateVersion, instance.TemplateChecksum, instance.AppliedComposeChecksum, instance.BaseDomain, instance.EncryptedVariables, instance.EncryptedOverrides, instance.ManagedEnvironmentKeys, instance.EnvironmentOwnershipRecorded).Scan(&instance.CreatedAt, &instance.UpdatedAt); err != nil {
		return ComposeService{}, nil, err
	}
	return service, routes, nil
}

func (s *Store) GetTemplateInstance(ctx context.Context, organizationID, serviceID uuid.UUID) (TemplateInstance, error) {
	var item TemplateInstance
	err := s.Pool.QueryRow(ctx, `SELECT t.compose_service_id,t.template_id,t.template_key,t.template_version,t.template_checksum,t.applied_compose_checksum,t.base_domain,t.encrypted_variables,t.encrypted_overrides,t.managed_environment_keys,t.environment_ownership_recorded,t.created_at,t.updated_at FROM template_instances t JOIN compose_services s ON s.id=t.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE t.compose_service_id=$1 AND p.organization_id=$2`, serviceID, organizationID).Scan(&item.ComposeServiceID, &item.TemplateID, &item.TemplateKey, &item.TemplateVersion, &item.TemplateChecksum, &item.AppliedComposeChecksum, &item.BaseDomain, &item.EncryptedVariables, &item.EncryptedOverrides, &item.ManagedEnvironmentKeys, &item.EnvironmentOwnershipRecorded, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return TemplateInstance{}, ErrNotFound
	}
	return item, err
}

func (s *Store) UpgradeTemplateService(ctx context.Context, organizationID uuid.UUID, expectedRevision int64, service ComposeService, routes []Route, instance TemplateInstance) (ComposeService, []Route, error) {
	if instance.ManagedEnvironmentKeys == nil {
		instance.ManagedEnvironmentKeys = []string{}
	}
	instance.EnvironmentOwnershipRecorded = true
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ComposeService{}, nil, err
	}
	defer tx.Rollback(ctx)
	service, routes, err = s.upgradeTemplateServiceTx(ctx, tx, organizationID, expectedRevision, service, routes, instance)
	if err != nil {
		return ComposeService{}, nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return ComposeService{}, nil, err
	}
	return service, routes, nil
}

func (s *Store) UpgradeTemplateServiceWithAudit(ctx context.Context, principal Principal, expectedRevision int64, service ComposeService, routes []Route, instance TemplateInstance, remoteAddr string, metadata any) (ComposeService, []Route, error) {
	if instance.ManagedEnvironmentKeys == nil {
		instance.ManagedEnvironmentKeys = []string{}
	}
	instance.EnvironmentOwnershipRecorded = true
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ComposeService{}, nil, err
	}
	defer tx.Rollback(ctx)
	service, routes, err = s.upgradeTemplateServiceTx(ctx, tx, principal.OrganizationID, expectedRevision, service, routes, instance)
	if err != nil {
		return ComposeService{}, nil, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "template.upgrade", "compose_service", service.ID.String(), remoteAddr, metadata); err != nil {
		return ComposeService{}, nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return ComposeService{}, nil, err
	}
	return service, routes, nil
}

func (s *Store) upgradeTemplateServiceTx(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, expectedRevision int64, service ComposeService, routes []Route, instance TemplateInstance) (ComposeService, []Route, error) {
	var projectID, environmentID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT p.id,e.id FROM compose_services s JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id JOIN template_instances t ON t.compose_service_id=s.id WHERE s.id=$1 AND s.deletion_requested_at IS NULL AND e.deletion_requested_at IS NULL AND p.deletion_requested_at IS NULL AND p.organization_id=$2 FOR UPDATE OF s,t`, service.ID, organizationID).Scan(&projectID, &environmentID); errors.Is(err, pgx.ErrNoRows) {
		return ComposeService{}, nil, ErrNotFound
	} else if err != nil {
		return ComposeService{}, nil, err
	}
	if err := s.enforcePolicy(ctx, tx, organizationID, &projectID, &environmentID, "deployment"); err != nil {
		return ComposeService{}, nil, err
	}
	if err := ensureNoActiveDeploymentTx(ctx, tx, service.ID); err != nil {
		return ComposeService{}, nil, err
	}
	if err := ensureProtectedVolumesDeclared(ctx, tx, service.ID, service.ComposeYAML); err != nil {
		return ComposeService{}, nil, err
	}
	if err := ensureScheduledTargetsDeclared(ctx, tx, service.ID, service.ComposeYAML); err != nil {
		return ComposeService{}, nil, err
	}
	err := tx.QueryRow(ctx, `UPDATE compose_services SET compose_yaml=$3,encrypted_env=$4,revision=revision+1,updated_at=now() WHERE id=$1 AND revision=$2 AND deletion_requested_at IS NULL RETURNING id,environment_id,name,slug,stack_name,storage_node_id,compose_yaml,encrypted_env,revision,desired_state,created_at,updated_at`, service.ID, expectedRevision, service.ComposeYAML, service.EncryptedEnv).Scan(&service.ID, &service.EnvironmentID, &service.Name, &service.Slug, &service.StackName, &service.StorageNodeID, &service.ComposeYAML, &service.EncryptedEnv, &service.Revision, &service.DesiredState, &service.CreatedAt, &service.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ComposeService{}, nil, ErrBusy
	}
	if err != nil {
		return ComposeService{}, nil, err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM routes WHERE compose_service_id=$1`, service.ID); err != nil {
		return ComposeService{}, nil, err
	}
	for index := range routes {
		if routes[index].InternalPath == "" {
			routes[index].InternalPath = "/"
		}
		routes[index].Enabled = !routes[index].Disabled
		routes[index].ID = uuid.New()
		routes[index].ComposeServiceID = service.ID
		if _, err = tx.Exec(ctx, `INSERT INTO routes(id,compose_service_id,service_name,host,path_prefix,internal_path,strip_path,enabled,redirect_regex,redirect_replacement,redirect_permanent,target_port,tls,certificate_resolver) VALUES($1,$2,$3,$4,$5,$6,$7,NOT $8,$9,$10,$11,$12,$13,$14)`, routes[index].ID, service.ID, routes[index].ServiceName, routes[index].Host, routes[index].PathPrefix, routes[index].InternalPath, routes[index].StripPath, routes[index].Disabled, routes[index].RedirectRegex, routes[index].RedirectReplacement, routes[index].RedirectPermanent, routes[index].TargetPort, routes[index].TLS, routes[index].CertificateResolver); err != nil {
			return ComposeService{}, nil, err
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE template_instances SET template_id=$2,template_key=$3,template_version=$4,template_checksum=$5,applied_compose_checksum=$6,encrypted_variables=$7,encrypted_overrides=$8,managed_environment_keys=$9,environment_ownership_recorded=$10,updated_at=now() WHERE compose_service_id=$1`, service.ID, instance.TemplateID, instance.TemplateKey, instance.TemplateVersion, instance.TemplateChecksum, instance.AppliedComposeChecksum, instance.EncryptedVariables, instance.EncryptedOverrides, instance.ManagedEnvironmentKeys, instance.EnvironmentOwnershipRecorded); err != nil {
		return ComposeService{}, nil, err
	}
	return service, routes, nil
}

func (s *Store) CreateOIDCProvider(ctx context.Context, p OIDCProvider) (OIDCProvider, error) {
	return createOIDCProvider(ctx, s.Pool, p)
}

func (s *Store) CreateOIDCProviderWithAudit(ctx context.Context, principal Principal, p OIDCProvider, remoteAddr string) (OIDCProvider, error) {
	p.OrganizationID = principal.OrganizationID
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return OIDCProvider{}, err
	}
	defer tx.Rollback(ctx)
	p, err = createOIDCProvider(ctx, tx, p)
	if err != nil {
		return OIDCProvider{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "sso.oidc.create", "oidc_provider", p.ID.String(), remoteAddr, nil); err != nil {
		return OIDCProvider{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return OIDCProvider{}, err
	}
	return p, nil
}

func createOIDCProvider(ctx context.Context, db interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, p OIDCProvider) (OIDCProvider, error) {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	if len(p.Scopes) == 0 {
		p.Scopes = []string{"openid", "profile", "email"}
	}
	if p.DefaultRole == "" {
		p.DefaultRole = "developer"
	}
	p.Enabled = true
	err := db.QueryRow(ctx, `INSERT INTO oidc_providers(id,organization_id,name,issuer,client_id,encrypted_client_secret,domains,scopes,default_role) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING enabled`, p.ID, p.OrganizationID, p.Name, p.Issuer, p.ClientID, p.EncryptedClientSecret, p.Domains, p.Scopes, p.DefaultRole).Scan(&p.Enabled)
	return p, err
}

func (s *Store) UpdateOIDCProvider(ctx context.Context, organizationID uuid.UUID, p OIDCProvider) (OIDCProvider, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return OIDCProvider{}, err
	}
	defer tx.Rollback(ctx)
	p, err = updateOIDCProviderTx(ctx, tx, organizationID, p)
	if err != nil {
		return OIDCProvider{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return OIDCProvider{}, err
	}
	return p, nil
}

func (s *Store) UpdateOIDCProviderWithAudit(ctx context.Context, principal Principal, p OIDCProvider, rotatedSecret bool, remoteAddr string) (OIDCProvider, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return OIDCProvider{}, err
	}
	defer tx.Rollback(ctx)
	p, err = updateOIDCProviderTx(ctx, tx, principal.OrganizationID, p)
	if err != nil {
		return OIDCProvider{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "sso.oidc.update", "oidc_provider", p.ID.String(), remoteAddr, map[string]any{"rotatedSecret": rotatedSecret}); err != nil {
		return OIDCProvider{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return OIDCProvider{}, err
	}
	return p, nil
}

func updateOIDCProviderTx(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, p OIDCProvider) (OIDCProvider, error) {
	err := tx.QueryRow(ctx, `UPDATE oidc_providers SET name=$3,issuer=$4,client_id=$5,encrypted_client_secret=CASE WHEN $6='' THEN encrypted_client_secret ELSE $6 END,domains=$7,scopes=$8,default_role=$9 WHERE id=$1 AND organization_id=$2 RETURNING id,organization_id,name,issuer,client_id,domains,scopes,default_role,enabled`, p.ID, organizationID, p.Name, p.Issuer, p.ClientID, p.EncryptedClientSecret, p.Domains, p.Scopes, p.DefaultRole).Scan(&p.ID, &p.OrganizationID, &p.Name, &p.Issuer, &p.ClientID, &p.Domains, &p.Scopes, &p.DefaultRole, &p.Enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return OIDCProvider{}, ErrNotFound
	}
	if err != nil {
		return OIDCProvider{}, err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM oidc_states WHERE provider_id=$1`, p.ID); err != nil {
		return OIDCProvider{}, err
	}
	return p, nil
}

func (s *Store) GetOIDCProvider(ctx context.Context, id uuid.UUID) (OIDCProvider, error) {
	var p OIDCProvider
	err := s.Pool.QueryRow(ctx, `SELECT id,organization_id,name,issuer,client_id,encrypted_client_secret,domains,scopes,default_role,enabled FROM oidc_providers WHERE id=$1 AND enabled`, id).Scan(&p.ID, &p.OrganizationID, &p.Name, &p.Issuer, &p.ClientID, &p.EncryptedClientSecret, &p.Domains, &p.Scopes, &p.DefaultRole, &p.Enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return OIDCProvider{}, ErrNotFound
	}
	return p, err
}

func (s *Store) ListOIDCProviders(ctx context.Context, organizationID uuid.UUID) ([]OIDCProvider, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id,organization_id,name,issuer,client_id,domains,scopes,default_role,enabled FROM oidc_providers WHERE organization_id=$1 ORDER BY name`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []OIDCProvider{}
	for rows.Next() {
		var p OIDCProvider
		if err := rows.Scan(&p.ID, &p.OrganizationID, &p.Name, &p.Issuer, &p.ClientID, &p.Domains, &p.Scopes, &p.DefaultRole, &p.Enabled); err != nil {
			return nil, err
		}
		items = append(items, p)
	}
	return items, rows.Err()
}
func (s *Store) DisableOIDCProvider(ctx context.Context, organizationID, id uuid.UUID) error {
	return s.setSSOProviderEnabled(ctx, organizationID, id, "oidc", false)
}

func (s *Store) SetOIDCProviderEnabled(ctx context.Context, organizationID, id uuid.UUID, enabled bool) error {
	return s.setSSOProviderEnabled(ctx, organizationID, id, "oidc", enabled)
}

func (s *Store) DiscoverOIDC(ctx context.Context, domain string) ([]OIDCProvider, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id,organization_id,name,issuer,client_id,domains,scopes,default_role,enabled FROM oidc_providers WHERE enabled AND $1=ANY(domains) ORDER BY name`, strings.ToLower(domain))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []OIDCProvider{}
	for rows.Next() {
		var p OIDCProvider
		if err := rows.Scan(&p.ID, &p.OrganizationID, &p.Name, &p.Issuer, &p.ClientID, &p.Domains, &p.Scopes, &p.DefaultRole, &p.Enabled); err != nil {
			return nil, err
		}
		items = append(items, p)
	}
	return items, rows.Err()
}

func (s *Store) CreateOIDCState(ctx context.Context, hash []byte, providerID uuid.UUID, verifier, nonce string) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO oidc_states(token_hash,provider_id,code_verifier,nonce,expires_at) VALUES($1,$2,$3,$4,now()+interval '10 minutes')`, hash, providerID, verifier, nonce)
	return err
}

func (s *Store) ConsumeOIDCState(ctx context.Context, hash []byte) (uuid.UUID, string, string, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, "", "", err
	}
	defer tx.Rollback(ctx)
	var providerID uuid.UUID
	var verifier, nonce string
	err = tx.QueryRow(ctx, `DELETE FROM oidc_states WHERE token_hash=$1 AND expires_at>now() RETURNING provider_id,code_verifier,nonce`, hash).Scan(&providerID, &verifier, &nonce)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, "", "", ErrNotFound
	}
	if err != nil {
		return uuid.Nil, "", "", err
	}
	return providerID, verifier, nonce, tx.Commit(ctx)
}

func (s *Store) JITOIDCUser(ctx context.Context, p OIDCProvider, subject, email, name string) (uuid.UUID, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx)
	email = strings.ToLower(email)
	var lockedOrganizationID uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT id FROM organizations WHERE id=$1 FOR UPDATE`, p.OrganizationID).Scan(&lockedOrganizationID); errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrNotFound
	} else if err != nil {
		return uuid.Nil, err
	}
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, email); err != nil {
		return uuid.Nil, err
	}
	var userID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT user_id FROM external_identities WHERE provider_id=$1 AND subject=$2`, p.ID, subject).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(ctx, `SELECT id FROM users WHERE email=$1`, email).Scan(&userID)
		if errors.Is(err, pgx.ErrNoRows) {
			userID = uuid.New()
			_, err = tx.Exec(ctx, `INSERT INTO users(id,email,password_hash,display_name) VALUES($1,$2,$3,$4)`, userID, email, "!oidc:"+uuid.NewString(), name)
		}
		if err != nil {
			return uuid.Nil, err
		}
		_, err = tx.Exec(ctx, `INSERT INTO external_identities(provider_id,subject,user_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, p.ID, subject, userID)
		if err != nil {
			return uuid.Nil, err
		}
	} else if err != nil {
		return uuid.Nil, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, p.OrganizationID, userID, p.DefaultRole)
	if err != nil {
		return uuid.Nil, err
	}
	return userID, tx.Commit(ctx)
}

func (s *Store) CreateSAMLProvider(ctx context.Context, p SAMLProvider) (SAMLProvider, error) {
	return createSAMLProvider(ctx, s.Pool, p)
}

func (s *Store) CreateSAMLProviderWithAudit(ctx context.Context, principal Principal, p SAMLProvider, remoteAddr string) (SAMLProvider, error) {
	p.OrganizationID = principal.OrganizationID
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return SAMLProvider{}, err
	}
	defer tx.Rollback(ctx)
	p, err = createSAMLProvider(ctx, tx, p)
	if err != nil {
		return SAMLProvider{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "sso.saml.create", "saml_provider", p.ID.String(), remoteAddr, nil); err != nil {
		return SAMLProvider{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return SAMLProvider{}, err
	}
	return p, nil
}

func createSAMLProvider(ctx context.Context, db interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, p SAMLProvider) (SAMLProvider, error) {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	p.Enabled = true
	err := db.QueryRow(ctx, `INSERT INTO saml_providers(id,organization_id,name,idp_metadata,certificate_pem,encrypted_private_key,domains,email_attribute,name_attribute,default_role,allow_idp_initiated) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING enabled`, p.ID, p.OrganizationID, p.Name, p.IDPMetadata, p.CertificatePEM, p.EncryptedPrivateKey, p.Domains, p.EmailAttribute, p.NameAttribute, p.DefaultRole, p.AllowIDPInitiated).Scan(&p.Enabled)
	return p, err
}

func (s *Store) UpdateSAMLProvider(ctx context.Context, organizationID uuid.UUID, p SAMLProvider) (SAMLProvider, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return SAMLProvider{}, err
	}
	defer tx.Rollback(ctx)
	p, err = updateSAMLProviderTx(ctx, tx, organizationID, p)
	if err != nil {
		return SAMLProvider{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return SAMLProvider{}, err
	}
	return p, nil
}

func (s *Store) UpdateSAMLProviderWithAudit(ctx context.Context, principal Principal, p SAMLProvider, remoteAddr string) (SAMLProvider, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return SAMLProvider{}, err
	}
	defer tx.Rollback(ctx)
	p, err = updateSAMLProviderTx(ctx, tx, principal.OrganizationID, p)
	if err != nil {
		return SAMLProvider{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "sso.saml.update", "saml_provider", p.ID.String(), remoteAddr, nil); err != nil {
		return SAMLProvider{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return SAMLProvider{}, err
	}
	return p, nil
}

func updateSAMLProviderTx(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, p SAMLProvider) (SAMLProvider, error) {
	err := tx.QueryRow(ctx, `UPDATE saml_providers SET name=$3,idp_metadata=$4,domains=$5,email_attribute=$6,name_attribute=$7,default_role=$8,allow_idp_initiated=$9 WHERE id=$1 AND organization_id=$2 RETURNING id,organization_id,name,idp_metadata,certificate_pem,COALESCE(pending_certificate_pem,''),pending_certificate_not_after,pending_certificate_created_at,domains,email_attribute,name_attribute,default_role,allow_idp_initiated,enabled`, p.ID, organizationID, p.Name, p.IDPMetadata, p.Domains, p.EmailAttribute, p.NameAttribute, p.DefaultRole, p.AllowIDPInitiated).Scan(&p.ID, &p.OrganizationID, &p.Name, &p.IDPMetadata, &p.CertificatePEM, &p.PendingCertificatePEM, &p.PendingCertificateNotAfter, &p.PendingCertificateCreatedAt, &p.Domains, &p.EmailAttribute, &p.NameAttribute, &p.DefaultRole, &p.AllowIDPInitiated, &p.Enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return SAMLProvider{}, ErrNotFound
	}
	if err != nil {
		return SAMLProvider{}, err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM saml_states WHERE provider_id=$1`, p.ID); err != nil {
		return SAMLProvider{}, err
	}
	return p, nil
}

func (s *Store) GetSAMLProvider(ctx context.Context, id uuid.UUID) (SAMLProvider, error) {
	var p SAMLProvider
	err := s.Pool.QueryRow(ctx, `SELECT id,organization_id,name,idp_metadata,certificate_pem,encrypted_private_key,COALESCE(pending_certificate_pem,''),COALESCE(pending_encrypted_private_key,''),pending_certificate_not_after,pending_certificate_created_at,domains,email_attribute,name_attribute,default_role,allow_idp_initiated,enabled FROM saml_providers WHERE id=$1 AND enabled`, id).Scan(&p.ID, &p.OrganizationID, &p.Name, &p.IDPMetadata, &p.CertificatePEM, &p.EncryptedPrivateKey, &p.PendingCertificatePEM, &p.PendingEncryptedPrivateKey, &p.PendingCertificateNotAfter, &p.PendingCertificateCreatedAt, &p.Domains, &p.EmailAttribute, &p.NameAttribute, &p.DefaultRole, &p.AllowIDPInitiated, &p.Enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return SAMLProvider{}, ErrNotFound
	}
	return p, err
}

func (s *Store) GetOrganizationSAMLProvider(ctx context.Context, organizationID, id uuid.UUID) (SAMLProvider, error) {
	var p SAMLProvider
	err := s.Pool.QueryRow(ctx, `SELECT id,organization_id,name,idp_metadata,certificate_pem,encrypted_private_key,COALESCE(pending_certificate_pem,''),COALESCE(pending_encrypted_private_key,''),pending_certificate_not_after,pending_certificate_created_at,domains,email_attribute,name_attribute,default_role,allow_idp_initiated,enabled FROM saml_providers WHERE id=$1 AND organization_id=$2`, id, organizationID).Scan(&p.ID, &p.OrganizationID, &p.Name, &p.IDPMetadata, &p.CertificatePEM, &p.EncryptedPrivateKey, &p.PendingCertificatePEM, &p.PendingEncryptedPrivateKey, &p.PendingCertificateNotAfter, &p.PendingCertificateCreatedAt, &p.Domains, &p.EmailAttribute, &p.NameAttribute, &p.DefaultRole, &p.AllowIDPInitiated, &p.Enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return SAMLProvider{}, ErrNotFound
	}
	return p, err
}

func (s *Store) ListSAMLProviders(ctx context.Context, organizationID uuid.UUID) ([]SAMLProvider, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id,organization_id,name,idp_metadata,certificate_pem,COALESCE(pending_certificate_pem,''),pending_certificate_not_after,pending_certificate_created_at,domains,email_attribute,name_attribute,default_role,allow_idp_initiated,enabled FROM saml_providers WHERE organization_id=$1 ORDER BY name`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []SAMLProvider{}
	for rows.Next() {
		var p SAMLProvider
		if err = rows.Scan(&p.ID, &p.OrganizationID, &p.Name, &p.IDPMetadata, &p.CertificatePEM, &p.PendingCertificatePEM, &p.PendingCertificateNotAfter, &p.PendingCertificateCreatedAt, &p.Domains, &p.EmailAttribute, &p.NameAttribute, &p.DefaultRole, &p.AllowIDPInitiated, &p.Enabled); err != nil {
			return nil, err
		}
		items = append(items, p)
	}
	return items, rows.Err()
}

func (s *Store) BeginSAMLCertificateRotation(ctx context.Context, organizationID, id uuid.UUID, certificatePEM, encryptedPrivateKey string, notAfter time.Time) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = beginSAMLCertificateRotationTx(ctx, tx, organizationID, id, certificatePEM, encryptedPrivateKey, notAfter); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) BeginSAMLCertificateRotationWithAudit(ctx context.Context, principal Principal, id uuid.UUID, certificatePEM, encryptedPrivateKey string, notAfter time.Time, remoteAddr string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = beginSAMLCertificateRotationTx(ctx, tx, principal.OrganizationID, id, certificatePEM, encryptedPrivateKey, notAfter); err != nil {
		return err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "sso.saml.certificate_rotation.begin", "saml_provider", id.String(), remoteAddr, map[string]any{"notAfter": notAfter}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func beginSAMLCertificateRotationTx(ctx context.Context, tx pgx.Tx, organizationID, id uuid.UUID, certificatePEM, encryptedPrivateKey string, notAfter time.Time) error {
	tag, err := tx.Exec(ctx, `UPDATE saml_providers SET pending_certificate_pem=$3,pending_encrypted_private_key=$4,pending_certificate_not_after=$5,pending_certificate_created_at=now() WHERE id=$1 AND organization_id=$2 AND enabled AND pending_certificate_pem IS NULL`, id, organizationID, certificatePEM, encryptedPrivateKey, notAfter)
	if err != nil || tag.RowsAffected() > 0 {
		return err
	}
	var pending bool
	if err = tx.QueryRow(ctx, `SELECT pending_certificate_pem IS NOT NULL FROM saml_providers WHERE id=$1 AND organization_id=$2`, id, organizationID).Scan(&pending); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if pending {
		return ErrSAMLCertificateRotationPending
	}
	return ErrNotFound
}

func (s *Store) PromoteSAMLCertificateRotation(ctx context.Context, organizationID, id uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = promoteSAMLCertificateRotationTx(ctx, tx, organizationID, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) PromoteSAMLCertificateRotationWithAudit(ctx context.Context, principal Principal, id uuid.UUID, remoteAddr string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = promoteSAMLCertificateRotationTx(ctx, tx, principal.OrganizationID, id); err != nil {
		return err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "sso.saml.certificate_rotation.promote", "saml_provider", id.String(), remoteAddr, nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func promoteSAMLCertificateRotationTx(ctx context.Context, tx pgx.Tx, organizationID, id uuid.UUID) error {
	tag, err := tx.Exec(ctx, `UPDATE saml_providers SET certificate_pem=pending_certificate_pem,encrypted_private_key=pending_encrypted_private_key,pending_certificate_pem=NULL,pending_encrypted_private_key=NULL,pending_certificate_not_after=NULL,pending_certificate_created_at=NULL WHERE id=$1 AND organization_id=$2 AND pending_certificate_pem IS NOT NULL`, id, organizationID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err = tx.Exec(ctx, `DELETE FROM saml_states WHERE provider_id=$1`, id); err != nil {
		return err
	}
	return nil
}

func (s *Store) CancelSAMLCertificateRotation(ctx context.Context, organizationID, id uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = cancelSAMLCertificateRotationTx(ctx, tx, organizationID, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) CancelSAMLCertificateRotationWithAudit(ctx context.Context, principal Principal, id uuid.UUID, remoteAddr string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = cancelSAMLCertificateRotationTx(ctx, tx, principal.OrganizationID, id); err != nil {
		return err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "sso.saml.certificate_rotation.cancel", "saml_provider", id.String(), remoteAddr, nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func cancelSAMLCertificateRotationTx(ctx context.Context, tx pgx.Tx, organizationID, id uuid.UUID) error {
	tag, err := tx.Exec(ctx, `UPDATE saml_providers SET pending_certificate_pem=NULL,pending_encrypted_private_key=NULL,pending_certificate_not_after=NULL,pending_certificate_created_at=NULL WHERE id=$1 AND organization_id=$2 AND pending_certificate_pem IS NOT NULL`, id, organizationID)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *Store) DiscoverSAML(ctx context.Context, domain string) ([]SAMLProvider, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id,organization_id,name,domains,email_attribute,name_attribute,default_role,allow_idp_initiated,enabled FROM saml_providers WHERE enabled AND $1=ANY(domains) ORDER BY name`, strings.ToLower(domain))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []SAMLProvider{}
	for rows.Next() {
		var p SAMLProvider
		if err = rows.Scan(&p.ID, &p.OrganizationID, &p.Name, &p.Domains, &p.EmailAttribute, &p.NameAttribute, &p.DefaultRole, &p.AllowIDPInitiated, &p.Enabled); err != nil {
			return nil, err
		}
		items = append(items, p)
	}
	return items, rows.Err()
}

func (s *Store) DisableSAMLProvider(ctx context.Context, organizationID, id uuid.UUID) error {
	return s.setSSOProviderEnabled(ctx, organizationID, id, "saml", false)
}

func (s *Store) SetSAMLProviderEnabled(ctx context.Context, organizationID, id uuid.UUID, enabled bool) error {
	return s.setSSOProviderEnabled(ctx, organizationID, id, "saml", enabled)
}

func (s *Store) CreateSAMLState(ctx context.Context, hash []byte, providerID uuid.UUID, requestID string) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO saml_states(token_hash,provider_id,request_id,expires_at) VALUES($1,$2,$3,now()+interval '10 minutes')`, hash, providerID, requestID)
	return err
}

func (s *Store) ConsumeSAMLState(ctx context.Context, hash []byte, providerID uuid.UUID) (string, error) {
	var requestID string
	err := s.Pool.QueryRow(ctx, `DELETE FROM saml_states WHERE token_hash=$1 AND provider_id=$2 AND expires_at>now() RETURNING request_id`, hash, providerID).Scan(&requestID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return requestID, err
}

func (s *Store) RecordSAMLAssertion(ctx context.Context, providerID uuid.UUID, assertionID string, expiresAt time.Time) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `DELETE FROM saml_assertions WHERE expires_at<now()`); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO saml_assertions(provider_id,assertion_id,expires_at) VALUES($1,$2,$3)`, providerID, assertionID, expiresAt); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) JITSAMLUser(ctx context.Context, p SAMLProvider, subject, email, name string) (uuid.UUID, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx)
	email = strings.ToLower(email)
	var lockedOrganizationID uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT id FROM organizations WHERE id=$1 FOR UPDATE`, p.OrganizationID).Scan(&lockedOrganizationID); errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrNotFound
	} else if err != nil {
		return uuid.Nil, err
	}
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, email); err != nil {
		return uuid.Nil, err
	}
	var userID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT user_id FROM saml_external_identities WHERE provider_id=$1 AND subject=$2`, p.ID, subject).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(ctx, `SELECT id FROM users WHERE email=$1`, email).Scan(&userID)
		if errors.Is(err, pgx.ErrNoRows) {
			userID = uuid.New()
			_, err = tx.Exec(ctx, `INSERT INTO users(id,email,password_hash,display_name) VALUES($1,$2,$3,$4)`, userID, email, "!saml:"+uuid.NewString(), name)
		}
		if err != nil {
			return uuid.Nil, err
		}
		_, err = tx.Exec(ctx, `INSERT INTO saml_external_identities(provider_id,subject,user_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, p.ID, subject, userID)
		if err != nil {
			return uuid.Nil, err
		}
	} else if err != nil {
		return uuid.Nil, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, p.OrganizationID, userID, p.DefaultRole)
	if err != nil {
		return uuid.Nil, err
	}
	return userID, tx.Commit(ctx)
}

func (s *Store) AuthenticateSCIM(ctx context.Context, hash []byte) (uuid.UUID, string, error) {
	var orgID uuid.UUID
	var role string
	err := s.Pool.QueryRow(ctx, `SELECT organization_id,default_role FROM scim_tokens WHERE token_hash=$1 AND revoked_at IS NULL AND expires_at>now()`, hash).Scan(&orgID, &role)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, "", ErrNotFound
	}
	return orgID, role, err
}

func (s *Store) Audit(ctx context.Context, p *Principal, action, resourceType, resourceID, remoteAddr string, metadata any) {
	b, _ := json.Marshal(metadata)
	var org, user, serviceAccount any
	if p != nil {
		org = p.OrganizationID
		user = nullableUUID(p.UserID)
		if p.ServiceAccountID != nil {
			serviceAccount = *p.ServiceAccountID
		}
	}
	_, _ = s.Pool.Exec(ctx, `INSERT INTO audit_events(organization_id,actor_user_id,actor_service_account_id,action,resource_type,resource_id,remote_addr,metadata) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, org, user, serviceAccount, action, resourceType, resourceID, remoteAddr, b)
}

func nullableUUID(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}

func (s *Store) AuditOrganization(ctx context.Context, organizationID uuid.UUID, action, resourceType, resourceID, remoteAddr string, metadata any) {
	b, _ := json.Marshal(metadata)
	_, _ = s.Pool.Exec(ctx, `INSERT INTO audit_events(organization_id,actor_user_id,action,resource_type,resource_id,remote_addr,metadata) VALUES($1,NULL,$2,$3,$4,$5,$6)`, organizationID, action, resourceType, resourceID, remoteAddr, b)
}

// AuditOrganizationTx appends a system-initiated tenant audit event as part of
// the caller's state transition. It is used when success must never be
// reported unless both the mutation and its audit record commit together.
func (s *Store) AuditOrganizationTx(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, action, resourceType, resourceID, remoteAddr string, metadata any) error {
	b, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(organization_id,actor_user_id,action,resource_type,resource_id,remote_addr,metadata) VALUES($1,NULL,$2,$3,$4,$5,$6)`, organizationID, action, resourceType, resourceID, remoteAddr, b)
	return err
}
