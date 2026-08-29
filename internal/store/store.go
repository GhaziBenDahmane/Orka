package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNotFound = errors.New("not found")
var ErrNotCancellable = errors.New("resource is not cancellable")
var ErrBusy = errors.New("resource has an operation in progress")
var ErrDuplicateDelivery = errors.New("webhook delivery already processed")
var ErrSSOProviderRequired = errors.New("an enabled SSO provider is required")
var ErrNoCapacity = errors.New("no eligible cluster has the requested placement capacity")
var ErrRemoteBackupRequired = errors.New("a remote backup destination is required")

type Store struct {
	Pool                 *pgxpool.Pool
	RequireRemoteBackups bool
}

func Open(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	if err := Migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{Pool: pool}, nil
}

type Principal struct {
	UserID           uuid.UUID  `json:"userId"`
	SessionID        uuid.UUID  `json:"-"`
	ServiceAccountID *uuid.UUID `json:"serviceAccountId,omitempty"`
	Email            string     `json:"email"`
	OrganizationID   uuid.UUID  `json:"organizationId"`
	Organization     string     `json:"organization"`
	Role             string     `json:"role"`
}

type Session struct {
	ID         uuid.UUID `json:"id"`
	AuthMethod string    `json:"authMethod"`
	UserAgent  string    `json:"userAgent"`
	IPAddress  string    `json:"ipAddress"`
	ExpiresAt  time.Time `json:"expiresAt"`
	CreatedAt  time.Time `json:"createdAt"`
	LastSeenAt time.Time `json:"lastSeenAt"`
	Current    bool      `json:"current"`
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
	ComposeYAML   string    `json:"composeYaml,omitempty"`
	EncryptedEnv  string    `json:"-"`
	Revision      int64     `json:"revision"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

type Route struct {
	ID                  uuid.UUID `json:"id"`
	ComposeServiceID    uuid.UUID `json:"composeServiceId"`
	ServiceName         string    `json:"serviceName"`
	Host                string    `json:"host"`
	PathPrefix          string    `json:"pathPrefix"`
	TargetPort          int       `json:"targetPort"`
	TLS                 bool      `json:"tls"`
	CertificateResolver string    `json:"certificateResolver"`
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
	ComposeServiceID uuid.UUID      `json:"composeServiceId"`
	Config           map[string]any `json:"config"`
	Status           string         `json:"status"`
	CreatedAt        time.Time      `json:"createdAt"`
}

type Template struct {
	ID             uuid.UUID       `json:"id"`
	OrganizationID *uuid.UUID      `json:"organizationId,omitempty"`
	Key            string          `json:"key"`
	Version        string          `json:"version"`
	Name           string          `json:"name"`
	Description    string          `json:"description"`
	ComposeYAML    string          `json:"composeYaml,omitempty"`
	Config         json.RawMessage `json:"-"`
	Source         string          `json:"source"`
	Checksum       string          `json:"checksum"`
	CreatedAt      time.Time       `json:"createdAt"`
}

type TemplateInstance struct {
	ComposeServiceID       uuid.UUID  `json:"composeServiceId"`
	TemplateID             *uuid.UUID `json:"templateId,omitempty"`
	TemplateKey            string     `json:"templateKey"`
	TemplateVersion        string     `json:"templateVersion"`
	TemplateChecksum       string     `json:"templateChecksum"`
	AppliedComposeChecksum string     `json:"appliedComposeChecksum"`
	BaseDomain             string     `json:"baseDomain"`
	EncryptedVariables     string     `json:"-"`
	Drifted                bool       `json:"drifted"`
	CreatedAt              time.Time  `json:"createdAt"`
	UpdatedAt              time.Time  `json:"updatedAt"`
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
	ID                  uuid.UUID `json:"id"`
	OrganizationID      uuid.UUID `json:"organizationId"`
	Name                string    `json:"name"`
	IDPMetadata         string    `json:"-"`
	CertificatePEM      string    `json:"-"`
	EncryptedPrivateKey string    `json:"-"`
	Domains             []string  `json:"domains"`
	EmailAttribute      string    `json:"emailAttribute"`
	NameAttribute       string    `json:"nameAttribute"`
	DefaultRole         string    `json:"defaultRole"`
	AllowIDPInitiated   bool      `json:"allowIdpInitiated"`
	Enabled             bool      `json:"enabled"`
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
		return Principal{}, errors.New("instance is already bootstrapped")
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
	err := s.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM memberships m LEFT JOIN organization_auth_settings a ON a.organization_id=m.organization_id WHERE m.user_id=$1 AND NOT COALESCE(a.require_sso,false))`, userID).Scan(&allowed)
	return allowed, err
}

func (s *Store) CreateSession(ctx context.Context, userID uuid.UUID, tokenHash []byte, expires time.Time) error {
	_, err := s.CreateSessionWithMetadata(ctx, userID, tokenHash, expires, "local", "", "")
	return err
}

func (s *Store) CreateSessionWithMetadata(ctx context.Context, userID uuid.UUID, tokenHash []byte, expires time.Time, authMethod, userAgent, ipAddress string) (uuid.UUID, error) {
	id := uuid.New()
	_, err := s.Pool.Exec(ctx, `INSERT INTO sessions(id,user_id,token_hash,expires_at,auth_method,user_agent,ip_address) VALUES($1,$2,$3,$4,$5,$6,$7)`, id, userID, tokenHash, expires, authMethod, userAgent, ipAddress)
	return id, err
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash []byte) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM sessions WHERE token_hash=$1`, tokenHash)
	return err
}

func (s *Store) Authenticate(ctx context.Context, tokenHash []byte, organizationID *uuid.UUID) (Principal, error) {
	query := `SELECT u.id,s.id,u.email,o.id,o.name,m.role FROM sessions s JOIN users u ON u.id=s.user_id JOIN memberships m ON m.user_id=u.id JOIN organizations o ON o.id=m.organization_id LEFT JOIN organization_auth_settings a ON a.organization_id=o.id WHERE s.token_hash=$1 AND s.expires_at>now() AND u.disabled_at IS NULL AND (NOT COALESCE(a.require_sso,false) OR s.auth_method<>'local')`
	args := []any{tokenHash}
	if organizationID != nil {
		query += ` AND o.id=$2`
		args = append(args, *organizationID)
	}
	query += ` ORDER BY m.created_at LIMIT 1`
	var p Principal
	if err := s.Pool.QueryRow(ctx, query, args...).Scan(&p.UserID, &p.SessionID, &p.Email, &p.OrganizationID, &p.Organization, &p.Role); err != nil {
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
	item := ServiceAccount{ID: uuid.New(), OrganizationID: organizationID, Name: name, Role: role, Enabled: true, TokenExpiresAt: &expiresAt}
	err = tx.QueryRow(ctx, `INSERT INTO service_accounts(id,organization_id,name,role,created_by) SELECT $1,o.id,$3,$4,$5 FROM organizations o WHERE o.id=$2 RETURNING created_at,updated_at`, item.ID, organizationID, name, role, creatorID).Scan(&item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ServiceAccount{}, ErrNotFound
	}
	if err != nil {
		return ServiceAccount{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO service_account_tokens(id,service_account_id,token_hash,expires_at) VALUES($1,$2,$3,$4)`, uuid.New(), item.ID, tokenHash, expiresAt); err != nil {
		return ServiceAccount{}, err
	}
	return item, tx.Commit(ctx)
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
	var exists bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM service_accounts WHERE id=$1 AND organization_id=$2 AND enabled)`, id, organizationID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	if _, err = tx.Exec(ctx, `UPDATE service_account_tokens SET revoked_at=now() WHERE service_account_id=$1 AND revoked_at IS NULL`, id); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO service_account_tokens(id,service_account_id,token_hash,expires_at) VALUES($1,$2,$3,$4)`, uuid.New(), id, tokenHash, expiresAt); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) DisableServiceAccount(ctx context.Context, organizationID, id uuid.UUID) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE service_accounts SET enabled=false,updated_at=now() WHERE id=$1 AND organization_id=$2`, id, organizationID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ListSessions(ctx context.Context, userID, currentID uuid.UUID) ([]Session, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id,auth_method,user_agent,ip_address,expires_at,created_at,last_seen_at,id=$2 FROM sessions WHERE user_id=$1 AND expires_at>now() ORDER BY last_seen_at DESC`, userID, currentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Session{}
	for rows.Next() {
		var item Session
		if err = rows.Scan(&item.ID, &item.AuthMethod, &item.UserAgent, &item.IPAddress, &item.ExpiresAt, &item.CreatedAt, &item.LastSeenAt, &item.Current); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) RevokeSession(ctx context.Context, userID, sessionID uuid.UUID) error {
	tag, err := s.Pool.Exec(ctx, `DELETE FROM sessions WHERE id=$1 AND user_id=$2`, sessionID, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) RevokeOtherSessions(ctx context.Context, userID, currentID uuid.UUID) (int64, error) {
	tag, err := s.Pool.Exec(ctx, `DELETE FROM sessions WHERE user_id=$1 AND id<>$2`, userID, currentID)
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
	var settings OrganizationAuthSettings
	err := s.Pool.QueryRow(ctx, `INSERT INTO organization_auth_settings(organization_id,require_sso)
		SELECT o.id,$2 FROM organizations o WHERE o.id=$1 AND (NOT $2 OR EXISTS(SELECT 1 FROM oidc_providers WHERE organization_id=$1 AND enabled) OR EXISTS(SELECT 1 FROM saml_providers WHERE organization_id=$1 AND enabled))
		ON CONFLICT(organization_id) DO UPDATE SET require_sso=excluded.require_sso,updated_at=now()
		RETURNING require_sso,updated_at`, organizationID, requireSSO).Scan(&settings.RequireSSO, &settings.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		var exists bool
		if lookupErr := s.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM organizations WHERE id=$1)`, organizationID).Scan(&exists); lookupErr != nil {
			return OrganizationAuthSettings{}, lookupErr
		}
		if exists && requireSSO {
			return OrganizationAuthSettings{}, ErrSSOProviderRequired
		}
		return OrganizationAuthSettings{}, ErrNotFound
	}
	return settings, err
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
	return items, rows.Err()
}

func (s *Store) GetProject(ctx context.Context, organizationID, projectID uuid.UUID) (Project, error) {
	var item Project
	err := s.Pool.QueryRow(ctx, `SELECT id,organization_id,name,slug,description,created_at FROM projects WHERE id=$1 AND organization_id=$2`, projectID, organizationID).Scan(&item.ID, &item.OrganizationID, &item.Name, &item.Slug, &item.Description, &item.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Project{}, ErrNotFound
	}
	return item, err
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
	var busy bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM jobs j JOIN deployments d ON d.id=(j.payload->>'deploymentId')::uuid JOIN compose_services s ON s.id=d.compose_service_id JOIN environments e ON e.id=s.environment_id WHERE j.kind='deploy.compose' AND j.status IN ('pending','running') AND e.project_id=$1)`, projectID).Scan(&busy); err != nil {
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
	rows, err := tx.Query(ctx, `SELECT s.id,COALESCE(s.stack_name,''),s.deletion_requested_at IS NOT NULL,e.id,e.deletion_requested_at IS NOT NULL FROM environments e LEFT JOIN compose_services s ON s.environment_id=e.id WHERE e.project_id=$1 ORDER BY e.id,s.id`, projectID)
	if err != nil {
		return err
	}
	type child struct {
		serviceID           *uuid.UUID
		stack               string
		serviceDeleting     bool
		environmentID       uuid.UUID
		environmentDeleting bool
	}
	children := []child{}
	for rows.Next() {
		var c child
		if err = rows.Scan(&c.serviceID, &c.stack, &c.serviceDeleting, &c.environmentID, &c.environmentDeleting); err != nil {
			rows.Close()
			return err
		}
		children = append(children, c)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	environments := map[uuid.UUID]bool{}
	for _, c := range children {
		environments[c.environmentID] = c.environmentDeleting
		if c.serviceID != nil {
			if !c.serviceDeleting {
				_, err = tx.Exec(ctx, `UPDATE compose_services SET deletion_requested_at=now() WHERE id=$1`, *c.serviceID)
			}
			if err != nil {
				return err
			}
			payload, _ := json.Marshal(map[string]string{"serviceId": c.serviceID.String(), "stackName": c.stack})
			if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,max_attempts) SELECT $1,'delete.compose',$2,10 WHERE NOT EXISTS(SELECT 1 FROM jobs WHERE kind='delete.compose' AND payload->>'serviceId'=$3 AND status IN ('pending','running'))`, uuid.New(), payload, c.serviceID.String()); err != nil {
				return err
			}
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
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM clusters WHERE id=$1 AND organization_id=$2 AND state='active' AND NOT COALESCE(now()>=maintenance_starts_at AND now()<maintenance_ends_at,false) AND ($3::jsonb='{}'::jsonb OR labels@>$3::jsonb) AND CASE WHEN jsonb_typeof(capacity->'schedulableNodes')='number' THEN (capacity->>'schedulableNodes')::integer WHEN jsonb_typeof(capacity->'nodes')='number' THEN (capacity->>'nodes')::integer ELSE 0 END >=$4 AND CASE WHEN jsonb_typeof(capacity->'nanoCpus')='number' THEN (capacity->>'nanoCpus')::bigint ELSE 0 END >=$5 AND CASE WHEN jsonb_typeof(capacity->'memoryBytes')='number' THEN (capacity->>'memoryBytes')::bigint ELSE 0 END >=$6 AND (($3::jsonb='{}'::jsonb AND $4=0 AND $5=0 AND $6=0) OR last_seen_at>now()-interval '2 minutes'))`, *clusterID, organizationID, selectorJSON, minimumNodes, minimumNanoCPUs, minimumMemoryBytes).Scan(&clusterExists); err != nil {
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
	var busy bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM jobs j JOIN deployments d ON d.id=(j.payload->>'deploymentId')::uuid JOIN compose_services s ON s.id=d.compose_service_id WHERE j.kind='deploy.compose' AND j.status IN ('pending','running') AND s.environment_id=$1)`, environmentID).Scan(&busy); err != nil {
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
	rows, err := tx.Query(ctx, `SELECT id,stack_name,deletion_requested_at IS NOT NULL FROM compose_services WHERE environment_id=$1`, environmentID)
	if err != nil {
		return err
	}
	type serviceChild struct {
		id       uuid.UUID
		stack    string
		deleting bool
	}
	services := []serviceChild{}
	for rows.Next() {
		var child serviceChild
		if err = rows.Scan(&child.id, &child.stack, &child.deleting); err != nil {
			rows.Close()
			return err
		}
		services = append(services, child)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
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

func (s *Store) CreateComposeService(ctx context.Context, organizationID uuid.UUID, service ComposeService) (ComposeService, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ComposeService{}, err
	}
	defer tx.Rollback(ctx)
	var projectID uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT p.id FROM environments e JOIN projects p ON p.id=e.project_id WHERE e.id=$1 AND p.organization_id=$2`, service.EnvironmentID, organizationID).Scan(&projectID); errors.Is(err, pgx.ErrNoRows) {
		return ComposeService{}, ErrNotFound
	} else if err != nil {
		return ComposeService{}, err
	}
	if err = s.enforcePolicy(ctx, tx, organizationID, &projectID, &service.EnvironmentID, "services"); err != nil {
		return ComposeService{}, err
	}
	if service.ID == uuid.Nil {
		service.ID = uuid.New()
	}
	service.Revision = 1
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
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ComposeService{}, err
	}
	defer tx.Rollback(ctx)
	projectID, environmentID, err := servicePolicyScope(ctx, tx, organizationID, id)
	if err != nil {
		return ComposeService{}, err
	}
	if err = s.enforcePolicy(ctx, tx, organizationID, &projectID, &environmentID, "deployment"); err != nil {
		return ComposeService{}, err
	}
	var service ComposeService
	err = tx.QueryRow(ctx, `UPDATE compose_services s SET compose_yaml=$3, encrypted_env=$4, revision=revision+1, updated_at=now() FROM environments e, projects p WHERE s.id=$1 AND s.deletion_requested_at IS NULL AND e.id=s.environment_id AND p.id=e.project_id AND p.organization_id=$2 RETURNING s.id,s.environment_id,s.name,s.slug,s.stack_name,s.compose_yaml,s.encrypted_env,s.revision,s.created_at,s.updated_at`, id, organizationID, composeYAML, encryptedEnv).Scan(&service.ID, &service.EnvironmentID, &service.Name, &service.Slug, &service.StackName, &service.ComposeYAML, &service.EncryptedEnv, &service.Revision, &service.CreatedAt, &service.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ComposeService{}, ErrNotFound
	}
	if err != nil {
		return ComposeService{}, err
	}
	return service, tx.Commit(ctx)
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
	projectID, environmentID, err := servicePolicyScope(ctx, tx, organizationID, source.ComposeServiceID)
	if err != nil {
		return ApplicationSource{}, err
	}
	if err = s.enforcePolicy(ctx, tx, organizationID, &projectID, &environmentID, "deployment"); err != nil {
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
	projectID, environmentID, err := servicePolicyScope(ctx, tx, organizationID, artifact.ComposeServiceID)
	if err != nil {
		return ApplicationArtifact{}, err
	}
	if err = s.enforcePolicy(ctx, tx, organizationID, &projectID, &environmentID, "deployment"); err != nil {
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
	tag, err := s.Pool.Exec(ctx, `DELETE FROM source_credentials WHERE id=$1 AND organization_id=$2`, id, organizationID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) GetComposeService(ctx context.Context, organizationID, id uuid.UUID) (ComposeService, []Route, error) {
	var v ComposeService
	err := s.Pool.QueryRow(ctx, `SELECT s.id,s.environment_id,s.name,s.slug,s.stack_name,s.compose_yaml,s.encrypted_env,s.revision,s.created_at,s.updated_at FROM compose_services s JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE s.id=$1 AND p.organization_id=$2`, id, organizationID).Scan(&v.ID, &v.EnvironmentID, &v.Name, &v.Slug, &v.StackName, &v.ComposeYAML, &v.EncryptedEnv, &v.Revision, &v.CreatedAt, &v.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ComposeService{}, nil, ErrNotFound
	}
	if err != nil {
		return ComposeService{}, nil, err
	}
	rows, err := s.Pool.Query(ctx, `SELECT id,compose_service_id,service_name,host,path_prefix,target_port,tls,certificate_resolver FROM routes WHERE compose_service_id=$1 ORDER BY host,path_prefix`, id)
	if err != nil {
		return ComposeService{}, nil, err
	}
	defer rows.Close()
	routes := []Route{}
	for rows.Next() {
		var r Route
		if err := rows.Scan(&r.ID, &r.ComposeServiceID, &r.ServiceName, &r.Host, &r.PathPrefix, &r.TargetPort, &r.TLS, &r.CertificateResolver); err != nil {
			return ComposeService{}, nil, err
		}
		routes = append(routes, r)
	}
	return v, routes, rows.Err()
}

func (s *Store) ListComposeServices(ctx context.Context, organizationID, environmentID uuid.UUID) ([]ComposeService, error) {
	rows, err := s.Pool.Query(ctx, `SELECT s.id,s.environment_id,s.name,s.slug,s.stack_name,s.revision,s.created_at,s.updated_at FROM compose_services s JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE s.environment_id=$1 AND s.deletion_requested_at IS NULL AND p.organization_id=$2 ORDER BY s.name`, environmentID, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ComposeService{}
	for rows.Next() {
		var item ComposeService
		if err := rows.Scan(&item.ID, &item.EnvironmentID, &item.Name, &item.Slug, &item.StackName, &item.Revision, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) AddRoute(ctx context.Context, organizationID uuid.UUID, r Route) (Route, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Route{}, err
	}
	defer tx.Rollback(ctx)
	projectID, environmentID, err := servicePolicyScope(ctx, tx, organizationID, r.ComposeServiceID)
	if err != nil {
		return Route{}, err
	}
	if err = s.enforcePolicy(ctx, tx, organizationID, &projectID, &environmentID, "deployment"); err != nil {
		return Route{}, err
	}
	r.ID = uuid.New()
	err = tx.QueryRow(ctx, `INSERT INTO routes(id,compose_service_id,service_name,host,path_prefix,target_port,tls,certificate_resolver) SELECT $1,s.id,$3,$4,$5,$6,$7,$8 FROM compose_services s JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE s.id=$2 AND s.deletion_requested_at IS NULL AND p.organization_id=$9 RETURNING id`, r.ID, r.ComposeServiceID, r.ServiceName, r.Host, r.PathPrefix, r.TargetPort, r.TLS, r.CertificateResolver, organizationID).Scan(&r.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Route{}, ErrNotFound
	}
	if err != nil {
		return Route{}, err
	}
	return r, tx.Commit(ctx)
}

func (s *Store) GetRoute(ctx context.Context, organizationID, id uuid.UUID) (Route, error) {
	var item Route
	err := s.Pool.QueryRow(ctx, `SELECT r.id,r.compose_service_id,r.service_name,r.host,r.path_prefix,r.target_port,r.tls,r.certificate_resolver FROM routes r JOIN compose_services s ON s.id=r.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE r.id=$1 AND p.organization_id=$2`, id, organizationID).Scan(&item.ID, &item.ComposeServiceID, &item.ServiceName, &item.Host, &item.PathPrefix, &item.TargetPort, &item.TLS, &item.CertificateResolver)
	if errors.Is(err, pgx.ErrNoRows) {
		return Route{}, ErrNotFound
	}
	return item, err
}

func (s *Store) DeleteRoute(ctx context.Context, organizationID, id uuid.UUID) error {
	tag, err := s.Pool.Exec(ctx, `DELETE FROM routes r USING compose_services s,environments e,projects p WHERE r.id=$1 AND s.id=r.compose_service_id AND e.id=s.environment_id AND p.id=e.project_id AND p.organization_id=$2`, id, organizationID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) QueueDeployment(ctx context.Context, organizationID, serviceID, actorID uuid.UUID, trigger string) (Deployment, error) {
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
	var compose, env string
	var projectID, environmentID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT s.revision,s.compose_yaml,s.encrypted_env,p.id,e.id FROM compose_services s JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE s.id=$1 AND s.deletion_requested_at IS NULL AND p.organization_id=$2`, serviceID, organizationID).Scan(&d.Revision, &compose, &env, &projectID, &environmentID)
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
	err = tx.QueryRow(ctx, `INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,env_snapshot,status,trigger,actor_user_id) VALUES($1,$2,$3,$4,$5,'queued',$6,$7) RETURNING created_at`, d.ID, serviceID, d.Revision, compose, env, trigger, nullableUUID(actorID)).Scan(&d.CreatedAt)
	if err != nil {
		return Deployment{}, err
	}
	payload, _ := json.Marshal(map[string]string{"deploymentId": d.ID.String()})
	if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload) VALUES($1,'deploy.compose',$2)`, uuid.New(), payload); err != nil {
		return Deployment{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Deployment{}, err
	}
	return d, nil
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
		if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,max_attempts) SELECT $1,'delete.compose',$2,10 WHERE NOT EXISTS(SELECT 1 FROM jobs WHERE kind='delete.compose' AND payload->>'serviceId'=$3 AND status IN ('pending','running'))`, uuid.New(), payload, serviceID.String()); err != nil {
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
	var busy bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM jobs j JOIN deployments d ON j.kind='deploy.compose' AND d.id=(j.payload->>'deploymentId')::uuid WHERE d.compose_service_id=$1 AND j.status IN ('pending','running'))`, serviceID).Scan(&busy); err != nil {
		return err
	}
	if busy {
		return ErrBusy
	}
	if _, err = tx.Exec(ctx, `UPDATE compose_services SET deletion_requested_at=now() WHERE id=$1`, serviceID); err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]any{"serviceId": serviceID.String(), "stackName": stackName, "deleteVolumes": len(deleteVolumes) > 0 && deleteVolumes[0]})
	if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,max_attempts) VALUES($1,'delete.compose',$2,10)`, uuid.New(), payload); err != nil {
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

func (s *Store) CreateDeployToken(ctx context.Context, organizationID, serviceID, userID uuid.UUID, name string, tokenHash []byte) error {
	tag, err := s.Pool.Exec(ctx, `INSERT INTO deploy_tokens(id,compose_service_id,token_hash,name,created_by) SELECT $1,s.id,$3,$4,$5 FROM compose_services s JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE s.id=$2 AND p.organization_id=$6`, uuid.New(), serviceID, tokenHash, name, nullableUUID(userID), organizationID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) CreateWebhookIntegration(ctx context.Context, organizationID uuid.UUID, item WebhookIntegration) (WebhookIntegration, error) {
	if item.ID == uuid.Nil {
		item.ID = uuid.New()
	}
	err := s.Pool.QueryRow(ctx, `INSERT INTO webhook_integrations(id,compose_service_id,name,provider,branch,encrypted_secret)
		SELECT $1,s.id,$3,$4,$5,$6 FROM compose_services s JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE s.id=$2 AND p.organization_id=$7
		RETURNING enabled,created_at,updated_at`, item.ID, item.ComposeServiceID, item.Name, item.Provider, item.Branch, item.EncryptedSecret, organizationID).Scan(&item.Enabled, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return WebhookIntegration{}, ErrNotFound
	}
	item.OrganizationID = organizationID
	return item, err
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
	tag, err := s.Pool.Exec(ctx, `UPDATE webhook_integrations i SET enabled=false,updated_at=now() FROM compose_services s,environments e,projects p WHERE i.id=$1 AND s.id=i.compose_service_id AND e.id=s.environment_id AND p.id=e.project_id AND p.organization_id=$2`, id, organizationID)
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
	err = tx.QueryRow(ctx, `SELECT s.id,s.revision,s.compose_yaml,s.encrypted_env,i.provider,p.organization_id,p.id,e.id FROM webhook_integrations i JOIN compose_services s ON s.id=i.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE i.id=$1 AND i.enabled FOR UPDATE OF i,s`, integrationID).Scan(&serviceID, &revision, &compose, &environment, &provider, &organizationID, &projectID, &environmentID)
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
	payload, _ := json.Marshal(map[string]string{"deploymentId": d.ID.String()})
	if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload) VALUES($1,'deploy.compose',$2)`, uuid.New(), payload); err != nil {
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
	var allowed bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM database_instances d JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE d.id=$1 AND p.organization_id=$2) AND ($3::uuid IS NULL OR EXISTS(SELECT 1 FROM backup_destinations b WHERE b.id=$3 AND b.organization_id=$2))`, databaseID, organizationID, destinationID).Scan(&allowed); err != nil {
		return DatabaseBackup{}, err
	}
	if !allowed {
		return DatabaseBackup{}, ErrNotFound
	}
	backup := DatabaseBackup{ID: uuid.New(), DatabaseInstanceID: databaseID, Status: "queued", Format: "native", DestinationID: destinationID}
	if err = tx.QueryRow(ctx, `INSERT INTO database_backups(id,database_instance_id,status,format,actor_user_id,destination_id) VALUES($1,$2,'queued','native',$3,$4) RETURNING created_at`, backup.ID, databaseID, nullableUUID(actorID), destinationID).Scan(&backup.CreatedAt); err != nil {
		return DatabaseBackup{}, err
	}
	payload, _ := json.Marshal(map[string]string{"backupId": backup.ID.String()})
	if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,resource_key) VALUES($1,'backup.database',$2,$3)`, uuid.New(), payload, "database:"+databaseID.String()); err != nil {
		return DatabaseBackup{}, err
	}
	if err = tx.Commit(ctx); err != nil {
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
	var item BackupPolicy
	err := s.Pool.QueryRow(ctx, `INSERT INTO backup_policies(id,database_instance_id,interval_seconds,retention_count,enabled,next_run_at,destination_id,verify_restore)
		SELECT $1,d.id,$4,$5,$6,now()+($4::int * interval '1 second'),$7,$8 FROM database_instances d JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE d.id=$2 AND p.organization_id=$3 AND ($7::uuid IS NULL OR EXISTS(SELECT 1 FROM backup_destinations bd WHERE bd.id=$7 AND bd.organization_id=$3))
		ON CONFLICT(database_instance_id) DO UPDATE SET interval_seconds=excluded.interval_seconds,retention_count=excluded.retention_count,enabled=excluded.enabled,destination_id=excluded.destination_id,verify_restore=excluded.verify_restore,next_run_at=CASE WHEN backup_policies.enabled=false AND excluded.enabled=true THEN now()+(excluded.interval_seconds * interval '1 second') ELSE backup_policies.next_run_at END,updated_at=now()
		RETURNING id,database_instance_id,interval_seconds,retention_count,enabled,verify_restore,destination_id,next_run_at,last_run_at,created_at,updated_at`, uuid.New(), databaseID, organizationID, intervalSeconds, retentionCount, enabled, destinationID, verifyRestore).Scan(&item.ID, &item.DatabaseInstanceID, &item.IntervalSeconds, &item.RetentionCount, &item.Enabled, &item.VerifyRestore, &item.DestinationID, &item.NextRunAt, &item.LastRunAt, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return BackupPolicy{}, ErrNotFound
	}
	return item, err
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
	tag, err := s.Pool.Exec(ctx, `DELETE FROM backup_policies b USING database_instances d,environments e,projects p WHERE b.database_instance_id=$1 AND d.id=b.database_instance_id AND e.id=d.environment_id AND p.id=e.project_id AND p.organization_id=$2`, databaseID, organizationID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
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
	tag, err := s.Pool.Exec(ctx, `DELETE FROM backup_destinations WHERE id=$1 AND organization_id=$2`, id, organizationID)
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
	var slug, status string
	var backupDatabaseID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT d.id,d.slug,b.status FROM database_backups b JOIN database_instances d ON d.id=b.database_instance_id JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE b.id=$1 AND p.organization_id=$2`, backupID, organizationID).Scan(&backupDatabaseID, &slug, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return DatabaseRestore{}, ErrNotFound
	}
	if err != nil {
		return DatabaseRestore{}, err
	}
	if status != "succeeded" {
		return DatabaseRestore{}, errors.New("backup is not restorable")
	}
	if confirmation != slug {
		return DatabaseRestore{}, errors.New("restore confirmation must match database slug")
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
	if err = tx.Commit(ctx); err != nil {
		return DatabaseRestore{}, err
	}
	return restore, nil
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
	var serviceID, organizationID, projectID, environmentID uuid.UUID
	var revision int64
	var compose, env string
	err = tx.QueryRow(ctx, `SELECT s.id,s.revision,s.compose_yaml,s.encrypted_env,p.organization_id,p.id,e.id FROM deploy_tokens t JOIN compose_services s ON s.id=t.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE t.token_hash=$1 AND t.revoked_at IS NULL`, tokenHash).Scan(&serviceID, &revision, &compose, &env, &organizationID, &projectID, &environmentID)
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
	d := Deployment{ID: uuid.New(), ComposeServiceID: serviceID, Revision: revision, Status: "queued", Trigger: "webhook"}
	if err = tx.QueryRow(ctx, `INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,env_snapshot,status,trigger) VALUES($1,$2,$3,$4,$5,'queued','webhook') RETURNING created_at`, d.ID, serviceID, revision, compose, env).Scan(&d.CreatedAt); err != nil {
		return Deployment{}, err
	}
	payload, _ := json.Marshal(map[string]string{"deploymentId": d.ID.String()})
	if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload) VALUES($1,'deploy.compose',$2)`, uuid.New(), payload); err != nil {
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
	var compose, encrypted string
	var projectID, environmentID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT d.compose_snapshot,d.env_snapshot,p.id,e.id FROM deployments d JOIN compose_services s ON s.id=d.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE s.id=$1 AND p.organization_id=$2 AND d.status='succeeded' ORDER BY d.finished_at DESC LIMIT 1`, serviceID, organizationID).Scan(&compose, &encrypted, &projectID, &environmentID)
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
	var revision int64
	if err = tx.QueryRow(ctx, `UPDATE compose_services SET compose_yaml=$2,encrypted_env=$3,revision=revision+1,updated_at=now() WHERE id=$1 RETURNING revision`, serviceID, compose, encrypted).Scan(&revision); err != nil {
		return Deployment{}, err
	}
	d := Deployment{ID: uuid.New(), ComposeServiceID: serviceID, Revision: revision, Status: "queued", Trigger: "rollback"}
	if err = tx.QueryRow(ctx, `INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,env_snapshot,status,trigger,actor_user_id) VALUES($1,$2,$3,$4,$5,'queued','rollback',$6) RETURNING created_at`, d.ID, serviceID, revision, compose, encrypted, nullableUUID(actorID)).Scan(&d.CreatedAt); err != nil {
		return Deployment{}, err
	}
	payload, _ := json.Marshal(map[string]string{"deploymentId": d.ID.String()})
	if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload) VALUES($1,'deploy.compose',$2)`, uuid.New(), payload); err != nil {
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
	var projectID uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT p.id FROM environments e JOIN projects p ON p.id=e.project_id WHERE e.id=$1 AND p.organization_id=$2`, instance.EnvironmentID, organizationID).Scan(&projectID); errors.Is(err, pgx.ErrNoRows) {
		return DatabaseInstance{}, ErrNotFound
	} else if err != nil {
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
	config, _ := json.Marshal(instance.Config)
	if err = tx.QueryRow(ctx, `INSERT INTO database_instances(id,environment_id,name,slug,engine,version,compose_service_id,encrypted_credentials,config) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING created_at`, instance.ID, instance.EnvironmentID, instance.Name, instance.Slug, instance.Engine, instance.Version, instance.ComposeServiceID, encryptedCredentials, config).Scan(&instance.CreatedAt); err != nil {
		return DatabaseInstance{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return DatabaseInstance{}, err
	}
	return instance, nil
}

func (s *Store) GetDatabase(ctx context.Context, organizationID, id uuid.UUID) (DatabaseInstance, error) {
	var item DatabaseInstance
	err := s.Pool.QueryRow(ctx, `SELECT d.id,d.environment_id,d.name,d.slug,d.engine,d.version,d.compose_service_id,d.config,d.status,d.created_at FROM database_instances d JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE d.id=$1 AND p.organization_id=$2`, id, organizationID).Scan(&item.ID, &item.EnvironmentID, &item.Name, &item.Slug, &item.Engine, &item.Version, &item.ComposeServiceID, &item.Config, &item.Status, &item.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return DatabaseInstance{}, ErrNotFound
	}
	return item, err
}

func (s *Store) ListDatabases(ctx context.Context, organizationID, environmentID uuid.UUID) ([]DatabaseInstance, error) {
	rows, err := s.Pool.Query(ctx, `SELECT d.id,d.environment_id,d.name,d.slug,d.engine,d.version,d.compose_service_id,d.config,d.status,d.created_at FROM database_instances d JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE d.environment_id=$1 AND p.organization_id=$2 ORDER BY d.name`, environmentID, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []DatabaseInstance{}
	for rows.Next() {
		var item DatabaseInstance
		if err = rows.Scan(&item.ID, &item.EnvironmentID, &item.Name, &item.Slug, &item.Engine, &item.Version, &item.ComposeServiceID, &item.Config, &item.Status, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) CreateTemplate(ctx context.Context, item Template) (Template, error) {
	item.ID = uuid.New()
	err := s.Pool.QueryRow(ctx, `INSERT INTO templates(id,organization_id,template_key,version,name,description,compose_yaml,config,source,checksum) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING created_at`, item.ID, item.OrganizationID, item.Key, item.Version, item.Name, item.Description, item.ComposeYAML, item.Config, item.Source, item.Checksum).Scan(&item.CreatedAt)
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

func (s *Store) ListTemplates(ctx context.Context, organizationID uuid.UUID) ([]Template, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id,organization_id,template_key,version,name,description,config,source,checksum,created_at FROM templates WHERE organization_id IS NULL OR organization_id=$1 ORDER BY name,version DESC`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Template{}
	for rows.Next() {
		var item Template
		if err := rows.Scan(&item.ID, &item.OrganizationID, &item.Key, &item.Version, &item.Name, &item.Description, &item.Config, &item.Source, &item.Checksum, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) GetTemplate(ctx context.Context, organizationID, id uuid.UUID) (Template, error) {
	var item Template
	err := s.Pool.QueryRow(ctx, `SELECT id,organization_id,template_key,version,name,description,compose_yaml,config,source,checksum,created_at FROM templates WHERE id=$1 AND (organization_id IS NULL OR organization_id=$2)`, id, organizationID).Scan(&item.ID, &item.OrganizationID, &item.Key, &item.Version, &item.Name, &item.Description, &item.ComposeYAML, &item.Config, &item.Source, &item.Checksum, &item.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Template{}, ErrNotFound
	}
	return item, err
}

// CreateTemplateService commits the service, its routes, and the catalog
// provenance as one unit so failed route or provenance validation cannot leave
// a partially instantiated workload behind.
func (s *Store) CreateTemplateService(ctx context.Context, organizationID uuid.UUID, service ComposeService, routes []Route, instance TemplateInstance) (ComposeService, []Route, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ComposeService{}, nil, err
	}
	defer tx.Rollback(ctx)
	var projectID uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT p.id FROM environments e JOIN projects p ON p.id=e.project_id WHERE e.id=$1 AND p.organization_id=$2`, service.EnvironmentID, organizationID).Scan(&projectID); errors.Is(err, pgx.ErrNoRows) {
		return ComposeService{}, nil, ErrNotFound
	} else if err != nil {
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
	if err = tx.QueryRow(ctx, `INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml,encrypted_env) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING created_at,updated_at`, service.ID, service.EnvironmentID, service.Name, service.Slug, service.StackName, service.ComposeYAML, service.EncryptedEnv).Scan(&service.CreatedAt, &service.UpdatedAt); err != nil {
		return ComposeService{}, nil, err
	}
	for index := range routes {
		routes[index].ID = uuid.New()
		routes[index].ComposeServiceID = service.ID
		if _, err = tx.Exec(ctx, `INSERT INTO routes(id,compose_service_id,service_name,host,path_prefix,target_port,tls,certificate_resolver) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, routes[index].ID, service.ID, routes[index].ServiceName, routes[index].Host, routes[index].PathPrefix, routes[index].TargetPort, routes[index].TLS, routes[index].CertificateResolver); err != nil {
			return ComposeService{}, nil, err
		}
	}
	instance.ComposeServiceID = service.ID
	if err = tx.QueryRow(ctx, `INSERT INTO template_instances(compose_service_id,template_id,template_key,template_version,template_checksum,applied_compose_checksum,base_domain,encrypted_variables) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING created_at,updated_at`, instance.ComposeServiceID, instance.TemplateID, instance.TemplateKey, instance.TemplateVersion, instance.TemplateChecksum, instance.AppliedComposeChecksum, instance.BaseDomain, instance.EncryptedVariables).Scan(&instance.CreatedAt, &instance.UpdatedAt); err != nil {
		return ComposeService{}, nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return ComposeService{}, nil, err
	}
	return service, routes, nil
}

func (s *Store) GetTemplateInstance(ctx context.Context, organizationID, serviceID uuid.UUID) (TemplateInstance, error) {
	var item TemplateInstance
	err := s.Pool.QueryRow(ctx, `SELECT t.compose_service_id,t.template_id,t.template_key,t.template_version,t.template_checksum,t.applied_compose_checksum,t.base_domain,t.encrypted_variables,t.created_at,t.updated_at FROM template_instances t JOIN compose_services s ON s.id=t.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE t.compose_service_id=$1 AND p.organization_id=$2`, serviceID, organizationID).Scan(&item.ComposeServiceID, &item.TemplateID, &item.TemplateKey, &item.TemplateVersion, &item.TemplateChecksum, &item.AppliedComposeChecksum, &item.BaseDomain, &item.EncryptedVariables, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return TemplateInstance{}, ErrNotFound
	}
	return item, err
}

func (s *Store) CreateOIDCProvider(ctx context.Context, p OIDCProvider) (OIDCProvider, error) {
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
	err := s.Pool.QueryRow(ctx, `INSERT INTO oidc_providers(id,organization_id,name,issuer,client_id,encrypted_client_secret,domains,scopes,default_role) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING enabled`, p.ID, p.OrganizationID, p.Name, p.Issuer, p.ClientID, p.EncryptedClientSecret, p.Domains, p.Scopes, p.DefaultRole).Scan(&p.Enabled)
	return p, err
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
	tag, err := s.Pool.Exec(ctx, `UPDATE oidc_providers SET enabled=false WHERE id=$1 AND organization_id=$2`, id, organizationID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
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
	var userID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT user_id FROM external_identities WHERE provider_id=$1 AND subject=$2`, p.ID, subject).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(ctx, `SELECT id FROM users WHERE email=$1`, strings.ToLower(email)).Scan(&userID)
		if errors.Is(err, pgx.ErrNoRows) {
			userID = uuid.New()
			_, err = tx.Exec(ctx, `INSERT INTO users(id,email,password_hash,display_name) VALUES($1,$2,$3,$4)`, userID, strings.ToLower(email), "!oidc:"+uuid.NewString(), name)
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
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	p.Enabled = true
	err := s.Pool.QueryRow(ctx, `INSERT INTO saml_providers(id,organization_id,name,idp_metadata,certificate_pem,encrypted_private_key,domains,email_attribute,name_attribute,default_role,allow_idp_initiated) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING enabled`, p.ID, p.OrganizationID, p.Name, p.IDPMetadata, p.CertificatePEM, p.EncryptedPrivateKey, p.Domains, p.EmailAttribute, p.NameAttribute, p.DefaultRole, p.AllowIDPInitiated).Scan(&p.Enabled)
	return p, err
}

func (s *Store) GetSAMLProvider(ctx context.Context, id uuid.UUID) (SAMLProvider, error) {
	var p SAMLProvider
	err := s.Pool.QueryRow(ctx, `SELECT id,organization_id,name,idp_metadata,certificate_pem,encrypted_private_key,domains,email_attribute,name_attribute,default_role,allow_idp_initiated,enabled FROM saml_providers WHERE id=$1 AND enabled`, id).Scan(&p.ID, &p.OrganizationID, &p.Name, &p.IDPMetadata, &p.CertificatePEM, &p.EncryptedPrivateKey, &p.Domains, &p.EmailAttribute, &p.NameAttribute, &p.DefaultRole, &p.AllowIDPInitiated, &p.Enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return SAMLProvider{}, ErrNotFound
	}
	return p, err
}

func (s *Store) ListSAMLProviders(ctx context.Context, organizationID uuid.UUID) ([]SAMLProvider, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id,organization_id,name,domains,email_attribute,name_attribute,default_role,allow_idp_initiated,enabled FROM saml_providers WHERE organization_id=$1 ORDER BY name`, organizationID)
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
	tag, err := s.Pool.Exec(ctx, `UPDATE saml_providers SET enabled=false WHERE id=$1 AND organization_id=$2`, id, organizationID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
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
	var userID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT user_id FROM saml_external_identities WHERE provider_id=$1 AND subject=$2`, p.ID, subject).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(ctx, `SELECT id FROM users WHERE email=$1`, strings.ToLower(email)).Scan(&userID)
		if errors.Is(err, pgx.ErrNoRows) {
			userID = uuid.New()
			_, err = tx.Exec(ctx, `INSERT INTO users(id,email,password_hash,display_name) VALUES($1,$2,$3,$4)`, userID, strings.ToLower(email), "!saml:"+uuid.NewString(), name)
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

func (s *Store) CreateSCIMToken(ctx context.Context, organizationID uuid.UUID, name, role string, hash []byte) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO scim_tokens(id,organization_id,name,token_hash,default_role) VALUES($1,$2,$3,$4,$5)`, uuid.New(), organizationID, name, hash, role)
	return err
}
func (s *Store) AuthenticateSCIM(ctx context.Context, hash []byte) (uuid.UUID, string, error) {
	var orgID uuid.UUID
	var role string
	err := s.Pool.QueryRow(ctx, `SELECT organization_id,default_role FROM scim_tokens WHERE token_hash=$1 AND revoked_at IS NULL`, hash).Scan(&orgID, &role)
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
