package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var ErrLeaseLost = errors.New("command lease is no longer valid")

const expireAgentUpgradeVerifications = `UPDATE cluster_commands SET status='failed',last_error='replacement agent did not confirm the requested image before the verification deadline',finished_at=now() WHERE cluster_id=$1 AND kind='agent.upgrade' AND status='verifying' AND run_after<=now()`

type Cluster struct {
	ID                                     uuid.UUID      `json:"id"`
	OrganizationID                         uuid.UUID      `json:"organizationId"`
	Name                                   string         `json:"name"`
	Slug                                   string         `json:"slug"`
	State                                  string         `json:"state"`
	Labels                                 map[string]any `json:"labels"`
	Capacity                               map[string]any `json:"capacity"`
	AgentVersion                           string         `json:"agentVersion"`
	AgentImage                             string         `json:"agentImage"`
	AgentUpdateState                       string         `json:"agentUpdateState"`
	DockerVersion                          string         `json:"dockerVersion"`
	CertificateAuthorityFingerprint        string         `json:"certificateAuthorityFingerprint,omitempty"`
	PendingCertificateAuthorityFingerprint string         `json:"pendingCertificateAuthorityFingerprint,omitempty"`
	CertificateNotAfter                    *time.Time     `json:"certificateNotAfter,omitempty"`
	LastSeenAt                             *time.Time     `json:"lastSeenAt,omitempty"`
	MaintenanceStartsAt                    *time.Time     `json:"maintenanceStartsAt,omitempty"`
	MaintenanceEndsAt                      *time.Time     `json:"maintenanceEndsAt,omitempty"`
	CreatedAt                              time.Time      `json:"createdAt"`
	UpdatedAt                              time.Time      `json:"updatedAt"`
}

type ClusterCommand struct {
	ID               uuid.UUID  `json:"id"`
	ClusterID        uuid.UUID  `json:"clusterId"`
	Kind             string     `json:"kind"`
	EncryptedPayload string     `json:"-"`
	Status           string     `json:"status"`
	Attempts         int        `json:"attempts"`
	TargetImage      string     `json:"targetImage,omitempty"`
	LeaseID          *uuid.UUID `json:"leaseId,omitempty"`
	LeaseExpiresAt   *time.Time `json:"leaseExpiresAt,omitempty"`
	EncryptedResult  string     `json:"-"`
	LastError        string     `json:"lastError,omitempty"`
	CreatedAt        time.Time  `json:"createdAt"`
}

type ClusterEnrollmentArtifacts struct {
	Certificate          string
	CABundle             string
	SigningCACertificate string
	SigningCAFingerprint string
}

type ClusterEnrollment struct {
	Cluster   Cluster
	Artifacts ClusterEnrollmentArtifacts
}

func (s *Store) CreateCluster(ctx context.Context, item Cluster) (Cluster, error) {
	item.ID = uuid.New()
	item.State = "pending"
	labels, _ := json.Marshal(item.Labels)
	err := s.Pool.QueryRow(ctx, `INSERT INTO clusters(id,organization_id,name,slug,state,labels) SELECT $1,o.id,$3,$4,'pending',$5 FROM organizations o WHERE o.id=$2 RETURNING created_at,updated_at`, item.ID, item.OrganizationID, item.Name, item.Slug, labels).Scan(&item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Cluster{}, ErrNotFound
	}
	return item, err
}

func (s *Store) ListClusters(ctx context.Context, organizationID uuid.UUID) ([]Cluster, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id,organization_id,name,slug,state,labels,capacity,agent_version,agent_image,agent_update_state,docker_version,certificate_ca_fingerprint,pending_certificate_ca_fingerprint,certificate_not_after,last_seen_at,maintenance_starts_at,maintenance_ends_at,created_at,updated_at FROM clusters WHERE organization_id=$1 ORDER BY name`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Cluster{}
	for rows.Next() {
		var item Cluster
		var labels []byte
		var capacity []byte
		if err := rows.Scan(&item.ID, &item.OrganizationID, &item.Name, &item.Slug, &item.State, &labels, &capacity, &item.AgentVersion, &item.AgentImage, &item.AgentUpdateState, &item.DockerVersion, &item.CertificateAuthorityFingerprint, &item.PendingCertificateAuthorityFingerprint, &item.CertificateNotAfter, &item.LastSeenAt, &item.MaintenanceStartsAt, &item.MaintenanceEndsAt, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(labels, &item.Labels)
		_ = json.Unmarshal(capacity, &item.Capacity)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) GetCluster(ctx context.Context, organizationID, clusterID uuid.UUID) (Cluster, error) {
	var item Cluster
	var labels, capacity []byte
	err := s.Pool.QueryRow(ctx, `SELECT id,organization_id,name,slug,state,labels,capacity,agent_version,agent_image,agent_update_state,docker_version,certificate_ca_fingerprint,pending_certificate_ca_fingerprint,certificate_not_after,last_seen_at,maintenance_starts_at,maintenance_ends_at,created_at,updated_at FROM clusters WHERE id=$1 AND organization_id=$2`, clusterID, organizationID).Scan(&item.ID, &item.OrganizationID, &item.Name, &item.Slug, &item.State, &labels, &capacity, &item.AgentVersion, &item.AgentImage, &item.AgentUpdateState, &item.DockerVersion, &item.CertificateAuthorityFingerprint, &item.PendingCertificateAuthorityFingerprint, &item.CertificateNotAfter, &item.LastSeenAt, &item.MaintenanceStartsAt, &item.MaintenanceEndsAt, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Cluster{}, ErrNotFound
	}
	_ = json.Unmarshal(labels, &item.Labels)
	_ = json.Unmarshal(capacity, &item.Capacity)
	return item, err
}

func (s *Store) UpdateClusterState(ctx context.Context, organizationID, clusterID uuid.UUID, state string) (Cluster, error) {
	return s.UpdateClusterConfiguration(ctx, organizationID, clusterID, state, nil, nil)
}

func (s *Store) UpdateClusterConfiguration(ctx context.Context, organizationID, clusterID uuid.UUID, state string, maintenanceStartsAt, maintenanceEndsAt *time.Time) (Cluster, error) {
	if state != "active" && state != "draining" && state != "disabled" {
		return Cluster{}, errors.New("invalid cluster state")
	}
	if (maintenanceStartsAt == nil) != (maintenanceEndsAt == nil) || maintenanceStartsAt != nil && !maintenanceEndsAt.After(*maintenanceStartsAt) {
		return Cluster{}, errors.New("invalid maintenance window")
	}
	var item Cluster
	var labels, capacity []byte
	err := s.Pool.QueryRow(ctx, `UPDATE clusters SET state=$3,maintenance_starts_at=$4,maintenance_ends_at=$5,updated_at=now() WHERE id=$1 AND organization_id=$2 AND deletion_requested_at IS NULL AND ($3<>'active' OR certificate_not_after>now()) RETURNING id,organization_id,name,slug,state,labels,capacity,agent_version,agent_image,agent_update_state,docker_version,certificate_ca_fingerprint,pending_certificate_ca_fingerprint,certificate_not_after,last_seen_at,maintenance_starts_at,maintenance_ends_at,created_at,updated_at`, clusterID, organizationID, state, maintenanceStartsAt, maintenanceEndsAt).Scan(&item.ID, &item.OrganizationID, &item.Name, &item.Slug, &item.State, &labels, &capacity, &item.AgentVersion, &item.AgentImage, &item.AgentUpdateState, &item.DockerVersion, &item.CertificateAuthorityFingerprint, &item.PendingCertificateAuthorityFingerprint, &item.CertificateNotAfter, &item.LastSeenAt, &item.MaintenanceStartsAt, &item.MaintenanceEndsAt, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Cluster{}, ErrNotFound
	}
	_ = json.Unmarshal(labels, &item.Labels)
	_ = json.Unmarshal(capacity, &item.Capacity)
	return item, err
}

func (s *Store) QueueClusterDeletion(ctx context.Context, organizationID, clusterID uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var deleting, assigned bool
	err = tx.QueryRow(ctx, `SELECT c.deletion_requested_at IS NOT NULL,EXISTS(SELECT 1 FROM environments e WHERE e.cluster_id=c.id) FROM clusters c WHERE c.id=$1 AND c.organization_id=$2 FOR UPDATE`, clusterID, organizationID).Scan(&deleting, &assigned)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if assigned {
		return ErrBusy
	}
	if !deleting {
		_, err = tx.Exec(ctx, `UPDATE clusters SET state='disabled',deletion_requested_at=now(),certificate_serial='',certificate_ca_fingerprint='',certificate_not_after=NULL,pending_certificate_serial='',pending_certificate_ca_fingerprint='',pending_certificate_not_after=NULL,pending_certificate_created_at=NULL,updated_at=now() WHERE id=$1`, clusterID)
	}
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE cluster_commands SET status='cancelled',lease_id=NULL,lease_expires_at=NULL,last_error='cluster deletion requested',finished_at=now() WHERE cluster_id=$1 AND status IN ('pending','leased','verifying')`, clusterID); err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]string{"clusterId": clusterID.String()})
	if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,max_attempts) SELECT $1,'delete.cluster',$2,10 WHERE NOT EXISTS(SELECT 1 FROM jobs WHERE kind='delete.cluster' AND payload->>'clusterId'=$3 AND status IN ('pending','running'))`, uuid.New(), payload, clusterID.String()); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) AuthenticateClusterCertificate(ctx context.Context, clusterID uuid.UUID, serial string) error {
	var valid bool
	err := s.Pool.QueryRow(ctx, `WITH promoted AS (
		UPDATE clusters SET certificate_serial=pending_certificate_serial,certificate_ca_fingerprint=pending_certificate_ca_fingerprint,certificate_not_after=pending_certificate_not_after,pending_certificate_serial='',pending_certificate_ca_fingerprint='',pending_certificate_not_after=NULL,pending_certificate_created_at=NULL,updated_at=now()
		WHERE id=$1 AND state IN ('active','draining') AND pending_certificate_serial=$2 AND pending_certificate_not_after>now()
		RETURNING 1
	) SELECT EXISTS(SELECT 1 FROM promoted) OR EXISTS(SELECT 1 FROM clusters WHERE id=$1 AND state IN ('active','draining') AND certificate_serial=$2 AND certificate_not_after>now())`, clusterID, serial).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return ErrNotFound
	}
	return nil
}

func (s *Store) RotateClusterCertificate(ctx context.Context, clusterID uuid.UUID, oldSerial, newSerial string, notAfter time.Time, caFingerprint string) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE clusters SET pending_certificate_serial=$3,pending_certificate_not_after=$4,pending_certificate_ca_fingerprint=$5,pending_certificate_created_at=now(),updated_at=now() WHERE id=$1 AND certificate_serial=$2 AND certificate_not_after>now() AND state IN ('active','draining')`, clusterID, oldSerial, newSerial, notAfter, caFingerprint)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrLeaseLost
	}
	return nil
}

func (s *Store) RecordClusterHeartbeat(ctx context.Context, clusterID uuid.UUID, agentVersion, agentImage, agentUpdateState, dockerVersion string, capacity map[string]any) error {
	encoded, err := json.Marshal(capacity)
	if err != nil {
		return err
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE clusters SET agent_version=$2,agent_image=$3,agent_update_state=$4,docker_version=$5,capacity=$6,last_seen_at=now(),updated_at=now() WHERE id=$1 AND state IN ('active','draining')`, clusterID, agentVersion, agentImage, agentUpdateState, dockerVersion, encoded)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err = tx.Exec(ctx, expireAgentUpgradeVerifications, clusterID); err != nil {
		return err
	}
	if agentUpdateState == "completed" {
		if _, err = tx.Exec(ctx, `UPDATE cluster_commands SET status='succeeded',last_error='',finished_at=now() WHERE cluster_id=$1 AND kind='agent.upgrade' AND status='verifying' AND target_image=$2`, clusterID, agentImage); err != nil {
			return err
		}
	} else if agentUpdateState == "paused" || agentUpdateState == "rollback_started" || agentUpdateState == "rollback_paused" || agentUpdateState == "rollback_completed" {
		if _, err = tx.Exec(ctx, `UPDATE cluster_commands SET status='failed',last_error='agent Swarm update entered ' || $2 || '; reported image ' || $3,finished_at=now() WHERE cluster_id=$1 AND kind='agent.upgrade' AND status='verifying'`, clusterID, agentUpdateState, agentImage); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) EnqueueClusterCommand(ctx context.Context, clusterID, commandID uuid.UUID, kind, encryptedPayload string) (ClusterCommand, error) {
	item := ClusterCommand{ID: commandID, ClusterID: clusterID, Kind: kind, Status: "pending"}
	err := s.Pool.QueryRow(ctx, `INSERT INTO cluster_commands(id,cluster_id,kind,encrypted_payload) SELECT $1,c.id,$3,$4 FROM clusters c WHERE c.id=$2 AND c.state='active' AND c.last_seen_at>now()-interval '2 minutes' AND ($3 NOT IN ('swarm.deploy','swarm.storage-node','swarm.volume-artifact','container.run','database.utility','database.transfer') OR NOT COALESCE(now()>=c.maintenance_starts_at AND now()<c.maintenance_ends_at,false)) RETURNING created_at`, item.ID, clusterID, kind, encryptedPayload).Scan(&item.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ClusterCommand{}, clusterCommandUnavailableError(ctx, s.Pool, clusterID, kind)
	}
	return item, err
}

func (s *Store) EnqueueAgentUpgrade(ctx context.Context, clusterID, commandID uuid.UUID, encryptedPayload, targetImage string) (ClusterCommand, error) {
	item := ClusterCommand{ID: commandID, ClusterID: clusterID, Kind: "agent.upgrade", TargetImage: targetImage, Status: "pending"}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ClusterCommand{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, expireAgentUpgradeVerifications, clusterID); err != nil {
		return ClusterCommand{}, err
	}
	err = tx.QueryRow(ctx, `INSERT INTO cluster_commands(id,cluster_id,kind,encrypted_payload,target_image) SELECT $1,c.id,'agent.upgrade',$3,$4 FROM clusters c WHERE c.id=$2 AND c.state='active' AND c.last_seen_at>now()-interval '2 minutes' RETURNING created_at`, commandID, clusterID, encryptedPayload, targetImage).Scan(&item.CreatedAt)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ClusterCommand{}, ErrBusy
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ClusterCommand{}, clusterCommandUnavailableError(ctx, tx, clusterID, "agent.upgrade")
	}
	if err != nil {
		return ClusterCommand{}, err
	}
	return item, tx.Commit(ctx)
}

func clusterCommandUnavailableError(ctx context.Context, db policyQueryer, clusterID uuid.UUID, kind string) error {
	var writable, fresh bool
	err := db.QueryRow(ctx, `SELECT
		state='active' AND ($2 NOT IN ('swarm.deploy','swarm.storage-node','swarm.volume-artifact','container.run','database.utility','database.transfer') OR NOT COALESCE(now()>=maintenance_starts_at AND now()<maintenance_ends_at,false)),
		COALESCE(last_seen_at>now()-interval '2 minutes',false)
		FROM clusters WHERE id=$1`, clusterID, kind).Scan(&writable, &fresh)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !writable) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if !fresh {
		return ErrClusterUnavailable
	}
	return ErrNotFound
}

func (s *Store) GetClusterCommand(ctx context.Context, clusterID, commandID uuid.UUID) (ClusterCommand, error) {
	var item ClusterCommand
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ClusterCommand{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, expireAgentUpgradeVerifications+` AND id=$2`, clusterID, commandID); err != nil {
		return ClusterCommand{}, err
	}
	err = tx.QueryRow(ctx, `SELECT id,cluster_id,kind,status,attempts,target_image,encrypted_result,last_error,created_at,lease_expires_at FROM cluster_commands WHERE id=$1 AND cluster_id=$2`, commandID, clusterID).Scan(&item.ID, &item.ClusterID, &item.Kind, &item.Status, &item.Attempts, &item.TargetImage, &item.EncryptedResult, &item.LastError, &item.CreatedAt, &item.LeaseExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ClusterCommand{}, ErrNotFound
	}
	if err != nil {
		return ClusterCommand{}, err
	}
	return item, tx.Commit(ctx)
}

func (s *Store) ListAgentUpgrades(ctx context.Context, organizationID uuid.UUID, limit int) ([]ClusterCommand, error) {
	if limit < 1 || limit > 200 {
		return nil, errors.New("agent upgrade limit must be between 1 and 200")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `UPDATE cluster_commands command SET status='failed',last_error='replacement agent did not confirm the requested image before the verification deadline',finished_at=now() FROM clusters cluster WHERE command.cluster_id=cluster.id AND cluster.organization_id=$1 AND command.kind='agent.upgrade' AND command.status='verifying' AND command.run_after<=now()`, organizationID); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT command.id,command.cluster_id,command.kind,command.status,command.attempts,command.target_image,command.last_error,command.created_at,command.lease_expires_at FROM cluster_commands command JOIN clusters cluster ON cluster.id=command.cluster_id WHERE cluster.organization_id=$1 AND command.kind='agent.upgrade' ORDER BY command.created_at DESC,command.id DESC LIMIT $2`, organizationID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ClusterCommand{}
	for rows.Next() {
		var item ClusterCommand
		if err = rows.Scan(&item.ID, &item.ClusterID, &item.Kind, &item.Status, &item.Attempts, &item.TargetImage, &item.LastError, &item.CreatedAt, &item.LeaseExpiresAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return items, nil
}

func (s *Store) CancelPendingAgentUpgrade(ctx context.Context, organizationID, clusterID, commandID uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var status string
	err = tx.QueryRow(ctx, `SELECT command.status FROM cluster_commands command JOIN clusters cluster ON cluster.id=command.cluster_id WHERE command.id=$1 AND command.cluster_id=$2 AND cluster.organization_id=$3 AND command.kind='agent.upgrade' FOR UPDATE OF command`, commandID, clusterID, organizationID).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if status != "pending" {
		return ErrNotCancellable
	}
	if _, err = tx.Exec(ctx, `UPDATE cluster_commands SET status='cancelled',last_error='cancelled by user',finished_at=now() WHERE id=$1`, commandID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) CancelClusterCommand(ctx context.Context, clusterID, commandID uuid.UUID) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE cluster_commands SET status='cancelled',lease_id=NULL,lease_expires_at=NULL,last_error='controller cancelled command',finished_at=now() WHERE id=$1 AND cluster_id=$2 AND status IN ('pending','leased','verifying')`, commandID, clusterID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotCancellable
	}
	return nil
}

func (s *Store) ClaimClusterCommand(ctx context.Context, clusterID uuid.UUID, leaseDuration time.Duration) (ClusterCommand, error) {
	if leaseDuration < 10*time.Second || leaseDuration > 5*time.Minute {
		return ClusterCommand{}, errors.New("invalid command lease duration")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ClusterCommand{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, expireAgentUpgradeVerifications, clusterID); err != nil {
		return ClusterCommand{}, err
	}
	_, err = tx.Exec(ctx, `UPDATE cluster_commands SET status=CASE WHEN attempts>=max_attempts THEN 'failed' ELSE 'pending' END,lease_id=NULL,lease_expires_at=NULL,run_after=now()+interval '5 seconds',last_error='agent lease expired',finished_at=CASE WHEN attempts>=max_attempts THEN now() ELSE NULL END WHERE cluster_id=$1 AND status='leased' AND lease_expires_at<now()`, clusterID)
	if err != nil {
		return ClusterCommand{}, err
	}
	var item ClusterCommand
	leaseID := uuid.New()
	err = tx.QueryRow(ctx, `SELECT id,cluster_id,kind,encrypted_payload,target_image,status,attempts,created_at FROM cluster_commands WHERE cluster_id=$1 AND status='pending' AND run_after<=now() ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1`, clusterID).Scan(&item.ID, &item.ClusterID, &item.Kind, &item.EncryptedPayload, &item.TargetImage, &item.Status, &item.Attempts, &item.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		if commitErr := tx.Commit(ctx); commitErr != nil {
			return ClusterCommand{}, commitErr
		}
		return ClusterCommand{}, ErrNotFound
	}
	if err != nil {
		return ClusterCommand{}, err
	}
	expiresAt := time.Now().Add(leaseDuration)
	if _, err = tx.Exec(ctx, `UPDATE cluster_commands SET status='leased',attempts=attempts+1,lease_id=$2,lease_expires_at=$3,started_at=COALESCE(started_at,now()) WHERE id=$1`, item.ID, leaseID, expiresAt); err != nil {
		return ClusterCommand{}, err
	}
	item.Status, item.LeaseID, item.LeaseExpiresAt = "leased", &leaseID, &expiresAt
	return item, tx.Commit(ctx)
}

func (s *Store) RenewClusterCommand(ctx context.Context, clusterID, commandID, leaseID uuid.UUID, leaseDuration time.Duration) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE cluster_commands SET lease_expires_at=now()+($4::bigint * interval '1 millisecond') WHERE id=$1 AND cluster_id=$2 AND status='leased' AND lease_id=$3 AND lease_expires_at>now()`, commandID, clusterID, leaseID, leaseDuration.Milliseconds())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrLeaseLost
	}
	return nil
}

func (s *Store) CompleteClusterCommand(ctx context.Context, clusterID, commandID, leaseID uuid.UUID, encryptedResult string, failed bool) error {
	status, message := "succeeded", ""
	if failed {
		status, message = "failed", "agent reported command failure"
	}
	tag, err := s.Pool.Exec(ctx, `UPDATE cluster_commands SET status=CASE WHEN $4='succeeded' AND kind='agent.upgrade' THEN 'verifying' ELSE $4 END,encrypted_result=$5,last_error=$6,finished_at=CASE WHEN $4='succeeded' AND kind='agent.upgrade' THEN NULL ELSE now() END,run_after=CASE WHEN $4='succeeded' AND kind='agent.upgrade' THEN now()+interval '15 minutes' ELSE run_after END,lease_id=NULL,lease_expires_at=NULL WHERE id=$1 AND cluster_id=$2 AND status='leased' AND lease_id=$3 AND lease_expires_at>now()`, commandID, clusterID, leaseID, status, encryptedResult, message)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrLeaseLost
	}
	return nil
}

func (s *Store) CreateClusterEnrollmentToken(ctx context.Context, organizationID, clusterID, creatorID uuid.UUID, tokenHash []byte, expiresAt time.Time) error {
	tag, err := s.Pool.Exec(ctx, `INSERT INTO cluster_enrollment_tokens(id,cluster_id,token_hash,expires_at,created_by) SELECT $1,c.id,$4,$5,$3 FROM clusters c WHERE c.id=$2 AND c.organization_id=$6 AND c.state<>'disabled'`, uuid.New(), clusterID, nullableUUID(creatorID), tokenHash, expiresAt, organizationID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) LookupClusterEnrollmentToken(ctx context.Context, tokenHash, csrHash []byte) (ClusterEnrollment, error) {
	var item ClusterEnrollment
	err := s.Pool.QueryRow(ctx, `SELECT c.id,c.organization_id,c.name,c.slug,c.state,t.issued_certificate,t.issued_ca_bundle,t.issued_signing_ca_certificate,t.issued_signing_ca_fingerprint FROM cluster_enrollment_tokens t JOIN clusters c ON c.id=t.cluster_id WHERE t.token_hash=$1 AND t.expires_at>now() AND c.state<>'disabled' AND (t.used_at IS NULL OR (t.enrollment_csr_sha256=$2 AND t.issued_certificate<>''))`, tokenHash, csrHash).Scan(&item.Cluster.ID, &item.Cluster.OrganizationID, &item.Cluster.Name, &item.Cluster.Slug, &item.Cluster.State, &item.Artifacts.Certificate, &item.Artifacts.CABundle, &item.Artifacts.SigningCACertificate, &item.Artifacts.SigningCAFingerprint)
	if errors.Is(err, pgx.ErrNoRows) {
		return ClusterEnrollment{}, ErrNotFound
	}
	return item, err
}

func (s *Store) CompleteClusterEnrollment(ctx context.Context, tokenHash, csrHash []byte, artifacts ClusterEnrollmentArtifacts, serial string, notAfter time.Time) (ClusterEnrollmentArtifacts, bool, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ClusterEnrollmentArtifacts{}, false, err
	}
	defer tx.Rollback(ctx)
	var clusterID uuid.UUID
	err = tx.QueryRow(ctx, `UPDATE cluster_enrollment_tokens SET used_at=now(),enrollment_csr_sha256=$2,issued_certificate=$3,issued_ca_bundle=$4,issued_signing_ca_certificate=$5,issued_signing_ca_fingerprint=$6 WHERE token_hash=$1 AND used_at IS NULL AND expires_at>now() RETURNING cluster_id`, tokenHash, csrHash, artifacts.Certificate, artifacts.CABundle, artifacts.SigningCACertificate, artifacts.SigningCAFingerprint).Scan(&clusterID)
	if errors.Is(err, pgx.ErrNoRows) {
		var stored ClusterEnrollmentArtifacts
		retryErr := tx.QueryRow(ctx, `SELECT t.issued_certificate,t.issued_ca_bundle,t.issued_signing_ca_certificate,t.issued_signing_ca_fingerprint FROM cluster_enrollment_tokens t JOIN clusters c ON c.id=t.cluster_id WHERE t.token_hash=$1 AND t.enrollment_csr_sha256=$2 AND t.used_at IS NOT NULL AND t.expires_at>now() AND t.issued_certificate<>'' AND c.state<>'disabled'`, tokenHash, csrHash).Scan(&stored.Certificate, &stored.CABundle, &stored.SigningCACertificate, &stored.SigningCAFingerprint)
		if errors.Is(retryErr, pgx.ErrNoRows) {
			return ClusterEnrollmentArtifacts{}, false, ErrNotFound
		}
		return stored, false, retryErr
	}
	if err != nil {
		return ClusterEnrollmentArtifacts{}, false, err
	}
	tag, err := tx.Exec(ctx, `UPDATE clusters SET state='active',certificate_serial=$2,certificate_not_after=$3,certificate_ca_fingerprint=$4,pending_certificate_serial='',pending_certificate_ca_fingerprint='',pending_certificate_not_after=NULL,pending_certificate_created_at=NULL,updated_at=now() WHERE id=$1 AND state<>'disabled'`, clusterID, serial, notAfter, artifacts.SigningCAFingerprint)
	if err != nil {
		return ClusterEnrollmentArtifacts{}, false, err
	}
	if tag.RowsAffected() == 0 {
		return ClusterEnrollmentArtifacts{}, false, ErrNotFound
	}
	if err = tx.Commit(ctx); err != nil {
		return ClusterEnrollmentArtifacts{}, false, err
	}
	return artifacts, true, nil
}
