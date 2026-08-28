package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrLeaseLost = errors.New("command lease is no longer valid")

type Cluster struct {
	ID                  uuid.UUID      `json:"id"`
	OrganizationID      uuid.UUID      `json:"organizationId"`
	Name                string         `json:"name"`
	Slug                string         `json:"slug"`
	State               string         `json:"state"`
	Labels              map[string]any `json:"labels"`
	Capacity            map[string]any `json:"capacity"`
	AgentVersion        string         `json:"agentVersion"`
	DockerVersion       string         `json:"dockerVersion"`
	CertificateNotAfter *time.Time     `json:"certificateNotAfter,omitempty"`
	LastSeenAt          *time.Time     `json:"lastSeenAt,omitempty"`
	CreatedAt           time.Time      `json:"createdAt"`
	UpdatedAt           time.Time      `json:"updatedAt"`
}

type ClusterCommand struct {
	ID               uuid.UUID  `json:"id"`
	ClusterID        uuid.UUID  `json:"clusterId"`
	Kind             string     `json:"kind"`
	EncryptedPayload string     `json:"-"`
	Status           string     `json:"status"`
	Attempts         int        `json:"attempts"`
	LeaseID          *uuid.UUID `json:"leaseId,omitempty"`
	LeaseExpiresAt   *time.Time `json:"leaseExpiresAt,omitempty"`
	EncryptedResult  string     `json:"-"`
	LastError        string     `json:"lastError,omitempty"`
	CreatedAt        time.Time  `json:"createdAt"`
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
	rows, err := s.Pool.Query(ctx, `SELECT id,organization_id,name,slug,state,labels,capacity,agent_version,docker_version,certificate_not_after,last_seen_at,created_at,updated_at FROM clusters WHERE organization_id=$1 ORDER BY name`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Cluster{}
	for rows.Next() {
		var item Cluster
		var labels []byte
		var capacity []byte
		if err := rows.Scan(&item.ID, &item.OrganizationID, &item.Name, &item.Slug, &item.State, &labels, &capacity, &item.AgentVersion, &item.DockerVersion, &item.CertificateNotAfter, &item.LastSeenAt, &item.CreatedAt, &item.UpdatedAt); err != nil {
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
	err := s.Pool.QueryRow(ctx, `SELECT id,organization_id,name,slug,state,labels,capacity,agent_version,docker_version,certificate_not_after,last_seen_at,created_at,updated_at FROM clusters WHERE id=$1 AND organization_id=$2`, clusterID, organizationID).Scan(&item.ID, &item.OrganizationID, &item.Name, &item.Slug, &item.State, &labels, &capacity, &item.AgentVersion, &item.DockerVersion, &item.CertificateNotAfter, &item.LastSeenAt, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Cluster{}, ErrNotFound
	}
	_ = json.Unmarshal(labels, &item.Labels)
	_ = json.Unmarshal(capacity, &item.Capacity)
	return item, err
}

func (s *Store) UpdateClusterState(ctx context.Context, organizationID, clusterID uuid.UUID, state string) (Cluster, error) {
	if state != "active" && state != "draining" && state != "disabled" {
		return Cluster{}, errors.New("invalid cluster state")
	}
	var item Cluster
	var labels, capacity []byte
	err := s.Pool.QueryRow(ctx, `UPDATE clusters SET state=$3,updated_at=now() WHERE id=$1 AND organization_id=$2 AND ($3<>'active' OR certificate_not_after>now()) RETURNING id,organization_id,name,slug,state,labels,capacity,agent_version,docker_version,certificate_not_after,last_seen_at,created_at,updated_at`, clusterID, organizationID, state).Scan(&item.ID, &item.OrganizationID, &item.Name, &item.Slug, &item.State, &labels, &capacity, &item.AgentVersion, &item.DockerVersion, &item.CertificateNotAfter, &item.LastSeenAt, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Cluster{}, ErrNotFound
	}
	_ = json.Unmarshal(labels, &item.Labels)
	_ = json.Unmarshal(capacity, &item.Capacity)
	return item, err
}

func (s *Store) AuthenticateClusterCertificate(ctx context.Context, clusterID uuid.UUID, serial string) error {
	var valid bool
	err := s.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM clusters WHERE id=$1 AND state IN ('active','draining') AND certificate_serial=$2 AND certificate_not_after>now())`, clusterID, serial).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return ErrNotFound
	}
	return nil
}

func (s *Store) RotateClusterCertificate(ctx context.Context, clusterID uuid.UUID, oldSerial, newSerial string, notAfter time.Time) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE clusters SET certificate_serial=$3,certificate_not_after=$4,updated_at=now() WHERE id=$1 AND certificate_serial=$2 AND state IN ('active','draining')`, clusterID, oldSerial, newSerial, notAfter)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrLeaseLost
	}
	return nil
}

func (s *Store) RecordClusterHeartbeat(ctx context.Context, clusterID uuid.UUID, agentVersion, dockerVersion string, capacity map[string]any) error {
	encoded, err := json.Marshal(capacity)
	if err != nil {
		return err
	}
	tag, err := s.Pool.Exec(ctx, `UPDATE clusters SET agent_version=$2,docker_version=$3,capacity=$4,last_seen_at=now(),updated_at=now() WHERE id=$1 AND state IN ('active','draining')`, clusterID, agentVersion, dockerVersion, encoded)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) EnqueueClusterCommand(ctx context.Context, clusterID, commandID uuid.UUID, kind, encryptedPayload string) (ClusterCommand, error) {
	item := ClusterCommand{ID: commandID, ClusterID: clusterID, Kind: kind, Status: "pending"}
	err := s.Pool.QueryRow(ctx, `INSERT INTO cluster_commands(id,cluster_id,kind,encrypted_payload) SELECT $1,c.id,$3,$4 FROM clusters c WHERE c.id=$2 AND c.state='active' RETURNING created_at`, item.ID, clusterID, kind, encryptedPayload).Scan(&item.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ClusterCommand{}, ErrNotFound
	}
	return item, err
}

func (s *Store) GetClusterCommand(ctx context.Context, clusterID, commandID uuid.UUID) (ClusterCommand, error) {
	var item ClusterCommand
	err := s.Pool.QueryRow(ctx, `SELECT id,cluster_id,kind,status,attempts,encrypted_result,last_error,created_at,lease_expires_at FROM cluster_commands WHERE id=$1 AND cluster_id=$2`, commandID, clusterID).Scan(&item.ID, &item.ClusterID, &item.Kind, &item.Status, &item.Attempts, &item.EncryptedResult, &item.LastError, &item.CreatedAt, &item.LeaseExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ClusterCommand{}, ErrNotFound
	}
	return item, err
}

func (s *Store) CancelClusterCommand(ctx context.Context, clusterID, commandID uuid.UUID) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE cluster_commands SET status='cancelled',lease_id=NULL,lease_expires_at=NULL,last_error='controller cancelled command',finished_at=now() WHERE id=$1 AND cluster_id=$2 AND status IN ('pending','leased')`, commandID, clusterID)
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
	_, err = tx.Exec(ctx, `UPDATE cluster_commands SET status=CASE WHEN attempts>=max_attempts THEN 'failed' ELSE 'pending' END,lease_id=NULL,lease_expires_at=NULL,run_after=now()+interval '5 seconds',last_error='agent lease expired',finished_at=CASE WHEN attempts>=max_attempts THEN now() ELSE NULL END WHERE cluster_id=$1 AND status='leased' AND lease_expires_at<now()`, clusterID)
	if err != nil {
		return ClusterCommand{}, err
	}
	var item ClusterCommand
	leaseID := uuid.New()
	err = tx.QueryRow(ctx, `SELECT id,cluster_id,kind,encrypted_payload,status,attempts,created_at FROM cluster_commands WHERE cluster_id=$1 AND status='pending' AND run_after<=now() ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1`, clusterID).Scan(&item.ID, &item.ClusterID, &item.Kind, &item.EncryptedPayload, &item.Status, &item.Attempts, &item.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
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
	tag, err := s.Pool.Exec(ctx, `UPDATE cluster_commands SET status=$4,encrypted_result=$5,last_error=$6,finished_at=now(),lease_id=NULL,lease_expires_at=NULL WHERE id=$1 AND cluster_id=$2 AND status='leased' AND lease_id=$3 AND lease_expires_at>now()`, commandID, clusterID, leaseID, status, encryptedResult, message)
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

func (s *Store) LookupClusterEnrollmentToken(ctx context.Context, tokenHash []byte) (Cluster, error) {
	var item Cluster
	err := s.Pool.QueryRow(ctx, `SELECT c.id,c.organization_id,c.name,c.slug,c.state FROM cluster_enrollment_tokens t JOIN clusters c ON c.id=t.cluster_id WHERE t.token_hash=$1 AND t.used_at IS NULL AND t.expires_at>now() AND c.state<>'disabled'`, tokenHash).Scan(&item.ID, &item.OrganizationID, &item.Name, &item.Slug, &item.State)
	if errors.Is(err, pgx.ErrNoRows) {
		return Cluster{}, ErrNotFound
	}
	return item, err
}

func (s *Store) ConsumeClusterEnrollmentToken(ctx context.Context, tokenHash []byte, serial string, notAfter time.Time) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var clusterID uuid.UUID
	err = tx.QueryRow(ctx, `UPDATE cluster_enrollment_tokens SET used_at=now() WHERE token_hash=$1 AND used_at IS NULL AND expires_at>now() RETURNING cluster_id`, tokenHash).Scan(&clusterID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE clusters SET state='active',certificate_serial=$2,certificate_not_after=$3,updated_at=now() WHERE id=$1`, clusterID, serial, notAfter); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
