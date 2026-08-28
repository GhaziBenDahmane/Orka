package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

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
