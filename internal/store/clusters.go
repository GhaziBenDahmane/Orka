package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/bendahma/dokploy-go/internal/clustercontract"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var ErrLeaseLost = errors.New("command lease is no longer valid")

const agentUpgradeVerificationTimeout = "replacement agent did not confirm the requested image before the verification deadline"

type Cluster struct {
	ID                                     uuid.UUID                    `json:"id"`
	OrganizationID                         uuid.UUID                    `json:"organizationId"`
	Name                                   string                       `json:"name"`
	Slug                                   string                       `json:"slug"`
	State                                  string                       `json:"state"`
	Labels                                 map[string]any               `json:"labels"`
	Capacity                               map[string]any               `json:"capacity"`
	Capabilities                           clustercontract.Capabilities `json:"capabilities"`
	AgentVersion                           string                       `json:"agentVersion"`
	AgentImage                             string                       `json:"agentImage"`
	AgentUpdateState                       string                       `json:"agentUpdateState"`
	DockerVersion                          string                       `json:"dockerVersion"`
	CertificateAuthorityFingerprint        string                       `json:"certificateAuthorityFingerprint,omitempty"`
	PendingCertificateAuthorityFingerprint string                       `json:"pendingCertificateAuthorityFingerprint,omitempty"`
	CertificateNotAfter                    *time.Time                   `json:"certificateNotAfter,omitempty"`
	LastSeenAt                             *time.Time                   `json:"lastSeenAt,omitempty"`
	MaintenanceStartsAt                    *time.Time                   `json:"maintenanceStartsAt,omitempty"`
	MaintenanceEndsAt                      *time.Time                   `json:"maintenanceEndsAt,omitempty"`
	CreatedAt                              time.Time                    `json:"createdAt"`
	UpdatedAt                              time.Time                    `json:"updatedAt"`
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
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Cluster{}, err
	}
	defer tx.Rollback(ctx)
	item, err = createClusterTx(ctx, tx, item)
	if err != nil {
		return Cluster{}, err
	}
	return item, tx.Commit(ctx)
}

func (s *Store) CreateClusterWithAudit(ctx context.Context, principal Principal, item Cluster, remoteAddr string) (Cluster, error) {
	item.OrganizationID = principal.OrganizationID
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Cluster{}, err
	}
	defer tx.Rollback(ctx)
	item, err = createClusterTx(ctx, tx, item)
	if err != nil {
		return Cluster{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "cluster.create", "cluster", item.ID.String(), remoteAddr, nil); err != nil {
		return Cluster{}, err
	}
	return item, tx.Commit(ctx)
}

func createClusterTx(ctx context.Context, tx pgx.Tx, item Cluster) (Cluster, error) {
	item.ID = uuid.New()
	item.State = "pending"
	labels, _ := json.Marshal(item.Labels)
	err := tx.QueryRow(ctx, `INSERT INTO clusters(id,organization_id,name,slug,state,labels) SELECT $1,o.id,$3,$4,'pending',$5 FROM organizations o WHERE o.id=$2 RETURNING created_at,updated_at`, item.ID, item.OrganizationID, item.Name, item.Slug, labels).Scan(&item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Cluster{}, ErrNotFound
	}
	return item, err
}

func (s *Store) ListClusters(ctx context.Context, organizationID uuid.UUID) ([]Cluster, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id,organization_id,name,slug,state,labels,capacity,capabilities,agent_version,agent_image,agent_update_state,docker_version,certificate_ca_fingerprint,pending_certificate_ca_fingerprint,certificate_not_after,last_seen_at,maintenance_starts_at,maintenance_ends_at,created_at,updated_at FROM clusters WHERE organization_id=$1 ORDER BY name`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Cluster{}
	for rows.Next() {
		var item Cluster
		var labels []byte
		var capacity, capabilities []byte
		if err := rows.Scan(&item.ID, &item.OrganizationID, &item.Name, &item.Slug, &item.State, &labels, &capacity, &capabilities, &item.AgentVersion, &item.AgentImage, &item.AgentUpdateState, &item.DockerVersion, &item.CertificateAuthorityFingerprint, &item.PendingCertificateAuthorityFingerprint, &item.CertificateNotAfter, &item.LastSeenAt, &item.MaintenanceStartsAt, &item.MaintenanceEndsAt, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(labels, &item.Labels)
		_ = json.Unmarshal(capacity, &item.Capacity)
		_ = json.Unmarshal(capabilities, &item.Capabilities)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) GetCluster(ctx context.Context, organizationID, clusterID uuid.UUID) (Cluster, error) {
	var item Cluster
	var labels, capacity, capabilities []byte
	err := s.Pool.QueryRow(ctx, `SELECT id,organization_id,name,slug,state,labels,capacity,capabilities,agent_version,agent_image,agent_update_state,docker_version,certificate_ca_fingerprint,pending_certificate_ca_fingerprint,certificate_not_after,last_seen_at,maintenance_starts_at,maintenance_ends_at,created_at,updated_at FROM clusters WHERE id=$1 AND organization_id=$2`, clusterID, organizationID).Scan(&item.ID, &item.OrganizationID, &item.Name, &item.Slug, &item.State, &labels, &capacity, &capabilities, &item.AgentVersion, &item.AgentImage, &item.AgentUpdateState, &item.DockerVersion, &item.CertificateAuthorityFingerprint, &item.PendingCertificateAuthorityFingerprint, &item.CertificateNotAfter, &item.LastSeenAt, &item.MaintenanceStartsAt, &item.MaintenanceEndsAt, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Cluster{}, ErrNotFound
	}
	_ = json.Unmarshal(labels, &item.Labels)
	_ = json.Unmarshal(capacity, &item.Capacity)
	_ = json.Unmarshal(capabilities, &item.Capabilities)
	return item, err
}

func (s *Store) UpdateClusterState(ctx context.Context, organizationID, clusterID uuid.UUID, state string) (Cluster, error) {
	return s.UpdateClusterConfiguration(ctx, organizationID, clusterID, state, nil, nil)
}

func (s *Store) UpdateClusterConfiguration(ctx context.Context, organizationID, clusterID uuid.UUID, state string, maintenanceStartsAt, maintenanceEndsAt *time.Time) (Cluster, error) {
	return s.updateClusterConfiguration(ctx, Principal{}, organizationID, clusterID, state, maintenanceStartsAt, maintenanceEndsAt, "", false)
}

func (s *Store) UpdateClusterConfigurationWithAudit(ctx context.Context, principal Principal, clusterID uuid.UUID, state string, maintenanceStartsAt, maintenanceEndsAt *time.Time, remoteAddr string) (Cluster, error) {
	return s.updateClusterConfiguration(ctx, principal, principal.OrganizationID, clusterID, state, maintenanceStartsAt, maintenanceEndsAt, remoteAddr, true)
}

func (s *Store) updateClusterConfiguration(ctx context.Context, principal Principal, organizationID, clusterID uuid.UUID, state string, maintenanceStartsAt, maintenanceEndsAt *time.Time, remoteAddr string, audit bool) (Cluster, error) {
	if state != "active" && state != "draining" && state != "disabled" {
		return Cluster{}, errors.New("invalid cluster state")
	}
	if (maintenanceStartsAt == nil) != (maintenanceEndsAt == nil) || maintenanceStartsAt != nil && !maintenanceEndsAt.After(*maintenanceStartsAt) {
		return Cluster{}, errors.New("invalid maintenance window")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Cluster{}, err
	}
	defer tx.Rollback(ctx)
	item, err := updateClusterConfigurationTx(ctx, tx, organizationID, clusterID, state, maintenanceStartsAt, maintenanceEndsAt)
	if err != nil {
		return Cluster{}, err
	}
	if audit {
		if err = appendPrincipalAudit(ctx, tx, principal, "cluster.state.update", "cluster", clusterID.String(), remoteAddr, map[string]any{"state": state, "maintenanceStartsAt": maintenanceStartsAt, "maintenanceEndsAt": maintenanceEndsAt}); err != nil {
			return Cluster{}, err
		}
	}
	return item, tx.Commit(ctx)
}

func updateClusterConfigurationTx(ctx context.Context, tx pgx.Tx, organizationID, clusterID uuid.UUID, state string, maintenanceStartsAt, maintenanceEndsAt *time.Time) (Cluster, error) {
	var item Cluster
	var labels, capacity, capabilities []byte
	err := tx.QueryRow(ctx, `UPDATE clusters SET state=$3,maintenance_starts_at=$4,maintenance_ends_at=$5,updated_at=now() WHERE id=$1 AND organization_id=$2 AND deletion_requested_at IS NULL AND ($3<>'active' OR certificate_not_after>now()) RETURNING id,organization_id,name,slug,state,labels,capacity,capabilities,agent_version,agent_image,agent_update_state,docker_version,certificate_ca_fingerprint,pending_certificate_ca_fingerprint,certificate_not_after,last_seen_at,maintenance_starts_at,maintenance_ends_at,created_at,updated_at`, clusterID, organizationID, state, maintenanceStartsAt, maintenanceEndsAt).Scan(&item.ID, &item.OrganizationID, &item.Name, &item.Slug, &item.State, &labels, &capacity, &capabilities, &item.AgentVersion, &item.AgentImage, &item.AgentUpdateState, &item.DockerVersion, &item.CertificateAuthorityFingerprint, &item.PendingCertificateAuthorityFingerprint, &item.CertificateNotAfter, &item.LastSeenAt, &item.MaintenanceStartsAt, &item.MaintenanceEndsAt, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Cluster{}, ErrNotFound
	}
	_ = json.Unmarshal(labels, &item.Labels)
	_ = json.Unmarshal(capacity, &item.Capacity)
	_ = json.Unmarshal(capabilities, &item.Capabilities)
	return item, err
}

func (s *Store) QueueClusterDeletion(ctx context.Context, organizationID, clusterID uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = queueClusterDeletionTx(ctx, tx, organizationID, clusterID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) QueueClusterDeletionWithAudit(ctx context.Context, principal Principal, clusterID uuid.UUID, remoteAddr string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = queueClusterDeletionTx(ctx, tx, principal.OrganizationID, clusterID); err != nil {
		return err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "cluster.delete", "cluster", clusterID.String(), remoteAddr, nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func queueClusterDeletionTx(ctx context.Context, tx pgx.Tx, organizationID, clusterID uuid.UUID) error {
	var deleting, assigned bool
	err := tx.QueryRow(ctx, `SELECT c.deletion_requested_at IS NOT NULL,EXISTS(SELECT 1 FROM environments e WHERE e.cluster_id=c.id) OR EXISTS(SELECT 1 FROM managed_networks n WHERE n.cluster_id=c.id) FROM clusters c WHERE c.id=$1 AND c.organization_id=$2 FOR UPDATE`, clusterID, organizationID).Scan(&deleting, &assigned)
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
	return nil
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

func (s *Store) RecordClusterHeartbeat(ctx context.Context, clusterID uuid.UUID, agentVersion, agentImage, agentUpdateState, dockerVersion string, capacity clustercontract.Capacity, capabilities clustercontract.Capabilities) error {
	return s.recordClusterHeartbeat(ctx, clusterID, "", agentVersion, agentImage, agentUpdateState, dockerVersion, capacity, capabilities)
}

func (s *Store) RecordAuthenticatedClusterHeartbeat(ctx context.Context, clusterID uuid.UUID, certificateSerial, agentVersion, agentImage, agentUpdateState, dockerVersion string, capacity clustercontract.Capacity, capabilities clustercontract.Capabilities) error {
	if certificateSerial == "" {
		return ErrAuthenticationStateChanged
	}
	return s.recordClusterHeartbeat(ctx, clusterID, certificateSerial, agentVersion, agentImage, agentUpdateState, dockerVersion, capacity, capabilities)
}

func (s *Store) recordClusterHeartbeat(ctx context.Context, clusterID uuid.UUID, certificateSerial, agentVersion, agentImage, agentUpdateState, dockerVersion string, capacity clustercontract.Capacity, capabilities clustercontract.Capabilities) error {
	if err := clustercontract.ValidateCapacity(capacity); err != nil {
		return err
	}
	encoded, err := json.Marshal(capacity)
	if err != nil {
		return err
	}
	encodedCapabilities, err := json.Marshal(capabilities)
	if err != nil {
		return err
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if certificateSerial != "" {
		if err = lockActiveClusterCertificateTx(ctx, tx, clusterID, certificateSerial); err != nil {
			return err
		}
	}
	tag, err := tx.Exec(ctx, `UPDATE clusters SET agent_version=$2,agent_image=$3,agent_update_state=$4,docker_version=$5,capacity=$6,capabilities=$7,last_seen_at=now(),updated_at=now() WHERE id=$1 AND state IN ('active','draining')`, clusterID, agentVersion, agentImage, agentUpdateState, dockerVersion, encoded, encodedCapabilities)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err = expireAgentUpgradeVerificationsTx(ctx, tx, clusterID, nil); err != nil {
		return err
	}
	if agentUpdateState == "completed" {
		if _, err = tx.Exec(ctx, `UPDATE cluster_commands SET status='succeeded',last_error='',finished_at=now() WHERE cluster_id=$1 AND kind='agent.upgrade' AND status='verifying' AND target_image=$2`, clusterID, agentImage); err != nil {
			return err
		}
	} else if agentUpdateState == "paused" || agentUpdateState == "rollback_started" || agentUpdateState == "rollback_paused" || agentUpdateState == "rollback_completed" {
		reason := "agent Swarm update entered " + agentUpdateState + "; reported image " + agentImage
		rows, updateErr := tx.Query(ctx, `UPDATE cluster_commands SET status='failed',last_error=$2,finished_at=now() WHERE cluster_id=$1 AND kind='agent.upgrade' AND status='verifying' RETURNING id`, clusterID, reason)
		if updateErr != nil {
			return updateErr
		}
		commandIDs, collectErr := collectUUIDRows(rows)
		if collectErr != nil {
			return collectErr
		}
		for _, commandID := range commandIDs {
			if err = queueAgentUpgradeFailureNotificationTx(ctx, tx, clusterID, commandID, reason); err != nil {
				return err
			}
		}
	}
	return tx.Commit(ctx)
}

func collectUUIDRows(rows pgx.Rows) ([]uuid.UUID, error) {
	defer rows.Close()
	items := []uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		items = append(items, id)
	}
	return items, rows.Err()
}

func (s *Store) EnqueueClusterCommand(ctx context.Context, clusterID, commandID uuid.UUID, kind, encryptedPayload string) (ClusterCommand, error) {
	return s.enqueueClusterCommand(ctx, clusterID, commandID, kind, encryptedPayload, uuid.Nil, uuid.Nil)
}

// EnqueueOwnedClusterCommand binds an outbound command to the exact worker-job
// attempt that requested it. Agent leases become invalid when that parent
// attempt loses ownership, preventing a recovered job from overlapping a stale
// remote command.
func (s *Store) EnqueueOwnedClusterCommand(ctx context.Context, clusterID, commandID uuid.UUID, kind, encryptedPayload string, jobID, jobLeaseID uuid.UUID) (ClusterCommand, error) {
	if jobID == uuid.Nil || jobLeaseID == uuid.Nil {
		return ClusterCommand{}, ErrLeaseLost
	}
	return s.enqueueClusterCommand(ctx, clusterID, commandID, kind, encryptedPayload, jobID, jobLeaseID)
}

func (s *Store) enqueueClusterCommand(ctx context.Context, clusterID, commandID uuid.UUID, kind, encryptedPayload string, jobID, jobLeaseID uuid.UUID) (ClusterCommand, error) {
	item := ClusterCommand{ID: commandID, ClusterID: clusterID, Kind: kind, Status: "pending"}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ClusterCommand{}, err
	}
	defer tx.Rollback(ctx)
	if jobID != uuid.Nil {
		var owned bool
		err = tx.QueryRow(ctx, `SELECT true FROM jobs WHERE id=$1 AND status='running' AND lease_id=$2 AND locked_at>=now()-interval '1 minute' FOR UPDATE`, jobID, jobLeaseID).Scan(&owned)
		if errors.Is(err, pgx.ErrNoRows) {
			return ClusterCommand{}, ErrLeaseLost
		}
		if err != nil {
			return ClusterCommand{}, err
		}
	}
	err = tx.QueryRow(ctx, `INSERT INTO cluster_commands(id,cluster_id,kind,encrypted_payload,owner_job_id,owner_job_lease_id) SELECT $1,c.id,$3,$4,$5,$6 FROM clusters c WHERE c.id=$2 AND c.state='active' AND c.last_seen_at>now()-interval '2 minutes' AND ($3 NOT IN ('swarm.deploy','swarm.storage-node','swarm.volume-artifact','swarm.network-create','swarm.network-remove','container.run','image.resolve','database.utility','database.transfer') OR NOT COALESCE(now()>=c.maintenance_starts_at AND now()<c.maintenance_ends_at,false)) RETURNING created_at`, item.ID, clusterID, kind, encryptedPayload, nullableUUID(jobID), nullableUUID(jobLeaseID)).Scan(&item.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ClusterCommand{}, clusterCommandUnavailableError(ctx, tx, clusterID, kind)
	}
	if err != nil {
		return ClusterCommand{}, err
	}
	return item, tx.Commit(ctx)
}

func (s *Store) EnqueueAgentUpgrade(ctx context.Context, clusterID, commandID uuid.UUID, encryptedPayload, targetImage string) (ClusterCommand, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ClusterCommand{}, err
	}
	defer tx.Rollback(ctx)
	item, err := enqueueAgentUpgradeTx(ctx, tx, uuid.Nil, clusterID, commandID, encryptedPayload, targetImage)
	if err != nil {
		return ClusterCommand{}, err
	}
	return item, tx.Commit(ctx)
}

func (s *Store) EnqueueAgentUpgradeWithAudit(ctx context.Context, principal Principal, clusterID, commandID uuid.UUID, encryptedPayload, targetImage, remoteAddr string) (ClusterCommand, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ClusterCommand{}, err
	}
	defer tx.Rollback(ctx)
	item, err := enqueueAgentUpgradeTx(ctx, tx, principal.OrganizationID, clusterID, commandID, encryptedPayload, targetImage)
	if err != nil {
		return ClusterCommand{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "cluster.agent.upgrade", "cluster", clusterID.String(), remoteAddr, map[string]any{"image": targetImage, "commandId": commandID}); err != nil {
		return ClusterCommand{}, err
	}
	return item, tx.Commit(ctx)
}

func enqueueAgentUpgradeTx(ctx context.Context, tx pgx.Tx, organizationID, clusterID, commandID uuid.UUID, encryptedPayload, targetImage string) (ClusterCommand, error) {
	item := ClusterCommand{ID: commandID, ClusterID: clusterID, Kind: "agent.upgrade", TargetImage: targetImage, Status: "pending"}
	var err error
	if err = expireAgentUpgradeVerificationsTx(ctx, tx, clusterID, nil); err != nil {
		return ClusterCommand{}, err
	}
	err = tx.QueryRow(ctx, `INSERT INTO cluster_commands(id,cluster_id,kind,encrypted_payload,target_image) SELECT $1,c.id,'agent.upgrade',$3,$4 FROM clusters c WHERE c.id=$2 AND ($5::uuid='00000000-0000-0000-0000-000000000000' OR c.organization_id=$5) AND c.state='active' AND c.last_seen_at>now()-interval '2 minutes' RETURNING created_at`, commandID, clusterID, encryptedPayload, targetImage, organizationID).Scan(&item.CreatedAt)
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
	return item, nil
}

func clusterCommandUnavailableError(ctx context.Context, db policyQueryer, clusterID uuid.UUID, kind string) error {
	var writable, fresh bool
	err := db.QueryRow(ctx, `SELECT
		state='active' AND ($2 NOT IN ('swarm.deploy','swarm.storage-node','swarm.volume-artifact','container.run','image.resolve','database.utility','database.transfer') OR NOT COALESCE(now()>=maintenance_starts_at AND now()<maintenance_ends_at,false)),
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
	if err = expireAgentUpgradeVerificationsTx(ctx, tx, clusterID, &commandID); err != nil {
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
	if err = expireOrganizationAgentUpgradeVerificationsTx(ctx, tx, organizationID); err != nil {
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
	if err = cancelPendingAgentUpgradeTx(ctx, tx, organizationID, clusterID, commandID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) CancelPendingAgentUpgradeWithAudit(ctx context.Context, principal Principal, clusterID, commandID uuid.UUID, remoteAddr string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = cancelPendingAgentUpgradeTx(ctx, tx, principal.OrganizationID, clusterID, commandID); err != nil {
		return err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "cluster.agent.upgrade.cancel", "cluster_command", commandID.String(), remoteAddr, map[string]any{"clusterId": clusterID}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func cancelPendingAgentUpgradeTx(ctx context.Context, tx pgx.Tx, organizationID, clusterID, commandID uuid.UUID) error {
	var status string
	err := tx.QueryRow(ctx, `SELECT command.status FROM cluster_commands command JOIN clusters cluster ON cluster.id=command.cluster_id WHERE command.id=$1 AND command.cluster_id=$2 AND cluster.organization_id=$3 AND command.kind='agent.upgrade' FOR UPDATE OF command`, commandID, clusterID, organizationID).Scan(&status)
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
	return nil
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
	return s.claimClusterCommand(ctx, clusterID, "", leaseDuration)
}

func (s *Store) ClaimAuthenticatedClusterCommand(ctx context.Context, clusterID uuid.UUID, certificateSerial string, leaseDuration time.Duration) (ClusterCommand, error) {
	if certificateSerial == "" {
		return ClusterCommand{}, ErrAuthenticationStateChanged
	}
	return s.claimClusterCommand(ctx, clusterID, certificateSerial, leaseDuration)
}

func (s *Store) claimClusterCommand(ctx context.Context, clusterID uuid.UUID, certificateSerial string, leaseDuration time.Duration) (ClusterCommand, error) {
	if leaseDuration < 10*time.Second || leaseDuration > 5*time.Minute {
		return ClusterCommand{}, errors.New("invalid command lease duration")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ClusterCommand{}, err
	}
	defer tx.Rollback(ctx)
	if certificateSerial != "" {
		if err = lockActiveClusterCertificateTx(ctx, tx, clusterID, certificateSerial); err != nil {
			return ClusterCommand{}, err
		}
	}
	if err = expireAgentUpgradeVerificationsTx(ctx, tx, clusterID, nil); err != nil {
		return ClusterCommand{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE cluster_commands command SET status='cancelled',lease_id=NULL,lease_expires_at=NULL,last_error='originating worker lease lost',finished_at=now()
		WHERE command.cluster_id=$1 AND command.owner_job_id IS NOT NULL AND command.status IN ('pending','leased','verifying')
		AND NOT EXISTS(SELECT 1 FROM jobs job WHERE job.id=command.owner_job_id AND job.status='running' AND job.lease_id=command.owner_job_lease_id AND job.locked_at>=now()-interval '1 minute')`, clusterID); err != nil {
		return ClusterCommand{}, err
	}
	rows, err := tx.Query(ctx, `UPDATE cluster_commands SET status=CASE WHEN attempts>=max_attempts THEN 'failed' ELSE 'pending' END,lease_id=NULL,lease_expires_at=NULL,run_after=now()+interval '5 seconds',last_error='agent lease expired',finished_at=CASE WHEN attempts>=max_attempts THEN now() ELSE NULL END WHERE cluster_id=$1 AND status='leased' AND lease_expires_at<now() RETURNING id,kind,status`, clusterID)
	if err != nil {
		return ClusterCommand{}, err
	}
	type expiredCommand struct {
		id     uuid.UUID
		kind   string
		status string
	}
	expired := []expiredCommand{}
	for rows.Next() {
		var item expiredCommand
		if err = rows.Scan(&item.id, &item.kind, &item.status); err != nil {
			rows.Close()
			return ClusterCommand{}, err
		}
		expired = append(expired, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return ClusterCommand{}, err
	}
	rows.Close()
	for _, item := range expired {
		if item.kind == "agent.upgrade" && item.status == "failed" {
			if err = queueAgentUpgradeFailureNotificationTx(ctx, tx, clusterID, item.id, "agent command lease expired after maximum attempts"); err != nil {
				return ClusterCommand{}, err
			}
		}
	}
	var item ClusterCommand
	leaseID := uuid.New()
	err = tx.QueryRow(ctx, `SELECT command.id,command.cluster_id,command.kind,command.encrypted_payload,command.target_image,command.status,command.attempts,command.created_at FROM cluster_commands command WHERE command.cluster_id=$1 AND command.status='pending' AND command.run_after<=now()
		AND (command.owner_job_id IS NULL OR EXISTS(SELECT 1 FROM jobs job WHERE job.id=command.owner_job_id AND job.status='running' AND job.lease_id=command.owner_job_lease_id AND job.locked_at>=now()-interval '1 minute'))
		ORDER BY command.created_at FOR UPDATE OF command SKIP LOCKED LIMIT 1`, clusterID).Scan(&item.ID, &item.ClusterID, &item.Kind, &item.EncryptedPayload, &item.TargetImage, &item.Status, &item.Attempts, &item.CreatedAt)
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
	return s.renewClusterCommand(ctx, clusterID, commandID, leaseID, "", leaseDuration)
}

func (s *Store) RenewAuthenticatedClusterCommand(ctx context.Context, clusterID, commandID, leaseID uuid.UUID, certificateSerial string, leaseDuration time.Duration) error {
	if certificateSerial == "" {
		return ErrAuthenticationStateChanged
	}
	return s.renewClusterCommand(ctx, clusterID, commandID, leaseID, certificateSerial, leaseDuration)
}

func (s *Store) renewClusterCommand(ctx context.Context, clusterID, commandID, leaseID uuid.UUID, certificateSerial string, leaseDuration time.Duration) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if certificateSerial != "" {
		if err = lockActiveClusterCertificateTx(ctx, tx, clusterID, certificateSerial); err != nil {
			return err
		}
	}
	if err = lockClusterCommandOwner(ctx, tx, clusterID, commandID); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE cluster_commands SET lease_expires_at=now()+($4::bigint * interval '1 millisecond') WHERE id=$1 AND cluster_id=$2 AND status='leased' AND lease_id=$3 AND lease_expires_at>now()`, commandID, clusterID, leaseID, leaseDuration.Milliseconds())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrLeaseLost
	}
	return tx.Commit(ctx)
}

func (s *Store) CompleteClusterCommand(ctx context.Context, clusterID, commandID, leaseID uuid.UUID, encryptedResult string, failed bool) error {
	return s.completeClusterCommand(ctx, clusterID, commandID, leaseID, "", encryptedResult, failed)
}

func (s *Store) CompleteAuthenticatedClusterCommand(ctx context.Context, clusterID, commandID, leaseID uuid.UUID, certificateSerial, encryptedResult string, failed bool) error {
	if certificateSerial == "" {
		return ErrAuthenticationStateChanged
	}
	return s.completeClusterCommand(ctx, clusterID, commandID, leaseID, certificateSerial, encryptedResult, failed)
}

func (s *Store) completeClusterCommand(ctx context.Context, clusterID, commandID, leaseID uuid.UUID, certificateSerial, encryptedResult string, failed bool) error {
	status, message := "succeeded", ""
	if failed {
		status, message = "failed", "agent reported command failure"
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if certificateSerial != "" {
		if err = lockActiveClusterCertificateTx(ctx, tx, clusterID, certificateSerial); err != nil {
			return err
		}
	}
	if err = lockClusterCommandOwner(ctx, tx, clusterID, commandID); err != nil {
		return err
	}
	var kind string
	err = tx.QueryRow(ctx, `UPDATE cluster_commands SET status=CASE WHEN $4='succeeded' AND kind='agent.upgrade' THEN 'verifying' ELSE $4 END,encrypted_result=$5,last_error=$6,finished_at=CASE WHEN $4='succeeded' AND kind='agent.upgrade' THEN NULL ELSE now() END,run_after=CASE WHEN $4='succeeded' AND kind='agent.upgrade' THEN now()+interval '15 minutes' ELSE run_after END,lease_id=NULL,lease_expires_at=NULL WHERE id=$1 AND cluster_id=$2 AND status='leased' AND lease_id=$3 AND lease_expires_at>now() RETURNING kind`, commandID, clusterID, leaseID, status, encryptedResult, message).Scan(&kind)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrLeaseLost
	}
	if err != nil {
		return err
	}
	if failed && kind == "agent.upgrade" {
		if err = queueAgentUpgradeFailureNotificationTx(ctx, tx, clusterID, commandID, message); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func expireAgentUpgradeVerificationsTx(ctx context.Context, tx pgx.Tx, clusterID uuid.UUID, commandID *uuid.UUID) error {
	rows, err := tx.Query(ctx, `UPDATE cluster_commands SET status='failed',last_error=$3,finished_at=now() WHERE cluster_id=$1 AND kind='agent.upgrade' AND status='verifying' AND run_after<=now() AND ($2::uuid IS NULL OR id=$2) RETURNING id`, clusterID, commandID, agentUpgradeVerificationTimeout)
	if err != nil {
		return err
	}
	commandIDs, err := collectUUIDRows(rows)
	if err != nil {
		return err
	}
	for _, id := range commandIDs {
		if err = queueAgentUpgradeFailureNotificationTx(ctx, tx, clusterID, id, agentUpgradeVerificationTimeout); err != nil {
			return err
		}
	}
	return nil
}

func expireOrganizationAgentUpgradeVerificationsTx(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID) error {
	rows, err := tx.Query(ctx, `UPDATE cluster_commands command SET status='failed',last_error=$2,finished_at=now() FROM clusters cluster WHERE command.cluster_id=cluster.id AND cluster.organization_id=$1 AND command.kind='agent.upgrade' AND command.status='verifying' AND command.run_after<=now() RETURNING command.id,command.cluster_id`, organizationID, agentUpgradeVerificationTimeout)
	if err != nil {
		return err
	}
	type expiredUpgrade struct{ commandID, clusterID uuid.UUID }
	items := []expiredUpgrade{}
	for rows.Next() {
		var item expiredUpgrade
		if err = rows.Scan(&item.commandID, &item.clusterID); err != nil {
			rows.Close()
			return err
		}
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, item := range items {
		if err = queueAgentUpgradeFailureNotificationTx(ctx, tx, item.clusterID, item.commandID, agentUpgradeVerificationTimeout); err != nil {
			return err
		}
	}
	return nil
}

func queueAgentUpgradeFailureNotificationTx(ctx context.Context, tx pgx.Tx, clusterID, commandID uuid.UUID, reason string) error {
	var organizationID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT organization_id FROM clusters WHERE id=$1`, clusterID).Scan(&organizationID); err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]any{
		"event":        "agent.upgrade.failed",
		"resourceType": "agent_upgrade",
		"resourceId":   commandID.String(),
		"clusterId":    clusterID.String(),
		"error":        truncateStore(reason, 8192),
		"occurredAt":   time.Now().UTC(),
		"text":         "Dockyard agent.upgrade.failed for cluster " + clusterID.String(),
	})
	if err != nil {
		return err
	}
	return queueNotificationDeliveries(ctx, tx, organizationID, "agent.upgrade.failed", "agent_upgrade", commandID.String(), payload)
}

func lockActiveClusterCertificateTx(ctx context.Context, tx pgx.Tx, clusterID uuid.UUID, certificateSerial string) error {
	var lockedClusterID uuid.UUID
	err := tx.QueryRow(ctx, `SELECT id FROM clusters WHERE id=$1 AND state IN ('active','draining') AND certificate_serial=$2 AND certificate_not_after>now() FOR NO KEY UPDATE`, clusterID, certificateSerial).Scan(&lockedClusterID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrAuthenticationStateChanged
	}
	return err
}

func lockClusterCommandOwner(ctx context.Context, tx pgx.Tx, clusterID, commandID uuid.UUID) error {
	var ownerJobID, ownerJobLeaseID *uuid.UUID
	err := tx.QueryRow(ctx, `SELECT owner_job_id,owner_job_lease_id FROM cluster_commands WHERE id=$1 AND cluster_id=$2`, commandID, clusterID).Scan(&ownerJobID, &ownerJobLeaseID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrLeaseLost
	}
	if err != nil {
		return err
	}
	if ownerJobID == nil {
		return nil
	}
	var owned bool
	err = tx.QueryRow(ctx, `SELECT true FROM jobs WHERE id=$1 AND status='running' AND lease_id=$2 AND locked_at>=now()-interval '1 minute' FOR UPDATE`, *ownerJobID, *ownerJobLeaseID).Scan(&owned)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrLeaseLost
	}
	return err
}

func (s *Store) CreateClusterEnrollmentToken(ctx context.Context, organizationID, clusterID, creatorID uuid.UUID, tokenHash []byte, expiresAt time.Time) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = createClusterEnrollmentTokenTx(ctx, tx, organizationID, clusterID, creatorID, tokenHash, expiresAt); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) CreateClusterEnrollmentTokenWithAudit(ctx context.Context, principal Principal, clusterID uuid.UUID, tokenHash []byte, expiresAt time.Time, remoteAddr string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = createClusterEnrollmentTokenTx(ctx, tx, principal.OrganizationID, clusterID, principal.UserID, tokenHash, expiresAt); err != nil {
		return err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "cluster.enrollment_token.create", "cluster", clusterID.String(), remoteAddr, map[string]any{"expiresAt": expiresAt}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func createClusterEnrollmentTokenTx(ctx context.Context, tx pgx.Tx, organizationID, clusterID, creatorID uuid.UUID, tokenHash []byte, expiresAt time.Time) error {
	tag, err := tx.Exec(ctx, `INSERT INTO cluster_enrollment_tokens(id,cluster_id,token_hash,expires_at,created_by) SELECT $1,c.id,$4,$5,$3 FROM clusters c WHERE c.id=$2 AND c.organization_id=$6 AND c.state<>'disabled'`, uuid.New(), clusterID, nullableUUID(creatorID), tokenHash, expiresAt, organizationID)
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
	return s.completeClusterEnrollment(ctx, tokenHash, csrHash, artifacts, serial, notAfter, "", false)
}

func (s *Store) CompleteClusterEnrollmentWithAudit(ctx context.Context, tokenHash, csrHash []byte, artifacts ClusterEnrollmentArtifacts, serial string, notAfter time.Time, remoteAddr string) (ClusterEnrollmentArtifacts, bool, error) {
	return s.completeClusterEnrollment(ctx, tokenHash, csrHash, artifacts, serial, notAfter, remoteAddr, true)
}

func (s *Store) completeClusterEnrollment(ctx context.Context, tokenHash, csrHash []byte, artifacts ClusterEnrollmentArtifacts, serial string, notAfter time.Time, remoteAddr string, audit bool) (ClusterEnrollmentArtifacts, bool, error) {
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
	var organizationID uuid.UUID
	err = tx.QueryRow(ctx, `UPDATE clusters SET state='active',certificate_serial=$2,certificate_not_after=$3,certificate_ca_fingerprint=$4,pending_certificate_serial='',pending_certificate_ca_fingerprint='',pending_certificate_not_after=NULL,pending_certificate_created_at=NULL,updated_at=now() WHERE id=$1 AND state<>'disabled' RETURNING organization_id`, clusterID, serial, notAfter, artifacts.SigningCAFingerprint).Scan(&organizationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ClusterEnrollmentArtifacts{}, false, ErrNotFound
	}
	if err != nil {
		return ClusterEnrollmentArtifacts{}, false, err
	}
	if audit {
		if err = s.AuditOrganizationTx(ctx, tx, organizationID, "cluster.enroll", "cluster", clusterID.String(), remoteAddr, map[string]any{"certificateNotAfter": notAfter}); err != nil {
			return ClusterEnrollmentArtifacts{}, false, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return ClusterEnrollmentArtifacts{}, false, err
	}
	return artifacts, true, nil
}
