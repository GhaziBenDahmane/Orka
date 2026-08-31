package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type NetworkIPAMConfig struct {
	Subnet  string `json:"subnet,omitempty"`
	Gateway string `json:"gateway,omitempty"`
	IPRange string `json:"ipRange,omitempty"`
}

type ManagedNetwork struct {
	ID                  uuid.UUID           `json:"id"`
	OrganizationID      uuid.UUID           `json:"organizationId"`
	ClusterID           *uuid.UUID          `json:"clusterId,omitempty"`
	Name                string              `json:"name"`
	Driver              string              `json:"driver"`
	Internal            bool                `json:"internal"`
	Attachable          bool                `json:"attachable"`
	EnableIPv4          bool                `json:"enableIpv4"`
	EnableIPv6          bool                `json:"enableIpv6"`
	MTU                 *int                `json:"mtu,omitempty"`
	IPAM                []NetworkIPAMConfig `json:"ipam"`
	DockerID            string              `json:"dockerId,omitempty"`
	Status              string              `json:"status"`
	LastError           string              `json:"lastError,omitempty"`
	DeletionRequestedAt *time.Time          `json:"deletionRequestedAt,omitempty"`
	CreatedAt           time.Time           `json:"createdAt"`
	UpdatedAt           time.Time           `json:"updatedAt"`
}

type ManagedNetworkAttachment struct {
	ManagedNetwork
	ServiceNames []string `json:"serviceNames"`
}

func scanManagedNetwork(row pgx.Row) (ManagedNetwork, error) {
	var item ManagedNetwork
	var ipam []byte
	err := row.Scan(&item.ID, &item.OrganizationID, &item.ClusterID, &item.Name, &item.Driver, &item.Internal, &item.Attachable, &item.EnableIPv4, &item.EnableIPv6, &item.MTU, &ipam, &item.DockerID, &item.Status, &item.LastError, &item.DeletionRequestedAt, &item.CreatedAt, &item.UpdatedAt)
	if err == nil {
		err = json.Unmarshal(ipam, &item.IPAM)
	}
	return item, err
}

const managedNetworkColumns = `id,organization_id,cluster_id,name,driver,internal,attachable,enable_ipv4,enable_ipv6,mtu,ipam,docker_id,status,last_error,deletion_requested_at,created_at,updated_at`

func (s *Store) CreateManagedNetwork(ctx context.Context, item ManagedNetwork) (ManagedNetwork, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ManagedNetwork{}, err
	}
	defer tx.Rollback(ctx)
	item, err = createManagedNetworkTx(ctx, tx, item)
	if err != nil {
		return ManagedNetwork{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return ManagedNetwork{}, err
	}
	return item, nil
}

func (s *Store) CreateManagedNetworkWithAudit(ctx context.Context, principal Principal, item ManagedNetwork, remoteAddr string) (ManagedNetwork, error) {
	item.OrganizationID = principal.OrganizationID
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ManagedNetwork{}, err
	}
	defer tx.Rollback(ctx)
	item, err = createManagedNetworkTx(ctx, tx, item)
	if err != nil {
		return ManagedNetwork{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "network.create.queued", "managed_network", item.ID.String(), remoteAddr, map[string]any{"name": item.Name, "driver": item.Driver, "clusterId": item.ClusterID}); err != nil {
		return ManagedNetwork{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return ManagedNetwork{}, err
	}
	return item, nil
}

func createManagedNetworkTx(ctx context.Context, tx pgx.Tx, item ManagedNetwork) (ManagedNetwork, error) {
	item.ID = uuid.New()
	item.Status = "provisioning"
	if item.IPAM == nil {
		item.IPAM = []NetworkIPAMConfig{}
	}
	ipam, err := json.Marshal(item.IPAM)
	if err != nil {
		return ManagedNetwork{}, err
	}
	if item.ClusterID != nil {
		var exists bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM clusters WHERE id=$1 AND organization_id=$2 AND state IN ('active','draining') AND deletion_requested_at IS NULL)`, *item.ClusterID, item.OrganizationID).Scan(&exists); err != nil {
			return ManagedNetwork{}, err
		}
		if !exists {
			return ManagedNetwork{}, ErrNotFound
		}
	}
	row := tx.QueryRow(ctx, `INSERT INTO managed_networks(id,organization_id,cluster_id,name,driver,internal,attachable,enable_ipv4,enable_ipv6,mtu,ipam) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING `+managedNetworkColumns, item.ID, item.OrganizationID, item.ClusterID, item.Name, item.Driver, item.Internal, item.Attachable, item.EnableIPv4, item.EnableIPv6, item.MTU, ipam)
	item, err = scanManagedNetwork(row)
	if err != nil {
		return ManagedNetwork{}, err
	}
	payload, _ := json.Marshal(map[string]string{"networkId": item.ID.String()})
	if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,resource_key,max_attempts) VALUES($1,'network.create',$2,$3,10)`, uuid.New(), payload, "network:"+item.ID.String()); err != nil {
		return ManagedNetwork{}, err
	}
	return item, nil
}

func (s *Store) ListManagedNetworks(ctx context.Context, organizationID uuid.UUID) ([]ManagedNetwork, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+managedNetworkColumns+` FROM managed_networks WHERE organization_id=$1 AND deletion_requested_at IS NULL ORDER BY lower(name),id`, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ManagedNetwork{}
	for rows.Next() {
		item, scanErr := scanManagedNetwork(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) GetManagedNetwork(ctx context.Context, organizationID, id uuid.UUID) (ManagedNetwork, error) {
	item, err := scanManagedNetwork(s.Pool.QueryRow(ctx, `SELECT `+managedNetworkColumns+` FROM managed_networks WHERE id=$1 AND organization_id=$2`, id, organizationID))
	if errors.Is(err, pgx.ErrNoRows) {
		return ManagedNetwork{}, ErrNotFound
	}
	return item, err
}

func (s *Store) QueueManagedNetworkDeletion(ctx context.Context, organizationID, id uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = queueManagedNetworkDeletionTx(ctx, tx, organizationID, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) QueueManagedNetworkDeletionWithAudit(ctx context.Context, principal Principal, id uuid.UUID, remoteAddr string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = queueManagedNetworkDeletionTx(ctx, tx, principal.OrganizationID, id); err != nil {
		return err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "network.delete.queued", "managed_network", id.String(), remoteAddr, nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func queueManagedNetworkDeletionTx(ctx context.Context, tx pgx.Tx, organizationID, id uuid.UUID) error {
	var deleting bool
	err := tx.QueryRow(ctx, `SELECT deletion_requested_at IS NOT NULL FROM managed_networks WHERE id=$1 AND organization_id=$2 FOR UPDATE`, id, organizationID).Scan(&deleting)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	var assigned bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM compose_service_networks WHERE network_id=$1)`, id).Scan(&assigned); err != nil {
		return err
	}
	if assigned {
		return ErrBusy
	}
	if !deleting {
		if _, err = tx.Exec(ctx, `UPDATE managed_networks SET status='deleting',deletion_requested_at=now(),last_error='',updated_at=now() WHERE id=$1`, id); err != nil {
			return err
		}
	}
	payload, _ := json.Marshal(map[string]string{"networkId": id.String()})
	if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,resource_key,max_attempts) SELECT $1,'network.delete',$2,$3,10 WHERE NOT EXISTS(SELECT 1 FROM jobs WHERE kind='network.delete' AND payload->>'networkId'=$4 AND status IN ('pending','running'))`, uuid.New(), payload, "network:"+id.String(), id.String()); err != nil {
		return err
	}
	return nil
}

func (s *Store) RetryManagedNetworkProvisioning(ctx context.Context, organizationID, id uuid.UUID) (ManagedNetwork, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ManagedNetwork{}, err
	}
	defer tx.Rollback(ctx)
	item, err := retryManagedNetworkProvisioningTx(ctx, tx, organizationID, id)
	if err != nil {
		return ManagedNetwork{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return ManagedNetwork{}, err
	}
	return item, nil
}

func (s *Store) RetryManagedNetworkProvisioningWithAudit(ctx context.Context, principal Principal, id uuid.UUID, remoteAddr string) (ManagedNetwork, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ManagedNetwork{}, err
	}
	defer tx.Rollback(ctx)
	item, err := retryManagedNetworkProvisioningTx(ctx, tx, principal.OrganizationID, id)
	if err != nil {
		return ManagedNetwork{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "network.create.retried", "managed_network", id.String(), remoteAddr, nil); err != nil {
		return ManagedNetwork{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return ManagedNetwork{}, err
	}
	return item, nil
}

func retryManagedNetworkProvisioningTx(ctx context.Context, tx pgx.Tx, organizationID, id uuid.UUID) (ManagedNetwork, error) {
	var status string
	var deleting bool
	if err := tx.QueryRow(ctx, `SELECT status,deletion_requested_at IS NOT NULL FROM managed_networks WHERE id=$1 AND organization_id=$2 FOR UPDATE`, id, organizationID).Scan(&status, &deleting); errors.Is(err, pgx.ErrNoRows) {
		return ManagedNetwork{}, ErrNotFound
	} else if err != nil {
		return ManagedNetwork{}, err
	}
	if deleting {
		return ManagedNetwork{}, ErrDeleting
	}
	if status != "error" {
		return ManagedNetwork{}, ErrBusy
	}
	var err error
	var active bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM jobs WHERE kind='network.create' AND payload->>'networkId'=$1 AND status IN ('pending','running'))`, id.String()).Scan(&active); err != nil {
		return ManagedNetwork{}, err
	}
	if active {
		return ManagedNetwork{}, ErrBusy
	}
	if _, err = tx.Exec(ctx, `UPDATE managed_networks SET status='provisioning',last_error='',updated_at=now() WHERE id=$1`, id); err != nil {
		return ManagedNetwork{}, err
	}
	payload, _ := json.Marshal(map[string]string{"networkId": id.String()})
	if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,resource_key,max_attempts) VALUES($1,'network.create',$2,$3,10)`, uuid.New(), payload, "network:"+id.String()); err != nil {
		return ManagedNetwork{}, err
	}
	return scanManagedNetwork(tx.QueryRow(ctx, `SELECT `+managedNetworkColumns+` FROM managed_networks WHERE id=$1 AND organization_id=$2`, id, organizationID))
}

func (s *Store) ListServiceNetworks(ctx context.Context, organizationID, serviceID uuid.UUID) ([]ManagedNetwork, error) {
	attachments, err := s.ListServiceNetworkAttachments(ctx, organizationID, serviceID)
	if err != nil {
		return nil, err
	}
	items := make([]ManagedNetwork, 0, len(attachments))
	for _, attachment := range attachments {
		items = append(items, attachment.ManagedNetwork)
	}
	return items, nil
}

func (s *Store) ListServiceNetworkAttachments(ctx context.Context, organizationID, serviceID uuid.UUID) ([]ManagedNetworkAttachment, error) {
	var exists bool
	if err := s.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM compose_services s JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE s.id=$1 AND p.organization_id=$2 AND s.deletion_requested_at IS NULL)`, serviceID, organizationID).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrNotFound
	}
	rows, err := s.Pool.Query(ctx, `SELECT `+prefixManagedNetworkColumns("n")+`,sn.service_names FROM managed_networks n JOIN compose_service_networks sn ON sn.network_id=n.id WHERE sn.compose_service_id=$1 AND n.organization_id=$2 ORDER BY lower(n.name),n.id`, serviceID, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ManagedNetworkAttachment{}
	for rows.Next() {
		var item ManagedNetworkAttachment
		var ipam []byte
		if err = rows.Scan(&item.ID, &item.OrganizationID, &item.ClusterID, &item.Name, &item.Driver, &item.Internal, &item.Attachable, &item.EnableIPv4, &item.EnableIPv6, &item.MTU, &ipam, &item.DockerID, &item.Status, &item.LastError, &item.DeletionRequestedAt, &item.CreatedAt, &item.UpdatedAt, &item.ServiceNames); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(ipam, &item.IPAM); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) ReplaceServiceNetworks(ctx context.Context, organizationID, serviceID uuid.UUID, networkIDs []uuid.UUID) ([]ManagedNetwork, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if err = replaceServiceNetworksTx(ctx, tx, organizationID, serviceID, networkIDs); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.ListServiceNetworks(ctx, organizationID, serviceID)
}

func (s *Store) ReplaceServiceNetworksWithAudit(ctx context.Context, principal Principal, serviceID uuid.UUID, networkIDs []uuid.UUID, remoteAddr string) ([]ManagedNetwork, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if err = replaceServiceNetworksTx(ctx, tx, principal.OrganizationID, serviceID, networkIDs); err != nil {
		return nil, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "service.networks.replace", "compose_service", serviceID.String(), remoteAddr, map[string]any{"count": len(networkIDs)}); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.ListServiceNetworks(ctx, principal.OrganizationID, serviceID)
}

func replaceServiceNetworksTx(ctx context.Context, tx pgx.Tx, organizationID, serviceID uuid.UUID, networkIDs []uuid.UUID) error {
	var clusterID *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT e.cluster_id FROM compose_services s JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE s.id=$1 AND p.organization_id=$2 AND s.deletion_requested_at IS NULL FOR UPDATE OF s`, serviceID, organizationID).Scan(&clusterID); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	var err error
	if len(networkIDs) > 0 {
		var count int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM managed_networks WHERE organization_id=$1 AND id=ANY($2::uuid[]) AND driver='overlay' AND status='ready' AND deletion_requested_at IS NULL AND cluster_id IS NOT DISTINCT FROM $3`, organizationID, networkIDs, clusterID).Scan(&count); err != nil {
			return err
		}
		if count != len(networkIDs) {
			return ErrNotFound
		}
	}
	if _, err = tx.Exec(ctx, `DELETE FROM compose_service_networks WHERE compose_service_id=$1`, serviceID); err != nil {
		return err
	}
	if len(networkIDs) > 0 {
		if _, err = tx.Exec(ctx, `INSERT INTO compose_service_networks(compose_service_id,network_id) SELECT $1,unnest($2::uuid[])`, serviceID, networkIDs); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE compose_services SET revision=revision+1,updated_at=now() WHERE id=$1`, serviceID); err != nil {
		return err
	}
	return nil
}

func prefixManagedNetworkColumns(alias string) string {
	return alias + ".id," + alias + ".organization_id," + alias + ".cluster_id," + alias + ".name," + alias + ".driver," + alias + ".internal," + alias + ".attachable," + alias + ".enable_ipv4," + alias + ".enable_ipv6," + alias + ".mtu," + alias + ".ipam," + alias + ".docker_id," + alias + ".status," + alias + ".last_error," + alias + ".deletion_requested_at," + alias + ".created_at," + alias + ".updated_at"
}
