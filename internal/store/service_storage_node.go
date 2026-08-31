package store

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var storageNodeIDPattern = regexp.MustCompile(`^[a-z0-9]{1,64}$`)

// RebindComposeServiceStorageNode records an operator-confirmed relocation of
// node-local named volumes. The platform does not copy data: callers must stop
// the service and move or restore every volume before changing the binding.
func (s *Store) RebindComposeServiceStorageNode(ctx context.Context, principal Principal, serviceID uuid.UUID, nodeID, confirmation, remoteAddr string) (ComposeService, error) {
	nodeID = strings.TrimSpace(nodeID)
	if !storageNodeIDPattern.MatchString(nodeID) {
		return ComposeService{}, ErrInvalidStorageNode
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ComposeService{}, err
	}
	defer tx.Rollback(ctx)

	var item ComposeService
	var deleting bool
	err = tx.QueryRow(ctx, `SELECT service.id,service.environment_id,service.name,service.slug,service.stack_name,service.storage_node_id,service.compose_yaml,service.encrypted_env,service.revision,service.desired_state,service.created_at,service.updated_at,service.deletion_requested_at IS NOT NULL
		FROM compose_services service
		JOIN environments environment ON environment.id=service.environment_id AND environment.deletion_requested_at IS NULL
		JOIN projects project ON project.id=environment.project_id AND project.deletion_requested_at IS NULL
		WHERE service.id=$1 AND project.organization_id=$2
		FOR UPDATE OF service`, serviceID, principal.OrganizationID).Scan(&item.ID, &item.EnvironmentID, &item.Name, &item.Slug, &item.StackName, &item.StorageNodeID, &item.ComposeYAML, &item.EncryptedEnv, &item.Revision, &item.DesiredState, &item.CreatedAt, &item.UpdatedAt, &deleting)
	if errors.Is(err, pgx.ErrNoRows) {
		return ComposeService{}, ErrNotFound
	}
	if err != nil {
		return ComposeService{}, err
	}
	if deleting {
		return ComposeService{}, ErrDeleting
	}
	if confirmation != item.Slug {
		return ComposeService{}, ErrStorageNodeConfirmation
	}
	if item.StorageNodeID == "" {
		return ComposeService{}, ErrStorageNodeUnassigned
	}
	if item.DesiredState != "stopped" {
		return ComposeService{}, ErrStorageNodeRebindRequiresStopped
	}
	var stopped bool
	err = tx.QueryRow(ctx, `SELECT COALESCE((SELECT status='succeeded' FROM jobs WHERE kind='stop.compose' AND resource_key=$1 ORDER BY created_at DESC,id DESC LIMIT 1),false)`, "service:"+serviceID.String()).Scan(&stopped)
	if err != nil {
		return ComposeService{}, err
	}
	if !stopped {
		return ComposeService{}, ErrStorageNodeRebindRequiresStopped
	}
	busy, err := activeServiceOperations(ctx, tx, []uuid.UUID{serviceID})
	if err != nil {
		return ComposeService{}, err
	}
	if busy {
		return ComposeService{}, ErrBusy
	}
	if item.StorageNodeID == nodeID {
		return item, tx.Commit(ctx)
	}
	previousNodeID := item.StorageNodeID
	if _, err = tx.Exec(ctx, `UPDATE compose_services SET storage_node_id=$2,updated_at=now() WHERE id=$1`, serviceID, nodeID); err != nil {
		return ComposeService{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE database_instances SET storage_node_id=$2,updated_at=now() WHERE compose_service_id=$1`, serviceID, nodeID); err != nil {
		return ComposeService{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "service.storage_node_rebind", "compose_service", serviceID.String(), remoteAddr, map[string]string{"previousNodeId": previousNodeID, "nodeId": nodeID}); err != nil {
		return ComposeService{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return ComposeService{}, err
	}
	item.StorageNodeID = nodeID
	return item, nil
}
