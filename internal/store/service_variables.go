package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ReplaceComposeServiceEnvironment atomically replaces encrypted runtime
// variables. The expected revision prevents a stale read/decrypt/merge cycle
// from overwriting a concurrent service update.
func (s *Store) ReplaceComposeServiceEnvironment(ctx context.Context, organizationID, serviceID uuid.UUID, expectedRevision int64, encryptedEnvironment string, templateManagedKeys *[]string) (ComposeService, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ComposeService{}, err
	}
	defer tx.Rollback(ctx)
	projectID, environmentID, err := lockActiveServiceForMutation(ctx, tx, organizationID, serviceID)
	if err != nil {
		return ComposeService{}, err
	}
	if err = s.enforcePolicy(ctx, tx, organizationID, &projectID, &environmentID, "deployment"); err != nil {
		return ComposeService{}, err
	}
	if err = ensureNoActiveDeploymentTx(ctx, tx, serviceID); err != nil {
		return ComposeService{}, err
	}
	var item ComposeService
	err = tx.QueryRow(ctx, `UPDATE compose_services SET encrypted_env=$3,revision=revision+1,updated_at=now() WHERE id=$1 AND revision=$2 AND deletion_requested_at IS NULL RETURNING id,environment_id,name,slug,stack_name,storage_node_id,compose_yaml,encrypted_env,revision,desired_state,created_at,updated_at`, serviceID, expectedRevision, encryptedEnvironment).Scan(&item.ID, &item.EnvironmentID, &item.Name, &item.Slug, &item.StackName, &item.StorageNodeID, &item.ComposeYAML, &item.EncryptedEnv, &item.Revision, &item.DesiredState, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ComposeService{}, ErrBusy
	}
	if err != nil {
		return ComposeService{}, err
	}
	if templateManagedKeys != nil {
		if _, err = tx.Exec(ctx, `UPDATE template_instances SET managed_environment_keys=$2,updated_at=now() WHERE compose_service_id=$1`, serviceID, *templateManagedKeys); err != nil {
			return ComposeService{}, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return ComposeService{}, err
	}
	item.Tags, err = s.ListServiceTags(ctx, organizationID, serviceID)
	return item, err
}
