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
	item, err := s.replaceComposeServiceEnvironmentTx(ctx, tx, organizationID, serviceID, expectedRevision, encryptedEnvironment, templateManagedKeys)
	if err != nil {
		return ComposeService{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return ComposeService{}, err
	}
	item.Tags, err = s.ListServiceTags(ctx, organizationID, serviceID)
	return item, err
}

func (s *Store) UpsertComposeServiceVariablesWithAudit(ctx context.Context, principal Principal, serviceID uuid.UUID, expectedRevision int64, encryptedEnvironment string, templateManagedKeys *[]string, names []string, remoteAddr string) (ComposeService, error) {
	return s.replaceComposeServiceEnvironmentWithAudit(ctx, principal, serviceID, expectedRevision, encryptedEnvironment, templateManagedKeys, "service.variables.upsert", map[string]any{"names": names, "count": len(names)}, remoteAddr)
}

func (s *Store) DeleteComposeServiceVariableWithAudit(ctx context.Context, principal Principal, serviceID uuid.UUID, expectedRevision int64, encryptedEnvironment, name, remoteAddr string) (ComposeService, error) {
	return s.replaceComposeServiceEnvironmentWithAudit(ctx, principal, serviceID, expectedRevision, encryptedEnvironment, nil, "service.variables.delete", map[string]any{"name": name}, remoteAddr)
}

func (s *Store) replaceComposeServiceEnvironmentWithAudit(ctx context.Context, principal Principal, serviceID uuid.UUID, expectedRevision int64, encryptedEnvironment string, templateManagedKeys *[]string, action string, metadata map[string]any, remoteAddr string) (ComposeService, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ComposeService{}, err
	}
	defer tx.Rollback(ctx)
	item, err := s.replaceComposeServiceEnvironmentTx(ctx, tx, principal.OrganizationID, serviceID, expectedRevision, encryptedEnvironment, templateManagedKeys)
	if err != nil {
		return ComposeService{}, err
	}
	metadata["revision"] = item.Revision
	if err = appendPrincipalAudit(ctx, tx, principal, action, "compose_service", serviceID.String(), remoteAddr, metadata); err != nil {
		return ComposeService{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return ComposeService{}, err
	}
	item.Tags, err = s.ListServiceTags(ctx, principal.OrganizationID, serviceID)
	return item, err
}

func (s *Store) replaceComposeServiceEnvironmentTx(ctx context.Context, tx pgx.Tx, organizationID, serviceID uuid.UUID, expectedRevision int64, encryptedEnvironment string, templateManagedKeys *[]string) (ComposeService, error) {
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
		if _, err = tx.Exec(ctx, `UPDATE template_instances SET managed_environment_keys=$2,environment_ownership_recorded=true,updated_at=now() WHERE compose_service_id=$1`, serviceID, *templateManagedKeys); err != nil {
			return ComposeService{}, err
		}
	}
	return item, nil
}
