package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// MoveComposeService changes only the service's organizational location. The
// stack name and Swarm placement remain stable, so moving across clusters is
// deliberately rejected rather than silently copying stateful workloads.
func (s *Store) MoveComposeService(ctx context.Context, organizationID, serviceID, targetEnvironmentID uuid.UUID) (ComposeService, error) {
	return s.moveComposeService(ctx, organizationID, serviceID, targetEnvironmentID, nil, "")
}

func (s *Store) MoveComposeServiceWithAudit(ctx context.Context, principal Principal, serviceID, targetEnvironmentID uuid.UUID, remoteAddr string) (ComposeService, error) {
	return s.moveComposeService(ctx, principal.OrganizationID, serviceID, targetEnvironmentID, &principal, remoteAddr)
}

func (s *Store) moveComposeService(ctx context.Context, organizationID, serviceID, targetEnvironmentID uuid.UUID, auditPrincipal *Principal, remoteAddr string) (ComposeService, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ComposeService{}, err
	}
	defer tx.Rollback(ctx)

	var sourceEnvironmentID, sourceProjectID uuid.UUID
	var sourceClusterID *uuid.UUID
	err = tx.QueryRow(ctx, `SELECT service.environment_id,environment.project_id,environment.cluster_id
		FROM compose_services service
		JOIN environments environment ON environment.id=service.environment_id
		JOIN projects project ON project.id=environment.project_id
		WHERE service.id=$1 AND project.organization_id=$2 AND service.deletion_requested_at IS NULL AND environment.deletion_requested_at IS NULL AND project.deletion_requested_at IS NULL`, serviceID, organizationID).Scan(&sourceEnvironmentID, &sourceProjectID, &sourceClusterID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ComposeService{}, ErrNotFound
	}
	if err != nil {
		return ComposeService{}, err
	}

	var targetProjectID uuid.UUID
	var targetClusterID *uuid.UUID
	err = tx.QueryRow(ctx, `SELECT environment.project_id,environment.cluster_id
		FROM environments environment
		JOIN projects project ON project.id=environment.project_id
		WHERE environment.id=$1 AND project.organization_id=$2`, targetEnvironmentID, organizationID).Scan(&targetProjectID, &targetClusterID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ComposeService{}, ErrNotFound
	}
	if err != nil {
		return ComposeService{}, err
	}
	if sourceEnvironmentID == targetEnvironmentID {
		if auditPrincipal != nil {
			if err = appendPrincipalAudit(ctx, tx, *auditPrincipal, "service.move", "compose_service", serviceID.String(), remoteAddr, map[string]any{"environmentId": targetEnvironmentID}); err != nil {
				return ComposeService{}, err
			}
		}
		if err = tx.Commit(ctx); err != nil {
			return ComposeService{}, err
		}
		service, _, err := s.GetComposeService(ctx, organizationID, serviceID)
		return service, err
	}

	// Lock parents before the child, matching create/delete lock ordering. The
	// source is rechecked after locking so a concurrent move cannot redirect it.
	projectIDs := []uuid.UUID{sourceProjectID}
	if targetProjectID != sourceProjectID {
		projectIDs = append(projectIDs, targetProjectID)
	}
	rows, err := tx.Query(ctx, `SELECT id FROM projects WHERE id=ANY($1::uuid[]) AND organization_id=$2 AND deletion_requested_at IS NULL ORDER BY id FOR UPDATE`, projectIDs, organizationID)
	if err != nil {
		return ComposeService{}, err
	}
	lockedProjects := 0
	for rows.Next() {
		lockedProjects++
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return ComposeService{}, err
	}
	if lockedProjects != len(projectIDs) {
		return ComposeService{}, ErrNotFound
	}

	environmentIDs := []uuid.UUID{sourceEnvironmentID, targetEnvironmentID}
	rows, err = tx.Query(ctx, `SELECT id FROM environments WHERE id=ANY($1::uuid[]) AND deletion_requested_at IS NULL ORDER BY id FOR UPDATE`, environmentIDs)
	if err != nil {
		return ComposeService{}, err
	}
	lockedEnvironments := 0
	for rows.Next() {
		lockedEnvironments++
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return ComposeService{}, err
	}
	if lockedEnvironments != 2 {
		return ComposeService{}, ErrNotFound
	}

	var currentEnvironmentID uuid.UUID
	var deleting bool
	err = tx.QueryRow(ctx, `SELECT environment_id,deletion_requested_at IS NOT NULL FROM compose_services WHERE id=$1 FOR UPDATE`, serviceID).Scan(&currentEnvironmentID, &deleting)
	if errors.Is(err, pgx.ErrNoRows) || currentEnvironmentID != sourceEnvironmentID {
		return ComposeService{}, ErrNotFound
	}
	if err != nil {
		return ComposeService{}, err
	}
	if deleting {
		return ComposeService{}, ErrDeleting
	}
	if !sameOptionalUUID(sourceClusterID, targetClusterID) {
		return ComposeService{}, ErrCrossClusterMove
	}

	var managedDatabase bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM database_instances WHERE compose_service_id=$1)`, serviceID).Scan(&managedDatabase); err != nil {
		return ComposeService{}, err
	}
	if managedDatabase {
		return ComposeService{}, ErrManagedDatabaseMove
	}
	busy, err := activeServiceOperations(ctx, tx, []uuid.UUID{serviceID})
	if err != nil {
		return ComposeService{}, err
	}
	if busy {
		return ComposeService{}, ErrBusy
	}
	if err = s.enforcePolicy(ctx, tx, organizationID, &sourceProjectID, &sourceEnvironmentID, "deployment"); err != nil {
		return ComposeService{}, err
	}
	if err = s.enforcePolicy(ctx, tx, organizationID, &targetProjectID, &targetEnvironmentID, "deployment"); err != nil {
		return ComposeService{}, err
	}
	if targetProjectID != sourceProjectID {
		if err = enforceMoveServiceQuota(ctx, tx, organizationID, "project", targetProjectID); err != nil {
			return ComposeService{}, err
		}
	}
	if err = enforceMoveServiceQuota(ctx, tx, organizationID, "environment", targetEnvironmentID); err != nil {
		return ComposeService{}, err
	}

	var service ComposeService
	err = tx.QueryRow(ctx, `UPDATE compose_services SET environment_id=$2,updated_at=now() WHERE id=$1
		RETURNING id,environment_id,name,slug,stack_name,storage_node_id,compose_yaml,encrypted_env,revision,desired_state,created_at,updated_at`, serviceID, targetEnvironmentID).Scan(&service.ID, &service.EnvironmentID, &service.Name, &service.Slug, &service.StackName, &service.StorageNodeID, &service.ComposeYAML, &service.EncryptedEnv, &service.Revision, &service.DesiredState, &service.CreatedAt, &service.UpdatedAt)
	if err != nil {
		return ComposeService{}, err
	}
	if auditPrincipal != nil {
		if err = appendPrincipalAudit(ctx, tx, *auditPrincipal, "service.move", "compose_service", serviceID.String(), remoteAddr, map[string]any{"environmentId": targetEnvironmentID}); err != nil {
			return ComposeService{}, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return ComposeService{}, err
	}
	service.Tags, err = s.ListServiceTags(ctx, organizationID, serviceID)
	return service, err
}

func enforceMoveServiceQuota(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, scopeType string, scopeID uuid.UUID) error {
	var limit *int
	err := tx.QueryRow(ctx, `SELECT max_services FROM resource_policies WHERE organization_id=$1 AND scope_type=$2 AND scope_id=$3`, organizationID, scopeType, scopeID).Scan(&limit)
	if errors.Is(err, pgx.ErrNoRows) || limit == nil {
		return nil
	}
	if err != nil {
		return err
	}
	count, err := policyResourceCount(ctx, tx, scopeType, scopeID, "services")
	if err != nil {
		return err
	}
	if count >= *limit {
		return &QuotaExceededError{Scope: scopeType, Resource: "services", Limit: *limit}
	}
	return nil
}
