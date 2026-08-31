package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Store) CreateLinkedDatabaseWithAudit(ctx context.Context, principal Principal, serviceID uuid.UUID, expectedRevision int64, item DatabaseInstance, encryptedCredentials, remoteAddr string) (DatabaseInstance, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return DatabaseInstance{}, err
	}
	defer tx.Rollback(ctx)
	projectID, environmentID, err := lockActiveServiceForMutation(ctx, tx, principal.OrganizationID, serviceID)
	if err != nil {
		return DatabaseInstance{}, err
	}
	var revision int64
	var desiredState string
	var deployed bool
	if err = tx.QueryRow(ctx, `SELECT service.revision,service.desired_state,EXISTS(SELECT 1 FROM deployments deployment WHERE deployment.compose_service_id=service.id AND deployment.revision=service.revision AND deployment.status='succeeded') FROM compose_services service WHERE service.id=$1`, serviceID).Scan(&revision, &desiredState, &deployed); err != nil {
		return DatabaseInstance{}, err
	}
	if revision != expectedRevision {
		return DatabaseInstance{}, ErrRevisionConflict
	}
	if err = s.enforcePolicy(ctx, tx, principal.OrganizationID, &projectID, &environmentID, "databases"); err != nil {
		return DatabaseInstance{}, err
	}
	if item.ID == uuid.Nil {
		item.ID = uuid.New()
	}
	item.EnvironmentID = environmentID
	item.ComposeServiceID = serviceID
	item.ManagementKind = "compose"
	item.Status = "pending"
	if desiredState == "stopped" {
		item.Status = "stopped"
	} else if deployed {
		item.Status = "running"
	}
	config, err := json.Marshal(item.Config)
	if err != nil {
		return DatabaseInstance{}, err
	}
	err = tx.QueryRow(ctx, `INSERT INTO database_instances(id,environment_id,name,slug,engine,version,driver_source,driver_artifact_digest,management_kind,connection_service_name,compose_service_id,encrypted_credentials,config,status)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,'compose',$9,$10,$11,$12,$13) RETURNING created_at`, item.ID, item.EnvironmentID, item.Name, item.Slug, item.Engine, item.Version, item.DriverSource, item.DriverDigest, item.ConnectionServiceName, serviceID, encryptedCredentials, config, item.Status).Scan(&item.CreatedAt)
	if err != nil {
		return DatabaseInstance{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "database.link", "database", item.ID.String(), remoteAddr, map[string]any{"composeServiceId": serviceID, "connectionServiceName": item.ConnectionServiceName, "engine": item.Engine}); err != nil {
		return DatabaseInstance{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return DatabaseInstance{}, err
	}
	return item, nil
}

func (s *Store) RotateLinkedDatabaseCredentialsWithAudit(ctx context.Context, principal Principal, databaseID uuid.UUID, expectedRevision int64, connectionServiceName, version, driverSource, driverDigest string, config map[string]any, encryptedCredentials, remoteAddr string) (DatabaseInstance, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return DatabaseInstance{}, err
	}
	defer tx.Rollback(ctx)
	var serviceID uuid.UUID
	var managementKind string
	var deleting bool
	err = tx.QueryRow(ctx, `SELECT database.compose_service_id,database.management_kind,database.deletion_requested_at IS NOT NULL FROM database_instances database JOIN environments environment ON environment.id=database.environment_id JOIN projects project ON project.id=environment.project_id WHERE database.id=$1 AND project.organization_id=$2 FOR UPDATE OF database`, databaseID, principal.OrganizationID).Scan(&serviceID, &managementKind, &deleting)
	if errors.Is(err, pgx.ErrNoRows) {
		return DatabaseInstance{}, ErrNotFound
	}
	if err != nil {
		return DatabaseInstance{}, err
	}
	if managementKind != "compose" {
		return DatabaseInstance{}, ErrLinkedDatabaseRequired
	}
	if deleting {
		return DatabaseInstance{}, ErrDeleting
	}
	if _, _, err = lockActiveServiceForMutation(ctx, tx, principal.OrganizationID, serviceID); err != nil {
		return DatabaseInstance{}, err
	}
	var revision int64
	if err = tx.QueryRow(ctx, `SELECT revision FROM compose_services WHERE id=$1`, serviceID).Scan(&revision); err != nil {
		return DatabaseInstance{}, err
	}
	if revision != expectedRevision {
		return DatabaseInstance{}, ErrRevisionConflict
	}
	var busy bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM jobs WHERE resource_key=$1 AND status IN ('pending','running'))`, "database:"+databaseID.String()).Scan(&busy); err != nil {
		return DatabaseInstance{}, err
	}
	if busy {
		return DatabaseInstance{}, ErrBusy
	}
	encodedConfig, err := json.Marshal(config)
	if err != nil {
		return DatabaseInstance{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE database_instances SET version=$2,driver_source=$3,driver_artifact_digest=$4,connection_service_name=$5,encrypted_credentials=$6,config=$7,updated_at=now() WHERE id=$1 AND management_kind='compose'`, databaseID, version, driverSource, driverDigest, connectionServiceName, encryptedCredentials, encodedConfig); err != nil {
		return DatabaseInstance{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "database.credentials.rotate", "database", databaseID.String(), remoteAddr, map[string]any{"composeServiceId": serviceID, "connectionServiceName": connectionServiceName}); err != nil {
		return DatabaseInstance{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return DatabaseInstance{}, err
	}
	return s.GetDatabase(ctx, principal.OrganizationID, databaseID)
}
