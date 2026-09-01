package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type ResourceGrant struct {
	ScopeType string    `json:"scopeType"`
	ScopeID   uuid.UUID `json:"scopeId"`
	UserID    uuid.UUID `json:"userId"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func ValidScopedRole(role string) bool {
	return role == "viewer" || role == "developer" || role == "admin"
}

func (s *Store) UpsertResourceGrant(ctx context.Context, organizationID uuid.UUID, scopeType string, scopeID, userID uuid.UUID, role string) (ResourceGrant, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ResourceGrant{}, err
	}
	defer tx.Rollback(ctx)
	item, err := upsertResourceGrantTx(ctx, tx, organizationID, scopeType, scopeID, userID, role)
	if err != nil {
		return ResourceGrant{}, err
	}
	return item, tx.Commit(ctx)
}

func (s *Store) UpsertResourceGrantWithAudit(ctx context.Context, principal Principal, scopeType string, scopeID, userID uuid.UUID, role, remoteAddr string) (ResourceGrant, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ResourceGrant{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = lockOrganizationAndRequirePrincipalRole(ctx, tx, principal, "admin"); err != nil {
		return ResourceGrant{}, err
	}
	item, err := upsertResourceGrantTx(ctx, tx, principal.OrganizationID, scopeType, scopeID, userID, role)
	if err != nil {
		return ResourceGrant{}, err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "grant.update", scopeType, scopeID.String(), remoteAddr, map[string]any{"userId": userID, "role": role}); err != nil {
		return ResourceGrant{}, err
	}
	return item, tx.Commit(ctx)
}

func upsertResourceGrantTx(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, scopeType string, scopeID, userID uuid.UUID, role string) (ResourceGrant, error) {
	if !ValidScopedRole(role) {
		return ResourceGrant{}, errors.New("invalid scoped role")
	}
	table, idColumn, parent := grantScope(scopeType)
	if table == "" {
		return ResourceGrant{}, errors.New("invalid grant scope")
	}
	query := `INSERT INTO ` + table + `(` + idColumn + `,user_id,role) SELECT $1,u.id,$3 FROM users u,` + parent + ` r WHERE u.id=$2 AND r.id=$1 AND r.organization_id=$4 AND r.deletion_requested_at IS NULL AND EXISTS(SELECT 1 FROM memberships m WHERE m.organization_id=$4 AND m.user_id=u.id) ON CONFLICT(` + idColumn + `,user_id) DO UPDATE SET role=excluded.role,updated_at=now() RETURNING created_at,updated_at`
	if scopeType == "environment" {
		query = `INSERT INTO environment_grants(environment_id,user_id,role) SELECT $1,u.id,$3 FROM users u,environments e JOIN projects p ON p.id=e.project_id WHERE u.id=$2 AND e.id=$1 AND p.organization_id=$4 AND e.deletion_requested_at IS NULL AND p.deletion_requested_at IS NULL AND EXISTS(SELECT 1 FROM memberships m WHERE m.organization_id=$4 AND m.user_id=u.id) ON CONFLICT(environment_id,user_id) DO UPDATE SET role=excluded.role,updated_at=now() RETURNING created_at,updated_at`
	}
	item := ResourceGrant{ScopeType: scopeType, ScopeID: scopeID, UserID: userID, Role: role}
	err := tx.QueryRow(ctx, query, scopeID, userID, role, organizationID).Scan(&item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ResourceGrant{}, ErrNotFound
	}
	if err == nil {
		err = tx.QueryRow(ctx, `SELECT email FROM users WHERE id=$1`, userID).Scan(&item.Email)
	}
	return item, err
}

func grantScope(scopeType string) (table, idColumn, parent string) {
	if scopeType == "project" {
		return "project_grants", "project_id", "projects"
	}
	if scopeType == "environment" {
		return "environment_grants", "environment_id", "environments"
	}
	return "", "", ""
}

func (s *Store) ListResourceGrants(ctx context.Context, organizationID uuid.UUID, scopeType string, scopeID uuid.UUID) ([]ResourceGrant, error) {
	table, idColumn, _ := grantScope(scopeType)
	if table == "" {
		return nil, errors.New("invalid grant scope")
	}
	ownership := `EXISTS(SELECT 1 FROM projects p WHERE p.id=$1 AND p.organization_id=$2 AND p.deletion_requested_at IS NULL)`
	if scopeType == "environment" {
		ownership = `EXISTS(SELECT 1 FROM environments e JOIN projects p ON p.id=e.project_id WHERE e.id=$1 AND p.organization_id=$2 AND e.deletion_requested_at IS NULL AND p.deletion_requested_at IS NULL)`
	}
	rows, err := s.Pool.Query(ctx, `SELECT g.user_id,u.email,g.role,g.created_at,g.updated_at FROM `+table+` g JOIN users u ON u.id=g.user_id WHERE g.`+idColumn+`=$1 AND `+ownership+` ORDER BY u.email`, scopeID, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ResourceGrant{}
	for rows.Next() {
		item := ResourceGrant{ScopeType: scopeType, ScopeID: scopeID}
		if err = rows.Scan(&item.UserID, &item.Email, &item.Role, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) DeleteResourceGrant(ctx context.Context, organizationID uuid.UUID, scopeType string, scopeID, userID uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = deleteResourceGrantTx(ctx, tx, organizationID, scopeType, scopeID, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) DeleteResourceGrantWithAudit(ctx context.Context, principal Principal, scopeType string, scopeID, userID uuid.UUID, remoteAddr string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = lockOrganizationAndRequirePrincipalRole(ctx, tx, principal, "admin"); err != nil {
		return err
	}
	if err = deleteResourceGrantTx(ctx, tx, principal.OrganizationID, scopeType, scopeID, userID); err != nil {
		return err
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "grant.delete", scopeType, scopeID.String(), remoteAddr, map[string]any{"userId": userID}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func deleteResourceGrantTx(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, scopeType string, scopeID, userID uuid.UUID) error {
	table, idColumn, _ := grantScope(scopeType)
	if table == "" {
		return errors.New("invalid grant scope")
	}
	ownership := `EXISTS(SELECT 1 FROM projects p WHERE p.id=$1 AND p.organization_id=$3)`
	if scopeType == "environment" {
		ownership = `EXISTS(SELECT 1 FROM environments e JOIN projects p ON p.id=e.project_id WHERE e.id=$1 AND p.organization_id=$3)`
	}
	tag, err := tx.Exec(ctx, `DELETE FROM `+table+` WHERE `+idColumn+`=$1 AND user_id=$2 AND `+ownership, scopeID, userID, organizationID)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *Store) EffectiveResourceRole(ctx context.Context, principal Principal, scopeType string, scopeID uuid.UUID) (string, error) {
	var projectID, environmentID *uuid.UUID
	switch scopeType {
	case "project":
		projectID = &scopeID
		var exists bool
		if err := s.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM projects WHERE id=$1 AND organization_id=$2)`, scopeID, principal.OrganizationID).Scan(&exists); err != nil || !exists {
			if err == nil {
				err = ErrNotFound
			}
			return "", err
		}
	case "environment":
		project, environment, err := s.resourceParents(ctx, principal.OrganizationID, scopeType, scopeID)
		if err != nil {
			return "", err
		}
		projectID, environmentID = &project, &environment
	case "service", "database", "deployment", "backup", "restore", "migration", "webhook", "route", "volume_backup", "volume_restore":
		project, environment, err := s.resourceParents(ctx, principal.OrganizationID, scopeType, scopeID)
		if err != nil {
			return "", err
		}
		projectID, environmentID = &project, &environment
	default:
		return "", errors.New("invalid grant scope")
	}
	if principal.ServiceAccountID != nil || principal.Role == "owner" || principal.Role == "admin" {
		return principal.Role, nil
	}
	role := principal.Role
	if projectID != nil {
		var grant string
		if err := s.Pool.QueryRow(ctx, `SELECT role FROM project_grants WHERE project_id=$1 AND user_id=$2`, *projectID, principal.UserID).Scan(&grant); err == nil && roleValue(grant) > roleValue(role) {
			role = grant
		} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return "", err
		}
	}
	if environmentID != nil {
		var grant string
		if err := s.Pool.QueryRow(ctx, `SELECT role FROM environment_grants WHERE environment_id=$1 AND user_id=$2`, *environmentID, principal.UserID).Scan(&grant); err == nil && roleValue(grant) > roleValue(role) {
			role = grant
		} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return "", err
		}
	}
	return role, nil
}

func (s *Store) resourceParents(ctx context.Context, organizationID uuid.UUID, resourceType string, id uuid.UUID) (uuid.UUID, uuid.UUID, error) {
	queries := map[string]string{
		"environment":    `SELECT p.id,e.id FROM environments e JOIN projects p ON p.id=e.project_id WHERE e.id=$1 AND p.organization_id=$2`,
		"service":        `SELECT p.id,e.id FROM compose_services s JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE s.id=$1 AND p.organization_id=$2`,
		"database":       `SELECT p.id,e.id FROM database_instances d JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE d.id=$1 AND p.organization_id=$2`,
		"deployment":     `SELECT p.id,e.id FROM deployments d JOIN compose_services s ON s.id=d.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE d.id=$1 AND p.organization_id=$2`,
		"backup":         `SELECT p.id,e.id FROM database_backups b JOIN database_instances d ON d.id=b.database_instance_id JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE b.id=$1 AND p.organization_id=$2`,
		"restore":        `SELECT p.id,e.id FROM database_restores r JOIN database_backups b ON b.id=r.database_backup_id JOIN database_instances d ON d.id=b.database_instance_id JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE r.id=$1 AND p.organization_id=$2`,
		"migration":      `SELECT p.id,e.id FROM database_migrations m JOIN database_instances d ON d.id=m.database_instance_id JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE m.id=$1 AND p.organization_id=$2`,
		"webhook":        `SELECT p.id,e.id FROM webhook_integrations w JOIN compose_services s ON s.id=w.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE w.id=$1 AND p.organization_id=$2`,
		"route":          `SELECT p.id,e.id FROM routes r JOIN compose_services s ON s.id=r.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE r.id=$1 AND p.organization_id=$2`,
		"volume_backup":  `SELECT p.id,e.id FROM volume_backups b JOIN compose_services s ON s.id=b.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE b.id=$1 AND p.organization_id=$2`,
		"volume_restore": `SELECT p.id,e.id FROM volume_restores r JOIN volume_backups b ON b.id=r.volume_backup_id JOIN compose_services s ON s.id=b.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE r.id=$1 AND p.organization_id=$2`,
	}
	query := queries[resourceType]
	if query == "" {
		return uuid.Nil, uuid.Nil, errors.New("invalid resource type")
	}
	var projectID, environmentID uuid.UUID
	if err := s.Pool.QueryRow(ctx, query, id, organizationID).Scan(&projectID, &environmentID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			err = ErrNotFound
		}
		return uuid.Nil, uuid.Nil, err
	}
	return projectID, environmentID, nil
}

func roleValue(role string) int {
	return map[string]int{"viewer": 1, "developer": 2, "admin": 3, "owner": 4}[role]
}
