package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrMaintenance = errors.New("resource is in maintenance mode")

type QuotaExceededError struct {
	Scope    string
	Resource string
	Limit    int
}

func (e *QuotaExceededError) Error() string {
	return fmt.Sprintf("%s %s quota of %d exceeded", e.Scope, e.Resource, e.Limit)
}

type ResourcePolicy struct {
	OrganizationID    uuid.UUID `json:"organizationId"`
	ScopeType         string    `json:"scopeType"`
	ScopeID           uuid.UUID `json:"scopeId"`
	Maintenance       bool      `json:"maintenance"`
	MaintenanceReason string    `json:"maintenanceReason"`
	MaxProjects       *int      `json:"maxProjects"`
	MaxEnvironments   *int      `json:"maxEnvironments"`
	MaxServices       *int      `json:"maxServices"`
	MaxDatabases      *int      `json:"maxDatabases"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

func (s *Store) GetResourcePolicy(ctx context.Context, organizationID uuid.UUID, scopeType string, scopeID uuid.UUID) (ResourcePolicy, error) {
	if err := s.validatePolicyScope(ctx, s.Pool, organizationID, scopeType, scopeID); err != nil {
		return ResourcePolicy{}, err
	}
	item := ResourcePolicy{OrganizationID: organizationID, ScopeType: scopeType, ScopeID: scopeID}
	err := s.Pool.QueryRow(ctx, `SELECT maintenance_enabled,maintenance_reason,max_projects,max_environments,max_services,max_databases,updated_at FROM resource_policies WHERE organization_id=$1 AND scope_type=$2 AND scope_id=$3`, organizationID, scopeType, scopeID).Scan(&item.Maintenance, &item.MaintenanceReason, &item.MaxProjects, &item.MaxEnvironments, &item.MaxServices, &item.MaxDatabases, &item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		item.UpdatedAt = time.Time{}
		return item, nil
	}
	return item, err
}

func (s *Store) PutResourcePolicy(ctx context.Context, item ResourcePolicy) (ResourcePolicy, error) {
	if err := validatePolicy(item); err != nil {
		return ResourcePolicy{}, err
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ResourcePolicy{}, err
	}
	defer tx.Rollback(ctx)
	if err := s.validatePolicyScope(ctx, tx, item.OrganizationID, item.ScopeType, item.ScopeID); err != nil {
		return ResourcePolicy{}, err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text,0))`, item.OrganizationID); err != nil {
		return ResourcePolicy{}, err
	}
	err = tx.QueryRow(ctx, `INSERT INTO resource_policies(organization_id,scope_type,scope_id,maintenance_enabled,maintenance_reason,max_projects,max_environments,max_services,max_databases)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT(scope_type,scope_id) DO UPDATE SET maintenance_enabled=excluded.maintenance_enabled,maintenance_reason=excluded.maintenance_reason,max_projects=excluded.max_projects,max_environments=excluded.max_environments,max_services=excluded.max_services,max_databases=excluded.max_databases,updated_at=now()
		WHERE resource_policies.organization_id=excluded.organization_id
		RETURNING updated_at`, item.OrganizationID, item.ScopeType, item.ScopeID, item.Maintenance, item.MaintenanceReason, item.MaxProjects, item.MaxEnvironments, item.MaxServices, item.MaxDatabases).Scan(&item.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ResourcePolicy{}, ErrNotFound
	}
	if err != nil {
		return ResourcePolicy{}, err
	}
	return item, tx.Commit(ctx)
}

func servicePolicyScope(ctx context.Context, tx pgx.Tx, organizationID, serviceID uuid.UUID) (uuid.UUID, uuid.UUID, error) {
	var projectID, environmentID uuid.UUID
	err := tx.QueryRow(ctx, `SELECT p.id,e.id FROM compose_services s JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE s.id=$1 AND p.organization_id=$2`, serviceID, organizationID).Scan(&projectID, &environmentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, uuid.Nil, ErrNotFound
	}
	return projectID, environmentID, err
}

func ensureEnvironmentClusterWritable(ctx context.Context, tx pgx.Tx, environmentID uuid.UUID) error {
	var available bool
	err := tx.QueryRow(ctx, `SELECT e.cluster_id IS NULL OR EXISTS(SELECT 1 FROM clusters c WHERE c.id=e.cluster_id AND c.state='active' AND NOT COALESCE(now()>=c.maintenance_starts_at AND now()<c.maintenance_ends_at,false)) FROM environments e WHERE e.id=$1`, environmentID).Scan(&available)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if !available {
		return ErrMaintenance
	}
	return nil
}

type policyQueryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (s *Store) validatePolicyScope(ctx context.Context, db policyQueryer, organizationID uuid.UUID, scopeType string, scopeID uuid.UUID) error {
	var exists bool
	switch scopeType {
	case "organization":
		exists = scopeID == organizationID
		if exists {
			err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM organizations WHERE id=$1)`, organizationID).Scan(&exists)
			if err != nil {
				return err
			}
		}
	case "project":
		if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM projects WHERE id=$1 AND organization_id=$2)`, scopeID, organizationID).Scan(&exists); err != nil {
			return err
		}
	case "environment":
		if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM environments e JOIN projects p ON p.id=e.project_id WHERE e.id=$1 AND p.organization_id=$2)`, scopeID, organizationID).Scan(&exists); err != nil {
			return err
		}
	default:
		return errors.New("invalid policy scope")
	}
	if !exists {
		return ErrNotFound
	}
	return nil
}

func validatePolicy(item ResourcePolicy) error {
	if item.ScopeType != "organization" && item.MaxProjects != nil {
		return errors.New("maxProjects is only valid for organization policies")
	}
	if item.ScopeType == "environment" && item.MaxEnvironments != nil {
		return errors.New("maxEnvironments is not valid for environment policies")
	}
	for _, limit := range []*int{item.MaxProjects, item.MaxEnvironments, item.MaxServices, item.MaxDatabases} {
		if limit != nil && (*limit < 1 || *limit > 1000000) {
			return errors.New("quota values must be between 1 and 1000000")
		}
	}
	if len(item.MaintenanceReason) > 500 {
		return errors.New("maintenanceReason is too long")
	}
	return nil
}

// enforcePolicy takes an organization-scoped transaction lock so quota checks
// and the following insert are serialized across controller replicas.
func (s *Store) enforcePolicy(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, projectID, environmentID *uuid.UUID, resource string) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text,0))`, organizationID); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT scope_type,scope_id,maintenance_enabled,max_projects,max_environments,max_services,max_databases FROM resource_policies WHERE organization_id=$1 AND ((scope_type='organization' AND scope_id=$1) OR (scope_type='project' AND scope_id=$2) OR (scope_type='environment' AND scope_id=$3))`, organizationID, projectID, environmentID)
	if err != nil {
		return err
	}
	policies := []ResourcePolicy{}
	for rows.Next() {
		var p ResourcePolicy
		if err := rows.Scan(&p.ScopeType, &p.ScopeID, &p.Maintenance, &p.MaxProjects, &p.MaxEnvironments, &p.MaxServices, &p.MaxDatabases); err != nil {
			rows.Close()
			return err
		}
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, p := range policies {
		if p.Maintenance {
			return ErrMaintenance
		}
	}
	for _, p := range policies {
		var limit *int
		switch resource {
		case "projects":
			limit = p.MaxProjects
		case "environments":
			limit = p.MaxEnvironments
		case "services":
			limit = p.MaxServices
		case "databases":
			limit = p.MaxDatabases
		case "deployment":
			continue
		}
		if limit == nil {
			continue
		}
		count, err := policyResourceCount(ctx, tx, p.ScopeType, p.ScopeID, resource)
		if err != nil {
			return err
		}
		if count >= *limit {
			return &QuotaExceededError{Scope: p.ScopeType, Resource: resource, Limit: *limit}
		}
	}
	return nil
}

func policyResourceCount(ctx context.Context, tx pgx.Tx, scopeType string, scopeID uuid.UUID, resource string) (int, error) {
	queries := map[string]map[string]string{
		"projects": {"organization": `SELECT count(*) FROM projects WHERE organization_id=$1`},
		"environments": {
			"organization": `SELECT count(*) FROM environments e JOIN projects p ON p.id=e.project_id WHERE p.organization_id=$1`,
			"project":      `SELECT count(*) FROM environments WHERE project_id=$1`,
		},
		"services": {
			"organization": `SELECT count(*) FROM compose_services s JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE p.organization_id=$1 AND s.deletion_requested_at IS NULL`,
			"project":      `SELECT count(*) FROM compose_services s JOIN environments e ON e.id=s.environment_id WHERE e.project_id=$1 AND s.deletion_requested_at IS NULL`,
			"environment":  `SELECT count(*) FROM compose_services WHERE environment_id=$1 AND deletion_requested_at IS NULL`,
		},
		"databases": {
			"organization": `SELECT count(*) FROM database_instances d JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE p.organization_id=$1`,
			"project":      `SELECT count(*) FROM database_instances d JOIN environments e ON e.id=d.environment_id WHERE e.project_id=$1`,
			"environment":  `SELECT count(*) FROM database_instances WHERE environment_id=$1`,
		},
	}
	query := queries[resource][scopeType]
	if query == "" {
		return 0, nil
	}
	var count int
	return count, tx.QueryRow(ctx, query, scopeID).Scan(&count)
}
