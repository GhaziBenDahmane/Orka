package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var deletionFinalizerResourceTypes = []string{"project", "environment", "service", "database", "cluster", "network"}

type DeletionFinalizer struct {
	ResourceType string     `json:"resourceType"`
	ResourceID   uuid.UUID  `json:"resourceId"`
	ResourceName string     `json:"resourceName"`
	RequestedAt  time.Time  `json:"requestedAt"`
	JobID        *uuid.UUID `json:"jobId,omitempty"`
	Kind         string     `json:"kind"`
	Status       string     `json:"status"`
	Attempts     int        `json:"attempts"`
	MaxAttempts  int        `json:"maxAttempts"`
	LastError    string     `json:"lastError,omitempty"`
	RunAfter     *time.Time `json:"runAfter,omitempty"`
	CreatedAt    *time.Time `json:"createdAt,omitempty"`
	LockedAt     *time.Time `json:"lockedAt,omitempty"`
	FinishedAt   *time.Time `json:"finishedAt,omitempty"`
	Retryable    bool       `json:"retryable"`
}

type DeletionFinalizerFilter struct {
	ResourceType string
	Status       string
	Limit        int
}

// ListDeletionFinalizers exposes bounded, tenant-scoped operational metadata.
// Job payloads and raw worker errors deliberately never cross the API boundary.
func (s *Store) ListDeletionFinalizers(ctx context.Context, organizationID uuid.UUID, filter DeletionFinalizerFilter) ([]DeletionFinalizer, error) {
	if filter.Limit <= 0 {
		filter.Limit = 100
	}
	if filter.Limit > 200 {
		filter.Limit = 200
	}
	rows, err := s.Pool.Query(ctx, `
		WITH deleting_resources(resource_type,resource_id,resource_name,requested_at,kind,payload_key) AS (
			SELECT 'project',project.id,project.name,project.deletion_requested_at,'delete.project','projectId'
			FROM projects project WHERE project.organization_id=$1 AND project.deletion_requested_at IS NOT NULL
			UNION ALL
			SELECT 'environment',environment.id,environment.name,environment.deletion_requested_at,'delete.environment','environmentId'
			FROM environments environment JOIN projects project ON project.id=environment.project_id
			WHERE project.organization_id=$1 AND environment.deletion_requested_at IS NOT NULL
			UNION ALL
			SELECT 'service',service.id,service.name,service.deletion_requested_at,'delete.compose','serviceId'
			FROM compose_services service JOIN environments environment ON environment.id=service.environment_id JOIN projects project ON project.id=environment.project_id
			WHERE project.organization_id=$1 AND service.deletion_requested_at IS NOT NULL
			UNION ALL
			SELECT 'database',database.id,database.name,database.deletion_requested_at,'delete.database-link','databaseId'
			FROM database_instances database JOIN environments environment ON environment.id=database.environment_id JOIN projects project ON project.id=environment.project_id
			WHERE project.organization_id=$1 AND database.deletion_requested_at IS NOT NULL AND database.management_kind='compose'
			UNION ALL
			SELECT 'cluster',cluster.id,cluster.name,cluster.deletion_requested_at,'delete.cluster','clusterId'
			FROM clusters cluster WHERE cluster.organization_id=$1 AND cluster.deletion_requested_at IS NOT NULL
			UNION ALL
			SELECT 'network',network.id,network.name,network.deletion_requested_at,'network.delete','networkId'
			FROM managed_networks network WHERE network.organization_id=$1 AND network.deletion_requested_at IS NOT NULL
		)
		SELECT resource.resource_type,resource.resource_id,resource.resource_name,resource.requested_at,
		       job.id,resource.kind,COALESCE(job.status,'missing'),COALESCE(job.attempts,0),COALESCE(job.max_attempts,0),
		       CASE WHEN COALESCE(job.last_error,'')='' THEN '' ELSE 'finalizer failed; inspect controller logs using the job ID' END,
		       job.run_after,job.created_at,job.locked_at,job.finished_at,
		       job.id IS NULL OR job.status NOT IN ('pending','running')
		FROM deleting_resources resource
		LEFT JOIN LATERAL (
			SELECT candidate.id,candidate.status,candidate.attempts,candidate.max_attempts,candidate.last_error,
			       candidate.run_after,candidate.created_at,candidate.locked_at,candidate.finished_at
			FROM jobs candidate
			WHERE candidate.kind=resource.kind AND candidate.payload->>resource.payload_key=resource.resource_id::text
			ORDER BY candidate.created_at DESC,candidate.id DESC LIMIT 1
		) job ON true
		WHERE ($2='' OR resource.resource_type=$2) AND ($3='' OR COALESCE(job.status,'missing')=$3)
		ORDER BY resource.requested_at,resource.resource_type,resource.resource_id
		LIMIT $4`, organizationID, filter.ResourceType, filter.Status, filter.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []DeletionFinalizer{}
	for rows.Next() {
		var item DeletionFinalizer
		if err = rows.Scan(&item.ResourceType, &item.ResourceID, &item.ResourceName, &item.RequestedAt,
			&item.JobID, &item.Kind, &item.Status, &item.Attempts, &item.MaxAttempts, &item.LastError,
			&item.RunAfter, &item.CreatedAt, &item.LockedAt, &item.FinishedAt, &item.Retryable); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

type deletionFinalizerTarget struct {
	resourceType string
	resourceID   uuid.UUID
	resourceName string
	requestedAt  time.Time
	kind         string
	payloadKey   string
	resourceKey  string
	defaultData  map[string]any
}

func lockDeletionFinalizerTarget(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, resourceType string, resourceID uuid.UUID) (deletionFinalizerTarget, error) {
	target := deletionFinalizerTarget{resourceType: resourceType, resourceID: resourceID}
	var query string
	switch resourceType {
	case "project":
		target.kind, target.payloadKey = "delete.project", "projectId"
		query = `SELECT project.name,project.deletion_requested_at FROM projects project WHERE project.id=$1 AND project.organization_id=$2 AND project.deletion_requested_at IS NOT NULL FOR UPDATE OF project`
	case "environment":
		target.kind, target.payloadKey = "delete.environment", "environmentId"
		query = `SELECT environment.name,environment.deletion_requested_at FROM environments environment JOIN projects project ON project.id=environment.project_id WHERE environment.id=$1 AND project.organization_id=$2 AND environment.deletion_requested_at IS NOT NULL FOR UPDATE OF environment`
	case "service":
		target.kind, target.payloadKey, target.resourceKey = "delete.compose", "serviceId", "service:"+resourceID.String()
		var stackName string
		err := tx.QueryRow(ctx, `SELECT service.name,service.deletion_requested_at,service.stack_name FROM compose_services service JOIN environments environment ON environment.id=service.environment_id JOIN projects project ON project.id=environment.project_id WHERE service.id=$1 AND project.organization_id=$2 AND service.deletion_requested_at IS NOT NULL FOR UPDATE OF service`, resourceID, organizationID).Scan(&target.resourceName, &target.requestedAt, &stackName)
		if errors.Is(err, pgx.ErrNoRows) {
			return deletionFinalizerTarget{}, ErrNotFound
		}
		if err != nil {
			return deletionFinalizerTarget{}, err
		}
		target.defaultData = map[string]any{"serviceId": resourceID.String(), "stackName": stackName, "deleteVolumes": false}
		return target, nil
	case "database":
		target.kind, target.payloadKey, target.resourceKey = "delete.database-link", "databaseId", "database:"+resourceID.String()
		query = `SELECT database.name,database.deletion_requested_at FROM database_instances database JOIN environments environment ON environment.id=database.environment_id JOIN projects project ON project.id=environment.project_id WHERE database.id=$1 AND project.organization_id=$2 AND database.management_kind='compose' AND database.deletion_requested_at IS NOT NULL FOR UPDATE OF database`
	case "cluster":
		target.kind, target.payloadKey = "delete.cluster", "clusterId"
		query = `SELECT cluster.name,cluster.deletion_requested_at FROM clusters cluster WHERE cluster.id=$1 AND cluster.organization_id=$2 AND cluster.deletion_requested_at IS NOT NULL FOR UPDATE OF cluster`
	case "network":
		target.kind, target.payloadKey, target.resourceKey = "network.delete", "networkId", "network:"+resourceID.String()
		query = `SELECT network.name,network.deletion_requested_at FROM managed_networks network WHERE network.id=$1 AND network.organization_id=$2 AND network.deletion_requested_at IS NOT NULL FOR UPDATE OF network`
	default:
		return deletionFinalizerTarget{}, ErrNotFound
	}
	err := tx.QueryRow(ctx, query, resourceID, organizationID).Scan(&target.resourceName, &target.requestedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return deletionFinalizerTarget{}, ErrNotFound
	}
	if err != nil {
		return deletionFinalizerTarget{}, err
	}
	target.defaultData = map[string]any{target.payloadKey: resourceID.String()}
	return target, nil
}

func (s *Store) RetryDeletionFinalizerWithAudit(ctx context.Context, principal Principal, resourceType string, resourceID uuid.UUID, remoteAddr string) (DeletionFinalizer, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return DeletionFinalizer{}, err
	}
	defer tx.Rollback(ctx)
	target, err := lockDeletionFinalizerTarget(ctx, tx, principal.OrganizationID, resourceType, resourceID)
	if err != nil {
		return DeletionFinalizer{}, err
	}

	var previousID uuid.UUID
	var previousStatus string
	var payload []byte
	var resourceKey *string
	var maxAttempts int
	err = tx.QueryRow(ctx, `SELECT id,status,payload,resource_key,max_attempts FROM jobs WHERE kind=$1 AND payload->>$2=$3 ORDER BY created_at DESC,id DESC LIMIT 1 FOR UPDATE`, target.kind, target.payloadKey, resourceID.String()).Scan(&previousID, &previousStatus, &payload, &resourceKey, &maxAttempts)
	if errors.Is(err, pgx.ErrNoRows) {
		payload, err = json.Marshal(target.defaultData)
		maxAttempts = 10
		if resourceType == "project" || resourceType == "environment" {
			maxAttempts = 50
		}
		if target.resourceKey != "" {
			resourceKey = &target.resourceKey
		}
	} else if err != nil {
		return DeletionFinalizer{}, err
	} else if previousStatus == "pending" || previousStatus == "running" {
		return DeletionFinalizer{}, ErrBusy
	}
	if err != nil {
		return DeletionFinalizer{}, err
	}
	var active bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM jobs WHERE kind=$1 AND payload->>$2=$3 AND status IN ('pending','running'))`, target.kind, target.payloadKey, resourceID.String()).Scan(&active); err != nil {
		return DeletionFinalizer{}, err
	}
	if active {
		return DeletionFinalizer{}, ErrBusy
	}
	jobID := uuid.New()
	if _, err = tx.Exec(ctx, `INSERT INTO jobs(id,kind,payload,resource_key,max_attempts) VALUES($1,$2,$3,$4,$5)`, jobID, target.kind, payload, resourceKey, maxAttempts); err != nil {
		return DeletionFinalizer{}, err
	}
	metadata := map[string]any{"jobId": jobID, "kind": target.kind}
	if previousID != uuid.Nil {
		metadata["previousJobId"] = previousID
	}
	if err = appendPrincipalAudit(ctx, tx, principal, "deletion_finalizer.retry", resourceType, resourceID.String(), remoteAddr, metadata); err != nil {
		return DeletionFinalizer{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return DeletionFinalizer{}, err
	}
	now := time.Now().UTC()
	return DeletionFinalizer{ResourceType: resourceType, ResourceID: resourceID, ResourceName: target.resourceName, RequestedAt: target.requestedAt, JobID: &jobID, Kind: target.kind, Status: "pending", Attempts: 0, MaxAttempts: maxAttempts, RunAfter: &now, CreatedAt: &now, Retryable: false}, nil
}

func ValidDeletionFinalizerResourceType(value string) bool {
	for _, candidate := range deletionFinalizerResourceTypes {
		if candidate == value {
			return true
		}
	}
	return false
}
