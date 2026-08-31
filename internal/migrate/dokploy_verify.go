package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrDokployManifestNotFound = errors.New("no persisted Dokploy parity manifest was found; run a non-dry-run import first")
var ErrDokployManifestOutdated = errors.New("persisted Dokploy parity manifest predates core-resource tracking; rerun the import")

type DokployVerification struct {
	Ready                bool                       `json:"ready"`
	TargetOrganizationID uuid.UUID                  `json:"targetOrganizationId"`
	SourceOrganizationID string                     `json:"sourceOrganizationId"`
	CheckedAt            time.Time                  `json:"checkedAt"`
	Verified             int                        `json:"verified"`
	Acknowledged         int                        `json:"acknowledged"`
	Blocked              int                        `json:"blocked"`
	Checks               []DokployVerificationCheck `json:"checks"`
}

type DokployVerificationCheck struct {
	SourceKind string     `json:"sourceKind"`
	SourceID   string     `json:"sourceId"`
	TargetID   *uuid.UUID `json:"targetId,omitempty"`
	Status     string     `json:"status"`
	Reason     string     `json:"reason,omitempty"`
}

func VerifyDokployImport(ctx context.Context, destination *store.Store, targetOrganizationID uuid.UUID, sourceOrganizationID string, requireOperational bool, acknowledgements []string) (DokployVerification, error) {
	report := DokployVerification{TargetOrganizationID: targetOrganizationID, SourceOrganizationID: strings.TrimSpace(sourceOrganizationID), CheckedAt: time.Now().UTC(), Checks: []DokployVerificationCheck{}}
	if targetOrganizationID == uuid.Nil || report.SourceOrganizationID == "" {
		return report, errors.New("source organization and target organization are required")
	}
	resources, err := destination.ListMigrationResources(ctx, targetOrganizationID, report.SourceOrganizationID)
	if err != nil {
		return report, err
	}
	if len(resources) == 0 {
		return report, ErrDokployManifestNotFound
	}
	coreKinds := map[string]bool{}
	for _, resource := range resources {
		coreKinds[resource.SourceKind] = true
	}
	if !coreKinds["project"] || !coreKinds["environment"] {
		return report, ErrDokployManifestOutdated
	}
	acknowledged := make(map[string]bool, len(acknowledgements))
	for _, value := range acknowledgements {
		acknowledged[strings.TrimSpace(value)] = true
	}
	for _, resource := range resources {
		check := DokployVerificationCheck{SourceKind: resource.SourceKind, SourceID: resource.SourceID, TargetID: resource.TargetID, Status: "verified"}
		if resource.Status != "imported" {
			check.Status, check.Reason = "blocked", resource.Reason
			if check.Reason == "" {
				check.Reason = "source resource was not imported"
			}
			if acknowledged[resource.SourceKind+":"+resource.SourceID] {
				check.Status = "acknowledged"
			}
		} else if resource.TargetID == nil {
			check.Status, check.Reason = "blocked", "imported resource has no target mapping"
		} else if check.Reason, err = verifyDokployTarget(ctx, destination, targetOrganizationID, resource, requireOperational); err != nil {
			return report, err
		} else if check.Reason != "" {
			check.Status = "blocked"
		}
		if check.Status == "verified" {
			report.Verified++
		} else if check.Status == "acknowledged" {
			report.Acknowledged++
		} else {
			report.Blocked++
		}
		report.Checks = append(report.Checks, check)
	}
	report.Ready = report.Blocked == 0
	return report, nil
}

func verifyDokployTarget(ctx context.Context, destination *store.Store, organizationID uuid.UUID, resource store.MigrationResource, requireOperational bool) (string, error) {
	id := *resource.TargetID
	if resource.SourceKind == "backup_policy" {
		return verifyDokployDatabaseBackup(ctx, destination, organizationID, id, resource.UpdatedAt, requireOperational)
	}
	if resource.SourceKind == "volume_backup" {
		return verifyDokployVolumeBackup(ctx, destination, organizationID, id, resource.UpdatedAt, requireOperational)
	}
	if resource.SourceKind == "compose" || resource.SourceKind == "application" {
		var exists bool
		err := destination.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM compose_services s JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE s.id=$1 AND p.organization_id=$2)`, id, organizationID).Scan(&exists)
		if err != nil {
			return "", err
		}
		if !exists {
			return "target service is missing", nil
		}
		if requireOperational {
			return verifyDokployServiceRuntime(ctx, destination, organizationID, id)
		}
		return "", nil
	}
	if resource.SourceKind == "database" {
		var status, engine string
		var serviceID uuid.UUID
		err := destination.Pool.QueryRow(ctx, `SELECT d.status,d.engine,d.compose_service_id FROM database_instances d JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE d.id=$1 AND p.organization_id=$2`, id, organizationID).Scan(&status, &engine, &serviceID)
		if errors.Is(err, pgx.ErrNoRows) {
			return "target database is missing", nil
		}
		if err != nil {
			return "", err
		}
		if requireOperational && status != "running" {
			return "target database is not running", nil
		}
		if requireOperational {
			if reason, runtimeErr := verifyDokployServiceRuntime(ctx, destination, organizationID, serviceID); runtimeErr != nil || reason != "" {
				return reason, runtimeErr
			}
		}
		if requireOperational && dokployTransferCapableEngine(engine) {
			_, sourceID, found := strings.Cut(resource.SourceID, ":")
			if !found || sourceID == "" {
				return "database parity record has an invalid source id", nil
			}
			var transferred bool
			if err = destination.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM database_migrations WHERE database_instance_id=$1 AND source_kind='dokploy' AND source_id=$2 AND status='succeeded' AND created_at >= $3)`, id, sourceID, resource.UpdatedAt).Scan(&transferred); err != nil {
				return "", err
			}
			if !transferred {
				return "target database has no successful Dokploy data transfer", nil
			}
		}
		return "", nil
	}
	if resource.SourceKind == "project_tag" {
		var metadata struct {
			ProjectID string `json:"projectId"`
		}
		if err := json.Unmarshal(resource.Metadata, &metadata); err != nil {
			return "project-tag parity metadata is invalid", nil
		}
		projectID, parseErr := uuid.Parse(metadata.ProjectID)
		if parseErr != nil {
			return "project-tag parity metadata has an invalid project id", nil
		}
		var exists bool
		if err := destination.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM project_tags pt JOIN projects p ON p.id=pt.project_id JOIN tags t ON t.id=pt.tag_id WHERE pt.project_id=$1 AND pt.tag_id=$2 AND p.organization_id=$3 AND t.organization_id=$3)`, projectID, id, organizationID).Scan(&exists); err != nil {
			return "", err
		}
		if !exists {
			return "target project tag assignment is missing", nil
		}
		return "", nil
	}
	if resource.SourceKind == "service_network" {
		var metadata struct {
			ServiceID string `json:"serviceId"`
		}
		if err := json.Unmarshal(resource.Metadata, &metadata); err != nil {
			return "service-network parity metadata is invalid", nil
		}
		serviceID, parseErr := uuid.Parse(metadata.ServiceID)
		if parseErr != nil {
			return "service-network parity metadata has an invalid service id", nil
		}
		var exists bool
		if err := destination.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM compose_service_networks sn JOIN compose_services s ON s.id=sn.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id JOIN managed_networks n ON n.id=sn.network_id WHERE sn.compose_service_id=$1 AND sn.network_id=$2 AND p.organization_id=$3 AND n.organization_id=$3)`, serviceID, id, organizationID).Scan(&exists); err != nil {
			return "", err
		}
		if !exists {
			return "target service network assignment is missing", nil
		}
		return "", nil
	}
	queries := map[string]string{
		"project":            `SELECT EXISTS(SELECT 1 FROM projects WHERE id=$1 AND organization_id=$2)`,
		"environment":        `SELECT EXISTS(SELECT 1 FROM environments e JOIN projects p ON p.id=e.project_id WHERE e.id=$1 AND p.organization_id=$2)`,
		"compose_route":      `SELECT EXISTS(SELECT 1 FROM routes r JOIN compose_services s ON s.id=r.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE r.id=$1 AND p.organization_id=$2)`,
		"application_route":  `SELECT EXISTS(SELECT 1 FROM routes r JOIN compose_services s ON s.id=r.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE r.id=$1 AND p.organization_id=$2)`,
		"backup_destination": `SELECT EXISTS(SELECT 1 FROM backup_destinations WHERE id=$1 AND organization_id=$2)`,
		"source_credential":  `SELECT EXISTS(SELECT 1 FROM source_credentials WHERE id=$1 AND organization_id=$2)`,
		"notification":       `SELECT EXISTS(SELECT 1 FROM notification_endpoints WHERE id=$1 AND organization_id=$2)`,
		"tag":                `SELECT EXISTS(SELECT 1 FROM tags WHERE id=$1 AND organization_id=$2)`,
		"network":            `SELECT EXISTS(SELECT 1 FROM managed_networks WHERE id=$1 AND organization_id=$2)`,
	}
	query := queries[resource.SourceKind]
	if query == "" {
		return fmt.Sprintf("unsupported parity resource kind %q", resource.SourceKind), nil
	}
	var exists bool
	if err := destination.Pool.QueryRow(ctx, query, id, organizationID).Scan(&exists); err != nil {
		return "", err
	}
	if !exists {
		return "target resource is missing", nil
	}
	return "", nil
}

func verifyDokployDatabaseBackup(ctx context.Context, destination *store.Store, organizationID, policyID uuid.UUID, importedAt time.Time, requireOperational bool) (string, error) {
	var enabled bool
	var databaseID uuid.UUID
	var destinationID *uuid.UUID
	err := destination.Pool.QueryRow(ctx, `SELECT policy.enabled,policy.database_instance_id,policy.destination_id
		FROM backup_policies policy
		JOIN database_instances database ON database.id=policy.database_instance_id
		JOIN environments environment ON environment.id=database.environment_id
		JOIN projects project ON project.id=environment.project_id
		WHERE policy.id=$1 AND project.organization_id=$2`, policyID, organizationID).Scan(&enabled, &databaseID, &destinationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "target database backup policy is missing", nil
	}
	if err != nil {
		return "", err
	}
	if !requireOperational || !enabled {
		return "", nil
	}
	if destinationID == nil {
		return "enabled target database backup policy has no remote destination", nil
	}
	var backedUp bool
	err = destination.Pool.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM database_backups backup
		WHERE backup.database_instance_id=$1
		  AND backup.destination_id=$2
		  AND backup.artifact_valid
		  AND backup.finished_at >= $3
	)`, databaseID, *destinationID, importedAt).Scan(&backedUp)
	if err != nil {
		return "", err
	}
	if !backedUp {
		return "enabled target database backup policy has no successful encrypted backup since import", nil
	}
	return "", nil
}

func verifyDokployVolumeBackup(ctx context.Context, destination *store.Store, organizationID, policyID uuid.UUID, importedAt time.Time, requireOperational bool) (string, error) {
	var enabled bool
	var storageNodeID string
	err := destination.Pool.QueryRow(ctx, `SELECT policy.enabled,service.storage_node_id
		FROM volume_backup_policies policy
		JOIN compose_services service ON service.id=policy.compose_service_id
		JOIN environments environment ON environment.id=service.environment_id
		JOIN projects project ON project.id=environment.project_id
		WHERE policy.id=$1 AND project.organization_id=$2`, policyID, organizationID).Scan(&enabled, &storageNodeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "target volume backup policy is missing", nil
	}
	if err != nil {
		return "", err
	}
	if !requireOperational || !enabled {
		return "", nil
	}
	if storageNodeID == "" {
		return "enabled target volume backup policy has no storage-node binding", nil
	}
	var backedUp bool
	err = destination.Pool.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM volume_backups backup
		WHERE backup.volume_backup_policy_id=$1
		  AND backup.storage_node_id=$2
		  AND backup.artifact_valid
		  AND backup.finished_at >= $3
	)`, policyID, storageNodeID, importedAt).Scan(&backedUp)
	if err != nil {
		return "", err
	}
	if !backedUp {
		return "enabled target volume backup policy has no successful encrypted backup since import", nil
	}
	return "", nil
}

func verifyDokployServiceRuntime(ctx context.Context, destination *store.Store, organizationID, serviceID uuid.UUID) (string, error) {
	var deployed bool
	var reconciliationState string
	var recentlyChecked bool
	err := destination.Pool.QueryRow(ctx, `SELECT
		EXISTS(SELECT 1 FROM deployments d WHERE d.compose_service_id=s.id AND d.revision=s.revision AND d.status='succeeded'),
		COALESCE(r.state,''),
		COALESCE(r.last_checked_at >= now()-interval '5 minutes',false)
		FROM compose_services s
		JOIN environments e ON e.id=s.environment_id
		JOIN projects p ON p.id=e.project_id
		LEFT JOIN service_reconciliations r ON r.compose_service_id=s.id
		WHERE s.id=$1 AND p.organization_id=$2`, serviceID, organizationID).Scan(&deployed, &reconciliationState, &recentlyChecked)
	if errors.Is(err, pgx.ErrNoRows) {
		return "target service is missing", nil
	}
	if err != nil {
		return "", err
	}
	if !deployed {
		return "target service has no successful deployment of its current revision", nil
	}
	if reconciliationState == "" {
		return "target service has no Swarm reconciliation observation", nil
	}
	if reconciliationState != "healthy" {
		return fmt.Sprintf("target service Swarm reconciliation is %s", reconciliationState), nil
	}
	if !recentlyChecked {
		return "target service Swarm reconciliation is stale", nil
	}
	return "", nil
}
