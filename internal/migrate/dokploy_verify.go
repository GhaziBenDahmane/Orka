package migrate

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

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
		return report, errors.New("no persisted Dokploy parity manifest was found; run a non-dry-run import first")
	}
	coreKinds := map[string]bool{}
	for _, resource := range resources {
		coreKinds[resource.SourceKind] = true
	}
	if !coreKinds["project"] || !coreKinds["environment"] {
		return report, errors.New("persisted Dokploy parity manifest predates core-resource tracking; rerun the import")
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
	if resource.SourceKind == "compose" || resource.SourceKind == "application" {
		var exists, deployed bool
		err := destination.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM compose_services s JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE s.id=$1 AND p.organization_id=$2),EXISTS(SELECT 1 FROM deployments d JOIN compose_services s ON s.id=d.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE d.compose_service_id=$1 AND d.revision=s.revision AND d.status='succeeded' AND p.organization_id=$2)`, id, organizationID).Scan(&exists, &deployed)
		if err != nil {
			return "", err
		}
		if !exists {
			return "target service is missing", nil
		}
		if requireOperational && !deployed {
			return "target service has no successful deployment", nil
		}
		return "", nil
	}
	if resource.SourceKind == "database" {
		var status, engine string
		err := destination.Pool.QueryRow(ctx, `SELECT d.status,d.engine FROM database_instances d JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE d.id=$1 AND p.organization_id=$2`, id, organizationID).Scan(&status, &engine)
		if errors.Is(err, pgx.ErrNoRows) {
			return "target database is missing", nil
		}
		if err != nil {
			return "", err
		}
		if requireOperational && status != "running" {
			return "target database is not running", nil
		}
		if requireOperational && migrationBackupCapableEngine(engine) {
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
	queries := map[string]string{
		"project":            `SELECT EXISTS(SELECT 1 FROM projects WHERE id=$1 AND organization_id=$2)`,
		"environment":        `SELECT EXISTS(SELECT 1 FROM environments e JOIN projects p ON p.id=e.project_id WHERE e.id=$1 AND p.organization_id=$2)`,
		"compose_route":      `SELECT EXISTS(SELECT 1 FROM routes r JOIN compose_services s ON s.id=r.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE r.id=$1 AND p.organization_id=$2)`,
		"application_route":  `SELECT EXISTS(SELECT 1 FROM routes r JOIN compose_services s ON s.id=r.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE r.id=$1 AND p.organization_id=$2)`,
		"backup_destination": `SELECT EXISTS(SELECT 1 FROM backup_destinations WHERE id=$1 AND organization_id=$2)`,
		"backup_policy":      `SELECT EXISTS(SELECT 1 FROM backup_policies b JOIN database_instances d ON d.id=b.database_instance_id JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE b.id=$1 AND p.organization_id=$2)`,
		"source_credential":  `SELECT EXISTS(SELECT 1 FROM source_credentials WHERE id=$1 AND organization_id=$2)`,
		"notification":       `SELECT EXISTS(SELECT 1 FROM notification_endpoints WHERE id=$1 AND organization_id=$2)`,
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
