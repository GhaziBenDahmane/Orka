package main

import (
	"fmt"
	"time"

	"github.com/bendahma/dokploy-go/internal/store"
)

const maxDeterministicAuditFindings = 100

func deterministicAuditFindings(snapshot store.AIAuditSnapshot, now time.Time) []modelFinding {
	findings := make([]modelFinding, 0)
	truncated := false
	add := func(finding modelFinding) {
		if len(findings) < maxDeterministicAuditFindings {
			findings = append(findings, finding)
		} else {
			truncated = true
		}
	}
	if snapshot.IdentityPosture.ActiveOwners == 0 {
		add(modelFinding{Severity: "critical", Category: "identity", Title: "Organization has no active owner", Description: "No active owner can perform break-glass administration or recover organization policy.", ResourceType: "organization", ResourceID: snapshot.Organization.String(), Evidence: map[string]any{"activeOwners": 0}, Remediation: "Restore or provision an active owner through the documented recovery procedure."})
	}
	if !snapshot.IdentityPosture.RequireSSO {
		add(modelFinding{Severity: "medium", Category: "identity", Title: "Mandatory SSO is disabled", Description: "Non-owner users can continue using local authentication instead of the configured workforce identity boundary.", ResourceType: "organization", ResourceID: snapshot.Organization.String(), Evidence: map[string]any{"requireSso": false}, Remediation: "Complete provider and break-glass testing, then enable mandatory SSO."})
	}
	for _, migration := range snapshot.MigrationPosture {
		if migration.Unresolved > 0 {
			add(modelFinding{Severity: "high", Category: "migration", Title: "Dokploy migration has unresolved resources", Description: "The persisted parity manifest contains resources that were not imported and still require explicit conversion or acknowledgement.", ResourceType: "dokploy_migration", ResourceID: migration.SourceOrganizationID, Evidence: map[string]any{"resources": migration.Resources, "imported": migration.Imported, "unresolved": migration.Unresolved}, Remediation: "Resolve each migration blocker and rerun verify-dokploy-import without blanket bypasses."})
		}
		if migration.SuccessfulDatabaseTransfers < migration.Databases {
			add(modelFinding{Severity: "high", Category: "migration", Title: "Dokploy database transfers are incomplete", Description: "Not every imported managed database has a successful native data transfer newer than its parity record.", ResourceType: "dokploy_migration", ResourceID: migration.SourceOrganizationID, Evidence: map[string]any{"databases": migration.Databases, "successfulTransfers": migration.SuccessfulDatabaseTransfers}, Remediation: "Quiesce source writes, queue the missing native transfers, and rerun operational migration verification."})
		}
	}
	for _, backup := range snapshot.BackupPosture {
		resourceID := backup.DatabaseID.String()
		if !backup.PolicyConfigured {
			add(modelFinding{Severity: "high", Category: "backup", Title: "Database has no backup policy", Description: "The managed database has no scheduled recovery policy.", ResourceType: "database", ResourceID: resourceID, Evidence: map[string]any{"engine": backup.Engine, "status": backup.Status}, Remediation: "Configure and enable a retained backup policy to durable storage."})
			continue
		}
		if !backup.PolicyEnabled {
			add(modelFinding{Severity: "high", Category: "backup", Title: "Database backup policy is disabled", Description: "A backup policy exists but is not scheduling backups.", ResourceType: "database", ResourceID: resourceID, Evidence: map[string]any{"engine": backup.Engine, "intervalSeconds": backup.IntervalSeconds}, Remediation: "Enable the policy after confirming its destination and retention settings."})
		}
		if backup.LastBackupStatus != "succeeded" {
			add(modelFinding{Severity: "high", Category: "backup", Title: "Database lacks a successful backup", Description: "No latest successful backup is visible for this managed database.", ResourceType: "database", ResourceID: resourceID, Evidence: map[string]any{"engine": backup.Engine, "lastBackupStatus": backup.LastBackupStatus}, Remediation: "Run a backup, resolve any failure, and verify the resulting artifact checksum."})
		}
		if !backup.VerifyRestore {
			add(modelFinding{Severity: "medium", Category: "backup", Title: "Automated restore verification is disabled", Description: "Backups are not automatically exercised through isolated restore drills.", ResourceType: "database", ResourceID: resourceID, Evidence: map[string]any{"engine": backup.Engine}, Remediation: "Enable restore verification and investigate any failed drill before relying on the backup."})
		} else if backup.LastRestoreDrillStatus != "succeeded" {
			add(modelFinding{Severity: "high", Category: "backup", Title: "Database lacks a successful restore drill", Description: "Restore verification is enabled, but no latest successful drill is visible.", ResourceType: "database", ResourceID: resourceID, Evidence: map[string]any{"engine": backup.Engine, "lastRestoreDrillStatus": backup.LastRestoreDrillStatus}, Remediation: "Run an isolated restore drill and validate application-level data."})
		}
	}
	for _, cluster := range snapshot.Clusters {
		if cluster.State != "active" && cluster.State != "draining" {
			continue
		}
		if cluster.LastSeenAt == nil || now.Sub(*cluster.LastSeenAt) > 2*time.Minute {
			lastSeen := ""
			if cluster.LastSeenAt != nil {
				lastSeen = cluster.LastSeenAt.UTC().Format(time.RFC3339)
			}
			add(modelFinding{Severity: "high", Category: "cluster", Title: "Remote cluster heartbeat is stale", Description: "The active or draining cluster has not reported inside the two-minute scheduling window.", ResourceType: "cluster", ResourceID: cluster.ID.String(), Evidence: map[string]any{"state": cluster.State, "lastSeenAt": lastSeen}, Remediation: "Restore agent connectivity and certificate validity before scheduling or mutating workloads."})
		}
		if cluster.CertificateNotAfter != nil && cluster.CertificateNotAfter.Before(now.Add(7*24*time.Hour)) {
			add(modelFinding{Severity: "high", Category: "cluster", Title: "Remote cluster certificate expires soon", Description: "The active agent certificate expires in less than seven days or is already expired.", ResourceType: "cluster", ResourceID: cluster.ID.String(), Evidence: map[string]any{"certificateNotAfter": cluster.CertificateNotAfter.UTC().Format(time.RFC3339)}, Remediation: "Complete two-phase agent certificate rotation and confirm the replacement heartbeat."})
		}
	}
	for _, upgrade := range snapshot.AgentUpgradePosture {
		if upgrade.VerificationOverdue || upgrade.Status == "failed" {
			add(modelFinding{Severity: "high", Category: "cluster", Title: "Remote agent upgrade requires intervention", Description: "The latest agent upgrade failed or did not confirm its immutable target before the verification deadline.", ResourceType: "cluster", ResourceID: upgrade.ClusterID.String(), Evidence: map[string]any{"status": upgrade.Status, "verificationOverdue": upgrade.VerificationOverdue, "targetImage": upgrade.TargetImage}, Remediation: "Inspect Swarm update state and agent logs, then retry only with a verified digest."})
		}
	}
	for _, repository := range snapshot.TemplateRepositories {
		if repository.Enabled && !repository.RequireSignature {
			add(modelFinding{Severity: "medium", Category: "supply_chain", Title: "Template repository does not require signatures", Description: "An enabled remote catalog can update deployable Compose definitions without signer verification.", ResourceType: "template_repository", ResourceID: repository.ID.String(), Evidence: map[string]any{"gitRef": repository.GitRef}, Remediation: "Pin an Ed25519 catalog signer and require signature verification."})
		}
		if repository.Enabled && repository.LastSyncStatus == "failed" {
			add(modelFinding{Severity: "high", Category: "supply_chain", Title: "Template repository synchronization failed", Description: "The latest refresh of an enabled template repository failed.", ResourceType: "template_repository", ResourceID: repository.ID.String(), Evidence: map[string]any{"lastSyncStatus": repository.LastSyncStatus}, Remediation: "Inspect the repository credential, ref, signature, and archive validation error before retrying."})
		}
	}
	for _, deployment := range snapshot.ServiceDeployments {
		if !deployment.CurrentRevisionDeployed {
			add(modelFinding{Severity: "medium", Category: "deployment", Title: "Desired service revision is not deployed", Description: "The service's current desired revision has no successful deployment.", ResourceType: "service", ResourceID: deployment.ServiceID.String(), Evidence: map[string]any{"desiredRevision": deployment.DesiredRevision, "latestDeploymentRevision": deployment.LatestDeploymentRevision, "latestDeploymentStatus": deployment.LatestDeploymentStatus}, Remediation: "Review the pending change and deploy it, or restore the intended revision."})
		}
	}
	for _, reconciliation := range snapshot.Reconciliation {
		if reconciliation.State != "healthy" {
			add(modelFinding{Severity: "high", Category: "availability", Title: "Swarm service reconciliation is unhealthy", Description: "The latest observed runtime state does not match a healthy service.", ResourceType: "service", ResourceID: reconciliation.ComposeServiceID.String(), Evidence: map[string]any{"state": reconciliation.State, "consecutiveFailures": reconciliation.ConsecutiveFailures}, Remediation: "Inspect the current deployment, Swarm tasks, placement capacity, and automatic repair history."})
		} else if now.Sub(reconciliation.LastCheckedAt) > 5*time.Minute {
			add(modelFinding{Severity: "medium", Category: "availability", Title: "Swarm service reconciliation is stale", Description: "The service has no fresh runtime observation from the last five minutes.", ResourceType: "service", ResourceID: reconciliation.ComposeServiceID.String(), Evidence: map[string]any{"lastCheckedAt": reconciliation.LastCheckedAt.UTC().Format(time.RFC3339)}, Remediation: "Restore controller reconciliation and verify the service on its assigned cluster."})
		}
	}
	if truncated {
		findings[maxDeterministicAuditFindings-1] = modelFinding{Severity: "high", Category: "audit", Title: "Deterministic audit findings were truncated", Description: fmt.Sprintf("The baseline audit reached its %d-finding safety limit.", maxDeterministicAuditFindings), ResourceType: "organization", ResourceID: snapshot.Organization.String(), Evidence: map[string]any{"limit": maxDeterministicAuditFindings}, Remediation: "Resolve existing findings and rerun the audit to reveal any remaining issues."}
	}
	return findings
}
