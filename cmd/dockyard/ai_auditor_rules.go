package main

import (
	"fmt"
	"sort"
	"time"

	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

const maxDeterministicAuditFindings = 100

const auditArchiveSchedulerGrace = 5 * time.Minute

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
	if snapshot.IdentityPosture.PendingSAMLCertificateRotations > 0 && snapshot.IdentityPosture.OldestPendingSAMLRotationAt != nil && now.Sub(*snapshot.IdentityPosture.OldestPendingSAMLRotationAt) > 7*24*time.Hour {
		add(modelFinding{Severity: "medium", Category: "identity", Title: "SAML certificate rotation is stalled", Description: "A replacement service-provider signing certificate has remained published without promotion or cancellation for more than seven days.", ResourceType: "organization", ResourceID: snapshot.Organization.String(), Evidence: map[string]any{"pendingRotations": snapshot.IdentityPosture.PendingSAMLCertificateRotations, "oldestPendingAt": snapshot.IdentityPosture.OldestPendingSAMLRotationAt.UTC().Format(time.RFC3339)}, Remediation: "Confirm the IdP imported the replacement certificate and promote it, or cancel the pending rotation."})
	}
	for _, provider := range snapshot.SAMLPosture {
		if !provider.CertificateConfigurationOK {
			evidence := map[string]any{}
			if provider.SPCertificateNotAfter != nil {
				evidence["spCertificateNotAfter"] = provider.SPCertificateNotAfter.UTC().Format(time.RFC3339)
			}
			if provider.IDPCertificateNotAfter != nil {
				evidence["idpCertificateNotAfter"] = provider.IDPCertificateNotAfter.UTC().Format(time.RFC3339)
			}
			add(modelFinding{Severity: "high", Category: "identity", Title: "SAML certificate configuration is invalid", Description: "An enabled SAML provider has an invalid, expired, or unusable service-provider or identity-provider trust certificate.", ResourceType: "saml_provider", ResourceID: provider.ID.String(), Evidence: evidence, Remediation: "Refresh IdP metadata and rotate the service-provider signing certificate, then validate both trust chains before relying on SSO."})
			continue
		}
		for _, certificate := range []struct {
			kind      string
			expiresAt *time.Time
		}{
			{kind: "service_provider", expiresAt: provider.SPCertificateNotAfter},
			{kind: "identity_provider", expiresAt: provider.IDPCertificateNotAfter},
		} {
			if certificate.expiresAt != nil && certificate.expiresAt.Before(now.Add(30*24*time.Hour)) {
				add(modelFinding{Severity: "medium", Category: "identity", Title: "SAML trust certificate expires soon", Description: "An enabled SAML trust certificate expires in less than thirty days.", ResourceType: "saml_provider", ResourceID: provider.ID.String(), Evidence: map[string]any{"kind": certificate.kind, "certificateNotAfter": certificate.expiresAt.UTC().Format(time.RFC3339)}, Remediation: "Complete the documented certificate or IdP metadata rotation before the trust boundary expires."})
			}
		}
	}
	if snapshot.IdentityPosture.ExpiringServiceAccounts > 0 {
		add(modelFinding{Severity: "medium", Category: "identity", Title: "Service account credentials expire soon", Description: "One or more active service accounts have credentials expiring within seven days.", ResourceType: "organization", ResourceID: snapshot.Organization.String(), Evidence: map[string]any{"expiringServiceAccounts7d": snapshot.IdentityPosture.ExpiringServiceAccounts}, Remediation: "Rotate each expiring service-account token and verify its consumer before revoking the old credential."})
	}
	if snapshot.IdentityPosture.ActiveSCIMTokens > 0 && snapshot.IdentityPosture.OldestActiveSCIMTokenCreatedAt != nil && now.Sub(*snapshot.IdentityPosture.OldestActiveSCIMTokenCreatedAt) > 180*24*time.Hour {
		add(modelFinding{Severity: "medium", Category: "identity", Title: "Long-lived SCIM credential requires rotation", Description: "The oldest active SCIM token is more than 180 days old.", ResourceType: "organization", ResourceID: snapshot.Organization.String(), Evidence: map[string]any{"activeScimTokens": snapshot.IdentityPosture.ActiveSCIMTokens, "oldestCreatedAt": snapshot.IdentityPosture.OldestActiveSCIMTokenCreatedAt.UTC().Format(time.RFC3339)}, Remediation: "Issue a replacement SCIM token, update the identity provider, verify synchronization, and revoke the old token."})
	}
	if snapshot.AuditLogPosture.RetentionDays > 0 {
		if snapshot.AuditLogPosture.EnabledArchives == 0 {
			add(modelFinding{Severity: "medium", Category: "audit", Title: "Immutable audit archive is not enabled", Description: "Audit events exist only in the mutable control-plane database and its configured retention window.", ResourceType: "organization", ResourceID: snapshot.Organization.String(), Evidence: map[string]any{"retentionDays": snapshot.AuditLogPosture.RetentionDays, "disabledArchives": snapshot.AuditLogPosture.DisabledArchives}, Remediation: "Configure and verify an enabled TLS S3 destination with Object Lock COMPLIANCE retention."})
		}
		for _, archive := range snapshot.AuditLogPosture.Destinations {
			if !archive.Enabled {
				continue
			}
			if archive.LatestBatchStatus == "failed" {
				evidence := map[string]any{"latestBatchStatus": archive.LatestBatchStatus, "retentionDays": archive.RetentionDays}
				if archive.LatestBatchFinishedAt != nil {
					evidence["latestBatchFinishedAt"] = archive.LatestBatchFinishedAt.UTC().Format(time.RFC3339)
				}
				add(modelFinding{Severity: "high", Category: "audit", Title: "Immutable audit archive delivery failed", Description: "The latest batch for an enabled immutable archive did not complete successfully.", ResourceType: "audit_archive", ResourceID: archive.ID.String(), Evidence: evidence, Remediation: "Inspect the archive worker and destination, retry the failed batch, and verify the resulting immutable object and chain checkpoint."})
			}
			if archive.UnarchivedEvents > 0 && archive.OldestUnarchivedAt != nil && now.Sub(*archive.OldestUnarchivedAt) > auditArchiveSchedulerGrace {
				add(modelFinding{Severity: "high", Category: "audit", Title: "Immutable audit archive is behind", Description: "Tenant audit events have remained outside this enabled immutable archive beyond the scheduler grace window.", ResourceType: "audit_archive", ResourceID: archive.ID.String(), Evidence: map[string]any{"unarchivedEvents": archive.UnarchivedEvents, "oldestUnarchivedAt": archive.OldestUnarchivedAt.UTC().Format(time.RFC3339), "maximumLagSeconds": int64(auditArchiveSchedulerGrace / time.Second), "lastArchivedId": archive.LastArchivedID, "currentMaxEventId": snapshot.AuditLogPosture.CurrentMaxEventID}, Remediation: "Restore archive scheduling and delivery, then confirm the destination checkpoint catches up to the tenant audit log."})
			}
		}
	}
	for _, route := range snapshot.Routes {
		if !route.TLS {
			add(modelFinding{Severity: "medium", Category: "network", Title: "Public route permits plaintext HTTP", Description: "A Traefik ingress route accepts traffic without transport encryption.", ResourceType: "route", ResourceID: route.ID.String(), Evidence: map[string]any{"serviceId": route.ComposeServiceID.String(), "host": route.Host, "pathPrefix": route.PathPrefix, "targetPort": route.TargetPort}, Remediation: "Enable TLS with a configured certificate resolver, redeploy the service, and redirect or retire the plaintext endpoint."})
		}
	}
	databaseEngines := make(map[string]store.AIAuditDatabaseEngineInfo, len(snapshot.DatabaseEngines))
	unusableDatabaseDrivers := make(map[uuid.UUID]bool)
	for _, engine := range snapshot.DatabaseEngines {
		databaseEngines[engine.Name] = engine
	}
	if len(databaseEngines) > 0 {
		for _, managedDatabase := range snapshot.Databases {
			engine, registered := databaseEngines[managedDatabase.Engine]
			if !registered {
				unusableDatabaseDrivers[managedDatabase.ID] = true
				add(modelFinding{Severity: "high", Category: "backup", Title: "Database engine is unavailable", Description: "A managed database references an engine that is no longer registered with the controller.", ResourceType: "database", ResourceID: managedDatabase.ID.String(), Evidence: map[string]any{"engine": managedDatabase.Engine, "version": managedDatabase.Version}, Remediation: "Restore the exact trusted driver used by this database before attempting deployment, backup, restore, or migration operations."})
			} else if managedDatabase.DriverSource == "" || managedDatabase.DriverSource == "unbound" {
				unusableDatabaseDrivers[managedDatabase.ID] = true
				add(modelFinding{Severity: "high", Category: "supply_chain", Title: "Database driver identity is unbound", Description: "A legacy managed database has not yet been bound to the exact driver implementation allowed to operate on it.", ResourceType: "database", ResourceID: managedDatabase.ID.String(), Evidence: map[string]any{"engine": managedDatabase.Engine, "version": managedDatabase.Version}, Remediation: "Run a controlled backup or migration with the intended driver on one controller to bind its identity, then verify every worker has the same artifact."})
			} else if managedDatabase.DriverSource != engine.Source || managedDatabase.DriverDigest != engine.ArtifactDigest {
				unusableDatabaseDrivers[managedDatabase.ID] = true
				add(modelFinding{Severity: "high", Category: "supply_chain", Title: "Database driver identity mismatch", Description: "The controller's registered driver does not match the implementation bound to this managed database.", ResourceType: "database", ResourceID: managedDatabase.ID.String(), Evidence: map[string]any{"engine": managedDatabase.Engine, "expectedSource": managedDatabase.DriverSource, "expectedDigest": managedDatabase.DriverDigest, "actualSource": engine.Source, "actualDigest": engine.ArtifactDigest}, Remediation: "Deploy the bound driver artifact consistently across controllers or perform an explicitly reviewed driver migration."})
			} else if !engine.BackupCapable {
				unusableDatabaseDrivers[managedDatabase.ID] = true
				add(modelFinding{Severity: "high", Category: "backup", Title: "Database engine has no recovery support", Description: "The registered driver cannot produce verified native backup and restore plans for this managed database.", ResourceType: "database", ResourceID: managedDatabase.ID.String(), Evidence: map[string]any{"engine": engine.Name, "version": managedDatabase.Version, "driverSource": engine.Source, "driverDigest": engine.ArtifactDigest}, Remediation: "Install a trusted backup-capable driver or migrate this database to an engine with verified recovery support."})
			}
		}
	}
	for _, migration := range snapshot.MigrationPosture {
		if migration.Unresolved > 0 {
			add(modelFinding{Severity: "high", Category: "migration", Title: "Dokploy migration has unresolved resources", Description: "The persisted parity manifest contains resources that were not imported and still require explicit conversion or acknowledgement.", ResourceType: "dokploy_migration", ResourceID: migration.SourceOrganizationID, Evidence: map[string]any{"resources": migration.Resources, "imported": migration.Imported, "unresolved": migration.Unresolved}, Remediation: "Resolve each migration blocker and rerun verify-dokploy-import without blanket bypasses."})
		}
		if migration.SuccessfulDatabaseTransfers < migration.Databases {
			add(modelFinding{Severity: "high", Category: "migration", Title: "Dokploy database transfers are incomplete", Description: "Not every imported managed database has a successful native data transfer newer than its parity record.", ResourceType: "dokploy_migration", ResourceID: migration.SourceOrganizationID, Evidence: map[string]any{"databases": migration.Databases, "successfulTransfers": migration.SuccessfulDatabaseTransfers}, Remediation: "Quiesce source writes, queue the missing native transfers, and rerun operational migration verification."})
		}
	}
	for _, policy := range snapshot.ResourcePolicies {
		if policy.Maintenance {
			add(modelFinding{Severity: "low", Category: "policy", Title: "Maintenance mode is active", Description: "A resource scope is intentionally blocking deployment and mutation operations.", ResourceType: policy.ScopeType, ResourceID: policy.ScopeID.String(), Evidence: map[string]any{"scopeType": policy.ScopeType, "updatedAt": policy.UpdatedAt.UTC().Format(time.RFC3339)}, Remediation: "Confirm the maintenance window is still required and disable it when the planned work is complete."})
		}
		for _, quota := range []struct {
			name    string
			current int
			limit   *int
		}{
			{name: "projects", current: policy.CurrentProjects, limit: policy.MaxProjects},
			{name: "environments", current: policy.CurrentEnvironments, limit: policy.MaxEnvironments},
			{name: "services", current: policy.CurrentServices, limit: policy.MaxServices},
			{name: "databases", current: policy.CurrentDatabases, limit: policy.MaxDatabases},
		} {
			if quota.limit == nil || quota.current*10 < *quota.limit*9 {
				continue
			}
			severity, title := "medium", "Resource quota is nearly exhausted"
			if quota.current >= *quota.limit {
				severity, title = "high", "Resource quota is exhausted"
			}
			add(modelFinding{Severity: severity, Category: "capacity", Title: title, Description: "A configured resource quota has little or no remaining capacity.", ResourceType: policy.ScopeType, ResourceID: policy.ScopeID.String(), Evidence: map[string]any{"scopeType": policy.ScopeType, "resource": quota.name, "used": quota.current, "limit": *quota.limit}, Remediation: "Review inactive resources and expected growth, then remove unused capacity or adjust the policy deliberately."})
		}
	}
	for _, backup := range snapshot.BackupPosture {
		resourceID := backup.DatabaseID.String()
		if len(databaseEngines) > 0 && unusableDatabaseDrivers[backup.DatabaseID] {
			continue
		}
		if !backup.PolicyConfigured {
			add(modelFinding{Severity: "high", Category: "backup", Title: "Database has no backup policy", Description: "The managed database has no scheduled recovery policy.", ResourceType: "database", ResourceID: resourceID, Evidence: map[string]any{"engine": backup.Engine, "status": backup.Status}, Remediation: "Configure and enable a retained backup policy to durable storage."})
			continue
		}
		if !backup.PolicyEnabled {
			add(modelFinding{Severity: "high", Category: "backup", Title: "Database backup policy is disabled", Description: "A backup policy exists but is not scheduling backups.", ResourceType: "database", ResourceID: resourceID, Evidence: map[string]any{"engine": backup.Engine, "intervalSeconds": backup.IntervalSeconds}, Remediation: "Enable the policy after confirming its destination and retention settings."})
		}
		if backup.LastBackupStatus != "succeeded" {
			add(modelFinding{Severity: "high", Category: "backup", Title: "Database lacks a successful backup", Description: "No latest successful backup is visible for this managed database.", ResourceType: "database", ResourceID: resourceID, Evidence: map[string]any{"engine": backup.Engine, "lastBackupStatus": backup.LastBackupStatus}, Remediation: "Run a backup, resolve any failure, and verify the resulting artifact checksum."})
		} else if recoveryEvidenceOverdue(now, backup.LastBackupAt, backup.IntervalSeconds, 30*time.Minute) {
			add(modelFinding{Severity: "high", Category: "backup", Title: "Database backup is overdue", Description: "The latest successful database backup is older than twice the configured interval.", ResourceType: "database", ResourceID: resourceID, Evidence: recoveryAgeEvidence(now, backup.LastBackupAt, backup.IntervalSeconds, 30*time.Minute), Remediation: "Inspect the backup scheduler and destination, then complete a fresh verified backup."})
		}
		if !backup.VerifyRestore {
			add(modelFinding{Severity: "medium", Category: "backup", Title: "Automated restore verification is disabled", Description: "Backups are not automatically exercised through isolated restore drills.", ResourceType: "database", ResourceID: resourceID, Evidence: map[string]any{"engine": backup.Engine}, Remediation: "Enable restore verification and investigate any failed drill before relying on the backup."})
		} else if backup.LastRestoreDrillStatus != "succeeded" {
			add(modelFinding{Severity: "high", Category: "backup", Title: "Database lacks a successful restore drill", Description: "Restore verification is enabled, but no latest successful drill is visible.", ResourceType: "database", ResourceID: resourceID, Evidence: map[string]any{"engine": backup.Engine, "lastRestoreDrillStatus": backup.LastRestoreDrillStatus}, Remediation: "Run an isolated restore drill and validate application-level data."})
		} else if backup.PolicyEnabled && recoveryEvidenceOverdue(now, backup.LastRestoreDrillAt, backup.IntervalSeconds, 24*time.Hour) {
			add(modelFinding{Severity: "high", Category: "backup", Title: "Database restore drill is overdue", Description: "The latest successful isolated restore drill is older than twice the configured backup interval, with a minimum one-day window.", ResourceType: "database", ResourceID: resourceID, Evidence: recoveryAgeEvidence(now, backup.LastRestoreDrillAt, backup.IntervalSeconds, 24*time.Hour), Remediation: "Run an isolated restore drill and validate application-level data before relying on recent backups."})
		}
	}
	for _, backup := range snapshot.VolumeBackupPosture {
		resourceID := backup.ServiceID.String()
		if !backup.PolicyEnabled {
			add(modelFinding{Severity: "high", Category: "backup", Title: "Volume backup policy is disabled", Description: "A named-volume backup policy exists but is not scheduling backups.", ResourceType: "service", ResourceID: resourceID, Evidence: map[string]any{"volumeName": backup.VolumeName, "intervalSeconds": backup.IntervalSeconds}, Remediation: "Enable the policy after confirming its destination and retention settings."})
		}
		if backup.StorageNodeID == "" {
			add(modelFinding{Severity: "high", Category: "backup", Title: "Protected volume has no storage-node binding", Description: "A named-volume backup policy exists, but its service has not been pinned to a Swarm storage node.", ResourceType: "service", ResourceID: resourceID, Evidence: map[string]any{"volumeName": backup.VolumeName}, Remediation: "Deploy the service so Orka can bind and pin its node-local volume before the first backup."})
		}
		if backup.LastBackupStatus != "succeeded" {
			add(modelFinding{Severity: "high", Category: "backup", Title: "Volume lacks a successful backup", Description: "No latest successful encrypted backup is visible for a protected named volume.", ResourceType: "service", ResourceID: resourceID, Evidence: map[string]any{"volumeName": backup.VolumeName, "lastBackupStatus": backup.LastBackupStatus}, Remediation: "Run a volume backup, resolve any failure, and verify the resulting artifact checksum."})
		} else if backup.PolicyEnabled && recoveryEvidenceOverdue(now, backup.LastBackupAt, backup.IntervalSeconds, 30*time.Minute) {
			evidence := recoveryAgeEvidence(now, backup.LastBackupAt, backup.IntervalSeconds, 30*time.Minute)
			evidence["volumeName"] = backup.VolumeName
			add(modelFinding{Severity: "high", Category: "backup", Title: "Volume backup is overdue", Description: "The latest successful named-volume backup is older than twice the configured interval.", ResourceType: "service", ResourceID: resourceID, Evidence: evidence, Remediation: "Inspect the backup scheduler and destination, then complete a fresh encrypted volume backup."})
		}
		if !backup.Quiesce {
			add(modelFinding{Severity: "medium", Category: "backup", Title: "Volume backups do not pause writers", Description: "The backup policy allows services to keep writing while the volume archive is created.", ResourceType: "service", ResourceID: resourceID, Evidence: map[string]any{"volumeName": backup.VolumeName}, Remediation: "Enable quiescence or document and validate the application's crash-consistent backup guarantees."})
		}
		if backup.LastRestoreStatus != "succeeded" {
			add(modelFinding{Severity: "medium", Category: "backup", Title: "Volume restore has not been validated", Description: "No latest successful restore is visible for a protected named volume.", ResourceType: "service", ResourceID: resourceID, Evidence: map[string]any{"volumeName": backup.VolumeName, "lastRestoreStatus": backup.LastRestoreStatus}, Remediation: "Perform a controlled restore rehearsal and validate application-level data before relying on the backup."})
		} else if backup.PolicyEnabled && recoveryEvidenceOverdue(now, backup.LastRestoreAt, backup.IntervalSeconds, 24*time.Hour) {
			evidence := recoveryAgeEvidence(now, backup.LastRestoreAt, backup.IntervalSeconds, 24*time.Hour)
			evidence["volumeName"] = backup.VolumeName
			add(modelFinding{Severity: "medium", Category: "backup", Title: "Volume restore validation is overdue", Description: "The latest successful named-volume restore validation is older than twice the configured backup interval, with a minimum one-day window.", ResourceType: "service", ResourceID: resourceID, Evidence: evidence, Remediation: "Perform a controlled restore rehearsal and validate application-level data before relying on current backups."})
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
		if snapshot.AgentCAPosture.Configured && cluster.CertificateAuthorityFingerprint != snapshot.AgentCAPosture.ActiveFingerprint {
			add(modelFinding{Severity: "high", Category: "cluster", Title: "Remote cluster uses a non-active certificate authority", Description: "The cluster's authenticated client identity does not match the controller's active signing CA.", ResourceType: "cluster", ResourceID: cluster.ID.String(), Evidence: map[string]any{"clusterFingerprint": cluster.CertificateAuthorityFingerprint, "pendingFingerprint": cluster.PendingCertificateAuthorityFingerprint, "activeFingerprint": snapshot.AgentCAPosture.ActiveFingerprint}, Remediation: "Keep dual trust enabled, restore a fresh heartbeat, and wait for automatic identity rotation before retiring the previous CA."})
		}
	}
	if snapshot.AgentCAPosture.RolloverActive {
		add(modelFinding{Severity: "medium", Category: "cluster", Title: "Previous agent certificate authority remains trusted", Description: "The controller is still accepting identities issued by the previous agent CA.", ResourceType: "organization", ResourceID: snapshot.Organization.String(), Evidence: map[string]any{"activeFingerprint": snapshot.AgentCAPosture.ActiveFingerprint, "previousFingerprint": snapshot.AgentCAPosture.PreviousFingerprint}, Remediation: "Complete the agent CA rotation runbook, verify every managed cluster fingerprint, and remove the previous-CA overlay."})
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
		if repository.Enabled && repository.LastSyncStatus != "failed" && repository.LastSyncedAt == nil {
			add(modelFinding{Severity: "medium", Category: "supply_chain", Title: "Template repository has never synchronized", Description: "An enabled remote catalog has no successful synchronization record.", ResourceType: "template_repository", ResourceID: repository.ID.String(), Evidence: map[string]any{"gitRef": repository.GitRef, "syncIntervalSeconds": repository.SyncIntervalSeconds}, Remediation: "Run a catalog synchronization and verify its signature and imported template inventory."})
		} else if repository.Enabled && repository.LastSyncStatus != "failed" && repository.SyncIntervalSeconds > 0 && now.Sub(*repository.LastSyncedAt) > 2*time.Duration(repository.SyncIntervalSeconds)*time.Second+5*time.Minute {
			add(modelFinding{Severity: "medium", Category: "supply_chain", Title: "Template repository synchronization is stale", Description: "An enabled scheduled catalog has not synchronized within two configured intervals plus a five-minute grace period.", ResourceType: "template_repository", ResourceID: repository.ID.String(), Evidence: map[string]any{"gitRef": repository.GitRef, "syncIntervalSeconds": repository.SyncIntervalSeconds, "lastSyncedAt": repository.LastSyncedAt.UTC().Format(time.RFC3339)}, Remediation: "Restore the catalog scheduler or repository access and complete a verified synchronization."})
		}
	}
	if snapshot.QueuePosture.OldestPendingAt != nil && now.Sub(*snapshot.QueuePosture.OldestPendingAt) > 10*time.Minute {
		add(modelFinding{Severity: "high", Category: "operations", Title: "Deployment queue is stalled", Description: "A tenant-scoped service or database job has remained pending for more than ten minutes.", ResourceType: "organization", ResourceID: snapshot.Organization.String(), Evidence: map[string]any{"pendingServiceJobs": snapshot.QueuePosture.PendingServiceJobs, "pendingDatabaseJobs": snapshot.QueuePosture.PendingDatabaseJobs, "oldestPendingAt": snapshot.QueuePosture.OldestPendingAt.UTC().Format(time.RFC3339)}, Remediation: "Check worker health, leader leases, cluster admission, and job retry state before accepting more work."})
	}
	if missing := missingNotificationCoverage(snapshot.NotificationPosture); len(missing) > 0 {
		add(modelFinding{Severity: "medium", Category: "operations", Title: "Failure notifications have coverage gaps", Description: "No enabled notification endpoint subscribes to one or more supported failure events.", ResourceType: "organization", ResourceID: snapshot.Organization.String(), Evidence: map[string]any{"missingEvents": missing}, Remediation: "Enable at least one tested notification destination for every supported failure event."})
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

func recoveryEvidenceOverdue(now time.Time, completedAt *time.Time, intervalSeconds int, minimum time.Duration) bool {
	if completedAt == nil {
		return false
	}
	maximumAge := 2 * time.Duration(intervalSeconds) * time.Second
	if maximumAge < minimum {
		maximumAge = minimum
	}
	return now.Sub(*completedAt) > maximumAge
}

func recoveryAgeEvidence(now time.Time, completedAt *time.Time, intervalSeconds int, minimum time.Duration) map[string]any {
	maximumAge := 2 * time.Duration(intervalSeconds) * time.Second
	if maximumAge < minimum {
		maximumAge = minimum
	}
	return map[string]any{
		"lastSucceededAt":   completedAt.UTC().Format(time.RFC3339),
		"ageSeconds":        int64(now.Sub(*completedAt) / time.Second),
		"maximumAgeSeconds": int64(maximumAge / time.Second),
	}
}

func missingNotificationCoverage(endpoints []store.AIAuditNotificationPosture) []string {
	required := map[string]bool{
		"deployment.failed":         false,
		"backup.failed":             false,
		"restore.failed":            false,
		"restore.drill.failed":      false,
		"database.migration.failed": false,
		"audit.archive.failed":      false,
		"ai.audit.failed":           false,
		"ai.finding.critical":       false,
	}
	for _, endpoint := range endpoints {
		if !endpoint.Enabled {
			continue
		}
		for _, event := range endpoint.Events {
			if _, tracked := required[event]; tracked {
				required[event] = true
			}
		}
	}
	missing := make([]string, 0, len(required))
	for event, covered := range required {
		if !covered {
			missing = append(missing, event)
		}
	}
	sort.Strings(missing)
	return missing
}
