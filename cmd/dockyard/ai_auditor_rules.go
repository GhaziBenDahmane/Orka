package main

import (
	"fmt"
	"sort"
	"time"

	"github.com/bendahma/dokploy-go/internal/ociref"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

const maxDeterministicAuditFindings = 100

const auditArchiveSchedulerGrace = 5 * time.Minute
const minimumOperationalSignalSample = 4
const finalizerStallThreshold = 15 * time.Minute
const jobHeartbeatStallThreshold = 2 * time.Minute
const agentCommandStallThreshold = 2 * time.Minute
const edgeTLSReconciliationStallThreshold = 5 * time.Minute
const managedNetworkProvisioningStallThreshold = 15 * time.Minute

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
	if missing := snapshot.IdentityPosture.PrivilegedLocalMembers - snapshot.IdentityPosture.MFAEnabledPrivilegedLocalMembers; missing > 0 {
		add(modelFinding{Severity: "high", Category: "identity", Title: "Privileged local accounts lack MFA", Description: "One or more active owner or administrator accounts can use a local password without a second factor.", ResourceType: "organization", ResourceID: snapshot.Organization.String(), Evidence: map[string]any{"privilegedLocalMembers": snapshot.IdentityPosture.PrivilegedLocalMembers, "mfaEnabledPrivilegedLocalMembers": snapshot.IdentityPosture.MFAEnabledPrivilegedLocalMembers, "missingMfa": missing}, Remediation: "Enroll TOTP for every privileged local and break-glass account, save recovery codes offline, and validate recovery access."})
	} else if missing := snapshot.IdentityPosture.ActiveLocalMembers - snapshot.IdentityPosture.MFAEnabledLocalMembers; missing > 0 {
		add(modelFinding{Severity: "medium", Category: "identity", Title: "Local accounts lack MFA", Description: "One or more active local-password accounts do not require a second factor.", ResourceType: "organization", ResourceID: snapshot.Organization.String(), Evidence: map[string]any{"activeLocalMembers": snapshot.IdentityPosture.ActiveLocalMembers, "mfaEnabledLocalMembers": snapshot.IdentityPosture.MFAEnabledLocalMembers, "missingMfa": missing}, Remediation: "Enroll TOTP for remaining local accounts or enforce workforce SSO where appropriate."})
	}
	if snapshot.IdentityPosture.RequireSSO && snapshot.IdentityPosture.ActiveMembers > 0 && snapshot.IdentityPosture.EnabledOIDCProviders+snapshot.IdentityPosture.EnabledSAMLProviders == 0 {
		add(modelFinding{Severity: "critical", Category: "identity", Title: "Mandatory SSO has no enabled provider", Description: "Non-owner members are required to use SSO, but the organization has no enabled OIDC or SAML provider.", ResourceType: "organization", ResourceID: snapshot.Organization.String(), Evidence: map[string]any{"requireSso": true, "enabledOidcProviders": 0, "enabledSamlProviders": 0, "activeMembers": snapshot.IdentityPosture.ActiveMembers}, Remediation: "Use owner break-glass access to enable and validate an SSO provider before restoring normal user access."})
	} else if !snapshot.IdentityPosture.RequireSSO {
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
	if snapshot.DeployTokenPosture.ExpiringTokens > 0 {
		add(modelFinding{Severity: "medium", Category: "supply_chain", Title: "Deployment hook credentials expire soon", Description: "One or more active CI deployment-hook credentials expire within seven days.", ResourceType: "organization", ResourceID: snapshot.Organization.String(), Evidence: map[string]any{"activeTokens": snapshot.DeployTokenPosture.ActiveTokens, "expiringTokens7d": snapshot.DeployTokenPosture.ExpiringTokens}, Remediation: "Create a replacement deployment token, update the CI secret, verify a deployment, and revoke the old token."})
	}
	if snapshot.DeployTokenPosture.ExpiredUnrevokedTokens > 0 {
		add(modelFinding{Severity: "low", Category: "supply_chain", Title: "Expired deployment hook credentials remain in inventory", Description: "Expired deployment-hook credentials cannot trigger deployments but remain unrevoked.", ResourceType: "organization", ResourceID: snapshot.Organization.String(), Evidence: map[string]any{"expiredUnrevokedTokens": snapshot.DeployTokenPosture.ExpiredUnrevokedTokens}, Remediation: "Revoke expired deployment tokens after confirming their CI consumers have migrated."})
	}
	if snapshot.IdentityPosture.ActiveSCIMTokens > 0 && snapshot.IdentityPosture.OldestActiveSCIMTokenCreatedAt != nil && now.Sub(*snapshot.IdentityPosture.OldestActiveSCIMTokenCreatedAt) > 180*24*time.Hour {
		add(modelFinding{Severity: "medium", Category: "identity", Title: "Long-lived SCIM credential requires rotation", Description: "The oldest active SCIM token is more than 180 days old.", ResourceType: "organization", ResourceID: snapshot.Organization.String(), Evidence: map[string]any{"activeScimTokens": snapshot.IdentityPosture.ActiveSCIMTokens, "oldestCreatedAt": snapshot.IdentityPosture.OldestActiveSCIMTokenCreatedAt.UTC().Format(time.RFC3339)}, Remediation: "Issue a replacement SCIM token, update the identity provider, verify synchronization, and revoke the old token."})
	}
	if snapshot.IdentityPosture.PendingPrivilegedInvitations > 0 {
		add(modelFinding{Severity: "medium", Category: "identity", Title: "Privileged organization invitations are pending", Description: "One or more unexpired bearer invitations can create an owner or administrator membership.", ResourceType: "organization", ResourceID: snapshot.Organization.String(), Evidence: map[string]any{"pendingInvitations": snapshot.IdentityPosture.PendingInvitations, "pendingPrivilegedInvitations": snapshot.IdentityPosture.PendingPrivilegedInvitations, "expiringInvitations24h": snapshot.IdentityPosture.InvitationsExpiringSoon}, Remediation: "Confirm each privileged invitation is expected and revoke any invitation that is no longer required."})
	}
	if snapshot.IdentityPosture.ExpiredInvitations > 0 {
		add(modelFinding{Severity: "low", Category: "identity", Title: "Expired organization invitations remain active in inventory", Description: "Expired invitations cannot be accepted but remain unrevoked in the organization inventory.", ResourceType: "organization", ResourceID: snapshot.Organization.String(), Evidence: map[string]any{"expiredInvitations": snapshot.IdentityPosture.ExpiredInvitations}, Remediation: "Revoke expired invitations so the administrative inventory reflects current access intent."})
	}
	if snapshot.IdentityPosture.RedundantScopedGrants > 0 {
		add(modelFinding{Severity: "low", Category: "authorization", Title: "Scoped access grants are redundant", Description: "One or more project or environment grants do not raise the member's effective organization role and add unnecessary policy state.", ResourceType: "organization", ResourceID: snapshot.Organization.String(), Evidence: map[string]any{"projectScopedGrants": snapshot.IdentityPosture.ProjectScopedGrants, "environmentScopedGrants": snapshot.IdentityPosture.EnvironmentScopedGrants, "adminScopedGrants": snapshot.IdentityPosture.AdminScopedGrants, "redundantScopedGrants": snapshot.IdentityPosture.RedundantScopedGrants}, Remediation: "Review and remove scoped grants that do not change effective access."})
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
		if !route.Disabled && !route.TLS {
			add(modelFinding{Severity: "medium", Category: "network", Title: "Public route permits plaintext HTTP", Description: "A Traefik ingress route accepts traffic without transport encryption.", ResourceType: "route", ResourceID: route.ID.String(), Evidence: map[string]any{"serviceId": route.ComposeServiceID.String(), "host": route.Host, "pathPrefix": route.PathPrefix, "targetPort": route.TargetPort}, Remediation: "Enable TLS with a configured certificate resolver, redeploy the service, and redirect or retire the plaintext endpoint."})
		}
	}
	for _, certificate := range snapshot.CustomTLSPosture {
		evidence := map[string]any{"notBefore": certificate.NotBefore.UTC().Format(time.RFC3339), "notAfter": certificate.NotAfter.UTC().Format(time.RFC3339), "revision": certificate.Revision, "attachedRoutes": certificate.AttachedRoutes, "enabledRoutes": certificate.EnabledRoutes}
		switch {
		case !certificate.NotAfter.After(now):
			add(modelFinding{Severity: "critical", Category: "network", Title: "Custom TLS certificate has expired", Description: "A managed custom certificate is past its validity window and can no longer provide a valid HTTPS identity.", ResourceType: "custom_tls_certificate", ResourceID: certificate.ID.String(), Evidence: evidence, Remediation: "Rotate the certificate and verify edge reconciliation reaches the new generation before redeploying attached routes."})
		case certificate.NotBefore.After(now):
			add(modelFinding{Severity: "high", Category: "network", Title: "Custom TLS certificate is not yet valid", Description: "A managed custom certificate has a validity window that begins in the future.", ResourceType: "custom_tls_certificate", ResourceID: certificate.ID.String(), Evidence: evidence, Remediation: "Install a currently valid certificate, verify controller time synchronization, and reconcile every attached edge target."})
		case certificate.NotAfter.Before(now.Add(30 * 24 * time.Hour)):
			severity := "medium"
			if certificate.EnabledRoutes > 0 {
				severity = "high"
			}
			add(modelFinding{Severity: severity, Category: "network", Title: "Custom TLS certificate expires soon", Description: "A managed custom certificate expires in less than thirty days.", ResourceType: "custom_tls_certificate", ResourceID: certificate.ID.String(), Evidence: evidence, Remediation: "Rotate the certificate before expiry and verify the replacement generation is ready on every attached edge target."})
		}
	}
	edgeTargets := make(map[string]bool, len(snapshot.EdgeTLSPosture))
	for _, target := range snapshot.EdgeTLSPosture {
		edgeTargets[target.TargetKey] = true
		evidence := map[string]any{"targetKey": target.TargetKey, "generation": target.Generation, "appliedGeneration": target.AppliedGeneration, "status": target.Status, "updatedAt": target.UpdatedAt.UTC().Format(time.RFC3339)}
		if target.ClusterID != nil {
			evidence["clusterId"] = target.ClusterID.String()
		}
		switch {
		case target.Status == "error":
			add(modelFinding{Severity: "critical", Category: "network", Title: "Custom TLS edge reconciliation failed", Description: "An edge target exhausted certificate reconciliation retries and cannot prove that its desired certificate generation is active.", ResourceType: "edge_tls_target", ResourceID: target.TargetKey, Evidence: evidence, Remediation: "Inspect the worker or remote edge capability, repair Traefik certificate delivery, and retry reconciliation before deploying attached workloads."})
		case target.Status == "pending" && now.Sub(target.UpdatedAt) > edgeTLSReconciliationStallThreshold:
			evidence["ageSeconds"] = int64(now.Sub(target.UpdatedAt) / time.Second)
			evidence["maximumPendingSeconds"] = int64(edgeTLSReconciliationStallThreshold / time.Second)
			add(modelFinding{Severity: "high", Category: "network", Title: "Custom TLS edge reconciliation is stalled", Description: "An edge target has remained pending beyond the certificate reconciliation grace period.", ResourceType: "edge_tls_target", ResourceID: target.TargetKey, Evidence: evidence, Remediation: "Restore worker or remote-agent connectivity and confirm the desired generation becomes ready before deploying attached workloads."})
		case target.Status == "ready" && target.AppliedGeneration != target.Generation:
			add(modelFinding{Severity: "high", Category: "network", Title: "Custom TLS edge reconciliation state is inconsistent", Description: "An edge target reports ready while its applied certificate generation differs from the desired generation.", ResourceType: "edge_tls_target", ResourceID: target.TargetKey, Evidence: evidence, Remediation: "Queue a fresh reconciliation and verify the target reports ready only after applying the desired generation."})
		}
	}
	serviceEnvironments := make(map[uuid.UUID]uuid.UUID, len(snapshot.Services))
	for _, service := range snapshot.Services {
		serviceEnvironments[service.ID] = service.EnvironmentID
	}
	environmentClusters := make(map[uuid.UUID]*uuid.UUID, len(snapshot.Environments))
	for _, environment := range snapshot.Environments {
		environmentClusters[environment.ID] = environment.ClusterID
	}
	missingTargets := map[string]bool{}
	for _, route := range snapshot.Routes {
		if route.Disabled || route.CustomCertificateID == nil {
			continue
		}
		environmentID, serviceKnown := serviceEnvironments[route.ComposeServiceID]
		clusterID, environmentKnown := environmentClusters[environmentID]
		if !serviceKnown || !environmentKnown {
			continue
		}
		targetKey := "local"
		if clusterID != nil {
			targetKey = clusterID.String()
		}
		if edgeTargets[targetKey] || missingTargets[targetKey] {
			continue
		}
		missingTargets[targetKey] = true
		evidence := map[string]any{"targetKey": targetKey, "routeId": route.ID.String(), "serviceId": route.ComposeServiceID.String(), "customCertificateId": route.CustomCertificateID.String()}
		if clusterID != nil {
			evidence["clusterId"] = clusterID.String()
		}
		add(modelFinding{Severity: "critical", Category: "network", Title: "Custom TLS edge target is missing", Description: "An enabled custom-certificate route has no edge reconciliation target, so certificate readiness cannot be established.", ResourceType: "edge_tls_target", ResourceID: targetKey, Evidence: evidence, Remediation: "Re-save the route or rotate its certificate to recreate the target, then verify reconciliation is ready before deploying the service."})
	}
	for _, destination := range snapshot.BackupDestinations {
		if !destination.UseTLS {
			add(modelFinding{Severity: "high", Category: "backup", Title: "Backup destination permits plaintext object-store transport", Description: "A configured backup destination can send credentials and recovery data without transport encryption.", ResourceType: "backup_destination", ResourceID: destination.ID.String(), Evidence: map[string]any{"useTls": false, "databasePolicyReferences": destination.DatabasePolicies, "volumePolicyReferences": destination.VolumePolicies, "auditArchiveReferences": destination.AuditArchives}, Remediation: "Move the destination to a certificate-validated TLS endpoint, rotate its credentials, and verify database, volume, and audit-archive delivery."})
		}
	}
	for _, network := range snapshot.ManagedNetworks {
		scope := "local"
		evidence := map[string]any{"scope": scope, "driver": network.Driver, "status": network.Status, "updatedAt": network.UpdatedAt.UTC().Format(time.RFC3339)}
		if network.ClusterID != nil {
			scope = "remote"
			evidence["scope"] = scope
			evidence["clusterId"] = network.ClusterID.String()
		}
		switch {
		case network.Status == "error":
			add(modelFinding{Severity: "high", Category: "network", Title: "Managed network provisioning failed", Description: "A managed Docker network is in a terminal provisioning error state.", ResourceType: "managed_network", ResourceID: network.ID.String(), Evidence: evidence, Remediation: "Inspect the redacted network state and durable provisioning job, restore Docker or agent connectivity, and retry provisioning before attaching workloads."})
		case network.Status == "provisioning" && now.Sub(network.UpdatedAt) > managedNetworkProvisioningStallThreshold:
			evidence["ageSeconds"] = int64(now.Sub(network.UpdatedAt) / time.Second)
			evidence["maximumProvisioningSeconds"] = int64(managedNetworkProvisioningStallThreshold / time.Second)
			add(modelFinding{Severity: "high", Category: "network", Title: "Managed network provisioning is stalled", Description: "A managed Docker network has remained in provisioning beyond fifteen minutes.", ResourceType: "managed_network", ResourceID: network.ID.String(), Evidence: evidence, Remediation: "Restore worker or remote-agent connectivity, inspect the durable create job, and confirm the network becomes ready before attaching workloads."})
		}
	}
	for _, workload := range snapshot.WorkloadPosture {
		if !workload.DefinitionParseable {
			add(modelFinding{Severity: "high", Category: "deployment", Title: "Workload definition cannot be audited", Description: "The stored Compose definition cannot be parsed into a service inventory.", ResourceType: "service", ResourceID: workload.ServiceID.String(), Evidence: map[string]any{"definitionParseable": false}, Remediation: "Repair and validate the Compose definition before attempting another deployment."})
		} else if workload.MissingImageOrBuild > 0 {
			add(modelFinding{Severity: "high", Category: "deployment", Title: "Workload services lack an image or build source", Description: "One or more Compose services cannot identify a container image or build input.", ResourceType: "service", ResourceID: workload.ServiceID.String(), Evidence: map[string]any{"containerCount": workload.ContainerCount, "missingImageOrBuild": workload.MissingImageOrBuild}, Remediation: "Configure an image or supported build source for every Compose service and validate the resulting revision."})
		}
		if !workload.SuccessfulDeployment {
			continue
		}
		if !workload.RuntimeSnapshotAvailable {
			add(modelFinding{Severity: "high", Category: "supply_chain", Title: "Successful deployment lacks immutable runtime snapshot", Description: "The latest successful deployment predates immutable effective-Compose capture, so its running image identities cannot be verified.", ResourceType: "service", ResourceID: workload.ServiceID.String(), Evidence: map[string]any{"successfulDeployment": true, "runtimeSnapshotAvailable": false}, Remediation: "Redeploy the intended revision and confirm the deployment records Swarm-resolved image digests."})
			continue
		}
		if !workload.RuntimeDefinitionParseable {
			add(modelFinding{Severity: "high", Category: "supply_chain", Title: "Deployed runtime snapshot cannot be audited", Description: "The immutable effective deployment snapshot cannot be parsed into a service inventory.", ResourceType: "service", ResourceID: workload.ServiceID.String(), Evidence: map[string]any{"runtimeSnapshotAvailable": true, "runtimeDefinitionParseable": false}, Remediation: "Redeploy from a validated revision and confirm the resulting immutable snapshot can be inspected."})
			continue
		}
		if workload.RuntimeMutableImages > 0 {
			add(modelFinding{Severity: "high", Category: "supply_chain", Title: "Deployed workload uses mutable container images", Description: "The latest successful effective deployment snapshot still contains image references without immutable SHA-256 digests.", ResourceType: "service", ResourceID: workload.ServiceID.String(), Evidence: map[string]any{"runtimeContainerCount": workload.RuntimeContainerCount, "runtimeMutableImages": workload.RuntimeMutableImages, "runtimeDigestPinnedImages": workload.RuntimeDigestPinnedImages}, Remediation: "Redeploy and confirm Swarm resolves every running image to repository@sha256:digest before treating the workload as immutable."})
		}
		if workload.RuntimeBuildOnlyServices > 0 || workload.RuntimeMissingImageOrBuild > 0 {
			add(modelFinding{Severity: "high", Category: "deployment", Title: "Deployed runtime snapshot is incomplete", Description: "The latest successful effective deployment snapshot still contains an unresolved build or lacks a runnable image.", ResourceType: "service", ResourceID: workload.ServiceID.String(), Evidence: map[string]any{"runtimeContainerCount": workload.RuntimeContainerCount, "runtimeBuildOnlyServices": workload.RuntimeBuildOnlyServices, "runtimeMissingImageOrBuild": workload.RuntimeMissingImageOrBuild}, Remediation: "Redeploy through the supported build pipeline and verify every runtime service records an immutable image digest."})
		}
	}
	for _, source := range snapshot.SourceBuildPosture {
		if source.SourceType == "git" && source.RepositoryTransport == "invalid" {
			add(modelFinding{Severity: "high", Category: "supply_chain", Title: "Source repository transport is invalid", Description: "A source-built workload does not use the supported HTTPS or pinned-host SSH transport.", ResourceType: "service", ResourceID: source.ServiceID.String(), Evidence: map[string]any{"sourceType": source.SourceType, "repositoryTransport": source.RepositoryTransport, "buildType": source.BuildType}, Remediation: "Configure an HTTPS repository or SSH repository with a pinned-host deploy key before rebuilding."})
		}
		if source.SourceType == "git" && source.RepositoryTransport == "ssh" && !source.GitCredentialConfigured {
			add(modelFinding{Severity: "high", Category: "supply_chain", Title: "SSH source has no pinned-host credential", Description: "An SSH source cannot authenticate with a tenant-scoped deploy key and known-host pin.", ResourceType: "service", ResourceID: source.ServiceID.String(), Evidence: map[string]any{"repositoryTransport": source.RepositoryTransport, "gitCredentialConfigured": false}, Remediation: "Attach a tenant-scoped git-ssh credential containing the expected username, private key, and pinned known-host entry."})
		}
		if source.SourceType == "drop" && (!source.ArtifactPresent || !source.ArtifactChecksumRecorded) {
			add(modelFinding{Severity: "high", Category: "supply_chain", Title: "Uploaded source artifact is unavailable", Description: "A drop-source workload has no encrypted artifact with a recorded checksum.", ResourceType: "service", ResourceID: source.ServiceID.String(), Evidence: map[string]any{"artifactPresent": source.ArtifactPresent, "artifactChecksumRecorded": source.ArtifactChecksumRecorded}, Remediation: "Upload and validate a bounded source archive before deploying this workload."})
		}
		if !source.CurrentSourceDeployed {
			add(modelFinding{Severity: "medium", Category: "deployment", Title: "Current source configuration has not been deployed", Description: "No successful deployment was recorded after the current source configuration or uploaded artifact changed.", ResourceType: "service", ResourceID: source.ServiceID.String(), Evidence: map[string]any{"sourceType": source.SourceType, "buildType": source.BuildType}, Remediation: "Review the current source configuration, deploy it, and verify the resulting workload revision."})
		} else if source.SourceType == "git" && !source.DeploymentCommitRecorded {
			add(modelFinding{Severity: "high", Category: "supply_chain", Title: "Source deployment lacks commit provenance", Description: "The successful source-built deployment did not record the resolved Git commit.", ResourceType: "service", ResourceID: source.ServiceID.String(), Evidence: map[string]any{"sourceType": source.SourceType, "gitRefPinned": source.GitRefPinned, "statusReportingConfigured": source.StatusReportingConfigured}, Remediation: "Rebuild through the source pipeline and verify the deployment records the resolved commit before promotion."})
		}
	}
	for _, finding := range operationalSignalFindings(snapshot.Signals, snapshot.Organization) {
		add(finding)
	}
	for _, database := range snapshot.Databases {
		if database.Status == "error" {
			add(modelFinding{Severity: "high", Category: "availability", Title: "Managed database deployment is unhealthy", Description: "The managed database's latest deployment failed and its lifecycle remains in an error state.", ResourceType: "database", ResourceID: database.ID.String(), Evidence: map[string]any{"engine": database.Engine, "version": database.Version, "status": database.Status}, Remediation: "Inspect the database deployment and Swarm task state, correct the failure, then redeploy and verify application connectivity."})
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
	protectedVolumes := make(map[string]bool, len(snapshot.VolumeBackupPosture))
	for _, backup := range snapshot.VolumeBackupPosture {
		protectedVolumes[backup.ServiceID.String()+"\x00"+backup.VolumeName] = true
	}
	for _, workload := range snapshot.WorkloadPosture {
		for _, volumeName := range workload.NamedVolumes {
			if !protectedVolumes[workload.ServiceID.String()+"\x00"+volumeName] {
				add(modelFinding{Severity: "high", Category: "backup", Title: "Named volume has no backup policy", Description: "A Compose named volume is mounted by the workload but has no configured backup policy.", ResourceType: "service_volume", ResourceID: workload.ServiceID.String() + "/" + volumeName, Evidence: map[string]any{"serviceId": workload.ServiceID.String(), "volumeName": volumeName}, Remediation: "Configure an encrypted retained volume-backup policy and complete a successful backup and restore rehearsal."})
			}
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
		if !ociref.IsDigestPinned(cluster.AgentImage) {
			add(modelFinding{Severity: "high", Category: "supply_chain", Title: "Remote agent image is not immutable", Description: "An active or draining remote agent does not report a digest-pinned runtime image.", ResourceType: "cluster", ResourceID: cluster.ID.String(), Evidence: map[string]any{"state": cluster.State, "agentImageRecorded": cluster.AgentImage != ""}, Remediation: "Upgrade the remote agent to a reviewed repository@sha256:digest image and verify the replacement heartbeat before scheduling workloads."})
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
	for _, queue := range snapshot.AgentCommandPosture {
		resourceID := queue.ClusterID.String() + "/" + queue.Kind
		if queue.OldestDueAt != nil && now.Sub(*queue.OldestDueAt) > agentCommandStallThreshold {
			add(modelFinding{Severity: "high", Category: "cluster", Title: "Remote command queue is stalled", Description: "An outbound command has remained ready for pickup by the cluster agent for more than two minutes.", ResourceType: "cluster_command_queue", ResourceID: resourceID, Evidence: map[string]any{"clusterId": queue.ClusterID.String(), "kind": queue.Kind, "pendingCommands": queue.PendingCommands, "dueCommands": queue.DueCommands, "oldestDueAt": queue.OldestDueAt.UTC().Format(time.RFC3339)}, Remediation: "Restore agent polling and certificate connectivity, then verify the queued command is claimed or safely cancelled."})
		}
		if queue.OldestExpiredLeaseAt != nil && now.Sub(*queue.OldestExpiredLeaseAt) > agentCommandStallThreshold {
			add(modelFinding{Severity: "high", Category: "cluster", Title: "Remote command lease recovery is stalled", Description: "An outbound command lease expired more than two minutes ago without being recovered by the cluster agent.", ResourceType: "cluster_command_queue", ResourceID: resourceID, Evidence: map[string]any{"clusterId": queue.ClusterID.String(), "kind": queue.Kind, "leasedCommands": queue.LeasedCommands, "expiredLeases": queue.ExpiredLeases, "oldestExpiredLeaseAt": queue.OldestExpiredLeaseAt.UTC().Format(time.RFC3339)}, Remediation: "Restore agent polling so expired leases are fenced and retried, and confirm no superseded command can report a terminal result."})
		}
	}
	for _, repository := range snapshot.TemplateRepositories {
		syncActive := repository.SyncRequestedAt != nil || repository.LastSyncStatus == "running"
		if repository.Enabled && !repository.RequireSignature {
			add(modelFinding{Severity: "medium", Category: "supply_chain", Title: "Template repository does not require signatures", Description: "An enabled remote catalog can update deployable Compose definitions without signer verification.", ResourceType: "template_repository", ResourceID: repository.ID.String(), Evidence: map[string]any{"gitRef": repository.GitRef}, Remediation: "Pin an Ed25519 catalog signer and require signature verification."})
		}
		if repository.Enabled && repository.LastSyncStatus == "failed" {
			add(modelFinding{Severity: "high", Category: "supply_chain", Title: "Template repository synchronization failed", Description: "The latest refresh of an enabled template repository failed.", ResourceType: "template_repository", ResourceID: repository.ID.String(), Evidence: map[string]any{"lastSyncStatus": repository.LastSyncStatus}, Remediation: "Inspect the repository credential, ref, signature, and archive validation error before retrying."})
		}
		if repository.Enabled && repository.SyncRequestedAt != nil && now.Sub(*repository.SyncRequestedAt) > 5*time.Minute {
			add(modelFinding{Severity: "medium", Category: "supply_chain", Title: "Template repository synchronization is queued too long", Description: "A durable catalog refresh request has not been claimed within five minutes.", ResourceType: "template_repository", ResourceID: repository.ID.String(), Evidence: map[string]any{"syncRequestedAt": repository.SyncRequestedAt.UTC().Format(time.RFC3339)}, Remediation: "Restore the template repository scheduler lease and controller database connectivity."})
		}
		if repository.Enabled && repository.SyncStartedAt != nil && now.Sub(*repository.SyncStartedAt) > 10*time.Minute {
			add(modelFinding{Severity: "medium", Category: "supply_chain", Title: "Template repository synchronization is stuck", Description: "A catalog refresh has remained in the running state for more than ten minutes.", ResourceType: "template_repository", ResourceID: repository.ID.String(), Evidence: map[string]any{"syncStartedAt": repository.SyncStartedAt.UTC().Format(time.RFC3339)}, Remediation: "Inspect controller connectivity and archive processing; stale work is eligible for a fenced retry."})
		}
		if repository.Enabled && !syncActive && repository.LastSyncStatus != "failed" && repository.LastSyncedAt == nil {
			add(modelFinding{Severity: "medium", Category: "supply_chain", Title: "Template repository has never synchronized", Description: "An enabled remote catalog has no successful synchronization record.", ResourceType: "template_repository", ResourceID: repository.ID.String(), Evidence: map[string]any{"gitRef": repository.GitRef, "syncIntervalSeconds": repository.SyncIntervalSeconds}, Remediation: "Run a catalog synchronization and verify its signature and imported template inventory."})
		} else if repository.Enabled && !syncActive && repository.LastSyncStatus != "failed" && repository.SyncIntervalSeconds > 0 && now.Sub(*repository.LastSyncedAt) > 2*time.Duration(repository.SyncIntervalSeconds)*time.Second+5*time.Minute {
			add(modelFinding{Severity: "medium", Category: "supply_chain", Title: "Template repository synchronization is stale", Description: "An enabled scheduled catalog has not synchronized within two configured intervals plus a five-minute grace period.", ResourceType: "template_repository", ResourceID: repository.ID.String(), Evidence: map[string]any{"gitRef": repository.GitRef, "syncIntervalSeconds": repository.SyncIntervalSeconds, "lastSyncedAt": repository.LastSyncedAt.UTC().Format(time.RFC3339)}, Remediation: "Restore the catalog scheduler or repository access and complete a verified synchronization."})
		}
	}
	for _, schedule := range snapshot.ServiceSchedules {
		if !schedule.Enabled || schedule.DesiredState == "stopped" {
			continue
		}
		if schedule.LastStatus == "failed" {
			add(modelFinding{Severity: "high", Category: "operations", Title: "Scheduled service command failed", Description: "The latest execution of an enabled service schedule failed.", ResourceType: "service_schedule", ResourceID: schedule.ID.String(), Evidence: map[string]any{"serviceId": schedule.ServiceID.String(), "name": schedule.Name, "failures24h": schedule.Failures24h, "lastFinishedAt": schedule.LastFinishedAt}, Remediation: "Inspect the bounded execution output, verify the target Compose service is running on the agent node, and run the schedule manually after correcting the command."})
		}
		if schedule.NextRunAt.Before(now.Add(-10 * time.Minute)) {
			add(modelFinding{Severity: "high", Category: "operations", Title: "Service schedule dispatch is overdue", Description: "An enabled service schedule has remained due for more than ten minutes.", ResourceType: "service_schedule", ResourceID: schedule.ID.String(), Evidence: map[string]any{"serviceId": schedule.ServiceID.String(), "name": schedule.Name, "timezone": schedule.Timezone, "nextRunAt": schedule.NextRunAt.UTC().Format(time.RFC3339)}, Remediation: "Restore the service-command scheduler lease, worker capacity, and assigned cluster connectivity."})
		}
	}
	if snapshot.QueuePosture.OldestPendingAt != nil && now.Sub(*snapshot.QueuePosture.OldestPendingAt) > 10*time.Minute {
		add(modelFinding{Severity: "high", Category: "operations", Title: "Platform job queue is stalled", Description: "A tenant-scoped deployment, recovery, integration, audit, or deletion job has remained pending for more than ten minutes.", ResourceType: "organization", ResourceID: snapshot.Organization.String(), Evidence: map[string]any{"pendingJobs": snapshot.QueuePosture.PendingJobs, "runningJobs": snapshot.QueuePosture.RunningJobs, "oldestPendingAt": snapshot.QueuePosture.OldestPendingAt.UTC().Format(time.RFC3339), "kinds": snapshot.QueuePosture.Kinds}, Remediation: "Check worker health, leader leases, cluster admission, and job retry state before accepting more work."})
	}
	if snapshot.QueuePosture.OldestRunningHeartbeatAt != nil && now.Sub(*snapshot.QueuePosture.OldestRunningHeartbeatAt) > jobHeartbeatStallThreshold {
		add(modelFinding{Severity: "high", Category: "operations", Title: "Platform job lease heartbeat is stale", Description: "A running tenant-scoped job has not renewed its worker lease heartbeat within two minutes.", ResourceType: "organization", ResourceID: snapshot.Organization.String(), Evidence: map[string]any{"runningJobs": snapshot.QueuePosture.RunningJobs, "oldestRunningHeartbeatAt": snapshot.QueuePosture.OldestRunningHeartbeatAt.UTC().Format(time.RFC3339), "maximumHeartbeatAgeSeconds": int64(jobHeartbeatStallThreshold / time.Second), "kinds": snapshot.QueuePosture.Kinds}, Remediation: "Restore worker processing and stale-job recovery, then verify the fenced replacement attempt completes without duplicate side effects."})
	}
	finalizers := snapshot.FinalizerPosture
	if finalizers.FailedJobs > 0 || finalizers.ResourcesWithoutActiveJob > 0 {
		add(modelFinding{Severity: "high", Category: "operations", Title: "Resource deletion finalizer requires intervention", Description: "One or more deleting resources have a failed finalizer or no pending/running finalizer job.", ResourceType: "organization", ResourceID: snapshot.Organization.String(), Evidence: map[string]any{"deletingProjects": finalizers.DeletingProjects, "deletingEnvironments": finalizers.DeletingEnvironments, "deletingServices": finalizers.DeletingServices, "deletingClusters": finalizers.DeletingClusters, "pendingJobs": finalizers.PendingJobs, "runningJobs": finalizers.RunningJobs, "failedJobs": finalizers.FailedJobs, "resourcesWithoutActiveJob": finalizers.ResourcesWithoutActiveJob}, Remediation: "Inspect the failed deletion jobs and Swarm state, restore worker access, then retry or safely reconstruct the missing finalizer job."})
	} else if finalizers.OldestRequestedAt != nil && now.Sub(*finalizers.OldestRequestedAt) > finalizerStallThreshold {
		add(modelFinding{Severity: "medium", Category: "operations", Title: "Resource deletion finalizer is stalled", Description: "A resource has remained in deletion for more than fifteen minutes while its finalizer is still pending or running.", ResourceType: "organization", ResourceID: snapshot.Organization.String(), Evidence: map[string]any{"deletingProjects": finalizers.DeletingProjects, "deletingEnvironments": finalizers.DeletingEnvironments, "deletingServices": finalizers.DeletingServices, "deletingClusters": finalizers.DeletingClusters, "pendingJobs": finalizers.PendingJobs, "runningJobs": finalizers.RunningJobs, "oldestRequestedAt": finalizers.OldestRequestedAt.UTC().Format(time.RFC3339)}, Remediation: "Inspect worker and Swarm availability, then confirm the finalizer completes before retrying dependent deletions."})
	}
	if missing := missingNotificationCoverage(snapshot.NotificationPosture); len(missing) > 0 {
		add(modelFinding{Severity: "medium", Category: "operations", Title: "Failure notifications have coverage gaps", Description: "No enabled notification endpoint subscribes to one or more supported failure events.", ResourceType: "organization", ResourceID: snapshot.Organization.String(), Evidence: map[string]any{"missingEvents": missing}, Remediation: "Enable at least one tested notification destination for every supported failure event."})
	}
	for _, deployment := range snapshot.ServiceDeployments {
		if deployment.DesiredState == "stopped" {
			continue
		}
		if !deployment.CurrentRevisionDeployed {
			add(modelFinding{Severity: "medium", Category: "deployment", Title: "Desired service revision is not deployed", Description: "The service's current desired revision has no successful deployment.", ResourceType: "service", ResourceID: deployment.ServiceID.String(), Evidence: map[string]any{"desiredRevision": deployment.DesiredRevision, "latestDeploymentRevision": deployment.LatestDeploymentRevision, "latestDeploymentStatus": deployment.LatestDeploymentStatus}, Remediation: "Review the pending change and deploy it, or restore the intended revision."})
		}
	}
	stoppedServices := make(map[uuid.UUID]bool, len(snapshot.Services))
	for _, service := range snapshot.Services {
		stoppedServices[service.ID] = service.DesiredState == "stopped"
	}
	for _, reconciliation := range snapshot.Reconciliation {
		if stoppedServices[reconciliation.ComposeServiceID] {
			continue
		}
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

func operationalSignalFindings(signals []store.AIAuditSignal, organizationID uuid.UUID) []modelFinding {
	type outcome struct{ succeeded, failed int64 }
	outcomes := map[string]outcome{}
	for _, signal := range signals {
		current := outcomes[signal.Kind]
		switch signal.Status {
		case "succeeded":
			current.succeeded += signal.Count
		case "failed":
			current.failed += signal.Count
		}
		outcomes[signal.Kind] = current
	}
	labels := []struct {
		kind  string
		title string
	}{
		{kind: "deployment", title: "Deployments"},
		{kind: "backup", title: "Database backups"},
		{kind: "restore", title: "Database restores"},
		{kind: "volume_backup", title: "Volume backups"},
		{kind: "volume_restore", title: "Volume restores"},
		{kind: "notification", title: "Notification deliveries"},
		{kind: "database_migration", title: "Database migrations"},
		{kind: "audit_archive", title: "Audit archive deliveries"},
		{kind: "agent_command", title: "Remote agent commands"},
		{kind: "commit_status", title: "Commit status deliveries"},
		{kind: "ai_audit", title: "AI audit runs"},
	}
	findings := []modelFinding{}
	for _, label := range labels {
		outcome := outcomes[label.kind]
		terminal := outcome.succeeded + outcome.failed
		if terminal < minimumOperationalSignalSample || outcome.failed*4 < terminal {
			continue
		}
		severity := "medium"
		if outcome.failed*2 >= terminal {
			severity = "high"
		}
		findings = append(findings, modelFinding{Severity: severity, Category: "reliability", Title: label.title + " have an elevated failure rate", Description: "At least twenty-five percent of this operation's terminal outcomes failed during the trailing thirty-day window.", ResourceType: "organization", ResourceID: organizationID.String(), Evidence: map[string]any{"kind": label.kind, "windowDays": 30, "succeeded": outcome.succeeded, "failed": outcome.failed, "terminal": terminal, "failurePercent": outcome.failed * 100 / terminal, "minimumSample": minimumOperationalSignalSample}, Remediation: "Inspect recent failures by resource, correct the shared cause, and confirm the failure rate returns below the alert threshold."})
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
		"service.stop.failed":       false,
		"service.schedule.failed":   false,
		"backup.failed":             false,
		"restore.failed":            false,
		"restore.drill.failed":      false,
		"database.migration.failed": false,
		"network.provision.failed":  false,
		"network.delete.failed":     false,
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
