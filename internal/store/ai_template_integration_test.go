package store

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAIAuditsAndTemplateRepositories(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, userID := uuid.New(), uuid.New()
	developerUserID, disabledUserID, otherUserID := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'AI test',$2)`, organizationID, "ai-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'unused')`, userID, userID.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	credentialID := uuid.New()
	if _, err := db.CreateSourceCredential(ctx, SourceCredential{ID: credentialID, OrganizationID: organizationID, Kind: "git", Name: "GitHub", Server: "github.com", Username: "token", EncryptedSecret: "ciphertext"}); err != nil {
		t.Fatal(err)
	}
	repository, err := db.CreateTemplateRepository(ctx, TemplateRepository{OrganizationID: organizationID, Name: "Community", Slug: "community", RepositoryURL: "https://github.com/acme/templates", GitRef: "main", TrustedPublicKey: "catalog-key", RequireSignature: true, CredentialID: &credentialID, SyncIntervalSeconds: 3600})
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := db.GetTemplateRepository(ctx, organizationID, repository.ID)
	if err != nil || loaded.TrustedPublicKey != "catalog-key" || !loaded.RequireSignature || loaded.CredentialID == nil || *loaded.CredentialID != credentialID || loaded.SyncIntervalSeconds != 3600 || loaded.NextSyncAt == nil {
		t.Fatalf("repository trust policy=%#v err=%v", loaded, err)
	}
	otherOrganizationID := uuid.New()
	if _, err = pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Other AI test',$2)`, otherOrganizationID, "other-ai-"+otherOrganizationID.String()); err != nil {
		t.Fatal(err)
	}
	scimTokenCreatedAt := time.Now().UTC().Add(-30 * 24 * time.Hour).Truncate(time.Microsecond)
	targetSCIMAdminGroupID, targetSCIMViewerGroupID, otherSCIMGroupID := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'unused'),($3,$4,'unused'),($5,$6,'unused')`, []any{developerUserID, developerUserID.String() + "@example.test", disabledUserID, disabledUserID.String() + "@example.test", otherUserID, otherUserID.String() + "@example.test"}},
		{`UPDATE users SET disabled_at=now() WHERE id=$1`, []any{disabledUserID}},
		{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner'),($1,$3,'developer'),($1,$4,'viewer'),($5,$6,'owner')`, []any{organizationID, userID, developerUserID, disabledUserID, otherOrganizationID, otherUserID}},
		{`INSERT INTO sessions(id,user_id,token_hash,expires_at,auth_method) VALUES($1,$2,$3,now()+interval '1 hour','local'),($4,$5,$6,now()+interval '1 hour','local'),($7,$8,$9,now()+interval '1 hour','local'),($10,$11,$12,now()+interval '1 hour','local')`, []any{uuid.New(), userID, []byte("target-owner-local"), uuid.New(), developerUserID, []byte("target-developer-local"), uuid.New(), disabledUserID, []byte("disabled-local"), uuid.New(), otherUserID, []byte("other-local")}},
		{`INSERT INTO sessions(id,user_id,organization_id,token_hash,expires_at,auth_method) VALUES($1,$2,$3,$4,now()+interval '1 hour','oidc'),($5,$6,$7,$8,now()+interval '1 hour','saml')`, []any{uuid.New(), developerUserID, organizationID, []byte("target-oidc"), uuid.New(), otherUserID, otherOrganizationID, []byte("other-saml")}},
		{`INSERT INTO scim_tokens(id,organization_id,name,token_hash,created_at) VALUES($1,$2,'Target SCIM',$3,$4),($5,$6,'Other SCIM',$7,now()-interval '1 year')`, []any{uuid.New(), organizationID, []byte("target-scim"), scimTokenCreatedAt, uuid.New(), otherOrganizationID, []byte("other-scim")}},
		{`INSERT INTO organization_invitations(id,organization_id,email,role,token_hash,created_by,expires_at) VALUES
			($1,$2,'target-admin-invite@example.test','admin',$3,$4,now()+interval '12 hours'),
			($5,$2,'target-viewer-invite@example.test','viewer',$6,$4,now()+interval '7 days'),
			($7,$2,'target-expired-invite@example.test','developer',$8,$4,now()-interval '1 hour'),
			($9,$10,'other-admin-invite@example.test','owner',$11,$12,now()+interval '12 hours')`, []any{uuid.New(), organizationID, []byte("target-admin-invitation-token-hash"), userID, uuid.New(), []byte("target-viewer-invitation-token-hash"), uuid.New(), []byte("target-expired-invitation-token-hash"), uuid.New(), otherOrganizationID, []byte("other-admin-invitation-token-hash"), otherUserID}},
		{`INSERT INTO scim_groups(id,organization_id,external_id,display_name,role) VALUES
			($1,$2,'target-admin-group-external-secret','Target administrators secret name','admin'),
			($3,$2,'target-viewer-group-external-secret','Target viewers secret name','viewer'),
			($4,$5,'other-group-external-secret','Other tenant group secret name','admin')`, []any{targetSCIMAdminGroupID, organizationID, targetSCIMViewerGroupID, otherSCIMGroupID, otherOrganizationID}},
		{`INSERT INTO scim_group_members(group_id,user_id) VALUES($1,$2),($3,$4),($5,$6)`, []any{targetSCIMAdminGroupID, developerUserID, targetSCIMViewerGroupID, disabledUserID, otherSCIMGroupID, otherUserID}},
	} {
		if _, err = pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.CreateTemplateRepository(ctx, TemplateRepository{OrganizationID: otherOrganizationID, Name: "Wrong scope", Slug: "wrong-scope", RepositoryURL: "https://github.com/acme/templates", GitRef: "main", CredentialID: &credentialID}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-organization catalog credential accepted: %v", err)
	}
	claimed, err := db.ClaimDueTemplateRepository(ctx)
	if err != nil || claimed.ID != repository.ID || claimed.LastSyncStatus != "running" || claimed.SyncStartedAt == nil || claimed.SyncAttemptID == nil {
		t.Fatalf("claimed repository=%#v err=%v", claimed, err)
	}
	if _, err = db.ClaimDueTemplateRepository(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("running repository was claimed twice: %v", err)
	}
	if err = db.FinishTemplateRepositorySync(ctx, claimed, "succeeded", ""); err != nil {
		t.Fatal(err)
	}
	loaded, err = db.GetTemplateRepository(ctx, organizationID, repository.ID)
	if err != nil || loaded.NextSyncAt == nil || !loaded.NextSyncAt.After(time.Now()) || loaded.LastSyncStatus != "succeeded" || loaded.SyncStartedAt != nil {
		t.Fatalf("completed repository schedule=%#v err=%v", loaded, err)
	}
	manualRequestedAt, err := db.QueueTemplateRepositorySync(ctx, organizationID, repository.ID)
	if err != nil || manualRequestedAt.IsZero() {
		t.Fatalf("queue manual sync requestedAt=%v err=%v", manualRequestedAt, err)
	}
	coalescedAt, err := db.QueueTemplateRepositorySync(ctx, organizationID, repository.ID)
	if err != nil || !coalescedAt.Equal(manualRequestedAt) {
		t.Fatalf("manual sync was not coalesced: first=%v second=%v err=%v", manualRequestedAt, coalescedAt, err)
	}
	if _, err = db.QueueTemplateRepositorySync(ctx, otherOrganizationID, repository.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-organization manual sync accepted: %v", err)
	}
	claimed, err = db.ClaimDueTemplateRepository(ctx)
	if err != nil || claimed.ID != repository.ID || claimed.SyncRequestedAt != nil || claimed.SyncStartedAt == nil || claimed.SyncAttemptID == nil {
		t.Fatalf("manual-requested repository=%#v err=%v", claimed, err)
	}
	if _, err = db.QueueTemplateRepositorySync(ctx, organizationID, repository.ID); err != nil {
		t.Fatal(err)
	}
	loaded, err = db.GetTemplateRepository(ctx, organizationID, repository.ID)
	if err != nil || loaded.SyncStartedAt == nil || !loaded.SyncStartedAt.Equal(*claimed.SyncStartedAt) || loaded.SyncRequestedAt == nil {
		t.Fatalf("running sync clock changed while follow-up was queued: repository=%#v err=%v", loaded, err)
	}
	if err = db.FinishTemplateRepositorySync(ctx, claimed, "succeeded", ""); err != nil {
		t.Fatal(err)
	}
	claimed, err = db.ClaimDueTemplateRepository(ctx)
	if err != nil || claimed.ID != repository.ID || claimed.SyncStartedAt == nil || claimed.SyncAttemptID == nil {
		t.Fatalf("follow-up manual repository=%#v err=%v", claimed, err)
	}
	if err = db.FinishTemplateRepositorySync(ctx, claimed, "succeeded", ""); err != nil {
		t.Fatal(err)
	}
	if err = db.SetTemplateRepositoryWebhookSecret(ctx, organizationID, repository.ID, "encrypted-webhook-secret"); err != nil {
		t.Fatal(err)
	}
	webhookRepository, err := db.GetTemplateRepositoryForWebhook(ctx, repository.ID)
	if err != nil || webhookRepository.EncryptedWebhookSecret != "encrypted-webhook-secret" || !webhookRepository.WebhookConfigured {
		t.Fatalf("webhook repository=%#v err=%v", webhookRepository, err)
	}
	if err = db.RequestTemplateRepositorySync(ctx, repository.ID, "delivery-1"); err != nil {
		t.Fatal(err)
	}
	if err = db.RequestTemplateRepositorySync(ctx, repository.ID, "delivery-1"); !errors.Is(err, ErrDuplicateDelivery) {
		t.Fatalf("duplicate webhook delivery accepted: %v", err)
	}
	claimed, err = db.ClaimDueTemplateRepository(ctx)
	if err != nil || claimed.ID != repository.ID || claimed.SyncRequestedAt != nil {
		t.Fatalf("webhook-requested repository=%#v err=%v", claimed, err)
	}
	if err = db.FinishTemplateRepositorySync(ctx, claimed, "succeeded", ""); err != nil {
		t.Fatal(err)
	}
	template, err := db.UpsertRepositoryTemplate(ctx, Template{OrganizationID: &organizationID, RepositoryID: &repository.ID, Key: "community/demo", Version: "1", Name: "Demo", ComposeYAML: "services: {}", Config: json.RawMessage(`{}`), Source: "github", SourcePath: "blueprints/demo", Checksum: "abc"})
	if err != nil {
		t.Fatal(err)
	}
	listed, err := db.ListTemplates(ctx, organizationID)
	if err != nil || len(listed) != 1 || listed[0].RepositoryID == nil || *listed[0].RepositoryID != repository.ID {
		t.Fatalf("templates=%#v err=%v", listed, err)
	}
	replacement := Template{OrganizationID: &organizationID, RepositoryID: &repository.ID, Key: "community/replacement", Version: "2", Name: "Replacement", ComposeYAML: "services: {}", Config: json.RawMessage(`{}`), Source: "github", SourcePath: "blueprints/replacement", Checksum: "def"}
	if _, err = db.QueueTemplateRepositorySync(ctx, organizationID, repository.ID); err != nil {
		t.Fatal(err)
	}
	catalogAttempt, err := db.ClaimDueTemplateRepository(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.ReplaceRepositoryTemplatesForSync(ctx, catalogAttempt, []Template{replacement}); err != nil {
		t.Fatal(err)
	}
	listed, err = db.ListTemplates(ctx, organizationID)
	if err != nil || len(listed) != 1 || listed[0].Key != "community/replacement" {
		t.Fatalf("repository snapshot was not reconciled atomically: templates=%#v err=%v", listed, err)
	}
	badScope := replacement
	badScope.OrganizationID = &otherOrganizationID
	if err = db.ReplaceRepositoryTemplatesForSync(ctx, catalogAttempt, []Template{badScope}); err == nil {
		t.Fatal("repository snapshot accepted a cross-tenant template")
	}
	if err = db.FinishTemplateRepositorySync(ctx, catalogAttempt, "succeeded", ""); err != nil {
		t.Fatal(err)
	}
	listed, err = db.ListTemplates(ctx, organizationID)
	if err != nil || len(listed) != 1 || listed[0].Key != "community/replacement" {
		t.Fatalf("failed replacement changed catalog: templates=%#v err=%v", listed, err)
	}
	account, err := db.CreateServiceAccount(ctx, organizationID, userID, "auditor", "auditor", []byte("token-hash"), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.CreateServiceAccount(ctx, organizationID, userID, "deployment-admin", "admin", []byte("admin-token-hash"), time.Now().Add(30*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err = db.CreateServiceAccount(ctx, otherOrganizationID, otherUserID, "other-admin", "admin", []byte("other-admin-token-hash"), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	run, err := db.CreateAIAuditRun(ctx, organizationID, account.ID, "security", "v1", "test", json.RawMessage(`{"kind":"platform"}`))
	if err != nil {
		t.Fatal(err)
	}
	forgedActor := uuid.New()
	forgedAt := time.Now().UTC()
	finding, err := db.AddAIAuditFinding(ctx, organizationID, account.ID, AIAuditFinding{RunID: run.ID, Severity: "high", Category: "backup", Title: "No backup", Description: "No recent successful backup", Evidence: json.RawMessage(`{}`), Fingerprint: "backup:none", Disposition: "resolved", TriageNote: "forged", TriagedByUser: &forgedActor, TriagedAt: &forgedAt, OccurrenceNumber: 99})
	if err != nil {
		t.Fatal(err)
	}
	if finding.ID == uuid.Nil || finding.Disposition != "open" || finding.TriageNote != "" || finding.TriagedByUser != nil || finding.TriagedAt != nil || finding.OccurrenceNumber != 1 {
		t.Fatalf("new finding accepted untrusted lifecycle fields: %#v", finding)
	}
	if err = db.FinishAIAuditRun(ctx, organizationID, account.ID, run.ID, "completed", "one finding"); err != nil {
		t.Fatal(err)
	}
	triagePrincipal := Principal{UserID: userID, OrganizationID: organizationID, Role: "owner"}
	finding, err = db.UpdateAIAuditFindingDisposition(ctx, triagePrincipal, finding.ID, "acknowledged", "accepted risk", "127.0.0.1")
	if err != nil || finding.Disposition != "acknowledged" {
		t.Fatalf("acknowledge finding=%#v err=%v", finding, err)
	}
	previous, err := db.CreateAIAuditRun(ctx, organizationID, account.ID, "reliability", "v1", "test", json.RawMessage(`{"kind":"platform"}`))
	if err != nil {
		t.Fatal(err)
	}
	replacementRun, err := db.CreateAIAuditRun(ctx, organizationID, account.ID, "reliability", "v2", "test", json.RawMessage(`{"kind":"platform"}`))
	if err != nil {
		t.Fatal(err)
	}
	var previousStatus, previousSummary string
	var previousCompletedAt *time.Time
	if err = pool.QueryRow(ctx, `SELECT status,summary,completed_at FROM ai_audit_runs WHERE id=$1`, previous.ID).Scan(&previousStatus, &previousSummary, &previousCompletedAt); err != nil {
		t.Fatal(err)
	}
	if previousStatus != "failed" || previousCompletedAt == nil || previousSummary != "superseded by a newer run for the same auditor identity" {
		t.Fatalf("superseded run status=%q summary=%q completed=%v", previousStatus, previousSummary, previousCompletedAt)
	}
	parallelRun, err := db.CreateAIAuditRun(ctx, organizationID, account.ID, "security", "v2", "test", json.RawMessage(`{"kind":"platform"}`))
	if err != nil {
		t.Fatal(err)
	}
	recurrence, err := db.AddAIAuditFinding(ctx, organizationID, account.ID, AIAuditFinding{RunID: parallelRun.ID, Severity: "critical", Category: "backup", Title: "Still no backup", Description: "No recent successful backup", Evidence: json.RawMessage(`{}`), Fingerprint: "backup:none"})
	if err != nil || recurrence.PreviousFindingID == nil || *recurrence.PreviousFindingID != finding.ID || recurrence.OccurrenceNumber != 2 || recurrence.Disposition != "acknowledged" || recurrence.TriageNote != "accepted risk" || recurrence.TriagedByUser == nil || *recurrence.TriagedByUser != userID {
		t.Fatalf("acknowledged recurrence=%#v err=%v", recurrence, err)
	}
	var activeRuns int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM ai_audit_runs WHERE service_account_id=$1 AND status='running'`, account.ID).Scan(&activeRuns); err != nil || activeRuns != 2 {
		t.Fatalf("independent active audit runs=%d err=%v", activeRuns, err)
	}
	reliabilityFinding, err := db.AddAIAuditFinding(ctx, organizationID, account.ID, AIAuditFinding{RunID: replacementRun.ID, Severity: "low", Category: "backup", Title: "Reliability backup review", Description: "Independent agent lineage", Evidence: json.RawMessage(`{}`), Fingerprint: "backup:none"})
	if err != nil || reliabilityFinding.OccurrenceNumber != 1 || reliabilityFinding.PreviousFindingID != nil || reliabilityFinding.AgentName != "reliability" || reliabilityFinding.ServiceAccountID != account.ID {
		t.Fatalf("independent agent finding=%#v err=%v", reliabilityFinding, err)
	}
	if err = db.FinishAIAuditRun(ctx, organizationID, account.ID, replacementRun.ID, "completed", "replacement completed"); err != nil {
		t.Fatal(err)
	}
	if err = db.FinishAIAuditRun(ctx, organizationID, account.ID, parallelRun.ID, "completed", "parallel specialist completed"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.UpdateAIAuditFindingDisposition(ctx, triagePrincipal, recurrence.ID, "resolved", "fixed", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	reopenedRun, err := db.CreateAIAuditRun(ctx, organizationID, account.ID, "security", "v3", "test", json.RawMessage(`{"kind":"platform"}`))
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := db.AddAIAuditFinding(ctx, organizationID, account.ID, AIAuditFinding{RunID: reopenedRun.ID, Severity: "high", Category: "backup", Title: "No backup again", Description: "The resolved condition recurred", Evidence: json.RawMessage(`{}`), Fingerprint: "backup:none"})
	if err != nil || reopened.PreviousFindingID == nil || *reopened.PreviousFindingID != recurrence.ID || reopened.OccurrenceNumber != 3 || reopened.Disposition != "open" || reopened.TriageNote != "" || reopened.TriagedByUser != nil || reopened.TriagedAt != nil {
		t.Fatalf("resolved recurrence=%#v err=%v", reopened, err)
	}
	if err = db.FinishAIAuditRun(ctx, organizationID, account.ID, reopenedRun.ID, "completed", "recurrence reopened"); err != nil {
		t.Fatal(err)
	}
	currentFindings, err := db.ListCurrentAIAuditFindings(ctx, organizationID, "active", "", 100)
	if err != nil || len(currentFindings) != 2 {
		t.Fatalf("current findings=%#v err=%v", currentFindings, err)
	}
	currentByAgent := map[string]AIAuditFinding{}
	for _, current := range currentFindings {
		currentByAgent[current.AgentName] = current
	}
	if currentByAgent["security"].ID != reopened.ID || currentByAgent["security"].OccurrenceNumber != 3 || currentByAgent["reliability"].ID != reliabilityFinding.ID || currentByAgent["reliability"].OccurrenceNumber != 1 {
		t.Fatalf("current lineage selection=%#v", currentByAgent)
	}
	highFindings, err := db.ListCurrentAIAuditFindings(ctx, organizationID, "open", "high", 1)
	if err != nil || len(highFindings) != 1 || highFindings[0].ID != reopened.ID {
		t.Fatalf("filtered current findings=%#v err=%v", highFindings, err)
	}
	if _, err = pool.Exec(ctx, `UPDATE ai_audit_runs SET started_at=started_at-interval '400 days',completed_at=completed_at-interval '400 days' WHERE service_account_id=$1`, account.ID); err != nil {
		t.Fatal(err)
	}
	if removed, pruneErr := db.PruneAIAuditRuns(ctx); pruneErr != nil || removed != 3 {
		t.Fatalf("pruned AI audit runs=%d err=%v", removed, pruneErr)
	}
	var retainedRuns int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM ai_audit_runs WHERE service_account_id=$1`, account.ID).Scan(&retainedRuns); err != nil || retainedRuns != 2 {
		t.Fatalf("retained latest AI audit runs=%d err=%v", retainedRuns, err)
	}
	currentFindings, err = db.ListCurrentAIAuditFindings(ctx, organizationID, "active", "", 100)
	if err != nil || len(currentFindings) != 2 {
		t.Fatalf("current findings after retention=%#v err=%v", currentFindings, err)
	}
	projectID, environmentID, serviceID, deletingServiceID, databaseID, clusterID, upgradeID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	otherProjectID, otherEnvironmentID, otherServiceID, otherDatabaseID, otherClusterID, otherUpgradeID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	backupID, policyID := uuid.New(), uuid.New()
	routeID, otherRouteID := uuid.New(), uuid.New()
	samlProviderID, otherSAMLProviderID := uuid.New(), uuid.New()
	notificationEndpointID, otherNotificationEndpointID := uuid.New(), uuid.New()
	enabledWebhookID, disabledWebhookID, otherWebhookID := uuid.New(), uuid.New(), uuid.New()
	activeDeployTokenID, expiringDeployTokenID, expiredDeployTokenID := uuid.New(), uuid.New(), uuid.New()
	auditArchiveID, disabledAuditArchiveID, otherAuditArchiveID := uuid.New(), uuid.New(), uuid.New()
	auditBackupDestinationID, disabledAuditBackupDestinationID, otherAuditBackupDestinationID := uuid.New(), uuid.New(), uuid.New()
	latestDeploymentAt := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	oldestPendingAt := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Microsecond)
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO projects(id,organization_id,name,slug,description) VALUES($1,$2,'Audit project','audit-project','target-project-description-secret')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug,placement_selector) VALUES($1,$2,'Production','production','{"credential":"target-placement-secret"}')`, []any{environmentID, projectID}},
		{`INSERT INTO project_grants(project_id,user_id,role) VALUES($1,$2,'admin')`, []any{projectID, developerUserID}},
		{`INSERT INTO environment_grants(environment_id,user_id,role) VALUES($1,$2,'viewer')`, []any{environmentID, developerUserID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml,encrypted_env,revision) VALUES($1,$2,'API','api',$3,'services: {api: {image: registry.example.test/private-api:latest, environment: [SECRET_COMPOSE_VALUE]}}','encrypted-service-env',3)`, []any{serviceID, environmentID, "audit-api-" + serviceID.String()}},
		{`INSERT INTO deploy_tokens(id,compose_service_id,token_hash,name,created_by,expires_at,last_used_at) VALUES
			($1,$2,$3,'target-active-deploy-token-secret-name',$4,now()+interval '30 days',now()),
			($5,$2,$6,'target-expiring-deploy-token-secret-name',$4,now()+interval '2 days',NULL),
			($7,$2,$8,'target-expired-deploy-token-secret-name',$4,now()-interval '1 hour',NULL)`, []any{activeDeployTokenID, serviceID, []byte("target-active-deploy-token-hash"), userID, expiringDeployTokenID, []byte("target-expiring-deploy-token-hash"), expiredDeployTokenID, []byte("target-expired-deploy-token-hash")}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml,encrypted_env,deletion_requested_at) VALUES($1,$2,'Deleting worker','deleting-worker',$3,'services: {worker: {image: worker:latest}}','deleting-service-env-secret',now()-interval '5 minutes')`, []any{deletingServiceID, environmentID, "deleting-worker-" + deletingServiceID.String()}},
		{`INSERT INTO jobs(id,kind,payload,status) VALUES($1,'delete.compose',$2,'pending')`, []any{uuid.New(), `{"serviceId":"` + deletingServiceID.String() + `","stackName":"target-deleting-stack-secret"}`}},
		{`INSERT INTO webhook_integrations(id,compose_service_id,name,provider,branch,encrypted_secret,enabled) VALUES($1,$2,'target-github-secret-name','github','target-main-secret',$3,true),($4,$2,'target-gitlab-secret-name','gitlab','target-release-secret',$5,false)`, []any{enabledWebhookID, serviceID, "target-webhook-encrypted-secret", disabledWebhookID, "target-disabled-webhook-encrypted-secret"}},
		{`INSERT INTO routes(id,compose_service_id,service_name,host,path_prefix,target_port,tls,certificate_resolver) VALUES($1,$2,'api','audit-api.example.test','/',8080,false,'letsencrypt')`, []any{routeID, serviceID}},
		{`INSERT INTO service_reconciliations(compose_service_id,state,consecutive_failures,detail,last_checked_at) VALUES($1,'degraded',2,'target-reconciliation-detail-secret',now()-interval '30 seconds')`, []any{serviceID}},
		{`INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,effective_compose,env_snapshot,status,trigger,created_at,finished_at) VALUES($1,$2,3,'services: {api: {image: app:v3}}',$3,'deployment-secret','succeeded','manual',$4::timestamptz - interval '1 minute',$4::timestamptz - interval '30 seconds')`, []any{uuid.New(), serviceID, "services: {api: {image: registry.example.test/private-api@sha256:" + strings.Repeat("b", 64) + "}}", latestDeploymentAt}},
		{`INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,env_snapshot,status,trigger,created_at) VALUES($1,$2,3,'services: {api: {image: app:v3}}','queued-secret','queued','manual',$3)`, []any{uuid.New(), serviceID, latestDeploymentAt}},
		{`INSERT INTO application_sources(compose_service_id,source_type,repository_url,git_ref,build_type,enable_submodules,encrypted_build_config,target_service,registry_image) VALUES($1,'git','ssh://git@target-source-secret.example/repository','main','dockerfile',true,'target-build-config-secret','api','target-registry-secret.example/private/api')`, []any{serviceID}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,encrypted_credentials,status) VALUES($1,$2,'Primary','primary','postgres','17','encrypted','ready')`, []any{databaseID, environmentID}},
		{`INSERT INTO resource_policies(organization_id,scope_type,scope_id,maintenance_enabled,maintenance_reason,max_projects,max_environments,max_services,max_databases) VALUES($1,'organization',$1,true,'policy-secret-marker',1,1,1,1)`, []any{organizationID}},
		{`INSERT INTO dokploy_migration_resources(target_organization_id,source_organization_id,source_kind,source_id,target_id,status,reason,metadata,updated_at) VALUES
			($1,'legacy-org','project','project-1',$2,'imported','','{}',now()-interval '1 minute'),
			($1,'legacy-org','database','postgres:source-db',$3,'imported','','{"private":"migration-metadata-secret"}',now()-interval '1 minute'),
			($1,'legacy-org','volume_backup','volume-1',NULL,'skipped','manual conversion required','{}',now()-interval '1 minute'),
			($4,'other-source-org','database','postgres:other-db',$5,'imported','','{"private":"other-migration-secret"}',now()-interval '1 minute')`, []any{organizationID, projectID, databaseID, otherOrganizationID, otherDatabaseID}},
		{`INSERT INTO database_migrations(id,database_instance_id,source_kind,source_id,source_engine,source_version,source_host,encrypted_source_config,status,finished_at) VALUES($1,$2,'dokploy','source-db','postgres','17','legacy-db.internal','migration-source-secret','succeeded',now())`, []any{uuid.New(), databaseID}},
		{`INSERT INTO backup_policies(id,database_instance_id,interval_seconds,retention_count,enabled,next_run_at,verify_restore) VALUES($1,$2,3600,14,true,now(),true)`, []any{policyID, databaseID}},
		{`INSERT INTO database_backups(id,database_instance_id,status,format,finished_at) VALUES($1,$2,'succeeded','dump',now())`, []any{backupID, databaseID}},
		{`INSERT INTO database_restores(id,database_backup_id,status,kind,finished_at) VALUES($1,$2,'succeeded','drill',now())`, []any{uuid.New(), backupID}},
		{`INSERT INTO clusters(id,organization_id,name,slug,state,labels,capacity,agent_image,agent_update_state,deletion_requested_at) VALUES($1,$2,'Paris','paris','active','{"secret":"target-cluster-label-secret"}','{"secret":"target-cluster-capacity-secret"}',$3,'updating',now()-interval '20 minutes')`, []any{clusterID, organizationID, "registry.example/dockyard@sha256:" + strings.Repeat("a", 64)}},
		{`INSERT INTO cluster_commands(id,cluster_id,kind,encrypted_payload,status,attempts,target_image,last_error,run_after) VALUES($1,$2,'agent.upgrade','agent-command-secret','verifying',1,$3,'target-agent-error-secret',now()-interval '1 minute')`, []any{upgradeID, clusterID, "registry.example/dockyard@sha256:" + strings.Repeat("b", 64)}},
		{`INSERT INTO jobs(id,kind,payload,status,attempts,max_attempts,last_error,finished_at) VALUES($1,'delete.cluster',$2,'failed',10,10,'target-finalizer-error-secret',now()-interval '10 minutes')`, []any{uuid.New(), `{"clusterId":"` + clusterID.String() + `"}`}},
		{`INSERT INTO organization_auth_settings(organization_id,require_sso) VALUES($1,true)`, []any{organizationID}},
		{`INSERT INTO oidc_providers(id,organization_id,name,issuer,client_id,encrypted_client_secret,enabled) VALUES($1,$2,'Company','https://id.example.test','client','encrypted',true)`, []any{uuid.New(), organizationID}},
		{`INSERT INTO saml_providers(id,organization_id,name,idp_metadata,certificate_pem,encrypted_private_key,enabled) VALUES($1,$2,'Target SAML','target-idp-metadata-secret','target-sp-certificate-secret','target-saml-key-secret',true),($3,$4,'Other SAML','other-idp-metadata-secret','other-sp-certificate-secret','other-saml-key-secret',true)`, []any{samlProviderID, organizationID, otherSAMLProviderID, otherOrganizationID}},
		{`INSERT INTO notification_endpoints(id,organization_id,name,kind,encrypted_url,encrypted_secret,events,enabled) VALUES($1,$2,'On-call','webhook','encrypted','encrypted',ARRAY['backup.failed'],true)`, []any{notificationEndpointID, organizationID}},
		{`INSERT INTO notification_endpoints(id,organization_id,name,kind,encrypted_url,encrypted_secret,events,enabled) VALUES($1,$2,'Other','webhook','other-secret-url','other-secret',ARRAY['backup.failed'],true)`, []any{otherNotificationEndpointID, otherOrganizationID}},
		{`INSERT INTO notification_deliveries(id,endpoint_id,event_type,resource_type,resource_id,payload,status) VALUES
				($1,$2,'backup.failed','database','target-1','{"secret":"target-notification-payload-secret"}','succeeded'),
				($3,$2,'backup.failed','database','target-2','{}','failed'),
				($4,$2,'backup.failed','database','target-3','{}','failed'),
				($5,$2,'backup.failed','database','target-4','{}','failed'),
				($6,$7,'backup.failed','database','other-1','{"secret":"other-notification-payload-secret"}','failed'),
				($8,$7,'backup.failed','database','other-2','{}','failed'),
				($9,$7,'backup.failed','database','other-3','{}','failed'),
				($10,$7,'backup.failed','database','other-4','{}','failed')`, []any{uuid.New(), notificationEndpointID, uuid.New(), uuid.New(), uuid.New(), uuid.New(), otherNotificationEndpointID, uuid.New(), uuid.New(), uuid.New()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Other audit project','other-audit-project')`, []any{otherProjectID, otherOrganizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{otherEnvironmentID, otherProjectID}},
		{`INSERT INTO project_grants(project_id,user_id,role) VALUES($1,$2,'admin')`, []any{otherProjectID, otherUserID}},
		{`INSERT INTO environment_grants(environment_id,user_id,role) VALUES($1,$2,'admin')`, []any{otherEnvironmentID, otherUserID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml,encrypted_env,revision) VALUES($1,$2,'Other API','other-api',$3,$4,'other-encrypted-env',7)`, []any{otherServiceID, otherEnvironmentID, "other-audit-api-" + otherServiceID.String(), "services: {api: {image: registry.example.test/other-private-api@sha256:" + strings.Repeat("a", 64) + ", environment: [OTHER_COMPOSE_SECRET]}}"}},
		{`INSERT INTO deploy_tokens(id,compose_service_id,token_hash,name,created_by,expires_at) VALUES($1,$2,$3,'other-deploy-token-secret-name',$4,now()+interval '1 day')`, []any{uuid.New(), otherServiceID, []byte("other-deploy-token-hash"), otherUserID}},
		{`INSERT INTO webhook_integrations(id,compose_service_id,name,provider,branch,encrypted_secret) VALUES($1,$2,'other-webhook-secret-name','bitbucket','other-main-secret',$3)`, []any{otherWebhookID, otherServiceID, "other-webhook-encrypted-secret"}},
		{`INSERT INTO routes(id,compose_service_id,service_name,host,path_prefix,target_port,tls,certificate_resolver) VALUES($1,$2,'api','other-audit-api.example.test','/',8080,true,'letsencrypt')`, []any{otherRouteID, otherServiceID}},
		{`INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,env_snapshot,status,trigger,created_at) VALUES($1,$2,7,'services: {api: {image: other:v7}}','other-deployment-secret','failed','manual',now())`, []any{uuid.New(), otherServiceID}},
		{`INSERT INTO application_sources(compose_service_id,source_type,repository_url,git_ref,build_type,encrypted_build_config,target_service,registry_image) VALUES($1,'git','https://other-source-secret.example/repository','main','dockerfile','other-build-config-secret','api','other-registry-secret.example/private/api')`, []any{otherServiceID}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,encrypted_credentials,status) VALUES($1,$2,'Other primary','other-primary','postgres','17','other-database-secret','ready')`, []any{otherDatabaseID, otherEnvironmentID}},
		{`INSERT INTO resource_policies(organization_id,scope_type,scope_id,maintenance_enabled,maintenance_reason,max_projects) VALUES($1,'organization',$1,true,'other-policy-secret',1)`, []any{otherOrganizationID}},
		{`INSERT INTO clusters(id,organization_id,name,slug,state,deletion_requested_at) VALUES($1,$2,'Other cluster','other-cluster','active',now()-interval '1 day')`, []any{otherClusterID, otherOrganizationID}},
		{`INSERT INTO cluster_commands(id,cluster_id,kind,encrypted_payload,status,attempts,target_image,last_error,finished_at) VALUES($1,$2,'agent.upgrade','other-agent-command-secret','failed',1,$3,'other tenant failure',now())`, []any{otherUpgradeID, otherClusterID, "registry.example/dockyard@sha256:" + strings.Repeat("c", 64)}},
		{`INSERT INTO jobs(id,kind,payload,status) VALUES($1,'delete.cluster',$2,'pending')`, []any{uuid.New(), `{"clusterId":"` + otherClusterID.String() + `"}`}},
		{`INSERT INTO jobs(id,kind,payload,status,resource_key,created_at) VALUES($1,'deploy.compose','{"secret":"job-secret-payload"}','pending',$2,$3)`, []any{uuid.New(), "service:" + serviceID.String(), oldestPendingAt}},
		{`INSERT INTO jobs(id,kind,payload,status,resource_key,created_at) VALUES($1,'deploy.compose','{}','running',$2,now())`, []any{uuid.New(), "service:" + serviceID.String()}},
		{`INSERT INTO jobs(id,kind,payload,status,resource_key,created_at) VALUES($1,'backup.database','{}','pending',$2,$3::timestamptz + interval '30 minutes')`, []any{uuid.New(), "database:" + databaseID.String(), oldestPendingAt}},
		{`INSERT INTO jobs(id,kind,payload,status,resource_key,created_at) VALUES($1,'restore.database','{}','running',$2,now())`, []any{uuid.New(), "database:" + databaseID.String()}},
		{`INSERT INTO jobs(id,kind,payload,status,resource_key,created_at) VALUES($1,'deploy.compose','{}','pending',$2,now() - interval '1 day')`, []any{uuid.New(), "service:" + otherServiceID.String()}},
		{`INSERT INTO jobs(id,kind,payload,status,resource_key,created_at) VALUES($1,'backup.database','{}','running',$2,now())`, []any{uuid.New(), "database:" + otherDatabaseID.String()}},
		{`INSERT INTO jobs(id,kind,payload,status,resource_key,created_at) VALUES($1,'unknown','{}','pending','service:not-a-uuid',now() - interval '2 days')`, []any{uuid.New()}},
	} {
		if _, err = pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	var archivedAuditEventID, unarchivedAuditEventID int64
	if err = pool.QueryRow(ctx, `INSERT INTO audit_events(organization_id,action,resource_type,created_at) VALUES($1,'archive-fixture','test',now()-interval '11 minutes') RETURNING id`, organizationID).Scan(&archivedAuditEventID); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `INSERT INTO audit_events(organization_id,action,resource_type,metadata,created_at) VALUES($1,'archive-pending','test','{"secret":"target-audit-metadata-secret"}',now()-interval '10 minutes') RETURNING id`, organizationID).Scan(&unarchivedAuditEventID); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO audit_retention_policies(organization_id,retention_days) VALUES($1,730)`, []any{organizationID}},
		{`INSERT INTO backup_destinations(id,organization_id,name,endpoint,bucket,use_tls,encrypted_credentials) VALUES($1,$2,'target-archive-secret-name','https://s3.example.test','target-secret-bucket',true,'target-archive-credentials-secret'),($3,$2,'disabled-archive-secret-name','http://target-plaintext-storage-secret.example.test','disabled-secret-bucket',false,'disabled-archive-credentials-secret'),($4,$5,'other-archive-secret-name','http://other-plaintext-storage-secret.example.test','other-secret-bucket',false,'other-archive-credentials-secret')`, []any{auditBackupDestinationID, organizationID, disabledAuditBackupDestinationID, otherAuditBackupDestinationID, otherOrganizationID}},
		{`INSERT INTO audit_archive_destinations(id,organization_id,backup_destination_id,name,object_prefix,retention_days,enabled,last_archived_id,last_chain_hash) VALUES($1,$2,$3,'target-archive-secret-name','target-secret-prefix',730,true,$4,'target-chain-secret'),($5,$2,$6,'disabled-archive-secret-name','disabled-secret-prefix',365,false,0,'disabled-chain-secret'),($7,$8,$9,'other-archive-secret-name','other-secret-prefix',365,true,0,'other-chain-secret')`, []any{auditArchiveID, organizationID, auditBackupDestinationID, archivedAuditEventID, disabledAuditArchiveID, disabledAuditBackupDestinationID, otherAuditArchiveID, otherOrganizationID, otherAuditBackupDestinationID}},
		{`INSERT INTO audit_archive_batches(id,destination_id,first_event_id,last_event_id,previous_sha256,object_key,status,last_error,created_at,finished_at) VALUES($1,$2,$3,$3,'target-chain-secret','target-secret-object','failed','target-archive-error-secret',now()-interval '9 minutes',now()-interval '8 minutes')`, []any{uuid.New(), auditArchiveID, unarchivedAuditEventID}},
		{`INSERT INTO audit_events(organization_id,action,resource_type,metadata,created_at) VALUES($1,'other-archive-pending','test','{"secret":"other-audit-metadata-secret"}',now()-interval '1 day')`, []any{otherOrganizationID}},
	} {
		if _, err = pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := db.BuildAIAuditSnapshot(ctx, organizationID)
	if err != nil || snapshot.Organization != organizationID {
		t.Fatalf("snapshot=%#v err=%v", snapshot, err)
	}
	if len(snapshot.Projects) != 1 || snapshot.Projects[0].ID != projectID || len(snapshot.Environments) != 1 || snapshot.Environments[0].ID != environmentID || !snapshot.Environments[0].PlacementSelectorConfigured {
		t.Fatalf("inventory projection projects=%#v environments=%#v", snapshot.Projects, snapshot.Environments)
	}
	if len(snapshot.BackupPosture) != 1 || snapshot.BackupPosture[0].DatabaseID != databaseID || !snapshot.BackupPosture[0].VerifyRestore || snapshot.BackupPosture[0].LastBackupStatus != "succeeded" || snapshot.BackupPosture[0].LastRestoreDrillStatus != "succeeded" {
		t.Fatalf("backup posture=%#v", snapshot.BackupPosture)
	}
	if len(snapshot.Routes) != 1 || snapshot.Routes[0].ID != routeID || snapshot.Routes[0].ComposeServiceID != serviceID || snapshot.Routes[0].TLS {
		t.Fatalf("route posture=%#v", snapshot.Routes)
	}
	if len(snapshot.WorkloadPosture) != 1 || snapshot.WorkloadPosture[0].ServiceID != serviceID || !snapshot.WorkloadPosture[0].DefinitionParseable || snapshot.WorkloadPosture[0].ContainerCount != 1 || snapshot.WorkloadPosture[0].MutableImages != 1 || snapshot.WorkloadPosture[0].DigestPinnedImages != 0 || snapshot.WorkloadPosture[0].BuildOnlyServices != 0 || snapshot.WorkloadPosture[0].MissingImageOrBuild != 0 || !snapshot.WorkloadPosture[0].SuccessfulDeployment || !snapshot.WorkloadPosture[0].RuntimeSnapshotAvailable || !snapshot.WorkloadPosture[0].RuntimeDefinitionParseable || snapshot.WorkloadPosture[0].RuntimeContainerCount != 1 || snapshot.WorkloadPosture[0].RuntimeDigestPinnedImages != 1 || snapshot.WorkloadPosture[0].RuntimeMutableImages != 0 {
		t.Fatalf("workload posture=%#v", snapshot.WorkloadPosture)
	}
	if len(snapshot.SourceBuildPosture) != 1 {
		t.Fatalf("source build posture=%#v", snapshot.SourceBuildPosture)
	}
	sourcePosture := snapshot.SourceBuildPosture[0]
	if sourcePosture.ServiceID != serviceID || sourcePosture.SourceType != "git" || sourcePosture.BuildType != "dockerfile" || sourcePosture.RepositoryTransport != "ssh" || sourcePosture.GitRefPinned || sourcePosture.GitCredentialConfigured || sourcePosture.RegistryCredentialConfigured || sourcePosture.StatusReportingConfigured || !sourcePosture.SubmodulesEnabled || !sourcePosture.BuildConfigurationConfigured || sourcePosture.ArtifactPresent || sourcePosture.ArtifactChecksumRecorded || sourcePosture.CurrentSourceDeployed || sourcePosture.DeploymentCommitRecorded {
		t.Fatalf("source build posture=%#v", sourcePosture)
	}
	if len(snapshot.ResourcePolicies) != 1 || snapshot.ResourcePolicies[0].ScopeID != organizationID || !snapshot.ResourcePolicies[0].Maintenance || snapshot.ResourcePolicies[0].CurrentProjects != 1 || snapshot.ResourcePolicies[0].CurrentEnvironments != 1 || snapshot.ResourcePolicies[0].CurrentServices != 1 || snapshot.ResourcePolicies[0].CurrentDatabases != 1 {
		t.Fatalf("resource policy posture=%#v", snapshot.ResourcePolicies)
	}
	if snapshot.AuditLogPosture.RetentionDays != 730 || snapshot.AuditLogPosture.CurrentMaxEventID != unarchivedAuditEventID || snapshot.AuditLogPosture.EnabledArchives != 1 || snapshot.AuditLogPosture.DisabledArchives != 1 || len(snapshot.AuditLogPosture.Destinations) != 2 {
		t.Fatalf("audit log posture=%#v", snapshot.AuditLogPosture)
	}
	archivePosture := map[uuid.UUID]AIAuditArchivePosture{}
	for _, item := range snapshot.AuditLogPosture.Destinations {
		archivePosture[item.ID] = item
	}
	if item := archivePosture[auditArchiveID]; !item.Enabled || item.RetentionDays != 730 || item.LastArchivedID != archivedAuditEventID || item.UnarchivedEvents != 1 || item.OldestUnarchivedAt == nil || item.LatestBatchStatus != "failed" || item.LatestBatchCreatedAt == nil || item.LatestBatchFinishedAt == nil {
		t.Fatalf("enabled audit archive posture=%#v", item)
	}
	if item := archivePosture[disabledAuditArchiveID]; item.Enabled || item.RetentionDays != 365 {
		t.Fatalf("disabled audit archive posture=%#v", item)
	}
	if len(snapshot.AgentUpgradePosture) != 1 || snapshot.AgentUpgradePosture[0].ClusterID != clusterID || snapshot.AgentUpgradePosture[0].CommandID != upgradeID || snapshot.AgentUpgradePosture[0].Status != "verifying" || !snapshot.AgentUpgradePosture[0].VerificationOverdue || snapshot.AgentUpgradePosture[0].VerificationDeadline == nil {
		t.Fatalf("agent upgrade posture=%#v", snapshot.AgentUpgradePosture)
	}
	if !snapshot.IdentityPosture.RequireSSO || snapshot.IdentityPosture.EnabledOIDCProviders != 1 || snapshot.IdentityPosture.EnabledSAMLProviders != 1 || snapshot.IdentityPosture.ActiveMembers != 2 || snapshot.IdentityPosture.ActiveOwners != 1 || snapshot.IdentityPosture.ActiveAdmins != 0 || snapshot.IdentityPosture.ActiveDevelopers != 1 || snapshot.IdentityPosture.ActiveViewers != 0 || snapshot.IdentityPosture.DisabledMembers != 1 {
		t.Fatalf("identity membership posture=%#v", snapshot.IdentityPosture)
	}
	if snapshot.IdentityPosture.ActiveLocalSessions != 1 || snapshot.IdentityPosture.ActiveOIDCSessions != 1 || snapshot.IdentityPosture.ActiveSAMLSessions != 0 || snapshot.IdentityPosture.ActiveServiceAccounts != 2 || snapshot.IdentityPosture.ActivePrivilegedServiceAccounts != 1 || snapshot.IdentityPosture.ExpiringServiceAccounts != 1 || snapshot.IdentityPosture.ActiveAuditorServiceAccounts != 1 || snapshot.IdentityPosture.ActiveSCIMTokens != 1 || snapshot.IdentityPosture.OldestActiveSCIMTokenCreatedAt == nil || !snapshot.IdentityPosture.OldestActiveSCIMTokenCreatedAt.Equal(scimTokenCreatedAt) {
		t.Fatalf("identity posture=%#v", snapshot.IdentityPosture)
	}
	if snapshot.IdentityPosture.PendingInvitations != 2 || snapshot.IdentityPosture.PendingPrivilegedInvitations != 1 || snapshot.IdentityPosture.InvitationsExpiringSoon != 1 || snapshot.IdentityPosture.ExpiredInvitations != 1 || snapshot.IdentityPosture.ProjectScopedGrants != 1 || snapshot.IdentityPosture.EnvironmentScopedGrants != 1 || snapshot.IdentityPosture.AdminScopedGrants != 1 || snapshot.IdentityPosture.RedundantScopedGrants != 1 || snapshot.IdentityPosture.SCIMGroups != 2 || snapshot.IdentityPosture.WriteCapableSCIMGroups != 1 || snapshot.IdentityPosture.SCIMGroupMemberships != 2 {
		t.Fatalf("identity governance posture=%#v", snapshot.IdentityPosture)
	}
	if snapshot.DeployTokenPosture.ActiveTokens != 2 || snapshot.DeployTokenPosture.ExpiringTokens != 1 || snapshot.DeployTokenPosture.ExpiredUnrevokedTokens != 1 || snapshot.DeployTokenPosture.UnusedActiveTokens != 1 || snapshot.DeployTokenPosture.OldestActiveTokenCreatedAt == nil {
		t.Fatalf("deploy token posture=%#v", snapshot.DeployTokenPosture)
	}
	if len(snapshot.SAMLPosture) != 1 || snapshot.SAMLPosture[0].ID != samlProviderID || snapshot.SAMLPosture[0].CertificateConfigurationOK || snapshot.SAMLPosture[0].SPCertificateNotAfter != nil || snapshot.SAMLPosture[0].IDPCertificateNotAfter != nil {
		t.Fatalf("SAML posture=%#v", snapshot.SAMLPosture)
	}
	if len(snapshot.NotificationPosture) != 1 || snapshot.NotificationPosture[0].Name != "On-call" {
		t.Fatalf("notification posture=%#v", snapshot.NotificationPosture)
	}
	webhookPosture := map[uuid.UUID]AIAuditWebhookPosture{}
	for _, item := range snapshot.WebhookPosture {
		webhookPosture[item.ID] = item
	}
	if len(webhookPosture) != 2 || webhookPosture[enabledWebhookID].ComposeServiceID != serviceID || webhookPosture[enabledWebhookID].Provider != "github" || !webhookPosture[enabledWebhookID].Enabled || webhookPosture[disabledWebhookID].Provider != "gitlab" || webhookPosture[disabledWebhookID].Enabled {
		t.Fatalf("webhook posture=%#v", snapshot.WebhookPosture)
	}
	backupDestinationPosture := map[uuid.UUID]AIAuditBackupDestinationInfo{}
	for _, item := range snapshot.BackupDestinations {
		backupDestinationPosture[item.ID] = item
	}
	if len(backupDestinationPosture) != 2 || !backupDestinationPosture[auditBackupDestinationID].UseTLS || backupDestinationPosture[auditBackupDestinationID].AuditArchives != 1 || backupDestinationPosture[disabledAuditBackupDestinationID].UseTLS || backupDestinationPosture[disabledAuditBackupDestinationID].AuditArchives != 1 {
		t.Fatalf("backup destination posture=%#v", snapshot.BackupDestinations)
	}
	signalCounts := map[string]int64{}
	for _, signal := range snapshot.Signals {
		signalCounts[signal.Kind+":"+signal.Status] = signal.Count
	}
	if signalCounts["notification:succeeded"] != 1 || signalCounts["notification:failed"] != 3 || signalCounts["database_migration:succeeded"] != 1 || signalCounts["audit_archive:failed"] != 1 || signalCounts["agent_command:verifying"] != 1 || signalCounts["agent_command:failed"] != 0 {
		t.Fatalf("tenant-scoped operational signals=%#v", snapshot.Signals)
	}
	if len(snapshot.TemplateRepositories) != 1 || snapshot.TemplateRepositories[0].ID != repository.ID || !snapshot.TemplateRepositories[0].RequireSignature || !snapshot.TemplateRepositories[0].CredentialConfigured || !snapshot.TemplateRepositories[0].WebhookConfigured {
		t.Fatalf("template repository posture=%#v", snapshot.TemplateRepositories)
	}
	if len(snapshot.MigrationPosture) != 1 || snapshot.MigrationPosture[0].SourceOrganizationID != "legacy-org" || snapshot.MigrationPosture[0].Resources != 3 || snapshot.MigrationPosture[0].Imported != 2 || snapshot.MigrationPosture[0].Unresolved != 1 || snapshot.MigrationPosture[0].Databases != 1 || snapshot.MigrationPosture[0].SuccessfulDatabaseTransfers != 1 {
		t.Fatalf("migration posture=%#v", snapshot.MigrationPosture)
	}
	if len(snapshot.MigrationBlockers) != 1 || snapshot.MigrationBlockers[0].SourceOrganizationID != "legacy-org" || snapshot.MigrationBlockers[0].SourceKind != "volume_backup" || snapshot.MigrationBlockers[0].SourceID != "volume-1" || snapshot.MigrationBlockers[0].Reason == "" {
		t.Fatalf("migration blockers=%#v", snapshot.MigrationBlockers)
	}
	if len(snapshot.ServiceDeployments) != 1 || snapshot.ServiceDeployments[0].ServiceID != serviceID || snapshot.ServiceDeployments[0].DesiredRevision != 3 || snapshot.ServiceDeployments[0].LatestDeploymentStatus != "queued" || snapshot.ServiceDeployments[0].LatestDeploymentRevision != 3 || snapshot.ServiceDeployments[0].LatestDeploymentAt == nil || !snapshot.ServiceDeployments[0].LatestDeploymentAt.Equal(latestDeploymentAt) || !snapshot.ServiceDeployments[0].CurrentRevisionDeployed {
		t.Fatalf("service deployment posture=%#v", snapshot.ServiceDeployments)
	}
	if len(snapshot.Reconciliation) != 1 || snapshot.Reconciliation[0].ComposeServiceID != serviceID || snapshot.Reconciliation[0].State != "degraded" || snapshot.Reconciliation[0].ConsecutiveFailures != 2 {
		t.Fatalf("reconciliation posture=%#v", snapshot.Reconciliation)
	}
	if snapshot.QueuePosture.Coverage != "resource-keyed-service-and-database-jobs" || snapshot.QueuePosture.PendingServiceJobs != 1 || snapshot.QueuePosture.RunningServiceJobs != 1 || snapshot.QueuePosture.PendingDatabaseJobs != 1 || snapshot.QueuePosture.RunningDatabaseJobs != 1 || snapshot.QueuePosture.OldestPendingAt == nil || !snapshot.QueuePosture.OldestPendingAt.Equal(oldestPendingAt) {
		t.Fatalf("queue posture=%#v", snapshot.QueuePosture)
	}
	if snapshot.FinalizerPosture.DeletingProjects != 0 || snapshot.FinalizerPosture.DeletingEnvironments != 0 || snapshot.FinalizerPosture.DeletingServices != 1 || snapshot.FinalizerPosture.DeletingClusters != 1 || snapshot.FinalizerPosture.PendingJobs != 1 || snapshot.FinalizerPosture.RunningJobs != 0 || snapshot.FinalizerPosture.FailedJobs != 1 || snapshot.FinalizerPosture.ResourcesWithoutActiveJob != 1 || snapshot.FinalizerPosture.OldestRequestedAt == nil {
		t.Fatalf("finalizer posture=%#v", snapshot.FinalizerPosture)
	}
	encodedSnapshot, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	for _, secret := range []string{"target-active-deploy-token-secret-name", "target-active-deploy-token-hash", "target-expiring-deploy-token-secret-name", "target-expiring-deploy-token-hash", "target-expired-deploy-token-secret-name", "target-expired-deploy-token-hash", "other-deploy-token-secret-name", "other-deploy-token-hash"} {
		if strings.Contains(string(encodedSnapshot), secret) {
			t.Fatalf("snapshot leaked deploy token material %q: body=%s", secret, encodedSnapshot)
		}
	}
	if strings.Contains(string(encodedSnapshot), "target-finalizer-error-secret") || strings.Contains(string(encodedSnapshot), "target-deleting-stack-secret") || strings.Contains(string(encodedSnapshot), "deleting-service-env-secret") {
		t.Fatalf("snapshot leaked finalizer error: body=%s", encodedSnapshot)
	}
	if strings.Contains(string(encodedSnapshot), deletingServiceID.String()) {
		t.Fatalf("snapshot leaked deleting resource identity %s: body=%s", deletingServiceID, encodedSnapshot)
	}
	for _, secret := range []string{"target-admin-invitation-token-hash", "target-viewer-invitation-token-hash", "target-expired-invitation-token-hash", "other-admin-invitation-token-hash", "target-admin-group-external-secret", "Target administrators secret name", "target-viewer-group-external-secret", "Target viewers secret name", "other-group-external-secret", "Other tenant group secret name", "target-github-secret-name", "target-main-secret", "target-webhook-encrypted-secret", "target-gitlab-secret-name", "target-release-secret", "target-disabled-webhook-encrypted-secret", "other-webhook-secret-name", "other-main-secret", "other-webhook-encrypted-secret", "target-plaintext-storage-secret.example.test", "other-plaintext-storage-secret.example.test"} {
		if strings.Contains(string(encodedSnapshot), secret) {
			t.Fatalf("snapshot leaked identity governance secret %q: body=%s", secret, encodedSnapshot)
		}
	}
	for _, secret := range []string{"encrypted-webhook-secret", "other-secret", "policy-secret-marker", "other-policy-secret", "target-project-description-secret", "target-placement-secret", "target-cluster-label-secret", "target-cluster-capacity-secret", "SECRET_COMPOSE_VALUE", "registry.example.test/private-api", "encrypted-service-env", "deployment-secret", "queued-secret", "job-secret-payload", "agent-command-secret", "target-agent-error-secret", "target-reconciliation-detail-secret", "migration-metadata-secret", "migration-source-secret", "OTHER_COMPOSE_SECRET", "registry.example.test/other-private-api", "other-encrypted-env", "other-deployment-secret", "other-database-secret", "other-agent-command-secret", "other-migration-secret", "other-source-org", "target-source-secret.example", "target-build-config-secret", "target-registry-secret.example", "other-source-secret.example", "other-build-config-secret", "other-registry-secret.example", "target-notification-payload-secret", "other-notification-payload-secret", "target-archive-secret-name", "target-secret-bucket", "target-archive-credentials-secret", "target-secret-prefix", "target-chain-secret", "target-secret-object", "target-archive-error-secret", "target-audit-metadata-secret", "disabled-archive-secret-name", "disabled-secret-bucket", "disabled-archive-credentials-secret", "disabled-secret-prefix", "disabled-chain-secret", "other-archive-secret-name", "other-secret-bucket", "other-archive-credentials-secret", "other-secret-prefix", "other-chain-secret", "other-audit-metadata-secret", "target-idp-metadata-secret", "target-sp-certificate-secret", "target-saml-key-secret", "other-idp-metadata-secret", "other-sp-certificate-secret", "other-saml-key-secret"} {
		if strings.Contains(string(encodedSnapshot), secret) {
			t.Fatalf("snapshot leaked %q: body=%s", secret, encodedSnapshot)
		}
	}
	for _, otherTenantID := range []uuid.UUID{otherProjectID, otherEnvironmentID, otherServiceID, otherDatabaseID, otherClusterID, otherUpgradeID, otherRouteID, otherSAMLProviderID, otherWebhookID, otherAuditArchiveID, otherAuditBackupDestinationID} {
		if strings.Contains(string(encodedSnapshot), otherTenantID.String()) {
			t.Fatalf("snapshot leaked cross-tenant resource %s: body=%s", otherTenantID, encodedSnapshot)
		}
	}
	if err = db.DeleteTemplateRepository(ctx, organizationID, repository.ID); err != nil {
		t.Fatal(err)
	}
	listed, err = db.ListTemplates(ctx, organizationID)
	if err != nil || len(listed) != 0 {
		t.Fatalf("templates remained after delete: %#v err=%v", listed, err)
	}
	_ = template
}
