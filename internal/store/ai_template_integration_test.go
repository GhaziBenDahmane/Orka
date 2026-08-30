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
	} {
		if _, err = pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = db.CreateTemplateRepository(ctx, TemplateRepository{OrganizationID: otherOrganizationID, Name: "Wrong scope", Slug: "wrong-scope", RepositoryURL: "https://github.com/acme/templates", GitRef: "main", CredentialID: &credentialID}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-organization catalog credential accepted: %v", err)
	}
	claimed, err := db.ClaimDueTemplateRepository(ctx)
	if err != nil || claimed.ID != repository.ID || claimed.LastSyncStatus != "running" {
		t.Fatalf("claimed repository=%#v err=%v", claimed, err)
	}
	if _, err = db.ClaimDueTemplateRepository(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("running repository was claimed twice: %v", err)
	}
	if err = db.FinishTemplateRepositorySync(ctx, claimed, "succeeded", ""); err != nil {
		t.Fatal(err)
	}
	loaded, err = db.GetTemplateRepository(ctx, organizationID, repository.ID)
	if err != nil || loaded.NextSyncAt == nil || !loaded.NextSyncAt.After(time.Now()) || loaded.LastSyncStatus != "succeeded" {
		t.Fatalf("completed repository schedule=%#v err=%v", loaded, err)
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
	if err = db.ReplaceRepositoryTemplates(ctx, organizationID, repository.ID, []Template{replacement}); err != nil {
		t.Fatal(err)
	}
	listed, err = db.ListTemplates(ctx, organizationID)
	if err != nil || len(listed) != 1 || listed[0].Key != "community/replacement" {
		t.Fatalf("repository snapshot was not reconciled atomically: templates=%#v err=%v", listed, err)
	}
	badScope := replacement
	badScope.OrganizationID = &otherOrganizationID
	if err = db.ReplaceRepositoryTemplates(ctx, organizationID, repository.ID, []Template{badScope}); err == nil {
		t.Fatal("repository snapshot accepted a cross-tenant template")
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
	projectID, environmentID, serviceID, databaseID, clusterID, upgradeID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	otherProjectID, otherEnvironmentID, otherServiceID, otherDatabaseID, otherClusterID, otherUpgradeID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	backupID, policyID := uuid.New(), uuid.New()
	latestDeploymentAt := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	oldestPendingAt := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Microsecond)
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Audit project','audit-project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml,encrypted_env,revision) VALUES($1,$2,'API','api',$3,'services: {api: {environment: [SECRET_COMPOSE_VALUE]}}','encrypted-service-env',3)`, []any{serviceID, environmentID, "audit-api-" + serviceID.String()}},
		{`INSERT INTO service_reconciliations(compose_service_id,state,consecutive_failures,detail,last_checked_at) VALUES($1,'degraded',2,'replica shortfall',now()-interval '30 seconds')`, []any{serviceID}},
		{`INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,env_snapshot,status,trigger,created_at,finished_at) VALUES($1,$2,3,'services: {api: {image: app:v3}}','deployment-secret','succeeded','manual',$3::timestamptz - interval '1 minute',$3::timestamptz - interval '30 seconds')`, []any{uuid.New(), serviceID, latestDeploymentAt}},
		{`INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,env_snapshot,status,trigger,created_at) VALUES($1,$2,3,'services: {api: {image: app:v3}}','queued-secret','queued','manual',$3)`, []any{uuid.New(), serviceID, latestDeploymentAt}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,encrypted_credentials,status) VALUES($1,$2,'Primary','primary','postgres','17','encrypted','ready')`, []any{databaseID, environmentID}},
		{`INSERT INTO dokploy_migration_resources(target_organization_id,source_organization_id,source_kind,source_id,target_id,status,reason,metadata,updated_at) VALUES
			($1,'legacy-org','project','project-1',$2,'imported','','{}',now()-interval '1 minute'),
			($1,'legacy-org','database','postgres:source-db',$3,'imported','','{"private":"migration-metadata-secret"}',now()-interval '1 minute'),
			($1,'legacy-org','volume_backup','volume-1',NULL,'skipped','manual conversion required','{}',now()-interval '1 minute'),
			($4,'other-source-org','database','postgres:other-db',$5,'imported','','{"private":"other-migration-secret"}',now()-interval '1 minute')`, []any{organizationID, projectID, databaseID, otherOrganizationID, otherDatabaseID}},
		{`INSERT INTO database_migrations(id,database_instance_id,source_kind,source_id,source_engine,source_version,source_host,encrypted_source_config,status,finished_at) VALUES($1,$2,'dokploy','source-db','postgres','17','legacy-db.internal','migration-source-secret','succeeded',now())`, []any{uuid.New(), databaseID}},
		{`INSERT INTO backup_policies(id,database_instance_id,interval_seconds,retention_count,enabled,next_run_at,verify_restore) VALUES($1,$2,3600,14,true,now(),true)`, []any{policyID, databaseID}},
		{`INSERT INTO database_backups(id,database_instance_id,status,format,finished_at) VALUES($1,$2,'succeeded','dump',now())`, []any{backupID, databaseID}},
		{`INSERT INTO database_restores(id,database_backup_id,status,kind,finished_at) VALUES($1,$2,'succeeded','drill',now())`, []any{uuid.New(), backupID}},
		{`INSERT INTO clusters(id,organization_id,name,slug,state,agent_image,agent_update_state) VALUES($1,$2,'Paris','paris','active',$3,'updating')`, []any{clusterID, organizationID, "registry.example/dockyard@sha256:" + strings.Repeat("a", 64)}},
		{`INSERT INTO cluster_commands(id,cluster_id,kind,encrypted_payload,status,attempts,target_image,run_after) VALUES($1,$2,'agent.upgrade','agent-command-secret','verifying',1,$3,now()-interval '1 minute')`, []any{upgradeID, clusterID, "registry.example/dockyard@sha256:" + strings.Repeat("b", 64)}},
		{`INSERT INTO organization_auth_settings(organization_id,require_sso) VALUES($1,true)`, []any{organizationID}},
		{`INSERT INTO oidc_providers(id,organization_id,name,issuer,client_id,encrypted_client_secret,enabled) VALUES($1,$2,'Company','https://id.example.test','client','encrypted',true)`, []any{uuid.New(), organizationID}},
		{`INSERT INTO saml_providers(id,organization_id,name,idp_metadata,certificate_pem,encrypted_private_key,enabled) VALUES($1,$2,'Legacy','metadata','certificate','encrypted',false)`, []any{uuid.New(), organizationID}},
		{`INSERT INTO notification_endpoints(id,organization_id,name,kind,encrypted_url,encrypted_secret,events,enabled) VALUES($1,$2,'On-call','webhook','encrypted','encrypted',ARRAY['backup.failed'],true)`, []any{uuid.New(), organizationID}},
		{`INSERT INTO notification_endpoints(id,organization_id,name,kind,encrypted_url,encrypted_secret,events,enabled) VALUES($1,$2,'Other','webhook','other-secret-url','other-secret',ARRAY['backup.failed'],true)`, []any{uuid.New(), otherOrganizationID}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Other audit project','other-audit-project')`, []any{otherProjectID, otherOrganizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{otherEnvironmentID, otherProjectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml,encrypted_env,revision) VALUES($1,$2,'Other API','other-api',$3,'services: {api: {environment: [OTHER_COMPOSE_SECRET]}}','other-encrypted-env',7)`, []any{otherServiceID, otherEnvironmentID, "other-audit-api-" + otherServiceID.String()}},
		{`INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,env_snapshot,status,trigger,created_at) VALUES($1,$2,7,'services: {api: {image: other:v7}}','other-deployment-secret','failed','manual',now())`, []any{uuid.New(), otherServiceID}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,encrypted_credentials,status) VALUES($1,$2,'Other primary','other-primary','postgres','17','other-database-secret','ready')`, []any{otherDatabaseID, otherEnvironmentID}},
		{`INSERT INTO clusters(id,organization_id,name,slug,state) VALUES($1,$2,'Other cluster','other-cluster','active')`, []any{otherClusterID, otherOrganizationID}},
		{`INSERT INTO cluster_commands(id,cluster_id,kind,encrypted_payload,status,attempts,target_image,last_error,finished_at) VALUES($1,$2,'agent.upgrade','other-agent-command-secret','failed',1,$3,'other tenant failure',now())`, []any{otherUpgradeID, otherClusterID, "registry.example/dockyard@sha256:" + strings.Repeat("c", 64)}},
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
	snapshot, err := db.BuildAIAuditSnapshot(ctx, organizationID)
	if err != nil || snapshot.Organization != organizationID {
		t.Fatalf("snapshot=%#v err=%v", snapshot, err)
	}
	if len(snapshot.BackupPosture) != 1 || snapshot.BackupPosture[0].DatabaseID != databaseID || !snapshot.BackupPosture[0].VerifyRestore || snapshot.BackupPosture[0].LastBackupStatus != "succeeded" || snapshot.BackupPosture[0].LastRestoreDrillStatus != "succeeded" {
		t.Fatalf("backup posture=%#v", snapshot.BackupPosture)
	}
	if len(snapshot.AgentUpgradePosture) != 1 || snapshot.AgentUpgradePosture[0].ClusterID != clusterID || snapshot.AgentUpgradePosture[0].CommandID != upgradeID || snapshot.AgentUpgradePosture[0].Status != "verifying" || !snapshot.AgentUpgradePosture[0].VerificationOverdue || snapshot.AgentUpgradePosture[0].VerificationDeadline == nil {
		t.Fatalf("agent upgrade posture=%#v", snapshot.AgentUpgradePosture)
	}
	if !snapshot.IdentityPosture.RequireSSO || snapshot.IdentityPosture.EnabledOIDCProviders != 1 || snapshot.IdentityPosture.EnabledSAMLProviders != 0 || snapshot.IdentityPosture.ActiveMembers != 2 || snapshot.IdentityPosture.ActiveOwners != 1 || snapshot.IdentityPosture.ActiveAdmins != 0 || snapshot.IdentityPosture.ActiveDevelopers != 1 || snapshot.IdentityPosture.ActiveViewers != 0 || snapshot.IdentityPosture.DisabledMembers != 1 {
		t.Fatalf("identity membership posture=%#v", snapshot.IdentityPosture)
	}
	if snapshot.IdentityPosture.ActiveLocalSessions != 1 || snapshot.IdentityPosture.ActiveOIDCSessions != 1 || snapshot.IdentityPosture.ActiveSAMLSessions != 0 || snapshot.IdentityPosture.ActiveServiceAccounts != 2 || snapshot.IdentityPosture.ActivePrivilegedServiceAccounts != 1 || snapshot.IdentityPosture.ExpiringServiceAccounts != 1 || snapshot.IdentityPosture.ActiveAuditorServiceAccounts != 1 || snapshot.IdentityPosture.ActiveSCIMTokens != 1 || snapshot.IdentityPosture.OldestActiveSCIMTokenCreatedAt == nil || !snapshot.IdentityPosture.OldestActiveSCIMTokenCreatedAt.Equal(scimTokenCreatedAt) {
		t.Fatalf("identity posture=%#v", snapshot.IdentityPosture)
	}
	if len(snapshot.NotificationPosture) != 1 || snapshot.NotificationPosture[0].Name != "On-call" {
		t.Fatalf("notification posture=%#v", snapshot.NotificationPosture)
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
	if len(snapshot.Reconciliation) != 1 || snapshot.Reconciliation[0].ComposeServiceID != serviceID || snapshot.Reconciliation[0].State != "degraded" || snapshot.Reconciliation[0].ConsecutiveFailures != 2 || snapshot.Reconciliation[0].Detail != "replica shortfall" {
		t.Fatalf("reconciliation posture=%#v", snapshot.Reconciliation)
	}
	if snapshot.QueuePosture.Coverage != "resource-keyed-service-and-database-jobs" || snapshot.QueuePosture.PendingServiceJobs != 1 || snapshot.QueuePosture.RunningServiceJobs != 1 || snapshot.QueuePosture.PendingDatabaseJobs != 1 || snapshot.QueuePosture.RunningDatabaseJobs != 1 || snapshot.QueuePosture.OldestPendingAt == nil || !snapshot.QueuePosture.OldestPendingAt.Equal(oldestPendingAt) {
		t.Fatalf("queue posture=%#v", snapshot.QueuePosture)
	}
	encodedSnapshot, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	for _, secret := range []string{"encrypted-webhook-secret", "other-secret", "SECRET_COMPOSE_VALUE", "encrypted-service-env", "deployment-secret", "queued-secret", "job-secret-payload", "agent-command-secret", "migration-metadata-secret", "migration-source-secret", "OTHER_COMPOSE_SECRET", "other-encrypted-env", "other-deployment-secret", "other-database-secret", "other-agent-command-secret", "other-migration-secret", "other-source-org"} {
		if strings.Contains(string(encodedSnapshot), secret) {
			t.Fatalf("snapshot leaked %q: body=%s", secret, encodedSnapshot)
		}
	}
	for _, otherTenantID := range []uuid.UUID{otherProjectID, otherEnvironmentID, otherServiceID, otherDatabaseID, otherClusterID, otherUpgradeID} {
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
