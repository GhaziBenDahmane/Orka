package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/agentpki"
	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/httpapi"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func TestAIAuditorEndToEndConformance(t *testing.T) {
	if os.Getenv("DOCKYARD_AI_AUDIT_CONFORMANCE") == "" {
		t.Skip("DOCKYARD_AI_AUDIT_CONFORMANCE is not set")
	}
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("DOCKYARD_TEST_DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	db, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)

	organizationID, accountID, staleServiceAccountID, clusterID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	ownerID, ownerSessionID := uuid.New(), uuid.New()
	otherOrganizationID, otherAccountID, otherRunID, otherFindingID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	projectID, environmentID, serviceID, mutableRuntimeServiceID, failedDatabaseID, notificationEndpointID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	customTLSCertificateID, customTLSRouteID := uuid.New(), uuid.New()
	managedNetworkID := uuid.New()
	staleDeployTokenID := uuid.New()
	staleSourceCredentialID, overdueSourceCredentialID := uuid.New(), uuid.New()
	overdueBackupDestinationID := uuid.New()
	offlineVolumeBackupID, offlineVolumeRestoreID := uuid.New(), uuid.New()
	customTLSHost := "ai-" + customTLSCertificateID.String() + ".example.test"
	auditorToken := "dky_ai_conformance_" + uuid.NewString()
	ownerToken := "dky_ai_owner_conformance_" + uuid.NewString()
	secretMarker := "DO_NOT_EXPOSE_AI_CONFORMANCE_SECRET_" + uuid.NewString()
	runtimeImageMarker := "runtime-private-" + uuid.NewString()
	activeAgentCA, _, err := agentpki.NewCA(time.Now(), 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	previousAgentCA, _, err := agentpki.NewCA(time.Now(), 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	previousAgentCAFingerprint, err := agentpki.CertificateFingerprint(previousAgentCA)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, otherOrganizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, ownerID)
	})
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'AI conformance',$2)`, []any{organizationID, "ai-conformance-" + organizationID.String()}},
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Other AI conformance',$2)`, []any{otherOrganizationID, "other-ai-conformance-" + otherOrganizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!conformance')`, []any{ownerID, ownerID.String() + "@example.test"}},
		{`INSERT INTO sessions(id,user_id,token_hash,expires_at,auth_method) VALUES($1,$2,$3,now()+interval '1 day','local')`, []any{ownerSessionID, ownerID, cryptox.Digest(ownerToken)}},
		{`INSERT INTO service_accounts(id,organization_id,name,role,enabled) VALUES($1,$2,'conformance-auditor','auditor',true)`, []any{accountID, organizationID}},
		{`INSERT INTO service_account_tokens(id,service_account_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '1 day')`, []any{uuid.New(), accountID, cryptox.Digest(auditorToken)}},
		{`INSERT INTO service_accounts(id,organization_id,name,role,enabled) VALUES($1,$2,'stale-conformance-admin','admin',true)`, []any{staleServiceAccountID, organizationID}},
		{`INSERT INTO service_account_tokens(id,service_account_id,token_hash,expires_at,created_at) VALUES($1,$2,$3,now()+interval '30 days',now()-interval '31 days')`, []any{uuid.New(), staleServiceAccountID, []byte("service-account:" + secretMarker)}},
		{`INSERT INTO service_accounts(id,organization_id,name,role,enabled) VALUES($1,$2,'other-conformance-auditor','auditor',true)`, []any{otherAccountID, otherOrganizationID}},
		{`INSERT INTO ai_audit_runs(id,organization_id,service_account_id,agent_name,status) VALUES($1,$2,$3,'other-auditor','completed')`, []any{otherRunID, otherOrganizationID, otherAccountID}},
		{`INSERT INTO ai_audit_findings(id,run_id,severity,category,title,description,evidence,fingerprint) VALUES($1,$2,'low','isolation','Other tenant finding','Must remain unchanged','{}','other-tenant')`, []any{otherFindingID, otherRunID}},
		{`INSERT INTO notification_endpoints(id,organization_id,name,kind,encrypted_url,encrypted_secret,events) VALUES($1,$2,'AI on-call','webhook','encrypted','encrypted',ARRAY['ai.finding.critical'])`, []any{notificationEndpointID, organizationID}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Audited project','audited-project')`, []any{projectID, organizationID}},
		{`INSERT INTO clusters(id,organization_id,name,slug,state,certificate_ca_fingerprint,certificate_not_after,last_seen_at) VALUES($1,$2,'Legacy CA cluster','legacy-ca','active',$3,now()+interval '1 day',now())`, []any{clusterID, organizationID, previousAgentCAFingerprint}},
		{`INSERT INTO environments(id,project_id,cluster_id,name,slug) VALUES($1,$2,$3,'Production','production')`, []any{environmentID, projectID, clusterID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,storage_node_id,compose_yaml,encrypted_env,revision) VALUES($1,$2,'Sensitive service','sensitive-service',$3,'nodeabc123',$4,$5,2)`, []any{serviceID, environmentID, "ai-conformance-" + serviceID.String(), "services: {app: {image: example.invalid/private, environment: [" + secretMarker + "]}}", "encrypted:" + secretMarker}},
		{`INSERT INTO deploy_tokens(id,compose_service_id,token_hash,name,expires_at,created_at) VALUES($1,$2,$3,'stale-conformance-hook',now()+interval '30 days',now()-interval '31 days')`, []any{staleDeployTokenID, serviceID, []byte("deploy-token:" + secretMarker)}},
		{`INSERT INTO source_credentials(id,organization_id,kind,name,server,username,encrypted_secret,created_at,updated_at) VALUES
			($1,$2,'registry','stale-conformance-credential','registry.example.test','robot',$3,now()-interval '31 days',now()-interval '31 days'),
			($4,$2,'registry','overdue-conformance-credential','registry.example.test','builder',$5,now()-interval '1 year',now()-interval '181 days')`, []any{staleSourceCredentialID, organizationID, "source-credential:" + secretMarker, overdueSourceCredentialID, "overdue-source-credential:" + secretMarker}},
		{`INSERT INTO application_sources(compose_service_id,repository_url,target_service,registry_image,registry_credential_id) VALUES($1,'https://example.test/conformance.git','app','registry.example.test/conformance/app',$2)`, []any{serviceID, overdueSourceCredentialID}},
		{`INSERT INTO custom_tls_certificates(id,organization_id,name,encrypted_certificate,encrypted_private_key,fingerprint,common_name,dns_names,not_before,not_after) VALUES($1,$2,'Expired conformance certificate',$3,$4,$5,$6,ARRAY[$6],now()-interval '90 days',now()-interval '1 hour')`, []any{customTLSCertificateID, organizationID, "encrypted-certificate:" + secretMarker, "encrypted-private-key:" + secretMarker, "sha256:" + strings.Repeat("c", 64), customTLSHost}},
		{`INSERT INTO routes(id,compose_service_id,service_name,host,path_prefix,internal_path,enabled,target_port,tls,certificate_resolver,custom_certificate_id) VALUES($1,$2,'app',$4,'/','/',true,8080,true,'',$3)`, []any{customTLSRouteID, serviceID, customTLSCertificateID, customTLSHost}},
		{`INSERT INTO managed_networks(id,organization_id,cluster_id,name,driver,status,last_error) VALUES($1,$2,$3,$4,'overlay','error',$5)`, []any{managedNetworkID, organizationID, clusterID, "audit-network-" + managedNetworkID.String(), "network-error:" + secretMarker}},
		{`INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,effective_compose,env_snapshot,status,trigger,created_at,finished_at) VALUES($1,$2,1,'services: {app: {image: example.invalid/private:v1}}',$3,'','succeeded','manual',now()-interval '2 minutes',now()-interval '1 minute')`, []any{uuid.New(), serviceID, "services: {app: {image: example.invalid/private@sha256:" + strings.Repeat("a", 64) + "}}"}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml,revision) VALUES($1,$2,'Mutable runtime service','mutable-runtime-service',$3,$4,1)`, []any{mutableRuntimeServiceID, environmentID, "ai-conformance-" + mutableRuntimeServiceID.String(), "services: {app: {image: example.invalid/desired:released}}"}},
		{`INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,effective_compose,env_snapshot,status,trigger,created_at,finished_at) VALUES($1,$2,1,$3,$3,'','succeeded','manual',now()-interval '2 minutes',now()-interval '1 minute')`, []any{uuid.New(), mutableRuntimeServiceID, "services: {app: {image: example.invalid/" + runtimeImageMarker + ":latest}}"}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,encrypted_credentials,status) VALUES($1,$2,'Failed database','failed-database','postgres','17','encrypted','error')`, []any{failedDatabaseID, environmentID}},
		{`INSERT INTO backup_destinations(id,organization_id,name,endpoint,bucket,use_tls,encrypted_credentials,created_at,updated_at) VALUES($1,$2,'Conformance backup','https://s3.example.test','conformance',true,$3,now()-interval '1 year',now()-interval '181 days')`, []any{overdueBackupDestinationID, organizationID, "backup-destination:" + secretMarker}},
		{`INSERT INTO volume_backups(id,compose_service_id,volume_name,storage_node_id,destination_id,quiesce,status,object_key,size_bytes,sha256,plaintext_sha256,encrypted_data_key,finished_at) VALUES($1,$2,'uploads','oldnode',$3,true,'succeeded','offline-recovery.enc',42,$4,$5,'encrypted',now()-interval '2 hours')`, []any{offlineVolumeBackupID, serviceID, overdueBackupDestinationID, strings.Repeat("a", 64), strings.Repeat("b", 64)}},
		{`INSERT INTO volume_restores(id,volume_backup_id,target_storage_node_id,offline,status,error,started_at,finished_at) VALUES($1,$2,'nodeabc123',true,'failed',$3,now()-interval '40 minutes',now()-interval '39 minutes')`, []any{offlineVolumeRestoreID, offlineVolumeBackupID, "offline-restore-error:" + secretMarker}},
		{`INSERT INTO backup_policies(id,database_instance_id,interval_seconds,retention_count,enabled,next_run_at,destination_id) VALUES($1,$2,86400,7,true,now()+interval '1 day',$3)`, []any{uuid.New(), failedDatabaseID, overdueBackupDestinationID}},
	}
	for _, statement := range statements {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	platform := httptest.NewServer((&httpapi.Server{Store: db, AgentCACertificate: activeAgentCA, AgentPreviousCACertificate: previousAgentCA}).Handler())
	defer platform.Close()
	modelCalled := false
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/chat/completions" {
			http.Error(w, "unexpected model request", http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer model-conformance-token" {
			http.Error(w, "missing model authorization", http.StatusUnauthorized)
			return
		}
		body, readErr := io.ReadAll(io.LimitReader(r.Body, 2<<20))
		if readErr != nil {
			t.Error(readErr)
			http.Error(w, "read failed", http.StatusBadRequest)
			return
		}
		if bytes.Contains(body, []byte(secretMarker)) || bytes.Contains(body, []byte(runtimeImageMarker)) {
			t.Error("workload secret or runtime image identity reached the model request")
			http.Error(w, "secret exposed", http.StatusBadRequest)
			return
		}
		var modelRequest struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		if decodeErr := json.Unmarshal(body, &modelRequest); decodeErr != nil {
			t.Error(decodeErr)
			http.Error(w, "invalid model request", http.StatusBadRequest)
			return
		}
		if len(modelRequest.Messages) != 2 || !strings.Contains(modelRequest.Messages[0].Content, "untrusted data") || !strings.Contains(modelRequest.Messages[1].Content, "SNAPSHOT_DATA_BEGIN") || !strings.Contains(modelRequest.Messages[1].Content, serviceID.String()) || !strings.Contains(modelRequest.Messages[1].Content, customTLSCertificateID.String()) || !strings.Contains(modelRequest.Messages[1].Content, managedNetworkID.String()) || !strings.Contains(modelRequest.Messages[1].Content, staleSourceCredentialID.String()) || !strings.Contains(modelRequest.Messages[1].Content, overdueSourceCredentialID.String()) || !strings.Contains(modelRequest.Messages[1].Content, overdueBackupDestinationID.String()) || !strings.Contains(modelRequest.Messages[1].Content, offlineVolumeRestoreID.String()) || !strings.Contains(modelRequest.Messages[1].Content, `"lastRotatedAt"`) || !strings.Contains(modelRequest.Messages[1].Content, `"runtimeDigestPinnedImages":1`) || !strings.Contains(modelRequest.Messages[1].Content, `"runtimeMutableImages":1`) || !strings.Contains(modelRequest.Messages[1].Content, `"customTlsPosture"`) || !strings.Contains(modelRequest.Messages[1].Content, `"edgeTlsPosture"`) || !strings.Contains(modelRequest.Messages[1].Content, `"managedNetworks"`) || !strings.Contains(modelRequest.Messages[1].Content, `"sourceCredentialPosture"`) || !strings.Contains(modelRequest.Messages[1].Content, `"volumeRestorePosture"`) {
			t.Error("model request did not contain the bounded platform snapshot and trust instruction")
			http.Error(w, "incomplete prompt", http.StatusBadRequest)
			return
		}
		modelCalled = true
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": `{"summary":"Conformance audit completed","findings":[{"severity":"critical","category":"capacity","title":"Capacity requires review","description":"The service has no recorded deployment capacity evidence.","resourceType":"service","resourceId":"` + serviceID.String() + `","evidence":{"source":"model-conformance"},"remediation":"Record a successful deployment and capacity observation."}]}`}}}})
	}))
	defer model.Close()

	cfg := auditorConfig{
		DockyardURL:   platform.URL,
		DockyardToken: auditorToken,
		ModelURL:      model.URL + "/v1",
		ModelToken:    "model-conformance-token",
		Model:         "conformance-model",
		AgentName:     "conformance-auditor",
		AgentVersion:  "conformance",
		Focus:         "security, availability, backups, and migration readiness",
	}
	if err = performAIAudit(ctx, &http.Client{Timeout: 10 * time.Second}, cfg); err != nil {
		t.Fatal(err)
	}
	if !modelCalled {
		t.Fatal("OpenAI-compatible model endpoint was not called")
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, platform.URL+"/v1/projects", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+auditorToken)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	deniedBody, readErr := io.ReadAll(response.Body)
	response.Body.Close()
	if readErr != nil || response.StatusCode != http.StatusForbidden || !bytes.Contains(deniedBody, []byte(`"code":"auditor_scope"`)) {
		t.Fatalf("auditor workload access status=%d body=%s err=%v", response.StatusCode, deniedBody, readErr)
	}

	var runID uuid.UUID
	var status, summary string
	if err = db.Pool.QueryRow(ctx, `SELECT id,status,summary FROM ai_audit_runs WHERE organization_id=$1 AND service_account_id=$2 ORDER BY started_at DESC LIMIT 1`, organizationID, accountID).Scan(&runID, &status, &summary); err != nil {
		t.Fatal(err)
	}
	if status != "completed" || !strings.Contains(summary, "Conformance audit completed") || !strings.Contains(summary, "Deterministic baseline:") {
		t.Fatalf("audit run status=%q summary=%q", status, summary)
	}
	request, err = http.NewRequestWithContext(ctx, http.MethodGet, platform.URL+"/v1/ai/audit-runs/self", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+auditorToken)
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var ownRuns struct {
		Items []store.AIAuditRun `json:"items"`
	}
	err = json.NewDecoder(response.Body).Decode(&ownRuns)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || len(ownRuns.Items) != 1 || ownRuns.Items[0].ID != runID || ownRuns.Items[0].Status != "completed" {
		t.Fatalf("auditor own-run status=%d runs=%#v err=%v", response.StatusCode, ownRuns.Items, err)
	}
	rows, err := db.Pool.Query(ctx, `SELECT title FROM ai_audit_findings WHERE run_id=$1`, runID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	titles := map[string]bool{}
	for rows.Next() {
		var title string
		if err = rows.Scan(&title); err != nil {
			t.Fatal(err)
		}
		titles[title] = true
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, title := range []string{"Organization has no active owner", "Mandatory SSO is disabled", "Remote agent image is not immutable", "Remote cluster uses a non-active certificate authority", "Previous agent certificate authority remains trusted", "Desired service revision is not deployed", "Deployed workload uses mutable container images", "Managed database deployment is unhealthy", "Managed network provisioning failed", "Custom TLS certificate has expired", "Custom TLS edge target is missing", "Unused deployment hook credentials are stale", "Unused service-account credentials are stale", "Unused source credential is stale", "Source credential rotation is overdue", "Backup destination credential rotation is overdue", "Offline volume recovery failed", "Capacity requires review"} {
		if !titles[title] {
			t.Errorf("missing persisted finding %q in %#v", title, titles)
		}
	}
	var auditEvents int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_service_account_id=$2 AND action IN ('ai_audit.start','ai_audit.completed')`, organizationID, accountID).Scan(&auditEvents); err != nil {
		t.Fatal(err)
	}
	if auditEvents != 2 {
		t.Fatalf("AI audit lifecycle events=%d, want 2", auditEvents)
	}
	if _, err = db.Pool.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')`, organizationID, ownerID); err != nil {
		t.Fatal(err)
	}

	var findingID uuid.UUID
	if err = db.Pool.QueryRow(ctx, `SELECT id FROM ai_audit_findings WHERE run_id=$1 AND title='Capacity requires review'`, runID).Scan(&findingID); err != nil {
		t.Fatal(err)
	}
	var criticalNotifications, criticalNotificationJobs int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM notification_deliveries WHERE endpoint_id=$1 AND event_type='ai.finding.critical' AND resource_id=$2`, notificationEndpointID, findingID.String()).Scan(&criticalNotifications); err != nil || criticalNotifications != 1 {
		t.Fatalf("critical finding notifications=%d err=%v", criticalNotifications, err)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE kind='notify.webhook' AND payload->>'deliveryId' IN (SELECT id::text FROM notification_deliveries WHERE endpoint_id=$1 AND resource_id=$2)`, notificationEndpointID, findingID.String()).Scan(&criticalNotificationJobs); err != nil || criticalNotificationJobs != 1 {
		t.Fatalf("critical finding notification jobs=%d err=%v", criticalNotificationJobs, err)
	}
	if _, err = db.Pool.Exec(ctx, `
		CREATE FUNCTION reject_ai_triage_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.action LIKE 'ai_audit_finding.%' THEN
				RAISE EXCEPTION 'forced triage audit failure';
			END IF;
			RETURN NEW;
		END $$;
		CREATE TRIGGER reject_ai_triage_audit BEFORE INSERT ON audit_events
		FOR EACH ROW EXECUTE FUNCTION reject_ai_triage_audit()`); err != nil {
		t.Fatal(err)
	}
	dropAuditFailureTrigger := func() {
		_, _ = db.Pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS reject_ai_triage_audit ON audit_events; DROP FUNCTION IF EXISTS reject_ai_triage_audit()`)
	}
	t.Cleanup(dropAuditFailureTrigger)
	if _, err = db.UpdateAIAuditFindingDisposition(ctx, store.Principal{UserID: ownerID, OrganizationID: organizationID, Role: "owner"}, findingID, "resolved", "must roll back", "127.0.0.1"); err == nil {
		t.Fatal("finding triage succeeded when its audit event was rejected")
	}
	var rolledBackDisposition string
	if err = db.Pool.QueryRow(ctx, `SELECT disposition FROM ai_audit_findings WHERE id=$1`, findingID).Scan(&rolledBackDisposition); err != nil || rolledBackDisposition != "open" {
		t.Fatalf("triage rollback disposition=%q err=%v", rolledBackDisposition, err)
	}
	dropAuditFailureTrigger()
	triage := func(token string, id uuid.UUID, body string) (int, []byte) {
		request, requestErr := http.NewRequestWithContext(ctx, http.MethodPatch, platform.URL+"/v1/ai/audit-findings/"+id.String(), strings.NewReader(body))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("X-Organization-ID", organizationID.String())
		request.Header.Set("Content-Type", "application/json")
		response, requestErr := http.DefaultClient.Do(request)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		data, readErr := io.ReadAll(response.Body)
		response.Body.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		return response.StatusCode, data
	}
	triageStatus, triageBody := triage(ownerToken, findingID, `{"disposition":"acknowledged","note":"reviewed during conformance"}`)
	var triaged store.AIAuditFinding
	if err = json.Unmarshal(triageBody, &triaged); triageStatus != http.StatusOK || err != nil || triaged.Disposition != "acknowledged" || triaged.TriagedByUser == nil || *triaged.TriagedByUser != ownerID || triaged.TriagedAt == nil {
		t.Fatalf("owner triage status=%d finding=%#v body=%s err=%v", triageStatus, triaged, triageBody, err)
	}
	triageStatus, triageBody = triage(auditorToken, findingID, `{"disposition":"resolved"}`)
	if triageStatus != http.StatusForbidden || !bytes.Contains(triageBody, []byte(`"code":"forbidden"`)) {
		t.Fatalf("auditor triage status=%d body=%s", triageStatus, triageBody)
	}
	triageStatus, triageBody = triage(ownerToken, otherFindingID, `{"disposition":"resolved"}`)
	if triageStatus != http.StatusNotFound {
		t.Fatalf("cross-tenant triage status=%d body=%s", triageStatus, triageBody)
	}
	var otherDisposition string
	if err = db.Pool.QueryRow(ctx, `SELECT disposition FROM ai_audit_findings WHERE id=$1`, otherFindingID).Scan(&otherDisposition); err != nil || otherDisposition != "open" {
		t.Fatalf("other-tenant disposition=%q err=%v", otherDisposition, err)
	}
	var triageAuditEvents int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND action='ai_audit_finding.acknowledged' AND resource_id=$3`, organizationID, ownerID, findingID.String()).Scan(&triageAuditEvents); err != nil || triageAuditEvents != 1 {
		t.Fatalf("AI finding triage audit events=%d err=%v", triageAuditEvents, err)
	}

	evidence, _ := json.Marshal(map[string]any{
		"status":                         "passed",
		"realPlatformAPI":                true,
		"openAICompatibleGateway":        true,
		"snapshotSecretsRedacted":        true,
		"promptInjectionBoundaryPresent": true,
		"deterministicFindingsPersisted": true,
		"deployedImageProvenanceAudited": true,
		"agentCAMismatchDetected":        true,
		"agentImageProvenanceAudited":    true,
		"databaseAvailabilityAudited":    true,
		"managedNetworkPostureAudited":   true,
		"staleDeployCredentialAudited":   true,
		"staleServiceAccountAudited":     true,
		"staleSourceCredentialAudited":   true,
		"customTLSValidityAudited":       true,
		"edgeTLSConvergenceAudited":      true,
		"offlineVolumeRecoveryAudited":   true,
		"modelFindingsPersisted":         true,
		"durableRunCompleted":            true,
		"lifecycleAudited":               true,
		"auditorLeastPrivilege":          true,
		"auditorOwnRunVerification":      true,
		"findingTriageAudited":           true,
		"findingTriageAtomic":            true,
		"criticalFindingNotified":        true,
		"auditorTriageDenied":            true,
		"triageTenantIsolated":           true,
	})
	fmt.Printf("AI_AUDIT_EVIDENCE %s\n", evidence)
}
