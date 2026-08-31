package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/agentpki"
	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/database"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func TestServiceAccountAuthenticationAndRotation(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)
	box, err := cryptox.New(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	orgID, userID := uuid.New(), uuid.New()
	userToken := "owner-session-" + uuid.NewString()
	_, err = db.Pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Service Accounts',$2)`, orgID, "service-accounts-"+orgID.String())
	if err == nil {
		_, err = db.Pool.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, userID, userID.String()+"@example.test")
	}
	if err == nil {
		_, err = db.Pool.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')`, orgID, userID)
	}
	if err == nil {
		_, err = db.Pool.Exec(ctx, `INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '5 minutes')`, uuid.New(), userID, cryptox.Digest(userToken))
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, orgID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})

	agentCA, _, err := agentpki.NewCA(time.Now(), 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	previousAgentCA, _, err := agentpki.NewCA(time.Now(), 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	agentCAFingerprint, _ := agentpki.CertificateFingerprint(agentCA)
	previousAgentCAFingerprint, _ := agentpki.CertificateFingerprint(previousAgentCA)
	server := httptest.NewServer((&Server{Store: db, Box: box, Databases: database.NewRegistry(), PublicURL: "https://dockyard.example.test", SessionTTL: time.Hour, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), AgentCACertificate: agentCA, AgentPreviousCACertificate: previousAgentCA}).Handler())
	defer server.Close()
	do := func(method, path, token string, body []byte) (*http.Response, []byte) {
		req, requestErr := http.NewRequest(method, server.URL+path, bytes.NewReader(body))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Organization-ID", orgID.String())
		req.Header.Set("Content-Type", "application/json")
		response, requestErr := http.DefaultClient.Do(req)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		data, _ := io.ReadAll(response.Body)
		response.Body.Close()
		return response, data
	}

	response, data := do(http.MethodPost, "/v1/service-accounts", userToken, []byte(`{"name":"automation","role":"admin","expiresInDays":30}`))
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d: %s", response.StatusCode, data)
	}
	var created struct {
		ServiceAccount store.ServiceAccount `json:"serviceAccount"`
		Token          string               `json:"token"`
	}
	if err = json.Unmarshal(data, &created); err != nil || created.Token == "" {
		t.Fatalf("created account = %#v, err = %v", created, err)
	}
	response, data = do(http.MethodGet, "/v1/me", created.Token, nil)
	if response.StatusCode != http.StatusOK || !bytes.Contains(data, []byte(created.ServiceAccount.ID.String())) {
		t.Fatalf("service account auth status = %d: %s", response.StatusCode, data)
	}
	response, _ = do(http.MethodGet, "/v1/sessions", created.Token, nil)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("service account session-list status = %d, want 403", response.StatusCode)
	}
	response, _ = do(http.MethodPost, "/v1/auth/logout", created.Token, nil)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("service account logout status = %d, want 403", response.StatusCode)
	}

	response, data = do(http.MethodPost, "/v1/service-accounts/"+created.ServiceAccount.ID.String()+"/rotate", userToken, []byte(`{"expiresInDays":60}`))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("rotate status = %d: %s", response.StatusCode, data)
	}
	var rotated map[string]any
	if err = json.Unmarshal(data, &rotated); err != nil {
		t.Fatal(err)
	}
	newToken, _ := rotated["token"].(string)
	response, _ = do(http.MethodGet, "/v1/me", created.Token, nil)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old token status = %d, want 401", response.StatusCode)
	}
	response, _ = do(http.MethodGet, "/v1/me", newToken, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("rotated token status = %d, want 200", response.StatusCode)
	}
	response, data = do(http.MethodPost, "/v1/projects", newToken, []byte(`{"name":"Automated Project"}`))
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("service-account project status = %d: %s", response.StatusCode, data)
	}
	var project store.Project
	if err = json.Unmarshal(data, &project); err != nil {
		t.Fatal(err)
	}
	response, data = do(http.MethodPost, "/v1/projects/"+project.ID.String()+"/environments", newToken, []byte(`{"name":"Production"}`))
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("service-account environment status = %d: %s", response.StatusCode, data)
	}
	var environment store.Environment
	if err = json.Unmarshal(data, &environment); err != nil {
		t.Fatal(err)
	}
	response, data = do(http.MethodPost, "/v1/environments/"+environment.ID.String()+"/databases", newToken, []byte(`{"name":"Primary","engine":"postgres","version":"17","config":{}}`))
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("service-account database status = %d: %s", response.StatusCode, data)
	}
	var databaseResponse struct {
		Database store.DatabaseInstance `json:"database"`
	}
	if err = json.Unmarshal(data, &databaseResponse); err != nil || databaseResponse.Database.DriverSource != "built-in" {
		t.Fatalf("created database=%s err=%v", data, err)
	}
	response, _ = do(http.MethodPost, "/v1/databases/"+databaseResponse.Database.ID.String()+"/driver-rebind", newToken, []byte(`{"confirm":"wrong"}`))
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("driver rebind confirmation status=%d, want 400", response.StatusCode)
	}
	response, data = do(http.MethodPost, "/v1/databases/"+databaseResponse.Database.ID.String()+"/driver-rebind", newToken, []byte(`{"confirm":"`+databaseResponse.Database.Slug+`"}`))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("driver rebind status=%d: %s", response.StatusCode, data)
	}
	var audited bool
	if err = db.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM audit_events WHERE organization_id=$1 AND actor_service_account_id=$2 AND action='project.create')`, orgID, created.ServiceAccount.ID).Scan(&audited); err != nil || !audited {
		t.Fatalf("service account audit present = %v, err = %v", audited, err)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM audit_events WHERE organization_id=$1 AND actor_service_account_id=$2 AND action='database.driver_rebind')`, orgID, created.ServiceAccount.ID).Scan(&audited); err != nil || !audited {
		t.Fatalf("driver rebind audit present = %v, err = %v", audited, err)
	}

	response, data = do(http.MethodPost, "/v1/service-accounts", userToken, []byte(`{"name":"ai-auditor","role":"auditor","expiresInDays":30}`))
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create auditor status = %d: %s", response.StatusCode, data)
	}
	var auditor struct {
		ServiceAccount store.ServiceAccount `json:"serviceAccount"`
		Token          string               `json:"token"`
	}
	if err = json.Unmarshal(data, &auditor); err != nil || auditor.Token == "" {
		t.Fatalf("auditor response=%s err=%v", data, err)
	}
	response, _ = do(http.MethodGet, "/v1/projects", auditor.Token, nil)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("auditor normal API status=%d, want 403", response.StatusCode)
	}
	response, _ = do(http.MethodGet, "/v1/scim/tokens", auditor.Token, nil)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("auditor SCIM token inventory status=%d, want 403", response.StatusCode)
	}
	response, data = do(http.MethodGet, "/v1/ai/audit-snapshot", auditor.Token, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("auditor snapshot status=%d: %s", response.StatusCode, data)
	}
	var snapshot store.AIAuditSnapshot
	if err = json.Unmarshal(data, &snapshot); err != nil || !snapshot.AgentCAPosture.Configured || !snapshot.AgentCAPosture.RolloverActive || snapshot.AgentCAPosture.ActiveFingerprint != agentCAFingerprint || snapshot.AgentCAPosture.PreviousFingerprint != previousAgentCAFingerprint {
		t.Fatalf("auditor agent CA posture=%#v err=%v", snapshot.AgentCAPosture, err)
	}
	if len(snapshot.DatabaseEngines) < 10 || snapshot.DatabaseEngines[0].Name == "" || snapshot.DatabaseEngines[0].DefaultVersion == "" || snapshot.DatabaseEngines[0].Source != "built-in" {
		t.Fatalf("auditor database engine posture=%#v", snapshot.DatabaseEngines)
	}
	response, data = do(http.MethodPost, "/v1/ai/audit-runs", auditor.Token, []byte(`{"agentName":"test-auditor","model":"test"}`))
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("auditor run status=%d: %s", response.StatusCode, data)
	}
	var auditRun struct {
		ID uuid.UUID `json:"id"`
	}
	if err = json.Unmarshal(data, &auditRun); err != nil || auditRun.ID == uuid.Nil {
		t.Fatalf("audit run response=%s err=%v", data, err)
	}
	otherAuditorID, otherRunID := uuid.New(), uuid.New()
	if _, err = db.Pool.Exec(ctx, `INSERT INTO service_accounts(id,organization_id,name,role) VALUES($1,$2,'other-ai-auditor','auditor')`, otherAuditorID, orgID); err == nil {
		_, err = db.Pool.Exec(ctx, `INSERT INTO ai_audit_runs(id,organization_id,service_account_id,agent_name,status,completed_at) VALUES($1,$2,$3,'other-agent','completed',now())`, otherRunID, orgID, otherAuditorID)
	}
	if err != nil {
		t.Fatal(err)
	}
	response, data = do(http.MethodGet, "/v1/ai/audit-runs/self", auditor.Token, nil)
	if response.StatusCode != http.StatusOK || !bytes.Contains(data, []byte(auditRun.ID.String())) || !bytes.Contains(data, []byte(`"agentName":"test-auditor"`)) || bytes.Contains(data, []byte(otherRunID.String())) {
		t.Fatalf("auditor own runs status=%d body=%s", response.StatusCode, data)
	}
	response, _ = do(http.MethodGet, "/v1/ai/audit-runs/self", newToken, nil)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("non-auditor own runs status=%d, want 403", response.StatusCode)
	}
	response, _ = do(http.MethodPost, "/v1/ai/audit-runs/"+auditRun.ID.String()+"/findings", auditor.Token, []byte(`{"severity":"high","category":"security","title":"Invalid evidence","description":"must be an object","evidence":[]}`))
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("non-object audit evidence status=%d, want 400", response.StatusCode)
	}
	for index := 0; index < store.MaxAIAuditFindingsPerRun; index++ {
		if _, err = db.AddAIAuditFinding(ctx, orgID, auditor.ServiceAccount.ID, store.AIAuditFinding{RunID: auditRun.ID, Severity: "low", Category: "limit-test", Title: "Finding", Description: "Bounded finding", Evidence: json.RawMessage(`{}`), Fingerprint: fmt.Sprintf("limit-%d", index)}); err != nil {
			t.Fatalf("seed audit finding %d: %v", index, err)
		}
	}
	response, data = do(http.MethodPost, "/v1/ai/audit-runs/"+auditRun.ID.String()+"/findings", auditor.Token, []byte(`{"severity":"low","category":"limit-test","title":"Overflow","description":"must be rejected","evidence":{},"fingerprint":"overflow"}`))
	if response.StatusCode != http.StatusConflict || !bytes.Contains(data, []byte(`"code":"ai_audit_finding_limit"`)) {
		t.Fatalf("audit finding overflow status=%d body=%s", response.StatusCode, data)
	}
	response, data = do(http.MethodPost, "/v1/ai/audit-runs/"+auditRun.ID.String()+"/findings", auditor.Token, []byte(`{"severity":"medium","category":"limit-test","title":"Updated","description":"existing fingerprints remain writable","evidence":{},"fingerprint":"limit-0"}`))
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("audit finding update at limit status=%d body=%s", response.StatusCode, data)
	}
	findings, err := db.ListAIAuditFindings(ctx, orgID, auditRun.ID)
	if err != nil || len(findings) != store.MaxAIAuditFindingsPerRun {
		t.Fatalf("list audit findings count=%d err=%v", len(findings), err)
	}
	findingID := findings[0].ID
	response, data = do(http.MethodPatch, "/v1/ai/audit-findings/"+findingID.String(), userToken, []byte(`{"disposition":"acknowledged","note":"reviewed by owner"}`))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("owner finding triage status=%d body=%s", response.StatusCode, data)
	}
	var triaged store.AIAuditFinding
	if err = json.Unmarshal(data, &triaged); err != nil || triaged.Disposition != "acknowledged" || triaged.TriageNote != "reviewed by owner" || triaged.TriagedByUser == nil || *triaged.TriagedByUser != userID || triaged.TriagedAt == nil {
		t.Fatalf("owner triaged finding=%#v err=%v", triaged, err)
	}
	response, _ = do(http.MethodPatch, "/v1/ai/audit-findings/"+findingID.String(), auditor.Token, []byte(`{"disposition":"resolved"}`))
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("auditor finding triage status=%d, want 403", response.StatusCode)
	}
	response, data = do(http.MethodPatch, "/v1/ai/audit-findings/"+findingID.String(), newToken, []byte(`{"disposition":"resolved","note":"resolved by automation"}`))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("admin service account finding triage status=%d body=%s", response.StatusCode, data)
	}
	triaged = store.AIAuditFinding{}
	if err = json.Unmarshal(data, &triaged); err != nil || triaged.Disposition != "resolved" || triaged.TriagedByUser != nil || triaged.TriagedByServiceAccount == nil || *triaged.TriagedByServiceAccount != created.ServiceAccount.ID {
		t.Fatalf("service account triaged finding=%#v err=%v", triaged, err)
	}
	response, _ = do(http.MethodPatch, "/v1/ai/audit-findings/"+uuid.NewString(), userToken, []byte(`{"disposition":"resolved"}`))
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown finding triage status=%d, want 404", response.StatusCode)
	}
	var findingAuditEvents int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND resource_id=$2 AND action IN ('ai_audit_finding.acknowledged','ai_audit_finding.resolved')`, orgID, findingID.String()).Scan(&findingAuditEvents); err != nil || findingAuditEvents != 2 {
		t.Fatalf("finding triage audit events=%d err=%v", findingAuditEvents, err)
	}
	response, data = do(http.MethodGet, "/v1/ai/audit-findings?disposition=resolved&limit=1", userToken, nil)
	if response.StatusCode != http.StatusOK || !bytes.Contains(data, []byte(findingID.String())) || !bytes.Contains(data, []byte(`"agentName":"test-auditor"`)) || !bytes.Contains(data, []byte(auditor.ServiceAccount.ID.String())) {
		t.Fatalf("current audit findings status=%d body=%s", response.StatusCode, data)
	}
	response, _ = do(http.MethodGet, "/v1/ai/audit-findings", auditor.Token, nil)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("auditor current findings status=%d, want 403", response.StatusCode)
	}
	response, _ = do(http.MethodGet, "/v1/ai/audit-findings?severity=urgent", userToken, nil)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid current finding severity status=%d, want 400", response.StatusCode)
	}
	response, _ = do(http.MethodPatch, "/v1/ai/audit-runs/"+auditRun.ID.String(), auditor.Token, []byte(`{"status":"completed","summary":"`+strings.Repeat("x", 8001)+`"}`))
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversized audit summary status=%d, want 400", response.StatusCode)
	}

	response, data = do(http.MethodPost, "/v1/scim/tokens", userToken, []byte(`{"name":"identity-provider","defaultRole":"developer","expiresInDays":30}`))
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create SCIM token status=%d: %s", response.StatusCode, data)
	}
	var createdSCIM struct {
		SCIMToken store.SCIMToken `json:"scimToken"`
		Token     string          `json:"token"`
		BaseURL   string          `json:"baseUrl"`
	}
	if err = json.Unmarshal(data, &createdSCIM); err != nil || createdSCIM.SCIMToken.ID == uuid.Nil || createdSCIM.Token == "" || createdSCIM.SCIMToken.ExpiresAt.Before(time.Now().Add(29*24*time.Hour)) || createdSCIM.BaseURL != "https://dockyard.example.test/scim/v2" {
		t.Fatalf("created SCIM token=%#v err=%v body=%s", createdSCIM, err, data)
	}
	response, _ = do(http.MethodPost, "/v1/scim/tokens", userToken, []byte(`{"name":"too-long-lived","expiresInDays":366}`))
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("overlong SCIM token expiry status=%d, want 400", response.StatusCode)
	}
	expiredSCIMToken := "expired-scim-" + uuid.NewString()
	expiredSCIM, err := db.CreateSCIMToken(ctx, orgID, "expired-provider", "viewer", cryptox.Digest(expiredSCIMToken), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, authenticateErr := db.AuthenticateSCIM(ctx, cryptox.Digest(expiredSCIMToken)); !errors.Is(authenticateErr, store.ErrNotFound) {
		t.Fatalf("expired SCIM token authenticated: %v", authenticateErr)
	}
	response, data = do(http.MethodGet, "/v1/scim/tokens", userToken, nil)
	if response.StatusCode != http.StatusOK || bytes.Contains(data, []byte(createdSCIM.Token)) || !bytes.Contains(data, []byte(createdSCIM.SCIMToken.ID.String())) {
		t.Fatalf("list SCIM tokens status=%d body=%s", response.StatusCode, data)
	}
	otherOrgID := uuid.New()
	if _, err = db.Pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Other service accounts',$2)`, otherOrgID, "other-service-accounts-"+otherOrgID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, otherOrgID) })
	otherSCIMToken := "other-scim-" + uuid.NewString()
	otherSCIM, err := db.CreateSCIMToken(ctx, otherOrgID, "other-provider", "viewer", cryptox.Digest(otherSCIMToken), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	response, _ = do(http.MethodDelete, "/v1/scim/tokens/"+otherSCIM.ID.String(), userToken, nil)
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-tenant SCIM revoke status=%d, want 404", response.StatusCode)
	}
	if authenticatedOrg, _, authenticateErr := db.AuthenticateSCIM(ctx, cryptox.Digest(otherSCIMToken)); authenticateErr != nil || authenticatedOrg != otherOrgID {
		t.Fatalf("cross-tenant revoke changed token: org=%s err=%v", authenticatedOrg, authenticateErr)
	}
	response, _ = do(http.MethodDelete, "/v1/scim/tokens/"+createdSCIM.SCIMToken.ID.String(), userToken, nil)
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke SCIM token status=%d, want 204", response.StatusCode)
	}
	if _, _, authenticateErr := db.AuthenticateSCIM(ctx, cryptox.Digest(createdSCIM.Token)); !errors.Is(authenticateErr, store.ErrNotFound) {
		t.Fatalf("revoked SCIM token authenticated: %v", authenticateErr)
	}
	response, data = do(http.MethodGet, "/v1/scim/tokens", userToken, nil)
	var listedSCIM struct {
		Items []store.SCIMToken `json:"items"`
	}
	if err = json.Unmarshal(data, &listedSCIM); err != nil || len(listedSCIM.Items) != 2 {
		t.Fatalf("listed SCIM tokens=%#v err=%v body=%s", listedSCIM.Items, err, data)
	}
	var foundRevoked, foundExpired bool
	for _, item := range listedSCIM.Items {
		foundRevoked = foundRevoked || item.ID == createdSCIM.SCIMToken.ID && item.RevokedAt != nil
		foundExpired = foundExpired || item.ID == expiredSCIM.ID && item.RevokedAt == nil && item.ExpiresAt.Before(time.Now())
	}
	if !foundRevoked || !foundExpired {
		t.Fatalf("SCIM inventory missing revoked or expired token: %#v", listedSCIM.Items)
	}
	var scimAuditEvents int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND resource_id=$2 AND action IN ('scim.token.create','scim.token.revoke')`, orgID, createdSCIM.SCIMToken.ID.String()).Scan(&scimAuditEvents); err != nil || scimAuditEvents != 2 {
		t.Fatalf("SCIM token audit events=%d err=%v", scimAuditEvents, err)
	}

	response, _ = do(http.MethodDelete, "/v1/service-accounts/"+created.ServiceAccount.ID.String(), userToken, nil)
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("disable status = %d, want 204", response.StatusCode)
	}
	response, _ = do(http.MethodGet, "/v1/me", newToken, nil)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("disabled account token status = %d, want 401", response.StatusCode)
	}
}
