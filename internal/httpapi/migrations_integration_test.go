package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/GhaziBenDahmane/Orka/internal/cryptox"
	"github.com/GhaziBenDahmane/Orka/internal/store"
	"github.com/google/uuid"
)

func TestDokployVerificationAPIIsAdminOnlyTenantScopedAndAudited(t *testing.T) {
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
	organizationID, otherOrganizationID, userID, viewerID, projectID, environmentID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	adminToken, viewerToken := "migration-admin-"+uuid.NewString(), "migration-viewer-"+uuid.NewString()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Migration API',$2)`, []any{organizationID, "migration-api-" + organizationID.String()}},
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Other migration',$2)`, []any{otherOrganizationID, "other-migration-" + otherOrganizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'x'),($3,$4,'x')`, []any{userID, userID.String() + "@example.test", viewerID, viewerID.String() + "@example.test"}},
		{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'admin'),($1,$3,'viewer')`, []any{organizationID, userID, viewerID}},
		{`INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '5 minutes'),($4,$5,$6,now()+interval '5 minutes')`, []any{uuid.New(), userID, cryptox.Digest(adminToken), uuid.New(), viewerID, cryptox.Digest(viewerToken)}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Imported','imported')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO dokploy_migration_resources(target_organization_id,source_organization_id,source_kind,source_id,target_id,status) VALUES($1,'source-org','project','project-1',$2,'imported'),($1,'source-org','environment','environment-1',$3,'imported')`, []any{organizationID, projectID, environmentID}},
		{`INSERT INTO dokploy_migration_resources(target_organization_id,source_organization_id,source_kind,source_id,status,reason) VALUES($1,'source-org','project','private-project','skipped','other tenant')`, []any{otherOrganizationID}},
	} {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, otherOrganizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=ANY($1::uuid[])`, []uuid.UUID{userID, viewerID})
	})
	server := httptest.NewServer((&Server{Store: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler())
	defer server.Close()
	endpoint := server.URL + "/v1/migration-resources/verify"
	request := map[string]any{"sourceOrganizationId": "source-org", "requireOperational": false, "acknowledgements": []string{}}
	if status, _ := scopedAPIRequest(t, endpoint, viewerToken, organizationID, http.MethodPost, request); status != http.StatusForbidden {
		t.Fatalf("viewer verification status=%d", status)
	}
	status, body := scopedAPIRequest(t, endpoint, adminToken, organizationID, http.MethodPost, request)
	var report struct {
		Ready    bool `json:"ready"`
		Verified int  `json:"verified"`
		Blocked  int  `json:"blocked"`
	}
	if err = json.Unmarshal(body, &report); status != http.StatusOK || err != nil || !report.Ready || report.Verified != 2 || report.Blocked != 0 {
		t.Fatalf("verification status=%d report=%#v body=%s err=%v", status, report, body, err)
	}
	if status, _ = scopedAPIRequest(t, endpoint, adminToken, organizationID, http.MethodPost, map[string]any{"sourceOrganizationId": "source-org", "acknowledgements": []string{"invalid"}}); status != http.StatusBadRequest {
		t.Fatalf("invalid acknowledgement status=%d", status)
	}
	var auditCount int
	var metadata []byte
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND action='dokploy_migration.verify' AND resource_id='source-org'`, organizationID, userID).Scan(&auditCount); err == nil && auditCount == 1 {
		err = db.Pool.QueryRow(ctx, `SELECT metadata::text::bytea FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND action='dokploy_migration.verify' AND resource_id='source-org'`, organizationID, userID).Scan(&metadata)
	}
	if err != nil || auditCount != 1 || !bytes.Contains(metadata, []byte(`"ready": true`)) {
		t.Fatalf("verification audit count=%d metadata=%s err=%v", auditCount, metadata, err)
	}
}
