package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func TestAuditExportIntegrityPaginationAndRetention(t *testing.T) {
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
	orgID, defaultRetentionOrgID, userID := uuid.New(), uuid.New(), uuid.New()
	token := "audit-" + uuid.NewString()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Audit',$2)`, []any{orgID, "audit-" + orgID.String()}},
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Default retention',$2)`, []any{defaultRetentionOrgID, "default-retention-" + defaultRetentionOrgID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'x')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')`, []any{orgID, userID}},
		{`INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '5 minutes')`, []any{uuid.New(), userID, cryptox.Digest(token)}},
		{`INSERT INTO audit_events(organization_id,action,resource_type,created_at) VALUES($1,'expired','test',now()-interval '31 days'),($1,'recent.one','test',now()),($1,'recent.two','test',now())`, []any{orgID}},
		{`INSERT INTO audit_events(organization_id,action,resource_type,created_at) VALUES($1,'default.expired','test',now()-interval '366 days'),($1,'default.recent','test',now()-interval '300 days')`, []any{defaultRetentionOrgID}},
	} {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, orgID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, defaultRetentionOrgID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})
	server := httptest.NewServer((&Server{Store: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler())
	defer server.Close()
	if status, body := scopedAPIRequest(t, server.URL+"/v1/audit-retention", token, orgID, http.MethodPut, map[string]int{"retentionDays": 30}); status != http.StatusOK {
		t.Fatalf("retention status = %d: %s", status, body)
	}
	if removed, pruneErr := db.PruneAuditEvents(ctx); pruneErr != nil || removed != 2 {
		t.Fatalf("pruned = %d, err = %v", removed, pruneErr)
	}
	var defaultRecent int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND action='default.recent'`, defaultRetentionOrgID).Scan(&defaultRecent); err != nil || defaultRecent != 1 {
		t.Fatalf("default-retention recent events=%d err=%v", defaultRecent, err)
	}
	backupDestinationID := uuid.New()
	if _, err = db.Pool.Exec(ctx, `INSERT INTO backup_destinations(id,organization_id,name,endpoint,bucket,use_tls,encrypted_credentials) VALUES($1,$2,'audit lookup','https://s3.example.test','audit',true,'encrypted')`, backupDestinationID, orgID); err != nil {
		t.Fatal(err)
	}
	archive, err := db.CreateAuditArchiveDestination(ctx, store.AuditArchiveDestination{OrganizationID: orgID, BackupDestinationID: backupDestinationID, Name: "compliance", ObjectPrefix: "audit", RetentionDays: 365})
	if err != nil {
		t.Fatal(err)
	}
	if status, body := scopedAPIRequest(t, server.URL+"/v1/audit-archives/"+archive.ID.String(), token, orgID, http.MethodGet, nil); status != http.StatusOK || !bytes.Contains(body, []byte(`"name":"compliance"`)) {
		t.Fatalf("audit archive lookup status=%d body=%s", status, body)
	}
	req, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/audit-events/export?limit=2", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Organization-ID", orgID.String())
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := io.ReadAll(response.Body)
	response.Body.Close()
	digest := sha256.Sum256(payload)
	if response.StatusCode != http.StatusOK || response.Header.Get("X-Content-SHA256") != hex.EncodeToString(digest[:]) || response.Header.Get("X-Next-After-ID") == "" || bytes.Contains(payload, []byte("expired")) {
		t.Fatalf("invalid export status=%d headers=%v body=%s", response.StatusCode, response.Header, payload)
	}
}
