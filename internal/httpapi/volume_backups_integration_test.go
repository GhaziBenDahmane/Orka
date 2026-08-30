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
	"strings"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func TestVolumeBackupPolicyLifecycleAndTenantIsolationAPI(t *testing.T) {
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

	organizationID, otherOrganizationID, userID := uuid.New(), uuid.New(), uuid.New()
	projectID, environmentID, serviceID, destinationID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	token := "volume-api-" + uuid.NewString()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Volume API',$2),($3,'Other Volume API',$4)`, []any{organizationID, "volume-api-" + organizationID.String(), otherOrganizationID, "other-volume-api-" + otherOrganizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner'),($3,$2,'owner')`, []any{organizationID, userID, otherOrganizationID}},
		{`INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '5 minutes')`, []any{uuid.New(), userID, cryptox.Digest(token)}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,storage_node_id,compose_yaml) VALUES($1,$2,'App','app',$3,'nodeabc123',$4)`, []any{serviceID, environmentID, "volume-api-" + serviceID.String(), "services:\n  app:\n    image: example/app:1\n    volumes:\n      - uploads:/data\nvolumes:\n  uploads: {}\n"}},
		{`INSERT INTO backup_destinations(id,organization_id,name,endpoint,bucket,use_tls,encrypted_credentials) VALUES($1,$2,'S3','https://s3.example.test','backups',true,'encrypted')`, []any{destinationID, organizationID}},
	}
	for _, statement := range statements {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM jobs WHERE payload->>'backupId' IN (SELECT id::text FROM volume_backups WHERE compose_service_id=$1) OR payload->>'restoreId' IN (SELECT restore.id::text FROM volume_restores restore JOIN volume_backups backup ON backup.id=restore.volume_backup_id WHERE backup.compose_service_id=$1)`, serviceID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=ANY($1)`, []uuid.UUID{organizationID, otherOrganizationID})
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})

	server := httptest.NewServer((&Server{Store: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler())
	defer server.Close()
	policyURL := server.URL + "/v1/services/" + serviceID.String() + "/volume-backup-policies/uploads"
	status, body := scopedAPIRequest(t, policyURL, token, organizationID, http.MethodPut, map[string]any{"destinationId": destinationID, "intervalSeconds": 3600, "retentionCount": 7, "quiesce": true, "enabled": true})
	if status != http.StatusOK {
		t.Fatalf("put policy status=%d body=%s", status, body)
	}
	status, body = scopedAPIRequest(t, server.URL+"/v1/services/"+serviceID.String()+"/volumes", token, organizationID, http.MethodGet, nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"dockerName":"volume-api-`)) || !bytes.Contains(body, []byte(`"storageNodeId":"nodeabc123"`)) {
		t.Fatalf("volumes status=%d body=%s", status, body)
	}

	backupURL := server.URL + "/v1/services/" + serviceID.String() + "/volume-backups/uploads"
	status, body = scopedAPIRequest(t, backupURL, token, organizationID, http.MethodPost, map[string]any{})
	var cancelledBackup store.VolumeBackup
	if err = json.Unmarshal(body, &cancelledBackup); status != http.StatusAccepted || err != nil {
		t.Fatalf("queue backup status=%d body=%s err=%v", status, body, err)
	}
	status, body = scopedAPIRequest(t, server.URL+"/v1/volume-backups/"+cancelledBackup.ID.String()+"/cancel", token, organizationID, http.MethodPost, map[string]any{})
	if status != http.StatusAccepted {
		t.Fatalf("cancel backup status=%d body=%s", status, body)
	}

	status, body = scopedAPIRequest(t, backupURL, token, organizationID, http.MethodPost, map[string]any{})
	var backup store.VolumeBackup
	if err = json.Unmarshal(body, &backup); status != http.StatusAccepted || err != nil {
		t.Fatalf("queue restorable backup status=%d body=%s err=%v", status, body, err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE volume_backups SET status='succeeded',object_key='private/object',size_bytes=42,sha256=$2,plaintext_sha256=$3,encrypted_data_key='wrapped-secret',finished_at=now() WHERE id=$1`, backup.ID, strings.Repeat("a", 64), strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	status, body = scopedAPIRequest(t, server.URL+"/v1/volume-backups/"+backup.ID.String(), token, organizationID, http.MethodGet, nil)
	if status != http.StatusOK || bytes.Contains(body, []byte("wrapped-secret")) {
		t.Fatalf("get backup status=%d body=%s", status, body)
	}
	status, body = scopedAPIRequest(t, server.URL+"/v1/volume-backups/"+backup.ID.String()+"/restore", token, organizationID, http.MethodPost, map[string]string{"confirm": "wrong"})
	if status != http.StatusConflict {
		t.Fatalf("unconfirmed restore status=%d body=%s", status, body)
	}
	status, body = scopedAPIRequest(t, server.URL+"/v1/volume-backups/"+backup.ID.String()+"/restore", token, organizationID, http.MethodPost, map[string]string{"confirm": "app"})
	var restore store.VolumeRestore
	if err = json.Unmarshal(body, &restore); status != http.StatusAccepted || err != nil {
		t.Fatalf("restore status=%d body=%s err=%v", status, body, err)
	}
	status, body = scopedAPIRequest(t, server.URL+"/v1/volume-restores/"+restore.ID.String()+"/cancel", token, organizationID, http.MethodPost, map[string]any{})
	if status != http.StatusAccepted {
		t.Fatalf("cancel restore status=%d body=%s", status, body)
	}
	status, body = scopedAPIRequest(t, server.URL+"/v1/volume-backups/"+backup.ID.String(), token, otherOrganizationID, http.MethodGet, nil)
	if status != http.StatusNotFound {
		t.Fatalf("cross-tenant backup status=%d body=%s", status, body)
	}
}
