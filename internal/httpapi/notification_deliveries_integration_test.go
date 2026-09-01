package httpapi

import (
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

func TestNotificationDeliveryHistoryAndRetryAPI(t *testing.T) {
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
	organizationID, otherOrganizationID := uuid.New(), uuid.New()
	adminID, viewerID, otherAdminID := uuid.New(), uuid.New(), uuid.New()
	adminToken, viewerToken, otherAdminToken := "notification-admin-"+uuid.NewString(), "notification-viewer-"+uuid.NewString(), "notification-other-"+uuid.NewString()
	endpointID, disabledEndpointID, otherEndpointID := uuid.New(), uuid.New(), uuid.New()
	deliveryID, activeDeliveryID, disabledDeliveryID, otherDeliveryID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Notification API',$2),($3,'Other notification API',$4)`, []any{organizationID, "notification-api-" + organizationID.String(), otherOrganizationID, "notification-api-" + otherOrganizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test'),($3,$4,'!test'),($5,$6,'!test')`, []any{adminID, adminID.String() + "@example.test", viewerID, viewerID.String() + "@example.test", otherAdminID, otherAdminID.String() + "@example.test"}},
		{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'admin'),($1,$3,'viewer'),($4,$5,'admin')`, []any{organizationID, adminID, viewerID, otherOrganizationID, otherAdminID}},
		{`INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '10 minutes'),($4,$5,$6,now()+interval '10 minutes'),($7,$8,$9,now()+interval '10 minutes')`, []any{uuid.New(), adminID, cryptox.Digest(adminToken), uuid.New(), viewerID, cryptox.Digest(viewerToken), uuid.New(), otherAdminID, cryptox.Digest(otherAdminToken)}},
		{`INSERT INTO notification_endpoints(id,organization_id,name,kind,encrypted_url,encrypted_secret,events,enabled) VALUES($1,$2,'Primary','webhook','encrypted-url','encrypted-secret',ARRAY['backup.failed'],true),($3,$2,'Disabled','webhook','disabled-url','disabled-secret',ARRAY['backup.failed'],false),($4,$5,'Foreign','webhook','foreign-url','foreign-secret',ARRAY['backup.failed'],true)`, []any{endpointID, organizationID, disabledEndpointID, otherEndpointID, otherOrganizationID}},
		{`INSERT INTO notification_deliveries(id,endpoint_id,event_type,resource_type,resource_id,payload,status,last_error,finished_at) VALUES($1,$2,'backup.failed','database','db-1',$3,'failed','provider secret error',now()),($4,$2,'backup.failed','database','db-2','{}','failed','transient',now()),($5,$6,'backup.failed','database','db-3','{}','failed','disabled',now()),($7,$8,'backup.failed','database','db-4','{}','failed','foreign',now())`, []any{deliveryID, endpointID, []byte(`{"secret":"history-must-not-leak"}`), activeDeliveryID, disabledDeliveryID, disabledEndpointID, otherDeliveryID, otherEndpointID}},
		{`INSERT INTO jobs(id,kind,payload,status,attempts,max_attempts,last_error,finished_at) VALUES($1,'notify.webhook',$2,'failed',8,8,'provider failed',now())`, []any{uuid.New(), []byte(`{"deliveryId":"` + deliveryID.String() + `"}`)}},
		{`INSERT INTO jobs(id,kind,payload,status,attempts,max_attempts,last_error,run_after) VALUES($1,'notify.webhook',$2,'pending',1,8,'transient',now()+interval '1 minute')`, []any{uuid.New(), []byte(`{"deliveryId":"` + activeDeliveryID.String() + `"}`)}},
	}
	for _, statement := range statements {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id IN ($1,$2)`, organizationID, otherOrganizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id IN ($1,$2,$3)`, adminID, viewerID, otherAdminID)
	})

	server := httptest.NewServer((&Server{Store: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler())
	t.Cleanup(server.Close)
	status, body := scopedAPIRequest(t, server.URL+"/v1/notification-deliveries?status=failed&event=backup.failed&limit=10", adminToken, organizationID, http.MethodGet, nil)
	if status != http.StatusOK || strings.Contains(string(body), "history-must-not-leak") || strings.Contains(string(body), "provider secret error") || strings.Contains(string(body), otherDeliveryID.String()) {
		t.Fatalf("delivery history status=%d body=%s", status, body)
	}
	var history struct {
		Items []store.NotificationDelivery `json:"items"`
	}
	if err = json.Unmarshal(body, &history); err != nil || len(history.Items) != 3 {
		t.Fatalf("delivery history=%#v body=%s err=%v", history.Items, body, err)
	}
	posture := map[uuid.UUID]store.NotificationDelivery{}
	for _, item := range history.Items {
		posture[item.ID] = item
	}
	if !posture[deliveryID].Retryable || posture[deliveryID].InProgress || posture[activeDeliveryID].Retryable || !posture[activeDeliveryID].InProgress || posture[disabledDeliveryID].Retryable {
		t.Fatalf("delivery API posture=%#v", posture)
	}
	for _, endpoint := range []string{
		server.URL + "/v1/notification-deliveries?status=invalid",
		server.URL + "/v1/notification-deliveries?event=unknown.event",
		server.URL + "/v1/notification-deliveries?limit=201",
	} {
		if status, _ = scopedAPIRequest(t, endpoint, adminToken, organizationID, http.MethodGet, nil); status != http.StatusBadRequest {
			t.Fatalf("invalid delivery query %s status=%d", endpoint, status)
		}
	}
	if status, _ = scopedAPIRequest(t, server.URL+"/v1/notification-deliveries", viewerToken, organizationID, http.MethodGet, nil); status != http.StatusForbidden {
		t.Fatalf("viewer history status=%d, want 403", status)
	}
	if status, body = scopedAPIRequest(t, server.URL+"/v1/notification-deliveries", otherAdminToken, otherOrganizationID, http.MethodGet, nil); status != http.StatusOK || !strings.Contains(string(body), otherDeliveryID.String()) || strings.Contains(string(body), deliveryID.String()) {
		t.Fatalf("foreign tenant history status=%d body=%s", status, body)
	}
	if status, _ = scopedAPIRequest(t, server.URL+"/v1/notification-deliveries/"+deliveryID.String()+"/retry", viewerToken, organizationID, http.MethodPost, nil); status != http.StatusForbidden {
		t.Fatalf("viewer retry status=%d, want 403", status)
	}
	if status, _ = scopedAPIRequest(t, server.URL+"/v1/notification-deliveries/"+otherDeliveryID.String()+"/retry", adminToken, organizationID, http.MethodPost, nil); status != http.StatusNotFound {
		t.Fatalf("cross-tenant retry status=%d, want 404", status)
	}
	if status, body = scopedAPIRequest(t, server.URL+"/v1/notification-deliveries/"+activeDeliveryID.String()+"/retry", adminToken, organizationID, http.MethodPost, nil); status != http.StatusConflict || !strings.Contains(string(body), `"code":"delivery_in_progress"`) {
		t.Fatalf("active retry status=%d body=%s", status, body)
	}
	if status, body = scopedAPIRequest(t, server.URL+"/v1/notification-deliveries/"+disabledDeliveryID.String()+"/retry", adminToken, organizationID, http.MethodPost, nil); status != http.StatusConflict || !strings.Contains(string(body), `"code":"notification_endpoint_disabled"`) {
		t.Fatalf("disabled retry status=%d body=%s", status, body)
	}
	if status, body = scopedAPIRequest(t, server.URL+"/v1/notification-deliveries/"+deliveryID.String()+"/retry", adminToken, organizationID, http.MethodPost, nil); status != http.StatusAccepted || strings.Contains(string(body), "history-must-not-leak") || !strings.Contains(string(body), `"status":"pending"`) || !strings.Contains(string(body), `"inProgress":true`) {
		t.Fatalf("redrive status=%d body=%s", status, body)
	}
	if status, body = scopedAPIRequest(t, server.URL+"/v1/notification-deliveries/"+deliveryID.String()+"/retry", adminToken, organizationID, http.MethodPost, nil); status != http.StatusConflict || !strings.Contains(string(body), `"code":"delivery_in_progress"`) {
		t.Fatalf("duplicate redrive status=%d body=%s", status, body)
	}
	var jobs, audits int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE kind='notify.webhook' AND payload->>'deliveryId'=$1`, deliveryID.String()).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND action='notification_delivery.retry' AND resource_id=$3`, organizationID, adminID, deliveryID.String()).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if jobs != 2 || audits != 1 {
		t.Fatalf("redrive jobs=%d audits=%d", jobs, audits)
	}
}
