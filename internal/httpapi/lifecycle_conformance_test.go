package httpapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/deploy"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestLifecycleAPIConformance joins the operator-visible deployment lifecycle
// into one scenario. Lower-level lease takeover and remote-agent fencing are
// exercised by the companion deploy-package tests selected by
// scripts/ci/test-lifecycle-conformance.sh.
func TestLifecycleAPIConformance(t *testing.T) {
	if os.Getenv("DOCKYARD_LIFECYCLE_CONFORMANCE") != "1" {
		t.Skip("set DOCKYARD_LIFECYCLE_CONFORMANCE=1 to run lifecycle conformance")
	}
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("DOCKYARD_TEST_DATABASE_URL is required for lifecycle conformance")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "lifecycle_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(ctx, fmt.Sprintf(`CREATE SCHEMA %s`, schema)); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), fmt.Sprintf(`DROP SCHEMA %s CASCADE`, schema))
		admin.Close()
	})
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err = store.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &store.Store{Pool: pool}
	box, err := cryptox.New(bytes.Repeat([]byte{17}, 32))
	if err != nil {
		t.Fatal(err)
	}

	organizationID, userID, projectID, environmentID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	successServiceID, failureServiceID, cancelledServiceID, webhookServiceID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	token := "lifecycle-" + uuid.NewString()
	successV1 := "services:\n  app:\n    image: example.invalid/success-v1:1\n"
	successV2 := "services:\n  app:\n    image: example.invalid/success-v2:1\n"
	failureCompose := "services:\n  app:\n    image: example.invalid/failure-marker:1\n"
	cancelledCompose := "services:\n  app:\n    image: example.invalid/cancelled-marker:1\n"
	webhookCompose := "services:\n  app:\n    image: example.invalid/webhook-marker:1\n"
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Lifecycle conformance',$2)`, []any{organizationID, "lifecycle-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!conformance')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')`, []any{organizationID, userID}},
		{`INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '10 minutes')`, []any{uuid.New(), userID, cryptox.Digest(token)}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'Success','success',$3,$4)`, []any{successServiceID, environmentID, "lifecycle-success-" + successServiceID.String(), successV1}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'Failure','failure',$3,$4)`, []any{failureServiceID, environmentID, "lifecycle-failure-" + failureServiceID.String(), failureCompose}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'Cancelled','cancelled',$3,$4)`, []any{cancelledServiceID, environmentID, "lifecycle-cancelled-" + cancelledServiceID.String(), cancelledCompose}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'Webhook','webhook',$3,$4)`, []any{webhookServiceID, environmentID, "lifecycle-webhook-" + webhookServiceID.String(), webhookCompose}},
	}
	for _, statement := range statements {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})

	var captureMu sync.Mutex
	notificationSecret := ""
	notificationValid := false
	commitStates := map[string]bool{}
	outbound := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			http.Error(w, readErr.Error(), http.StatusBadRequest)
			return
		}
		captureMu.Lock()
		defer captureMu.Unlock()
		if r.URL.Path == "/notification" {
			timestamp := r.Header.Get("X-Dockyard-Timestamp")
			mac := hmac.New(sha256.New, []byte(notificationSecret))
			_, _ = mac.Write([]byte(timestamp + "."))
			_, _ = mac.Write(body)
			expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
			notificationValid = notificationSecret != "" && hmac.Equal([]byte(expected), []byte(r.Header.Get("X-Dockyard-Signature-256"))) && r.Header.Get("X-Dockyard-Event") == "deployment.failed"
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/repos/acme/api/statuses/") && r.Header.Get("Authorization") == "Bearer status-token" {
			var payload struct {
				State string `json:"state"`
			}
			if json.Unmarshal(body, &payload) == nil {
				commitStates[payload.State] = true
			}
			w.WriteHeader(http.StatusCreated)
			return
		}
		http.Error(w, "unexpected outbound request", http.StatusBadRequest)
	}))
	defer outbound.Close()
	outboundURL, err := url.Parse(outbound.URL)
	if err != nil {
		t.Fatal(err)
	}
	baseTransport := outbound.Client().Transport.(*http.Transport).Clone()
	client := &http.Client{Timeout: 5 * time.Second, Transport: lifecycleRewriteTransport{base: baseTransport, target: outboundURL}}

	scheduler := &lifecycleScheduler{}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	api := httptest.NewServer((&Server{Store: db, Box: box, Compiler: deploy.Compiler{PublicNetwork: "dockyard-public"}, Swarm: scheduler, PublicURL: "https://dockyard.example.test", Logger: logger}).Handler())
	defer api.Close()

	status, body := scopedAPIRequest(t, api.URL+"/v1/notification-endpoints", token, organizationID, http.MethodPost, map[string]any{
		"name": "lifecycle-webhook", "kind": "webhook", "url": outbound.URL + "/notification", "events": []string{"deployment.failed"},
	})
	if status != http.StatusCreated {
		t.Fatalf("create notification endpoint status=%d body=%s", status, body)
	}
	var notificationResponse struct {
		SigningSecret string `json:"signingSecret"`
	}
	if err = json.Unmarshal(body, &notificationResponse); err != nil || notificationResponse.SigningSecret == "" {
		t.Fatalf("notification endpoint response=%s err=%v", body, err)
	}
	captureMu.Lock()
	notificationSecret = notificationResponse.SigningSecret
	captureMu.Unlock()

	queueDeployment := func(serviceID uuid.UUID) store.Deployment {
		t.Helper()
		requestStatus, responseBody := scopedAPIRequest(t, api.URL+"/v1/services/"+serviceID.String()+"/deployments", token, organizationID, http.MethodPost, map[string]any{})
		if requestStatus != http.StatusAccepted {
			t.Fatalf("queue deployment status=%d body=%s", requestStatus, responseBody)
		}
		var deployment store.Deployment
		if unmarshalErr := json.Unmarshal(responseBody, &deployment); unmarshalErr != nil {
			t.Fatal(unmarshalErr)
		}
		return deployment
	}
	successDeployment := queueDeployment(successServiceID)
	failureDeployment := queueDeployment(failureServiceID)
	cancelledDeployment := queueDeployment(cancelledServiceID)
	if _, err = db.Pool.Exec(ctx, `UPDATE jobs SET max_attempts=1 WHERE kind='deploy.compose' AND payload->>'deploymentId'=$1`, failureDeployment.ID.String()); err != nil {
		t.Fatal(err)
	}
	status, body = scopedAPIRequest(t, api.URL+"/v1/deployments/"+cancelledDeployment.ID.String()+"/cancel", token, organizationID, http.MethodPost, map[string]any{})
	if status != http.StatusAccepted {
		t.Fatalf("cancel deployment status=%d body=%s", status, body)
	}

	workerCtx, stopWorker := context.WithCancel(ctx)
	workerDone := make(chan struct{})
	worker := &deploy.Worker{Store: db, Box: box, Compiler: deploy.Compiler{PublicNetwork: "dockyard-public"}, Swarm: scheduler, Concurrency: 1, Logger: logger, ID: "lifecycle-worker", NotificationClient: client}
	go func() {
		worker.Run(workerCtx)
		close(workerDone)
	}()
	stop := func() {
		stopWorker()
		select {
		case <-workerDone:
		case <-time.After(5 * time.Second):
			t.Fatal("worker did not stop")
		}
	}
	workerStopped := false
	t.Cleanup(func() {
		if !workerStopped {
			stopWorker()
			<-workerDone
		}
	})

	waitLifecycleCondition(t, ctx, "successful and failed deployments plus notification", func() (bool, error) {
		var succeeded, failed, cancelled, delivery string
		err := db.Pool.QueryRow(ctx, `SELECT
			(SELECT status FROM deployments WHERE id=$1),
			(SELECT status FROM deployments WHERE id=$2),
			(SELECT status FROM deployments WHERE id=$3),
			COALESCE((SELECT status FROM notification_deliveries WHERE resource_id=$2::text ORDER BY created_at DESC LIMIT 1),'')`,
			successDeployment.ID, failureDeployment.ID, cancelledDeployment.ID).Scan(&succeeded, &failed, &cancelled, &delivery)
		return succeeded == "succeeded" && failed == "failed" && cancelled == "cancelled" && delivery == "succeeded", err
	})
	captureMu.Lock()
	validNotification := notificationValid
	captureMu.Unlock()
	if !validNotification {
		t.Fatal("failure notification was not signed correctly")
	}
	resolvedImage := "example.invalid/conformance@sha256:" + strings.Repeat("a", 64)
	var effectiveCompose string
	if err = db.Pool.QueryRow(ctx, `SELECT effective_compose FROM deployments WHERE id=$1`, successDeployment.ID).Scan(&effectiveCompose); err != nil || !strings.Contains(effectiveCompose, resolvedImage) || strings.Contains(effectiveCompose, "success-v1:1") {
		t.Fatalf("successful deployment did not persist its resolved image: compose=%q err=%v", effectiveCompose, err)
	}

	status, body = scopedAPIRequest(t, api.URL+"/v1/services/"+successServiceID.String(), token, organizationID, http.MethodPatch, map[string]any{"composeYaml": successV2})
	if status != http.StatusOK {
		t.Fatalf("update service status=%d body=%s", status, body)
	}
	status, body = scopedAPIRequest(t, api.URL+"/v1/services/"+successServiceID.String()+"/rollback", token, organizationID, http.MethodPost, map[string]any{})
	if status != http.StatusAccepted {
		t.Fatalf("rollback status=%d body=%s", status, body)
	}
	var rollback store.Deployment
	if err = json.Unmarshal(body, &rollback); err != nil {
		t.Fatal(err)
	}
	waitLifecycleCondition(t, ctx, "rollback deployment", func() (bool, error) {
		var state string
		err := db.Pool.QueryRow(ctx, `SELECT status FROM deployments WHERE id=$1`, rollback.ID).Scan(&state)
		return state == "succeeded", err
	})
	if rollback.Trigger != "rollback" || !scheduler.deployedAtLeast(resolvedImage, 1) {
		t.Fatalf("rollback did not redeploy the last successful snapshot: trigger=%q deploys=%v", rollback.Trigger, scheduler.snapshot())
	}
	stop()
	workerStopped = true

	credentialID := uuid.New()
	encryptedCredential, err := box.Encrypt([]byte("status-token"), cryptox.ResourceContext("source-credential", credentialID.String()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Pool.Exec(ctx, `INSERT INTO source_credentials(id,organization_id,kind,name,server,username,encrypted_secret) VALUES($1,$2,'git','lifecycle-status','github.com','bot',$3)`, credentialID, organizationID, encryptedCredential); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Pool.Exec(ctx, `INSERT INTO application_sources(compose_service_id,repository_url,target_service,registry_image,status_provider,status_credential_id,status_context) VALUES($1,'https://github.com/acme/api.git','app','registry.example/acme/api','github',$2,'dockyard/deploy')`, webhookServiceID, credentialID); err != nil {
		t.Fatal(err)
	}
	status, body = scopedAPIRequest(t, api.URL+"/v1/services/"+webhookServiceID.String()+"/webhooks", token, organizationID, http.MethodPost, map[string]string{"name": "github-main", "provider": "github", "branch": "main"})
	if status != http.StatusCreated {
		t.Fatalf("create provider webhook status=%d body=%s", status, body)
	}
	var webhook struct {
		Integration store.WebhookIntegration `json:"integration"`
		Secret      string                   `json:"secret"`
	}
	if err = json.Unmarshal(body, &webhook); err != nil || webhook.Secret == "" {
		t.Fatalf("webhook response=%s err=%v", body, err)
	}
	commitSHA := strings.Repeat("a", 40)
	webhookPayload := []byte(`{"ref":"refs/heads/main","after":"` + commitSHA + `","deleted":false}`)
	mac := hmac.New(sha256.New, []byte(webhook.Secret))
	_, _ = mac.Write(webhookPayload)
	hookRequest, _ := http.NewRequest(http.MethodPost, api.URL+"/v1/hooks/provider/"+webhook.Integration.ID.String(), bytes.NewReader(webhookPayload))
	hookRequest.Header.Set("X-GitHub-Event", "push")
	hookRequest.Header.Set("X-GitHub-Delivery", "lifecycle-delivery")
	hookRequest.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	hookResponse, err := http.DefaultClient.Do(hookRequest)
	if err != nil {
		t.Fatal(err)
	}
	hookBody, _ := io.ReadAll(hookResponse.Body)
	hookResponse.Body.Close()
	if hookResponse.StatusCode != http.StatusAccepted {
		t.Fatalf("provider webhook status=%d body=%s", hookResponse.StatusCode, hookBody)
	}
	var webhookDeployment store.Deployment
	if err = json.Unmarshal(hookBody, &webhookDeployment); err != nil {
		t.Fatal(err)
	}
	replayRequest := hookRequest.Clone(ctx)
	replayRequest.Body = io.NopCloser(bytes.NewReader(webhookPayload))
	replayResponse, err := http.DefaultClient.Do(replayRequest)
	if err != nil {
		t.Fatal(err)
	}
	replayResponse.Body.Close()
	if replayResponse.StatusCode != http.StatusConflict {
		t.Fatalf("provider webhook replay status=%d, want 409", replayResponse.StatusCode)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE jobs SET status='cancelled',cancel_requested_at=now(),finished_at=now() WHERE kind='deploy.compose' AND payload->>'deploymentId'=$1`, webhookDeployment.ID.String()); err != nil {
		t.Fatal(err)
	}
	if err = db.FinishDeployment(ctx, webhookDeployment.ID, "succeeded", "conformance status delivery", ""); err != nil {
		t.Fatal(err)
	}

	deliveryCtx, stopDeliveryWorker := context.WithCancel(ctx)
	deliveryDone := make(chan struct{})
	deliveryWorker := &deploy.Worker{Store: db, Box: box, Compiler: deploy.Compiler{PublicNetwork: "dockyard-public"}, Swarm: scheduler, Concurrency: 1, Logger: logger, ID: "lifecycle-delivery-worker", NotificationClient: client}
	go func() {
		deliveryWorker.Run(deliveryCtx)
		close(deliveryDone)
	}()
	waitLifecycleCondition(t, ctx, "pending and success commit statuses", func() (bool, error) {
		var count int
		err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM commit_status_deliveries WHERE deployment_id=$1 AND status='succeeded'`, webhookDeployment.ID).Scan(&count)
		return count == 2, err
	})
	stopDeliveryWorker()
	select {
	case <-deliveryDone:
	case <-time.After(5 * time.Second):
		t.Fatal("delivery worker did not stop")
	}
	captureMu.Lock()
	statusPending, statusSuccess := commitStates["pending"], commitStates["success"]
	captureMu.Unlock()
	if !statusPending || !statusSuccess {
		t.Fatalf("commit status states delivered=%v", commitStates)
	}

	evidence, _ := json.Marshal(map[string]any{
		"status":                       "passed",
		"deploySucceeded":              true,
		"deployFailed":                 true,
		"deploymentCancelled":          true,
		"rollbackSucceeded":            true,
		"resolvedImageSnapshot":        true,
		"signedWebhookAccepted":        true,
		"webhookReplayRejected":        true,
		"commitStatusDelivered":        true,
		"failureNotificationDelivered": true,
	})
	fmt.Printf("LIFECYCLE_EVIDENCE %s\n", evidence)
}

type lifecycleScheduler struct {
	mu      sync.Mutex
	deploys []string
}

func (s *lifecycleScheduler) Deploy(_ context.Context, _ string, compose string, _ map[string]string, _ *deploy.Credential) (deploy.DeploymentResult, error) {
	s.mu.Lock()
	s.deploys = append(s.deploys, compose)
	s.mu.Unlock()
	if strings.Contains(compose, "failure-marker") {
		return deploy.DeploymentResult{Output: "scheduler rejected fixture"}, errors.New("conformance deployment failure")
	}
	return deploy.DeploymentResult{Output: "scheduler accepted fixture", ResolvedImages: map[string]string{"app": "example.invalid/conformance@sha256:" + strings.Repeat("a", 64)}}, nil
}

func (s *lifecycleScheduler) Remove(context.Context, string) (string, error)        { return "", nil }
func (s *lifecycleScheduler) RemoveVolumes(context.Context, string) (string, error) { return "", nil }
func (s *lifecycleScheduler) Logs(context.Context, string, int) (string, error)     { return "", nil }
func (s *lifecycleScheduler) Nodes(context.Context) ([]deploy.Node, error)          { return nil, nil }
func (s *lifecycleScheduler) RunContainerJob(context.Context, string, string, string, map[string]string, []string) (string, error) {
	return "", nil
}

func (s *lifecycleScheduler) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.deploys...)
}

func (s *lifecycleScheduler) deployedAtLeast(marker string, count int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	matched := 0
	for _, deployed := range s.deploys {
		if strings.Contains(deployed, marker) {
			matched++
		}
	}
	return matched >= count
}

type lifecycleRewriteTransport struct {
	base   http.RoundTripper
	target *url.URL
}

func (t lifecycleRewriteTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Hostname() != "api.github.com" {
		return t.base.RoundTrip(request)
	}
	clone := request.Clone(request.Context())
	clone.URL.Scheme = t.target.Scheme
	clone.URL.Host = t.target.Host
	return t.base.RoundTrip(clone)
}

func waitLifecycleCondition(t *testing.T, ctx context.Context, description string, condition func() (bool, error)) {
	t.Helper()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		ready, err := condition()
		if err != nil {
			t.Fatalf("wait for %s: %v", description, err)
		}
		if ready {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for %s: %v", description, ctx.Err())
		case <-ticker.C:
		}
	}
}
