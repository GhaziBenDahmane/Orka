package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestClusterEnrollmentCommitsWithSystemAudit(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Enrollment system audit',$2)`, organizationID, "enrollment-system-audit-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS reject_cluster_enroll_audit ON audit_events`)
		_, _ = pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS reject_cluster_enroll_audit()`)
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	})
	cluster, err := db.CreateCluster(ctx, Cluster{OrganizationID: organizationID, Name: "Paris", Slug: "paris", Labels: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	tokenHash, csrHash := []byte("system-audit-token"), []byte("system-audit-csr")
	if err = db.CreateClusterEnrollmentToken(ctx, organizationID, cluster.ID, uuid.Nil, tokenHash, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	artifacts := ClusterEnrollmentArtifacts{Certificate: "certificate", CABundle: "bundle", SigningCACertificate: "signing-ca", SigningCAFingerprint: "sha256:" + strings.Repeat("a", 64)}
	notAfter := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Microsecond)
	if _, err = pool.Exec(ctx, `CREATE FUNCTION reject_cluster_enroll_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='cluster.enroll' THEN RAISE EXCEPTION 'forced audit failure'; END IF; RETURN NEW; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `CREATE TRIGGER reject_cluster_enroll_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_cluster_enroll_audit()`); err != nil {
		t.Fatal(err)
	}
	if _, _, err = db.CompleteClusterEnrollmentWithAudit(ctx, tokenHash, csrHash, artifacts, "012345", notAfter, "127.0.0.1:1234"); err == nil {
		t.Fatal("cluster enrollment completed without audit evidence")
	}
	var usedAt *time.Time
	if err = pool.QueryRow(ctx, `SELECT used_at FROM cluster_enrollment_tokens WHERE token_hash=$1`, tokenHash).Scan(&usedAt); err != nil || usedAt != nil {
		t.Fatalf("failed evidence consumed enrollment token: usedAt=%v err=%v", usedAt, err)
	}
	var state, serial string
	if err = pool.QueryRow(ctx, `SELECT state,certificate_serial FROM clusters WHERE id=$1`, cluster.ID).Scan(&state, &serial); err != nil || state == "active" || serial != "" {
		t.Fatalf("failed evidence activated cluster: state=%q serial=%q err=%v", state, serial, err)
	}
	if _, err = pool.Exec(ctx, `DROP TRIGGER reject_cluster_enroll_audit ON audit_events`); err != nil {
		t.Fatal(err)
	}
	stored, created, err := db.CompleteClusterEnrollmentWithAudit(ctx, tokenHash, csrHash, artifacts, "012345", notAfter, "127.0.0.1:1234")
	if err != nil || !created || stored != artifacts {
		t.Fatalf("audited cluster enrollment artifacts=%#v created=%t err=%v", stored, created, err)
	}
	var count int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id IS NULL AND actor_service_account_id IS NULL AND action='cluster.enroll' AND resource_id=$2`, organizationID, cluster.ID.String()).Scan(&count); err != nil || count != 1 {
		t.Fatalf("cluster enrollment audit count=%d err=%v", count, err)
	}
}

func TestWebhookDeploymentCommitsWithSystemAudit(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Webhook system audit',$2)`, []any{organizationID, "webhook-system-audit-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'API','api',$3,'services: {}')`, []any{serviceID, environmentID, "webhook-system-audit-" + serviceID.String()}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS reject_deployment_webhook_audit ON audit_events`)
		_, _ = pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS reject_deployment_webhook_audit()`)
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	})
	integration, err := db.CreateWebhookIntegration(ctx, organizationID, WebhookIntegration{ID: uuid.New(), ComposeServiceID: serviceID, Name: "GitHub", Provider: "github", Branch: "main", EncryptedSecret: "encrypted"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `CREATE FUNCTION reject_deployment_webhook_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='deployment.webhook' THEN RAISE EXCEPTION 'forced audit failure'; END IF; RETURN NEW; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `CREATE TRIGGER reject_deployment_webhook_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_deployment_webhook_audit()`); err != nil {
		t.Fatal(err)
	}
	failedDeliveryID := "delivery-failed"
	if _, err = db.QueueWebhookDeploymentWithAudit(ctx, integration.ID, failedDeliveryID, "abcdef0", "127.0.0.1:1234"); err == nil {
		t.Fatal("webhook deployment queued without audit evidence")
	}
	var deployments, deliveries, jobs int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM deployments WHERE compose_service_id=$1`, serviceID).Scan(&deployments); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM webhook_deliveries WHERE integration_id=$1`, integration.ID).Scan(&deliveries); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE resource_key=$1`, "service:"+serviceID.String()).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if deployments != 0 || deliveries != 0 || jobs != 0 {
		t.Fatalf("failed evidence retained webhook work: deployments=%d deliveries=%d jobs=%d", deployments, deliveries, jobs)
	}
	if _, err = pool.Exec(ctx, `DROP TRIGGER reject_deployment_webhook_audit ON audit_events`); err != nil {
		t.Fatal(err)
	}
	deployment, err := db.QueueWebhookDeploymentWithAudit(ctx, integration.ID, "delivery-success", "abcdef0", "127.0.0.1:1234")
	if err != nil || deployment.Status != "queued" {
		t.Fatalf("audited webhook deployment=%#v err=%v", deployment, err)
	}
	var count int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id IS NULL AND actor_service_account_id IS NULL AND action='deployment.webhook' AND resource_id=$2`, organizationID, deployment.ID.String()).Scan(&count); err != nil || count != 1 {
		t.Fatalf("webhook deployment audit count=%d err=%v", count, err)
	}
}
