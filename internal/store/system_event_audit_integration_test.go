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

func TestDatabaseMigrationQueueCommitsWithSystemAudit(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, projectID, environmentID, serviceID, databaseID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Migration system audit',$2)`, []any{organizationID, "migration-system-audit-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'Database','database',$3,'services: {}')`, []any{serviceID, environmentID, "migration-system-audit-" + serviceID.String()}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,compose_service_id,encrypted_credentials,status) VALUES($1,$2,'Database','database','postgres','17',$3,'encrypted','running')`, []any{databaseID, environmentID, serviceID}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS reject_database_migration_queue_audit ON audit_events`)
		_, _ = pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS reject_database_migration_queue_audit()`)
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	})
	if _, err := pool.Exec(ctx, `CREATE FUNCTION reject_database_migration_queue_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='database_migration.queue' THEN RAISE EXCEPTION 'forced audit failure'; END IF; RETURN NEW; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `CREATE TRIGGER reject_database_migration_queue_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_database_migration_queue_audit()`); err != nil {
		t.Fatal(err)
	}
	failedID := uuid.New()
	input := DatabaseMigration{ID: failedID, DatabaseInstanceID: databaseID, SourceKind: "dokploy", SourceID: "source-db", SourceEngine: "postgres", SourceVersion: "17", SourceHost: "source.internal", EncryptedSourceConfig: "encrypted"}
	if _, err := db.QueueDatabaseMigrationWithSystemAudit(ctx, organizationID, input, "cli"); err == nil {
		t.Fatal("database migration queued without audit evidence")
	}
	var migrations, jobs int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM database_migrations WHERE id=$1`, failedID).Scan(&migrations); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE kind='migrate.database' AND payload->>'migrationId'=$1`, failedID.String()).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if migrations != 0 || jobs != 0 {
		t.Fatalf("failed evidence retained migration work: migrations=%d jobs=%d", migrations, jobs)
	}
	if _, err := pool.Exec(ctx, `DROP TRIGGER reject_database_migration_queue_audit ON audit_events`); err != nil {
		t.Fatal(err)
	}
	input.ID = uuid.New()
	queued, err := db.QueueDatabaseMigrationWithSystemAudit(ctx, organizationID, input, "cli")
	if err != nil || queued.Status != "queued" {
		t.Fatalf("audited database migration=%#v err=%v", queued, err)
	}
	var count int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id IS NULL AND actor_service_account_id IS NULL AND action='database_migration.queue' AND resource_id=$2`, organizationID, queued.ID.String()).Scan(&count); err != nil || count != 1 {
		t.Fatalf("database migration audit count=%d err=%v", count, err)
	}
}

func TestTemplateRepositoryPublicationCommitsWithSystemAudit(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Template system audit',$2)`, organizationID, "template-system-audit-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS reject_template_sync_audit ON audit_events`)
		_, _ = pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS reject_template_sync_audit()`)
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	})
	repository, err := db.CreateTemplateRepository(ctx, TemplateRepository{OrganizationID: organizationID, Name: "Catalog", Slug: "catalog", RepositoryURL: "https://github.com/acme/catalog", GitRef: "main"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.QueueTemplateRepositorySync(ctx, organizationID, repository.ID); err != nil {
		t.Fatal(err)
	}
	claimed, err := db.ClaimDueTemplateRepository(ctx)
	if err != nil || claimed.SyncAttemptID == nil {
		t.Fatalf("claimed repository=%#v err=%v", claimed, err)
	}
	oldTemplate := Template{OrganizationID: &organizationID, RepositoryID: &repository.ID, Key: "catalog/redis", Version: "1", Name: "Old Redis", ComposeYAML: "services: {}", Source: "github", SourcePath: "blueprints/redis", Checksum: "old"}
	if err = db.ReplaceRepositoryTemplatesForSync(ctx, claimed, []Template{oldTemplate}); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `CREATE FUNCTION reject_template_sync_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='template_repository.sync' THEN RAISE EXCEPTION 'forced audit failure'; END IF; RETURN NEW; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `CREATE TRIGGER reject_template_sync_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_template_sync_audit()`); err != nil {
		t.Fatal(err)
	}
	metadata := map[string]any{"imported": 1, "scheduled": true}
	newTemplate := Template{OrganizationID: &organizationID, RepositoryID: &repository.ID, Key: "catalog/postgres", Version: "1", Name: "New Postgres", ComposeYAML: "services: {}", Source: "github", SourcePath: "blueprints/postgres", Checksum: "new"}
	if err = db.PublishRepositoryTemplatesForSyncWithAudit(ctx, claimed, []Template{newTemplate}, "scheduler", metadata); err == nil {
		t.Fatal("template catalog published without audit evidence")
	}
	stored, err := db.GetTemplateRepository(ctx, organizationID, repository.ID)
	if err != nil || stored.LastSyncStatus != "running" || stored.SyncAttemptID == nil || *stored.SyncAttemptID != *claimed.SyncAttemptID {
		t.Fatalf("failed evidence finalized template sync: repository=%#v err=%v", stored, err)
	}
	var templateName string
	if err = pool.QueryRow(ctx, `SELECT name FROM templates WHERE repository_id=$1`, repository.ID).Scan(&templateName); err != nil || templateName != "Old Redis" {
		t.Fatalf("failed evidence changed published catalog: name=%q err=%v", templateName, err)
	}
	if _, err = pool.Exec(ctx, `DROP TRIGGER reject_template_sync_audit ON audit_events`); err != nil {
		t.Fatal(err)
	}
	if err = db.PublishRepositoryTemplatesForSyncWithAudit(ctx, claimed, []Template{newTemplate}, "scheduler", metadata); err != nil {
		t.Fatal(err)
	}
	stored, err = db.GetTemplateRepository(ctx, organizationID, repository.ID)
	if err != nil || stored.LastSyncStatus != "succeeded" || stored.SyncAttemptID != nil {
		t.Fatalf("audited template sync finalization=%#v err=%v", stored, err)
	}
	if err = pool.QueryRow(ctx, `SELECT name FROM templates WHERE repository_id=$1`, repository.ID).Scan(&templateName); err != nil || templateName != "New Postgres" {
		t.Fatalf("audited catalog publication: name=%q err=%v", templateName, err)
	}
	var count int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id IS NULL AND actor_service_account_id IS NULL AND action='template_repository.sync' AND resource_id=$2`, organizationID, repository.ID.String()).Scan(&count); err != nil || count != 1 {
		t.Fatalf("template sync audit count=%d err=%v", count, err)
	}
}
