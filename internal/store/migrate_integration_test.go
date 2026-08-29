package store

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func migrationTestPool(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "migration_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, fmt.Sprintf(`CREATE SCHEMA %s`, schema)); err != nil {
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
	return pool, ctx
}

func embeddedMigrationCount(t *testing.T) int {
	t.Helper()
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			count++
		}
	}
	return count
}

func TestMigrateFreshInstallIsCompleteAndIdempotent(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	want := embeddedMigrationCount(t)
	var count, checksummed int
	if err := pool.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE checksum<>'') FROM schema_migrations`).Scan(&count, &checksummed); err != nil {
		t.Fatal(err)
	}
	if count != want || checksummed != want {
		t.Fatalf("migration records count=%d checksummed=%d want=%d", count, checksummed, want)
	}
	organizationID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'survivor','survivor')`, organizationID); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("second migration run: %v", err)
	}
	var name string
	if err := pool.QueryRow(ctx, `SELECT name FROM organizations WHERE id=$1`, organizationID).Scan(&name); err != nil || name != "survivor" {
		t.Fatalf("data did not survive idempotent run: name=%q err=%v", name, err)
	}
}

func TestMigrateUpgradeFrom062AddsRemoteCatalogTrustPolicy(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := migrateThrough(ctx, pool, "062_ai_audits_and_template_repositories.sql"); err != nil {
		t.Fatal(err)
	}
	organizationID, repositoryID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'catalog org',$2)`, organizationID, "catalog-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO template_repositories(id,organization_id,name,slug,repository_url,git_ref) VALUES($1,$2,'Catalog','catalog','https://github.com/acme/catalog','main')`, repositoryID, organizationID); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var key string
	var required bool
	if err := pool.QueryRow(ctx, `SELECT trusted_public_key,require_signature FROM template_repositories WHERE id=$1`, repositoryID).Scan(&key, &required); err != nil {
		t.Fatal(err)
	}
	if key != "" || required {
		t.Fatalf("unexpected migrated trust policy key=%q required=%v", key, required)
	}
	if _, err := pool.Exec(ctx, `UPDATE template_repositories SET require_signature=true WHERE id=$1`, repositoryID); err == nil {
		t.Fatal("signature requirement accepted without a trusted public key")
	}
}

func TestMigrateUpgradeFrom063AddsTemplateRepositorySchedules(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := migrateThrough(ctx, pool, "063_remote_catalog_signing.sql"); err != nil {
		t.Fatal(err)
	}
	organizationID, repositoryID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'scheduled catalog org',$2)`, organizationID, "scheduled-catalog-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO template_repositories(id,organization_id,name,slug,repository_url,git_ref) VALUES($1,$2,'Catalog','catalog','https://github.com/acme/catalog','main')`, repositoryID, organizationID); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var interval int
	var nextSyncAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT sync_interval_seconds,next_sync_at FROM template_repositories WHERE id=$1`, repositoryID).Scan(&interval, &nextSyncAt); err != nil {
		t.Fatal(err)
	}
	if interval != 0 || nextSyncAt != nil {
		t.Fatalf("existing repository schedule interval=%d next=%v", interval, nextSyncAt)
	}
	if _, err := pool.Exec(ctx, `UPDATE template_repositories SET sync_interval_seconds=299 WHERE id=$1`, repositoryID); err == nil {
		t.Fatal("invalid template repository sync interval was accepted")
	}
}

func TestMigrateUpgradeFrom064AddsTemplateRepositoryCredentials(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := migrateThrough(ctx, pool, "064_template_repository_schedules.sql"); err != nil {
		t.Fatal(err)
	}
	organizationID, repositoryID, credentialID := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'private catalog org',$2)`, organizationID, "private-catalog-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO source_credentials(id,organization_id,kind,name,server,username,encrypted_secret) VALUES($1,$2,'git','GitHub','github.com','token','ciphertext')`, credentialID, organizationID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO template_repositories(id,organization_id,name,slug,repository_url,git_ref) VALUES($1,$2,'Catalog','catalog','https://github.com/acme/catalog','main')`, repositoryID, organizationID); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var storedCredentialID *uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT credential_id FROM template_repositories WHERE id=$1`, repositoryID).Scan(&storedCredentialID); err != nil {
		t.Fatal(err)
	}
	if storedCredentialID != nil {
		t.Fatalf("existing repository unexpectedly gained credential %v", storedCredentialID)
	}
	if _, err := pool.Exec(ctx, `UPDATE template_repositories SET credential_id=$2 WHERE id=$1`, repositoryID, credentialID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM source_credentials WHERE id=$1`, credentialID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT credential_id FROM template_repositories WHERE id=$1`, repositoryID).Scan(&storedCredentialID); err != nil || storedCredentialID != nil {
		t.Fatalf("credential deletion did not detach repository: credential=%v err=%v", storedCredentialID, err)
	}
}

func TestMigrateUpgradeFrom065AddsTemplateRepositoryWebhooks(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := migrateThrough(ctx, pool, "065_template_repository_credentials.sql"); err != nil {
		t.Fatal(err)
	}
	organizationID, repositoryID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'webhook catalog org',$2)`, organizationID, "webhook-catalog-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO template_repositories(id,organization_id,name,slug,repository_url,git_ref) VALUES($1,$2,'Catalog','catalog','https://github.com/acme/catalog','main')`, repositoryID, organizationID); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var encrypted string
	var requestedAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT encrypted_webhook_secret,sync_requested_at FROM template_repositories WHERE id=$1`, repositoryID).Scan(&encrypted, &requestedAt); err != nil {
		t.Fatal(err)
	}
	if encrypted != "" || requestedAt != nil {
		t.Fatalf("unexpected webhook migration defaults secret=%q requested=%v", encrypted, requestedAt)
	}
}

func TestMigrateUpgradeFrom034PreservesResources(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := migrateThrough(ctx, pool, "034_ssh_source_credentials.sql"); err != nil {
		t.Fatal(err)
	}
	organizationID, projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	seed := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'upgrade org','upgrade-org')`, []any{organizationID}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'upgrade project','upgrade-project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'api','api',$3,'services: {}')`, []any{serviceID, environmentID, "upgrade-" + serviceID.String()}},
	}
	for _, statement := range seed {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var serviceName string
	if err := pool.QueryRow(ctx, `SELECT name FROM compose_services WHERE id=$1`, serviceID).Scan(&serviceName); err != nil || serviceName != "api" {
		t.Fatalf("seeded service missing after upgrade: name=%q err=%v", serviceName, err)
	}
	for _, table := range []string{"commit_status_deliveries", "audit_archive_destinations", "dokploy_migration_resources"} {
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil || !exists {
			t.Errorf("expected upgraded table %s: exists=%v err=%v", table, exists, err)
		}
	}
	for _, version := range []string{"035_commit_statuses.sql", "041_dokploy_migration_metadata.sql", "046_oidc_nonce.sql", "047_application_build_settings.sql", "048_application_build_types.sql", "049_nixpacks_builds.sql", "050_railpack_builds.sql", "051_buildpack_builds.sql", "052_application_artifacts.sql", "053_custom_buildpack_builders.sql", "054_database_migrations.sql", "055_cluster_database_transfers.sql", "056_database_operation_serialization.sql", "057_preserve_cancelled_database_jobs.sql", "067_service_reconciliation.sql"} {
		var checksum string
		if err := pool.QueryRow(ctx, `SELECT checksum FROM schema_migrations WHERE version=$1`, version).Scan(&checksum); err != nil || checksum == "" {
			t.Errorf("migration %s lacks checksum: %q err=%v", version, checksum, err)
		}
	}
}

func TestMigrateRejectsChecksumMismatch(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE schema_migrations SET checksum='tampered' WHERE version='001_initial.sql'`); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("expected checksum mismatch, got %v", err)
	}
}

func TestMigrateUpgradeFrom066AddsReconciliationState(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := migrateThrough(ctx, pool, "066_template_repository_webhooks.sql"); err != nil {
		t.Fatal(err)
	}
	organizationID, projectID, environmentID, serviceID, deploymentID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'upgrade reconcile',$2)`, []any{organizationID, "upgrade-reconcile-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'app','app',$3,'services: {}')`, []any{serviceID, environmentID, "upgrade-reconcile-" + serviceID.String()}},
		{`INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,status,trigger) VALUES($1,$2,1,'services: {}','succeeded','manual')`, []any{deploymentID, serviceID}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var effective string
	var tableExists bool
	if err := pool.QueryRow(ctx, `SELECT effective_compose FROM deployments WHERE id=$1`, deploymentID).Scan(&effective); err != nil || effective != "" {
		t.Fatalf("effective snapshot=%q err=%v", effective, err)
	}
	if err := pool.QueryRow(ctx, `SELECT to_regclass('service_reconciliations') IS NOT NULL`).Scan(&tableExists); err != nil || !tableExists {
		t.Fatalf("reconciliation table exists=%v err=%v", tableExists, err)
	}
}

func TestMigrateUpgradeFrom067AddsAuthenticationRateLimits(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := migrateThrough(ctx, pool, "067_service_reconciliation.sql"); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('auth_rate_limits') IS NOT NULL`).Scan(&exists); err != nil || !exists {
		t.Fatalf("authentication rate-limit table missing: exists=%v err=%v", exists, err)
	}
}

func TestMigrateUpgradeFrom068ScopesFederatedSessions(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := migrateThrough(ctx, pool, "068_auth_rate_limits.sql"); err != nil {
		t.Fatal(err)
	}
	organizationID, userID := uuid.New(), uuid.New()
	var err error
	if _, err = pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'session scope',$2)`, organizationID, "session-scope-"+organizationID.String()); err == nil {
		_, err = pool.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, userID, userID.String()+"@example.test")
	}
	if err == nil {
		_, err = pool.Exec(ctx, `INSERT INTO sessions(id,user_id,token_hash,expires_at,auth_method) VALUES($1,$2,$3,now()+interval '1 hour','local'),($4,$2,$5,now()+interval '1 hour','oidc'),($6,$2,$7,now()+interval '1 hour','saml')`, uuid.New(), userID, []byte("local"), uuid.New(), []byte("oidc"), uuid.New(), []byte("saml"))
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var localCount, federatedCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE auth_method='local'),count(*) FILTER (WHERE auth_method<>'local') FROM sessions WHERE user_id=$1`, userID).Scan(&localCount, &federatedCount); err != nil {
		t.Fatal(err)
	}
	if localCount != 1 || federatedCount != 0 {
		t.Fatalf("migrated sessions local=%d federated=%d, want 1 and 0", localCount, federatedCount)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO sessions(id,user_id,token_hash,expires_at,auth_method) VALUES($1,$2,$3,now()+interval '1 hour','oidc')`, uuid.New(), userID, []byte("unscoped")); err == nil {
		t.Fatal("unscoped federated session was accepted")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO sessions(id,user_id,organization_id,token_hash,expires_at,auth_method) VALUES($1,$2,$3,$4,now()+interval '1 hour','oidc')`, uuid.New(), userID, organizationID, []byte("scoped")); err != nil {
		t.Fatalf("scoped federated session was rejected: %v", err)
	}
}

func TestMigrateUpgradeFrom069ExpiresLegacySCIMTokens(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := migrateThrough(ctx, pool, "069_federated_session_scope.sql"); err != nil {
		t.Fatal(err)
	}
	organizationID, tokenID := uuid.New(), uuid.New()
	tokenHash := []byte("legacy-scim-token")
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'SCIM expiry',$2)`, organizationID, "scim-expiry-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO scim_tokens(id,organization_id,name,token_hash,default_role,created_at) VALUES($1,$2,'legacy',$3,'developer',now()-interval '1 year')`, tokenID, organizationID, tokenHash); err != nil {
		t.Fatal(err)
	}
	migratedAt := time.Now()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var expiresAt time.Time
	if err := pool.QueryRow(ctx, `SELECT expires_at FROM scim_tokens WHERE id=$1`, tokenID).Scan(&expiresAt); err != nil {
		t.Fatal(err)
	}
	if expiresAt.Before(migratedAt.Add(89*24*time.Hour)) || expiresAt.After(migratedAt.Add(91*24*time.Hour)) {
		t.Fatalf("legacy SCIM token expiry=%s, want approximately 90 days after migration", expiresAt)
	}
	db := &Store{Pool: pool}
	if authenticatedOrg, role, err := db.AuthenticateSCIM(ctx, tokenHash); err != nil || authenticatedOrg != organizationID || role != "developer" {
		t.Fatalf("migrated SCIM token authentication org=%s role=%q err=%v", authenticatedOrg, role, err)
	}
}
