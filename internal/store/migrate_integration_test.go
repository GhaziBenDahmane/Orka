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
	for _, version := range []string{"035_commit_statuses.sql", "041_dokploy_migration_metadata.sql", "046_oidc_nonce.sql", "047_application_build_settings.sql", "048_application_build_types.sql", "049_nixpacks_builds.sql", "050_railpack_builds.sql", "051_buildpack_builds.sql", "052_application_artifacts.sql", "053_custom_buildpack_builders.sql", "054_database_migrations.sql", "055_cluster_database_transfers.sql", "056_database_operation_serialization.sql", "057_preserve_cancelled_database_jobs.sql"} {
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
