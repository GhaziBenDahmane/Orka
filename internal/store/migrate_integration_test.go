package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
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

func TestMigrateRejectsUnknownFutureMigration(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO schema_migrations(version,checksum) VALUES('999_future.sql',$1)`, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE schema_migrations SET checksum='' WHERE version='001_initial.sql'`); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); err == nil || !strings.Contains(err.Error(), "unknown migration 999_future.sql") {
		t.Fatalf("future-schema error=%v", err)
	}
	var checksum string
	if err := pool.QueryRow(ctx, `SELECT checksum FROM schema_migrations WHERE version='001_initial.sql'`).Scan(&checksum); err != nil {
		t.Fatal(err)
	}
	if checksum != "" {
		t.Fatal("migration state changed before the unknown future migration was rejected")
	}
}

func TestReadOnlyVerifiedStoreRejectsDatabaseWrites(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	box, err := cryptox.New([]byte(strings.Repeat("r", 32)))
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyOrInitializeMasterKey(ctx, pool, box); err != nil {
		t.Fatal(err)
	}
	readOnlyPool, err := openReadOnlyConfiguredPool(ctx, pool.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(readOnlyPool.Close)
	if err = verifyMasterKeyRequired(ctx, readOnlyPool, box); err != nil {
		t.Fatal(err)
	}
	if err = ValidateMigrationState(ctx, readOnlyPool); err != nil {
		t.Fatal(err)
	}
	if _, err = readOnlyPool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'forbidden','forbidden')`, uuid.New()); err == nil {
		t.Fatal("read-only migration pool accepted a write")
	} else if pgErr, ok := err.(*pgconn.PgError); !ok || pgErr.Code != "25006" {
		t.Fatalf("write error=%T %v", err, err)
	}
}

func TestMigrateFrom080AddsFailClosedDatabaseStoragePlacement(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := migrateThrough(ctx, pool, "080_database_driver_identity.sql"); err != nil {
		t.Fatal(err)
	}
	organizationID, projectID, environmentID, databaseID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Storage migration',$2)`, []any{organizationID, "storage-migration-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Environment','environment')`, []any{environmentID, projectID}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,encrypted_credentials) VALUES($1,$2,'Database','database','postgres','17','encrypted')`, []any{databaseID, environmentID}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var storageNode string
	if err := pool.QueryRow(ctx, `SELECT storage_node_id FROM database_instances WHERE id=$1`, databaseID).Scan(&storageNode); err != nil || storageNode != "" {
		t.Fatalf("legacy storage node=%q err=%v", storageNode, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE database_instances SET storage_node_id='../unsafe' WHERE id=$1`, databaseID); err == nil {
		t.Fatal("unsafe storage node ID was accepted")
	}
}

func TestMigrateRepairsKnownPrecommitDatabaseStorageMigration(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := migrateThrough(ctx, pool, "080_database_driver_identity.sql"); err != nil {
		t.Fatal(err)
	}
	legacySQL := `ALTER TABLE database_instances
    ADD COLUMN storage_node_id text NOT NULL DEFAULT ''
        CHECK (storage_node_id = '' OR storage_node_id ~ '^[a-z0-9]{1,64}$');
`
	legacyChecksum := fmt.Sprintf("%x", sha256.Sum256([]byte(legacySQL)))
	if legacyChecksum != "9509f0a111e3f606030742a4f00231928635d097601394c4dcf4d57e4842d39f" {
		t.Fatalf("legacy fixture checksum=%s", legacyChecksum)
	}
	if _, err := pool.Exec(ctx, legacySQL); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO schema_migrations(version,checksum) VALUES('081_database_storage_node.sql',$1)`, legacyChecksum); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("repair known migration: %v", err)
	}
	currentSQL, err := migrations.ReadFile("migrations/081_database_storage_node.sql")
	if err != nil {
		t.Fatal(err)
	}
	wantChecksum := fmt.Sprintf("%x", sha256.Sum256(currentSQL))
	var recordedChecksum, constraint string
	if err = pool.QueryRow(ctx, `SELECT checksum FROM schema_migrations WHERE version='081_database_storage_node.sql'`).Scan(&recordedChecksum); err != nil || recordedChecksum != wantChecksum {
		t.Fatalf("repaired checksum=%q want=%q err=%v", recordedChecksum, wantChecksum, err)
	}
	if err = pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='cluster_commands'::regclass AND conname='cluster_commands_kind_check'`).Scan(&constraint); err != nil || !strings.Contains(constraint, "swarm.storage-node") {
		t.Fatalf("repaired command constraint=%q err=%v", constraint, err)
	}
}

func TestMigrateUpgradeFrom073AddsTwoPhaseAgentCertificateRotation(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := migrateThrough(ctx, pool, "073_cluster_command_history_index.sql"); err != nil {
		t.Fatal(err)
	}
	organizationID, clusterID := uuid.New(), uuid.New()
	_, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Certificate migration',$2)`, organizationID, "certificate-migration-"+organizationID.String())
	if err == nil {
		_, err = pool.Exec(ctx, `INSERT INTO clusters(id,organization_id,name,slug,state,certificate_serial,certificate_not_after) VALUES($1,$2,'Remote','remote','active','current',now()+interval '1 day')`, clusterID, organizationID)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var pending string
	var pendingExpiry, pendingCreated *time.Time
	if err := pool.QueryRow(ctx, `SELECT pending_certificate_serial,pending_certificate_not_after,pending_certificate_created_at FROM clusters WHERE id=$1`, clusterID).Scan(&pending, &pendingExpiry, &pendingCreated); err != nil {
		t.Fatal(err)
	}
	if pending != "" || pendingExpiry != nil || pendingCreated != nil {
		t.Fatalf("unexpected pending rotation after migration: serial=%q expiry=%v created=%v", pending, pendingExpiry, pendingCreated)
	}
	if err := (&Store{Pool: pool}).AuthenticateClusterCertificate(ctx, clusterID, "current"); err != nil {
		t.Fatalf("existing agent certificate was not preserved: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE clusters SET pending_certificate_serial='broken' WHERE id=$1`, clusterID); err == nil {
		t.Fatal("incomplete pending certificate state was accepted")
	}
}

func TestMigrateUpgradeFrom079BindsKnownDatabaseDrivers(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := migrateThrough(ctx, pool, "079_ai_finding_recurrence.sql"); err != nil {
		t.Fatal(err)
	}
	organizationID, projectID, environmentID := uuid.New(), uuid.New(), uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Driver migration',$2)`, []any{organizationID, "driver-migration-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Environment','environment')`, []any{environmentID, projectID}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,encrypted_credentials) VALUES($1,$2,'Built in','built-in','postgres','17','encrypted')`, []any{uuid.New(), environmentID}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,encrypted_credentials) VALUES($1,$2,'External','external','cockroach','v25.2','encrypted')`, []any{uuid.New(), environmentID}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var builtInSource, builtInDigest, externalSource, externalDigest string
	if err := pool.QueryRow(ctx, `SELECT driver_source,driver_artifact_digest FROM database_instances WHERE environment_id=$1 AND engine='postgres'`, environmentID).Scan(&builtInSource, &builtInDigest); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT driver_source,driver_artifact_digest FROM database_instances WHERE environment_id=$1 AND engine='cockroach'`, environmentID).Scan(&externalSource, &externalDigest); err != nil {
		t.Fatal(err)
	}
	if builtInSource != "built-in" || builtInDigest != "" || externalSource != "unbound" || externalDigest != "" {
		t.Fatalf("migrated identities built-in=%s/%q external=%s/%q", builtInSource, builtInDigest, externalSource, externalDigest)
	}
	if _, err := pool.Exec(ctx, `UPDATE database_instances SET driver_source='external' WHERE environment_id=$1 AND engine='cockroach'`, environmentID); err == nil {
		t.Fatal("external source without a digest passed the consistency constraint")
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
	for _, version := range []string{"035_commit_statuses.sql", "041_dokploy_migration_metadata.sql", "046_oidc_nonce.sql", "047_application_build_settings.sql", "048_application_build_types.sql", "049_nixpacks_builds.sql", "050_railpack_builds.sql", "051_buildpack_builds.sql", "052_application_artifacts.sql", "053_custom_buildpack_builders.sql", "054_database_migrations.sql", "055_cluster_database_transfers.sql", "056_database_operation_serialization.sql", "057_preserve_cancelled_database_jobs.sql", "067_service_reconciliation.sql", "074_pending_agent_certificate_rotation.sql", "075_ai_audit_observability.sql", "076_ai_audit_single_flight.sql", "077_saml_certificate_rotation.sql", "081_database_storage_node.sql", "082_volume_artifact_command.sql", "086_template_repository_sync_started.sql", "093_scim_user_external_ids.sql", "094_scim_resource_versions.sql", "098_deployment_registry_credentials.sql"} {
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

func TestMigrateAIFindingRecurrencePreservesExistingTriage(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := migrateThrough(ctx, pool, "078_agent_ca_fingerprints.sql"); err != nil {
		t.Fatal(err)
	}
	organizationID, userID, accountID, runID, findingID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'AI recurrence upgrade',$2)`, []any{organizationID, "ai-recurrence-upgrade-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!upgrade')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO service_accounts(id,organization_id,name,role) VALUES($1,$2,'auditor','auditor')`, []any{accountID, organizationID}},
		{`INSERT INTO ai_audit_runs(id,organization_id,service_account_id,agent_name,status) VALUES($1,$2,$3,'security','completed')`, []any{runID, organizationID, accountID}},
		{`INSERT INTO ai_audit_findings(id,run_id,severity,category,title,description,evidence,fingerprint,disposition,triage_note,triaged_by_user_id,triaged_at) VALUES($1,$2,'high','backup','No backup','Missing backup','{}','backup:none','acknowledged','accepted risk',$3,now())`, []any{findingID, runID, userID}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var disposition, note string
	var previousFindingID *uuid.UUID
	var occurrenceNumber int
	if err := pool.QueryRow(ctx, `SELECT disposition,triage_note,previous_finding_id,occurrence_number FROM ai_audit_findings WHERE id=$1`, findingID).Scan(&disposition, &note, &previousFindingID, &occurrenceNumber); err != nil {
		t.Fatal(err)
	}
	if disposition != "acknowledged" || note != "accepted risk" || previousFindingID != nil || occurrenceNumber != 1 {
		t.Fatalf("upgraded finding disposition=%q note=%q previous=%v occurrence=%d", disposition, note, previousFindingID, occurrenceNumber)
	}
}

func TestMigrateAIAuditSingleFlightReconcilesExistingRuns(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := migrateThrough(ctx, pool, "075_ai_audit_observability.sql"); err != nil {
		t.Fatal(err)
	}
	organizationID, accountID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'AI migration',$2)`, organizationID, "ai-migration-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO service_accounts(id,organization_id,name,role) VALUES($1,$2,'auditor','auditor')`, accountID, organizationID); err != nil {
		t.Fatal(err)
	}
	olderID, newerID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO ai_audit_runs(id,organization_id,service_account_id,agent_name,status,started_at) VALUES($1,$2,$3,'security','running',now()-interval '1 hour'),($4,$2,$3,'security','running',now())`, olderID, organizationID, accountID, newerID); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var olderStatus, newerStatus string
	if err := pool.QueryRow(ctx, `SELECT status FROM ai_audit_runs WHERE id=$1`, olderID).Scan(&olderStatus); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT status FROM ai_audit_runs WHERE id=$1`, newerID).Scan(&newerStatus); err != nil {
		t.Fatal(err)
	}
	if olderStatus != "failed" || newerStatus != "running" {
		t.Fatalf("migration statuses older=%q newer=%q", olderStatus, newerStatus)
	}
	var indexExists bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('ai_audit_runs_active_agent_idx') IS NOT NULL`).Scan(&indexExists); err != nil || !indexExists {
		t.Fatalf("single-flight index exists=%v err=%v", indexExists, err)
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

func TestMigrateDeploymentRegistryCredentialSnapshots(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := migrateThrough(ctx, pool, "097_volume_policy_retirement_indexes.sql"); err != nil {
		t.Fatal(err)
	}
	organizationID, projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	credentialID, deploymentID := uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'registry snapshot',$2)`, []any{organizationID, "registry-snapshot-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'app','app',$3,'services: {}')`, []any{serviceID, environmentID, "registry-snapshot-" + serviceID.String()}},
		{`INSERT INTO source_credentials(id,organization_id,kind,name,server,username,encrypted_secret) VALUES($1,$2,'registry','registry','registry.example.test','robot','ciphertext')`, []any{credentialID, organizationID}},
		{`INSERT INTO application_sources(compose_service_id,repository_url,target_service,registry_image,registry_credential_id) VALUES($1,'https://github.com/acme/app','web','registry.example.test/acme/app',$2)`, []any{serviceID, credentialID}},
		{`INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,status,trigger) VALUES($1,$2,1,'services: {}','succeeded','manual')`, []any{deploymentID, serviceID}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var gotID *uuid.UUID
	var server, username, encrypted string
	if err := pool.QueryRow(ctx, `SELECT registry_credential_id,registry_credential_server,registry_credential_username,encrypted_registry_credential FROM deployments WHERE id=$1`, deploymentID).Scan(&gotID, &server, &username, &encrypted); err != nil {
		t.Fatal(err)
	}
	if gotID == nil || *gotID != credentialID || server != "registry.example.test" || username != "robot" || encrypted != "ciphertext" {
		t.Fatalf("credential snapshot id=%v server=%q username=%q encrypted=%q", gotID, server, username, encrypted)
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

func TestMigrateUpgradeFrom070AddsOrganizationInvitations(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := migrateThrough(ctx, pool, "070_scim_token_expiry.sql"); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('organization_invitations') IS NOT NULL`).Scan(&exists); err != nil || !exists {
		t.Fatalf("organization invitations table missing: exists=%v err=%v", exists, err)
	}
}

func TestMigrateUpgradeFrom071AddsDurableAgentUpgradeVerification(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := migrateThrough(ctx, pool, "071_organization_invitations.sql"); err != nil {
		t.Fatal(err)
	}
	organizationID, clusterID, legacyCommandID := uuid.New(), uuid.New(), uuid.New()
	var err error
	if _, err = pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Agent migration',$2)`, organizationID, "agent-migration-"+organizationID.String()); err == nil {
		_, err = pool.Exec(ctx, `INSERT INTO clusters(id,organization_id,name,slug,state,last_seen_at) VALUES($1,$2,'Remote','remote','active',now())`, clusterID, organizationID)
	}
	if err == nil {
		_, err = pool.Exec(ctx, `INSERT INTO cluster_commands(id,cluster_id,kind,encrypted_payload,status,lease_id,lease_expires_at) VALUES($1,$2,'agent.upgrade','legacy','leased',$3,now()+interval '1 minute')`, legacyCommandID, clusterID, uuid.New())
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var status, reason, agentImage, updateState string
	if err := pool.QueryRow(ctx, `SELECT command.status,command.last_error,cluster.agent_image,cluster.agent_update_state FROM cluster_commands command JOIN clusters cluster ON cluster.id=command.cluster_id WHERE command.id=$1`, legacyCommandID).Scan(&status, &reason, &agentImage, &updateState); err != nil {
		t.Fatal(err)
	}
	if status != "cancelled" || !strings.Contains(reason, "predates durable convergence") || agentImage != "" || updateState != "" {
		t.Fatalf("legacy command status=%q reason=%q image=%q update=%q", status, reason, agentImage, updateState)
	}
	var historyIndexExists bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('cluster_commands_history_idx') IS NOT NULL`).Scan(&historyIndexExists); err != nil || !historyIndexExists {
		t.Fatalf("cluster command history index missing: exists=%v err=%v", historyIndexExists, err)
	}
	db := &Store{Pool: pool}
	target := "registry.example/dockyard@sha256:" + strings.Repeat("a", 64)
	if _, err := db.EnqueueAgentUpgrade(ctx, clusterID, uuid.New(), "encrypted", target); err != nil {
		t.Fatalf("enqueue tracked upgrade after migration: %v", err)
	}
	if _, err := db.EnqueueAgentUpgrade(ctx, clusterID, uuid.New(), "encrypted", target); !errors.Is(err, ErrBusy) {
		t.Fatalf("duplicate tracked upgrade error=%v, want ErrBusy", err)
	}
}

func TestMigrateUpgradeFrom085AddsTemplateRepositorySyncStart(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := migrateThrough(ctx, pool, "085_audit_event_archive_index.sql"); err != nil {
		t.Fatal(err)
	}
	organizationID, repositoryID := uuid.New(), uuid.New()
	startedAt := time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Catalog migration',$2)`, organizationID, "catalog-migration-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO template_repositories(id,organization_id,name,slug,repository_url,git_ref,last_sync_status,updated_at) VALUES($1,$2,'Catalog','catalog','https://github.com/acme/catalog','main','running',$3)`, repositoryID, organizationID, startedAt); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var migratedStartedAt time.Time
	var migratedAttemptID *uuid.UUID
	var indexExists bool
	if err := pool.QueryRow(ctx, `SELECT sync_started_at,sync_attempt_id FROM template_repositories WHERE id=$1`, repositoryID).Scan(&migratedStartedAt, &migratedAttemptID); err != nil || !migratedStartedAt.Equal(startedAt) || migratedAttemptID != nil {
		t.Fatalf("sync start=%v want=%v err=%v", migratedStartedAt, startedAt, err)
	}
	if err := pool.QueryRow(ctx, `SELECT to_regclass('template_repositories_sync_started_idx') IS NOT NULL`).Scan(&indexExists); err != nil || !indexExists {
		t.Fatalf("sync start index exists=%v err=%v", indexExists, err)
	}
}

func TestMigrateUpgradeFrom086AddsRetryableClusterEnrollment(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := migrateThrough(ctx, pool, "086_template_repository_sync_started.sql"); err != nil {
		t.Fatal(err)
	}
	organizationID, clusterID, tokenID := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Enrollment migration',$2)`, organizationID, "enrollment-migration-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,organization_id,name,slug,state) VALUES($1,$2,'Remote','remote','active')`, clusterID, organizationID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO cluster_enrollment_tokens(id,cluster_id,token_hash,expires_at,used_at) VALUES($1,$2,$3,now()+interval '5 minutes',now())`, tokenID, clusterID, []byte("legacy-used-token")); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var csrHash []byte
	var certificate, caBundle, signingCA, fingerprint string
	if err := pool.QueryRow(ctx, `SELECT enrollment_csr_sha256,issued_certificate,issued_ca_bundle,issued_signing_ca_certificate,issued_signing_ca_fingerprint FROM cluster_enrollment_tokens WHERE id=$1`, tokenID).Scan(&csrHash, &certificate, &caBundle, &signingCA, &fingerprint); err != nil {
		t.Fatal(err)
	}
	if csrHash != nil || certificate != "" || caBundle != "" || signingCA != "" || fingerprint != "" {
		t.Fatalf("legacy used token unexpectedly became replayable: csr=%x certificate=%q CA=%q signer=%q fingerprint=%q", csrHash, certificate, caBundle, signingCA, fingerprint)
	}
}

func TestMigrateUpgradeFrom087AddsDurableArtifactCleanup(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := migrateThrough(ctx, pool, "087_retryable_cluster_enrollment.sql"); err != nil {
		t.Fatal(err)
	}
	organizationID, projectID, environmentID := uuid.New(), uuid.New(), uuid.New()
	serviceID, destinationID, backupID, restoreID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Cleanup migration',$2)`, []any{organizationID, "cleanup-migration-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml,storage_node_id) VALUES($1,$2,'App','app',$3,'services: {}','node1')`, []any{serviceID, environmentID, "cleanup-" + serviceID.String()}},
		{`INSERT INTO backup_destinations(id,organization_id,name,endpoint,bucket,encrypted_credentials) VALUES($1,$2,'archive','https://objects.example.test','backups','ciphertext')`, []any{destinationID, organizationID}},
		{`INSERT INTO volume_backups(id,compose_service_id,volume_name,storage_node_id,destination_id,quiesce,status,object_key) VALUES($1,$2,'data','node1',$3,true,'succeeded','volume/object.enc')`, []any{backupID, serviceID, destinationID}},
		{`INSERT INTO volume_restores(id,volume_backup_id,status) VALUES($1,$2,'succeeded')`, []any{restoreID, backupID}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	cleanupID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO backup_artifact_deletions(id,destination_id,object_key,source_kind,source_id) VALUES($1,$2,'volume/object.enc','volume',$3)`, cleanupID, destinationID, backupID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM compose_services WHERE id=$1`, serviceID); err != nil {
		t.Fatalf("volume restore history did not cascade with service deletion: %v", err)
	}
	var backups, restores int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM volume_backups WHERE id=$1),(SELECT count(*) FROM volume_restores WHERE id=$2)`, backupID, restoreID).Scan(&backups, &restores); err != nil || backups != 0 || restores != 0 {
		t.Fatalf("remaining backups=%d restores=%d err=%v", backups, restores, err)
	}
	_, err := pool.Exec(ctx, `DELETE FROM backup_destinations WHERE id=$1`, destinationID)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
		t.Fatalf("pending cleanup did not protect destination: %v", err)
	}
	if _, err = pool.Exec(ctx, `DELETE FROM backup_artifact_deletions WHERE id=$1`, cleanupID); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `DELETE FROM backup_destinations WHERE id=$1`, destinationID); err != nil {
		t.Fatalf("destination remained blocked after cleanup: %v", err)
	}
}

func TestMigrateUpgradeFrom089ExpiresLegacyDeployTokens(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := migrateThrough(ctx, pool, "089_ai_finalizer_posture.sql"); err != nil {
		t.Fatal(err)
	}
	organizationID, projectID, environmentID, serviceID, tokenID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Deploy token migration',$2)`, []any{organizationID, "deploy-token-migration-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'API','api',$3,'services: {}')`, []any{serviceID, environmentID, "deploy-token-migration-" + serviceID.String()}},
		{`INSERT INTO deploy_tokens(id,compose_service_id,token_hash,name) VALUES($1,$2,$3,'legacy')`, []any{tokenID, serviceID, []byte("legacy-deploy-token")}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	migratedAt := time.Now().UTC()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var expiresAt time.Time
	var lastUsedAt *time.Time
	var indexExists bool
	if err := pool.QueryRow(ctx, `SELECT expires_at,last_used_at FROM deploy_tokens WHERE id=$1`, tokenID).Scan(&expiresAt, &lastUsedAt); err != nil {
		t.Fatal(err)
	}
	if expiresAt.Before(migratedAt.Add(89*24*time.Hour)) || expiresAt.After(migratedAt.Add(91*24*time.Hour)) || lastUsedAt != nil {
		t.Fatalf("legacy deploy token expiry=%s lastUsedAt=%v", expiresAt, lastUsedAt)
	}
	if err := pool.QueryRow(ctx, `SELECT to_regclass('deploy_tokens_active_expiry_idx') IS NOT NULL`).Scan(&indexExists); err != nil || !indexExists {
		t.Fatalf("deploy token expiry index exists=%v err=%v", indexExists, err)
	}
}

func TestMigrateUpgradeFrom092AddsSCIMUserExternalIDs(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := migrateThrough(ctx, pool, "092_template_catalog_pagination.sql"); err != nil {
		t.Fatal(err)
	}
	organizationID, firstUserID, secondUserID := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'SCIM external ID migration',$2)`, organizationID, "scim-external-id-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test'),($3,$4,'!test')`, firstUserID, firstUserID.String()+"@example.test", secondUserID, secondUserID.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO scim_user_defaults(organization_id,user_id,default_role) VALUES($1,$2,'viewer')`, organizationID, firstUserID); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var externalID *string
	if err := pool.QueryRow(ctx, `SELECT external_id FROM scim_user_defaults WHERE organization_id=$1 AND user_id=$2`, organizationID, firstUserID).Scan(&externalID); err != nil || externalID != nil {
		t.Fatalf("legacy SCIM external ID=%v err=%v", externalID, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE scim_user_defaults SET external_id='directory-user' WHERE organization_id=$1 AND user_id=$2`, organizationID, firstUserID); err != nil {
		t.Fatal(err)
	}
	_, err := pool.Exec(ctx, `INSERT INTO scim_user_defaults(organization_id,user_id,default_role,external_id) VALUES($1,$2,'viewer','directory-user')`, organizationID, secondUserID)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		t.Fatalf("duplicate organization external ID was accepted: %v", err)
	}
	otherOrganizationID, thirdUserID := uuid.New(), uuid.New()
	if _, err = pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Other SCIM directory',$2)`, otherOrganizationID, "other-scim-external-id-"+otherOrganizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, thirdUserID, thirdUserID.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO scim_user_defaults(organization_id,user_id,default_role,external_id) VALUES($1,$2,'viewer','directory-user')`, otherOrganizationID, thirdUserID); err != nil {
		t.Fatalf("external ID was not tenant scoped: %v", err)
	}
}

func TestMigrateUpgradeFrom093AddsSCIMResourceVersions(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := migrateThrough(ctx, pool, "093_scim_user_external_ids.sql"); err != nil {
		t.Fatal(err)
	}
	organizationID, userID, groupID := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'SCIM version migration',$2)`, organizationID, "scim-version-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, userID, userID.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO scim_user_defaults(organization_id,user_id,default_role) VALUES($1,$2,'viewer')`, organizationID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO scim_groups(id,organization_id,display_name,role) VALUES($1,$2,'Versioned','viewer')`, groupID, organizationID); err != nil {
		t.Fatal(err)
	}
	migratedAt := time.Now().UTC()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var createdAt, updatedAt time.Time
	var userRevision, groupRevision int64
	if err := pool.QueryRow(ctx, `SELECT created_at,updated_at,revision FROM scim_user_defaults WHERE organization_id=$1 AND user_id=$2`, organizationID, userID).Scan(&createdAt, &updatedAt, &userRevision); err != nil {
		t.Fatal(err)
	}
	if createdAt.Before(migratedAt.Add(-time.Second)) || updatedAt.Before(migratedAt.Add(-time.Second)) || userRevision != 1 {
		t.Fatalf("migrated user metadata created=%s updated=%s revision=%d", createdAt, updatedAt, userRevision)
	}
	if err := pool.QueryRow(ctx, `SELECT revision FROM scim_groups WHERE id=$1`, groupID).Scan(&groupRevision); err != nil || groupRevision != 1 {
		t.Fatalf("migrated group revision=%d err=%v", groupRevision, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE scim_groups SET revision=0 WHERE id=$1`, groupID); err == nil {
		t.Fatal("non-positive SCIM group revision was accepted")
	}
}
