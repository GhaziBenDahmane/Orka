package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRotateMasterKeyCoversEveryEncryptedColumn(t *testing.T) {
	pool, ctx := masterKeyRotationTestPool(t)
	oldKey, newKey := bytesOf(1), bytesOf(2)
	oldBox, _ := cryptox.New(oldKey)
	rows := seedMasterKeyRotationRows(t, ctx, pool, oldBox)
	if err := VerifyOrInitializeMasterKey(ctx, pool, oldBox); err != nil {
		t.Fatalf("initialize verifier: %v", err)
	}

	dryReport, err := RotateMasterKey(ctx, pool, oldKey, newKey, true)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if !dryReport.DryRun || dryReport.Validated != len(masterKeyEncryptedColumns) || dryReport.Rotated != 0 {
		t.Fatalf("unexpected dry-run report: %#v", dryReport)
	}
	for _, row := range rows {
		if got := readEncryptedValue(t, ctx, pool, row.spec, row.id); got != row.ciphertext {
			t.Fatalf("dry run changed %s.%s", row.spec.table, row.spec.column)
		}
	}

	report, err := RotateMasterKey(ctx, pool, oldKey, newKey, false)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if report.DryRun || report.Validated != len(masterKeyEncryptedColumns) || report.Rotated != len(masterKeyEncryptedColumns) {
		t.Fatalf("unexpected rotation report: %#v", report)
	}
	newBox, _ := cryptox.New(newKey)
	if err = VerifyOrInitializeMasterKey(ctx, pool, oldBox); err == nil || !strings.Contains(err.Error(), "master key does not match") {
		t.Fatalf("old key remained valid after rotation: %v", err)
	}
	if err = VerifyOrInitializeMasterKey(ctx, pool, newBox); err != nil {
		t.Fatalf("new key verifier: %v", err)
	}
	for _, row := range rows {
		ciphertext := readEncryptedValue(t, ctx, pool, row.spec, row.id)
		if ciphertext == row.ciphertext {
			t.Fatalf("ciphertext was not replaced for %s.%s", row.spec.table, row.spec.column)
		}
		plain, decryptErr := newBox.Decrypt(ciphertext, cryptox.ResourceContext(row.spec.contextKind, row.contextID))
		if decryptErr != nil || string(plain) != row.plaintext {
			t.Fatalf("new ciphertext %s.%s plaintext=%q err=%v", row.spec.table, row.spec.column, plain, decryptErr)
		}
		clear(plain)
		if _, decryptErr = oldBox.Decrypt(ciphertext, cryptox.ResourceContext(row.spec.contextKind, row.contextID)); decryptErr == nil {
			t.Fatalf("old key still decrypts %s.%s", row.spec.table, row.spec.column)
		}
	}
}

func TestVerifyOrInitializeMasterKeyRejectsWrongLegacyKey(t *testing.T) {
	pool, ctx := masterKeyRotationTestPool(t)
	correctBox, _ := cryptox.New(bytesOf(11))
	seedMasterKeyRotationRows(t, ctx, pool, correctBox)
	wrongBox, _ := cryptox.New(bytesOf(12))
	if err := VerifyOrInitializeMasterKey(ctx, pool, wrongBox); err == nil || !strings.Contains(err.Error(), "initialize master-key verifier") {
		t.Fatalf("wrong legacy key error=%v", err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM master_key_verifier`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("wrong key initialized %d verifier rows", count)
	}
	if err := VerifyOrInitializeMasterKey(ctx, pool, correctBox); err != nil {
		t.Fatalf("initialize correct key: %v", err)
	}
	var ciphertext string
	if err := pool.QueryRow(ctx, `SELECT ciphertext FROM master_key_verifier WHERE singleton=true`).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if ciphertext == "" || strings.Contains(ciphertext, masterKeyVerifierPlaintext) {
		t.Fatalf("verifier was not stored as ciphertext: %q", ciphertext)
	}
	if err := VerifyOrInitializeMasterKey(ctx, pool, wrongBox); err == nil || !strings.Contains(err.Error(), "master key does not match") {
		t.Fatalf("wrong initialized key error=%v", err)
	}
}

func TestVerifyOrInitializeMasterKeyIsSafeAcrossHAStartup(t *testing.T) {
	pool, ctx := masterKeyRotationTestPool(t)
	box, _ := cryptox.New(bytesOf(13))
	const replicas = 8
	start := make(chan struct{})
	errors := make(chan error, replicas)
	var workers sync.WaitGroup
	for range replicas {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			errors <- VerifyOrInitializeMasterKey(ctx, pool, box)
		}()
	}
	close(start)
	workers.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("concurrent verifier initialization: %v", err)
		}
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM master_key_verifier`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("verifier rows=%d want=1", count)
	}
}

func TestVerifiedStoreRejectsWrongKeyBeforeMigrationChecks(t *testing.T) {
	pool, ctx := masterKeyRotationTestPool(t)
	correctBox, _ := cryptox.New(bytesOf(14))
	if err := VerifyOrInitializeMasterKey(ctx, pool, correctBox); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE schema_migrations SET checksum='tampered' WHERE version='095_master_key_verifier.sql'`); err != nil {
		t.Fatal(err)
	}
	wrongBox, _ := cryptox.New(bytesOf(15))
	err := prepareVerifiedStore(ctx, pool, wrongBox)
	if err == nil || !strings.Contains(err.Error(), "verify master key before migrations: master key does not match") {
		t.Fatalf("pre-migration verification error=%v", err)
	}
}

func TestRotateMasterKeyRollsBackWhenAnyCiphertextIsCorrupt(t *testing.T) {
	pool, ctx := masterKeyRotationTestPool(t)
	oldKey, newKey := bytesOf(3), bytesOf(4)
	oldBox, _ := cryptox.New(oldKey)
	rows := seedMasterKeyRotationRows(t, ctx, pool, oldBox)
	corrupt := rows[len(rows)-1]
	query := fmt.Sprintf("UPDATE %s SET %s='not-valid-ciphertext' WHERE %s=$1", identifier(corrupt.spec.table), identifier(corrupt.spec.column), identifier(corrupt.spec.idColumn))
	if _, err := pool.Exec(ctx, query, corrupt.id); err != nil {
		t.Fatal(err)
	}
	first := rows[0]
	before := readEncryptedValue(t, ctx, pool, first.spec, first.id)
	if _, err := RotateMasterKey(ctx, pool, oldKey, newKey, false); err == nil || !strings.Contains(err.Error(), corrupt.spec.table+"."+corrupt.spec.column) {
		t.Fatalf("corrupt rotation error=%v", err)
	}
	if after := readEncryptedValue(t, ctx, pool, first.spec, first.id); after != before {
		t.Fatal("a row changed despite failed preflight authentication")
	}
}

func TestRotateMasterKeyRefusesActiveController(t *testing.T) {
	pool, ctx := masterKeyRotationTestPool(t)
	if _, err := pool.Exec(ctx, `INSERT INTO controller_leases(name,holder,expires_at) VALUES('worker','controller-a',now()+interval '1 minute')`); err != nil {
		t.Fatal(err)
	}
	_, err := RotateMasterKey(ctx, pool, bytesOf(5), bytesOf(6), true)
	if err == nil || !strings.Contains(err.Error(), "active controller leases=1") {
		t.Fatalf("active controller error=%v", err)
	}
}

func TestRotateMasterKeyRefusesUnknownEncryptedColumn(t *testing.T) {
	pool, ctx := masterKeyRotationTestPool(t)
	if _, err := pool.Exec(ctx, `ALTER TABLE organizations ADD COLUMN encrypted_future_secret text NOT NULL DEFAULT ''`); err != nil {
		t.Fatal(err)
	}
	_, err := RotateMasterKey(ctx, pool, bytesOf(7), bytesOf(8), true)
	if err == nil || !strings.Contains(err.Error(), "organizations.encrypted_future_secret") {
		t.Fatalf("unknown encrypted column error=%v", err)
	}
}

func TestRotateMasterKeyRefusesRunningWorker(t *testing.T) {
	pool, ctx := masterKeyRotationTestPool(t)
	if _, err := pool.Exec(ctx, `INSERT INTO jobs(id,kind,payload,status) VALUES($1,'test','{}','running')`, uuid.New()); err != nil {
		t.Fatal(err)
	}
	_, err := RotateMasterKey(ctx, pool, bytesOf(9), bytesOf(10), true)
	if err == nil || !strings.Contains(err.Error(), "running jobs=1") {
		t.Fatalf("running worker error=%v", err)
	}
}

type masterKeyTestRow struct {
	spec       encryptedColumnSpec
	id         uuid.UUID
	contextID  string
	plaintext  string
	ciphertext string
}

func masterKeyRotationTestPool(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	return pool, ctx
}

func seedMasterKeyRotationRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool, box *cryptox.Box) []masterKeyTestRow {
	t.Helper()
	organizationID, projectID, environmentID := uuid.New(), uuid.New(), uuid.New()
	serviceID, databaseID, backupID, volumeBackupID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	credentialID, destinationID, providerID := uuid.New(), uuid.New(), uuid.New()
	webhookID, notificationID, clusterID := uuid.New(), uuid.New(), uuid.New()
	commandID, deploymentID, deliveryID := uuid.New(), uuid.New(), uuid.New()
	migrationID, repositoryID := uuid.New(), uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'rotation',$2)`, []any{organizationID, "rotation-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'service','service',$3,'services: {}')`, []any{serviceID, environmentID, "rotation-" + serviceID.String()}},
		{`INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,status,trigger,registry_credential_id,registry_credential_server,registry_credential_username,encrypted_registry_credential) VALUES($1,$2,1,'services: {}','queued','test',$3,'registry.example.test','robot','pending')`, []any{deploymentID, serviceID, credentialID}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,compose_service_id,encrypted_credentials) VALUES($1,$2,'database','database','postgres','17',$3,'')`, []any{databaseID, environmentID, serviceID}},
		{`INSERT INTO database_backups(id,database_instance_id,status,format) VALUES($1,$2,'queued','native')`, []any{backupID, databaseID}},
		{`INSERT INTO oidc_providers(id,organization_id,name,issuer,client_id,encrypted_client_secret) VALUES($1,$2,'oidc','https://id.example.test','client','')`, []any{providerID, organizationID}},
		{`INSERT INTO source_credentials(id,organization_id,kind,name,server,username,encrypted_secret) VALUES($1,$2,'git','git','github.com','bot','')`, []any{credentialID, organizationID}},
		{`INSERT INTO backup_destinations(id,organization_id,name,endpoint,bucket,encrypted_credentials) VALUES($1,$2,'backup','https://s3.example.test','bucket','')`, []any{destinationID, organizationID}},
		{`INSERT INTO volume_backups(id,compose_service_id,volume_name,storage_node_id,destination_id,quiesce,status) VALUES($1,$2,'data','node1',$3,true,'succeeded')`, []any{volumeBackupID, serviceID, destinationID}},
		{`INSERT INTO saml_providers(id,organization_id,name,idp_metadata,certificate_pem,encrypted_private_key,pending_certificate_pem,pending_encrypted_private_key,pending_certificate_not_after,pending_certificate_created_at) VALUES($1,$2,'saml','metadata','certificate','','pending-certificate','pending',now()+interval '1 day',now())`, []any{providerID, organizationID}},
		{`INSERT INTO webhook_integrations(id,compose_service_id,name,provider,branch,encrypted_secret) VALUES($1,$2,'deploy','github','main','')`, []any{webhookID, serviceID}},
		{`INSERT INTO notification_endpoints(id,organization_id,name,kind,encrypted_url,encrypted_secret,events) VALUES($1,$2,'alerts','webhook','','',ARRAY['backup.failed'])`, []any{notificationID, organizationID}},
		{`INSERT INTO clusters(id,organization_id,name,slug,state) VALUES($1,$2,'cluster','cluster','active')`, []any{clusterID, organizationID}},
		{`INSERT INTO cluster_commands(id,cluster_id,kind,encrypted_payload) VALUES($1,$2,'swarm.logs','')`, []any{commandID, clusterID}},
		{`INSERT INTO commit_status_deliveries(id,deployment_id,state,provider,repository_url,status_context,credential_server,credential_username,credential_id,encrypted_credential) VALUES($1,$2,'pending','github','https://github.com/acme/repo','dockyard/deploy','github.com','bot',$3,'')`, []any{deliveryID, deploymentID, credentialID}},
		{`INSERT INTO application_sources(compose_service_id,repository_url,target_service,registry_image) VALUES($1,'https://github.com/acme/repo','app','ghcr.io/acme/app')`, []any{serviceID}},
		{`INSERT INTO application_artifacts(compose_service_id,encrypted_archive,filename,sha256,compressed_size) VALUES($1,'','source.zip',$2,1)`, []any{serviceID, strings.Repeat("a", 64)}},
		{`INSERT INTO database_migrations(id,database_instance_id,source_id,source_engine,source_version,source_host,encrypted_source_config) VALUES($1,$2,'legacy','postgres','17','legacy.internal','')`, []any{migrationID, databaseID}},
		{`INSERT INTO template_instances(compose_service_id,template_key,template_version,template_checksum,encrypted_variables) VALUES($1,'postgres','1.0.0',$2,'')`, []any{serviceID, strings.Repeat("b", 64)}},
		{`INSERT INTO template_repositories(id,organization_id,name,slug,repository_url) VALUES($1,$2,'catalog','catalog','https://github.com/acme/templates')`, []any{repositoryID, organizationID}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("seed rotation fixture: %v\n%s", err, statement.query)
		}
	}
	ids := map[string]uuid.UUID{
		"application_artifacts": serviceID, "application_sources": serviceID, "backup_destinations": destinationID,
		"cluster_commands": commandID, "commit_status_deliveries": deliveryID, "compose_services": serviceID,
		"database_backups": backupID, "database_instances": databaseID, "database_migrations": migrationID, "deployments": deploymentID,
		"notification_endpoints": notificationID, "oidc_providers": providerID, "saml_providers": providerID,
		"source_credentials": credentialID, "template_instances": serviceID, "template_repositories": repositoryID,
		"volume_backups": volumeBackupID, "webhook_integrations": webhookID,
	}
	result := make([]masterKeyTestRow, 0, len(masterKeyEncryptedColumns))
	for index, spec := range masterKeyEncryptedColumns {
		id := ids[spec.table]
		contextID := id.String()
		if spec.table == "commit_status_deliveries" || spec.table == "deployments" {
			contextID = credentialID.String()
		}
		plaintext := "secret-" + spec.table + "-" + spec.column
		contextValue := cryptox.ResourceContext(spec.contextKind, contextID)
		if index == 2 && spec.legacyContext != "" {
			contextValue = spec.legacyContext
		}
		ciphertext, err := box.Encrypt([]byte(plaintext), contextValue)
		if err != nil {
			t.Fatal(err)
		}
		query := fmt.Sprintf("UPDATE %s SET %s=$1 WHERE %s=$2", identifier(spec.table), identifier(spec.column), identifier(spec.idColumn))
		if _, err = pool.Exec(ctx, query, ciphertext, id); err != nil {
			t.Fatalf("set %s.%s: %v", spec.table, spec.column, err)
		}
		result = append(result, masterKeyTestRow{spec: spec, id: id, contextID: contextID, plaintext: plaintext, ciphertext: ciphertext})
	}
	return result
}

func readEncryptedValue(t *testing.T, ctx context.Context, pool *pgxpool.Pool, spec encryptedColumnSpec, id uuid.UUID) string {
	t.Helper()
	query := fmt.Sprintf("SELECT COALESCE(%s,'') FROM %s WHERE %s=$1", identifier(spec.column), identifier(spec.table), identifier(spec.idColumn))
	var value string
	if err := pool.QueryRow(ctx, query, id).Scan(&value); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal(err)
	}
	return value
}

func bytesOf(value byte) []byte { return []byte(strings.Repeat(string([]byte{value}), 32)) }
