package store

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestParentDeletionFencesChildOperationsAndCreation(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)

	organizationID, userID, projectID, environmentID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	serviceID, destinationID := uuid.New(), uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Parent deletion fence',$2)`, []any{organizationID, "parent-deletion-fence-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,storage_node_id,compose_yaml) VALUES($1,$2,'App','app',$3,'node1',$4)`, []any{serviceID, environmentID, "parent-deletion-fence-" + serviceID.String(), "services:\n  app:\n    image: example/app:1\n    volumes:\n      - data:/data\nvolumes:\n  data: {}\n"}},
		{`INSERT INTO backup_destinations(id,organization_id,name,endpoint,bucket,use_tls,encrypted_credentials) VALUES($1,$2,'S3','https://s3.example.test','backups',true,'encrypted')`, []any{destinationID, organizationID}},
		{`INSERT INTO volume_backup_policies(id,compose_service_id,volume_name,destination_id,interval_seconds,retention_count,quiesce,enabled,next_run_at) VALUES($1,$2,'data',$3,3600,7,true,true,now()+interval '1 hour')`, []any{uuid.New(), serviceID, destinationID}},
	}
	for _, statement := range statements {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM jobs WHERE resource_key=$1 OR payload->>'projectId'=$2 OR payload->>'environmentId' IN (SELECT id::text FROM environments WHERE project_id=$3) OR payload->>'serviceId' IN (SELECT service.id::text FROM compose_services service JOIN environments environment ON environment.id=service.environment_id WHERE environment.project_id=$3)`, "service:"+serviceID.String(), projectID.String(), projectID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})

	backup, err := db.QueueVolumeBackup(ctx, organizationID, serviceID, "data", userID)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.DeleteEnvironment(ctx, organizationID, environmentID); !errors.Is(err, ErrBusy) {
		t.Fatalf("environment deletion during child backup error=%v, want ErrBusy", err)
	}
	if err = db.DeleteProject(ctx, organizationID, projectID); !errors.Is(err, ErrBusy) {
		t.Fatalf("project deletion during child backup error=%v, want ErrBusy", err)
	}
	if err = db.CancelVolumeBackup(ctx, organizationID, backup.ID); err != nil {
		t.Fatal(err)
	}
	environmentBlocker, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer environmentBlocker.Rollback(context.Background())
	if err = environmentBlocker.QueryRow(ctx, `SELECT id FROM environments WHERE id=$1 FOR UPDATE`, environmentID).Scan(new(uuid.UUID)); err != nil {
		t.Fatal(err)
	}
	environmentDeleteResult := make(chan error, 1)
	go func() { environmentDeleteResult <- db.DeleteEnvironment(ctx, organizationID, environmentID) }()
	waitForBlockedStoreQuery(t, ctx, db, "SELECT e.deletion_requested_at IS NOT NULL FROM environments")
	type serviceResult struct {
		service ComposeService
		err     error
	}
	serviceCreateResult := make(chan serviceResult, 1)
	go func() {
		service, createErr := db.CreateComposeService(ctx, organizationID, ComposeService{EnvironmentID: environmentID, Name: "Concurrent", Slug: "concurrent", StackName: "concurrent-" + uuid.NewString(), ComposeYAML: "services: {}"})
		serviceCreateResult <- serviceResult{service: service, err: createErr}
	}()
	waitForBlockedStoreQuery(t, ctx, db, "SELECT id FROM environments WHERE id=$1 AND deletion_requested_at IS NULL FOR UPDATE")
	if err = environmentBlocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-environmentDeleteResult; err != nil {
		t.Fatalf("environment deletion after child backup cancellation: %v", err)
	}
	concurrentService := <-serviceCreateResult
	if concurrentService.err != nil && !errors.Is(concurrentService.err, ErrNotFound) {
		t.Fatalf("concurrent service creation error=%v", concurrentService.err)
	}
	if concurrentService.err == nil {
		var deleting bool
		if err = db.Pool.QueryRow(ctx, `SELECT deletion_requested_at IS NOT NULL FROM compose_services WHERE id=$1`, concurrentService.service.ID).Scan(&deleting); err != nil || !deleting {
			t.Fatalf("concurrently created service escaped environment deletion: deleting=%v err=%v", deleting, err)
		}
	}
	lateService := ComposeService{EnvironmentID: environmentID, Name: "Late", Slug: "late", StackName: "late-" + uuid.NewString(), ComposeYAML: "services: {}"}
	if _, err = db.CreateComposeService(ctx, organizationID, lateService); !errors.Is(err, ErrNotFound) {
		t.Fatalf("service creation in deleting environment error=%v, want ErrNotFound", err)
	}
	if _, err = db.CreateDatabase(ctx, organizationID, DatabaseInstance{EnvironmentID: environmentID, Name: "Late DB", Slug: "late-db", Engine: "postgres", Version: "17"}, lateService, "encrypted"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("database creation in deleting environment error=%v, want ErrNotFound", err)
	}
	if _, _, err = db.CreateTemplateService(ctx, organizationID, lateService, nil, TemplateInstance{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("template creation in deleting environment error=%v, want ErrNotFound", err)
	}
	activeEnvironments, err := db.ListEnvironments(ctx, organizationID, projectID)
	if err != nil {
		t.Fatal(err)
	}
	if len(activeEnvironments) != 0 {
		t.Fatalf("deleting environment remained in active inventory: %#v", activeEnvironments)
	}

	secondEnvironment, err := db.CreateEnvironment(ctx, organizationID, projectID, "Staging", "staging")
	if err != nil {
		t.Fatalf("create sibling environment before project deletion: %v", err)
	}
	blocker, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	if err = blocker.QueryRow(ctx, `SELECT id FROM projects WHERE id=$1 FOR UPDATE`, projectID).Scan(new(uuid.UUID)); err != nil {
		t.Fatal(err)
	}
	deleteResult := make(chan error, 1)
	go func() { deleteResult <- db.DeleteProject(ctx, organizationID, projectID) }()
	waitForBlockedStoreQuery(t, ctx, db, "SELECT deletion_requested_at IS NOT NULL FROM projects")
	type environmentResult struct {
		environment Environment
		err         error
	}
	createResult := make(chan environmentResult, 1)
	go func() {
		environment, createErr := db.CreateEnvironment(ctx, organizationID, projectID, "Concurrent", "concurrent")
		createResult <- environmentResult{environment: environment, err: createErr}
	}()
	waitForBlockedStoreQuery(t, ctx, db, "SELECT id FROM projects WHERE id=$1 AND organization_id=$2 AND deletion_requested_at IS NULL FOR UPDATE")
	if err = blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-deleteResult; err != nil {
		t.Fatalf("project deletion after child operations became terminal: %v", err)
	}
	concurrentEnvironment := <-createResult
	if concurrentEnvironment.err != nil && !errors.Is(concurrentEnvironment.err, ErrNotFound) {
		t.Fatalf("concurrent environment creation error=%v", concurrentEnvironment.err)
	}
	if concurrentEnvironment.err == nil {
		var deleting bool
		if err = db.Pool.QueryRow(ctx, `SELECT deletion_requested_at IS NOT NULL FROM environments WHERE id=$1`, concurrentEnvironment.environment.ID).Scan(&deleting); err != nil || !deleting {
			t.Fatalf("concurrently created environment escaped project deletion: deleting=%v err=%v", deleting, err)
		}
	}
	if _, err = db.CreateEnvironment(ctx, organizationID, projectID, "Late", "late"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("environment creation in deleting project error=%v, want ErrNotFound", err)
	}
	var projectDeleting, firstEnvironmentDeleting, secondEnvironmentDeleting, serviceDeleting bool
	if err = db.Pool.QueryRow(ctx, `SELECT project.deletion_requested_at IS NOT NULL,first.deletion_requested_at IS NOT NULL,second.deletion_requested_at IS NOT NULL,service.deletion_requested_at IS NOT NULL FROM projects project JOIN environments first ON first.id=$2 JOIN environments second ON second.id=$3 JOIN compose_services service ON service.id=$4 WHERE project.id=$1`, projectID, environmentID, secondEnvironment.ID, serviceID).Scan(&projectDeleting, &firstEnvironmentDeleting, &secondEnvironmentDeleting, &serviceDeleting); err != nil {
		t.Fatal(err)
	}
	if !projectDeleting || !firstEnvironmentDeleting || !secondEnvironmentDeleting || !serviceDeleting {
		t.Fatalf("deletion flags project=%v firstEnvironment=%v secondEnvironment=%v service=%v", projectDeleting, firstEnvironmentDeleting, secondEnvironmentDeleting, serviceDeleting)
	}
	projects, err := db.ListProjects(ctx, organizationID)
	if err != nil {
		t.Fatal(err)
	}
	if len(projects) != 0 {
		t.Fatalf("deleting project remained in active inventory: %#v", projects)
	}
	environments, err := db.ListEnvironments(ctx, organizationID, projectID)
	if err != nil {
		t.Fatal(err)
	}
	if len(environments) != 0 {
		t.Fatalf("environments under deleting project remained in active inventory: %#v", environments)
	}
}

func TestParentDeletionFencesUnboundDatabaseOperations(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)

	organizationID, projectID := uuid.New(), uuid.New()
	firstEnvironmentID, secondEnvironmentID := uuid.New(), uuid.New()
	firstDatabaseID, secondDatabaseID := uuid.New(), uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Unbound database deletion fence',$2)`, []any{organizationID, "unbound-database-deletion-fence-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'First','first'),($3,$2,'Second','second')`, []any{firstEnvironmentID, projectID, secondEnvironmentID}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,encrypted_credentials) VALUES($1,$2,'First database','first-database','postgres','17','encrypted'),($3,$4,'Second database','second-database','postgres','17','encrypted')`, []any{firstDatabaseID, firstEnvironmentID, secondDatabaseID, secondEnvironmentID}},
	}
	for _, statement := range statements {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM jobs WHERE resource_key=ANY($1) OR payload->>'projectId'=$2 OR payload->>'environmentId'=ANY($3)`, []string{"database:" + firstDatabaseID.String(), "database:" + secondDatabaseID.String()}, projectID.String(), []string{firstEnvironmentID.String(), secondEnvironmentID.String()})
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	})

	migration, err := db.QueueDatabaseMigration(ctx, organizationID, DatabaseMigration{
		DatabaseInstanceID:    firstDatabaseID,
		SourceKind:            "postgres",
		SourceID:              "source",
		SourceEngine:          "postgres",
		SourceVersion:         "16",
		SourceHost:            "source.example.test",
		EncryptedSourceConfig: "encrypted",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.DeleteEnvironment(ctx, organizationID, firstEnvironmentID); !errors.Is(err, ErrBusy) {
		t.Fatalf("environment deletion during unbound database migration error=%v, want ErrBusy", err)
	}
	if err = db.DeleteProject(ctx, organizationID, projectID); !errors.Is(err, ErrBusy) {
		t.Fatalf("project deletion during unbound database migration error=%v, want ErrBusy", err)
	}
	if err = db.CancelDatabaseMigration(ctx, organizationID, migration.ID); err != nil {
		t.Fatal(err)
	}
	blocker, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	if err = blocker.QueryRow(ctx, `SELECT id FROM database_instances WHERE id=$1 FOR UPDATE`, firstDatabaseID).Scan(new(uuid.UUID)); err != nil {
		t.Fatal(err)
	}
	deleteResult := make(chan error, 1)
	go func() { deleteResult <- db.DeleteEnvironment(ctx, organizationID, firstEnvironmentID) }()
	waitForBlockedStoreQuery(t, ctx, db, "SELECT id FROM database_instances WHERE environment_id=$1 ORDER BY id FOR UPDATE")
	type backupResult struct {
		backup DatabaseBackup
		err    error
	}
	backupResultChannel := make(chan backupResult, 1)
	go func() {
		backup, backupErr := db.QueueDatabaseBackup(ctx, organizationID, firstDatabaseID, uuid.Nil, nil)
		backupResultChannel <- backupResult{backup: backup, err: backupErr}
	}()
	waitForBlockedStoreQuery(t, ctx, db, "SELECT d.id,d.compose_service_id FROM database_instances")
	if err = blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	deleteErr := <-deleteResult
	concurrentBackup := <-backupResultChannel
	switch {
	case deleteErr == nil:
		if !errors.Is(concurrentBackup.err, ErrDeleting) {
			t.Fatalf("database backup admitted after environment deletion request: backup=%#v err=%v", concurrentBackup.backup, concurrentBackup.err)
		}
	case concurrentBackup.err == nil:
		if !errors.Is(deleteErr, ErrBusy) {
			t.Fatalf("environment deletion did not reject concurrent unbound database backup: %v", deleteErr)
		}
		if err = db.CancelDatabaseBackup(ctx, organizationID, concurrentBackup.backup.ID); err != nil {
			t.Fatal(err)
		}
		if err = db.DeleteEnvironment(ctx, organizationID, firstEnvironmentID); err != nil {
			t.Fatalf("delete environment after concurrent backup cancellation: %v", err)
		}
	default:
		t.Fatalf("unbound database deletion race produced no valid winner: deletion=%v backup=%v", deleteErr, concurrentBackup.err)
	}
	if _, err = db.QueueDatabaseBackup(ctx, organizationID, firstDatabaseID, uuid.Nil, nil); !errors.Is(err, ErrDeleting) {
		t.Fatalf("database backup in deleting environment error=%v, want ErrDeleting", err)
	}
	if err = db.DeleteProject(ctx, organizationID, projectID); err != nil {
		t.Fatalf("delete project after migration cancellation: %v", err)
	}
	if _, err = db.QueueDatabaseMigration(ctx, organizationID, DatabaseMigration{DatabaseInstanceID: secondDatabaseID}); !errors.Is(err, ErrDeleting) {
		t.Fatalf("database migration in deleting project error=%v, want ErrDeleting", err)
	}
	if _, err = db.RebindDatabaseDriverIdentity(ctx, Principal{OrganizationID: organizationID}, secondDatabaseID, "second-database", "built-in", "", "127.0.0.1"); !errors.Is(err, ErrDeleting) {
		t.Fatalf("database driver rebind in deleting project error=%v, want ErrDeleting", err)
	}
}
