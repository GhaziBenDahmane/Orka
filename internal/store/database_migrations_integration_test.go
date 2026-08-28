package store

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestDatabaseMigrationQueueScopeUniquenessAndCancellation(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	s := &Store{Pool: pool}
	organizationID, otherOrganizationID := uuid.New(), uuid.New()
	projectID, environmentID, serviceID, databaseID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'migration org',$2)`, []any{organizationID, "migration-" + organizationID.String()}},
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'other org',$2)`, []any{otherOrganizationID, "other-" + otherOrganizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'database','database',$3,'services: {}')`, []any{serviceID, environmentID, "db-" + serviceID.String()}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,compose_service_id,encrypted_credentials,status) VALUES($1,$2,'database','database','postgres','17',$3,'encrypted','running')`, []any{databaseID, environmentID, serviceID}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}

	queued, err := s.QueueDatabaseMigration(ctx, organizationID, DatabaseMigration{DatabaseInstanceID: databaseID, SourceKind: "dokploy", SourceID: "source-db", SourceEngine: "postgres", SourceVersion: "17", SourceHost: "source.internal", EncryptedSourceConfig: "ciphertext"})
	if err != nil {
		t.Fatal(err)
	}
	if queued.Status != "queued" || queued.EncryptedSourceConfig != "" {
		t.Fatalf("unsafe or incomplete queue response: %#v", queued)
	}
	if _, err = s.QueueDatabaseMigration(ctx, organizationID, DatabaseMigration{DatabaseInstanceID: databaseID, SourceKind: "dokploy", SourceID: "second", SourceEngine: "postgres", SourceVersion: "17", SourceHost: "source.internal", EncryptedSourceConfig: "ciphertext"}); !errors.Is(err, ErrBusy) {
		t.Fatalf("concurrent queue error=%v, want ErrBusy", err)
	}
	if _, err = s.GetDatabaseMigration(ctx, otherOrganizationID, queued.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-organization get error=%v, want ErrNotFound", err)
	}
	if err = s.CancelDatabaseMigration(ctx, organizationID, queued.ID); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetDatabaseMigration(ctx, organizationID, queued.ID)
	if err != nil || got.Status != "cancelled" || got.FinishedAt == nil {
		t.Fatalf("cancelled migration=%#v err=%v", got, err)
	}
	var jobStatus string
	if err = pool.QueryRow(ctx, `SELECT status FROM jobs WHERE kind='migrate.database' AND payload->>'migrationId'=$1`, queued.ID.String()).Scan(&jobStatus); err != nil || jobStatus != "cancelled" {
		t.Fatalf("job status=%q err=%v", jobStatus, err)
	}
	if err = s.CancelDatabaseMigration(ctx, organizationID, queued.ID); !errors.Is(err, ErrNotCancellable) {
		t.Fatalf("second cancellation error=%v, want ErrNotCancellable", err)
	}
}
