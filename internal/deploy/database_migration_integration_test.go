package deploy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/database"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func TestWorkerMigratesDatabaseWithFencedNativeTransfer(t *testing.T) {
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
	box, err := cryptox.New(bytes.Repeat([]byte{6}, 32))
	if err != nil {
		t.Fatal(err)
	}
	organizationID, projectID, environmentID, serviceID, databaseID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	targetJSON, _ := json.Marshal(map[string]string{"username": "target", "password": "target-secret", "database": "app"})
	encryptedTarget, _ := box.Encrypt(targetJSON, "database-credentials")
	stackName := "migration-" + serviceID.String()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Migration Worker',$2)`, []any{organizationID, "migration-worker-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'Postgres','postgres',$3,'services: {}')`, []any{serviceID, environmentID, stackName}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,compose_service_id,encrypted_credentials,status) VALUES($1,$2,'Postgres','postgres','postgres','17',$3,$4,'running')`, []any{databaseID, environmentID, serviceID, encryptedTarget}},
	}
	for _, statement := range statements {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	})

	migrationID := uuid.New()
	sourceJSON, _ := json.Marshal(database.SourceConnection{Username: "source", Password: "source-secret", Database: "legacy", Port: 15432})
	encryptedSource, _ := box.Encrypt(sourceJSON, "database-migration-source:"+migrationID.String())
	migration, err := db.QueueDatabaseMigration(ctx, organizationID, store.DatabaseMigration{ID: migrationID, DatabaseInstanceID: databaseID, SourceKind: "dokploy", SourceID: "legacy-postgres", SourceEngine: "postgres", SourceVersion: "16", SourceHost: "legacy.internal", EncryptedSourceConfig: encryptedSource})
	if err != nil {
		t.Fatal(err)
	}

	directory := t.TempDir()
	dockerBin, restoreMarker := filepath.Join(directory, "docker"), filepath.Join(directory, "restored")
	script := `#!/bin/sh
mount=""
entrypoint=""
filename=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --volume) shift; mount="${1%%:*}" ;;
    --entrypoint) shift; entrypoint="$1" ;;
    --file) shift; filename="${1#/backup/}" ;;
    /backup/*) filename="${1#/backup/}" ;;
  esac
  shift
done
case "$entrypoint" in
  pg_isready) exit 0 ;;
  pg_dump) printf 'native migration dump' > "$mount/$filename"; printf 'backup password=%s\n' "$PGPASSWORD" ;;
  pg_restore) test "$(cat "$mount/$filename")" = 'native migration dump' || exit 7; touch "` + restoreMarker + `"; printf 'restore password=%s\n' "$PGPASSWORD" ;;
  *) exit 8 ;;
esac
`
	if err = os.WriteFile(dockerBin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	worker := Worker{Store: db, Box: box, Swarm: Swarm{DockerBin: dockerBin}, Databases: database.NewRegistry(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	claimed := leaseResourceJob(t, ctx, db, "migrate.database", "migrationId", migration.ID)
	if err = worker.migrateDatabase(ctx, claimed); err != nil {
		t.Fatal(err)
	}
	if err = worker.finish(ctx, claimed, nil); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetDatabaseMigration(ctx, organizationID, migration.ID)
	if err != nil || got.Status != "succeeded" || got.SizeBytes == nil || *got.SizeBytes != int64(len("native migration dump")) || len(got.SHA256) != 64 {
		t.Fatalf("migration=%#v err=%v", got, err)
	}
	if strings.Contains(got.Output, "source-secret") || strings.Contains(got.Output, "target-secret") || !strings.Contains(got.Output, "[REDACTED]") {
		t.Fatalf("migration output was not redacted: %q", got.Output)
	}
	if _, err = os.Stat(restoreMarker); err != nil {
		t.Fatal("target restore did not run")
	}
}
