package deploy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/database"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func TestWorkersRejectDifferentExternalDriverForBoundDatabase(t *testing.T) {
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
	organizationID, projectID, environmentID, databaseID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Driver workers',$2)`, []any{organizationID, "driver-workers-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Environment','environment')`, []any{environmentID, projectID}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,encrypted_credentials) VALUES($1,$2,'Data','data','shared-driver','1','encrypted')`, []any{databaseID, environmentID}},
	}
	for _, statement := range statements {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	})

	registryA := externalDriverRegistry(t, "# controller-a")
	registryB := externalDriverRegistry(t, "# controller-b")
	workerA := &Worker{Store: db, Databases: registryA}
	if err = workerA.ensureDatabaseDriver(ctx, databaseID, "shared-driver", "unbound", ""); err != nil {
		t.Fatalf("first worker binding: %v", err)
	}
	var source, digest string
	if err = db.Pool.QueryRow(ctx, `SELECT driver_source,driver_artifact_digest FROM database_instances WHERE id=$1`, databaseID).Scan(&source, &digest); err != nil {
		t.Fatal(err)
	}
	if source != "external" || !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("persisted identity=%s %s", source, digest)
	}
	workerB := &Worker{Store: db, Databases: registryB}
	if err = workerB.ensureDatabaseDriver(ctx, databaseID, "shared-driver", source, digest); err == nil || !strings.Contains(err.Error(), "does not match this worker") {
		t.Fatalf("different worker driver error=%v", err)
	}
}

func externalDriverRegistry(t *testing.T, marker string) *database.Registry {
	t.Helper()
	directory := t.TempDir()
	script := `#!/bin/sh
` + marker + `
case "$(cat)" in
  *'"operation":"describe"'*) echo '{"protocolVersion":1,"description":{"name":"shared-driver","defaultVersion":"1","capabilities":["backup-restore"],"backupExtension":"dump"}}' ;;
  *) echo '{"protocolVersion":1,"plan":{"image":"example/database:1","command":["true"],"environment":{},"extension":"dump"}}' ;;
esac
`
	if err := os.WriteFile(filepath.Join(directory, "driver"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	registry := database.NewRegistry()
	if err := registry.LoadExternal(directory); err != nil {
		t.Fatal(err)
	}
	return registry
}
