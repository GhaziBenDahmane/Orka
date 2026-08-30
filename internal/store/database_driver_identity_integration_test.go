package store

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDatabaseDriverIdentityBindsAtomically(t *testing.T) {
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
	organizationID, projectID, environmentID, databaseID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Driver identity',$2)`, []any{organizationID, "driver-identity-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Environment','environment')`, []any{environmentID, projectID}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,encrypted_credentials) VALUES($1,$2,'Data','data','external-test','1','encrypted')`, []any{databaseID, environmentID}},
	}
	for _, statement := range statements {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	})

	digests := []string{
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	errorsByDigest := make([]error, len(digests))
	var wait sync.WaitGroup
	for index := range digests {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			errorsByDigest[index] = db.BindDatabaseDriverIdentity(ctx, databaseID, "external", digests[index])
		}(index)
	}
	wait.Wait()
	successes := 0
	for _, bindErr := range errorsByDigest {
		if bindErr == nil {
			successes++
		} else if !errors.Is(bindErr, ErrDatabaseDriverIdentityMismatch) {
			t.Fatalf("unexpected bind error: %v", bindErr)
		}
	}
	if successes != 1 {
		t.Fatalf("successful bindings=%d errors=%v", successes, errorsByDigest)
	}
	var source, digest string
	if err = db.Pool.QueryRow(ctx, `SELECT driver_source,driver_artifact_digest FROM database_instances WHERE id=$1`, databaseID).Scan(&source, &digest); err != nil {
		t.Fatal(err)
	}
	if source != "external" || digest != digests[0] && digest != digests[1] {
		t.Fatalf("bound identity=%s %s", source, digest)
	}
	if err = db.BindDatabaseDriverIdentity(ctx, databaseID, source, digest); err != nil {
		t.Fatalf("idempotent binding: %v", err)
	}
	other := digests[0]
	if other == digest {
		other = digests[1]
	}
	if err = db.BindDatabaseDriverIdentity(ctx, databaseID, source, other); !errors.Is(err, ErrDatabaseDriverIdentityMismatch) {
		t.Fatalf("mismatched binding error=%v", err)
	}
}
