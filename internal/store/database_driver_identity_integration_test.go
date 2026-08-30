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
	jobID := uuid.New()
	if _, err = db.Pool.Exec(ctx, `INSERT INTO jobs(id,kind,payload,status,resource_key) VALUES($1,'backup.database','{}','pending',$2)`, jobID, "database:"+databaseID.String()); err != nil {
		t.Fatal(err)
	}
	principal := Principal{OrganizationID: organizationID}
	if _, err = db.RebindDatabaseDriverIdentity(ctx, principal, databaseID, "data", "external", other, "127.0.0.1"); !errors.Is(err, ErrBusy) {
		t.Fatalf("active-job rebind error=%v", err)
	}
	if _, err = db.Pool.Exec(ctx, `DELETE FROM jobs WHERE id=$1`, jobID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.RebindDatabaseDriverIdentity(ctx, principal, databaseID, "wrong", "external", other, "127.0.0.1"); !errors.Is(err, ErrDatabaseDriverConfirmation) {
		t.Fatalf("confirmation error=%v", err)
	}
	updated, err := db.RebindDatabaseDriverIdentity(ctx, principal, databaseID, "data", "external", other, "127.0.0.1")
	if err != nil || updated.DriverDigest != other {
		t.Fatalf("reviewed rebind=%#v err=%v", updated, err)
	}
	var auditCount int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND action='database.driver_rebind' AND resource_id=$2`, organizationID, databaseID.String()).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("rebind audit count=%d err=%v", auditCount, err)
	}
}

func TestDatabaseStorageNodeBindsAtomically(t *testing.T) {
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
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Storage placement',$2)`, []any{organizationID, "storage-placement-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Environment','environment')`, []any{environmentID, projectID}},
		{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,encrypted_credentials) VALUES($1,$2,'Data','data','postgres','17','encrypted')`, []any{databaseID, environmentID}},
	} {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	})
	if err = db.BindDatabaseStorageNode(ctx, databaseID, "nodea"); err != nil {
		t.Fatal(err)
	}
	if err = db.BindDatabaseStorageNode(ctx, databaseID, "nodea"); err != nil {
		t.Fatalf("idempotent bind: %v", err)
	}
	if err = db.BindDatabaseStorageNode(ctx, databaseID, "nodeb"); !errors.Is(err, ErrDatabaseStorageNodeMismatch) {
		t.Fatalf("mismatched bind error=%v", err)
	}
	item, err := db.GetDatabase(ctx, organizationID, databaseID)
	if err != nil || item.StorageNodeID != "nodea" {
		t.Fatalf("database=%#v err=%v", item, err)
	}
}
