package store

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestScopedGrantRevocationFencesAuthorizedMutation(t *testing.T) {
	for _, scopeType := range []string{"project", "environment"} {
		t.Run(scopeType, func(t *testing.T) {
			databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
			if databaseURL == "" {
				t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			db, err := Open(ctx, databaseURL)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(db.Pool.Close)

			organizationID, userID, sessionID := uuid.New(), uuid.New(), uuid.New()
			projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New()
			for _, statement := range []struct {
				query string
				args  []any
			}{
				{`INSERT INTO organizations(id,name,slug) VALUES($1,'Scoped authority',$2)`, []any{organizationID, "scoped-authority-" + organizationID.String()}},
				{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
				{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'viewer')`, []any{organizationID, userID}},
				{`INSERT INTO sessions(id,user_id,token_hash,expires_at,auth_method) VALUES($1,$2,$3,now()+interval '1 hour','local')`, []any{sessionID, userID, []byte("scoped-authority-session")}},
				{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
				{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Environment','environment')`, []any{environmentID, projectID}},
				{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'Service','service',$3,'services: {}')`, []any{serviceID, environmentID, "scoped-authority-" + serviceID.String()}},
			} {
				if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() {
				_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
				_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
			})

			scopeID := projectID
			if scopeType == "environment" {
				scopeID = environmentID
			}
			if _, err = db.UpsertResourceGrant(ctx, organizationID, scopeType, scopeID, userID, "developer"); err != nil {
				t.Fatal(err)
			}
			principal := Principal{UserID: userID, SessionID: sessionID, OrganizationID: organizationID, Role: "viewer"}
			principal, role, err := db.BindResourceAuthorization(ctx, principal, "service", serviceID, "developer")
			if err != nil || role != "developer" || len(principal.ScopedAuthorizations) != 1 {
				t.Fatalf("bound authorization role=%q claims=%#v err=%v", role, principal.ScopedAuthorizations, err)
			}

			revocation, err := db.Pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer revocation.Rollback(context.Background())
			table, idColumn, _ := grantScope(scopeType)
			if _, err = revocation.Exec(ctx, `DELETE FROM `+table+` WHERE `+idColumn+`=$1 AND user_id=$2`, scopeID, userID); err != nil {
				t.Fatal(err)
			}

			result := make(chan error, 1)
			go func() {
				_, updateErr := db.UpdateComposeServiceConfigurationWithAudit(ctx, principal, serviceID, "services:\n  app:\n    image: example.invalid/new:1\n", nil, "127.0.0.1:1234")
				result <- updateErr
			}()
			waitForBlockedScopedAuthorization(t, ctx, db, table)
			if err = revocation.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case updateErr := <-result:
				if !errors.Is(updateErr, ErrInsufficientRole) {
					t.Fatalf("mutation error=%v, want insufficient role", updateErr)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}

			var compose string
			var revision int64
			if err = db.Pool.QueryRow(ctx, `SELECT compose_yaml,revision FROM compose_services WHERE id=$1`, serviceID).Scan(&compose, &revision); err != nil || compose != "services: {}" || revision != 1 {
				t.Fatalf("revoked grant changed service: compose=%q revision=%d err=%v", compose, revision, err)
			}
			var audits int
			if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND action='service.update'`, organizationID, userID).Scan(&audits); err != nil || audits != 0 {
				t.Fatalf("revoked grant audit events=%d err=%v", audits, err)
			}
		})
	}
}

func waitForBlockedScopedAuthorization(t *testing.T, ctx context.Context, db *Store, table string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	fragment := "%SELECT role FROM " + table + " WHERE%FOR UPDATE%"
	for time.Now().Before(deadline) {
		var blocked bool
		err := db.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE $1)`, fragment).Scan(&blocked)
		if err != nil {
			t.Fatal(err)
		}
		if blocked {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("scoped authorization query for %s did not block behind grant revocation", table)
}
