package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestLateAuditedMutationsRollbackAfterSessionRevocation(t *testing.T) {
	t.Run("database driver rebind", func(t *testing.T) {
		db, ctx, organizationID, _, actorID := authorityFenceFixture(t)
		sessionID, projectID, environmentID, databaseID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
		insertAuthenticatedSession(t, ctx, db, sessionID, actorID)
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Authority project',$3)`, []any{projectID, organizationID, "authority-project-" + projectID.String()}},
			{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Authority environment',$3)`, []any{environmentID, projectID, "authority-environment-" + environmentID.String()}},
			{`INSERT INTO database_instances(id,environment_id,name,slug,engine,version,driver_source,driver_artifact_digest,encrypted_credentials) VALUES($1,$2,'Authority data','authority-data','external-test','1','external',$3,'encrypted')`, []any{databaseID, environmentID, "sha256:" + strings.Repeat("0", 64)}},
		} {
			if _, err := db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
				t.Fatal(err)
			}
		}

		principal := Principal{OrganizationID: organizationID, UserID: actorID, SessionID: sessionID, Role: "admin"}
		revocation := beginSessionRevocation(t, ctx, db, principal)
		result := make(chan error, 1)
		go func() {
			_, err := db.RebindDatabaseDriverIdentity(ctx, principal, databaseID, "authority-data", "external", "sha256:"+strings.Repeat("1", 64), "127.0.0.1:1234")
			result <- err
		}()
		assertAuthorityMutationBlocked(t, result)
		if err := revocation.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		assertInsufficientRoleResult(t, result)

		var source, digest string
		if err := db.Pool.QueryRow(ctx, `SELECT driver_source,driver_artifact_digest FROM database_instances WHERE id=$1`, databaseID).Scan(&source, &digest); err != nil {
			t.Fatal(err)
		}
		if source != "external" || digest != "sha256:"+strings.Repeat("0", 64) {
			t.Fatalf("revoked session changed database driver identity to %q %q", source, digest)
		}
		assertNoAuthorityMutationAudit(t, db, ctx, organizationID, actorID, "database.driver_rebind")
	})

	t.Run("AI finding triage", func(t *testing.T) {
		db, ctx, organizationID, ownerID, actorID := authorityFenceFixture(t)
		sessionID := uuid.New()
		insertAuthenticatedSession(t, ctx, db, sessionID, actorID)
		auditor, err := db.CreateServiceAccount(ctx, organizationID, ownerID, "authority-auditor", "auditor", []byte("authority-auditor-"+uuid.NewString()), time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		run, err := db.CreateAIAuditRun(ctx, organizationID, auditor.ID, "authority", "v1", "test", json.RawMessage(`{"kind":"platform"}`))
		if err != nil {
			t.Fatal(err)
		}
		finding, err := db.AddAIAuditFinding(ctx, organizationID, auditor.ID, AIAuditFinding{
			RunID: run.ID, Severity: "high", Category: "authority", Title: "Authority test",
			Description: "session revocation must fence triage", Evidence: json.RawMessage(`{}`), Fingerprint: "authority:session",
		})
		if err != nil {
			t.Fatal(err)
		}

		principal := Principal{OrganizationID: organizationID, UserID: actorID, SessionID: sessionID, Role: "admin"}
		revocation := beginSessionRevocation(t, ctx, db, principal)
		result := make(chan error, 1)
		go func() {
			_, updateErr := db.UpdateAIAuditFindingDisposition(ctx, principal, finding.ID, "acknowledged", "stale triage", "127.0.0.1:1234")
			result <- updateErr
		}()
		assertAuthorityMutationBlocked(t, result)
		if err = revocation.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		assertInsufficientRoleResult(t, result)

		items, err := db.ListAIAuditFindings(ctx, organizationID, run.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(items) != 1 || items[0].Disposition != "open" || items[0].TriageNote != "" || items[0].TriagedByUser != nil || items[0].TriagedAt != nil {
			t.Fatalf("revoked session changed AI finding: %#v", items)
		}
		assertNoAuthorityMutationAudit(t, db, ctx, organizationID, actorID, "ai_audit_finding.acknowledged")
	})
}

func TestAIAuditFindingIngestionRollsBackAfterTokenRotation(t *testing.T) {
	db, ctx, organizationID, ownerID, _ := authorityFenceFixture(t)
	tokenHash := []byte("finding-token-" + uuid.NewString())
	auditor, err := db.CreateServiceAccount(ctx, organizationID, ownerID, "finding-auditor", "auditor", tokenHash, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	principal, err := db.Authenticate(ctx, tokenHash, &organizationID)
	if err != nil || principal.ServiceAccountTokenID == nil {
		t.Fatalf("authenticate auditor principal=%#v err=%v", principal, err)
	}
	run, err := db.CreateAIAuditRun(ctx, organizationID, auditor.ID, "authority", "v1", "test", json.RawMessage(`{"kind":"platform"}`))
	if err != nil {
		t.Fatal(err)
	}

	rotation, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rotation.Rollback(context.Background()) })
	if err = rotateServiceAccountTokenTx(ctx, rotation, organizationID, auditor.ID, []byte("replacement-"+uuid.NewString()), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	result := make(chan error, 1)
	go func() {
		_, addErr := db.AddAuthenticatedAIAuditFinding(ctx, principal, AIAuditFinding{
			RunID: run.ID, Severity: "critical", Category: "authority", Title: "Stale auditor",
			Description: "rotated auditor credentials must not publish findings", Evidence: json.RawMessage(`{}`), Fingerprint: "authority:auditor-token",
		})
		result <- addErr
	}()
	assertAuthorityMutationBlocked(t, result)
	if err = rotation.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	assertInsufficientRoleResult(t, result)

	items, err := db.ListAIAuditFindings(ctx, organizationID, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("rotated auditor token retained findings: %#v", items)
	}
}

func insertAuthenticatedSession(t *testing.T, ctx context.Context, db *Store, sessionID, userID uuid.UUID) {
	t.Helper()
	if _, err := db.Pool.Exec(ctx, `INSERT INTO sessions(id,user_id,token_hash,expires_at,auth_method) VALUES($1,$2,$3,now()+interval '1 hour','local')`, sessionID, userID, []byte("late-audit-session-"+uuid.NewString())); err != nil {
		t.Fatal(err)
	}
}

func beginSessionRevocation(t *testing.T, ctx context.Context, db *Store, principal Principal) interface {
	Commit(context.Context) error
	Rollback(context.Context) error
} {
	t.Helper()
	revocation, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = revocation.Rollback(context.Background()) })
	if err = lockPrincipalSession(ctx, revocation, principal); err != nil {
		t.Fatal(err)
	}
	if tag, deleteErr := revocation.Exec(ctx, `DELETE FROM sessions WHERE id=$1`, principal.SessionID); deleteErr != nil {
		t.Fatal(deleteErr)
	} else if tag.RowsAffected() != 1 {
		t.Fatal("session revocation did not delete the authenticated session")
	}
	return revocation
}
