package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/GhaziBenDahmane/Orka/internal/cryptox"
	"github.com/GhaziBenDahmane/Orka/internal/store"
	"github.com/google/uuid"
)

func TestSCIMRevocationFencesAuthenticatedUserAndGroupMutations(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	db, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)

	organizationID, tokenID := uuid.New(), uuid.New()
	token := "scim-authority-" + uuid.NewString()
	if _, err = db.Pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'SCIM authority',$2)`, organizationID, "scim-authority-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Pool.Exec(ctx, `INSERT INTO scim_tokens(id,organization_id,name,token_hash,default_role,expires_at) VALUES($1,$2,'authority',$3,'viewer',now()+interval '1 hour')`, tokenID, organizationID, cryptox.Digest(token)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	})

	authenticatedTokenID, authenticatedOrganizationID, role, err := db.AuthenticateSCIMWithID(ctx, cryptox.Digest(token))
	if err != nil {
		t.Fatal(err)
	}
	credential := scimCredential{tokenID: authenticatedTokenID, organizationID: authenticatedOrganizationID, defaultRole: role}

	// Hold the same organization-first revocation transaction used by the
	// administration API. Both already-authenticated writes must wait for its
	// outcome, then observe the revoked exact token instead of committing.
	revocation, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer revocation.Rollback(context.Background())
	var lockedOrganizationID uuid.UUID
	if err = revocation.QueryRow(ctx, `SELECT id FROM organizations WHERE id=$1 FOR UPDATE`, organizationID).Scan(&lockedOrganizationID); err != nil {
		t.Fatal(err)
	}
	if _, err = revocation.Exec(ctx, `UPDATE scim_tokens SET revoked_at=now() WHERE id=$1 AND organization_id=$2`, tokenID, organizationID); err != nil {
		t.Fatal(err)
	}

	type response struct {
		status int
		body   string
	}
	server := &Server{Store: db, PublicURL: "http://example.test"}
	userEmail := "revoked-" + uuid.NewString() + "@example.test"
	userResult := make(chan response, 1)
	go func() {
		request := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", strings.NewReader(`{"userName":"`+userEmail+`","active":true}`))
		request.Header.Set("Content-Type", "application/scim+json")
		recorder := httptest.NewRecorder()
		server.createSCIMUser(recorder, request, credential)
		userResult <- response{status: recorder.Code, body: recorder.Body.String()}
	}()

	groupName := "Revoked " + uuid.NewString()
	groupResult := make(chan response, 1)
	go func() {
		request := httptest.NewRequest(http.MethodPost, "/scim/v2/Groups", strings.NewReader(`{"displayName":"`+groupName+`","role":"viewer"}`))
		request.Header.Set("Content-Type", "application/scim+json")
		recorder := httptest.NewRecorder()
		server.createSCIMGroup(recorder, request, credential)
		groupResult <- response{status: recorder.Code, body: recorder.Body.String()}
	}()

	waitForBlockedSCIMMutations(t, ctx, db, 2)
	if err = revocation.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for name, result := range map[string]<-chan response{"user": userResult, "group": groupResult} {
		select {
		case got := <-result:
			if got.status != http.StatusUnauthorized || !strings.Contains(got.body, "invalid SCIM token") {
				t.Fatalf("%s mutation response=(%d, %q), want revoked credential rejection", name, got.status, got.body)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}

	var users, groups, audits int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE email=$1`, userEmail).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM scim_groups WHERE organization_id=$1 AND display_name=$2`, organizationID, groupName).Scan(&groups); err != nil {
		t.Fatal(err)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND action IN ('scim.user.create','scim.group.create')`, organizationID).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if users != 0 || groups != 0 || audits != 0 {
		t.Fatalf("revoked SCIM writes changed state: users=%d groups=%d audits=%d", users, groups, audits)
	}
}

func waitForBlockedSCIMMutations(t *testing.T, ctx context.Context, db *store.Store, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var blocked int
		err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE '%SELECT id FROM organizations WHERE id=$1 FOR UPDATE%'`).Scan(&blocked)
		if err != nil {
			t.Fatal(err)
		}
		if blocked >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%d SCIM mutations did not block behind revocation", want)
}
