package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func TestOrganizationMemberAdministration(t *testing.T) {
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
	box, _ := cryptox.New(bytes.Repeat([]byte{7}, 32))
	organizationID, otherOrganizationID := uuid.New(), uuid.New()
	ownerID, secondOwnerID, adminID, viewerID, scimID, otherID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	projectID, environmentID := uuid.New(), uuid.New()
	ownerToken, adminToken, viewerToken := "owner-"+uuid.NewString(), "admin-"+uuid.NewString(), "viewer-"+uuid.NewString()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Members',$2),($3,'Other members',$4)`, []any{organizationID, "members-" + organizationID.String(), otherOrganizationID, "other-members-" + otherOrganizationID.String()}},
		{`INSERT INTO users(id,email,password_hash,display_name) VALUES($1,$2,'x','Owner'),($3,$4,'x','Second owner'),($5,$6,'x','Admin'),($7,$8,'x','Viewer'),($9,$10,'x','SCIM user'),($11,$12,'x','Other user')`, []any{ownerID, ownerID.String() + "@example.test", secondOwnerID, secondOwnerID.String() + "@example.test", adminID, adminID.String() + "@example.test", viewerID, viewerID.String() + "@example.test", scimID, scimID.String() + "@example.test", otherID, otherID.String() + "@example.test"}},
		{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner'),($1,$3,'owner'),($1,$4,'admin'),($1,$5,'viewer'),($1,$6,'developer'),($7,$8,'owner')`, []any{organizationID, ownerID, secondOwnerID, adminID, viewerID, scimID, otherOrganizationID, otherID}},
		{`INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '1 hour'),($4,$5,$6,now()+interval '1 hour'),($7,$8,$9,now()+interval '1 hour')`, []any{uuid.New(), ownerID, cryptox.Digest(ownerToken), uuid.New(), adminID, cryptox.Digest(adminToken), uuid.New(), viewerID, cryptox.Digest(viewerToken)}},
		{`INSERT INTO scim_user_defaults(organization_id,user_id,default_role) VALUES($1,$2,'developer')`, []any{organizationID, scimID}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO project_grants(project_id,user_id,role) VALUES($1,$2,'developer')`, []any{projectID, viewerID}},
		{`INSERT INTO environment_grants(environment_id,user_id,role) VALUES($1,$2,'admin')`, []any{environmentID, viewerID}},
	} {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id IN ($1,$2)`, organizationID, otherOrganizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=ANY($1)`, []uuid.UUID{ownerID, secondOwnerID, adminID, viewerID, scimID, otherID})
	})

	server := httptest.NewServer((&Server{Store: db, Box: box, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler())
	defer server.Close()
	membersURL := server.URL + "/v1/members"
	status, body := scopedAPIRequest(t, membersURL, adminToken, organizationID, http.MethodGet, nil)
	var listed struct {
		Items []store.OrganizationMember `json:"items"`
	}
	if err = json.Unmarshal(body, &listed); err != nil || status != http.StatusOK || len(listed.Items) != 5 {
		t.Fatalf("member list status=%d items=%#v err=%v body=%s", status, listed.Items, err, body)
	}
	var scimManaged bool
	for _, member := range listed.Items {
		if member.UserID == otherID {
			t.Fatalf("cross-tenant member leaked: %#v", member)
		}
		scimManaged = scimManaged || member.UserID == scimID && member.ManagedBySCIM
	}
	if !scimManaged {
		t.Fatalf("SCIM-managed member was not identified: %#v", listed.Items)
	}
	if status, _ = scopedAPIRequest(t, membersURL, viewerToken, organizationID, http.MethodGet, nil); status != http.StatusForbidden {
		t.Fatalf("viewer member list status=%d, want 403", status)
	}
	if status, _ = scopedAPIRequest(t, membersURL+"/"+viewerID.String(), ownerToken, organizationID, http.MethodPatch, map[string]string{"role": "superadmin"}); status != http.StatusBadRequest {
		t.Fatalf("invalid role status=%d, want 400", status)
	}
	if status, _ = scopedAPIRequest(t, membersURL+"/"+viewerID.String(), adminToken, organizationID, http.MethodPatch, map[string]string{"role": "owner"}); status != http.StatusForbidden {
		t.Fatalf("admin promoted owner status=%d, want 403", status)
	}
	if status, _ = scopedAPIRequest(t, membersURL+"/"+secondOwnerID.String(), adminToken, organizationID, http.MethodPatch, map[string]string{"role": "admin"}); status != http.StatusForbidden {
		t.Fatalf("admin demoted owner status=%d, want 403", status)
	}
	if status, _ = scopedAPIRequest(t, membersURL+"/"+secondOwnerID.String(), adminToken, organizationID, http.MethodDelete, nil); status != http.StatusForbidden {
		t.Fatalf("admin removed owner status=%d, want 403", status)
	}
	if status, body = scopedAPIRequest(t, membersURL+"/"+secondOwnerID.String(), ownerToken, organizationID, http.MethodPatch, map[string]string{"role": "admin"}); status != http.StatusOK || !bytes.Contains(body, []byte(`"role":"admin"`)) {
		t.Fatalf("owner demotion status=%d body=%s", status, body)
	}
	if status, _ = scopedAPIRequest(t, membersURL+"/"+ownerID.String(), ownerToken, organizationID, http.MethodPatch, map[string]string{"role": "admin"}); status != http.StatusConflict {
		t.Fatalf("last owner demotion status=%d, want 409", status)
	}
	if status, _ = scopedAPIRequest(t, membersURL+"/"+scimID.String(), ownerToken, organizationID, http.MethodDelete, nil); status != http.StatusConflict {
		t.Fatalf("SCIM-managed deletion status=%d, want 409", status)
	}
	if status, _ = scopedAPIRequest(t, membersURL+"/"+scimID.String(), ownerToken, organizationID, http.MethodPatch, map[string]string{"role": "viewer"}); status != http.StatusConflict {
		t.Fatalf("SCIM-managed update status=%d, want 409", status)
	}
	if status, _ = scopedAPIRequest(t, membersURL+"/"+otherID.String(), ownerToken, organizationID, http.MethodDelete, nil); status != http.StatusNotFound {
		t.Fatalf("cross-tenant member deletion status=%d, want 404", status)
	}
	if status, body = scopedAPIRequest(t, membersURL+"/"+viewerID.String(), adminToken, organizationID, http.MethodPatch, map[string]string{"role": "developer"}); status != http.StatusOK || !bytes.Contains(body, []byte(`"role":"developer"`)) {
		t.Fatalf("member role update status=%d body=%s", status, body)
	}
	if status, body = scopedAPIRequest(t, membersURL+"/"+viewerID.String(), ownerToken, organizationID, http.MethodDelete, nil); status != http.StatusNoContent {
		t.Fatalf("member removal status=%d body=%s", status, body)
	}
	if status, _ = scopedAPIRequest(t, server.URL+"/v1/me", viewerToken, organizationID, http.MethodGet, nil); status != http.StatusUnauthorized {
		t.Fatalf("removed member authentication status=%d, want 401", status)
	}
	var membershipCount, grantCount, auditCount int
	if err = db.Pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM memberships WHERE organization_id=$1 AND user_id=$2),
		(SELECT count(*) FROM project_grants WHERE project_id=$3 AND user_id=$2)+(SELECT count(*) FROM environment_grants WHERE environment_id=$4 AND user_id=$2),
		(SELECT count(*) FROM audit_events WHERE organization_id=$1 AND resource_id=$2::text AND action IN ('membership.role.update','membership.remove'))`, organizationID, viewerID, projectID, environmentID).Scan(&membershipCount, &grantCount, &auditCount); err != nil {
		t.Fatal(err)
	}
	if membershipCount != 0 || grantCount != 0 || auditCount != 2 {
		t.Fatalf("member cleanup membership=%d grants=%d audits=%d", membershipCount, grantCount, auditCount)
	}
}

func TestConcurrentOwnerDemotionsRetainAnOwner(t *testing.T) {
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
	organizationID, firstOwnerID, secondOwnerID := uuid.New(), uuid.New(), uuid.New()
	if _, err = db.Pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Concurrent owners',$2)`, organizationID, "concurrent-owners-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Pool.Exec(ctx, `INSERT INTO users(id,email,password_hash,display_name) VALUES($1,$2,'x','First owner'),($3,$4,'x','Second owner')`, firstOwnerID, firstOwnerID.String()+"@example.test", secondOwnerID, secondOwnerID.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Pool.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner'),($1,$3,'owner')`, organizationID, firstOwnerID, secondOwnerID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=ANY($1)`, []uuid.UUID{firstOwnerID, secondOwnerID})
	})

	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for _, userID := range []uuid.UUID{firstOwnerID, secondOwnerID} {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			_, updateErr := db.UpdateOrganizationMemberRole(ctx, organizationID, userID, "admin", "owner")
			results <- updateErr
		}()
	}
	close(start)
	workers.Wait()
	close(results)

	var succeeded, rejected int
	for updateErr := range results {
		switch {
		case updateErr == nil:
			succeeded++
		case errors.Is(updateErr, store.ErrLastOwner):
			rejected++
		default:
			t.Fatalf("unexpected concurrent update error: %v", updateErr)
		}
	}
	var owners int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM memberships WHERE organization_id=$1 AND role='owner'`, organizationID).Scan(&owners); err != nil {
		t.Fatal(err)
	}
	if succeeded != 1 || rejected != 1 || owners != 1 {
		t.Fatalf("concurrent demotions succeeded=%d rejected=%d owners=%d", succeeded, rejected, owners)
	}
}
