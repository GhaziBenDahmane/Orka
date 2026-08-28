package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func TestSCIMGroupRoleAndTenantIsolation(t *testing.T) {
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

	orgID, otherOrgID, ownerID, otherUserID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	token := "integration-" + uuid.NewString()
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'SCIM Test',$2),($3,'Other Test',$4)`, orgID, "scim-"+orgID.String(), otherOrgID, "other-"+otherOrgID.String())
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test'),($3,$4,'!test')`, ownerID, ownerID.String()+"@example.test", otherUserID, otherUserID.String()+"@example.test")
	}
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner'),($3,$4,'viewer')`, orgID, ownerID, otherOrgID, otherUserID)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO scim_tokens(id,organization_id,name,token_hash,default_role) VALUES($1,$2,'integration',$3,'viewer')`, uuid.New(), orgID, cryptox.Digest(token))
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=ANY($1)`, []uuid.UUID{orgID, otherOrgID})
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=ANY($1)`, []uuid.UUID{ownerID, otherUserID})
	})

	server := httptest.NewServer((&Server{Store: db, PublicURL: "http://example.test", Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler())
	defer server.Close()

	createdUser := doSCIMRequest(t, server.URL+"/scim/v2/Users", token, http.MethodPost, map[string]any{"userName": "member-" + orgID.String() + "@example.test", "active": true}, http.StatusCreated)
	memberID := createdUser["id"].(string)
	t.Cleanup(func() { _, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, memberID) })

	// A token can never attach a user from another organization to its group.
	doSCIMRequest(t, server.URL+"/scim/v2/Groups", token, http.MethodPost, map[string]any{"displayName": "Cross tenant", "members": []map[string]string{{"value": otherUserID.String()}}}, http.StatusBadRequest)

	group := doSCIMRequest(t, server.URL+"/scim/v2/Groups", token, http.MethodPost, map[string]any{"externalId": uuid.NewString(), "displayName": "Engineering", "role": "admin", "members": []map[string]string{{"value": memberID}}}, http.StatusCreated)
	groupID := group["id"].(string)
	var role string
	if err = db.Pool.QueryRow(ctx, `SELECT role FROM memberships WHERE organization_id=$1 AND user_id=$2`, orgID, memberID).Scan(&role); err != nil || role != "admin" {
		t.Fatalf("group role = %q, err = %v", role, err)
	}
	doSCIMRequest(t, server.URL+"/scim/v2/Groups/"+groupID, token, http.MethodPatch, map[string]any{"Operations": []map[string]any{{"op": "replace", "path": "role", "value": "developer"}}}, http.StatusNoContent)
	if err = db.Pool.QueryRow(ctx, `SELECT role FROM memberships WHERE organization_id=$1 AND user_id=$2`, orgID, memberID).Scan(&role); err != nil || role != "developer" {
		t.Fatalf("updated group role = %q, err = %v", role, err)
	}
	doSCIMRequest(t, server.URL+"/scim/v2/Groups/"+groupID, token, http.MethodPatch, map[string]any{"Operations": []map[string]any{{"op": "remove", "path": `members[value eq "` + memberID + `"]`}}}, http.StatusNoContent)
	if err = db.Pool.QueryRow(ctx, `SELECT role FROM memberships WHERE organization_id=$1 AND user_id=$2`, orgID, memberID).Scan(&role); err != nil || role != "viewer" {
		t.Fatalf("removed group role = %q, err = %v", role, err)
	}
	doSCIMRequest(t, server.URL+"/scim/v2/Groups/"+groupID, token, http.MethodDelete, nil, http.StatusNoContent)
	if err = db.Pool.QueryRow(ctx, `SELECT role FROM memberships WHERE organization_id=$1 AND user_id=$2`, orgID, memberID).Scan(&role); err != nil || role != "viewer" {
		t.Fatalf("fallback role = %q, err = %v", role, err)
	}

	// Organization owners remain outside SCIM deprovisioning authority.
	doSCIMRequest(t, server.URL+"/scim/v2/Users/"+ownerID.String(), token, http.MethodDelete, nil, http.StatusConflict)
}

func doSCIMRequest(t *testing.T, url, token, method string, body any, wantStatus int) map[string]any {
	t.Helper()
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequest(method, url, bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/scim+json")
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != wantStatus {
		data, _ := io.ReadAll(response.Body)
		t.Fatalf("%s %s status = %d, want %d: %s", method, url, response.StatusCode, wantStatus, data)
	}
	if wantStatus == http.StatusNoContent {
		return nil
	}
	var result map[string]any
	if err = json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
}
