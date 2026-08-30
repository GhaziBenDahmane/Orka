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
	"strings"
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

	for _, invalid := range []string{"missing-at-sign", "Display Name <member@example.test>", "member@example.test@attacker.test"} {
		doSCIMRequest(t, server.URL+"/scim/v2/Users", token, http.MethodPost, map[string]any{"userName": invalid, "active": true}, http.StatusBadRequest)
	}
	doSCIMRequest(t, server.URL+"/scim/v2/Users", token, http.MethodPost, map[string]any{"userName": "oversized@example.test", "displayName": strings.Repeat("x", 121), "active": true}, http.StatusBadRequest)

	externalUserID := "directory-" + uuid.NewString()
	createdUser := doSCIMRequest(t, server.URL+"/scim/v2/Users", token, http.MethodPost, map[string]any{
		"schemas":    []string{scimUserSchema, "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"},
		"externalId": externalUserID,
		"userName":   "member-" + orgID.String() + "@example.test",
		"active":     true,
		"name":       map[string]string{"givenName": "Example", "familyName": "Member"},
		"emails":     []map[string]any{{"value": "member-" + orgID.String() + "@example.test", "primary": true}},
		"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": map[string]string{"department": "Engineering"},
	}, http.StatusCreated)
	memberID := createdUser["id"].(string)
	if createdUser["externalId"] != externalUserID {
		t.Fatalf("created SCIM externalId=%v, want %q", createdUser["externalId"], externalUserID)
	}
	t.Cleanup(func() { _, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, memberID) })
	reprovisionedUser := doSCIMRequest(t, server.URL+"/scim/v2/Users", token, http.MethodPost, map[string]any{"userName": "member-" + orgID.String() + "@example.test", "active": true}, http.StatusCreated)
	if reprovisionedUser["id"] != memberID || reprovisionedUser["externalId"] != externalUserID {
		t.Fatalf("reprovisioned SCIM identity lost correlation: %#v", reprovisionedUser)
	}
	externalMatch := doSCIMRequest(t, server.URL+`/scim/v2/Users?filter=externalId%20eq%20%22`+externalUserID+`%22`, token, http.MethodGet, nil, http.StatusOK)
	if externalMatch["totalResults"] != float64(1) || len(externalMatch["Resources"].([]any)) != 1 {
		t.Fatalf("unexpected externalId filter response: %#v", externalMatch)
	}
	doSCIMRequest(t, server.URL+"/scim/v2/Users", token, http.MethodPost, map[string]any{"userName": "duplicate-" + orgID.String() + "@example.test", "externalId": externalUserID}, http.StatusConflict)
	updatedExternalUserID := "updated-" + externalUserID
	updatedUserName := "updated-" + orgID.String() + "@example.test"
	doSCIMRequest(t, server.URL+"/scim/v2/Users/"+memberID, token, http.MethodPatch, map[string]any{
		"Operations": []map[string]any{{"op": "replace", "value": map[string]any{"userName": updatedUserName, "displayName": "Updated Member", "externalId": updatedExternalUserID, "active": true}}},
	}, http.StatusNoContent)
	updatedUser := doSCIMRequest(t, server.URL+"/scim/v2/Users/"+memberID, token, http.MethodGet, nil, http.StatusOK)
	if updatedUser["userName"] != updatedUserName || updatedUser["displayName"] != "Updated Member" || updatedUser["externalId"] != updatedExternalUserID {
		t.Fatalf("pathless SCIM patch was not persisted: %#v", updatedUser)
	}
	externalMatch = doSCIMRequest(t, server.URL+`/scim/v2/Users?filter=externalId%20eq%20%22`+updatedExternalUserID+`%22`, token, http.MethodGet, nil, http.StatusOK)
	if externalMatch["totalResults"] != float64(1) {
		t.Fatalf("updated externalId cannot be resolved: %#v", externalMatch)
	}
	userPage := doSCIMRequest(t, server.URL+"/scim/v2/Users?startIndex=2&count=1", token, http.MethodGet, nil, http.StatusOK)
	if userPage["totalResults"] != float64(2) || userPage["startIndex"] != float64(2) || userPage["itemsPerPage"] != float64(1) || len(userPage["Resources"].([]any)) != 1 {
		t.Fatalf("unexpected paginated user response: %#v", userPage)
	}
	doSCIMRequest(t, server.URL+"/scim/v2/Users?count=101", token, http.MethodGet, nil, http.StatusBadRequest)

	// User mutation endpoints are scoped to resources visible in the token's
	// organization. A global user UUID from another tenant cannot be renamed or
	// attached by PATCH.
	doSCIMRequest(t, server.URL+"/scim/v2/Users/"+otherUserID.String(), token, http.MethodPatch, map[string]any{"Operations": []map[string]any{{"op": "replace", "path": "displayName", "value": "Compromised"}}}, http.StatusNotFound)
	doSCIMRequest(t, server.URL+"/scim/v2/Users/"+otherUserID.String(), token, http.MethodPatch, map[string]any{"Operations": []map[string]any{{"op": "replace", "path": "active", "value": true}}}, http.StatusNotFound)
	doSCIMRequest(t, server.URL+"/scim/v2/Users/"+memberID, token, http.MethodPatch, map[string]any{"Operations": []map[string]any{{"op": "replace", "path": "displayName", "value": strings.Repeat("x", 121)}}}, http.StatusBadRequest)
	var otherName string
	var attached bool
	if err = db.Pool.QueryRow(ctx, `SELECT display_name FROM users WHERE id=$1`, otherUserID).Scan(&otherName); err != nil || otherName != "" {
		t.Fatalf("cross-tenant display name = %q, err = %v", otherName, err)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM memberships WHERE organization_id=$1 AND user_id=$2)`, orgID, otherUserID).Scan(&attached); err != nil || attached {
		t.Fatalf("cross-tenant user attached = %v, err = %v", attached, err)
	}

	// A token can never attach a user from another organization to its group.
	doSCIMRequest(t, server.URL+"/scim/v2/Groups", token, http.MethodPost, map[string]any{"displayName": "Cross tenant", "members": []map[string]string{{"value": otherUserID.String()}}}, http.StatusBadRequest)

	group := doSCIMRequest(t, server.URL+"/scim/v2/Groups", token, http.MethodPost, map[string]any{"externalId": uuid.NewString(), "displayName": "Engineering", "role": "admin", "members": []map[string]string{{"value": memberID}}}, http.StatusCreated)
	groupID := group["id"].(string)
	groupCount := doSCIMRequest(t, server.URL+"/scim/v2/Groups?count=0", token, http.MethodGet, nil, http.StatusOK)
	if groupCount["totalResults"] != float64(1) || groupCount["itemsPerPage"] != float64(0) || len(groupCount["Resources"].([]any)) != 0 {
		t.Fatalf("unexpected group count response: %#v", groupCount)
	}
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

	// A global identity may be a member of several organizations, but one
	// organization's SCIM token cannot rewrite profile data observed by another.
	if _, err = db.Pool.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'viewer')`, otherOrgID, memberID); err != nil {
		t.Fatal(err)
	}
	doSCIMRequest(t, server.URL+"/scim/v2/Users/"+memberID, token, http.MethodPatch, map[string]any{"Operations": []map[string]any{{"op": "replace", "path": "displayName", "value": "Cross-tenant rename"}}}, http.StatusConflict)
	var memberName string
	if err = db.Pool.QueryRow(ctx, `SELECT display_name FROM users WHERE id=$1`, memberID).Scan(&memberName); err != nil || memberName != "Updated Member" {
		t.Fatalf("shared display name = %q, err = %v", memberName, err)
	}

	// Inactive SCIM resources retain their organization-scoped binding so the
	// identity provider can query and reactivate them without a global lookup.
	inactive := doSCIMRequest(t, server.URL+"/scim/v2/Users", token, http.MethodPost, map[string]any{"userName": "inactive-" + orgID.String() + "@example.test", "displayName": "Inactive", "active": false}, http.StatusCreated)
	inactiveID := inactive["id"].(string)
	t.Cleanup(func() { _, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, inactiveID) })
	loaded := doSCIMRequest(t, server.URL+"/scim/v2/Users/"+inactiveID, token, http.MethodGet, nil, http.StatusOK)
	if active, _ := loaded["active"].(bool); active {
		t.Fatal("new inactive SCIM user is active")
	}
	doSCIMRequest(t, server.URL+"/scim/v2/Users/"+inactiveID, token, http.MethodPatch, map[string]any{"Operations": []map[string]any{{"op": "replace", "path": "active", "value": true}}}, http.StatusNoContent)
	if err = db.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM memberships WHERE organization_id=$1 AND user_id=$2)`, orgID, inactiveID).Scan(&attached); err != nil || !attached {
		t.Fatalf("inactive user reactivated = %v, err = %v", attached, err)
	}
	doSCIMRequest(t, server.URL+"/scim/v2/Users/"+inactiveID, token, http.MethodPatch, map[string]any{"Operations": []map[string]any{{"op": "replace", "path": "active", "value": false}}}, http.StatusNoContent)
	loaded = doSCIMRequest(t, server.URL+"/scim/v2/Users/"+inactiveID, token, http.MethodGet, nil, http.StatusOK)
	if active, _ := loaded["active"].(bool); active {
		t.Fatal("deprovisioned SCIM user is active")
	}
	doSCIMRequest(t, server.URL+"/scim/v2/Users/"+inactiveID, token, http.MethodDelete, nil, http.StatusNoContent)
	doSCIMRequest(t, server.URL+"/scim/v2/Users/"+inactiveID, token, http.MethodGet, nil, http.StatusNotFound)
	if err = db.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM scim_user_defaults WHERE organization_id=$1 AND user_id=$2)`, orgID, inactiveID).Scan(&attached); err != nil || attached {
		t.Fatalf("deleted inactive user retained SCIM binding = %v, err = %v", attached, err)
	}

	// Organization owners remain outside SCIM deprovisioning authority.
	doSCIMRequest(t, server.URL+"/scim/v2/Users/"+ownerID.String(), token, http.MethodDelete, nil, http.StatusConflict)

	var scimAuditEvents int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND action IN ('scim.user.create','scim.user.patch','scim.user.delete','scim.group.create','scim.group.patch','scim.group.delete')`, orgID).Scan(&scimAuditEvents); err != nil || scimAuditEvents != 11 {
		t.Fatalf("SCIM audit event count=%d, want 11, err=%v", scimAuditEvents, err)
	}
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
	if contentType := response.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "application/scim+json") {
		t.Fatalf("SCIM Content-Type = %q", contentType)
	}
	var result map[string]any
	if err = json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
}
