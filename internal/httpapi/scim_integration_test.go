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
	createdUser, createdUserHeaders := doSCIMRequestWithHeaders(t, server.URL+"/scim/v2/Users", token, http.MethodPost, map[string]any{
		"schemas":    []string{scimUserSchema, "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"},
		"externalId": externalUserID,
		"userName":   "member-" + orgID.String() + "@example.test",
		"active":     true,
		"name":       map[string]string{"givenName": "Example", "familyName": "Member"},
		"emails":     []map[string]any{{"value": "member-" + orgID.String() + "@example.test", "primary": true}},
		"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": map[string]string{"department": "Engineering"},
	}, http.StatusCreated, nil)
	memberID := createdUser["id"].(string)
	if createdUser["externalId"] != externalUserID {
		t.Fatalf("created SCIM externalId=%v, want %q", createdUser["externalId"], externalUserID)
	}
	createdUserETag := createdUserHeaders.Get("ETag")
	createdUserMeta := createdUser["meta"].(map[string]any)
	if createdUserETag != `W/"1"` || createdUserHeaders.Get("Location") == "" || createdUserMeta["version"] != createdUserETag || createdUserMeta["created"] == "" || createdUserMeta["lastModified"] == "" {
		t.Fatalf("created SCIM user metadata=%#v headers=%v", createdUser["meta"], createdUserHeaders)
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
	updatedUser, updatedUserHeaders := doSCIMRequestWithHeaders(t, server.URL+"/scim/v2/Users/"+memberID, token, http.MethodGet, nil, http.StatusOK, nil)
	if updatedUser["userName"] != updatedUserName || updatedUser["displayName"] != "Updated Member" || updatedUser["externalId"] != updatedExternalUserID {
		t.Fatalf("pathless SCIM patch was not persisted: %#v", updatedUser)
	}
	replacedExternalUserID := "replaced-" + externalUserID
	replacedUserName := "replaced-" + orgID.String() + "@example.test"
	replacementBody := map[string]any{
		"schemas":    []string{scimUserSchema, "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"},
		"externalId": replacedExternalUserID, "userName": replacedUserName, "displayName": "Replaced Member", "active": true,
		"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": map[string]string{"department": "Operations"},
	}
	doSCIMRequestWithHeaders(t, server.URL+"/scim/v2/Users/"+memberID, token, http.MethodPut, replacementBody, http.StatusPreconditionFailed, map[string]string{"If-Match": createdUserETag})
	replacedUser, replacedUserHeaders := doSCIMRequestWithHeaders(t, server.URL+"/scim/v2/Users/"+memberID, token, http.MethodPut, replacementBody, http.StatusOK, map[string]string{"If-Match": updatedUserHeaders.Get("ETag")})
	if replacedUser["id"] != memberID || replacedUser["userName"] != replacedUserName || replacedUser["displayName"] != "Replaced Member" || replacedUser["externalId"] != replacedExternalUserID || replacedUser["active"] != true {
		t.Fatalf("SCIM user replacement was not persisted: %#v", replacedUser)
	}
	if replacedUserHeaders.Get("ETag") == updatedUserHeaders.Get("ETag") || replacedUser["meta"].(map[string]any)["version"] != replacedUserHeaders.Get("ETag") {
		t.Fatalf("SCIM user replacement did not advance version: body=%#v headers=%v", replacedUser, replacedUserHeaders)
	}
	updatedExternalUserID = replacedExternalUserID
	externalMatch = doSCIMRequest(t, server.URL+`/scim/v2/Users?filter=externalId%20eq%20%22`+updatedExternalUserID+`%22`, token, http.MethodGet, nil, http.StatusOK)
	if externalMatch["totalResults"] != float64(1) {
		t.Fatalf("updated externalId cannot be resolved: %#v", externalMatch)
	}
	userPage := doSCIMRequest(t, server.URL+"/scim/v2/Users?startIndex=2&count=1", token, http.MethodGet, nil, http.StatusOK)
	if userPage["totalResults"] != float64(2) || userPage["startIndex"] != float64(2) || userPage["itemsPerPage"] != float64(1) || len(userPage["Resources"].([]any)) != 1 {
		t.Fatalf("unexpected paginated user response: %#v", userPage)
	}
	doSCIMRequest(t, server.URL+"/scim/v2/Users?count=101", token, http.MethodGet, nil, http.StatusBadRequest)
	manualUserID := uuid.New()
	if _, err = db.Pool.Exec(ctx, `INSERT INTO users(id,email,password_hash,display_name) VALUES($1,$2,'!test','Manual Member')`, manualUserID, manualUserID.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Pool.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'viewer')`, orgID, manualUserID); err != nil {
		t.Fatal(err)
	}
	manualProviderID, manualLocalSessionID, manualFederatedSessionID := uuid.New(), uuid.New(), uuid.New()
	if _, err = db.Pool.Exec(ctx, `INSERT INTO oidc_providers(id,organization_id,name,issuer,client_id,encrypted_client_secret,domains) VALUES($1,$2,'Manual user OIDC','https://identity.example.test','manual','ciphertext','{example.test}')`, manualProviderID, orgID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Pool.Exec(ctx, `INSERT INTO sessions(id,user_id,token_hash,expires_at,auth_method) VALUES($1,$2,$3,now()+interval '1 hour','local'),($4,$2,$5,now()+interval '1 hour','local')`, manualLocalSessionID, manualUserID, cryptox.Digest("manual-local-session"), uuid.New(), cryptox.Digest("manual-local-session-two")); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Pool.Exec(ctx, `INSERT INTO sessions(id,user_id,organization_id,oidc_provider_id,token_hash,expires_at,auth_method) VALUES($1,$2,$3,$4,$5,now()+interval '1 hour','oidc')`, manualFederatedSessionID, manualUserID, orgID, manualProviderID, cryptox.Digest("manual-federated-session")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, manualUserID) })
	doSCIMRequest(t, server.URL+"/scim/v2/Users/"+manualUserID.String(), token, http.MethodPatch, map[string]any{"Operations": []map[string]any{{"op": "replace", "path": "active", "value": false}}}, http.StatusNoContent)
	var remainingSessions int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE user_id=$1`, manualUserID).Scan(&remainingSessions); err != nil || remainingSessions != 0 {
		t.Fatalf("SCIM deprovision retained %d interactive sessions: %v", remainingSessions, err)
	}
	manualUser := doSCIMRequest(t, server.URL+"/scim/v2/Users/"+manualUserID.String(), token, http.MethodGet, nil, http.StatusOK)
	if manualUser["active"] != false || manualUser["meta"].(map[string]any)["version"] != `W/"2"` {
		t.Fatalf("deactivated manual member did not retain versioned SCIM ownership: %#v", manualUser)
	}

	// User mutation endpoints are scoped to resources visible in the token's
	// organization. A global user UUID from another tenant cannot be renamed or
	// attached by PATCH.
	doSCIMRequest(t, server.URL+"/scim/v2/Users/"+otherUserID.String(), token, http.MethodPatch, map[string]any{"Operations": []map[string]any{{"op": "replace", "path": "displayName", "value": "Compromised"}}}, http.StatusNotFound)
	doSCIMRequest(t, server.URL+"/scim/v2/Users/"+otherUserID.String(), token, http.MethodPatch, map[string]any{"Operations": []map[string]any{{"op": "replace", "path": "active", "value": true}}}, http.StatusNotFound)
	doSCIMRequest(t, server.URL+"/scim/v2/Users/"+otherUserID.String(), token, http.MethodPut, map[string]any{"userName": "compromised@example.test", "active": true}, http.StatusNotFound)
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

	groupExternalID := "directory-group-" + uuid.NewString()
	group, groupHeaders := doSCIMRequestWithHeaders(t, server.URL+"/scim/v2/Groups", token, http.MethodPost, map[string]any{"externalId": groupExternalID, "displayName": "Engineering", "role": "admin", "members": []map[string]string{{"value": memberID}}}, http.StatusCreated, nil)
	groupID := group["id"].(string)
	groupMeta := group["meta"].(map[string]any)
	if groupHeaders.Get("ETag") != `W/"1"` || groupMeta["version"] != groupHeaders.Get("ETag") || groupMeta["created"] == "" || groupMeta["lastModified"] == "" {
		t.Fatalf("created SCIM group metadata=%#v headers=%v", group["meta"], groupHeaders)
	}
	groupMatch := doSCIMRequest(t, server.URL+`/scim/v2/Groups?filter=externalId%20eq%20%22`+groupExternalID+`%22`, token, http.MethodGet, nil, http.StatusOK)
	if groupMatch["totalResults"] != float64(1) || len(groupMatch["Resources"].([]any)) != 1 {
		t.Fatalf("unexpected group externalId filter response: %#v", groupMatch)
	}
	groupCount := doSCIMRequest(t, server.URL+"/scim/v2/Groups?count=0", token, http.MethodGet, nil, http.StatusOK)
	if groupCount["totalResults"] != float64(1) || groupCount["itemsPerPage"] != float64(0) || len(groupCount["Resources"].([]any)) != 0 {
		t.Fatalf("unexpected group count response: %#v", groupCount)
	}
	var role string
	if err = db.Pool.QueryRow(ctx, `SELECT role FROM memberships WHERE organization_id=$1 AND user_id=$2`, orgID, memberID).Scan(&role); err != nil || role != "admin" {
		t.Fatalf("group role = %q, err = %v", role, err)
	}
	replacedGroupExternalID := "replaced-" + groupExternalID
	replacedGroup, replacedGroupHeaders := doSCIMRequestWithHeaders(t, server.URL+"/scim/v2/Groups/"+groupID, token, http.MethodPut, map[string]any{
		"schemas": []string{scimGroupSchema}, "externalId": replacedGroupExternalID, "displayName": "Platform Engineering",
		"members": []map[string]string{{"value": memberID}},
	}, http.StatusOK, map[string]string{"If-Match": groupHeaders.Get("ETag")})
	if replacedGroup["externalId"] != replacedGroupExternalID || replacedGroup["displayName"] != "Platform Engineering" || replacedGroup["role"] != "admin" || len(replacedGroup["members"].([]any)) != 1 {
		t.Fatalf("SCIM group replacement was not persisted: %#v", replacedGroup)
	}
	doSCIMRequestWithHeaders(t, server.URL+"/scim/v2/Groups/"+groupID, token, http.MethodPatch, map[string]any{"Operations": []map[string]any{{"op": "replace", "path": "displayName", "value": "Stale update"}}}, http.StatusPreconditionFailed, map[string]string{"If-Match": groupHeaders.Get("ETag")})
	if replacedGroupHeaders.Get("ETag") == groupHeaders.Get("ETag") || replacedGroup["meta"].(map[string]any)["version"] != replacedGroupHeaders.Get("ETag") {
		t.Fatalf("SCIM group replacement did not advance version: body=%#v headers=%v", replacedGroup, replacedGroupHeaders)
	}
	groupExternalID = replacedGroupExternalID
	updatedGroupExternalID := "updated-" + groupExternalID
	doSCIMRequest(t, server.URL+"/scim/v2/Groups/"+groupID, token, http.MethodPatch, map[string]any{"Operations": []map[string]any{{"op": "replace", "value": map[string]any{
		"displayName": "Runtime Engineering", "externalId": updatedGroupExternalID, "role": "developer", "members": []map[string]string{{"value": memberID}},
	}}}}, http.StatusNoContent)
	groupMatch = doSCIMRequest(t, server.URL+`/scim/v2/Groups?filter=externalId%20eq%20%22`+updatedGroupExternalID+`%22`, token, http.MethodGet, nil, http.StatusOK)
	if groupMatch["totalResults"] != float64(1) {
		t.Fatalf("updated group externalId cannot be resolved: %#v", groupMatch)
	}
	doSCIMRequest(t, server.URL+"/scim/v2/Groups/"+groupID, token, http.MethodPatch, map[string]any{"Operations": []map[string]any{{"op": "replace", "path": "displayName", "value": strings.Repeat("x", 121)}}}, http.StatusBadRequest)
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
	if err = db.Pool.QueryRow(ctx, `SELECT display_name FROM users WHERE id=$1`, memberID).Scan(&memberName); err != nil || memberName != "Replaced Member" {
		t.Fatalf("shared display name = %q, err = %v", memberName, err)
	}

	// Inactive SCIM resources retain their organization-scoped binding so the
	// identity provider can query and reactivate them without a global lookup.
	inactiveUserName := "inactive-" + orgID.String() + "@example.test"
	inactive := doSCIMRequest(t, server.URL+"/scim/v2/Users", token, http.MethodPost, map[string]any{"userName": inactiveUserName, "displayName": "Inactive", "active": false}, http.StatusCreated)
	inactiveID := inactive["id"].(string)
	t.Cleanup(func() { _, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, inactiveID) })
	loaded := doSCIMRequest(t, server.URL+"/scim/v2/Users/"+inactiveID, token, http.MethodGet, nil, http.StatusOK)
	if active, _ := loaded["active"].(bool); active {
		t.Fatal("new inactive SCIM user is active")
	}
	doSCIMRequest(t, server.URL+"/scim/v2/Users/"+inactiveID, token, http.MethodPut, map[string]any{"userName": inactiveUserName, "displayName": "Inactive", "active": true}, http.StatusOK)
	if err = db.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM memberships WHERE organization_id=$1 AND user_id=$2)`, orgID, inactiveID).Scan(&attached); err != nil || !attached {
		t.Fatalf("inactive user reactivated = %v, err = %v", attached, err)
	}
	inactiveUUID := uuid.MustParse(inactiveID)
	if _, err = db.Pool.Exec(ctx, `INSERT INTO sessions(id,user_id,token_hash,expires_at,auth_method) VALUES($1,$2,$3,now()+interval '1 hour','local')`, uuid.New(), inactiveUUID, cryptox.Digest("inactive-put-session")); err != nil {
		t.Fatal(err)
	}
	doSCIMRequest(t, server.URL+"/scim/v2/Users/"+inactiveID, token, http.MethodPut, map[string]any{"userName": inactiveUserName, "displayName": "Inactive", "active": false}, http.StatusOK)
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE user_id=$1`, inactiveUUID).Scan(&remainingSessions); err != nil || remainingSessions != 0 {
		t.Fatalf("SCIM replacement deprovision retained %d interactive sessions: %v", remainingSessions, err)
	}
	loaded = doSCIMRequest(t, server.URL+"/scim/v2/Users/"+inactiveID, token, http.MethodGet, nil, http.StatusOK)
	if active, _ := loaded["active"].(bool); active {
		t.Fatal("deprovisioned SCIM user is active")
	}
	if _, err = db.Pool.Exec(ctx, `INSERT INTO sessions(id,user_id,token_hash,expires_at,auth_method) VALUES($1,$2,$3,now()+interval '1 hour','local')`, uuid.New(), inactiveUUID, cryptox.Digest("inactive-delete-session")); err != nil {
		t.Fatal(err)
	}
	doSCIMRequest(t, server.URL+"/scim/v2/Users/"+inactiveID, token, http.MethodDelete, nil, http.StatusNoContent)
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE user_id=$1`, inactiveUUID).Scan(&remainingSessions); err != nil || remainingSessions != 0 {
		t.Fatalf("SCIM delete retained %d interactive sessions: %v", remainingSessions, err)
	}
	doSCIMRequest(t, server.URL+"/scim/v2/Users/"+inactiveID, token, http.MethodGet, nil, http.StatusNotFound)
	var tombstoned bool
	if err = db.Pool.QueryRow(ctx, `SELECT deleted_at IS NOT NULL FROM scim_user_defaults WHERE organization_id=$1 AND user_id=$2`, orgID, inactiveID).Scan(&tombstoned); err != nil || !tombstoned {
		t.Fatalf("deleted inactive user tombstone = %v, err = %v", tombstoned, err)
	}
	federatedProvider, err := db.GetOIDCProvider(ctx, manualProviderID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.JITOIDCUser(ctx, federatedProvider, "deleted-scim-subject", inactiveUserName, "Deleted SCIM User"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("federated login after SCIM delete error=%v, want ErrNotFound", err)
	}
	recreated := doSCIMRequest(t, server.URL+"/scim/v2/Users", token, http.MethodPost, map[string]any{"userName": inactiveUserName, "displayName": "Recreated", "active": true}, http.StatusCreated)
	if recreated["id"] != inactiveID {
		t.Fatalf("SCIM recreate changed global identity: got=%v want=%s", recreated["id"], inactiveID)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT deleted_at IS NULL FROM scim_user_defaults WHERE organization_id=$1 AND user_id=$2`, orgID, inactiveID).Scan(&attached); err != nil || !attached {
		t.Fatalf("SCIM recreate cleared tombstone = %v, err = %v", attached, err)
	}
	if loggedInID, loginErr := db.JITOIDCUser(ctx, federatedProvider, "deleted-scim-subject", inactiveUserName, "Recreated"); loginErr != nil || loggedInID != inactiveUUID {
		t.Fatalf("federated login after SCIM recreate user=%s err=%v", loggedInID, loginErr)
	}

	// Organization owners remain outside SCIM deprovisioning authority.
	doSCIMRequest(t, server.URL+"/scim/v2/Users/"+ownerID.String(), token, http.MethodDelete, nil, http.StatusConflict)

	var scimAuditEvents int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND action IN ('scim.user.create','scim.user.replace','scim.user.patch','scim.user.delete','scim.group.create','scim.group.replace','scim.group.patch','scim.group.delete')`, orgID).Scan(&scimAuditEvents); err != nil || scimAuditEvents != 15 {
		t.Fatalf("SCIM audit event count=%d, want 15, err=%v", scimAuditEvents, err)
	}
}

func TestSCIMGroupAddEnforcesPersistedMemberLimit(t *testing.T) {
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

	orgID, groupID := uuid.New(), uuid.New()
	token := "group-limit-" + uuid.NewString()
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'SCIM group limit',$2)`, orgID, "scim-group-limit-"+orgID.String()); err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO users(id,email,password_hash)
			SELECT md5(($1::uuid)::text||':'||n::text)::uuid,n::text||'-'||($1::uuid)::text||'@scim-limit.example.test','!test'
			FROM generate_series(1,$2) AS n`, orgID, scimMaxGroupMembers+1)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role)
			SELECT $1::uuid,md5(($1::uuid)::text||':'||n::text)::uuid,'viewer' FROM generate_series(1,$2) AS n`, orgID, scimMaxGroupMembers+1)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO scim_groups(id,organization_id,display_name,role) VALUES($1,$2,'Bounded group','viewer')`, groupID, orgID)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO scim_group_members(group_id,user_id)
			SELECT $1::uuid,md5(($2::uuid)::text||':'||n::text)::uuid FROM generate_series(1,$3) AS n`, groupID, orgID, scimMaxGroupMembers)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO scim_tokens(id,organization_id,name,token_hash,default_role) VALUES($1,$2,'group-limit',$3,'viewer')`, uuid.New(), orgID, cryptox.Digest(token))
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, orgID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE email LIKE $1`, "%-"+orgID.String()+"@scim-limit.example.test")
	})

	var extraUserID uuid.UUID
	if err = db.Pool.QueryRow(ctx, `SELECT md5(($1::uuid)::text||':'||($2::int)::text)::uuid`, orgID, scimMaxGroupMembers+1).Scan(&extraUserID); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer((&Server{Store: db, PublicURL: "http://example.test", Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler())
	defer server.Close()
	doSCIMRequest(t, server.URL+"/scim/v2/Groups/"+groupID.String(), token, http.MethodPatch, map[string]any{
		"Operations": []map[string]any{{"op": "add", "path": "members", "value": []map[string]string{{"value": extraUserID.String()}}}},
	}, http.StatusBadRequest)
	var persistedCount int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM scim_group_members WHERE group_id=$1`, groupID).Scan(&persistedCount); err != nil || persistedCount != scimMaxGroupMembers {
		t.Fatalf("persisted group member count=%d, want %d, err=%v", persistedCount, scimMaxGroupMembers, err)
	}
}

func doSCIMRequest(t *testing.T, url, token, method string, body any, wantStatus int) map[string]any {
	t.Helper()
	result, _ := doSCIMRequestWithHeaders(t, url, token, method, body, wantStatus, nil)
	return result
}

func doSCIMRequestWithHeaders(t *testing.T, url, token, method string, body any, wantStatus int, headers map[string]string) (map[string]any, http.Header) {
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
	for name, value := range headers {
		req.Header.Set(name, value)
	}
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
		return nil, response.Header.Clone()
	}
	if contentType := response.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "application/scim+json") {
		t.Fatalf("SCIM Content-Type = %q", contentType)
	}
	var result map[string]any
	if err = json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result, response.Header.Clone()
}
