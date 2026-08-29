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
	"sync"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func TestOrganizationInvitationLifecycle(t *testing.T) {
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
	organizationID, otherOrganizationID := uuid.New(), uuid.New()
	ownerID, adminID, existingID, otherOwnerID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	ownerToken, adminToken, otherOwnerToken := "owner-"+uuid.NewString(), "admin-"+uuid.NewString(), "other-owner-"+uuid.NewString()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Invitations',$2),($3,'Other',$4)`, []any{organizationID, "invitations-" + organizationID.String(), otherOrganizationID, "other-invitations-" + otherOrganizationID.String()}},
		{`INSERT INTO users(id,email,password_hash,display_name) VALUES($1,$2,'x','Owner'),($3,$4,'x','Admin'),($5,$6,'x','Existing'),($7,$8,'x','Other owner')`, []any{ownerID, ownerID.String() + "@example.test", adminID, adminID.String() + "@example.test", existingID, existingID.String() + "@example.test", otherOwnerID, otherOwnerID.String() + "@example.test"}},
		{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner'),($1,$3,'admin'),($4,$5,'owner')`, []any{organizationID, ownerID, adminID, otherOrganizationID, otherOwnerID}},
		{`INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '1 hour'),($4,$5,$6,now()+interval '1 hour'),($7,$8,$9,now()+interval '1 hour')`, []any{uuid.New(), ownerID, cryptox.Digest(ownerToken), uuid.New(), adminID, cryptox.Digest(adminToken), uuid.New(), otherOwnerID, cryptox.Digest(otherOwnerToken)}},
		{`INSERT INTO organization_auth_settings(organization_id,require_sso) VALUES($1,true)`, []any{otherOrganizationID}},
	} {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id IN ($1,$2)`, organizationID, otherOrganizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE email LIKE $1`, "%@invite.test")
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=ANY($1)`, []uuid.UUID{ownerID, adminID, existingID, otherOwnerID})
	})

	server := httptest.NewServer((&Server{Store: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), SessionTTL: time.Hour, PublicURL: "https://dockyard.example.test"}).Handler())
	defer server.Close()
	invitationsURL := server.URL + "/v1/invitations"
	if status, _ := scopedAPIRequest(t, invitationsURL, adminToken, organizationID, http.MethodPost, map[string]any{"email": "owner@invite.test", "role": "owner"}); status != http.StatusForbidden {
		t.Fatalf("admin owner invitation status=%d, want 403", status)
	}
	if status, _ := scopedAPIRequest(t, invitationsURL, ownerToken, organizationID, http.MethodPost, map[string]any{"email": ownerID.String() + "@example.test", "role": "viewer"}); status != http.StatusConflict {
		t.Fatalf("existing member invitation status=%d, want 409", status)
	}

	status, body := scopedAPIRequest(t, invitationsURL, adminToken, organizationID, http.MethodPost, map[string]any{"email": "new-local@invite.test", "role": "developer", "expiresInDays": 3})
	var created struct {
		Invitation store.OrganizationInvitation `json:"invitation"`
		Token      string                       `json:"token"`
		AcceptURL  string                       `json:"acceptUrl"`
	}
	if err = json.Unmarshal(body, &created); err != nil || status != http.StatusCreated || !strings.HasPrefix(created.Token, "dky_inv_") || !strings.Contains(created.AcceptURL, "#invitation=") {
		t.Fatalf("create invitation status=%d response=%#v err=%v body=%s", status, created, err, body)
	}
	status, body = scopedAPIRequest(t, invitationsURL, adminToken, organizationID, http.MethodGet, nil)
	if status != http.StatusOK || bytes.Contains(body, []byte(created.Token)) {
		t.Fatalf("invitation list status=%d leaked token=%v body=%s", status, bytes.Contains(body, []byte(created.Token)), body)
	}
	if status, _ = apiRequest(t, server.URL+"/v1/invitations/accept", http.MethodPost, map[string]string{"token": created.Token}); status != http.StatusBadRequest {
		t.Fatalf("passwordless local acceptance status=%d, want 400", status)
	}
	if status, _ = apiRequest(t, server.URL+"/v1/invitations/accept", http.MethodPost, map[string]string{"token": created.Token, "password": "short"}); status != http.StatusBadRequest {
		t.Fatalf("weak-password acceptance status=%d, want 400", status)
	}
	status, body = apiRequest(t, server.URL+"/v1/invitations/accept", http.MethodPost, map[string]string{"token": created.Token, "password": "a-secure-invite-password", "displayName": "New Local"})
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"role":"developer"`)) || !bytes.Contains(body, []byte(`"requireSso":false`)) {
		t.Fatalf("local acceptance status=%d body=%s", status, body)
	}
	if status, _ = apiRequest(t, server.URL+"/v1/invitations/accept", http.MethodPost, map[string]string{"token": created.Token, "password": "a-secure-invite-password"}); status != http.StatusNotFound {
		t.Fatalf("replayed acceptance status=%d, want 404", status)
	}
	if status, _ = apiRequest(t, server.URL+"/v1/auth/login", http.MethodPost, map[string]string{"email": "new-local@invite.test", "password": "a-secure-invite-password"}); status != http.StatusOK {
		t.Fatalf("invited local login status=%d, want 200", status)
	}
	existingToken := "dky_inv_existing-test-token-012345678901234"
	if _, err = db.CreateOrganizationInvitation(ctx, organizationID, ownerID, existingID.String()+"@example.test", "viewer", "owner", cryptox.Digest(existingToken), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if status, body = apiRequest(t, server.URL+"/v1/invitations/accept", http.MethodPost, map[string]string{"token": existingToken}); status != http.StatusOK || !bytes.Contains(body, []byte(existingID.String())) {
		t.Fatalf("existing-user acceptance status=%d body=%s", status, body)
	}
	var retainedHash string
	if err = db.Pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE id=$1`, existingID).Scan(&retainedHash); err != nil || retainedHash != "x" {
		t.Fatalf("existing user credentials changed hash=%q err=%v", retainedHash, err)
	}

	ssoInvitation, err := db.CreateOrganizationInvitation(ctx, otherOrganizationID, ownerID, "new-sso@invite.test", "viewer", "owner", cryptox.Digest("dky_inv_sso-test-token-012345678901234567890"), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	status, body = apiRequest(t, server.URL+"/v1/invitations/accept", http.MethodPost, map[string]string{"token": "dky_inv_sso-test-token-012345678901234567890", "displayName": "New SSO", "password": "should-not-become-a-local-password"})
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"requireSso":true`)) {
		t.Fatalf("SSO acceptance status=%d body=%s", status, body)
	}
	var ssoMemberships int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.organization_id=$1 AND u.email='new-sso@invite.test' AND m.role='viewer'`, otherOrganizationID).Scan(&ssoMemberships); err != nil || ssoMemberships != 1 {
		t.Fatalf("SSO invitation membership count=%d err=%v invitation=%s", ssoMemberships, err, ssoInvitation.ID)
	}
	var ssoPasswordHash string
	if err = db.Pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE email='new-sso@invite.test'`).Scan(&ssoPasswordHash); err != nil || !strings.HasPrefix(ssoPasswordHash, "!invite:") {
		t.Fatalf("SSO invitation created a local credential hash=%q err=%v", ssoPasswordHash, err)
	}

	revoked, err := db.CreateOrganizationInvitation(ctx, organizationID, ownerID, "revoked@invite.test", "viewer", "owner", cryptox.Digest("dky_inv_revoked-test-token-0123456789012345"), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if status, _ = scopedAPIRequest(t, invitationsURL+"/"+revoked.ID.String(), otherOwnerToken, otherOrganizationID, http.MethodDelete, nil); status != http.StatusNotFound {
		t.Fatalf("cross-tenant revocation status=%d, want 404", status)
	}
	if status, _ = scopedAPIRequest(t, invitationsURL+"/"+revoked.ID.String(), adminToken, organizationID, http.MethodDelete, nil); status != http.StatusNoContent {
		t.Fatalf("revocation status=%d, want 204", status)
	}
	if status, _ = apiRequest(t, server.URL+"/v1/invitations/accept", http.MethodPost, map[string]string{"token": "dky_inv_revoked-test-token-0123456789012345"}); status != http.StatusNotFound {
		t.Fatalf("revoked acceptance status=%d, want 404", status)
	}

	t.Run("concurrent acceptance is exactly once", func(t *testing.T) {
		token := "dky_inv_concurrent-accept-012345678901234567890"
		if _, createErr := db.CreateOrganizationInvitation(ctx, otherOrganizationID, otherOwnerID, "accept-race@invite.test", "developer", "owner", cryptox.Digest(token), time.Now().Add(time.Hour)); createErr != nil {
			t.Fatal(createErr)
		}
		start := make(chan struct{})
		results := make(chan error, 2)
		var group sync.WaitGroup
		for range 2 {
			group.Add(1)
			go func() {
				defer group.Done()
				<-start
				_, acceptErr := db.AcceptOrganizationInvitation(ctx, cryptox.Digest(token), "Race User", "")
				results <- acceptErr
			}()
		}
		close(start)
		group.Wait()
		close(results)
		succeeded, rejected := 0, 0
		for acceptErr := range results {
			switch {
			case acceptErr == nil:
				succeeded++
			case errors.Is(acceptErr, store.ErrNotFound):
				rejected++
			default:
				t.Fatalf("unexpected concurrent acceptance error: %v", acceptErr)
			}
		}
		if succeeded != 1 || rejected != 1 {
			t.Fatalf("concurrent acceptance succeeded=%d rejected=%d", succeeded, rejected)
		}
	})

	t.Run("concurrent replacement leaves one usable token", func(t *testing.T) {
		email := "create-race@invite.test"
		tokens := []string{"dky_inv_create-race-a-012345678901234567890", "dky_inv_create-race-b-012345678901234567890"}
		start := make(chan struct{})
		results := make(chan error, len(tokens))
		var group sync.WaitGroup
		for _, token := range tokens {
			token := token
			group.Add(1)
			go func() {
				defer group.Done()
				<-start
				_, createErr := db.CreateOrganizationInvitation(ctx, otherOrganizationID, otherOwnerID, email, "viewer", "owner", cryptox.Digest(token), time.Now().Add(time.Hour))
				results <- createErr
			}()
		}
		close(start)
		group.Wait()
		close(results)
		for createErr := range results {
			if createErr != nil {
				t.Fatalf("concurrent invitation creation failed: %v", createErr)
			}
		}
		var pending int
		if queryErr := db.Pool.QueryRow(ctx, `SELECT count(*) FROM organization_invitations WHERE organization_id=$1 AND email=$2 AND accepted_at IS NULL AND revoked_at IS NULL`, otherOrganizationID, email).Scan(&pending); queryErr != nil || pending != 1 {
			t.Fatalf("pending replacement invitations=%d err=%v", pending, queryErr)
		}
		succeeded, rejected := 0, 0
		for _, token := range tokens {
			_, acceptErr := db.AcceptOrganizationInvitation(ctx, cryptox.Digest(token), "Replacement Race", "")
			if acceptErr == nil {
				succeeded++
			} else if errors.Is(acceptErr, store.ErrNotFound) {
				rejected++
			} else {
				t.Fatalf("replacement token acceptance failed: %v", acceptErr)
			}
		}
		if succeeded != 1 || rejected != 1 {
			t.Fatalf("replacement token outcomes succeeded=%d rejected=%d", succeeded, rejected)
		}
	})

	t.Run("accept and revoke have one terminal outcome", func(t *testing.T) {
		token := "dky_inv_revoke-race-012345678901234567890"
		invitation, createErr := db.CreateOrganizationInvitation(ctx, otherOrganizationID, otherOwnerID, "revoke-race@invite.test", "viewer", "owner", cryptox.Digest(token), time.Now().Add(time.Hour))
		if createErr != nil {
			t.Fatal(createErr)
		}
		start := make(chan struct{})
		acceptResult := make(chan error, 1)
		revokeResult := make(chan error, 1)
		go func() {
			<-start
			_, acceptErr := db.AcceptOrganizationInvitation(ctx, cryptox.Digest(token), "Revoke Race", "")
			acceptResult <- acceptErr
		}()
		go func() {
			<-start
			revokeResult <- db.RevokeOrganizationInvitation(ctx, otherOrganizationID, invitation.ID)
		}()
		close(start)
		acceptErr, revokeErr := <-acceptResult, <-revokeResult
		if !((acceptErr == nil && errors.Is(revokeErr, store.ErrNotFound)) || (revokeErr == nil && errors.Is(acceptErr, store.ErrNotFound))) {
			t.Fatalf("accept/revoke outcomes accept=%v revoke=%v", acceptErr, revokeErr)
		}
		var accepted, revoked bool
		if queryErr := db.Pool.QueryRow(ctx, `SELECT accepted_at IS NOT NULL,revoked_at IS NOT NULL FROM organization_invitations WHERE id=$1`, invitation.ID).Scan(&accepted, &revoked); queryErr != nil || accepted == revoked {
			t.Fatalf("terminal invitation state accepted=%v revoked=%v err=%v", accepted, revoked, queryErr)
		}
	})
}

func apiRequest(t *testing.T, endpoint, method string, value any) (int, []byte) {
	t.Helper()
	var payload io.Reader
	if value != nil {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		payload = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, endpoint, payload)
	if err != nil {
		t.Fatal(err)
	}
	if value != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return response.StatusCode, body
}
