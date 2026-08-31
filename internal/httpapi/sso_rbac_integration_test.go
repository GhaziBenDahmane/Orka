package httpapi

import (
	"context"
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

func TestSSOTrustConfigurationRequiresOwner(t *testing.T) {
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

	organizationID, ownerID, adminID := uuid.New(), uuid.New(), uuid.New()
	ownerToken, adminToken := "sso-owner-"+uuid.NewString(), "sso-admin-"+uuid.NewString()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'SSO RBAC',$2)`, []any{organizationID, "sso-rbac-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test'),($3,$4,'!test')`, []any{ownerID, ownerID.String() + "@example.test", adminID, adminID.String() + "@example.test"}},
		{`INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner'),($1,$3,'admin')`, []any{organizationID, ownerID, adminID}},
		{`INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '1 hour'),($4,$5,$6,now()+interval '1 hour')`, []any{uuid.New(), ownerID, cryptox.Digest(ownerToken), uuid.New(), adminID, cryptox.Digest(adminToken)}},
	} {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id IN ($1,$2)`, ownerID, adminID)
	})

	server := httptest.NewServer((&Server{Store: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler())
	defer server.Close()
	randomID := uuid.NewString()
	mutations := []struct {
		method string
		path   string
	}{
		{http.MethodPut, "/v1/sso/settings"},
		{http.MethodPost, "/v1/sso/oidc-providers"},
		{http.MethodPut, "/v1/sso/oidc-providers/" + randomID},
		{http.MethodPost, "/v1/sso/oidc-providers/" + randomID + "/enable"},
		{http.MethodDelete, "/v1/sso/oidc-providers/" + randomID},
		{http.MethodPost, "/v1/sso/saml-providers"},
		{http.MethodPut, "/v1/sso/saml-providers/" + randomID},
		{http.MethodPost, "/v1/sso/saml-providers/" + randomID + "/enable"},
		{http.MethodPost, "/v1/sso/saml-providers/" + randomID + "/certificate-rotation"},
		{http.MethodPost, "/v1/sso/saml-providers/" + randomID + "/certificate-rotation/promote"},
		{http.MethodDelete, "/v1/sso/saml-providers/" + randomID + "/certificate-rotation"},
		{http.MethodDelete, "/v1/sso/saml-providers/" + randomID},
	}
	for _, mutation := range mutations {
		name := mutation.method + " " + mutation.path
		t.Run(name, func(t *testing.T) {
			if status, _ := scopedAPIRequest(t, server.URL+mutation.path, adminToken, organizationID, mutation.method, map[string]any{}); status != http.StatusForbidden {
				t.Fatalf("admin mutation status=%d, want 403", status)
			}
			if status, _ := scopedAPIRequest(t, server.URL+mutation.path, ownerToken, organizationID, mutation.method, map[string]any{}); status == http.StatusForbidden || status == http.StatusUnauthorized {
				t.Fatalf("owner mutation stopped by authorization: status=%d", status)
			}
		})
	}

	for _, path := range []string{"/v1/sso/settings", "/v1/sso/oidc-providers", "/v1/sso/saml-providers"} {
		if status, body := scopedAPIRequest(t, server.URL+path, adminToken, organizationID, http.MethodGet, nil); status != http.StatusOK {
			t.Fatalf("admin read %s status=%d body=%s", path, status, body)
		}
	}
}
