package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func TestOIDCStartPersistsNonceAndPKCE(t *testing.T) {
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

	var issuer string
	idp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/authorize",
			"token_endpoint":                        issuer + "/token",
			"jwks_uri":                              issuer + "/keys",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	}))
	defer idp.Close()
	issuer = idp.URL
	previousTransport := http.DefaultTransport
	http.DefaultTransport = idp.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = previousTransport })

	organizationID, providerID := uuid.New(), uuid.New()
	if _, err = db.Pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'OIDC API',$2)`, organizationID, "oidc-api-"+organizationID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	})
	if _, err = db.CreateOIDCProvider(ctx, store.OIDCProvider{ID: providerID, OrganizationID: organizationID, Name: "workforce", Issuer: issuer, ClientID: "dockyard", EncryptedClientSecret: "unused", Domains: []string{"example.test"}, Scopes: []string{"openid", "email"}, DefaultRole: "developer"}); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer((&Server{Store: db, PublicURL: "https://dockyard.example.test", Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler())
	defer server.Close()
	response, err := http.Get(server.URL + "/v1/auth/sso/" + providerID.String() + "/start")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(response.Body)
		t.Fatalf("start status=%d: %s", response.StatusCode, data)
	}
	var started map[string]string
	if err = json.NewDecoder(response.Body).Decode(&started); err != nil {
		t.Fatal(err)
	}
	authorizeURL, err := url.Parse(started["url"])
	if err != nil {
		t.Fatal(err)
	}
	query := authorizeURL.Query()
	if authorizeURL.String() == "" || query.Get("state") == "" || query.Get("nonce") == "" || query.Get("code_challenge") == "" || query.Get("code_challenge_method") != "S256" {
		t.Fatalf("authorization URL lacks state, nonce, or PKCE: %s", authorizeURL)
	}
	var storedNonce string
	if err = db.Pool.QueryRow(ctx, `SELECT nonce FROM oidc_states WHERE token_hash=$1`, cryptox.Digest(query.Get("state"))).Scan(&storedNonce); err != nil {
		t.Fatal(err)
	}
	if storedNonce != query.Get("nonce") {
		t.Fatalf("stored nonce %q does not match authorization nonce %q", storedNonce, query.Get("nonce"))
	}
}
