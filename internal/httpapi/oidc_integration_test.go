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

	box, err := cryptox.New(bytes.Repeat([]byte{23}, 32))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer((&Server{Store: db, Box: box, PublicURL: "https://dockyard.example.test", Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler())
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
	cookies := response.Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode || cookies[0].MaxAge <= 0 {
		t.Fatalf("OIDC start did not set a hardened state cookie: %#v", cookies)
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
	updated, err := db.UpdateOIDCProvider(ctx, organizationID, store.OIDCProvider{ID: providerID, Name: "renamed", Issuer: issuer, ClientID: "dockyard-v2", Domains: []string{"example.test"}, Scopes: []string{"openid", "email"}, DefaultRole: "viewer"})
	if err != nil || updated.Name != "renamed" || updated.ClientID != "dockyard-v2" {
		t.Fatalf("provider update = %#v, %v", updated, err)
	}
	var preservedSecret string
	var remainingStates int
	if err = db.Pool.QueryRow(ctx, `SELECT encrypted_client_secret,(SELECT count(*) FROM oidc_states WHERE provider_id=$1) FROM oidc_providers WHERE id=$1`, providerID).Scan(&preservedSecret, &remainingStates); err != nil || preservedSecret != "unused" || remainingStates != 0 {
		t.Fatalf("provider update did not preserve secret and revoke pending states: secret=%q states=%d err=%v", preservedSecret, remainingStates, err)
	}
	if _, err = db.UpdateOIDCProvider(ctx, uuid.New(), store.OIDCProvider{ID: providerID, Name: "cross-tenant", Issuer: issuer, ClientID: "x", Domains: []string{"example.test"}, Scopes: []string{"openid"}, DefaultRole: "viewer"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant provider update error = %v", err)
	}
	if err = db.DisableOIDCProvider(ctx, organizationID, providerID); err != nil {
		t.Fatal(err)
	}
	if err = db.SetOIDCProviderEnabled(ctx, uuid.New(), providerID, true); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant provider enable error = %v", err)
	}
	if err = db.SetOIDCProviderEnabled(ctx, organizationID, providerID, true); err != nil {
		t.Fatal(err)
	}
}

func TestOIDCEmailValidationRejectsMalformedClaims(t *testing.T) {
	for _, value := range []string{"", "missing-at-sign", "Display Name <user@example.test>", "@example.test", "user@"} {
		if _, _, ok := oidcEmail(value); ok {
			t.Fatalf("accepted malformed OIDC email claim %q", value)
		}
	}
	email, domain, ok := oidcEmail("User@Example.Test")
	if !ok || email != "user@example.test" || domain != "example.test" {
		t.Fatalf("valid claim normalized to email=%q domain=%q ok=%v", email, domain, ok)
	}
}

func TestOIDCIdentityClaimsUseProviderCompatibleEmail(t *testing.T) {
	verified := true
	tests := []struct {
		name       string
		claims     oidcIdentityClaims
		wantEmail  string
		wantDomain string
		wantOK     bool
	}{
		{name: "email", claims: oidcIdentityClaims{Email: "User@Example.Test", PreferredUsername: "other@example.test", EmailVerified: &verified}, wantEmail: "user@example.test", wantDomain: "example.test", wantOK: true},
		{name: "entra preferred username", claims: oidcIdentityClaims{PreferredUsername: "User@Contoso.com"}, wantEmail: "user@contoso.com", wantDomain: "contoso.com", wantOK: true},
		{name: "malformed email fails closed", claims: oidcIdentityClaims{Email: "not-an-email", PreferredUsername: "user@example.test"}, wantOK: false},
		{name: "non-email username", claims: oidcIdentityClaims{PreferredUsername: "shortname"}, wantOK: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			email, domain, ok := test.claims.loginEmail()
			if email != test.wantEmail || domain != test.wantDomain || ok != test.wantOK {
				t.Fatalf("loginEmail() = %q, %q, %v; want %q, %q, %v", email, domain, ok, test.wantEmail, test.wantDomain, test.wantOK)
			}
		})
	}
}

func TestLoginStateCookieIsOpaqueAndBrowserBound(t *testing.T) {
	box, err := cryptox.New(bytes.Repeat([]byte{29}, 32))
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Box: box, PublicURL: "https://dockyard.example.test"}
	state := "state-visible-in-callback-url"
	setRecorder := httptest.NewRecorder()
	if err = server.setLoginStateCookie(setRecorder, "oidc", state, http.SameSiteLaxMode); err != nil {
		t.Fatal(err)
	}
	cookies := setRecorder.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Value == state || cookies[0].Value == string(cryptox.Digest(state)) || !cookies[0].Secure || !cookies[0].HttpOnly {
		t.Fatalf("state cookie was not opaque and hardened: %#v", cookies)
	}
	if server.consumeLoginStateCookie(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/auth/sso/callback", nil), "oidc", state, http.SameSiteLaxMode) {
		t.Fatal("callback without the initiating browser cookie was accepted")
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/auth/sso/callback", nil)
	request.AddCookie(cookies[0])
	clearRecorder := httptest.NewRecorder()
	if !server.consumeLoginStateCookie(clearRecorder, request, "oidc", state, http.SameSiteLaxMode) {
		t.Fatal("callback with the initiating browser cookie was rejected")
	}
	cleared := clearRecorder.Result().Cookies()
	if len(cleared) != 1 || cleared[0].MaxAge >= 0 {
		t.Fatalf("state cookie was not cleared: %#v", cleared)
	}
}
