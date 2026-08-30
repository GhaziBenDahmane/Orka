package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func TestNormalizedOIDCIssuer(t *testing.T) {
	got, err := normalizedOIDCIssuer("  https://login.example.test/tenant/  ")
	if err != nil || got != "https://login.example.test/tenant" {
		t.Fatalf("normalized issuer=%q err=%v", got, err)
	}
	for _, invalid := range []string{
		"http://login.example.test", "https://user@login.example.test",
		"https://login.example.test?tenant=one", "https://login.example.test/#fragment",
		"//login.example.test", "https:///missing-host", "https://" + strings.Repeat("a", maxOIDCIssuerBytes),
	} {
		if _, err = normalizedOIDCIssuer(invalid); err == nil {
			t.Errorf("accepted unsafe issuer %q", invalid)
		}
	}
}

func TestNormalizeOIDCScopes(t *testing.T) {
	got, err := normalizeOIDCScopes([]string{" openid ", "email", "email"})
	if err != nil || len(got) != 2 || got[0] != "openid" || got[1] != "email" {
		t.Fatalf("normalized scopes=%v err=%v", got, err)
	}
	for _, invalid := range [][]string{
		{}, {"profile"}, {"openid profile"}, {"openid", "bad\\scope"},
		append([]string{"openid"}, make([]string, maxOIDCScopes)...),
		{"openid", strings.Repeat("a", maxOIDCScopeBytes+1)},
	} {
		if _, err = normalizeOIDCScopes(invalid); err == nil {
			t.Errorf("accepted invalid scopes %#v", invalid)
		}
	}
}

func TestOIDCProviderFieldsAreBounded(t *testing.T) {
	if !validOIDCProviderFields("workforce", "client", "secret") || !validOIDCProviderFields("workforce", "client", "") {
		t.Fatal("valid OIDC provider fields rejected")
	}
	for _, input := range []struct{ name, clientID, secret string }{
		{"", "client", "secret"},
		{strings.Repeat("n", maxSSOProviderName+1), "client", "secret"},
		{"workforce", strings.Repeat("c", maxOIDCClientIDBytes+1), "secret"},
		{"workforce", "client", strings.Repeat("s", maxOIDCSecretBytes+1)},
	} {
		if validOIDCProviderFields(input.name, input.clientID, input.secret) {
			t.Errorf("accepted invalid OIDC provider fields with lengths name=%d client=%d secret=%d", len(input.name), len(input.clientID), len(input.secret))
		}
	}
}

func TestSAMLProviderFieldsAreBounded(t *testing.T) {
	if !validSAMLProviderFields("workforce", "<metadata/>", "email", "displayName") {
		t.Fatal("valid SAML provider fields rejected")
	}
	for _, input := range []struct{ name, metadata, emailAttribute, nameAttribute string }{
		{strings.Repeat("n", maxSSOProviderName+1), "<metadata/>", "email", "name"},
		{"workforce", strings.Repeat("x", maxSAMLMetadataBytes+1), "email", "name"},
		{"workforce", "<metadata/>", strings.Repeat("e", maxSAMLAttributeBytes+1), "name"},
		{"workforce", "<metadata/>", " email", "name"},
		{"workforce", "<metadata/>", "email", "name\nclaim"},
	} {
		if validSAMLProviderFields(input.name, input.metadata, input.emailAttribute, input.nameAttribute) {
			t.Errorf("accepted invalid SAML provider fields: %#v", input)
		}
	}
}

func TestCanonicalEmailIsSharedAcrossIdentityProviders(t *testing.T) {
	email, domain, ok := canonicalEmail("  User.Name+tag@Example.TEST  ")
	if !ok || email != "user.name+tag@example.test" || domain != "example.test" {
		t.Fatalf("canonical email=%q domain=%q valid=%t", email, domain, ok)
	}
	for _, invalid := range []string{
		"", "missing-at-sign", "Display Name <user@example.test>", "@example.test", "user@",
		"user@example.test@attacker.test", strings.Repeat("a", 309) + "@example.test",
	} {
		if email, domain, ok = canonicalEmail(invalid); ok || email != "" || domain != "" {
			t.Errorf("accepted non-canonical email %q as %q domain %q", invalid, email, domain)
		}
	}
}

func TestCanonicalDisplayNameBoundsProvisionedProfiles(t *testing.T) {
	if name, ok := canonicalDisplayName("  Example User  "); !ok || name != "Example User" {
		t.Fatalf("canonical display name=%q valid=%t", name, ok)
	}
	if name, ok := canonicalDisplayName(strings.Repeat("a", 121)); ok || name != strings.Repeat("a", 121) {
		t.Fatalf("oversized display name=%q valid=%t", name, ok)
	}
}

func TestFederatedIdentityKeysAreBounded(t *testing.T) {
	for _, valid := range []string{"subject", strings.Repeat("s", 1024)} {
		if !validFederatedIdentifier(valid) {
			t.Errorf("rejected valid federated identifier of length %d", len(valid))
		}
	}
	for _, invalid := range []string{"", strings.Repeat("s", 1025)} {
		if validFederatedIdentifier(invalid) {
			t.Errorf("accepted invalid federated identifier of length %d", len(invalid))
		}
	}
}

func TestOIDCClientRefusesDiscoveryAndTokenRedirects(t *testing.T) {
	targetRequests := 0
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetRequests++
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	server := &Server{OIDCHTTPClient: redirect.Client()}

	ctx := oidc.ClientContext(context.Background(), server.oidcHTTPClient())
	if _, err := oidc.NewProvider(ctx, redirect.URL); err == nil || !strings.Contains(err.Error(), "redirects are disabled") {
		t.Fatalf("discovery redirect error=%v", err)
	}
	config := oauth2.Config{
		ClientID: "client", ClientSecret: "client-secret",
		Endpoint: oauth2.Endpoint{TokenURL: redirect.URL},
	}
	if _, err := config.Exchange(ctx, "authorization-code"); err == nil || !strings.Contains(err.Error(), "redirects are disabled") {
		t.Fatalf("token redirect error=%v", err)
	}
	if targetRequests != 0 {
		t.Fatalf("redirect target received %d OIDC request(s)", targetRequests)
	}
}

func TestOIDCClientBoundsProviderResponses(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", maxOIDCResponseBytes+1))
	}))
	defer provider.Close()
	server := &Server{OIDCHTTPClient: provider.Client()}
	response, err := server.oidcHTTPClient().Get(provider.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if _, err = io.ReadAll(response.Body); !errors.Is(err, errOIDCResponseTooLarge) {
		t.Fatalf("oversized response error=%v", err)
	}
}

func TestValidateOIDCProviderEndpoints(t *testing.T) {
	var issuer string
	providerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": issuer, "authorization_endpoint": "https://login.example.test/authorize",
			"token_endpoint": "https://login.example.test/token", "jwks_uri": "https://keys.example.test/jwks",
			"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	}))
	defer providerServer.Close()
	issuer = providerServer.URL
	provider, err := oidc.NewProvider(context.Background(), issuer)
	if err != nil {
		t.Fatal(err)
	}
	if err = validateOIDCProviderEndpoints(provider); err != nil {
		t.Fatal(err)
	}

	unsafeProviderServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": issuer, "authorization_endpoint": "https://login.example.test/authorize",
			"token_endpoint": "http://login.example.test/token", "jwks_uri": "https://keys.example.test/jwks",
			"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	}))
	defer unsafeProviderServer.Close()
	issuer = unsafeProviderServer.URL
	provider, err = oidc.NewProvider(context.Background(), issuer)
	if err != nil {
		t.Fatal(err)
	}
	if err = validateOIDCProviderEndpoints(provider); err == nil || !strings.Contains(err.Error(), "token_endpoint") {
		t.Fatalf("unsafe endpoint error=%v", err)
	}
}
