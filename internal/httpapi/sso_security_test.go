package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/bendahma/dokploy-go/internal/agentpki"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func TestWriteFederatedStateError(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "provider removed or disabled", err: store.ErrNotFound, want: true},
		{name: "provider revision changed", err: store.ErrAuthenticationStateChanged, want: true},
		{name: "wrapped state change", err: fmt.Errorf("issue session: %w", store.ErrAuthenticationStateChanged), want: true},
		{name: "unrelated storage failure", err: errors.New("database unavailable")},
		{name: "success"},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			if got := writeFederatedStateError(recorder, test.err); got != test.want {
				t.Fatalf("handled=%t want=%t", got, test.want)
			}
			if !test.want {
				if recorder.Code != http.StatusOK || recorder.Body.Len() != 0 {
					t.Fatalf("unhandled error wrote status=%d body=%s", recorder.Code, recorder.Body.String())
				}
				return
			}
			if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), `"code":"invalid_state"`) {
				t.Fatalf("state error response status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestNormalizedOIDCIssuer(t *testing.T) {
	got, err := normalizedOIDCIssuer("  https://login.example.test/tenant/  ")
	if err != nil || got != "https://login.example.test/tenant" {
		t.Fatalf("normalized issuer=%q err=%v", got, err)
	}
	for _, invalid := range []string{
		"http://login.example.test", "https://user@login.example.test",
		"https://login.example.test?tenant=one", "https://login.example.test/#fragment",
		"//login.example.test", "https:///missing-host", "https://" + strings.Repeat("a", maxOIDCIssuerBytes),
		"https://bad_label.example.test", "https://-bad.example.test", "https://login.example.test:",
		"https://login.example.test:0", "https://login.example.test:65536", "https://[not-an-ip]",
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
		{"provider\u0085name", "client", "secret"},
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
		{"provider\u0085name", "<metadata/>", "email", "name"},
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

func TestSSODiscoveryRejectsMalformedEmailBeforeStoreAccess(t *testing.T) {
	server := &Server{}
	for _, handler := range []struct {
		name string
		path string
		fn   http.HandlerFunc
	}{
		{name: "oidc", path: "/v1/auth/sso/discover", fn: server.discoverOIDC},
		{name: "saml", path: "/v1/auth/saml/discover", fn: server.discoverSAML},
	} {
		for _, email := range []string{"Display Name <user@example.test>", "user@example.test@attacker.test", strings.Repeat("a", 321)} {
			t.Run(handler.name+"/length-"+fmt.Sprint(len(email)), func(t *testing.T) {
				recorder := httptest.NewRecorder()
				request := httptest.NewRequest(http.MethodGet, handler.path+"?"+url.Values{"email": {email}}.Encode(), nil)
				handler.fn(recorder, request)
				if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), `"code":"invalid_email"`) {
					t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
				}
			})
		}
	}
}

func TestOversizedPublicCredentialsFailBeforeStoreAccess(t *testing.T) {
	server := &Server{}
	oversized := strings.Repeat("x", maxPublicCredentialBytes+1)

	t.Run("deploy token", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/v1/hooks/deploy/oversized", nil)
		request.SetPathValue("token", oversized)
		server.deployWebhook(recorder, request)
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
		}
	})

	t.Run("agent enrollment token", func(t *testing.T) {
		server := &Server{AgentCACertificate: []byte("configured"), AgentCAKey: []byte("configured")}
		body, err := json.Marshal(map[string]string{"token": oversized, "csr": "unused"})
		if err != nil {
			t.Fatal(err)
		}
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/v1/agent/enroll", strings.NewReader(string(body)))
		request.Header.Set("Content-Type", "application/json")
		server.enrollClusterAgent(recorder, request)
		if recorder.Code != http.StatusUnauthorized || !strings.Contains(recorder.Body.String(), `"code":"invalid_enrollment_token"`) {
			t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
		}
	})

	t.Run("agent enrollment csr", func(t *testing.T) {
		server := &Server{AgentCACertificate: []byte("configured"), AgentCAKey: []byte("configured")}
		body, err := json.Marshal(map[string]string{"token": "valid-shape", "csr": strings.Repeat("x", agentpki.MaxCSRPEMBytes+1)})
		if err != nil {
			t.Fatal(err)
		}
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/v1/agent/enroll", strings.NewReader(string(body)))
		request.Header.Set("Content-Type", "application/json")
		server.enrollClusterAgent(recorder, request)
		if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), `"code":"invalid_csr"`) {
			t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
		}
	})

	t.Run("oidc state", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		query := url.Values{"state": {oversized}, "code": {"code"}}
		server.callbackOIDC(recorder, httptest.NewRequest(http.MethodGet, "/v1/auth/sso/callback?"+query.Encode(), nil))
		if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), `"code":"invalid_callback"`) {
			t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
		}
	})

	t.Run("oidc authorization code", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		query := url.Values{"state": {"state"}, "code": {strings.Repeat("c", maxAuthorizationCodeBytes+1)}}
		server.callbackOIDC(recorder, httptest.NewRequest(http.MethodGet, "/v1/auth/sso/callback?"+query.Encode(), nil))
		if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), `"code":"invalid_callback"`) {
			t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
		}
	})

	t.Run("saml relay state", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		body := url.Values{"SAMLResponse": {"unused"}, "RelayState": {oversized}}.Encode()
		request := httptest.NewRequest(http.MethodPost, "/v1/auth/saml/provider/acs", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.SetPathValue("providerID", "f47ac10b-58cc-4372-a567-0e02b2c3d479")
		server.callbackSAML(recorder, request)
		if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), `"code":"invalid_state"`) {
			t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
		}
	})
}

func TestCanonicalDisplayNameBoundsProvisionedProfiles(t *testing.T) {
	if name, ok := canonicalDisplayName("  Example User  "); !ok || name != "Example User" {
		t.Fatalf("canonical display name=%q valid=%t", name, ok)
	}
	if name, ok := canonicalDisplayName(strings.Repeat("a", 121)); ok || name != strings.Repeat("a", 121) {
		t.Fatalf("oversized display name=%q valid=%t", name, ok)
	}
	for _, invalid := range []string{"line\nbreak", "hidden\u0085break", string([]byte{'n', 0xff})} {
		if _, ok := canonicalDisplayName(invalid); ok {
			t.Errorf("invalid display name %q was accepted", invalid)
		}
	}
}

func TestFederatedIdentityKeysAreBounded(t *testing.T) {
	for _, valid := range []string{"subject", strings.Repeat("s", 1024)} {
		if !validFederatedIdentifier(valid) {
			t.Errorf("rejected valid federated identifier of length %d", len(valid))
		}
	}
	for _, invalid := range []string{"", "subject\nother", "subject\u0085other", string([]byte{'s', 0xff}), strings.Repeat("s", 1025)} {
		if validFederatedIdentifier(invalid) {
			t.Errorf("accepted invalid federated identifier %q", invalid)
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
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/known-size" {
			w.Header().Set("Content-Length", "4194305")
			w.WriteHeader(http.StatusOK)
			return
		}
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
	if _, err = server.oidcHTTPClient().Get(provider.URL + "/known-size"); !errors.Is(err, errOIDCResponseTooLarge) {
		t.Fatalf("known oversized response error=%v", err)
	}
}

func TestOIDCClientFailsClosedWithoutConfiguredEgressTransport(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer provider.Close()

	if _, err := (&Server{}).oidcHTTPClient().Get(provider.URL); err == nil || !strings.Contains(err.Error(), "egress policy blocks") {
		t.Fatalf("loopback OIDC request error=%v", err)
	}

	response, err := (&Server{EgressTransport: provider.Client().Transport}).oidcHTTPClient().Get(provider.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status=%d", response.StatusCode)
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
