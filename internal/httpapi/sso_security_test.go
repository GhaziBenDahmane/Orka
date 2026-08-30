package httpapi

import (
	"context"
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
		"//login.example.test", "https:///missing-host",
	} {
		if _, err = normalizedOIDCIssuer(invalid); err == nil {
			t.Errorf("accepted unsafe issuer %q", invalid)
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
