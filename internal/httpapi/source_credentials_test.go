package httpapi

import (
	"net/url"
	"testing"

	"github.com/bendahma/dokploy-go/internal/store"
)

func TestCredentialMatchesRepository(t *testing.T) {
	httpsRepository := mustParseSourceURL(t, "https://git.example.test:8443/acme/app.git")
	sshRepository := mustParseSourceURL(t, "ssh://git@git.example.test:2222/acme/app.git")
	for _, test := range []struct {
		credential  store.SourceCredential
		repository  *url.URL
		kind, fixed string
		want        bool
	}{
		{store.SourceCredential{Kind: "git", Server: "git.example.test:8443"}, httpsRepository, "git", "", true},
		{store.SourceCredential{Kind: "git-ssh", Server: "git.example.test"}, sshRepository, "git-ssh", "", true},
		{store.SourceCredential{Kind: "git", Server: "github.com"}, mustParseSourceURL(t, "https://github.com/acme/app.git"), "git", "github.com", true},
		{store.SourceCredential{Kind: "git", Server: "github.com:443"}, mustParseSourceURL(t, "https://github.com/acme/app.git"), "git", "github.com", false},
		{store.SourceCredential{Kind: "registry", Server: "git.example.test"}, httpsRepository, "git", "", false},
		{store.SourceCredential{Kind: "git", Server: "attacker.example.test"}, httpsRepository, "git", "", false},
		{store.SourceCredential{Kind: "git", Server: "git.example.test/path"}, httpsRepository, "git", "", false},
	} {
		if got := credentialMatchesRepository(test.credential, test.repository, test.kind, test.fixed); got != test.want {
			t.Errorf("credentialMatchesRepository(%#v, %s, %q, %q) = %t, want %t", test.credential, test.repository, test.kind, test.fixed, got, test.want)
		}
	}
}

func mustParseSourceURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
