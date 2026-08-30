package httpapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/url"
	"strings"
	"testing"

	"github.com/bendahma/dokploy-go/internal/store"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
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
		{store.SourceCredential{Kind: "git-ssh", Server: "git.example.test:2222"}, sshRepository, "git-ssh", "", true},
		{store.SourceCredential{Kind: "git-ssh", Server: "git.example.test"}, sshRepository, "git-ssh", "", false},
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

func TestValidKnownHostsBindsParsedKeysToExactAuthority(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	keyText := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	if !validKnownHosts("git.example.test", "git.example.test "+keyText) {
		t.Fatal("exact default-port host key was rejected")
	}
	if !validKnownHosts("git.example.test:2222", "[git.example.test]:2222 "+keyText) {
		t.Fatal("exact non-default-port host key was rejected")
	}
	hashed := knownhosts.HashHostname("[git.example.test]:2222")
	if !validKnownHosts("git.example.test:2222", hashed+" "+keyText) {
		t.Fatal("matching hashed host key was rejected")
	}
	for _, contents := range []string{
		"git.example.test " + keyText,
		"[git.example.test]:2022 " + keyText,
		knownhosts.HashHostname("[other.example.test]:2222") + " " + keyText,
		"*.example.test " + keyText,
		"@revoked [git.example.test]:2222 " + keyText,
		"[git.example.test]:2222 ssh-ed25519 invalid",
	} {
		if validKnownHosts("git.example.test:2222", contents) {
			t.Errorf("mismatched or invalid known-hosts entry was accepted: %q", contents)
		}
	}
}
