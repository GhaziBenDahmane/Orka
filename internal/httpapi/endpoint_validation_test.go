package httpapi

import (
	"strings"
	"testing"
)

func TestNormalizeCredentialServer(t *testing.T) {
	for input, want := range map[string]string{
		"github.com":              "github.com",
		"REGISTRY.example.test":   "registry.example.test",
		"registry.example.test:5": "registry.example.test:5",
		"127.0.0.1:5000":          "127.0.0.1:5000",
		"[2001:db8::1]:5000":      "[2001:db8::1]:5000",
	} {
		got, err := normalizeCredentialServer(input)
		if err != nil || got != want {
			t.Errorf("normalizeCredentialServer(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []string{"", " registry.example.test", "https://registry.example.test", "user@registry.example.test", "bad_label.example.test", "-bad.example.test", "registry.example.test/path", "registry.example.test:", "registry.example.test:0", "registry.example.test:65536", "[not-an-ip]:5000", strings.Repeat("a", maxSourceCredentialServerBytes+1)} {
		if _, err := normalizeCredentialServer(input); err == nil {
			t.Errorf("unsafe credential server %q was accepted", input)
		}
	}
}

func TestSourceCredentialIdentityIsBoundedAndSingleLine(t *testing.T) {
	if !validSourceCredentialIdentity("git", "GitHub", "automation@example.test") {
		t.Fatal("valid source credential identity was rejected")
	}
	for _, test := range []struct{ kind, name, username string }{
		{"unknown", "GitHub", "automation"},
		{"git", "", "automation"},
		{"git", "line\nbreak", "automation"},
		{"git", strings.Repeat("n", maxSourceCredentialNameBytes+1), "automation"},
		{"git", "GitHub", ""},
		{"git", "GitHub", "user\nheader"},
		{"git", "GitHub", strings.Repeat("u", maxSourceCredentialUsernameBytes+1)},
	} {
		if validSourceCredentialIdentity(test.kind, test.name, test.username) {
			t.Errorf("invalid source credential identity %#v was accepted", test)
		}
	}
}
