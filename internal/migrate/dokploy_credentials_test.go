package migrate

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/GhaziBenDahmane/Orka/internal/cryptox"
	"github.com/google/uuid"
)

func TestPrepareSourceCredentialEncryptsSecret(t *testing.T) {
	box, err := cryptox.New(bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	options := DokployOptions{TargetOrganizationID: uuid.New(), SourceOrganizationID: "source"}
	prepared, err := prepareSourceCredential(box, options, sourceCredential{sourceID: "gitlab-1", sourceKind: "gitlab", kind: "git", name: "GitLab", server: "https://gitlab.example.test/", username: "oauth2", secret: "source-token", supported: true})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.server != "gitlab.example.test" || prepared.secret == "source-token" {
		t.Fatal("credential was not normalized and encrypted")
	}
	plain, err := box.Decrypt(prepared.secret, cryptox.ResourceContext("source-credential", prepared.id.String()))
	if err != nil || string(plain) != "source-token" {
		t.Fatalf("credential cannot be decrypted: %q, %v", plain, err)
	}
}

func TestCredentialServer(t *testing.T) {
	tests := []struct {
		value, kind, want string
	}{
		{"", "registry", "docker.io"},
		{"registry.example.test:5000", "registry", "registry.example.test:5000"},
		{"https://git.example.test:8443/", "git", "git.example.test:8443"},
	}
	for _, test := range tests {
		got, err := credentialServer(test.value, test.kind)
		if err != nil || got != test.want {
			t.Errorf("credentialServer(%q, %q) = %q, %v; want %q", test.value, test.kind, got, err, test.want)
		}
	}
	for _, test := range []struct{ value, kind string }{
		{"http://git.example.test", "git"},
		{"https://user@git.example.test", "git"},
		{"https://bad_label.example.test", "git"},
		{"https://git.example.test:0", "git"},
		{"https://registry.example.test/path", "registry"},
		{"https://registry.example.test?token=secret", "registry"},
		{"registry.example.test", "unknown"},
	} {
		if _, err := credentialServer(test.value, test.kind); err == nil {
			t.Errorf("unsafe credential server %q (%s) was accepted", test.value, test.kind)
		}
	}
}

func TestMigratedCredentialNameIsSafeAndBounded(t *testing.T) {
	id := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	name, err := migratedCredentialName(strings.Repeat("é", 100), id)
	if err != nil || len(name) > maxMigratedCredentialNameBytes || !strings.HasSuffix(name, " (Dokploy 11111111)") || !utf8.ValidString(name) {
		t.Fatalf("migrated credential name %q has length %d: %v", name, len(name), err)
	}
	for _, value := range []string{"", "line\nbreak", "nul\x00byte"} {
		if _, err = migratedCredentialName(value, id); err == nil {
			t.Errorf("invalid migrated credential name %q was accepted", value)
		}
	}
}

func TestPrepareSourceCredentialRejectsUnsafeImportedFields(t *testing.T) {
	box, _ := cryptox.New(bytes.Repeat([]byte{4}, 32))
	options := DokployOptions{TargetOrganizationID: uuid.New(), SourceOrganizationID: "source"}
	base := sourceCredential{sourceID: "gitlab-1", sourceKind: "gitlab", kind: "git", name: "GitLab", server: "https://gitlab.example.test", username: "oauth2", secret: "source-token", supported: true}
	for _, mutate := range []func(*sourceCredential){
		func(item *sourceCredential) { item.username = "oauth2\nheader" },
		func(item *sourceCredential) {
			item.username = strings.Repeat("u", maxMigratedCredentialUsernameBytes+1)
		},
		func(item *sourceCredential) { item.secret = "token\nheader" },
		func(item *sourceCredential) { item.secret = strings.Repeat("s", maxDokployEncryptedCredentialBytes+1) },
	} {
		item := base
		mutate(&item)
		if _, err := prepareSourceCredential(box, options, item); err == nil {
			t.Fatal("unsafe imported credential was accepted")
		}
	}
}
