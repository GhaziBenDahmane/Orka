package migrate

import (
	"bytes"
	"testing"

	"github.com/bendahma/dokploy-go/internal/cryptox"
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
	plain, err := box.Decrypt(prepared.secret, "source-credential")
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
		{"https://git.example.test:8443/", "git", "git.example.test"},
	}
	for _, test := range tests {
		got, err := credentialServer(test.value, test.kind)
		if err != nil || got != test.want {
			t.Errorf("credentialServer(%q, %q) = %q, %v; want %q", test.value, test.kind, got, err, test.want)
		}
	}
}
