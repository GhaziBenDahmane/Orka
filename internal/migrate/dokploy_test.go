package migrate

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestDecryptDokploy(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	nonce := []byte("123456789012")
	sealed := aead.Seal(nil, nonce, []byte("A=one\nB='two words'"), nil)
	ciphertext, tag := sealed[:len(sealed)-aead.Overhead()], sealed[len(sealed)-aead.Overhead():]
	payload := append(append(append([]byte{}, nonce...), tag...), ciphertext...)
	encoded := "enc:v1:" + base64.StdEncoding.EncodeToString(payload)
	plain, err := decryptDokploy(encoded, [][]byte{key})
	if err != nil || plain != "A=one\nB='two words'" {
		t.Fatalf("plain = %q, err = %v", plain, err)
	}
	env := parseEnv(plain)
	if env["A"] != "one" || env["B"] != "two words" {
		t.Fatalf("unexpected environment: %#v", env)
	}
}

func TestParseDokployKeys(t *testing.T) {
	keys, err := ParseDokployKeys([]byte("3031323334353637383930313233343536373839303132333435363738393031\n"))
	if err != nil || len(keys) != 1 || len(keys[0]) != 32 {
		t.Fatalf("keys = %#v, err = %v", keys, err)
	}
	if _, err = ParseDokployKeys([]byte("not-a-key")); err == nil {
		t.Fatal("expected invalid key error")
	}
}

func TestMappedIDsAreStableAndTargetScoped(t *testing.T) {
	first := DokployOptions{SourceOrganizationID: "source", TargetOrganizationID: uuid.MustParse("00000000-0000-0000-0000-000000000001")}
	second := first
	second.TargetOrganizationID = uuid.MustParse("00000000-0000-0000-0000-000000000002")
	if mappedID(first, "compose", "abc") != mappedID(first, "compose", "abc") {
		t.Fatal("mapping is not deterministic")
	}
	if mappedID(first, "compose", "abc") == mappedID(second, "compose", "abc") {
		t.Fatal("mapping is not target scoped")
	}
}

func TestPrepareGitApplicationRequiresRegistryPrefix(t *testing.T) {
	item := sourceApplication{ID: "app1", AppName: "Web", Name: "Web", SourceType: "github", BuildType: "dockerfile", Owner: "acme", Repository: "web", Branch: "main", BuildPath: "/", DockerBuildStage: "runtime", EnableSubmodules: true, Replicas: 1}
	options := DokployOptions{SourceOrganizationID: "source", TargetOrganizationID: uuid.New()}
	if _, _, err := prepareApplication(item, options); err == nil {
		t.Fatal("expected missing registry prefix to be rejected")
	}
	options.RegistryPrefix = "ghcr.io/acme"
	prepared, warnings, err := prepareApplication(item, options)
	if err != nil || prepared.source == nil || prepared.source.RepositoryURL != "https://github.com/acme/web.git" || prepared.source.RegistryImage == "" || prepared.source.BuildTarget != "runtime" || !prepared.source.EnableSubmodules || len(warnings) != 2 {
		t.Fatalf("prepared = %#v, warnings = %#v, err = %v", prepared, warnings, err)
	}
}

func TestMigrationApplicationReportDoesNotExposeCredentials(t *testing.T) {
	item := sourceApplication{ID: "app", Name: "App", SourceType: "git", CustomGitURL: "https://username:password@git.example.test/acme/app.git?token=secret#fragment", BuildType: "dockerfile", BuildSecrets: "SECRET=value"}
	report := dokployApplicationReport(item, nil, "skipped", "unsupported")
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	if strings.Contains(text, "password") || strings.Contains(text, "token=secret") || strings.Contains(text, "SECRET=value") {
		t.Fatalf("migration report leaked source secrets: %s", text)
	}
	if !strings.Contains(text, `"hasBuildSecrets":true`) {
		t.Fatalf("migration report omitted the secret-presence flag: %s", text)
	}
}

func TestPrepareGitApplicationMigratesBuildSettings(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	item := sourceApplication{
		ID: "app-build", AppName: "Web", Name: "Web", SourceType: "git", BuildType: "dockerfile",
		CustomGitURL: "https://git.example.test/acme/web.git", CustomGitBranch: "main", DockerBuildStage: "runtime",
		BuildArgs: "GO_VERSION=1.26\nPUBLIC_FLAG=yes", BuildSecrets: encryptDokployFixture(t, key, "NPM_TOKEN=secret"), EnableSubmodules: true, Replicas: 1,
	}
	prepared, _, err := prepareApplication(item, DokployOptions{SourceOrganizationID: "source", TargetOrganizationID: uuid.New(), RegistryPrefix: "registry.example.test/imports", EncryptionKeys: [][]byte{key}})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.source.BuildTarget != "runtime" || !prepared.source.EnableSubmodules || prepared.source.BuildArguments["GO_VERSION"] != "1.26" || prepared.source.BuildSecrets["NPM_TOKEN"] != "secret" {
		t.Fatalf("build settings were not migrated: %#v", prepared.source)
	}
}

func TestPrepareStaticApplication(t *testing.T) {
	item := sourceApplication{ID: "static-app", AppName: "Docs", Name: "Docs", SourceType: "git", BuildType: "static", CustomGitURL: "https://git.example.test/acme/docs.git", CustomGitBranch: "main", CustomGitBuild: "frontend", PublishDirectory: "frontend/dist", Replicas: 1}
	prepared, warnings, err := prepareApplication(item, DokployOptions{SourceOrganizationID: "source", TargetOrganizationID: uuid.New(), RegistryPrefix: "registry.example.test/imports"})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.source == nil || prepared.source.BuildType != "static" || prepared.source.ContextDirectory != "frontend" || prepared.source.OutputDirectory != "dist" {
		t.Fatalf("static source was not migrated: %#v", prepared.source)
	}
	if !strings.Contains(strings.Join(warnings, "\n"), "must already exist") {
		t.Fatalf("static migration warning missing: %#v", warnings)
	}
}

func TestPrepareRailpackApplication(t *testing.T) {
	item := sourceApplication{ID: "railpack-app", AppName: "API", Name: "API", SourceType: "git", BuildType: "railpack", CustomGitURL: "https://git.example.test/acme/api.git", CustomGitBranch: "main", BuildArgs: "NODE_VERSION=24", BuildSecrets: "NPM_TOKEN=secret", Replicas: 1}
	prepared, _, err := prepareApplication(item, DokployOptions{SourceOrganizationID: "source", TargetOrganizationID: uuid.New(), RegistryPrefix: "registry.example.test/imports"})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.source == nil || prepared.source.BuildType != "railpack" || prepared.source.BuildArguments["NODE_VERSION"] != "24" || prepared.source.BuildSecrets["NPM_TOKEN"] != "secret" {
		t.Fatalf("Railpack source was not migrated: %#v", prepared.source)
	}
}

func TestPreparePaketoApplication(t *testing.T) {
	item := sourceApplication{ID: "paketo-app", AppName: "API", Name: "API", SourceType: "git", BuildType: "paketo_buildpacks", CustomGitURL: "https://git.example.test/acme/api.git", CustomGitBranch: "main", BuildArgs: "BP_JVM_VERSION=21", Replicas: 1}
	prepared, _, err := prepareApplication(item, DokployOptions{SourceOrganizationID: "source", TargetOrganizationID: uuid.New(), RegistryPrefix: "registry.example.test/imports"})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.source == nil || prepared.source.BuildType != "buildpacks" || prepared.source.BuildArguments["BP_JVM_VERSION"] != "21" {
		t.Fatalf("Paketo source was not migrated: %#v", prepared.source)
	}
}

func TestPrepareHerokuBuildpackRemainsManual(t *testing.T) {
	item := sourceApplication{ID: "heroku-app", AppName: "API", Name: "API", SourceType: "git", BuildType: "heroku_buildpacks", CustomGitURL: "https://git.example.test/acme/api.git", CustomGitBranch: "main", Replicas: 1}
	if _, _, err := prepareApplication(item, DokployOptions{SourceOrganizationID: "source", TargetOrganizationID: uuid.New(), RegistryPrefix: "registry.example.test/imports"}); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("expected Heroku buildpack to require manual conversion, got %v", err)
	}
}

func TestPrepareDropApplicationExplainsManualArtifactTransfer(t *testing.T) {
	item := sourceApplication{ID: "drop-app", AppName: "Drop", Name: "Drop", SourceType: "drop", BuildType: "dockerfile", Replicas: 1}
	if _, _, err := prepareApplication(item, DokployOptions{SourceOrganizationID: "source", TargetOrganizationID: uuid.New(), RegistryPrefix: "registry.example.test/imports"}); err == nil || !strings.Contains(err.Error(), "filesystem") || !strings.Contains(err.Error(), "upload the ZIP") {
		t.Fatalf("expected actionable manual drop migration guidance, got %v", err)
	}
}
