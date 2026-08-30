package templates

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bendahma/dokploy-go/internal/deploy"
)

func TestValidateDokployCatalogFailsClosedOnInvalidMetadata(t *testing.T) {
	root := t.TempDir()
	writeCatalogBlueprint(t, root, "valid", `{"id":"valid","name":"Valid","version":"1.0.0"}`)
	invalid := filepath.Join(root, "blueprints", "invalid")
	if err := os.MkdirAll(invalid, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(invalid, "template.toml"), []byte("[variables]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(invalid, "docker-compose.yml"), []byte("services:\n  app:\n    image: example:1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	report, err := ValidateDokployCatalog(root, deploy.Compiler{PublicNetwork: "dockyard-public"})
	if err == nil || report.Imported != 1 || !strings.Contains(report.Failed["invalid"], "meta.json") {
		t.Fatalf("partial invalid catalog report=%#v err=%v", report, err)
	}
}

func TestImportDokployCatalogValidatesEverythingBeforePublication(t *testing.T) {
	root := t.TempDir()
	writeCatalogBlueprint(t, root, "a-valid", `{"id":"valid","name":"Valid","version":"1.0.0"}`)
	writeCatalogBlueprint(t, root, "z-invalid", `{"id":"invalid","name":"Invalid","version":"1.0.0"}`)
	if err := os.Remove(filepath.Join(root, "blueprints", "z-invalid", "docker-compose.yml")); err != nil {
		t.Fatal(err)
	}
	report, err := ImportDokployCatalog(context.Background(), nil, root)
	if err == nil || report.Imported != 0 || !strings.Contains(report.Failed["z-invalid"], "docker-compose.yml") {
		t.Fatalf("pre-publication validation report=%#v err=%v", report, err)
	}
}

func TestValidateDokployCatalogRejectsDuplicateIdentity(t *testing.T) {
	root := t.TempDir()
	metadata := `{"id":"duplicate","name":"Duplicate","version":"1.0.0"}`
	writeCatalogBlueprint(t, root, "first", metadata)
	writeCatalogBlueprint(t, root, "second", metadata)
	report, err := ValidateDokployCatalog(root, deploy.Compiler{PublicNetwork: "dockyard-public"})
	if err == nil || report.Imported != 1 || !strings.Contains(report.Failed["second"], "duplicates template key and version") {
		t.Fatalf("duplicate catalog report=%#v err=%v", report, err)
	}
}

func TestValidateDokployCatalogRejectsEmptyCatalog(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "blueprints"), 0700); err != nil {
		t.Fatal(err)
	}
	report, err := ValidateDokployCatalog(root, deploy.Compiler{PublicNetwork: "dockyard-public"})
	if err == nil || report.Imported != 0 || !strings.Contains(err.Error(), "no templates") {
		t.Fatalf("empty catalog report=%#v err=%v", report, err)
	}
}

func TestTemplateMetadataRequiresStableIdentity(t *testing.T) {
	for _, metadata := range []string{
		`{"name":"Missing ID","version":"1"}`,
		`{"id":"UPPERCASE","name":"Uppercase","version":"1"}`,
		`{"id":"path/escape","name":"Path","version":"1"}`,
		`{"id":"missing-name","version":"1"}`,
		`{"id":"missing-version","name":"Missing version"}`,
	} {
		if _, err := parseTemplateMetadata([]byte(metadata)); err == nil {
			t.Errorf("invalid metadata accepted: %s", metadata)
		}
	}
}

func writeCatalogBlueprint(t *testing.T, root, directory, metadata string) {
	t.Helper()
	blueprint := filepath.Join(root, "blueprints", directory)
	if err := os.MkdirAll(blueprint, 0700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"meta.json":          metadata,
		"template.toml":      "[variables]\n",
		"docker-compose.yml": "services:\n  app:\n    image: example:1\n",
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(blueprint, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
