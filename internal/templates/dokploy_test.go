package templates

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstantiateDokployTemplate(t *testing.T) {
	var template DokployTemplate
	template.Variables = map[string]string{"main_domain": "${domain}", "password": "${password:24}"}
	template.Config.Env = map[string]any{"PASSWORD": "${password}"}
	template.Config.Domains = []Domain{{ServiceName: "web", Port: int64(8080), Host: "${main_domain}"}}
	instance, err := Instantiate(template, "services:\n  web:\n    image: example\n", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(instance.Environment["PASSWORD"]) != 24 {
		t.Fatalf("wrong password length: %q", instance.Environment["PASSWORD"])
	}
	if !strings.HasSuffix(instance.Domains[0].Host, ".example.com") {
		t.Fatalf("unexpected domain %q", instance.Domains[0].Host)
	}
}

func TestSignedCatalogDetectsTampering(t *testing.T) {
	root := t.TempDir()
	blueprint := filepath.Join(root, "blueprints", "demo")
	if err := os.MkdirAll(blueprint, 0700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"meta.json":          `{"id":"demo","name":"Demo","version":"1"}`,
		"template.toml":      "[variables]\n",
		"docker-compose.yml": "services:\n  web:\n    image: example@sha256:" + strings.Repeat("a", 64) + "\n",
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(blueprint, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	publicKey, privateKey, err := GenerateCatalogKey()
	if err != nil {
		t.Fatal(err)
	}
	if err = SignCatalog(root, privateKey); err != nil {
		t.Fatal(err)
	}
	if err = VerifyCatalog(root, publicKey); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(blueprint, "meta.json"), []byte(`{"id":"other"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err = VerifyCatalog(root, publicKey); err == nil {
		t.Fatal("expected modified catalog to fail verification")
	}
}

func TestApplyMountsConvertsFilesToSwarmConfigs(t *testing.T) {
	compose := "services:\n  db:\n    image: example\n    volumes:\n      - ../files/db/config.xml:/etc/db/config.xml:ro\n"
	out, err := ApplyMounts(compose, []Mount{{FilePath: "/db/config.xml", Content: "<config/>"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"x-dockyard-files", "configs:", "/etc/db/config.xml"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}
