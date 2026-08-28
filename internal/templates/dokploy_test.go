package templates

import (
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
