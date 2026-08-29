package deploy

import (
	"strings"
	"testing"

	"github.com/bendahma/dokploy-go/internal/store"
	"gopkg.in/yaml.v3"
)

func TestCompileInjectsTraefikAndNetwork(t *testing.T) {
	c := Compiler{PublicNetwork: "public"}
	out, err := c.Compile("services:\n  web:\n    image: nginx:alpine\n", []store.Route{{ServiceName: "web", Host: "app.example.com", PathPrefix: "/", TargetPort: 80, TLS: true, CertificateResolver: "letsencrypt"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"traefik.enable", "app.example.com", "public", "websecure"} {
		if !strings.Contains(out, want) {
			t.Errorf("compiled compose does not contain %q:\n%s", want, out)
		}
	}
}
func TestCompileRejectsHostMount(t *testing.T) {
	c := Compiler{}
	_, err := c.Compile("services:\n  web:\n    image: nginx\n    volumes:\n      - /etc:/host\n", nil)
	if err == nil {
		t.Fatal("expected host mount rejection")
	}
}

func TestCompileRejectsTraefikRuleInjection(t *testing.T) {
	c := Compiler{PublicNetwork: "public"}
	for _, route := range []store.Route{
		{ServiceName: "web", Host: "app.example.com`) || Host(`evil.example.com", PathPrefix: "/", TargetPort: 80, TLS: true, CertificateResolver: "letsencrypt"},
		{ServiceName: "web", Host: "app.example.com", PathPrefix: "/`) || PathPrefix(`/admin", TargetPort: 80, TLS: true, CertificateResolver: "letsencrypt"},
		{ServiceName: "web", Host: "app.example.com", PathPrefix: "/", TargetPort: 80, TLS: true, CertificateResolver: "bad resolver"},
	} {
		if _, err := c.Compile("services:\n  web:\n    image: nginx:alpine\n", []store.Route{route}); err == nil {
			t.Fatalf("accepted unsafe route: %#v", route)
		}
	}
}

func TestValidateRouteAcceptsDNSHosts(t *testing.T) {
	for _, host := range []string{"app.example.com", "nested.apps.example.com", "xn--bcher-kva.example"} {
		if err := ValidateRoute(store.Route{ServiceName: "web", Host: host, PathPrefix: "/api/v1", TargetPort: 8080, TLS: true, CertificateResolver: "letsencrypt-prod"}); err != nil {
			t.Fatalf("rejected %q: %v", host, err)
		}
	}
}

func TestCompileAddsRollbackSafeSwarmDefaults(t *testing.T) {
	out, err := (Compiler{}).Compile("services:\n  web:\n    image: nginx:alpine\n", nil)
	if err != nil {
		t.Fatal(err)
	}
	service := compiledService(t, out, "web")
	deploy, ok := stringMap(service["deploy"])
	if !ok {
		t.Fatalf("compiled service has no deploy object: %s", out)
	}
	update, _ := stringMap(deploy["update_config"])
	rollback, _ := stringMap(deploy["rollback_config"])
	if update["parallelism"] != 1 || update["order"] != "stop-first" || update["failure_action"] != "rollback" || update["monitor"] != "30s" {
		t.Fatalf("unsafe update defaults: %#v", update)
	}
	if rollback["parallelism"] != 1 || rollback["order"] != "stop-first" || rollback["monitor"] != "30s" {
		t.Fatalf("unsafe rollback defaults: %#v", rollback)
	}
}

func TestCompilePreservesExplicitRolloutPolicy(t *testing.T) {
	source := `services:
  web:
    image: nginx:alpine
    deploy:
      update_config:
        parallelism: 4
        order: start-first
        failure_action: pause
        monitor: 2m
      rollback_config:
        parallelism: 3
        order: start-first
        monitor: 1m
`
	out, err := (Compiler{}).Compile(source, nil)
	if err != nil {
		t.Fatal(err)
	}
	deploy, _ := stringMap(compiledService(t, out, "web")["deploy"])
	update, _ := stringMap(deploy["update_config"])
	rollback, _ := stringMap(deploy["rollback_config"])
	if update["parallelism"] != 4 || update["order"] != "start-first" || update["failure_action"] != "pause" || update["monitor"] != "2m" {
		t.Fatalf("explicit update policy changed: %#v", update)
	}
	if rollback["parallelism"] != 3 || rollback["order"] != "start-first" || rollback["monitor"] != "1m" {
		t.Fatalf("explicit rollback policy changed: %#v", rollback)
	}
}

func TestCompileSkipsRolloutDefaultsForJobs(t *testing.T) {
	for _, mode := range []string{"replicated-job", "global-job"} {
		out, err := (Compiler{}).Compile("services:\n  task:\n    image: busybox\n    deploy:\n      mode: "+mode+"\n", nil)
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		deploy, _ := stringMap(compiledService(t, out, "task")["deploy"])
		if _, exists := deploy["update_config"]; exists {
			t.Fatalf("%s received an update policy: %#v", mode, deploy)
		}
	}
}

func TestCompileRejectsMalformedRolloutPolicy(t *testing.T) {
	for _, source := range []string{
		"services:\n  web:\n    image: nginx\n    deploy: invalid\n",
		"services:\n  web:\n    image: nginx\n    deploy:\n      update_config: invalid\n",
		"services:\n  web:\n    image: nginx\n    deploy:\n      rollback_config: invalid\n",
	} {
		if _, err := (Compiler{}).Compile(source, nil); err == nil {
			t.Fatalf("accepted malformed rollout policy:\n%s", source)
		}
	}
}

func compiledService(t *testing.T, compose, name string) map[string]any {
	t.Helper()
	var document map[string]any
	if err := yaml.Unmarshal([]byte(compose), &document); err != nil {
		t.Fatal(err)
	}
	services, ok := stringMap(document["services"])
	if !ok {
		t.Fatalf("compiled Compose has no services: %s", compose)
	}
	service, ok := stringMap(services[name])
	if !ok {
		t.Fatalf("compiled Compose has no %s service: %s", name, compose)
	}
	return service
}
