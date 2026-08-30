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

func TestCompilePreservesImplicitDefaultNetworkForRoutedService(t *testing.T) {
	source := `services:
  web:
    image: nginx:alpine
  database:
    image: postgres:17-alpine
`
	out, err := (Compiler{PublicNetwork: "public"}).Compile(source, []store.Route{{ServiceName: "web", Host: "app.example.com", PathPrefix: "/", TargetPort: 80}})
	if err != nil {
		t.Fatal(err)
	}
	assertNetworkNames(t, compiledService(t, out, "web")["networks"], "default", "public")
	if _, exists := compiledService(t, out, "database")["networks"]; exists {
		t.Fatalf("unrouted sidecar should retain its implicit default network: %s", out)
	}
	var document map[string]any
	if err := yaml.Unmarshal([]byte(out), &document); err != nil {
		t.Fatal(err)
	}
	networks, _ := stringMap(document["networks"])
	if _, exists := networks["default"]; !exists {
		t.Fatalf("compiled Compose does not declare the synthesized default network: %s", out)
	}
}

func TestCompilePreservesImplicitDefaultNetworkAcrossMultipleRoutes(t *testing.T) {
	routes := []store.Route{
		{ServiceName: "web", Host: "app.example.com", PathPrefix: "/", TargetPort: 80},
		{ServiceName: "web", Host: "api.example.com", PathPrefix: "/api", TargetPort: 80},
	}
	out, err := (Compiler{PublicNetwork: "public"}).Compile("services:\n  web:\n    image: nginx:alpine\n", routes)
	if err != nil {
		t.Fatal(err)
	}
	service := compiledService(t, out, "web")
	assertNetworkNames(t, service["networks"], "default", "public")
	deploy, _ := stringMap(service["deploy"])
	labels := normalizeLabels(deploy["labels"])
	for _, host := range []string{"app.example.com", "api.example.com"} {
		found := false
		for key, value := range labels {
			if strings.HasSuffix(key, ".rule") && strings.Contains(value.(string), host) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("compiled labels do not include route for %s: %#v", host, labels)
		}
	}
}

func TestCompilePreservesExplicitServiceNetworks(t *testing.T) {
	tests := []struct {
		name   string
		source string
		check  func(*testing.T, any)
	}{
		{
			name: "list",
			source: `services:
  web:
    image: nginx:alpine
    networks: [internal]
networks:
  internal: {}
`,
			check: func(t *testing.T, value any) {
				assertNetworkNames(t, value, "internal", "public")
			},
		},
		{
			name: "map",
			source: `services:
  web:
    image: nginx:alpine
    networks:
      internal:
        aliases: [api]
networks:
  internal: {}
`,
			check: func(t *testing.T, value any) {
				networks, ok := stringMap(value)
				if !ok {
					t.Fatalf("map-form networks changed form: %#v", value)
				}
				assertNetworkNames(t, networks, "internal", "public")
				internal, _ := stringMap(networks["internal"])
				aliases := anySlice(internal["aliases"])
				if len(aliases) != 1 || aliases[0] != "api" {
					t.Fatalf("network aliases were not preserved: %#v", networks)
				}
			},
		},
		{
			name: "explicit public only",
			source: `services:
  web:
    image: nginx:alpine
    networks: [public]
networks:
  public:
    external: true
`,
			check: func(t *testing.T, value any) {
				assertNetworkNames(t, value, "public")
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			out, err := (Compiler{PublicNetwork: "public"}).Compile(test.source, []store.Route{{ServiceName: "web", Host: "app.example.com", PathPrefix: "/", TargetPort: 80}})
			if err != nil {
				t.Fatal(err)
			}
			test.check(t, compiledService(t, out, "web")["networks"])
		})
	}
}

func TestCompileRejectsMalformedNetworksWhenAddingRoute(t *testing.T) {
	tests := []string{
		"services:\n  web:\n    image: nginx\n    networks: internal\n",
		"services:\n  web:\n    image: nginx\n    networks: [internal, 7]\n",
		"services:\n  web:\n    image: nginx\nnetworks: invalid\n",
	}
	for _, source := range tests {
		if _, err := (Compiler{PublicNetwork: "public"}).Compile(source, []store.Route{{ServiceName: "web", Host: "app.example.com", PathPrefix: "/", TargetPort: 80}}); err == nil {
			t.Fatalf("accepted malformed networks:\n%s", source)
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

func TestCompileSafeModeRejectsHostAndCrossTenantPrimitives(t *testing.T) {
	tests := map[string]string{
		"device":                  "services:\n  app:\n    image: alpine\n    devices: [/dev/kvm:/dev/kvm]\n",
		"capability":              "services:\n  app:\n    image: alpine\n    cap_add: [SYS_ADMIN]\n",
		"host user namespace":     "services:\n  app:\n    image: alpine\n    userns_mode: host\n",
		"host cgroup namespace":   "services:\n  app:\n    image: alpine\n    cgroup: host\n",
		"unconfined profile":      "services:\n  app:\n    image: alpine\n    security_opt: [seccomp=unconfined]\n",
		"host env file":           "services:\n  app:\n    image: alpine\n    env_file: /etc/environment\n",
		"compose secret":          "services:\n  app:\n    image: alpine\n    secrets: [host]\nsecrets:\n  host:\n    file: /etc/shadow\n",
		"external volume":         "services:\n  app:\n    image: alpine\n    volumes: [shared:/data]\nvolumes:\n  shared:\n    external: true\n",
		"volume driver options":   "services:\n  app:\n    image: alpine\n    volumes: [host:/data]\nvolumes:\n  host:\n    driver_opts:\n      type: none\n      o: bind\n      device: /etc\n",
		"external network":        "services:\n  app:\n    image: alpine\n    networks: [shared]\nnetworks:\n  shared:\n    external: true\n",
		"legacy external network": "services:\n  app:\n    image: alpine\n    networks: [shared]\nnetworks:\n  shared:\n    external:\n      name: shared\n",
		"custom network name":     "services:\n  app:\n    image: alpine\nnetworks:\n  default:\n    name: another-stack_default\n",
		"service traefik label":   "services:\n  app:\n    image: alpine\n    labels:\n      traefik.enable: 'true'\n",
		"swarm traefik label":     "services:\n  app:\n    image: alpine\n    deploy:\n      labels:\n        - traefik.http.routers.escape.rule=Host(`other.example.test`)\n",
	}
	for name, source := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := (Compiler{PublicNetwork: "public"}).Compile(source, nil); err == nil {
				t.Fatalf("safe mode accepted privileged Compose input:\n%s", source)
			}
			if _, err := (Compiler{PublicNetwork: "public", AllowUnsafe: true}).Compile(source, nil); err != nil {
				t.Fatalf("explicit unsafe mode rejected input: %v", err)
			}
		})
	}
}

func TestCompileSafeModeAllowsScopedResourcesAndHardening(t *testing.T) {
	source := `services:
  app:
    image: alpine
    volumes: [data:/data]
    networks: [default]
    security_opt: [no-new-privileges:true]
    labels:
      com.example.owner: platform
volumes:
  data: {}
networks:
  default: {}
`
	if _, err := (Compiler{PublicNetwork: "public"}).Compile(source, nil); err != nil {
		t.Fatal(err)
	}
}

func TestCompileSafeModeAllowsOnlyPlatformExternalNetwork(t *testing.T) {
	source := `services:
  app:
    image: alpine
    networks: [public]
networks:
  public:
    external: true
    name: public
`
	if _, err := (Compiler{PublicNetwork: "public"}).Compile(source, nil); err != nil {
		t.Fatal(err)
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

func assertNetworkNames(t *testing.T, value any, expected ...string) {
	t.Helper()
	actual := networkNames(value)
	if strings.Join(actual, ",") != strings.Join(expected, ",") {
		t.Fatalf("unexpected networks: got %v, want %v", actual, expected)
	}
}
