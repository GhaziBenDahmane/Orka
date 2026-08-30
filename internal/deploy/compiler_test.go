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

func TestCompileRoutePathRewriteAndRedirect(t *testing.T) {
	route := store.Route{ServiceName: "web", Host: "app.example.com", PathPrefix: "/public", InternalPath: "/internal", StripPath: true, RedirectRegex: `^https://app\.example\.com/old/(.*)`, RedirectReplacement: `https://app.example.com/new/${1}`, RedirectPermanent: true, BasicAuthUsers: []string{`operator:$2a$12$C6UzMDM.H6dfI/f/IKxGhuVvZ4GuGNmi1wT7dSx.QcpQo.eN8wxQe`}, TargetPort: 80, TLS: true, CertificateResolver: "letsencrypt"}
	out, err := (Compiler{PublicNetwork: "public"}).Compile("services:\n  web:\n    image: nginx:alpine\n", []store.Route{route})
	if err != nil {
		t.Fatal(err)
	}
	service := compiledService(t, out, "web")
	deployment, ok := stringMap(service["deploy"])
	if !ok {
		t.Fatalf("compiled service has no deploy object: %s", out)
	}
	labels := normalizeLabels(deployment["labels"])
	wants := map[string]string{
		"traefik.http.middlewares.dockyard-0-app-example-com-strip-path.stripprefix.prefixes":    "/public",
		"traefik.http.middlewares.dockyard-0-app-example-com-internal-path.addprefix.prefix":     "/internal",
		"traefik.http.middlewares.dockyard-0-app-example-com-redirect.redirectregex.regex":       `^https://app\.example\.com/old/(.*)`,
		"traefik.http.middlewares.dockyard-0-app-example-com-redirect.redirectregex.replacement": `https://app.example.com/new/$${1}`,
		"traefik.http.middlewares.dockyard-0-app-example-com-redirect.redirectregex.permanent":   "true",
		"traefik.http.middlewares.dockyard-0-app-example-com-basic-auth.basicauth.users":         `operator:$$2a$$12$$C6UzMDM.H6dfI/f/IKxGhuVvZ4GuGNmi1wT7dSx.QcpQo.eN8wxQe`,
		"traefik.http.middlewares.dockyard-0-app-example-com-basic-auth.basicauth.removeheader":  "true",
		"traefik.http.routers.dockyard-0-app-example-com.middlewares":                            "dockyard-0-app-example-com-strip-path,dockyard-0-app-example-com-internal-path,dockyard-0-app-example-com-redirect,dockyard-0-app-example-com-basic-auth",
	}
	for key, want := range wants {
		if got := labels[key]; got != want {
			t.Errorf("label %s=%v, want %q", key, got, want)
		}
	}
}

func TestCompileIgnoresDisabledRoutes(t *testing.T) {
	out, err := (Compiler{PublicNetwork: "public"}).Compile("services:\n  web:\n    image: nginx:alpine\n", []store.Route{{ServiceName: "web", Host: "disabled.example.com", PathPrefix: "/", TargetPort: 80, Disabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "traefik") || strings.Contains(out, "disabled.example.com") {
		t.Fatalf("disabled route was compiled: %s", out)
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
	assertEncryptedOverlay(t, networks, "default")
	public, _ := stringMap(networks["public"])
	if public["external"] != true || public["name"] != "public" {
		t.Fatalf("platform network was changed: %#v", public)
	}
	if _, exists := public["driver_opts"]; exists {
		t.Fatalf("platform network received stack-owned driver options: %#v", public)
	}
}

func TestCompileEncryptsImplicitDefaultNetwork(t *testing.T) {
	out, err := (Compiler{PublicNetwork: "public"}).Compile("services:\n  app:\n    image: alpine\n", nil)
	if err != nil {
		t.Fatal(err)
	}
	assertEncryptedOverlay(t, compiledNetworks(t, out), "default")
}

func TestCompileEncryptsExplicitStackNetworks(t *testing.T) {
	source := `services:
  app:
    image: alpine
    networks: [internal]
networks:
  internal:
    internal: true
`
	out, err := (Compiler{PublicNetwork: "public"}).Compile(source, nil)
	if err != nil {
		t.Fatal(err)
	}
	networks := compiledNetworks(t, out)
	assertEncryptedOverlay(t, networks, "internal")
	internal, _ := stringMap(networks["internal"])
	if internal["internal"] != true {
		t.Fatalf("network properties were not preserved: %#v", internal)
	}
}

func TestCompileEncryptsImplicitDefaultAlongsideDeclaredNetwork(t *testing.T) {
	source := `services:
  app:
    image: alpine
networks:
  unused: {}
`
	out, err := (Compiler{PublicNetwork: "public"}).Compile(source, nil)
	if err != nil {
		t.Fatal(err)
	}
	networks := compiledNetworks(t, out)
	assertEncryptedOverlay(t, networks, "default")
	assertEncryptedOverlay(t, networks, "unused")
}

func TestCompileSafeModeRejectsUnsafeNetworkDriversAndOptions(t *testing.T) {
	tests := map[string]string{
		"bridge driver":      "services:\n  app:\n    image: alpine\nnetworks:\n  default:\n    driver: bridge\n",
		"invalid driver":     "services:\n  app:\n    image: alpine\nnetworks:\n  default:\n    driver: 7\n",
		"extra option":       "services:\n  app:\n    image: alpine\nnetworks:\n  default:\n    driver_opts:\n      encrypted: ''\n      com.example.option: enabled\n",
		"invalid encryption": "services:\n  app:\n    image: alpine\nnetworks:\n  default:\n    driver_opts:\n      encrypted: 'false'\n",
	}
	for name, source := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := (Compiler{PublicNetwork: "public"}).Compile(source, nil); err == nil {
				t.Fatalf("safe mode accepted unsafe network configuration:\n%s", source)
			}
			if _, err := (Compiler{PublicNetwork: "public", AllowUnsafe: true}).Compile(source, nil); err != nil {
				t.Fatalf("unsafe mode changed explicit network semantics: %v", err)
			}
		})
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

func TestCompileAllowsOnlyEncryptedManagedFileConfigs(t *testing.T) {
	key := InlineFileEnvironmentPrefix + strings.Repeat("A", 64)
	valid := "services:\n  app:\n    image: alpine\n    configs:\n      - source: tpl-config-1234\n        target: /etc/app/config.yml\n        mode: 292\nconfigs:\n  tpl-config-1234:\n    file: ./.dockyard-files/tpl-config-1234\nx-dockyard-files:\n  tpl-config-1234: " + InlineFileReferencePrefix + key + "\n"
	if _, err := (Compiler{}).Compile(valid, nil); err != nil {
		t.Fatalf("encrypted managed file was rejected: %v", err)
	}
	tests := map[string]string{
		"ordinary config":    "services:\n  app:\n    image: alpine\nconfigs:\n  arbitrary:\n    file: /etc/passwd\n",
		"plaintext content":  strings.Replace(valid, InlineFileReferencePrefix+key, "plaintext-secret", 1),
		"unlisted source":    strings.Replace(valid, "source: tpl-config-1234", "source: another-config", 1),
		"relative target":    strings.Replace(valid, "target: /etc/app/config.yml", "target: ../config.yml", 1),
		"writable mode":      strings.Replace(valid, "mode: 292", "mode: 420", 1),
		"extra config field": strings.Replace(valid, "mode: 292", "mode: 292\n        uid: root", 1),
	}
	for name, source := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := (Compiler{}).Compile(source, nil); err == nil {
				t.Fatal("unsafe managed config was accepted")
			}
		})
	}
}

func TestCompileSafeModeRejectsHostAndCrossTenantPrimitives(t *testing.T) {
	tests := map[string]string{
		"device":                    "services:\n  app:\n    image: alpine\n    devices: [/dev/kvm:/dev/kvm]\n",
		"reserved device":           "services:\n  app:\n    image: alpine\n    deploy:\n      resources:\n        reservations:\n          devices:\n            - capabilities: [gpu]\n",
		"reserved generic resource": "services:\n  app:\n    image: alpine\n    deploy:\n      resources:\n        reservations:\n          generic_resources:\n            - discrete_resource_spec:\n                kind: GPU\n                value: 1\n",
		"gpu":                       "services:\n  app:\n    image: alpine\n    gpus: all\n",
		"custom runtime":            "services:\n  app:\n    image: alpine\n    runtime: nvidia\n",
		"custom cgroup parent":      "services:\n  app:\n    image: alpine\n    cgroup_parent: tenant.slice\n",
		"kernel sysctl":             "services:\n  app:\n    image: alpine\n    sysctls:\n      net.core.somaxconn: 65535\n",
		"raised ulimit":             "services:\n  app:\n    image: alpine\n    ulimits:\n      nofile: 1000000\n",
		"storage option":            "services:\n  app:\n    image: alpine\n    storage_opt:\n      size: 1T\n",
		"legacy scale":              "services:\n  app:\n    image: alpine\n    scale: 1000000\n",
		"privileged lifecycle hook": "services:\n  app:\n    image: alpine\n    post_start:\n      - command: whoami\n        privileged: true\n",
		"capability":                "services:\n  app:\n    image: alpine\n    cap_add: [SYS_ADMIN]\n",
		"container network":         "services:\n  app:\n    image: alpine\n    network_mode: container:control-plane\n",
		"service process":           "services:\n  app:\n    image: alpine\n    pid: service:other\n",
		"container ipc":             "services:\n  app:\n    image: alpine\n    ipc: container:control-plane\n",
		"host uts":                  "services:\n  app:\n    image: alpine\n    uts: host\n",
		"published port":            "services:\n  app:\n    image: nginx\n    ports: ['8080:80']\n",
		"host user namespace":       "services:\n  app:\n    image: alpine\n    userns_mode: host\n",
		"host cgroup namespace":     "services:\n  app:\n    image: alpine\n    cgroup: host\n",
		"unconfined profile":        "services:\n  app:\n    image: alpine\n    security_opt: [seccomp=unconfined]\n",
		"host env file":             "services:\n  app:\n    image: alpine\n    env_file: /etc/environment\n",
		"host label file":           "services:\n  app:\n    image: alpine\n    label_file: /etc/environment\n",
		"external compose":          "services:\n  app:\n    extends:\n      file: /etc/compose.yml\n      service: app\n",
		"compose provider":          "services:\n  app:\n    provider:\n      type: host-plugin\n",
		"compose secret":            "services:\n  app:\n    image: alpine\n    secrets: [host]\nsecrets:\n  host:\n    file: /etc/shadow\n",
		"compose model":             "services:\n  app:\n    image: alpine\n    models: [llm]\nmodels:\n  llm:\n    model: ai/example\n",
		"external volume":           "services:\n  app:\n    image: alpine\n    volumes: [shared:/data]\nvolumes:\n  shared:\n    external: true\n",
		"volume driver options":     "services:\n  app:\n    image: alpine\n    volumes: [host:/data]\nvolumes:\n  host:\n    driver_opts:\n      type: none\n      o: bind\n      device: /etc\n",
		"volume plugin":             "services:\n  app:\n    image: alpine\n    volumes: [data:/data]\nvolumes:\n  data:\n    driver: vendor/plugin\n",
		"cluster volume":            "services:\n  app:\n    image: alpine\n    volumes:\n      - type: cluster\n        source: shared\n        target: /data\n",
		"named pipe":                "services:\n  app:\n    image: alpine\n    volumes:\n      - type: npipe\n        source: pipe\n        target: /pipe\n",
		"interpolated host mount":   "services:\n  app:\n    image: alpine\n    volumes: ['${HOME}:/host']\n",
		"external network":          "services:\n  app:\n    image: alpine\n    networks: [shared]\nnetworks:\n  shared:\n    external: true\n",
		"legacy external network":   "services:\n  app:\n    image: alpine\n    networks: [shared]\nnetworks:\n  shared:\n    external:\n      name: shared\n",
		"custom network name":       "services:\n  app:\n    image: alpine\nnetworks:\n  default:\n    name: another-stack_default\n",
		"service traefik label":     "services:\n  app:\n    image: alpine\n    labels:\n      traefik.enable: 'true'\n",
		"swarm traefik label":       "services:\n  app:\n    image: alpine\n    deploy:\n      labels:\n        - traefik.http.routers.escape.rule=Host(`other.example.test`)\n",
		"external log driver":       "services:\n  app:\n    image: alpine\n    logging:\n      driver: syslog\n      options:\n        syslog-address: tcp://169.254.169.254:514\n",
		"logging plugin":            "services:\n  app:\n    image: alpine\n    logging:\n      driver: vendor/plugin\n",
		"unsafe logging option":     "services:\n  app:\n    image: alpine\n    logging:\n      driver: json-file\n      options:\n        syslog-address: tcp://example.test:514\n",
		"excessive log file size":   "services:\n  app:\n    image: alpine\n    logging:\n      driver: local\n      options:\n        max-size: \"1g\"\n",
		"overflowing log size":      "services:\n  app:\n    image: alpine\n    logging:\n      driver: local\n      options:\n        max-size: \"999999999999999999999999g\"\n",
		"excessive log files":       "services:\n  app:\n    image: alpine\n    logging:\n      driver: local\n      options:\n        max-file: \"100\"\n",
		"invalid log compression":   "services:\n  app:\n    image: alpine\n    logging:\n      driver: local\n      options:\n        compress: sometimes\n",
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

func TestCompileSafeModeAllowsDisabledNetworking(t *testing.T) {
	source := "services:\n  app:\n    image: alpine\n    network_mode: none\n"
	out, err := (Compiler{PublicNetwork: "public"}).Compile(source, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := compiledNetworks(t, out)["default"]; exists {
		t.Fatalf("network-disabled service caused a default network to be created: %s", out)
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
    logging:
      driver: local
      options:
        max-size: "20m"
        max-file: "5"
        compress: "true"
volumes:
  data: {}
networks:
  default: {}
`
	if _, err := (Compiler{PublicNetwork: "public"}).Compile(source, nil); err != nil {
		t.Fatal(err)
	}
}

func TestCompileSafeModeAllowsAnonymousNamedAndTmpfsVolumes(t *testing.T) {
	source := `services:
  app:
    image: alpine
    volumes:
      - /cache
      - data:/data:ro
      - type: volume
        source: data
        target: /other
      - type: tmpfs
        target: /run
volumes:
  data:
    driver: local
`
	if _, err := (Compiler{PublicNetwork: "public"}).Compile(source, nil); err != nil {
		t.Fatal(err)
	}
}

func TestPinNamedVolumesAddsStorageNodeConstraint(t *testing.T) {
	source := `services:
  database:
    image: postgres:17
    volumes:
      - data:/var/lib/postgresql/data
    deploy:
      placement:
        constraints: [node.labels.region == eu]
  metrics:
    image: exporter:1
volumes:
  data: {}
`
	pinned, found, err := PinNamedVolumes(source, "abc123")
	if err != nil || !found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if !strings.Contains(pinned, "node.id == abc123") || !strings.Contains(pinned, "node.labels.region == eu") {
		t.Fatalf("storage placement was not preserved and pinned:\n%s", pinned)
	}
	if strings.Count(pinned, "node.id == abc123") != 1 {
		t.Fatalf("unexpected storage-node constraint count:\n%s", pinned)
	}
	withoutVolumes, found, err := PinNamedVolumes("services:\n  app:\n    image: nginx\n", "abc123")
	if err != nil || found || withoutVolumes == "" {
		t.Fatalf("volume-free compose found=%v err=%v output=%q", found, err, withoutVolumes)
	}
}

func TestNamedVolumesReturnsMountedDeclarations(t *testing.T) {
	source := `services:
  app:
    image: example/app
    volumes:
      - uploads:/uploads
      - type: volume
        source: cache
        target: /cache
      - type: tmpfs
        target: /tmp
volumes:
  unused: {}
  uploads: {}
  cache: {}
`
	names, err := NamedVolumes(source)
	if err != nil || strings.Join(names, ",") != "cache,uploads" {
		t.Fatalf("names=%v err=%v", names, err)
	}
	if actual, err := StackVolumeName("my-stack", "uploads"); err != nil || actual != "my-stack_uploads" {
		t.Fatalf("actual=%q err=%v", actual, err)
	}
}

func TestPinNamedVolumesIsIdempotentForPersistedStorageNode(t *testing.T) {
	source := "services:\n  database:\n    image: postgres:17\n    volumes: [data:/data]\n    deploy:\n      placement:\n        constraints: ['node.id == abc123']\nvolumes:\n  data: {}\n"
	pinned, found, err := PinNamedVolumes(source, "abc123")
	if err != nil || !found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if strings.Count(pinned, "node.id == abc123") != 1 {
		t.Fatalf("storage-node constraint was duplicated:\n%s", pinned)
	}
}

func TestPinNamedVolumesRejectsConflictingStorageNodeConstraint(t *testing.T) {
	for _, constraint := range []string{"node.id == attacker", "node.hostname==worker-1"} {
		source := "services:\n  database:\n    image: postgres:17\n    volumes: [data:/data]\n    deploy:\n      placement:\n        constraints: ['" + constraint + "']\nvolumes:\n  data: {}\n"
		if _, _, err := PinNamedVolumes(source, "abc123"); err == nil {
			t.Fatalf("constraint %q err=%v", constraint, err)
		}
	}
	if _, _, err := PinNamedVolumes("services: {db: {image: postgres, volumes: [data:/data]}}", "../node"); err == nil {
		t.Fatal("unsafe node ID was accepted")
	}
}

func TestCompileSafeModeReservesPlatformNetworkForRoutes(t *testing.T) {
	tests := map[string]string{
		"declared external": `services:
  app:
    image: alpine
networks:
  public:
    external: true
    name: public
`,
		"undeclared attachment": `services:
  app:
    image: alpine
    networks: [public]
`,
		"unrouted sidecar": `services:
  web:
    image: nginx
  sidecar:
    image: alpine
    networks: [public]
`,
	}
	for name, source := range tests {
		t.Run(name, func(t *testing.T) {
			routes := []store.Route(nil)
			if name == "unrouted sidecar" {
				routes = []store.Route{{ServiceName: "web", Host: "app.example.com", PathPrefix: "/", TargetPort: 80}}
			}
			if _, err := (Compiler{PublicNetwork: "public"}).Compile(source, routes); err == nil {
				t.Fatal("safe mode accepted caller access to the platform network")
			}
			if _, err := (Compiler{PublicNetwork: "public", AllowUnsafe: true}).Compile(source, routes); err != nil {
				t.Fatalf("unsafe mode rejected caller-managed network: %v", err)
			}
		})
	}
}

func TestCompileRejectsTraefikRuleInjection(t *testing.T) {
	c := Compiler{PublicNetwork: "public"}
	for _, route := range []store.Route{
		{ServiceName: "web", Host: "app.example.com`) || Host(`evil.example.com", PathPrefix: "/", TargetPort: 80, TLS: true, CertificateResolver: "letsencrypt"},
		{ServiceName: "web", Host: "app.example.com", PathPrefix: "/`) || PathPrefix(`/admin", TargetPort: 80, TLS: true, CertificateResolver: "letsencrypt"},
		{ServiceName: "web", Host: "app.example.com", PathPrefix: "/", TargetPort: 80, TLS: true, CertificateResolver: "bad resolver"},
		{ServiceName: "web", Host: "app.example.com", PathPrefix: "/", InternalPath: "relative", TargetPort: 80},
		{ServiceName: "web", Host: "app.example.com", PathPrefix: "/", RedirectRegex: "(", RedirectReplacement: "https://example.com", TargetPort: 80},
		{ServiceName: "web", Host: "app.example.com", PathPrefix: "/", RedirectRegex: "^https://example.com", TargetPort: 80},
		{ServiceName: "web", Host: "app.example.com", PathPrefix: "/", StripPath: true, TargetPort: 80},
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

func TestCompileCanonicalizesRouteHostname(t *testing.T) {
	out, err := (Compiler{PublicNetwork: "public"}).Compile("services:\n  web:\n    image: nginx\n", []store.Route{{ServiceName: "web", Host: " APP.Example.COM\n", PathPrefix: "/", TargetPort: 80}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Host(`app.example.com`)") || strings.Contains(out, "APP.Example.COM") {
		t.Fatalf("route hostname was not canonicalized: %s", out)
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
	for _, mode := range []string{"replicated-job"} {
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

func TestCompileSafeModeBoundsScheduledTasks(t *testing.T) {
	tests := map[string]string{
		"global service":       "services:\n  task:\n    image: busybox\n    deploy:\n      mode: global\n",
		"global job":           "services:\n  task:\n    image: busybox\n    deploy:\n      mode: global-job\n",
		"too many replicas":    "services:\n  app:\n    image: nginx\n    deploy:\n      replicas: 101\n",
		"non-integer replicas": "services:\n  app:\n    image: nginx\n    deploy:\n      replicas: many\n",
		"aggregate replicas":   "services:\n  api:\n    image: nginx\n    deploy:\n      replicas: 60\n  worker:\n    image: busybox\n    deploy:\n      replicas: 41\n",
	}
	for name, source := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := (Compiler{}).Compile(source, nil); err == nil {
				t.Fatalf("safe mode accepted unbounded scheduling:\n%s", source)
			}
			if _, err := (Compiler{AllowUnsafe: true}).Compile(source, nil); err != nil {
				t.Fatalf("explicit unsafe mode rejected scheduling request: %v", err)
			}
		})
	}
}

func TestCompileSafeModeAcceptsBoundedReplicas(t *testing.T) {
	source := "services:\n  api:\n    image: nginx\n    deploy:\n      replicas: 60\n  worker:\n    image: busybox\n    deploy:\n      replicas: 40\n"
	if _, err := (Compiler{}).Compile(source, nil); err != nil {
		t.Fatal(err)
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

func compiledNetworks(t *testing.T, compose string) map[string]any {
	t.Helper()
	var document map[string]any
	if err := yaml.Unmarshal([]byte(compose), &document); err != nil {
		t.Fatal(err)
	}
	networks, ok := stringMap(document["networks"])
	if !ok {
		t.Fatalf("compiled Compose has no networks: %s", compose)
	}
	return networks
}

func assertEncryptedOverlay(t *testing.T, networks map[string]any, name string) {
	t.Helper()
	network, ok := stringMap(networks[name])
	if !ok {
		t.Fatalf("compiled Compose has no %s network: %#v", name, networks)
	}
	if network["driver"] != "overlay" {
		t.Fatalf("network %s does not use overlay: %#v", name, network)
	}
	options, ok := stringMap(network["driver_opts"])
	if !ok || len(options) != 1 || options["encrypted"] != "" {
		t.Fatalf("network %s is not encrypted: %#v", name, network)
	}
}

func assertNetworkNames(t *testing.T, value any, expected ...string) {
	t.Helper()
	actual := networkNames(value)
	if strings.Join(actual, ",") != strings.Join(expected, ",") {
		t.Fatalf("unexpected networks: got %v, want %v", actual, expected)
	}
}
