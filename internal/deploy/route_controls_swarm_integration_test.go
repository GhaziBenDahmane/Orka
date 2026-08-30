package deploy

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/store"
)

func TestRouteControlsDeployAsSwarmLabels(t *testing.T) {
	if os.Getenv("DOCKYARD_TEST_SWARM") != "1" {
		t.Skip("DOCKYARD_TEST_SWARM is not set")
	}
	image := os.Getenv("DOCKYARD_TEST_SWARM_PROBE_IMAGE")
	if image == "" {
		image = "node@sha256:e67514e5d0f6c46656005e1b693b2ec9d52e80b641307de684d4a015ba7a4eaf"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	suffix := strings.ToLower(time.Now().Format("150405"))
	network, stack := "route-net-"+suffix, "route-live-"+suffix
	swarm := Swarm{DockerBin: "docker", Network: network, Timeout: time.Minute}
	if _, err := swarm.run(ctx, "network", "create", "--driver", "overlay", "--attachable", "--opt", "encrypted", network); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
		defer cleanupCancel()
		_, _ = swarm.Remove(cleanupCtx, stack)
		for range 30 {
			if _, err := swarm.run(cleanupCtx, "network", "rm", network); err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	})
	route := store.Route{ServiceName: "web", Host: "route.example.test", PathPrefix: "/public", InternalPath: "/internal", StripPath: true, RedirectRegex: `^https://route\.example\.test/old/(.*)`, RedirectReplacement: `https://route.example.test/new/${1}`, BasicAuthUsers: []string{`operator:$2a$12$C6UzMDM.H6dfI/f/IKxGhuVvZ4GuGNmi1wT7dSx.QcpQo.eN8wxQe`}, TargetPort: 8080, TLS: true, CertificateResolver: "letsencrypt"}
	compose, err := (Compiler{PublicNetwork: network}).Compile("services:\n  web:\n    image: "+image+"\n    command: [node, -e, 'setInterval(() => {}, 60000)']\n", []store.Route{route})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = swarm.Deploy(ctx, stack, compose, nil, nil); err != nil {
		t.Fatal(err)
	}
	output, err := swarm.run(ctx, "service", "inspect", stack+"_web", "--format", "{{json .Spec.Labels}}")
	if err != nil {
		t.Fatal(err)
	}
	labels := map[string]string{}
	if err = json.Unmarshal([]byte(strings.TrimSpace(output)), &labels); err != nil {
		t.Fatal(err)
	}
	if got := labels["traefik.http.middlewares.dockyard-0-route-example-test-redirect.redirectregex.replacement"]; got != `https://route.example.test/new/${1}` {
		t.Fatalf("redirect replacement=%q", got)
	}
	if got := labels["traefik.http.middlewares.dockyard-0-route-example-test-basic-auth.basicauth.users"]; !strings.HasPrefix(got, "operator:$2a$12$") {
		t.Fatalf("basic-auth label=%q", got)
	}
	if got := labels["traefik.http.routers.dockyard-0-route-example-test.middlewares"]; got != "dockyard-0-route-example-test-strip-path,dockyard-0-route-example-test-internal-path,dockyard-0-route-example-test-redirect,dockyard-0-route-example-test-basic-auth" {
		t.Fatalf("middleware chain=%q", got)
	}
}
