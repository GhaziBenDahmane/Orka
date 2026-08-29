package deploy

import (
	"strings"
	"testing"

	"github.com/bendahma/dokploy-go/internal/store"
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
