package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

func TestPlatformRoutesUseTheExpectedAuthenticationBoundary(t *testing.T) {
	routes := registeredRoutes(t, "server.go", "Handler")
	for pattern, wrapper := range routes {
		_, path, ok := strings.Cut(pattern, " ")
		if !ok {
			t.Errorf("route %q does not include an HTTP method", pattern)
			continue
		}
		switch {
		case path == "/metrics":
			if wrapper != "requireMetricsAuth" {
				t.Errorf("%s uses %s, want requireMetricsAuth", pattern, wrapper)
			}
		case isDirectPublicRoute(path):
			if wrapper != "direct" {
				t.Errorf("public route %s unexpectedly uses %s", pattern, wrapper)
			}
		case strings.HasPrefix(path, "/scim/v2/"):
			if wrapper != "direct" {
				t.Errorf("SCIM route %s unexpectedly uses %s instead of its SCIM token boundary", pattern, wrapper)
			}
		case strings.HasPrefix(path, "/v1/"):
			if wrapper != "requireAuth" && wrapper != "requireRole" && wrapper != "requireResourceRole" && wrapper != "requireAuditor" {
				t.Errorf("protected route %s has no recognized tenant authentication wrapper (got %s)", pattern, wrapper)
			}
		}
	}
}

func TestAgentRoutesRemainOnTheDedicatedMTLSHandler(t *testing.T) {
	platformRoutes := registeredRoutes(t, "server.go", "Handler")
	agentRoutes := registeredRoutes(t, "clusters.go", "AgentHandler")
	if len(agentRoutes) == 0 {
		t.Fatal("agent handler has no registered routes")
	}
	for pattern, wrapper := range agentRoutes {
		_, path, ok := strings.Cut(pattern, " ")
		if !ok || !strings.HasPrefix(path, "/v1/agent/") || path == "/v1/agent/enroll" {
			t.Errorf("unexpected route %q on the agent mTLS handler", pattern)
		}
		if wrapper != "direct" {
			t.Errorf("agent route %s unexpectedly uses HTTP bearer middleware %s", pattern, wrapper)
		}
		if _, exposed := platformRoutes[pattern]; exposed {
			t.Errorf("agent mTLS route %s is also registered on the public platform handler", pattern)
		}
	}
}

func isDirectPublicRoute(path string) bool {
	if path == "/healthz" || path == "/readyz" || path == "/v1/auth/bootstrap" || path == "/v1/auth/login" || path == "/v1/invitations/accept" || path == "/v1/agent/enroll" || path == "/scim/v2/ServiceProviderConfig" {
		return true
	}
	return strings.HasPrefix(path, "/v1/auth/sso/") || strings.HasPrefix(path, "/v1/auth/saml/") || strings.HasPrefix(path, "/v1/hooks/")
}

func registeredRoutes(t *testing.T, filename, methodName string) map[string]string {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	routes := map[string]string{}
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != methodName || function.Body == nil {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || len(call.Args) < 2 {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (selector.Sel.Name != "Handle" && selector.Sel.Name != "HandleFunc") {
				return true
			}
			literal, ok := call.Args[0].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			pattern, unquoteErr := strconv.Unquote(literal.Value)
			if unquoteErr != nil {
				t.Errorf("decode route pattern %s: %v", literal.Value, unquoteErr)
				return true
			}
			wrapper := "direct"
			if selector.Sel.Name == "Handle" {
				if middleware, ok := call.Args[1].(*ast.CallExpr); ok {
					if middlewareSelector, ok := middleware.Fun.(*ast.SelectorExpr); ok {
						wrapper = middlewareSelector.Sel.Name
					}
				}
			}
			if previous, duplicate := routes[pattern]; duplicate {
				t.Errorf("route %s is registered more than once (%s and %s)", pattern, previous, wrapper)
			}
			routes[pattern] = wrapper
			return false
		})
	}
	if len(routes) == 0 {
		t.Fatalf("no routes found in %s.%s", filename, methodName)
	}
	return routes
}
