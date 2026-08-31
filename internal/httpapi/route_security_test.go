package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
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
			if wrapper != "rateLimitSCIM" {
				t.Errorf("SCIM route %s uses %s, want the pre-authentication SCIM rate-limit boundary", pattern, wrapper)
			}
		case strings.HasPrefix(path, "/v1/"):
			if wrapper != "requireAuth" && wrapper != "requireRole" && wrapper != "requireResourceRole" && wrapper != "requireAuditor" {
				t.Errorf("protected route %s has no recognized tenant authentication wrapper (got %s)", pattern, wrapper)
			}
		}
	}
}

func TestAuthorizationMiddlewareArgumentsAreValid(t *testing.T) {
	parsed, err := parser.ParseFile(token.NewFileSet(), "server.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(parsed, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Handle" || len(call.Args) < 2 {
			return true
		}
		pattern, ok := stringLiteral(call.Args[0])
		if !ok {
			return true
		}
		middleware, ok := call.Args[1].(*ast.CallExpr)
		if !ok {
			return true
		}
		middlewareSelector, ok := middleware.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch middlewareSelector.Sel.Name {
		case "requireRole":
			role, literal := middlewareStringArgument(middleware, 0)
			if !literal || !validAuthorizationRole(role) {
				t.Errorf("route %s has invalid requireRole minimum %q", pattern, role)
			}
		case "requireResourceRole":
			role, roleLiteral := middlewareStringArgument(middleware, 0)
			resource, resourceLiteral := middlewareStringArgument(middleware, 1)
			parameter, parameterLiteral := middlewareStringArgument(middleware, 2)
			if !roleLiteral || !validAuthorizationRole(role) {
				t.Errorf("route %s has invalid requireResourceRole minimum %q", pattern, role)
			}
			if !resourceLiteral || !validAuthorizationResource(resource) {
				t.Errorf("route %s has invalid authorization resource %q", pattern, resource)
			}
			if !parameterLiteral || !strings.Contains(pattern, "{"+parameter+"}") {
				t.Errorf("route %s authorization parameter %q is absent from its path", pattern, parameter)
			}
		}
		return true
	})
}

func TestAuthorizationMiddlewareRejectsInvalidConfiguration(t *testing.T) {
	server := &Server{}
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	tests := map[string]func(){
		"empty organization role":   func() { server.requireRole("", handler) },
		"unknown organization role": func() { server.requireRole("superadmin", handler) },
		"auditor organization role": func() { server.requireRole("auditor", handler) },
		"empty resource role":       func() { server.requireResourceRole("", "service", "serviceID", handler) },
		"unknown resource role":     func() { server.requireResourceRole("superadmin", "service", "serviceID", handler) },
		"unknown resource type":     func() { server.requireResourceRole("viewer", "cluster", "clusterID", handler) },
		"empty path parameter":      func() { server.requireResourceRole("viewer", "service", "", handler) },
	}
	for name, construct := range tests {
		t.Run(name, func(t *testing.T) {
			deferred := false
			func() {
				defer func() { deferred = recover() != nil }()
				construct()
			}()
			if !deferred {
				t.Fatal("invalid authorization middleware configuration did not panic")
			}
		})
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
	if isPublicSCIMDiscovery(path) {
		return true
	}
	switch path {
	case "/healthz", "/readyz",
		"/v1/auth/bootstrap", "/v1/auth/login", "/v1/invitations/accept",
		"/v1/auth/sso/discover", "/v1/auth/sso/{providerID}/start", "/v1/auth/sso/callback",
		"/v1/auth/saml/discover", "/v1/auth/saml/{providerID}/metadata", "/v1/auth/saml/{providerID}/start", "/v1/auth/saml/{providerID}/acs",
		"/v1/hooks/deploy/{token}", "/v1/hooks/provider/{integrationID}", "/v1/hooks/template-repositories/{repositoryID}",
		"/v1/agent/enroll":
		return true
	default:
		return false
	}
}

func isPublicSCIMDiscovery(path string) bool {
	return path == "/scim/v2/ServiceProviderConfig" || path == "/scim/v2/Schemas" || strings.HasPrefix(path, "/scim/v2/Schemas/") || path == "/scim/v2/ResourceTypes" || strings.HasPrefix(path, "/scim/v2/ResourceTypes/")
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

func middlewareStringArgument(call *ast.CallExpr, index int) (string, bool) {
	if index >= len(call.Args) {
		return "", false
	}
	return stringLiteral(call.Args[index])
}

func stringLiteral(expression ast.Expr) (string, bool) {
	literal, ok := expression.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(literal.Value)
	return value, err == nil
}
