package deploy

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/bendahma/dokploy-go/internal/store"
	"gopkg.in/yaml.v3"
)

var safeName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

type Compiler struct {
	PublicNetwork string
	AllowUnsafe   bool
}

func (c Compiler) Compile(source string, routes []store.Route) (string, error) {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(source), &doc); err != nil {
		return "", fmt.Errorf("parse compose yaml: %w", err)
	}
	services, ok := stringMap(doc["services"])
	if !ok || len(services) == 0 {
		return "", errors.New("compose document must define at least one service")
	}
	for name, raw := range services {
		if !safeName.MatchString(name) {
			return "", fmt.Errorf("invalid compose service name %q", name)
		}
		service, ok := stringMap(raw)
		if !ok {
			return "", fmt.Errorf("service %q must be an object", name)
		}
		if !c.AllowUnsafe {
			if err := validateSafeService(name, service); err != nil {
				return "", err
			}
		}
	}
	if len(routes) > 0 {
		networks, _ := stringMap(doc["networks"])
		if networks == nil {
			networks = map[string]any{}
		}
		networks[c.PublicNetwork] = map[string]any{"external": true, "name": c.PublicNetwork}
		doc["networks"] = networks
	}
	for i, route := range routes {
		service, ok := stringMap(services[route.ServiceName])
		if !ok {
			return "", fmt.Errorf("route references missing service %q", route.ServiceName)
		}
		deploy, _ := stringMap(service["deploy"])
		if deploy == nil {
			deploy = map[string]any{}
		}
		labels := normalizeLabels(deploy["labels"])
		key := fmt.Sprintf("dockyard-%d-%s", i, sanitize(route.Host))
		rule := fmt.Sprintf("Host(`%s`)", route.Host)
		if route.PathPrefix != "" && route.PathPrefix != "/" {
			rule += fmt.Sprintf(" && PathPrefix(`%s`)", route.PathPrefix)
		}
		labels["traefik.enable"] = "true"
		labels["traefik.http.routers."+key+".rule"] = rule
		labels["traefik.http.routers."+key+".entrypoints"] = map[bool]string{true: "websecure", false: "web"}[route.TLS]
		labels["traefik.http.services."+key+".loadbalancer.server.port"] = fmt.Sprint(route.TargetPort)
		labels["traefik.docker.network"] = c.PublicNetwork
		if route.TLS {
			labels["traefik.http.routers."+key+".tls"] = "true"
			labels["traefik.http.routers."+key+".tls.certresolver"] = route.CertificateResolver
		}
		deploy["labels"] = labels
		service["deploy"] = deploy
		service["networks"] = appendUnique(networkNames(service["networks"]), c.PublicNetwork)
		services[route.ServiceName] = service
	}
	doc["services"] = services
	out, err := yaml.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("render compose yaml: %w", err)
	}
	return string(out), nil
}

func validateSafeService(name string, service map[string]any) error {
	if value, _ := service["privileged"].(bool); value {
		return fmt.Errorf("service %q requests privileged mode", name)
	}
	for _, key := range []string{"pid", "ipc"} {
		if value, _ := service[key].(string); value == "host" {
			return fmt.Errorf("service %q requests host %s", name, key)
		}
	}
	if value, _ := service["network_mode"].(string); value == "host" {
		return fmt.Errorf("service %q requests host networking", name)
	}
	for _, volume := range anySlice(service["volumes"]) {
		if spec, ok := stringMap(volume); ok {
			kind, _ := spec["type"].(string)
			source, _ := spec["source"].(string)
			if kind == "bind" || strings.HasPrefix(source, "/") {
				return fmt.Errorf("service %q requests forbidden bind mount %q", name, source)
			}
		}
		text, ok := volume.(string)
		if !ok {
			continue
		}
		source := strings.SplitN(text, ":", 2)[0]
		if source == "/var/run/docker.sock" || strings.HasPrefix(source, "/") || strings.HasPrefix(source, ".") {
			return fmt.Errorf("service %q requests forbidden host mount %q", name, source)
		}
	}
	return nil
}

func stringMap(value any) (map[string]any, bool) { v, ok := value.(map[string]any); return v, ok }
func anySlice(value any) []any                   { v, _ := value.([]any); return v }
func normalizeLabels(value any) map[string]any {
	if labels, ok := stringMap(value); ok {
		return labels
	}
	labels := map[string]any{}
	for _, item := range anySlice(value) {
		if text, ok := item.(string); ok {
			parts := strings.SplitN(text, "=", 2)
			if len(parts) == 2 {
				labels[parts[0]] = parts[1]
			}
		}
	}
	return labels
}
func networkNames(value any) []string {
	out := []string{}
	switch v := value.(type) {
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	case map[string]any:
		for s := range v {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
func appendUnique(items []string, item string) []string {
	for _, v := range items {
		if v == item {
			return items
		}
	}
	return append(items, item)
}
func sanitize(value string) string {
	value = strings.ToLower(value)
	value = regexp.MustCompile(`[^a-z0-9-]+`).ReplaceAllString(value, "-")
	return strings.Trim(value, "-")
}
