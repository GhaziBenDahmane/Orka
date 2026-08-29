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
var safeHostname = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var safeCertificateResolver = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

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
		if err := applyRolloutDefaults(name, service); err != nil {
			return "", err
		}
		services[name] = service
	}
	if len(routes) > 0 {
		networks, ok := stringMap(doc["networks"])
		if doc["networks"] != nil && !ok {
			return "", errors.New("compose networks must be an object")
		}
		if networks == nil {
			networks = map[string]any{}
		}
		networks[c.PublicNetwork] = map[string]any{"external": true, "name": c.PublicNetwork}
		doc["networks"] = networks
	}
	for i, route := range routes {
		if err := ValidateRoute(route); err != nil {
			return "", err
		}
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
		networksValue, implicitDefault, networkErr := addServiceNetwork(service["networks"], c.PublicNetwork)
		if networkErr != nil {
			return "", fmt.Errorf("service %q: %w", route.ServiceName, networkErr)
		}
		service["networks"] = networksValue
		if implicitDefault {
			networks, _ := stringMap(doc["networks"])
			if networks == nil {
				networks = map[string]any{}
			}
			if _, exists := networks["default"]; !exists {
				networks["default"] = map[string]any{}
			}
			doc["networks"] = networks
		}
		services[route.ServiceName] = service
	}
	doc["services"] = services
	out, err := yaml.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("render compose yaml: %w", err)
	}
	return string(out), nil
}

func applyRolloutDefaults(name string, service map[string]any) error {
	deploy := map[string]any{}
	if raw, exists := service["deploy"]; exists && raw != nil {
		var ok bool
		deploy, ok = stringMap(raw)
		if !ok {
			return fmt.Errorf("service %q deploy must be an object", name)
		}
	}
	if mode, _ := deploy["mode"].(string); mode == "replicated-job" || mode == "global-job" {
		return nil
	}
	update, err := rolloutConfig(name, "update_config", deploy["update_config"])
	if err != nil {
		return err
	}
	setDefault(update, "parallelism", 1)
	setDefault(update, "order", "stop-first")
	setDefault(update, "failure_action", "rollback")
	setDefault(update, "monitor", "30s")
	deploy["update_config"] = update

	rollback, err := rolloutConfig(name, "rollback_config", deploy["rollback_config"])
	if err != nil {
		return err
	}
	setDefault(rollback, "parallelism", 1)
	setDefault(rollback, "order", "stop-first")
	setDefault(rollback, "monitor", "30s")
	deploy["rollback_config"] = rollback
	service["deploy"] = deploy
	return nil
}

func rolloutConfig(serviceName, field string, raw any) (map[string]any, error) {
	if raw == nil {
		return map[string]any{}, nil
	}
	config, ok := stringMap(raw)
	if !ok {
		return nil, fmt.Errorf("service %q deploy.%s must be an object", serviceName, field)
	}
	return config, nil
}

func setDefault(values map[string]any, key string, value any) {
	if _, exists := values[key]; !exists {
		values[key] = value
	}
}

func ValidateRoute(route store.Route) error {
	host := strings.ToLower(strings.TrimSpace(route.Host))
	if !safeName.MatchString(route.ServiceName) || len(host) > 253 || !safeHostname.MatchString(host) || route.TargetPort < 1 || route.TargetPort > 65535 {
		return errors.New("invalid route")
	}
	if route.PathPrefix == "" || !strings.HasPrefix(route.PathPrefix, "/") || len(route.PathPrefix) > 2048 || strings.ContainsAny(route.PathPrefix, "`\r\n") {
		return errors.New("invalid route")
	}
	if route.TLS && !safeCertificateResolver.MatchString(route.CertificateResolver) {
		return errors.New("invalid route")
	}
	return nil
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
	case []string:
		out = append(out, v...)
	case map[string]any:
		for s := range v {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
func addServiceNetwork(value any, network string) (any, bool, error) {
	if value == nil {
		return []string{"default", network}, true, nil
	}
	switch networks := value.(type) {
	case []any:
		for _, item := range networks {
			if _, ok := item.(string); !ok {
				return nil, false, errors.New("networks list must contain only names")
			}
		}
		return appendUnique(networkNames(networks), network), false, nil
	case []string:
		return appendUnique(networks, network), false, nil
	case map[string]any:
		if _, exists := networks[network]; !exists {
			networks[network] = map[string]any{}
		}
		return networks, false, nil
	default:
		return nil, false, errors.New("networks must be a list or object")
	}
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
