package deploy

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/bendahma/dokploy-go/internal/store"
	"gopkg.in/yaml.v3"
)

var safeName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
var safeHostname = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var safeCertificateResolver = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
var safeVolumeSource = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$`)
var safeLogSize = regexp.MustCompile(`^([1-9][0-9]*)([kKmMgG]?)$`)

const maxSafeTasksPerStack = 100
const maxSafeLogFileSize = 20 << 20
const maxSafeLogFiles = 5

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
	if !c.AllowUnsafe && len(services) > maxSafeTasksPerStack {
		return "", fmt.Errorf("safe compose stacks may schedule at most %d tasks", maxSafeTasksPerStack)
	}
	if !c.AllowUnsafe {
		if err := c.validateSafeDocument(doc); err != nil {
			return "", err
		}
	}
	scheduledTasks := 0
	for name, raw := range services {
		if !safeName.MatchString(name) {
			return "", fmt.Errorf("invalid compose service name %q", name)
		}
		service, ok := stringMap(raw)
		if !ok {
			return "", fmt.Errorf("service %q must be an object", name)
		}
		if !c.AllowUnsafe {
			if err := validateSafeService(name, service, c.PublicNetwork); err != nil {
				return "", err
			}
			replicas, err := safeServiceReplicas(name, service)
			if err != nil {
				return "", err
			}
			scheduledTasks += replicas
			if scheduledTasks > maxSafeTasksPerStack {
				return "", fmt.Errorf("safe compose stacks may schedule at most %d tasks", maxSafeTasksPerStack)
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
		route.Host = strings.ToLower(strings.TrimSpace(route.Host))
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
	if !c.AllowUnsafe {
		if err := c.encryptStackNetworks(doc); err != nil {
			return "", err
		}
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("render compose yaml: %w", err)
	}
	return string(out), nil
}

func safeServiceReplicas(name string, service map[string]any) (int, error) {
	deploy, valid := stringMap(service["deploy"])
	if service["deploy"] != nil && !valid {
		return 0, fmt.Errorf("service %q deploy must be an object", name)
	}
	mode := "replicated"
	if rawMode, exists := deploy["mode"]; exists {
		var ok bool
		mode, ok = rawMode.(string)
		if !ok {
			return 0, fmt.Errorf("service %q deploy mode must be a string", name)
		}
	}
	if mode == "global" || mode == "global-job" {
		return 0, fmt.Errorf("service %q requests unbounded %s scheduling", name, mode)
	}
	if mode != "replicated" && mode != "replicated-job" {
		return 0, fmt.Errorf("service %q requests unsupported deploy mode %q", name, mode)
	}
	replicas := 1
	if rawReplicas, exists := deploy["replicas"]; exists {
		var ok bool
		replicas, ok = rawReplicas.(int)
		if !ok {
			return 0, fmt.Errorf("service %q deploy replicas must be an integer", name)
		}
	}
	if replicas < 0 || replicas > maxSafeTasksPerStack {
		return 0, fmt.Errorf("service %q deploy replicas must be between 0 and %d", name, maxSafeTasksPerStack)
	}
	return replicas, nil
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

func validateSafeService(name string, service map[string]any, publicNetwork string) error {
	if value, _ := service["privileged"].(bool); value {
		return fmt.Errorf("service %q requests privileged mode", name)
	}
	for _, key := range []string{"pid", "ipc", "uts", "userns_mode", "cgroup"} {
		if value, exists := service[key]; exists && value != nil {
			return fmt.Errorf("service %q requests custom %s namespace access", name, key)
		}
	}
	if rawMode, exists := service["network_mode"]; exists && rawMode != nil {
		mode, valid := rawMode.(string)
		if !valid || mode != "none" {
			return fmt.Errorf("service %q requests custom network namespace access", name)
		}
	}
	for _, key := range []string{
		"devices", "device_cgroup_rules", "volumes_from", "gpus", "runtime", "isolation",
		"env_file", "label_file", "extends", "develop", "provider",
		"secrets", "configs", "credential_spec", "use_api_socket",
		"cgroup_parent", "storage_opt", "sysctls", "ulimits", "oom_kill_disable", "oom_score_adj",
		"scale", "models", "post_start", "pre_stop",
	} {
		if value, exists := service[key]; exists && value != nil {
			return fmt.Errorf("service %q requests forbidden %s access", name, key)
		}
	}
	if devices := nestedValue(service, "deploy", "resources", "reservations", "devices"); devices != nil {
		return fmt.Errorf("service %q requests reserved device access", name)
	}
	if resources := nestedValue(service, "deploy", "resources", "reservations", "generic_resources"); resources != nil {
		return fmt.Errorf("service %q requests reserved generic resource access", name)
	}
	if capabilities, exists := service["cap_add"]; exists && capabilities != nil {
		return fmt.Errorf("service %q requests added Linux capabilities", name)
	}
	if ports, exists := service["ports"]; exists && ports != nil {
		return fmt.Errorf("service %q requests direct port publishing", name)
	}
	if rawNetworks, exists := service["networks"]; exists && rawNetworks != nil {
		networks, err := validatedServiceNetworkNames(rawNetworks)
		if err != nil {
			return fmt.Errorf("service %q: %w", name, err)
		}
		for _, network := range networks {
			if publicNetwork != "" && network == publicNetwork {
				return fmt.Errorf("service %q requests platform-managed network %q", name, network)
			}
		}
	}
	if rawOptions, exists := service["security_opt"]; exists && rawOptions != nil {
		options, ok := rawOptions.([]any)
		if !ok {
			return fmt.Errorf("service %q security_opt must be a list", name)
		}
		for _, rawOption := range options {
			option, ok := rawOption.(string)
			if !ok {
				return fmt.Errorf("service %q security_opt must contain only strings", name)
			}
			normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(option), "=", ":"))
			if normalized != "no-new-privileges:true" {
				return fmt.Errorf("service %q requests unsafe security option %q", name, option)
			}
		}
	}
	if err := validateSafeLogging(name, service["logging"]); err != nil {
		return err
	}
	for _, rawLabels := range []any{service["labels"], nestedValue(service, "deploy", "labels")} {
		for _, label := range labelNames(rawLabels) {
			if strings.HasPrefix(strings.ToLower(label), "traefik.") {
				return fmt.Errorf("service %q requests platform-managed Traefik label %q", name, label)
			}
		}
	}
	volumes, err := safeServiceVolumes(service["volumes"])
	if err != nil {
		return fmt.Errorf("service %q: %w", name, err)
	}
	for _, volume := range volumes {
		if spec, ok := stringMap(volume); ok {
			kind, valid := spec["type"].(string)
			if !valid || (kind != "volume" && kind != "tmpfs") {
				return fmt.Errorf("service %q requests forbidden mount type", name)
			}
			source, sourceExists := spec["source"].(string)
			if spec["source"] != nil && !sourceExists {
				return fmt.Errorf("service %q volume source must be a string", name)
			}
			if kind == "tmpfs" && source != "" {
				return fmt.Errorf("service %q tmpfs mount requests a source", name)
			}
			if kind == "volume" && source != "" && !safeVolumeSource.MatchString(source) {
				return fmt.Errorf("service %q requests forbidden bind mount %q", name, source)
			}
			continue
		}
		text, ok := volume.(string)
		if !ok {
			return fmt.Errorf("service %q volume must be a string or object", name)
		}
		parts := strings.SplitN(text, ":", 2)
		if len(parts) == 1 {
			continue
		}
		source := parts[0]
		if !safeVolumeSource.MatchString(source) {
			return fmt.Errorf("service %q requests forbidden host mount %q", name, source)
		}
	}
	return nil
}

func validateSafeLogging(serviceName string, raw any) error {
	if raw == nil {
		return nil
	}
	logging, valid := stringMap(raw)
	if !valid {
		return fmt.Errorf("service %q logging must be an object", serviceName)
	}
	driver := ""
	if rawDriver, exists := logging["driver"]; exists {
		var ok bool
		driver, ok = rawDriver.(string)
		if !ok {
			return fmt.Errorf("service %q logging driver must be a string", serviceName)
		}
	}
	if driver != "" && driver != "json-file" && driver != "local" && driver != "none" {
		return fmt.Errorf("service %q requests external logging driver %q", serviceName, driver)
	}
	rawOptions, hasOptions := logging["options"]
	if !hasOptions || rawOptions == nil {
		return nil
	}
	options, valid := stringMap(rawOptions)
	if !valid || driver == "" || driver == "none" {
		return fmt.Errorf("service %q logging options require a local or json-file driver", serviceName)
	}
	for key, value := range options {
		if key != "max-size" && key != "max-file" && key != "compress" {
			return fmt.Errorf("service %q requests unsafe logging option %q", serviceName, key)
		}
		text, isString := value.(string)
		if !isString {
			return fmt.Errorf("service %q logging option %q must be a string", serviceName, key)
		}
		switch key {
		case "max-size":
			matches := safeLogSize.FindStringSubmatch(text)
			if matches == nil {
				return fmt.Errorf("service %q logging max-size is invalid", serviceName)
			}
			size, err := strconv.ParseInt(matches[1], 10, 64)
			if err != nil {
				return fmt.Errorf("service %q logging max-size is invalid", serviceName)
			}
			multiplier := int64(1)
			switch strings.ToLower(matches[2]) {
			case "k":
				multiplier = 1 << 10
			case "m":
				multiplier = 1 << 20
			case "g":
				multiplier = 1 << 30
			}
			if size < 1 || size > maxSafeLogFileSize/multiplier {
				return fmt.Errorf("service %q logging max-size must not exceed 20 MiB", serviceName)
			}
		case "max-file":
			files, err := strconv.Atoi(text)
			if err != nil || files < 1 || files > maxSafeLogFiles {
				return fmt.Errorf("service %q logging max-file must be between 1 and %d", serviceName, maxSafeLogFiles)
			}
		case "compress":
			if text != "true" && text != "false" {
				return fmt.Errorf("service %q logging compress must be true or false", serviceName)
			}
		}
	}
	return nil
}

func (c Compiler) validateSafeDocument(document map[string]any) error {
	for _, key := range []string{"secrets", "configs", "include", "models"} {
		if value, exists := document[key]; exists && value != nil {
			return fmt.Errorf("compose document requests forbidden top-level %s", key)
		}
	}
	volumes, volumesValid := stringMap(document["volumes"])
	if document["volumes"] != nil && !volumesValid {
		return errors.New("compose volumes must be an object")
	}
	if volumesValid {
		for name, raw := range volumes {
			spec, valid := stringMap(raw)
			if raw != nil && !valid {
				return fmt.Errorf("volume %q must be an object", name)
			}
			if external, exists := spec["external"]; exists {
				externalValue, valid := external.(bool)
				if !valid || externalValue {
					return fmt.Errorf("volume %q requests cross-stack external access", name)
				}
			}
			for _, key := range []string{"name", "driver_opts"} {
				if value, exists := spec[key]; exists && value != nil {
					return fmt.Errorf("volume %q requests forbidden %s", name, key)
				}
			}
			if driver, exists := spec["driver"]; exists {
				driverName, valid := driver.(string)
				if !valid || driverName != "local" {
					return fmt.Errorf("volume %q requests a non-local driver", name)
				}
			}
		}
	}
	if networks, ok := stringMap(document["networks"]); ok {
		for name, raw := range networks {
			if c.PublicNetwork != "" && name == c.PublicNetwork {
				return fmt.Errorf("network %q is managed by the platform", name)
			}
			spec, valid := stringMap(raw)
			if raw != nil && !valid {
				return fmt.Errorf("network %q must be an object", name)
			}
			externalValue, hasExternal := spec["external"]
			external, externalValid := externalValue.(bool)
			if hasExternal && !externalValid {
				return fmt.Errorf("network %q has an invalid external declaration", name)
			}
			_, hasName := spec["name"]
			if external || hasName {
				return fmt.Errorf("network %q requests cross-stack external access", name)
			}
		}
	}
	return nil
}

func safeServiceVolumes(value any) ([]any, error) {
	if value == nil {
		return nil, nil
	}
	volumes, valid := value.([]any)
	if !valid {
		return nil, errors.New("volumes must be a list")
	}
	return volumes, nil
}

func validatedServiceNetworkNames(value any) ([]string, error) {
	switch networks := value.(type) {
	case []any:
		names := make([]string, 0, len(networks))
		for _, rawName := range networks {
			name, valid := rawName.(string)
			if !valid {
				return nil, errors.New("networks list must contain only names")
			}
			names = append(names, name)
		}
		return names, nil
	case []string:
		return networks, nil
	case map[string]any:
		names := make([]string, 0, len(networks))
		for name := range networks {
			names = append(names, name)
		}
		return names, nil
	default:
		return nil, errors.New("networks must be a list or object")
	}
}

func (c Compiler) encryptStackNetworks(document map[string]any) error {
	networks, ok := stringMap(document["networks"])
	if document["networks"] != nil && !ok {
		return errors.New("compose networks must be an object")
	}
	if networks == nil {
		networks = map[string]any{}
	}
	if servicesUseDefaultNetwork(document["services"]) {
		if _, exists := networks["default"]; !exists {
			networks["default"] = map[string]any{}
		}
	}
	for name, raw := range networks {
		spec, valid := stringMap(raw)
		if raw != nil && !valid {
			return fmt.Errorf("network %q must be an object", name)
		}
		if spec == nil {
			spec = map[string]any{}
		}
		if external, _ := spec["external"].(bool); external {
			continue
		}
		if driver, exists := spec["driver"]; exists {
			driverName, valid := driver.(string)
			if !valid || driverName != "overlay" {
				return fmt.Errorf("network %q must use the overlay driver", name)
			}
		}
		if rawOptions, exists := spec["driver_opts"]; exists {
			options, valid := stringMap(rawOptions)
			if !valid || len(options) != 1 || options["encrypted"] != "" {
				return fmt.Errorf("network %q requests unsafe driver options", name)
			}
		}
		spec["driver"] = "overlay"
		spec["driver_opts"] = map[string]any{"encrypted": ""}
		networks[name] = spec
	}
	document["networks"] = networks
	return nil
}

func servicesUseDefaultNetwork(rawServices any) bool {
	services, _ := stringMap(rawServices)
	for _, rawService := range services {
		service, _ := stringMap(rawService)
		if mode, _ := service["network_mode"].(string); mode == "none" {
			continue
		}
		rawNetworks, exists := service["networks"]
		if !exists || rawNetworks == nil {
			return true
		}
		for _, name := range networkNames(rawNetworks) {
			if name == "default" {
				return true
			}
		}
	}
	return false
}

func nestedValue(value map[string]any, keys ...string) any {
	var current any = value
	for _, key := range keys {
		mapping, ok := stringMap(current)
		if !ok {
			return nil
		}
		current = mapping[key]
	}
	return current
}

func stringValues(value any) []string {
	values := []string{}
	for _, item := range anySlice(value) {
		if text, ok := item.(string); ok {
			values = append(values, text)
		}
	}
	return values
}

func labelNames(value any) []string {
	names := []string{}
	if labels, ok := stringMap(value); ok {
		for name := range labels {
			names = append(names, name)
		}
		return names
	}
	for _, label := range stringValues(value) {
		name, _, _ := strings.Cut(label, "=")
		names = append(names, strings.TrimSpace(name))
	}
	return names
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
