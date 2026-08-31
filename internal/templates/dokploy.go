package templates

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bendahma/dokploy-go/internal/deploy"
	"github.com/google/uuid"
	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

type DokployTemplate struct {
	Variables map[string]string `toml:"variables"`
	Config    struct {
		Domains []Domain `toml:"domains"`
		Env     any      `toml:"env"`
		Mounts  []Mount  `toml:"mounts"`
	} `toml:"config"`
}
type Domain struct {
	ServiceName string `toml:"serviceName"`
	Port        any    `toml:"port"`
	Host        string `toml:"host"`
	Path        string `toml:"path"`
}
type Mount struct {
	FilePath string `toml:"filePath"`
	Content  string `toml:"content"`
}
type Instance struct {
	ComposeYAML string
	Environment map[string]string
	Domains     []Domain
	Mounts      []Mount
	Variables   map[string]string
}

type Preview struct {
	Services        []PreviewService `json:"services"`
	Routes          []PreviewRoute   `json:"routes"`
	EnvironmentKeys []string         `json:"environmentKeys"`
	ManagedFiles    int              `json:"managedFiles"`
}
type PreviewService struct {
	Name  string `json:"name"`
	Image string `json:"image,omitempty"`
}
type PreviewRoute struct {
	ServiceName string `json:"serviceName"`
	Host        string `json:"host"`
	Path        string `json:"path"`
	TargetPort  int    `json:"targetPort"`
}

type VariableDescriptor struct {
	Name      string `json:"name"`
	Default   string `json:"default,omitempty"`
	Generated bool   `json:"generated"`
	Sensitive bool   `json:"sensitive"`
}

const (
	maxTemplateVariables      = 128
	maxVariableNameBytes      = 128
	maxVariableValueBytes     = 8 << 10
	maxVariableTotalBytes     = 64 << 10
	maxResolvedValueBytes     = 512 << 10
	maxResolvedVariablesBytes = 1 << 20
	maxExpressionsPerValue    = 256
)

var sensitiveVariableName = regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|encryption[_-]?key|signing[_-]?key|credential|auth|salt)`)

// DescribeVariables returns the operator-editable template inputs without ever
// resolving generators or disclosing literal values that look secret.
func DescribeVariables(template DokployTemplate) []VariableDescriptor {
	sensitiveVariables := classifySensitiveVariables(template.Variables)
	descriptors := make([]VariableDescriptor, 0, len(template.Variables))
	for name, value := range template.Variables {
		generated := expression.MatchString(value)
		sensitive := sensitiveVariables[name]
		descriptor := VariableDescriptor{Name: name, Generated: generated, Sensitive: sensitive}
		if !generated && !sensitive {
			descriptor.Default = value
		}
		descriptors = append(descriptors, descriptor)
	}
	sort.Slice(descriptors, func(i, j int) bool { return descriptors[i].Name < descriptors[j].Name })
	return descriptors
}

func classifySensitiveVariables(variables map[string]string) map[string]bool {
	sensitive := make(map[string]bool, len(variables))
	for name, value := range variables {
		sensitive[name] = sensitiveVariableName.MatchString(name) || containsSensitiveGenerator(value)
	}
	for changed := true; changed; {
		changed = false
		for name, value := range variables {
			if sensitive[name] {
				continue
			}
			for _, match := range expression.FindAllStringSubmatch(value, -1) {
				if sensitive[strings.SplitN(match[1], ":", 2)[0]] {
					sensitive[name] = true
					changed = true
					break
				}
			}
		}
	}
	return sensitive
}

func containsSensitiveGenerator(value string) bool {
	for _, match := range expression.FindAllStringSubmatch(value, -1) {
		helper := strings.SplitN(match[1], ":", 2)[0]
		switch helper {
		case "password", "base64", "hash", "jwt", "basicAuth":
			return true
		}
	}
	return false
}

// UpgradeOverrides keeps explicit operator choices and stable generated values
// that still exist in a target template. Derived variables are recomputed so a
// changed dependency cannot leave stale connection strings or URLs behind.
func UpgradeOverrides(template DokployTemplate, resolved, savedOverrides, requested map[string]string) map[string]string {
	result := map[string]string{}
	for key, value := range savedOverrides {
		if _, declared := template.Variables[key]; declared {
			result[key] = value
		}
	}
	for key, definition := range template.Variables {
		if _, explicitlySet := result[key]; explicitlySet || !directGenerator.MatchString(definition) {
			continue
		}
		if value, ok := resolved[key]; ok {
			result[key] = value
		}
	}
	for key, value := range requested {
		result[key] = value
	}
	return result
}

var directGenerator = regexp.MustCompile(`^\$\{(?:domain|password(?::[0-9]+)?|base64(?::[0-9]+)?|hash(?::[0-9]+)?|uuid|timestamp|timestampms(?::[^}]+)?|timestamps(?::[^}]+)?|randomPort|email|username(?::[0-9]+)?|jwt(?::[^}]+)?)\}$`)

// DescribeInstance exposes only deploy topology. It deliberately omits
// environment values, commands, and inline mount contents; resolved routes are
// included because they are public ingress addresses after deployment.
func DescribeInstance(instance Instance) (Preview, error) {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(instance.ComposeYAML), &doc); err != nil {
		return Preview{}, err
	}
	services, ok := doc["services"].(map[string]any)
	if !ok || len(services) == 0 {
		return Preview{}, fmt.Errorf("compose document has no services")
	}
	preview := Preview{}
	for name, raw := range services {
		service, _ := raw.(map[string]any)
		image, _ := service["image"].(string)
		preview.Services = append(preview.Services, PreviewService{Name: name, Image: image})
	}
	sort.Slice(preview.Services, func(i, j int) bool { return preview.Services[i].Name < preview.Services[j].Name })
	for _, domain := range instance.Domains {
		port, err := PortNumber(domain.Port)
		if err != nil {
			return Preview{}, err
		}
		preview.Routes = append(preview.Routes, PreviewRoute{ServiceName: domain.ServiceName, Host: domain.Host, Path: domain.Path, TargetPort: port})
	}
	for key := range instance.Environment {
		if strings.HasPrefix(key, deploy.InlineFileEnvironmentPrefix) {
			continue
		}
		preview.EnvironmentKeys = append(preview.EnvironmentKeys, key)
	}
	sort.Strings(preview.EnvironmentKeys)
	preview.ManagedFiles = len(instance.Mounts)
	return preview, nil
}

func LoadDokployDirectory(path, baseDomain string) (Instance, error) {
	tomlBytes, err := os.ReadFile(filepath.Join(path, "template.toml"))
	if err != nil {
		return Instance{}, err
	}
	compose, err := os.ReadFile(filepath.Join(path, "docker-compose.yml"))
	if err != nil {
		return Instance{}, err
	}
	template, err := ParseDokploy(tomlBytes)
	if err != nil {
		return Instance{}, fmt.Errorf("parse template.toml: %w", err)
	}
	instance, err := Instantiate(template, string(compose), baseDomain)
	if err != nil {
		return Instance{}, err
	}
	instance.ComposeYAML, err = ApplyMounts(instance.ComposeYAML, instance.Mounts, instance.Environment)
	return instance, err
}

func ParseDokploy(data []byte) (DokployTemplate, error) {
	data = []byte(strings.ReplaceAll(string(data), `\${`, "__DOCKYARD_ESCAPED_DOLLAR__{"))
	data = []byte(strings.ReplaceAll(string(data), `\$`, "__DOCKYARD_ESCAPED_DOLLAR__"))
	data = []byte(strings.ReplaceAll(string(data), `\{`, "__DOCKYARD_BACKSLASH_BRACE__"))
	data = escapeInvalidTOMLSequences(data)
	if bytes.Contains(data, []byte("[[config.mounts]]")) {
		data = regexp.MustCompile(`(?m)^\s*mounts\s*=\s*\[\s*\]\s*$`).ReplaceAll(data, nil)
	}
	var template DokployTemplate
	err := toml.Unmarshal(data, &template)
	return template, err
}

func escapeInvalidTOMLSequences(data []byte) []byte {
	out := make([]byte, 0, len(data))
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' || i+1 >= len(data) {
			out = append(out, data[i])
			continue
		}
		next := data[i+1]
		if strings.ContainsRune(`btnfr"\/uU`, rune(next)) {
			out = append(out, data[i], next)
			i++
			continue
		}
		out = append(out, '\\', '\\')
	}
	return out
}

func PortNumber(value any) (int, error) {
	switch v := value.(type) {
	case int64:
		return int(v), nil
	case int:
		return v, nil
	case string:
		n, err := strconv.Atoi(v)
		return n, err
	default:
		return 0, fmt.Errorf("invalid port %v", value)
	}
}

// ApplyMounts replaces Dokploy's manager-local ../files bind mounts with Swarm
// configs. Persisted Compose contains only references; contents are added to the
// encrypted environment and materialized immediately before stack deployment.
func ApplyMounts(compose string, mounts []Mount, environment map[string]string) (string, error) {
	if len(mounts) == 0 {
		return compose, nil
	}
	if environment == nil {
		return "", errors.New("template managed files require an environment map")
	}
	if len(mounts) > deploy.MaxInlineFiles {
		return "", fmt.Errorf("template has too many managed files (maximum %d)", deploy.MaxInlineFiles)
	}
	for name := range environment {
		if strings.HasPrefix(name, deploy.InlineFileEnvironmentPrefix) {
			return "", errors.New("template environment uses the reserved managed-file prefix")
		}
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(compose), &doc); err != nil {
		return "", err
	}
	services, ok := doc["services"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("compose document has no services")
	}
	configs, _ := doc["configs"].(map[string]any)
	if configs == nil {
		configs = map[string]any{}
	}
	inline := map[string]any{}
	seenMounts := map[string]struct{}{}
	totalFileBytes := 0
	for _, mount := range mounts {
		cleanPath := filepath.Clean(mount.FilePath)
		if cleanPath == "." || cleanPath == ".." || strings.HasPrefix(cleanPath, ".."+string(filepath.Separator)) || len(cleanPath) > deploy.MaxInlineFilePathBytes {
			return "", errors.New("template managed file has an invalid path")
		}
		if _, exists := seenMounts[cleanPath]; exists {
			return "", errors.New("template managed file path is duplicated")
		}
		seenMounts[cleanPath] = struct{}{}
		if len(mount.Content) > deploy.MaxInlineFileBytes {
			return "", errors.New("template managed file exceeds size limit")
		}
		totalFileBytes += len(mount.Content)
		if totalFileBytes > deploy.MaxInlineFilesBytes {
			return "", errors.New("template managed files exceed total size limit")
		}
	}
	for serviceName, raw := range services {
		service, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		volumes, ok := service["volumes"].([]any)
		if !ok {
			continue
		}
		remaining := make([]any, 0, len(volumes))
		serviceConfigs, _ := service["configs"].([]any)
		for _, item := range volumes {
			text, ok := item.(string)
			if !ok {
				remaining = append(remaining, item)
				continue
			}
			parts := strings.Split(text, ":")
			if len(parts) < 2 {
				remaining = append(remaining, item)
				continue
			}
			source := filepath.Clean(parts[0])
			matchedVolume := false
			for _, mount := range mounts {
				expected := filepath.Clean(filepath.Join("../files", mount.FilePath))
				if expected != source && !strings.HasPrefix(expected, source+string(filepath.Separator)) {
					continue
				}
				relative := strings.TrimPrefix(expected, source)
				relative = strings.TrimPrefix(relative, string(filepath.Separator))
				target := parts[1]
				if relative != "" {
					target = filepath.Join(target, relative)
				}
				sum := sha256.Sum256([]byte(filepath.Clean(mount.FilePath)))
				base := sanitize(filepath.Base(mount.FilePath))
				if len(base) > 24 {
					base = base[:24]
				}
				if base == "" {
					base = "file"
				}
				name := "tpl-" + base + "-" + hex.EncodeToString(sum[:8])
				environmentKey := deploy.InlineFileEnvironmentPrefix + strings.ToUpper(hex.EncodeToString(sum[:]))
				entry := map[string]any{"source": name, "target": target}
				if len(parts) > 2 && strings.Contains(parts[2], "ro") {
					entry["mode"] = 0444
				}
				serviceConfigs = append(serviceConfigs, entry)
				configs[name] = map[string]any{"file": "./.dockyard-files/" + name}
				inline[name] = deploy.InlineFileReferencePrefix + environmentKey
				environment[environmentKey] = mount.Content
				matchedVolume = true
			}
			if !matchedVolume {
				remaining = append(remaining, item)
			}
		}
		if len(remaining) == 0 {
			delete(service, "volumes")
		} else {
			service["volumes"] = remaining
		}
		if len(serviceConfigs) > 0 {
			service["configs"] = serviceConfigs
		}
		services[serviceName] = service
	}
	doc["services"] = services
	doc["configs"] = configs
	doc["x-dockyard-files"] = inline
	out, err := yaml.Marshal(doc)
	return string(out), err
}

func sanitize(value string) string {
	value = strings.ToLower(value)
	value = regexp.MustCompile(`[^a-z0-9-]+`).ReplaceAllString(value, "-")
	return strings.Trim(value, "-")
}

func Instantiate(template DokployTemplate, compose, baseDomain string) (Instance, error) {
	return InstantiateWithOverrides(template, compose, baseDomain, nil)
}

// InstantiateWithOverrides applies literal operator-provided values only to
// variables declared by the template. Overrides are deliberately not expanded
// as helper expressions, which prevents callers from injecting generators.
func InstantiateWithOverrides(template DokployTemplate, compose, baseDomain string, overrides map[string]string) (Instance, error) {
	if err := validateTemplateVariables(template); err != nil {
		return Instance{}, err
	}
	if err := validateOverrides(template, overrides); err != nil {
		return Instance{}, err
	}
	if len(baseDomain) > 253 {
		return Instance{}, errors.New("template base domain exceeds 253 bytes")
	}
	resolved := make(map[string]string, len(template.Variables))
	resolvedBytes := 0
	for key, value := range overrides {
		resolved[key] = value
		resolvedBytes += len(key) + len(value)
	}
	unresolved := make(map[string]string, len(template.Variables)-len(resolved))
	for key, value := range template.Variables {
		if _, overridden := resolved[key]; !overridden {
			unresolved[key] = value
		}
	}
	for len(unresolved) > 0 {
		progress := false
		for key, value := range unresolved {
			if !dependenciesResolved(key, value, template.Variables, resolved) {
				continue
			}
			next, err := resolve(value, resolved, baseDomain)
			if err != nil {
				return Instance{}, fmt.Errorf("resolve variable %q: %w", key, err)
			}
			if len(next) > maxResolvedValueBytes {
				return Instance{}, fmt.Errorf("resolved template variable %q exceeds %d bytes", key, maxResolvedValueBytes)
			}
			resolvedBytes += len(key) + len(next)
			if resolvedBytes > maxResolvedVariablesBytes {
				return Instance{}, fmt.Errorf("resolved template variables exceed %d bytes", maxResolvedVariablesBytes)
			}
			resolved[key] = next
			delete(unresolved, key)
			progress = true
		}
		if !progress {
			for key := range unresolved {
				return Instance{}, fmt.Errorf("cannot resolve variable %q", key)
			}
		}
	}
	instance := Instance{ComposeYAML: compose, Environment: map[string]string{}, Variables: resolved}
	switch env := template.Config.Env.(type) {
	case nil:
	case map[string]any:
		for key, value := range env {
			text := fmt.Sprint(value)
			v, err := resolve(text, resolved, baseDomain)
			if err != nil {
				return Instance{}, fmt.Errorf("resolve env %s: %w", key, err)
			}
			instance.Environment[key] = v
		}
	case []any:
		for _, value := range env {
			if object, ok := value.(map[string]any); ok {
				for key, raw := range object {
					resolvedValue, err := resolve(fmt.Sprint(raw), resolved, baseDomain)
					if err != nil {
						return Instance{}, err
					}
					instance.Environment[key] = resolvedValue
				}
				continue
			}
			if err := addEnvLine(instance.Environment, fmt.Sprint(value), resolved, baseDomain); err != nil {
				return Instance{}, err
			}
		}
	case []string:
		for _, value := range env {
			if err := addEnvLine(instance.Environment, value, resolved, baseDomain); err != nil {
				return Instance{}, err
			}
		}
	default:
		return Instance{}, fmt.Errorf("unsupported config.env type %T", env)
	}
	for _, domain := range template.Config.Domains {
		var err error
		domain.Host, err = resolve(domain.Host, resolved, baseDomain)
		if err != nil {
			return Instance{}, err
		}
		domain.Host = strings.ToLower(strings.TrimSpace(domain.Host))
		if domain.Path == "" {
			domain.Path = "/"
		}
		instance.Domains = append(instance.Domains, domain)
	}
	for _, mount := range template.Config.Mounts {
		var err error
		mount.FilePath, err = resolve(mount.FilePath, resolved, baseDomain)
		if err != nil {
			return Instance{}, err
		}
		mount.Content, err = resolve(mount.Content, resolved, baseDomain)
		if err != nil {
			return Instance{}, err
		}
		instance.Mounts = append(instance.Mounts, mount)
	}
	return instance, nil
}

func validateTemplateVariables(template DokployTemplate) error {
	if len(template.Variables) > maxTemplateVariables {
		return fmt.Errorf("template declares too many variables (maximum %d)", maxTemplateVariables)
	}
	total := 0
	for key, value := range template.Variables {
		if key == "" || len(key) > maxVariableNameBytes || strings.ContainsRune(key, '\x00') {
			return errors.New("template declares an invalid variable name")
		}
		if len(value) > maxVariableValueBytes {
			return fmt.Errorf("template variable %q exceeds %d bytes", key, maxVariableValueBytes)
		}
		total += len(key) + len(value)
		if total > maxVariableTotalBytes {
			return fmt.Errorf("template variable definitions exceed %d bytes", maxVariableTotalBytes)
		}
	}
	return nil
}

func validateOverrides(template DokployTemplate, overrides map[string]string) error {
	if len(overrides) > maxTemplateVariables {
		return fmt.Errorf("too many variable overrides (maximum %d)", maxTemplateVariables)
	}
	total := 0
	for key, value := range overrides {
		if _, ok := template.Variables[key]; !ok {
			return fmt.Errorf("unknown template variable %q", key)
		}
		if key == "" || len(key) > maxVariableNameBytes {
			return fmt.Errorf("invalid template variable name")
		}
		if len(value) > maxVariableValueBytes {
			return fmt.Errorf("template variable %q exceeds %d bytes", key, maxVariableValueBytes)
		}
		total += len(key) + len(value)
		if total > maxVariableTotalBytes {
			return fmt.Errorf("template variable overrides exceed %d bytes", maxVariableTotalBytes)
		}
	}
	return nil
}

func dependenciesResolved(currentKey, value string, declared, resolved map[string]string) bool {
	for _, match := range expression.FindAllStringSubmatch(value, -1) {
		parts := strings.Split(match[1], ":")
		if _, isVariable := declared[parts[0]]; isVariable && parts[0] != currentKey {
			if _, ok := resolved[parts[0]]; !ok {
				return false
			}
		}
		if parts[0] == "jwt" || parts[0] == "basicAuth" {
			for _, dependency := range parts[1:] {
				if _, isVariable := declared[dependency]; isVariable {
					if _, ok := resolved[dependency]; !ok {
						return false
					}
				}
			}
		}
	}
	return true
}

func addEnvLine(target map[string]string, line string, variables map[string]string, baseDomain string) error {
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 && (strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#")) {
		return nil
	}
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
		return fmt.Errorf("invalid environment entry %q", line)
	}
	value, err := resolve(parts[1], variables, baseDomain)
	if err != nil {
		return fmt.Errorf("resolve env %s: %w", parts[0], err)
	}
	target[parts[0]] = value
	return nil
}

var expression = regexp.MustCompile(`\$\{([^}]+)\}`)

func resolve(value string, variables map[string]string, baseDomain string) (string, error) {
	if len(value) > maxResolvedValueBytes {
		return "", fmt.Errorf("template value exceeds %d bytes before expansion", maxResolvedValueBytes)
	}
	if len(expression.FindAllStringIndex(value, maxExpressionsPerValue+1)) > maxExpressionsPerValue {
		return "", fmt.Errorf("template value contains more than %d expressions", maxExpressionsPerValue)
	}
	var resolveErr error
	result := expression.ReplaceAllStringFunc(value, func(match string) string {
		key := expression.FindStringSubmatch(match)[1]
		if v, ok := variables[key]; ok {
			return v
		}
		parts := strings.Split(key, ":")
		switch parts[0] {
		case "domain":
			if len(parts) != 1 {
				resolveErr = errors.New("domain helper does not accept parameters")
				return match
			}
			id, err := uuid.NewRandom()
			if err != nil {
				resolveErr = fmt.Errorf("generate domain: %w", err)
				return match
			}
			if baseDomain == "" {
				return id.String() + ".local"
			}
			return id.String()[:8] + "." + baseDomain
		case "password":
			length, err := generatorLength(parts, 16)
			if err != nil {
				resolveErr = err
				return match
			}
			generated, err := randomText(length)
			if err != nil {
				resolveErr = fmt.Errorf("generate password: %w", err)
				return match
			}
			return generated
		case "base64":
			length, err := generatorLength(parts, 32)
			if err != nil {
				resolveErr = err
				return match
			}
			b, err := randomBytes(length)
			if err != nil {
				resolveErr = fmt.Errorf("generate base64 value: %w", err)
				return match
			}
			return base64.StdEncoding.EncodeToString(b)
		case "basicAuth":
			if len(parts) != 3 {
				resolveErr = errors.New("basicAuth helper requires declared username and password variables")
				return match
			}
			username, usernameOK := variables[parts[1]]
			password, passwordOK := variables[parts[2]]
			if !usernameOK || !passwordOK || username == "" || password == "" {
				resolveErr = errors.New("basicAuth helper username or password variable is missing or empty")
				return match
			}
			if strings.Contains(username, ":") {
				resolveErr = errors.New("basicAuth helper username cannot contain a colon")
				return match
			}
			return "basic:" + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
		case "hash":
			length, err := generatorLength(parts, 8)
			if err != nil {
				resolveErr = err
				return match
			}
			bytes, err := randomBytes((length + 1) / 2)
			if err != nil {
				resolveErr = fmt.Errorf("generate hash: %w", err)
				return match
			}
			return hex.EncodeToString(bytes)[:length]
		case "username":
			length, err := generatorLength(parts, 16)
			if err != nil {
				resolveErr = err
				return match
			}
			generated, err := randomText(length)
			if err != nil {
				resolveErr = fmt.Errorf("generate username: %w", err)
				return match
			}
			return strings.ToLower(generated)
		case "timestampms", "timestamps":
			value, err := timestampValue(parts[0], key)
			if err != nil {
				resolveErr = err
				return match
			}
			return value
		case "uuid", "timestamp", "randomPort", "email":
			if len(parts) != 1 {
				resolveErr = fmt.Errorf("%s helper does not accept parameters", parts[0])
				return match
			}
			switch parts[0] {
			case "uuid":
				id, err := uuid.NewRandom()
				if err != nil {
					resolveErr = fmt.Errorf("generate UUID: %w", err)
					return match
				}
				return id.String()
			case "timestamp":
				return strconv.FormatInt(time.Now().UnixMilli(), 10)
			case "randomPort":
				bytes, err := randomBytes(2)
				if err != nil {
					resolveErr = fmt.Errorf("generate random port: %w", err)
					return match
				}
				n := int(bytes[0])<<8 + int(bytes[1])
				return strconv.Itoa(10000 + n%50000)
			default:
				generated, err := randomText(8)
				if err != nil {
					resolveErr = fmt.Errorf("generate email: %w", err)
					return match
				}
				return "admin-" + generated + "@example.com"
			}
		case "jwt":
			payload := map[string]any{"iss": "dokploy", "iat": time.Now().Unix(), "exp": int64(1893456000)}
			secret := ""
			if len(parts) == 1 {
				bytes, err := randomBytes(32)
				if err != nil {
					resolveErr = fmt.Errorf("generate jwt secret: %w", err)
					return match
				}
				secret = hex.EncodeToString(bytes)
			}
			if len(parts) == 2 {
				if size, err := strictDecimal(parts[1]); err == nil {
					if size < 1 || size > 256 {
						resolveErr = errors.New("jwt helper length must be between 1 and 256")
						return match
					}
					bytes, randomErr := randomBytes(size)
					if randomErr != nil {
						resolveErr = fmt.Errorf("generate jwt value: %w", randomErr)
						return match
					}
					return hex.EncodeToString(bytes)
				}
			}
			if len(parts) > 3 {
				resolveErr = errors.New("jwt helper requires a declared secret variable and optional payload variable")
				return match
			}
			if len(parts) >= 2 {
				var ok bool
				secret, ok = variables[parts[1]]
				if !ok || secret == "" {
					resolveErr = errors.New("jwt helper secret variable is missing or empty")
					return match
				}
			}
			if len(parts) == 3 {
				raw, ok := variables[parts[2]]
				if !ok || raw == "" {
					resolveErr = errors.New("jwt helper payload variable is missing or empty")
					return match
				}
				if err := json.Unmarshal([]byte(raw), &payload); err != nil {
					resolveErr = fmt.Errorf("invalid jwt payload: %w", err)
					return match
				}
			}
			header, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
			body, _ := json.Marshal(payload)
			unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
			mac := hmac.New(sha256.New, []byte(secret))
			_, _ = mac.Write([]byte(unsigned))
			return unsigned + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		default:
			return match
		}
	})
	result = strings.ReplaceAll(result, "__DOCKYARD_ESCAPED_DOLLAR__{", "${")
	result = strings.ReplaceAll(result, "__DOCKYARD_ESCAPED_DOLLAR__", "$")
	result = strings.ReplaceAll(result, "__DOCKYARD_BACKSLASH_BRACE__", `\{`)
	if len(result) > maxResolvedValueBytes {
		return "", fmt.Errorf("resolved template value exceeds %d bytes", maxResolvedValueBytes)
	}
	return result, resolveErr
}

func timestampValue(helper, key string) (string, error) {
	if key == helper {
		if helper == "timestampms" {
			return strconv.FormatInt(time.Now().UnixMilli(), 10), nil
		}
		return strconv.FormatInt(time.Now().Unix(), 10), nil
	}
	prefix := helper + ":"
	if !strings.HasPrefix(key, prefix) {
		return "", fmt.Errorf("invalid %s helper", helper)
	}
	raw := strings.TrimPrefix(key, prefix)
	var parsed time.Time
	var err error
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02"} {
		parsed, err = time.Parse(layout, raw)
		if err == nil {
			if helper == "timestampms" {
				return strconv.FormatInt(parsed.UnixMilli(), 10), nil
			}
			return strconv.FormatInt(parsed.Unix(), 10), nil
		}
	}
	return "", fmt.Errorf("%s helper requires an RFC3339 or YYYY-MM-DD date", helper)
}

func generatorLength(parts []string, defaultLength int) (int, error) {
	if len(parts) == 1 {
		return defaultLength, nil
	}
	if len(parts) != 2 {
		return 0, fmt.Errorf("%s helper accepts at most one length parameter", parts[0])
	}
	length, err := strictDecimal(parts[1])
	if err != nil || length < 1 || length > 4096 {
		return 0, fmt.Errorf("%s helper length must be between 1 and 4096", parts[0])
	}
	return length, nil
}

func strictDecimal(value string) (int, error) {
	if value == "" || strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return 0, errors.New("not a decimal integer")
	}
	return strconv.Atoi(value)
}

func randomBytes(length int) ([]byte, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
func randomText(length int) (string, error) {
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b, err := randomBytes(length)
	if err != nil {
		return "", err
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b), nil
}
