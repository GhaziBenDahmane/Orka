package templates

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

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

type VariableDescriptor struct {
	Name      string `json:"name"`
	Default   string `json:"default,omitempty"`
	Generated bool   `json:"generated"`
	Sensitive bool   `json:"sensitive"`
}

const (
	maxVariableOverrides  = 128
	maxVariableNameBytes  = 128
	maxVariableValueBytes = 8 << 10
	maxVariableTotalBytes = 64 << 10
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
		case "password", "base64", "hash", "jwt":
			return true
		}
	}
	return false
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
	instance.ComposeYAML, err = ApplyMounts(instance.ComposeYAML, instance.Mounts)
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
// configs. The inline extension is materialized by the Swarm adapter immediately
// before docker stack deploy reads the Compose document.
func ApplyMounts(compose string, mounts []Mount) (string, error) {
	if len(mounts) == 0 {
		return compose, nil
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
				sum := sha256.Sum256([]byte(mount.Content))
				name := "tpl-" + sanitize(filepath.Base(mount.FilePath)) + "-" + hex.EncodeToString(sum[:4])
				entry := map[string]any{"source": name, "target": target}
				if len(parts) > 2 && strings.Contains(parts[2], "ro") {
					entry["mode"] = 0444
				}
				serviceConfigs = append(serviceConfigs, entry)
				configs[name] = map[string]any{"file": "./.dockyard-files/" + name}
				inline[name] = mount.Content
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
	if err := validateOverrides(template, overrides); err != nil {
		return Instance{}, err
	}
	resolved := make(map[string]string, len(template.Variables))
	for key, value := range overrides {
		resolved[key] = value
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

func validateOverrides(template DokployTemplate, overrides map[string]string) error {
	if len(overrides) > maxVariableOverrides {
		return fmt.Errorf("too many variable overrides (maximum %d)", maxVariableOverrides)
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
		if parts[0] == "jwt" {
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
	var resolveErr error
	result := expression.ReplaceAllStringFunc(value, func(match string) string {
		key := expression.FindStringSubmatch(match)[1]
		if v, ok := variables[key]; ok {
			return v
		}
		parts := strings.Split(key, ":")
		length := 32
		if len(parts) == 2 {
			parsed, err := strconv.Atoi(parts[1])
			if err == nil && parsed > 0 && parsed <= 256 {
				length = parsed
			}
		}
		switch parts[0] {
		case "domain":
			if baseDomain == "" {
				return uuid.NewString() + ".local"
			}
			return uuid.NewString()[:8] + "." + baseDomain
		case "password":
			return randomText(length)
		case "base64":
			b := randomBytes(length)
			return base64.RawStdEncoding.EncodeToString(b)
		case "hash":
			sum := sha256.Sum256(randomBytes(length))
			return hex.EncodeToString(sum[:])[:min(length, 64)]
		case "uuid":
			return uuid.NewString()
		case "timestamp", "timestampms":
			return strconv.FormatInt(time.Now().UnixMilli(), 10)
		case "timestamps":
			return strconv.FormatInt(time.Now().Unix(), 10)
		case "randomPort":
			n := int(randomBytes(2)[0])<<8 + int(randomBytes(2)[1])
			return strconv.Itoa(10000 + n%50000)
		case "email":
			return "admin-" + randomText(8) + "@example.com"
		case "username":
			return strings.ToLower(randomText(length))
		case "jwt":
			if len(parts) == 2 {
				if size, err := strconv.Atoi(parts[1]); err == nil {
					return hex.EncodeToString(randomBytes(size))
				}
			}
			if len(parts) < 2 {
				resolveErr = fmt.Errorf("jwt helper requires a secret variable")
				return match
			}
			secret := variables[parts[1]]
			if secret == "" {
				secret = parts[1]
			}
			payload := map[string]any{"iat": time.Now().Unix(), "exp": time.Now().AddDate(1, 0, 0).Unix()}
			if len(parts) > 2 {
				raw := variables[parts[2]]
				if raw == "" {
					raw = parts[2]
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
	return strings.ReplaceAll(result, "__DOCKYARD_BACKSLASH_BRACE__", `\{`), resolveErr
}
func randomBytes(length int) []byte {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
func randomText(length int) string {
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := randomBytes(length)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}
