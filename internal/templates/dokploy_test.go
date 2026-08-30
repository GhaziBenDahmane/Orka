package templates

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bendahma/dokploy-go/internal/deploy"
)

func TestInstantiateDokployTemplate(t *testing.T) {
	var template DokployTemplate
	template.Variables = map[string]string{"main_domain": "${domain}", "password": "${password:24}"}
	template.Config.Env = map[string]any{"PASSWORD": "${password}"}
	template.Config.Domains = []Domain{{ServiceName: "web", Port: int64(8080), Host: "${main_domain}"}}
	instance, err := Instantiate(template, "services:\n  web:\n    image: example\n", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(instance.Environment["PASSWORD"]) != 24 {
		t.Fatalf("wrong password length: %q", instance.Environment["PASSWORD"])
	}
	if !strings.HasSuffix(instance.Domains[0].Host, ".example.com") {
		t.Fatalf("unexpected domain %q", instance.Domains[0].Host)
	}
}

func TestInstantiateWithOverridesUsesDeclaredLiteralValues(t *testing.T) {
	var template DokployTemplate
	template.Variables = map[string]string{
		"admin_email": "admin@example.test",
		"password":    "${password:24}",
		"dsn":         "postgres://app:${password}@db/app",
	}
	template.Config.Env = map[string]any{"ADMIN_EMAIL": "${admin_email}", "DATABASE_URL": "${dsn}", "PASSWORD": "${password}"}
	overrides := map[string]string{"admin_email": "operator@example.test", "password": "literal-${password:99}"}
	instance, err := InstantiateWithOverrides(template, "services: {}\n", "example.test", overrides)
	if err != nil {
		t.Fatal(err)
	}
	if got := instance.Environment["ADMIN_EMAIL"]; got != overrides["admin_email"] {
		t.Fatalf("admin email = %q", got)
	}
	if got := instance.Environment["PASSWORD"]; got != overrides["password"] {
		t.Fatalf("override was expanded instead of treated literally: %q", got)
	}
	if got := instance.Environment["DATABASE_URL"]; !strings.Contains(got, overrides["password"]) {
		t.Fatalf("dependent variable did not use override: %q", got)
	}
}

func TestInstantiateWithOverridesRejectsUnknownAndOversizedValues(t *testing.T) {
	template := DokployTemplate{Variables: map[string]string{"name": "default"}}
	if _, err := InstantiateWithOverrides(template, "services: {}\n", "", map[string]string{"other": "value"}); err == nil || !strings.Contains(err.Error(), "unknown template variable") {
		t.Fatalf("unknown override error = %v", err)
	}
	if _, err := InstantiateWithOverrides(template, "services: {}\n", "", map[string]string{"name": strings.Repeat("x", maxVariableValueBytes+1)}); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized override error = %v", err)
	}
	manyVariables, manyOverrides := map[string]string{}, map[string]string{}
	for index := 0; index <= maxTemplateVariables; index++ {
		name := fmt.Sprintf("variable_%d", index)
		manyVariables[name], manyOverrides[name] = "default", "override"
	}
	if _, err := InstantiateWithOverrides(DokployTemplate{Variables: manyVariables}, "services: {}\n", "", manyOverrides); err == nil || !strings.Contains(err.Error(), "too many") {
		t.Fatalf("override count error = %v", err)
	}
}

func TestInstantiateRejectsOversizedTemplateDefinitionsAndExpansion(t *testing.T) {
	t.Run("too many variables", func(t *testing.T) {
		variables := map[string]string{}
		for index := 0; index <= maxTemplateVariables; index++ {
			variables[fmt.Sprintf("value_%d", index)] = "safe"
		}
		if _, err := Instantiate(DokployTemplate{Variables: variables}, "services: {}\n", ""); err == nil || !strings.Contains(err.Error(), "too many variables") {
			t.Fatalf("oversized definition error=%v", err)
		}
	})
	t.Run("definition bytes", func(t *testing.T) {
		variables := map[string]string{}
		for index := 0; index < 9; index++ {
			variables[fmt.Sprintf("value_%d", index)] = strings.Repeat("x", maxVariableValueBytes)
		}
		if _, err := Instantiate(DokployTemplate{Variables: variables}, "services: {}\n", ""); err == nil || !strings.Contains(err.Error(), "definitions exceed") {
			t.Fatalf("oversized definitions error=%v", err)
		}
	})
	t.Run("expanded value", func(t *testing.T) {
		template := DokployTemplate{Variables: map[string]string{
			"seed":     strings.Repeat("x", maxVariableValueBytes),
			"expanded": strings.Repeat("${seed}", 65),
		}}
		if _, err := Instantiate(template, "services: {}\n", ""); err == nil || !strings.Contains(err.Error(), "resolved template value exceeds") {
			t.Fatalf("expansion error=%v", err)
		}
	})
	t.Run("expression count", func(t *testing.T) {
		template := DokployTemplate{Variables: map[string]string{
			"seed":     "x",
			"expanded": strings.Repeat("${seed}", maxExpressionsPerValue+1),
		}}
		if _, err := Instantiate(template, "services: {}\n", ""); err == nil || !strings.Contains(err.Error(), "more than 256 expressions") {
			t.Fatalf("expression-count error=%v", err)
		}
	})
}

func TestInstantiateRejectsUnsafeGeneratorParameters(t *testing.T) {
	for _, definition := range []string{
		"${jwt:-1}",
		"${jwt:+1}",
		"${jwt:257}",
		"${jwt:999999999}",
		"${jwt:missing_secret}",
		"${jwt:secret:missing_payload}",
		"${password:0}",
		"${password:+1}",
		"${password:4097}",
		"${password:not-a-number}",
		"${base64:1:2}",
		"${uuid:ignored}",
	} {
		t.Run(definition, func(t *testing.T) {
			template := DokployTemplate{Variables: map[string]string{"token": definition, "secret": ""}}
			if _, err := Instantiate(template, "services: {}\n", "example.test"); err == nil {
				t.Fatalf("unsafe generator %q was accepted", definition)
			}
		})
	}
}

func TestInstantiateSupportsDokployLargeBase64Generator(t *testing.T) {
	template := DokployTemplate{Variables: map[string]string{"mongo_key": "${base64:756}"}}
	instance, err := Instantiate(template, "services: {}\n", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(instance.Variables["mongo_key"]) != 1008 {
		t.Fatalf("base64 generator length=%d", len(instance.Variables["mongo_key"]))
	}
}

func TestInstantiateMatchesDokployGeneratorDefaults(t *testing.T) {
	template := DokployTemplate{Variables: map[string]string{
		"password":  "${password}",
		"base64":    "${base64}",
		"hash":      "${hash}",
		"long_hash": "${hash:128}",
		"jwt":       "${jwt}",
	}}
	instance, err := Instantiate(template, "services: {}\n", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(instance.Variables["password"]) != 16 {
		t.Fatalf("password length=%d", len(instance.Variables["password"]))
	}
	if value := instance.Variables["base64"]; len(value) != 44 || !strings.HasSuffix(value, "=") {
		t.Fatalf("base64 value does not use padded 32-byte encoding: %q", value)
	}
	if len(instance.Variables["hash"]) != 8 || len(instance.Variables["long_hash"]) != 128 {
		t.Fatalf("hash lengths=%d,%d", len(instance.Variables["hash"]), len(instance.Variables["long_hash"]))
	}
	parts := strings.Split(instance.Variables["jwt"], ".")
	if len(parts) != 3 {
		t.Fatalf("default JWT has %d segments", len(parts))
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err = json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["iss"] != "dokploy" || payload["exp"] != float64(1893456000) {
		t.Fatalf("default JWT payload=%#v", payload)
	}
}

func TestInstantiateSupportsDokployTimestampParameters(t *testing.T) {
	template := DokployTemplate{Variables: map[string]string{
		"milliseconds": "${timestampms:2025-01-01}",
		"seconds":      "${timestamps:2030-01-01T00:00:00Z}",
	}}
	instance, err := Instantiate(template, "services: {}\n", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if instance.Variables["milliseconds"] != "1735689600000" {
		t.Fatalf("milliseconds=%q", instance.Variables["milliseconds"])
	}
	if instance.Variables["seconds"] != "1893456000" {
		t.Fatalf("seconds=%q", instance.Variables["seconds"])
	}
}

func TestInstantiateSupportsBoundedJWTGenerators(t *testing.T) {
	template := DokployTemplate{Variables: map[string]string{
		"random_token": "${jwt:32}",
		"secret":       "stable-test-secret",
		"payload":      `{"sub":"template-test"}`,
		"signed_token": "${jwt:secret:payload}",
	}}
	instance, err := Instantiate(template, "services: {}\n", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(instance.Variables["random_token"]) != 64 {
		t.Fatalf("random JWT token length=%d", len(instance.Variables["random_token"]))
	}
	if parts := strings.Split(instance.Variables["signed_token"], "."); len(parts) != 3 {
		t.Fatalf("signed JWT has %d segments", len(parts))
	}
}

func TestDescribeVariablesRedactsGeneratedAndSensitiveDefaults(t *testing.T) {
	template := DokployTemplate{Variables: map[string]string{
		"admin_email": "admin@example.test",
		"api_token":   "do-not-disclose",
		"hostname":    "${domain}",
		"password":    "${password:32}",
		"dsn":         "postgres://app:${api_token}@db/app",
	}}
	descriptors := DescribeVariables(template)
	if len(descriptors) != 5 || descriptors[0].Name != "admin_email" {
		t.Fatalf("descriptors are incomplete or unsorted: %#v", descriptors)
	}
	byName := map[string]VariableDescriptor{}
	for _, descriptor := range descriptors {
		byName[descriptor.Name] = descriptor
	}
	if byName["admin_email"].Default != "admin@example.test" || byName["admin_email"].Sensitive {
		t.Fatalf("safe default missing: %#v", byName["admin_email"])
	}
	for _, name := range []string{"api_token", "password"} {
		if !byName[name].Sensitive || byName[name].Default != "" {
			t.Fatalf("secret descriptor leaked a default: %#v", byName[name])
		}
	}
	if !byName["dsn"].Sensitive {
		t.Fatalf("derived secret was not classified: %#v", byName["dsn"])
	}
	if !byName["hostname"].Generated || byName["hostname"].Sensitive || byName["hostname"].Default != "" {
		t.Fatalf("domain descriptor = %#v", byName["hostname"])
	}
}

func TestUpgradeOverridesPreservesInputsAndGeneratorsButRecomputesDerivedValues(t *testing.T) {
	template := DokployTemplate{Variables: map[string]string{
		"password": "${password:32}",
		"database": "new_default",
		"dsn":      "postgres://app:${password}@db/${database}",
		"removed":  "not actually present",
	}}
	delete(template.Variables, "removed")
	merged := UpgradeOverrides(template,
		map[string]string{"password": "stable-secret", "database": "old_default", "dsn": "old-dsn", "old_key": "old"},
		map[string]string{"database": "operator_database", "old_key": "old"},
		map[string]string{"password": "replacement-secret"},
	)
	if merged["password"] != "replacement-secret" || merged["database"] != "operator_database" {
		t.Fatalf("explicit and requested overrides were not retained: %#v", merged)
	}
	if _, exists := merged["dsn"]; exists {
		t.Fatalf("derived value must be recomputed: %#v", merged)
	}
	if _, exists := merged["old_key"]; exists {
		t.Fatalf("removed variable survived upgrade: %#v", merged)
	}
}

func TestSignedCatalogDetectsTampering(t *testing.T) {
	root := t.TempDir()
	blueprint := filepath.Join(root, "blueprints", "demo")
	if err := os.MkdirAll(blueprint, 0700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"meta.json":          `{"id":"demo","name":"Demo","version":"1"}`,
		"template.toml":      "[variables]\n",
		"docker-compose.yml": "services:\n  web:\n    image: example@sha256:" + strings.Repeat("a", 64) + "\n",
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(blueprint, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	publicKey, privateKey, err := GenerateCatalogKey()
	if err != nil {
		t.Fatal(err)
	}
	if err = SignCatalog(root, privateKey); err != nil {
		t.Fatal(err)
	}
	if err = VerifyCatalog(root, publicKey); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(blueprint, "meta.json"), []byte(`{"id":"other"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err = VerifyCatalog(root, publicKey); err == nil {
		t.Fatal("expected modified catalog to fail verification")
	}
}

func TestApplyMountsConvertsFilesToSwarmConfigs(t *testing.T) {
	compose := "services:\n  db:\n    image: example\n    volumes:\n      - ../files/db/config.xml:/etc/db/config.xml:ro\n"
	environment := map[string]string{}
	out, err := ApplyMounts(compose, []Mount{{FilePath: "/db/config.xml", Content: "<config secret='generated'/>"}}, environment)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"x-dockyard-files", "configs:", "/etc/db/config.xml"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "generated") || len(environment) != 1 {
		t.Fatalf("managed file was not moved to encrypted environment storage: compose=%q environment=%#v", out, environment)
	}
	for key, value := range environment {
		if !strings.HasPrefix(key, deploy.InlineFileEnvironmentPrefix) || value != "<config secret='generated'/>" || !strings.Contains(out, deploy.InlineFileReferencePrefix+key) {
			t.Fatalf("managed file reference is invalid: compose=%q environment=%#v", out, environment)
		}
	}
	if _, err = (deploy.Compiler{PublicNetwork: "public"}).Compile(out, nil); err != nil {
		t.Fatalf("managed file compose rejected by safe compiler: %v", err)
	}
}

func TestApplyMountsRejectsUnsafeOrOversizedManagedFiles(t *testing.T) {
	compose := "services:\n  db:\n    image: example\n    volumes:\n      - ../files/db/config.xml:/etc/db/config.xml:ro\n"
	if _, err := ApplyMounts(compose, []Mount{{FilePath: "../../escape", Content: "secret"}}, map[string]string{}); err == nil {
		t.Fatal("traversing managed file path was accepted")
	}
	if _, err := ApplyMounts(compose, []Mount{{FilePath: "/db/config.xml", Content: strings.Repeat("x", deploy.MaxInlineFileBytes+1)}}, map[string]string{}); err == nil {
		t.Fatal("oversized managed file was accepted")
	}
	reserved := map[string]string{deploy.InlineFileEnvironmentPrefix + strings.Repeat("A", 64): "collision"}
	if _, err := ApplyMounts(compose, []Mount{{FilePath: "/db/config.xml", Content: "secret"}}, reserved); err == nil {
		t.Fatal("reserved environment prefix was accepted")
	}
}
