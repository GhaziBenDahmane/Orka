package templates

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"

	"github.com/bendahma/dokploy-go/internal/deploy"
	"github.com/bendahma/dokploy-go/internal/store"
)

//go:embed builtin/blueprints/*/*
var builtinCatalog embed.FS

func SeedBuiltinCatalog(ctx context.Context, db *store.Store, compiler deploy.Compiler) (ImportReport, error) {
	// Built-ins are always advertised as safe. Validate them with the safe
	// profile even when the controller permits explicitly opted-in unsafe
	// tenant workloads.
	compiler.AllowUnsafe = false
	entries, err := fs.ReadDir(builtinCatalog, "builtin/blueprints")
	if err != nil {
		return ImportReport{}, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	report := ImportReport{Failed: map[string]string{}}
	identities := map[string]string{}
	items := make([]store.Template, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		root := path.Join("builtin/blueprints", entry.Name())
		metaBytes, readErr := fs.ReadFile(builtinCatalog, path.Join(root, "meta.json"))
		if readErr != nil {
			report.Failed[entry.Name()] = readErr.Error()
			continue
		}
		meta, metadataErr := parseTemplateMetadata(metaBytes)
		if metadataErr != nil {
			report.Failed[entry.Name()] = metadataErr.Error()
			continue
		}
		identity := meta.ID + "\x00" + meta.Version
		if previous, duplicate := identities[identity]; duplicate {
			report.Failed[entry.Name()] = fmt.Sprintf("duplicates template key and version from %s", previous)
			continue
		}
		identities[identity] = entry.Name()
		tomlBytes, readErr := fs.ReadFile(builtinCatalog, path.Join(root, "template.toml"))
		if readErr != nil {
			report.Failed[entry.Name()] = readErr.Error()
			continue
		}
		compose, readErr := fs.ReadFile(builtinCatalog, path.Join(root, "docker-compose.yml"))
		if readErr != nil {
			report.Failed[entry.Name()] = readErr.Error()
			continue
		}
		readErr = validateBuiltinBlueprint(tomlBytes, compose, compiler)
		if readErr != nil {
			report.Failed[entry.Name()] = readErr.Error()
			continue
		}
		hash := sha256.New()
		_, _ = hash.Write(tomlBytes)
		_, _ = hash.Write(compose)
		config, _ := json.Marshal(map[string]string{"templateToml": string(tomlBytes), "safetyClass": SafetyClassSafe})
		items = append(items, store.Template{Key: meta.ID, Version: meta.Version, Name: meta.Name, Description: meta.Description, ComposeYAML: string(compose), Config: config, Source: "builtin", SourcePath: path.Join("blueprints", entry.Name()), Checksum: hex.EncodeToString(hash.Sum(nil))})
	}
	if len(report.Failed) > 0 {
		return report, fmt.Errorf("%d built-in template(s) failed to import", len(report.Failed))
	}
	if err = db.UpsertGlobalTemplates(ctx, items); err != nil {
		return report, err
	}
	report.Imported = len(items)
	return report, nil
}

func ValidateBuiltinCatalog(compiler deploy.Compiler) (ImportReport, error) {
	entries, err := fs.ReadDir(builtinCatalog, "builtin/blueprints")
	if err != nil {
		return ImportReport{}, err
	}
	report := ImportReport{Failed: map[string]string{}}
	identities := map[string]string{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		root := path.Join("builtin/blueprints", entry.Name())
		metaBytes, readErr := fs.ReadFile(builtinCatalog, path.Join(root, "meta.json"))
		var meta metadata
		if readErr == nil {
			meta, readErr = parseTemplateMetadata(metaBytes)
		}
		if readErr == nil {
			identity := meta.ID + "\x00" + meta.Version
			if previous, duplicate := identities[identity]; duplicate {
				readErr = fmt.Errorf("duplicates template key and version from %s", previous)
			} else {
				identities[identity] = entry.Name()
			}
		}
		var tomlBytes []byte
		if readErr == nil {
			tomlBytes, readErr = fs.ReadFile(builtinCatalog, path.Join(root, "template.toml"))
		}
		if readErr != nil {
			report.Failed[entry.Name()] = readErr.Error()
			continue
		}
		compose, readErr := fs.ReadFile(builtinCatalog, path.Join(root, "docker-compose.yml"))
		if readErr == nil {
			readErr = validateBuiltinBlueprint(tomlBytes, compose, compiler)
		}
		if readErr != nil {
			report.Failed[entry.Name()] = readErr.Error()
		} else {
			report.Imported++
		}
	}
	if len(report.Failed) > 0 {
		return report, fmt.Errorf("%d built-in template(s) failed validation", len(report.Failed))
	}
	return report, nil
}

func validateBuiltinBlueprint(tomlBytes, compose []byte, compiler deploy.Compiler) error {
	compiler.AllowUnsafe = false
	definition, err := ParseDokploy(tomlBytes)
	if err != nil {
		return err
	}
	instance, err := Instantiate(definition, string(compose), "example.test")
	if err != nil {
		return err
	}
	instance.ComposeYAML, err = ApplyMounts(instance.ComposeYAML, instance.Mounts, instance.Environment)
	if err != nil {
		return err
	}
	routes, err := instanceRoutes(instance)
	if err != nil {
		return err
	}
	_, err = compiler.Compile(instance.ComposeYAML, routes)
	return err
}
