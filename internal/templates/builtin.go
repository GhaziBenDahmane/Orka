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

func SeedBuiltinCatalog(ctx context.Context, db *store.Store) (ImportReport, error) {
	entries, err := fs.ReadDir(builtinCatalog, "builtin/blueprints")
	if err != nil {
		return ImportReport{}, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	report := ImportReport{Failed: map[string]string{}}
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
		var meta metadata
		if readErr = json.Unmarshal(metaBytes, &meta); readErr != nil {
			report.Failed[entry.Name()] = readErr.Error()
			continue
		}
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
		if _, readErr = ParseDokploy(tomlBytes); readErr != nil {
			report.Failed[entry.Name()] = readErr.Error()
			continue
		}
		hash := sha256.New()
		_, _ = hash.Write(tomlBytes)
		_, _ = hash.Write(compose)
		config, _ := json.Marshal(map[string]string{"templateToml": string(tomlBytes)})
		_, readErr = db.UpsertGlobalTemplate(ctx, store.Template{Key: meta.ID, Version: meta.Version, Name: meta.Name, Description: meta.Description, ComposeYAML: string(compose), Config: config, Source: "builtin", SourcePath: path.Join("blueprints", entry.Name()), Checksum: hex.EncodeToString(hash.Sum(nil))})
		if readErr != nil {
			report.Failed[entry.Name()] = readErr.Error()
			continue
		}
		report.Imported++
	}
	if len(report.Failed) > 0 {
		return report, fmt.Errorf("%d built-in template(s) failed to import", len(report.Failed))
	}
	return report, nil
}

func ValidateBuiltinCatalog(compiler deploy.Compiler) (ImportReport, error) {
	entries, err := fs.ReadDir(builtinCatalog, "builtin/blueprints")
	if err != nil {
		return ImportReport{}, err
	}
	report := ImportReport{Failed: map[string]string{}}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		root := path.Join("builtin/blueprints", entry.Name())
		tomlBytes, readErr := fs.ReadFile(builtinCatalog, path.Join(root, "template.toml"))
		if readErr != nil {
			report.Failed[entry.Name()] = readErr.Error()
			continue
		}
		compose, readErr := fs.ReadFile(builtinCatalog, path.Join(root, "docker-compose.yml"))
		if readErr == nil {
			var definition DokployTemplate
			definition, readErr = ParseDokploy(tomlBytes)
			if readErr == nil {
				var instance Instance
				instance, readErr = Instantiate(definition, string(compose), "example.test")
				if readErr == nil {
					_, readErr = compiler.Compile(instance.ComposeYAML, nil)
				}
			}
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
