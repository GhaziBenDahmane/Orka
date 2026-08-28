package templates

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/bendahma/dokploy-go/internal/deploy"
	"github.com/bendahma/dokploy-go/internal/store"
)

type ImportReport struct {
	Imported int               `json:"imported"`
	Failed   map[string]string `json:"failed"`
}
type metadata struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
}

func ImportDokployCatalog(ctx context.Context, db *store.Store, root string) (ImportReport, error) {
	entries, err := os.ReadDir(filepath.Join(root, "blueprints"))
	if err != nil {
		return ImportReport{}, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	report := ImportReport{Failed: map[string]string{}}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(root, "blueprints", entry.Name())
		metaBytes, readErr := os.ReadFile(filepath.Join(path, "meta.json"))
		if readErr != nil {
			report.Failed[entry.Name()] = readErr.Error()
			continue
		}
		var meta metadata
		if readErr = json.Unmarshal(metaBytes, &meta); readErr != nil {
			report.Failed[entry.Name()] = readErr.Error()
			continue
		}
		tomlBytes, readErr := os.ReadFile(filepath.Join(path, "template.toml"))
		if readErr != nil {
			report.Failed[entry.Name()] = readErr.Error()
			continue
		}
		compose, readErr := os.ReadFile(filepath.Join(path, "docker-compose.yml"))
		if readErr != nil {
			report.Failed[entry.Name()] = readErr.Error()
			continue
		}
		if _, readErr = ParseDokploy(tomlBytes); readErr != nil {
			report.Failed[entry.Name()] = readErr.Error()
			continue
		}
		config, _ := json.Marshal(map[string]string{"templateToml": string(tomlBytes)})
		sum := sha256.Sum256(append(tomlBytes, compose...))
		_, readErr = db.UpsertGlobalTemplate(ctx, store.Template{Key: meta.ID, Version: meta.Version, Name: meta.Name, Description: meta.Description, ComposeYAML: string(compose), Config: config, Source: "dokploy", Checksum: hex.EncodeToString(sum[:])})
		if readErr != nil {
			report.Failed[entry.Name()] = readErr.Error()
			continue
		}
		report.Imported++
	}
	if report.Imported == 0 && len(report.Failed) > 0 {
		return report, fmt.Errorf("no templates imported")
	}
	return report, nil
}

func ValidateDokployCatalog(root string, compiler deploy.Compiler) (ImportReport, error) {
	entries, err := os.ReadDir(filepath.Join(root, "blueprints"))
	if err != nil {
		return ImportReport{}, err
	}
	report := ImportReport{Failed: map[string]string{}}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		instance, loadErr := LoadDokployDirectory(filepath.Join(root, "blueprints", entry.Name()), "example.invalid")
		if loadErr == nil {
			for _, domain := range instance.Domains {
				_, loadErr = PortNumber(domain.Port)
				if loadErr != nil {
					break
				}
			}
		}
		if loadErr == nil {
			_, loadErr = compiler.Compile(instance.ComposeYAML, nil)
		}
		if loadErr != nil {
			report.Failed[entry.Name()] = loadErr.Error()
		} else {
			report.Imported++
		}
	}
	if report.Imported == 0 && len(report.Failed) > 0 {
		return report, fmt.Errorf("no valid templates")
	}
	return report, nil
}
