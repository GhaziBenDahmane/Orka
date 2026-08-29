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

// ImportRepositoryCatalog imports a Dokploy-compatible catalog while namespacing
// keys by repository slug. This keeps identically named templates from multiple
// repositories independent and makes their provenance explicit.
func ImportRepositoryCatalog(ctx context.Context, db *store.Store, repository store.TemplateRepository, root string) (ImportReport, error) {
	blueprints := filepath.Join(root, filepath.FromSlash(repository.CatalogPath), "blueprints")
	entries, err := os.ReadDir(blueprints)
	if err != nil {
		return ImportReport{}, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	report := ImportReport{Failed: map[string]string{}}
	items := make([]store.Template, 0, len(entries))
	identities := map[string]string{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(blueprints, entry.Name())
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
		if meta.ID == "" || meta.Version == "" || meta.Name == "" {
			report.Failed[entry.Name()] = "meta.json requires id, version, and name"
			continue
		}
		provenance := map[string]string{"templateToml": string(tomlBytes), "repositorySlug": repository.Slug, "repositoryUrl": repository.RepositoryURL, "gitRef": repository.GitRef}
		if key, keyErr := ParsePublicKey([]byte(repository.TrustedPublicKey)); keyErr == nil && len(key) > 0 {
			provenance["catalogSigner"] = PublicKeyFingerprint(key)
		}
		config, _ := json.Marshal(provenance)
		sum := sha256.Sum256(append(tomlBytes, compose...))
		key := repository.Slug + "/" + meta.ID
		identity := key + "\x00" + meta.Version
		if previous, duplicate := identities[identity]; duplicate {
			report.Failed[entry.Name()] = fmt.Sprintf("duplicates template key and version from %s", previous)
			continue
		}
		identities[identity] = entry.Name()
		organizationID, repositoryID := repository.OrganizationID, repository.ID
		items = append(items, store.Template{OrganizationID: &organizationID, RepositoryID: &repositoryID, Key: key, Version: meta.Version, Name: meta.Name, Description: meta.Description, ComposeYAML: string(compose), Config: config, Source: "github", SourcePath: filepath.ToSlash(filepath.Join(repository.CatalogPath, "blueprints", entry.Name())), Checksum: hex.EncodeToString(sum[:])})
	}
	if len(report.Failed) > 0 {
		return report, fmt.Errorf("catalog contains %d invalid template(s)", len(report.Failed))
	}
	if err = db.ReplaceRepositoryTemplates(ctx, repository.OrganizationID, repository.ID, items); err != nil {
		return report, err
	}
	report.Imported = len(items)
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
