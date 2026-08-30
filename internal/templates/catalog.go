package templates

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/bendahma/dokploy-go/internal/deploy"
	"github.com/bendahma/dokploy-go/internal/store"
)

type ImportReport struct {
	Imported   int               `json:"imported"`
	Restricted int               `json:"restricted"`
	Invalid    int               `json:"invalid"`
	Failed     map[string]string `json:"failed"`
}

const (
	SafetyClassSafe           = "safe"
	SafetyClassRequiresUnsafe = "requires_unsafe"
	SafetyClassInvalid        = "invalid"
)

type metadata struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
}

var templateMetadataIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

func parseTemplateMetadata(data []byte) (metadata, error) {
	var item metadata
	if err := json.Unmarshal(data, &item); err != nil {
		return metadata{}, fmt.Errorf("parse meta.json: %w", err)
	}
	item.ID = strings.TrimSpace(item.ID)
	item.Name = strings.TrimSpace(item.Name)
	item.Version = strings.TrimSpace(item.Version)
	item.Description = strings.TrimSpace(item.Description)
	if !templateMetadataIDPattern.MatchString(item.ID) {
		return metadata{}, errors.New("meta.json id must be a lowercase template slug of at most 128 characters")
	}
	if item.Version == "" || len(item.Version) > 128 {
		return metadata{}, errors.New("meta.json version must contain between 1 and 128 characters")
	}
	if item.Name == "" || len(item.Name) > 200 {
		return metadata{}, errors.New("meta.json name must contain between 1 and 200 characters")
	}
	if len(item.Description) > 4096 {
		return metadata{}, errors.New("meta.json description must not exceed 4096 characters")
	}
	return item, nil
}

func ImportDokployCatalog(ctx context.Context, db *store.Store, root string) (ImportReport, error) {
	entries, err := os.ReadDir(filepath.Join(root, "blueprints"))
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
		path := filepath.Join(root, "blueprints", entry.Name())
		metaBytes, readErr := os.ReadFile(filepath.Join(path, "meta.json"))
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
		safetyClass, safetyReason, classifyErr := classifyCatalogBlueprint(path, "dockyard-public")
		if classifyErr != nil {
			readErr = classifyErr
			report.Failed[entry.Name()] = readErr.Error()
			continue
		}
		if safetyClass == SafetyClassRequiresUnsafe {
			report.Restricted++
		} else if safetyClass == SafetyClassInvalid {
			report.Invalid++
		}
		config, _ := json.Marshal(map[string]string{"templateToml": string(tomlBytes), "safetyClass": safetyClass, "safetyReason": safetyReason})
		sum := sha256.Sum256(append(tomlBytes, compose...))
		items = append(items, store.Template{Key: meta.ID, Version: meta.Version, Name: meta.Name, Description: meta.Description, ComposeYAML: string(compose), Config: config, Source: "dokploy", SourcePath: filepath.ToSlash(filepath.Join("blueprints", entry.Name())), Checksum: hex.EncodeToString(sum[:])})
	}
	if len(report.Failed) > 0 {
		return report, fmt.Errorf("catalog contains %d invalid template(s)", len(report.Failed))
	}
	if len(items) == 0 {
		return report, errors.New("catalog contains no templates")
	}
	if err = db.UpsertGlobalTemplates(ctx, items); err != nil {
		return report, err
	}
	report.Imported = len(items)
	return report, nil
}

// ImportRepositoryCatalog imports a Dokploy-compatible catalog while namespacing
// keys by repository slug. This keeps identically named templates from multiple
// repositories independent and makes their provenance explicit.
func ImportRepositoryCatalog(ctx context.Context, db *store.Store, repository store.TemplateRepository, root string) (ImportReport, error) {
	catalogPath, err := NormalizeCatalogPath(repository.CatalogPath)
	if err != nil {
		return ImportReport{}, err
	}
	blueprints := filepath.Join(root, filepath.FromSlash(catalogPath), "blueprints")
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
		meta, metadataErr := parseTemplateMetadata(metaBytes)
		if metadataErr != nil {
			report.Failed[entry.Name()] = metadataErr.Error()
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
		safetyClass, safetyReason, classifyErr := classifyCatalogBlueprint(path, "dockyard-public")
		if classifyErr != nil {
			readErr = classifyErr
			report.Failed[entry.Name()] = readErr.Error()
			continue
		}
		if safetyClass == SafetyClassRequiresUnsafe {
			report.Restricted++
		} else if safetyClass == SafetyClassInvalid {
			report.Invalid++
		}
		provenance := map[string]string{"templateToml": string(tomlBytes), "repositorySlug": repository.Slug, "repositoryUrl": repository.RepositoryURL, "gitRef": repository.GitRef, "safetyClass": safetyClass, "safetyReason": safetyReason}
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
	if len(items) == 0 {
		return report, errors.New("catalog contains no templates")
	}
	if err = db.ReplaceRepositoryTemplatesForSync(ctx, repository, items); err != nil {
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
	identities := map[string]string{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		blueprint := filepath.Join(root, "blueprints", entry.Name())
		metaBytes, loadErr := os.ReadFile(filepath.Join(blueprint, "meta.json"))
		var meta metadata
		if loadErr == nil {
			meta, loadErr = parseTemplateMetadata(metaBytes)
		}
		if loadErr == nil {
			identity := meta.ID + "\x00" + meta.Version
			if previous, duplicate := identities[identity]; duplicate {
				loadErr = fmt.Errorf("duplicates template key and version from %s", previous)
			} else {
				identities[identity] = entry.Name()
			}
		}
		if loadErr == nil {
			loadErr = validateCatalogBlueprint(blueprint, compiler)
		}
		if loadErr != nil {
			report.Failed[entry.Name()] = loadErr.Error()
		} else {
			report.Imported++
		}
	}
	if len(report.Failed) > 0 {
		return report, fmt.Errorf("catalog contains %d invalid template(s)", len(report.Failed))
	}
	if report.Imported == 0 {
		return report, fmt.Errorf("catalog contains no templates")
	}
	return report, nil
}

func validateCatalogBlueprint(blueprint string, compiler deploy.Compiler) error {
	compose, routes, err := loadCatalogBlueprint(blueprint)
	if err != nil {
		return err
	}
	_, err = compiler.Compile(compose, routes)
	return err
}

func classifyCatalogBlueprint(blueprint, publicNetwork string) (string, string, error) {
	compose, routes, err := loadCatalogBlueprint(blueprint)
	if err != nil {
		return SafetyClassInvalid, boundedSafetyReason(err), nil
	}
	class, reason, err := ClassifyComposeSafety(compose, routes, publicNetwork)
	if err != nil {
		return SafetyClassInvalid, boundedSafetyReason(err), nil
	}
	return class, reason, nil
}

// ClassifyComposeSafety distinguishes structurally invalid templates from
// valid templates that need the operator's explicit unsafe-workload opt-in.
func ClassifyComposeSafety(compose string, routes []store.Route, publicNetwork string) (string, string, error) {
	_, safeErr := (deploy.Compiler{PublicNetwork: publicNetwork}).Compile(compose, routes)
	if safeErr == nil {
		return SafetyClassSafe, "", nil
	}
	if _, unsafeErr := (deploy.Compiler{PublicNetwork: publicNetwork, AllowUnsafe: true}).Compile(compose, routes); unsafeErr != nil {
		return "", "", unsafeErr
	}
	return SafetyClassRequiresUnsafe, boundedSafetyReason(safeErr), nil
}

func boundedSafetyReason(err error) string {
	reason := err.Error()
	if len(reason) > 512 {
		reason = reason[:512]
	}
	return reason
}

func loadCatalogBlueprint(blueprint string) (string, []store.Route, error) {
	instance, err := LoadDokployDirectory(blueprint, "example.invalid")
	if err != nil {
		return "", nil, err
	}
	routes, err := instanceRoutes(instance)
	if err != nil {
		return "", nil, err
	}
	return instance.ComposeYAML, routes, nil
}

func instanceRoutes(instance Instance) ([]store.Route, error) {
	routes := make([]store.Route, 0, len(instance.Domains))
	for _, domain := range instance.Domains {
		port, portErr := PortNumber(domain.Port)
		if portErr != nil {
			return nil, portErr
		}
		routes = append(routes, store.Route{
			ServiceName: domain.ServiceName, Host: domain.Host, PathPrefix: domain.Path,
			TargetPort: port, TLS: true, CertificateResolver: "letsencrypt",
		})
	}
	return routes, nil
}
