package migrate

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/deploy"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DokployOptions struct {
	SourceURL            string
	SourceOrganizationID string
	TargetOrganizationID uuid.UUID
	DryRun               bool
	EncryptionKeys       [][]byte
}

type DokployReport struct {
	DryRun       bool     `json:"dryRun"`
	Projects     int      `json:"projects"`
	Environments int      `json:"environments"`
	Services     int      `json:"services"`
	Routes       int      `json:"routes"`
	Skipped      int      `json:"skipped"`
	Warnings     []string `json:"warnings"`
}

type sourceProject struct{ id, name, description string }
type sourceEnvironment struct{ id, projectID, name string }
type sourceCompose struct{ id, environmentID, name, appName, compose, env string }
type sourceRoute struct {
	id, composeID, host, path, serviceName, resolver string
	port                                             int
	tls, enabled                                     bool
}

func ImportDokploy(ctx context.Context, destination *store.Store, box *cryptox.Box, compiler deploy.Compiler, options DokployOptions) (DokployReport, error) {
	report := DokployReport{DryRun: options.DryRun, Warnings: []string{}}
	if options.SourceURL == "" || options.SourceOrganizationID == "" || options.TargetOrganizationID == uuid.Nil {
		return report, errors.New("source URL, source organization, and target organization are required")
	}
	source, err := pgxpool.New(ctx, options.SourceURL)
	if err != nil {
		return report, fmt.Errorf("open Dokploy database: %w", err)
	}
	defer source.Close()
	if err = source.Ping(ctx); err != nil {
		return report, fmt.Errorf("connect to Dokploy database: %w", err)
	}
	var targetExists bool
	if err = destination.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM organizations WHERE id=$1)`, options.TargetOrganizationID).Scan(&targetExists); err != nil || !targetExists {
		if err == nil {
			err = store.ErrNotFound
		}
		return report, fmt.Errorf("target organization: %w", err)
	}

	projects, err := readProjects(ctx, source, options.SourceOrganizationID)
	if err != nil {
		return report, err
	}
	environments, err := readEnvironments(ctx, source, options.SourceOrganizationID)
	if err != nil {
		return report, err
	}
	services, err := readCompose(ctx, source, options.SourceOrganizationID)
	if err != nil {
		return report, err
	}
	routes, err := readRoutes(ctx, source, options.SourceOrganizationID)
	if err != nil {
		return report, err
	}
	report.Projects, report.Environments, report.Services = len(projects), len(environments), len(services)

	validServices := map[string]bool{}
	for _, service := range services {
		if strings.TrimSpace(service.compose) == "" {
			report.Skipped++
			report.Warnings = append(report.Warnings, fmt.Sprintf("compose %s has no inline composeFile and was skipped", service.id))
			continue
		}
		if _, compileErr := compiler.Compile(service.compose, nil); compileErr != nil {
			report.Skipped++
			report.Warnings = append(report.Warnings, fmt.Sprintf("compose %s is incompatible: %v", service.id, compileErr))
			continue
		}
		validServices[service.id] = true
		if strings.HasPrefix(service.env, "enc:v1:") && len(options.EncryptionKeys) == 0 {
			report.Warnings = append(report.Warnings, fmt.Sprintf("compose %s has encrypted environment values; supply --encryption-key-file before import", service.id))
		}
	}
	filteredRoutes := make([]sourceRoute, 0, len(routes))
	seenRoute := map[string]bool{}
	for _, route := range routes {
		if !route.enabled || !validServices[route.composeID] || route.serviceName == "" || route.port < 1 || route.port > 65535 {
			report.Skipped++
			continue
		}
		key := strings.ToLower(route.host) + "\x00" + route.path
		if seenRoute[key] {
			report.Skipped++
			report.Warnings = append(report.Warnings, "duplicate route "+route.host+route.path+" was skipped")
			continue
		}
		seenRoute[key] = true
		filteredRoutes = append(filteredRoutes, route)
	}
	report.Routes = len(filteredRoutes)
	var applications, databases int
	_ = source.QueryRow(ctx, `SELECT count(*) FROM application a JOIN environment e ON e."environmentId"=a."environmentId" JOIN project p ON p."projectId"=e."projectId" WHERE p."organizationId"=$1`, options.SourceOrganizationID).Scan(&applications)
	for _, table := range []string{"postgres", "mysql", "mariadb", "mongo", "redis", "libsql"} {
		var count int
		query := fmt.Sprintf(`SELECT count(*) FROM %s d JOIN environment e ON e."environmentId"=d."environmentId" JOIN project p ON p."projectId"=e."projectId" WHERE p."organizationId"=$1`, pgx.Identifier{table}.Sanitize())
		if source.QueryRow(ctx, query, options.SourceOrganizationID).Scan(&count) == nil {
			databases += count
		}
	}
	if applications > 0 {
		report.Warnings = append(report.Warnings, fmt.Sprintf("%d Dokploy application records require the application conversion phase and were not imported", applications))
		report.Skipped += applications
	}
	if databases > 0 {
		report.Warnings = append(report.Warnings, fmt.Sprintf("%d managed database records require secret-aware conversion and were not imported", databases))
		report.Skipped += databases
	}
	sort.Strings(report.Warnings)
	if options.DryRun {
		return report, nil
	}

	tx, err := destination.Pool.Begin(ctx)
	if err != nil {
		return report, err
	}
	defer tx.Rollback(ctx)
	for _, item := range projects {
		id := mappedID(options, "project", item.id)
		_, err = tx.Exec(ctx, `INSERT INTO projects(id,organization_id,name,slug,description) VALUES($1,$2,$3,$4,$5) ON CONFLICT(id) DO UPDATE SET name=excluded.name,description=excluded.description`, id, options.TargetOrganizationID, item.name, migratedSlug(item.name, id), item.description)
		if err != nil {
			return report, fmt.Errorf("import project %s: %w", item.id, err)
		}
	}
	for _, item := range environments {
		id, projectID := mappedID(options, "environment", item.id), mappedID(options, "project", item.projectID)
		_, err = tx.Exec(ctx, `INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,$3,$4) ON CONFLICT(id) DO UPDATE SET name=excluded.name`, id, projectID, item.name, migratedSlug(item.name, id))
		if err != nil {
			return report, fmt.Errorf("import environment %s: %w", item.id, err)
		}
	}
	for _, item := range services {
		if !validServices[item.id] {
			continue
		}
		id := mappedID(options, "compose", item.id)
		encryptedEnv := ""
		if item.env != "" {
			plain, decryptErr := decryptDokploy(item.env, options.EncryptionKeys)
			if decryptErr != nil {
				return report, fmt.Errorf("decrypt compose %s environment: %w", item.id, decryptErr)
			}
			environment := parseEnv(plain)
			data, _ := json.Marshal(environment)
			encryptedEnv, err = box.Encrypt(data, "compose-env")
			if err != nil {
				return report, err
			}
		}
		name := item.name
		if name == "" {
			name = item.appName
		}
		_, err = tx.Exec(ctx, `INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml,encrypted_env) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(id) DO UPDATE SET name=excluded.name,compose_yaml=excluded.compose_yaml,encrypted_env=excluded.encrypted_env,revision=compose_services.revision+1,updated_at=now()`, id, mappedID(options, "environment", item.environmentID), name, migratedSlug(item.appName, id), migratedSlug(item.appName, id), item.compose, encryptedEnv)
		if err != nil {
			return report, fmt.Errorf("import compose %s: %w", item.id, err)
		}
	}
	for _, item := range filteredRoutes {
		id := mappedID(options, "route", item.id)
		path := item.path
		if path == "" {
			path = "/"
		}
		resolver := item.resolver
		if resolver == "" {
			resolver = "letsencrypt"
		}
		_, err = tx.Exec(ctx, `INSERT INTO routes(id,compose_service_id,service_name,host,path_prefix,target_port,tls,certificate_resolver) VALUES($1,$2,$3,lower($4),$5,$6,$7,$8) ON CONFLICT(id) DO UPDATE SET service_name=excluded.service_name,host=excluded.host,path_prefix=excluded.path_prefix,target_port=excluded.target_port,tls=excluded.tls,certificate_resolver=excluded.certificate_resolver`, id, mappedID(options, "compose", item.composeID), item.serviceName, item.host, path, item.port, item.tls, resolver)
		if err != nil {
			return report, fmt.Errorf("import route %s: %w", item.id, err)
		}
	}
	return report, tx.Commit(ctx)
}

func readProjects(ctx context.Context, db *pgxpool.Pool, org string) ([]sourceProject, error) {
	rows, err := db.Query(ctx, `SELECT "projectId",name,COALESCE(description,'') FROM project WHERE "organizationId"=$1 ORDER BY "projectId"`, org)
	if err != nil {
		return nil, fmt.Errorf("read Dokploy projects: %w", err)
	}
	defer rows.Close()
	items := []sourceProject{}
	for rows.Next() {
		var v sourceProject
		if err = rows.Scan(&v.id, &v.name, &v.description); err != nil {
			return nil, err
		}
		items = append(items, v)
	}
	return items, rows.Err()
}
func readEnvironments(ctx context.Context, db *pgxpool.Pool, org string) ([]sourceEnvironment, error) {
	rows, err := db.Query(ctx, `SELECT e."environmentId",e."projectId",e.name FROM environment e JOIN project p ON p."projectId"=e."projectId" WHERE p."organizationId"=$1 ORDER BY e."environmentId"`, org)
	if err != nil {
		return nil, fmt.Errorf("read Dokploy environments: %w", err)
	}
	defer rows.Close()
	items := []sourceEnvironment{}
	for rows.Next() {
		var v sourceEnvironment
		if err = rows.Scan(&v.id, &v.projectID, &v.name); err != nil {
			return nil, err
		}
		items = append(items, v)
	}
	return items, rows.Err()
}
func readCompose(ctx context.Context, db *pgxpool.Pool, org string) ([]sourceCompose, error) {
	rows, err := db.Query(ctx, `SELECT c."composeId",c."environmentId",c.name,c."appName",c."composeFile",COALESCE(c.env,'') FROM compose c JOIN environment e ON e."environmentId"=c."environmentId" JOIN project p ON p."projectId"=e."projectId" WHERE p."organizationId"=$1 ORDER BY c."composeId"`, org)
	if err != nil {
		return nil, fmt.Errorf("read Dokploy compose services: %w", err)
	}
	defer rows.Close()
	items := []sourceCompose{}
	for rows.Next() {
		var v sourceCompose
		if err = rows.Scan(&v.id, &v.environmentID, &v.name, &v.appName, &v.compose, &v.env); err != nil {
			return nil, err
		}
		items = append(items, v)
	}
	return items, rows.Err()
}
func readRoutes(ctx context.Context, db *pgxpool.Pool, org string) ([]sourceRoute, error) {
	rows, err := db.Query(ctx, `SELECT d."domainId",d."composeId",d.host,COALESCE(d.path,'/'),COALESCE(d."serviceName",''),COALESCE(d.port,3000),d.https,d.enabled,COALESCE(d."customCertResolver",'') FROM domain d JOIN compose c ON c."composeId"=d."composeId" JOIN environment e ON e."environmentId"=c."environmentId" JOIN project p ON p."projectId"=e."projectId" WHERE p."organizationId"=$1 AND d."composeId" IS NOT NULL ORDER BY d."domainId"`, org)
	if err != nil {
		return nil, fmt.Errorf("read Dokploy routes: %w", err)
	}
	defer rows.Close()
	items := []sourceRoute{}
	for rows.Next() {
		var v sourceRoute
		if err = rows.Scan(&v.id, &v.composeID, &v.host, &v.path, &v.serviceName, &v.port, &v.tls, &v.enabled, &v.resolver); err != nil {
			return nil, err
		}
		items = append(items, v)
	}
	return items, rows.Err()
}

func mappedID(options DokployOptions, kind, sourceID string) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("dockyard:dokploy:"+options.TargetOrganizationID.String()+":"+options.SourceOrganizationID+":"+kind+":"+sourceID))
}

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

func migratedSlug(name string, id uuid.UUID) string {
	base := strings.Trim(nonSlug.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if base == "" {
		base = "imported"
	}
	if len(base) > 52 {
		base = base[:52]
	}
	return base + "-" + strings.Split(id.String(), "-")[0]
}

func decryptDokploy(value string, keys [][]byte) (string, error) {
	if !strings.HasPrefix(value, "enc:v1:") {
		return value, nil
	}
	payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, "enc:v1:"))
	if err != nil {
		return "", err
	}
	if len(payload) < 28 {
		return "", errors.New("encrypted value is too short")
	}
	for _, key := range keys {
		if len(key) != 32 {
			continue
		}
		block, e := aes.NewCipher(key)
		if e != nil {
			continue
		}
		var aead cipher.AEAD
		aead, e = cipher.NewGCM(block)
		if e != nil {
			continue
		}
		ciphertextAndTag := append(append([]byte{}, payload[28:]...), payload[12:28]...)
		plain, e := aead.Open(nil, payload[:12], ciphertextAndTag, nil)
		if e == nil {
			return string(plain), nil
		}
	}
	return "", errors.New("no Dokploy encryption key could decrypt the value")
}
func ParseDokployKeys(data []byte) ([][]byte, error) {
	keys := [][]byte{}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		key, err := hex.DecodeString(line)
		if err != nil || len(key) != 32 {
			return nil, errors.New("Dokploy encryption keys must be 32-byte hex values")
		}
		keys = append(keys, key)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return keys, nil
}
func parseEnv(value string) map[string]string {
	result := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(value))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		val = strings.TrimSpace(val)
		if len(val) >= 2 && ((val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'')) {
			val = val[1 : len(val)-1]
		}
		result[key] = val
	}
	return result
}
