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
	"github.com/bendahma/dokploy-go/internal/database"
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
	RegistryPrefix       string
	DryRun               bool
	EncryptionKeys       [][]byte
}

type DokployReport struct {
	DryRun                bool                    `json:"dryRun"`
	Projects              int                     `json:"projects"`
	Environments          int                     `json:"environments"`
	Services              int                     `json:"services"`
	Applications          int                     `json:"applications"`
	Databases             int                     `json:"databases"`
	Routes                int                     `json:"routes"`
	BackupDestinations    int                     `json:"backupDestinations"`
	BackupPolicies        int                     `json:"backupPolicies"`
	SourceCredentials     int                     `json:"sourceCredentials"`
	NotificationEndpoints int                     `json:"notificationEndpoints"`
	Skipped               int                     `json:"skipped"`
	Warnings              []string                `json:"warnings"`
	Resources             []DokployResourceReport `json:"resources"`
}

type DokployResourceReport struct {
	SourceKind string         `json:"sourceKind"`
	SourceID   string         `json:"sourceId"`
	TargetID   *uuid.UUID     `json:"targetId,omitempty"`
	Status     string         `json:"status"`
	Reason     string         `json:"reason,omitempty"`
	Metadata   map[string]any `json:"metadata"`
}

type sourceProject struct{ id, name, description string }
type sourceEnvironment struct{ id, projectID, name string }
type sourceCompose struct{ id, environmentID, name, appName, compose, env string }
type sourceDatabase struct {
	id, environmentID, name, appName, engine                   string
	databaseName, databaseUser, databasePassword, rootPassword string
	dockerImage, env                                           string
}
type sourceRoute struct {
	id, composeID, host, path, serviceName, resolver string
	port                                             int
	tls, enabled                                     bool
}

type preparedBackupDestination struct {
	sourceID, key, name, endpoint, region, bucket, prefix string
	id, reportID                                          uuid.UUID
	useTLS                                                bool
	encryptedCredentials                                  string
}

type preparedBackupPolicy struct {
	source                        sourceBackupPolicy
	id, databaseID, destinationID uuid.UUID
	intervalSeconds               int
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
	applications, err := readApplications(ctx, source, options.SourceOrganizationID)
	if err != nil {
		return report, err
	}
	applicationRoutes, err := readApplicationRoutes(ctx, source, options.SourceOrganizationID)
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
	validApplications := map[string]bool{}
	for _, item := range applications {
		prepared, warnings, prepareErr := prepareApplication(item, options)
		report.Warnings = append(report.Warnings, warnings...)
		if prepareErr == nil {
			_, prepareErr = compiler.Compile(prepared.composeYAML, nil)
		}
		if prepareErr != nil {
			report.Skipped++
			report.Warnings = append(report.Warnings, fmt.Sprintf("application %s is incompatible: %v", item.ID, prepareErr))
			report.Resources = append(report.Resources, dokployApplicationReport(item, nil, "skipped", prepareErr.Error()))
			continue
		}
		validApplications[item.ID] = true
		targetID := prepared.serviceID
		report.Resources = append(report.Resources, dokployApplicationReport(item, &targetID, "imported", ""))
		if strings.HasPrefix(item.Env, "enc:v1:") && len(options.EncryptionKeys) == 0 {
			report.Warnings = append(report.Warnings, fmt.Sprintf("application %s has encrypted environment values; supply --encryption-key-file before import", item.ID))
		}
	}
	filteredApplicationRoutes := make([]sourceApplicationRoute, 0, len(applicationRoutes))
	for _, route := range applicationRoutes {
		if !route.enabled || !validApplications[route.applicationID] || route.port < 1 || route.port > 65535 {
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
		filteredApplicationRoutes = append(filteredApplicationRoutes, route)
	}
	report.Routes = len(filteredRoutes) + len(filteredApplicationRoutes)
	databases, err := readDatabases(ctx, source, options.SourceOrganizationID)
	if err != nil {
		return report, err
	}
	report.Applications = len(applications)
	report.Databases = len(databases)
	backupDestinations, err := readBackupDestinations(ctx, source, options.SourceOrganizationID)
	if err != nil {
		return report, err
	}
	backupPolicies, err := readBackupPolicies(ctx, source, options.SourceOrganizationID)
	if err != nil {
		return report, err
	}
	report.BackupDestinations, report.BackupPolicies = len(backupDestinations), len(backupPolicies)
	sourceCredentials, err := readSourceCredentials(ctx, source, options.SourceOrganizationID)
	if err != nil {
		return report, err
	}
	report.SourceCredentials = len(sourceCredentials)
	notifications, err := readNotifications(ctx, source, options.SourceOrganizationID)
	if err != nil {
		return report, err
	}
	report.NotificationEndpoints = len(notifications)
	registry := database.NewRegistry()
	validDatabases := map[string]bool{}
	for _, item := range databases {
		_, renderErr := registry.Render(item.engine, database.Request{Name: migratedSlug(item.appName, mappedID(options, "database:"+item.engine, item.id)), Version: imageVersion(item.dockerImage, "latest"), Config: databaseConfig(item)})
		if renderErr != nil {
			report.Skipped++
			report.Warnings = append(report.Warnings, fmt.Sprintf("%s database %s is incompatible: %v", item.engine, item.id, renderErr))
			continue
		}
		validDatabases[item.engine+":"+item.id] = true
		if strings.HasPrefix(item.env, "enc:v1:") && len(options.EncryptionKeys) == 0 {
			report.Warnings = append(report.Warnings, fmt.Sprintf("%s database %s has encrypted environment values; supply --encryption-key-file before import", item.engine, item.id))
		}
	}
	preparedDestinations := map[string]preparedBackupDestination{}
	destinationSources := map[string]sourceBackupDestination{}
	for _, item := range backupDestinations {
		destinationSources[item.id] = item
		if len(item.additionalFlags) > 0 {
			report.Warnings = append(report.Warnings, fmt.Sprintf("backup destination %s has additional flags that require manual review", item.id))
		}
		prepared, prepareErr := prepareDokployBackupDestination(box, options, item, "")
		if prepareErr != nil {
			report.Skipped++
			report.Warnings = append(report.Warnings, fmt.Sprintf("backup destination %s is incompatible: %v", item.id, prepareErr))
			report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "backup_destination", SourceID: item.id, Status: "skipped", Reason: prepareErr.Error(), Metadata: backupDestinationMetadata(item, "")})
			continue
		}
		preparedDestinations[prepared.key] = prepared
		report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "backup_destination", SourceID: item.id, TargetID: &prepared.reportID, Status: "imported", Metadata: backupDestinationMetadata(item, "")})
	}
	preparedPolicies := []preparedBackupPolicy{}
	seenDatabasePolicy := map[uuid.UUID]bool{}
	for _, item := range backupPolicies {
		policyID := mappedID(options, "backup-policy", item.id)
		metadata := map[string]any{"schedule": item.schedule, "databaseType": item.databaseType, "backupType": item.backupType, "prefix": item.prefix, "enabled": item.enabled, "retentionCount": item.retentionCount}
		reason := ""
		interval, supportedSchedule := cronInterval(item.schedule)
		databaseID := mappedID(options, "database:"+item.databaseType, item.databaseID)
		if item.backupType != "database" {
			reason = "Compose backup policies are not supported"
		} else if !validDatabases[item.databaseType+":"+item.databaseID] || item.databaseID == "" || !migrationBackupCapableEngine(item.databaseType) {
			reason = "the referenced database was not imported or is not backup-capable"
		} else if !supportedSchedule || interval < 900 || interval > 2_678_400 {
			reason = "cron schedule cannot be represented as a fixed 15-minute to 31-day interval"
		} else if item.retentionCount < 1 || item.retentionCount > 100 {
			reason = "retention count is outside Dockyard's 1..100 range"
		} else if seenDatabasePolicy[databaseID] {
			reason = "Dockyard supports one backup policy per database"
		}
		destinationSource, destinationFound := destinationSources[item.destinationID]
		if reason == "" && !destinationFound {
			reason = "the referenced backup destination was not found"
		}
		var preparedDestination preparedBackupDestination
		if reason == "" {
			preparedDestination, err = prepareDokployBackupDestination(box, options, destinationSource, item.prefix)
			if err != nil {
				reason = err.Error()
			}
		}
		if reason != "" {
			report.Skipped++
			report.Warnings = append(report.Warnings, fmt.Sprintf("backup policy %s was skipped: %s", item.id, reason))
			report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "backup_policy", SourceID: item.id, Status: "skipped", Reason: reason, Metadata: metadata})
			continue
		}
		seenDatabasePolicy[databaseID] = true
		preparedDestinations[preparedDestination.key] = preparedDestination
		preparedPolicies = append(preparedPolicies, preparedBackupPolicy{source: item, id: policyID, databaseID: databaseID, destinationID: preparedDestination.id, intervalSeconds: interval})
		report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "backup_policy", SourceID: item.id, TargetID: &policyID, Status: "imported", Metadata: metadata})
	}
	preparedCredentials := map[string]preparedSourceCredential{}
	for _, item := range sourceCredentials {
		prepared, prepareErr := prepareSourceCredential(box, options, item)
		metadata := map[string]any{"name": item.name, "provider": item.sourceKind, "server": item.server, "kind": item.kind}
		if prepareErr != nil {
			report.Skipped++
			report.Warnings = append(report.Warnings, fmt.Sprintf("%s credential %s was skipped: %v", item.sourceKind, item.sourceID, prepareErr))
			report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "source_credential", SourceID: item.sourceKind + ":" + item.sourceID, Status: "skipped", Reason: prepareErr.Error(), Metadata: metadata})
			continue
		}
		preparedCredentials[credentialKey(item.sourceKind, item.sourceID)] = prepared
		report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "source_credential", SourceID: item.sourceKind + ":" + item.sourceID, TargetID: &prepared.id, Status: "imported", Metadata: metadata})
	}
	preparedNotifications := []preparedNotification{}
	for _, item := range notifications {
		prepared, warnings, prepareErr := prepareNotification(box, options, item)
		report.Warnings = append(report.Warnings, warnings...)
		metadata := notificationMetadata(item, prepared.events)
		if prepareErr != nil {
			report.Skipped++
			report.Warnings = append(report.Warnings, fmt.Sprintf("notification %s was skipped: %v", item.id, prepareErr))
			report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "notification", SourceID: item.id, Status: "skipped", Reason: prepareErr.Error(), Metadata: metadata})
			continue
		}
		preparedNotifications = append(preparedNotifications, prepared)
		report.Resources = append(report.Resources, DokployResourceReport{SourceKind: "notification", SourceID: item.id, TargetID: &prepared.id, Status: "imported", Metadata: metadata})
	}
	for _, item := range applications {
		if !validApplications[item.ID] {
			continue
		}
		providerID := applicationProviderID(item)
		if providerID != "" {
			if _, ok := preparedCredentials[credentialKey(item.SourceType, providerID)]; !ok {
				report.Warnings = append(report.Warnings, fmt.Sprintf("application %s has no convertible %s credential", item.ID, item.SourceType))
			}
		}
		registryID := item.BuildRegistryID
		if registryID == "" {
			registryID = item.RegistryID
		}
		if registryID != "" {
			credential, ok := preparedCredentials[credentialKey("registry", registryID)]
			if !ok || credential.server != migrationImageRegistry(options.RegistryPrefix) {
				report.Warnings = append(report.Warnings, fmt.Sprintf("application %s build registry credential could not be attached to %s", item.ID, options.RegistryPrefix))
			}
		}
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
	for _, item := range preparedCredentials {
		name := strings.TrimSpace(item.source.name) + " (Dokploy " + strings.Split(item.id.String(), "-")[0] + ")"
		_, err = tx.Exec(ctx, `INSERT INTO source_credentials(id,organization_id,kind,name,server,username,encrypted_secret) VALUES($1,$2,$3,$4,$5,$6,$7)
			ON CONFLICT(id) DO UPDATE SET name=excluded.name,server=excluded.server,username=excluded.username,encrypted_secret=excluded.encrypted_secret,updated_at=now()`, item.id, options.TargetOrganizationID, item.source.kind, name, item.server, item.source.username, item.secret)
		if err != nil {
			return report, fmt.Errorf("import %s credential %s: %w", item.source.sourceKind, item.source.sourceID, err)
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
	for _, item := range applications {
		if !validApplications[item.ID] {
			continue
		}
		if item.Env != "" {
			plain, decryptErr := decryptDokploy(item.Env, options.EncryptionKeys)
			if decryptErr != nil {
				return report, fmt.Errorf("decrypt application %s environment: %w", item.ID, decryptErr)
			}
			item.Env = plain
		}
		prepared, _, prepareErr := prepareApplication(item, options)
		if prepareErr != nil {
			return report, fmt.Errorf("prepare application %s: %w", item.ID, prepareErr)
		}
		environmentJSON, _ := json.Marshal(prepared.environment)
		encryptedEnvironment, encryptErr := box.Encrypt(environmentJSON, "compose-env")
		if encryptErr != nil {
			return report, encryptErr
		}
		_, err = tx.Exec(ctx, `INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml,encrypted_env) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(id) DO UPDATE SET name=excluded.name,compose_yaml=excluded.compose_yaml,encrypted_env=excluded.encrypted_env,revision=compose_services.revision+1,updated_at=now()`, prepared.serviceID, mappedID(options, "environment", item.EnvironmentID), item.Name, "app-"+prepared.slug, prepared.slug, prepared.composeYAML, encryptedEnvironment)
		if err != nil {
			return report, fmt.Errorf("import application %s: %w", item.ID, err)
		}
		if prepared.source != nil {
			var gitCredentialID, registryCredentialID *uuid.UUID
			if providerID := applicationProviderID(item); providerID != "" {
				if credential, ok := preparedCredentials[credentialKey(item.SourceType, providerID)]; ok && credential.server == repositoryHost(prepared.source.RepositoryURL) {
					id := credential.id
					gitCredentialID = &id
				}
			}
			registryID := item.BuildRegistryID
			if registryID == "" {
				registryID = item.RegistryID
			}
			if credential, ok := preparedCredentials[credentialKey("registry", registryID)]; ok && credential.server == migrationImageRegistry(prepared.source.RegistryImage) {
				id := credential.id
				registryCredentialID = &id
			}
			encryptedBuildConfig := ""
			if len(prepared.source.BuildArguments) > 0 || len(prepared.source.BuildSecrets) > 0 {
				data, marshalErr := json.Marshal(store.ApplicationBuildConfig{Arguments: prepared.source.BuildArguments, Secrets: prepared.source.BuildSecrets})
				if marshalErr != nil {
					return report, marshalErr
				}
				encryptedBuildConfig, err = box.Encrypt(data, "application-build-config:"+prepared.source.ComposeServiceID.String())
				if err != nil {
					return report, err
				}
			}
			_, err = tx.Exec(ctx, `INSERT INTO application_sources(compose_service_id,source_type,repository_url,git_ref,context_directory,dockerfile,build_type,builder_image,output_directory,build_target,enable_submodules,encrypted_build_config,target_service,registry_image,git_credential_id,registry_credential_id) VALUES($1,'git',$2,$3,$4,$5,$6,'',$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT(compose_service_id) DO UPDATE SET source_type=excluded.source_type,repository_url=excluded.repository_url,git_ref=excluded.git_ref,context_directory=excluded.context_directory,dockerfile=excluded.dockerfile,build_type=excluded.build_type,builder_image=excluded.builder_image,output_directory=excluded.output_directory,build_target=excluded.build_target,enable_submodules=excluded.enable_submodules,encrypted_build_config=excluded.encrypted_build_config,target_service=excluded.target_service,registry_image=excluded.registry_image,git_credential_id=excluded.git_credential_id,registry_credential_id=excluded.registry_credential_id,updated_at=now()`, prepared.source.ComposeServiceID, prepared.source.RepositoryURL, prepared.source.GitRef, prepared.source.ContextDirectory, prepared.source.Dockerfile, prepared.source.BuildType, prepared.source.OutputDirectory, prepared.source.BuildTarget, prepared.source.EnableSubmodules, encryptedBuildConfig, prepared.source.TargetService, prepared.source.RegistryImage, gitCredentialID, registryCredentialID)
			if err != nil {
				return report, fmt.Errorf("import application source %s: %w", item.ID, err)
			}
		} else if _, err = tx.Exec(ctx, `DELETE FROM application_sources WHERE compose_service_id=$1`, prepared.serviceID); err != nil {
			return report, fmt.Errorf("remove stale application source %s: %w", item.ID, err)
		}
	}
	for _, item := range databases {
		if !validDatabases[item.engine+":"+item.id] {
			continue
		}
		databaseID := mappedID(options, "database:"+item.engine, item.id)
		serviceID := mappedID(options, "database-service:"+item.engine, item.id)
		slug := migratedSlug(item.appName, databaseID)
		config := databaseConfig(item)
		version := imageVersion(item.dockerImage, "latest")
		rendered, renderErr := registry.Render(item.engine, database.Request{Name: slug, Version: version, Config: config})
		if renderErr != nil {
			return report, fmt.Errorf("render %s database %s: %w", item.engine, item.id, renderErr)
		}
		environment := map[string]string{}
		if item.env != "" {
			plain, decryptErr := decryptDokploy(item.env, options.EncryptionKeys)
			if decryptErr != nil {
				return report, fmt.Errorf("decrypt %s database %s environment: %w", item.engine, item.id, decryptErr)
			}
			environment = parseEnv(plain)
		}
		for key, value := range rendered.Environment {
			environment[key] = value
		}
		environmentJSON, _ := json.Marshal(environment)
		encryptedEnvironment, encryptErr := box.Encrypt(environmentJSON, "compose-env")
		if encryptErr != nil {
			return report, encryptErr
		}
		credentialsJSON, _ := json.Marshal(rendered.Credentials)
		encryptedCredentials, encryptErr := box.Encrypt(credentialsJSON, "database-credentials")
		if encryptErr != nil {
			return report, encryptErr
		}
		configJSON, _ := json.Marshal(database.StoredConfig(config))
		_, err = tx.Exec(ctx, `INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml,encrypted_env) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(id) DO UPDATE SET name=excluded.name,compose_yaml=excluded.compose_yaml,encrypted_env=excluded.encrypted_env,revision=compose_services.revision+1,updated_at=now()`, serviceID, mappedID(options, "environment", item.environmentID), item.name, "db-"+slug, slug, rendered.ComposeYAML, encryptedEnvironment)
		if err != nil {
			return report, fmt.Errorf("import %s service %s: %w", item.engine, item.id, err)
		}
		_, err = tx.Exec(ctx, `INSERT INTO database_instances(id,environment_id,name,slug,engine,version,compose_service_id,encrypted_credentials,config,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending') ON CONFLICT(id) DO UPDATE SET name=excluded.name,version=excluded.version,compose_service_id=excluded.compose_service_id,encrypted_credentials=excluded.encrypted_credentials,config=excluded.config,status='pending',updated_at=now()`, databaseID, mappedID(options, "environment", item.environmentID), item.name, slug, item.engine, rendered.Version, serviceID, encryptedCredentials, configJSON)
		if err != nil {
			return report, fmt.Errorf("import %s database %s: %w", item.engine, item.id, err)
		}
	}
	for _, item := range preparedDestinations {
		_, err = tx.Exec(ctx, `INSERT INTO backup_destinations(id,organization_id,name,endpoint,region,bucket,prefix,use_tls,encrypted_credentials) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
			ON CONFLICT(id) DO UPDATE SET name=excluded.name,endpoint=excluded.endpoint,region=excluded.region,bucket=excluded.bucket,prefix=excluded.prefix,use_tls=excluded.use_tls,encrypted_credentials=excluded.encrypted_credentials,updated_at=now()`, item.id, options.TargetOrganizationID, item.name, item.endpoint, item.region, item.bucket, item.prefix, item.useTLS, item.encryptedCredentials)
		if err != nil {
			return report, fmt.Errorf("import backup destination %s: %w", item.sourceID, err)
		}
	}
	for _, item := range preparedPolicies {
		_, err = tx.Exec(ctx, `INSERT INTO backup_policies(id,database_instance_id,interval_seconds,retention_count,enabled,next_run_at,destination_id,verify_restore) VALUES($1,$2,$3,$4,$5,now()+($3::int * interval '1 second'),$6,false)
			ON CONFLICT(database_instance_id) DO UPDATE SET interval_seconds=excluded.interval_seconds,retention_count=excluded.retention_count,enabled=excluded.enabled,destination_id=excluded.destination_id,next_run_at=CASE WHEN backup_policies.enabled=false AND excluded.enabled=true THEN excluded.next_run_at ELSE backup_policies.next_run_at END,updated_at=now()`, item.id, item.databaseID, item.intervalSeconds, item.source.retentionCount, item.source.enabled, item.destinationID)
		if err != nil {
			return report, fmt.Errorf("import backup policy %s: %w", item.source.id, err)
		}
	}
	for _, item := range preparedNotifications {
		name := strings.TrimSpace(item.source.name) + " (Dokploy " + strings.Split(item.id.String(), "-")[0] + ")"
		_, err = tx.Exec(ctx, `INSERT INTO notification_endpoints(id,organization_id,name,kind,encrypted_url,encrypted_secret,events,enabled) VALUES($1,$2,$3,$4,$5,$6,$7,true)
			ON CONFLICT(id) DO UPDATE SET name=excluded.name,kind=excluded.kind,encrypted_url=excluded.encrypted_url,encrypted_secret=excluded.encrypted_secret,events=excluded.events,enabled=true,updated_at=now()`, item.id, options.TargetOrganizationID, name, item.kind, item.encryptedURL, item.encryptedSecret, item.events)
		if err != nil {
			return report, fmt.Errorf("import notification %s: %w", item.source.id, err)
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
	for _, item := range filteredApplicationRoutes {
		path := item.path
		if path == "" {
			path = "/"
		}
		resolver := item.resolver
		if resolver == "" {
			resolver = "letsencrypt"
		}
		_, err = tx.Exec(ctx, `INSERT INTO routes(id,compose_service_id,service_name,host,path_prefix,target_port,tls,certificate_resolver) VALUES($1,$2,'app',lower($3),$4,$5,$6,$7) ON CONFLICT(id) DO UPDATE SET service_name='app',host=excluded.host,path_prefix=excluded.path_prefix,target_port=excluded.target_port,tls=excluded.tls,certificate_resolver=excluded.certificate_resolver`, mappedID(options, "application-route", item.id), mappedID(options, "application-service", item.applicationID), item.host, path, item.port, item.tls, resolver)
		if err != nil {
			return report, fmt.Errorf("import application route %s: %w", item.id, err)
		}
	}
	for _, resource := range report.Resources {
		metadata, marshalErr := json.Marshal(resource.Metadata)
		if marshalErr != nil {
			return report, marshalErr
		}
		_, err = tx.Exec(ctx, `INSERT INTO dokploy_migration_resources(target_organization_id,source_organization_id,source_kind,source_id,target_id,status,reason,metadata) VALUES($1,$2,$3,$4,$5,$6,$7,$8)
			ON CONFLICT(target_organization_id,source_organization_id,source_kind,source_id) DO UPDATE SET target_id=excluded.target_id,status=excluded.status,reason=excluded.reason,metadata=excluded.metadata,updated_at=now()`, options.TargetOrganizationID, options.SourceOrganizationID, resource.SourceKind, resource.SourceID, resource.TargetID, resource.Status, resource.Reason, metadata)
		if err != nil {
			return report, fmt.Errorf("record migration metadata for %s %s: %w", resource.SourceKind, resource.SourceID, err)
		}
	}
	return report, tx.Commit(ctx)
}

func migrationBackupCapableEngine(engine string) bool {
	switch engine {
	case "postgres", "mysql", "mariadb", "mongo":
		return true
	default:
		return false
	}
}

func databaseConfig(item sourceDatabase) map[string]any {
	return map[string]any{"username": item.databaseUser, "password": item.databasePassword, "database": item.databaseName, "rootPassword": item.rootPassword, "image": item.dockerImage, "source": "dokploy", "sourceId": item.id}
}

func readDatabases(ctx context.Context, db *pgxpool.Pool, org string) ([]sourceDatabase, error) {
	items := []sourceDatabase{}
	for _, engine := range []string{"postgres", "mysql", "mariadb", "mongo", "redis", "libsql"} {
		idColumn := pgx.Identifier{engine + "Id"}.Sanitize()
		table := pgx.Identifier{engine}.Sanitize()
		var query string
		switch engine {
		case "postgres":
			query = fmt.Sprintf(`SELECT d.%s,d."environmentId",d.name,d."appName",d."databaseName",d."databaseUser",d."databasePassword",'',d."dockerImage",COALESCE(d.env,'') FROM %s d JOIN environment e ON e."environmentId"=d."environmentId" JOIN project p ON p."projectId"=e."projectId" WHERE p."organizationId"=$1 ORDER BY d.%s`, idColumn, table, idColumn)
		case "mysql", "mariadb":
			query = fmt.Sprintf(`SELECT d.%s,d."environmentId",d.name,d."appName",d."databaseName",d."databaseUser",d."databasePassword",d."rootPassword",d."dockerImage",COALESCE(d.env,'') FROM %s d JOIN environment e ON e."environmentId"=d."environmentId" JOIN project p ON p."projectId"=e."projectId" WHERE p."organizationId"=$1 ORDER BY d.%s`, idColumn, table, idColumn)
		case "mongo":
			query = fmt.Sprintf(`SELECT d.%s,d."environmentId",d.name,d."appName",'admin',d."databaseUser",d."databasePassword",'',d."dockerImage",COALESCE(d.env,'') FROM %s d JOIN environment e ON e."environmentId"=d."environmentId" JOIN project p ON p."projectId"=e."projectId" WHERE p."organizationId"=$1 ORDER BY d.%s`, idColumn, table, idColumn)
		case "redis":
			query = fmt.Sprintf(`SELECT d.%s,d."environmentId",d.name,d."appName",'0','',d.password,'',d."dockerImage",COALESCE(d.env,'') FROM %s d JOIN environment e ON e."environmentId"=d."environmentId" JOIN project p ON p."projectId"=e."projectId" WHERE p."organizationId"=$1 ORDER BY d.%s`, idColumn, table, idColumn)
		case "libsql":
			query = fmt.Sprintf(`SELECT d.%s,d."environmentId",d.name,d."appName",'app',d."databaseUser",d."databasePassword",'',d."dockerImage",COALESCE(d.env,'') FROM %s d JOIN environment e ON e."environmentId"=d."environmentId" JOIN project p ON p."projectId"=e."projectId" WHERE p."organizationId"=$1 ORDER BY d.%s`, idColumn, table, idColumn)
		}
		rows, err := db.Query(ctx, query, org)
		if err != nil {
			return nil, fmt.Errorf("read Dokploy %s databases: %w", engine, err)
		}
		for rows.Next() {
			item := sourceDatabase{engine: engine}
			if err = rows.Scan(&item.id, &item.environmentID, &item.name, &item.appName, &item.databaseName, &item.databaseUser, &item.databasePassword, &item.rootPassword, &item.dockerImage, &item.env); err != nil {
				rows.Close()
				return nil, err
			}
			items = append(items, item)
		}
		if err = rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	return items, nil
}

func imageVersion(image, fallback string) string {
	withoutDigest := strings.SplitN(image, "@", 2)[0]
	colon := strings.LastIndex(withoutDigest, ":")
	if colon > strings.LastIndex(withoutDigest, "/") && colon+1 < len(withoutDigest) {
		return withoutDigest[colon+1:]
	}
	return fallback
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
