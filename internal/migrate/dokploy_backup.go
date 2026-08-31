package migrate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/deploy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"gopkg.in/yaml.v3"
)

func dokployVolumeService(options DokployOptions, policy sourceVolumeBackupPolicy, services []sourceCompose, applications []sourceApplication, validServices, validApplications map[string]bool) (uuid.UUID, string, bool) {
	var foundID uuid.UUID
	var foundCompose string
	found := false
	switch strings.ToLower(strings.TrimSpace(policy.serviceType)) {
	case "compose":
		for _, service := range services {
			if service.appName == policy.appName && validServices[service.id] {
				if found {
					return uuid.Nil, "", false
				}
				foundID, foundCompose, found = mappedID(options, "compose", service.id), service.compose, true
			}
		}
	case "application", "app":
		for _, application := range applications {
			if application.AppName == policy.appName && validApplications[application.ID] {
				prepared, _, err := prepareApplication(application, options)
				if err == nil {
					if found {
						return uuid.Nil, "", false
					}
					foundID, foundCompose, found = prepared.serviceID, prepared.composeYAML, true
				}
			}
		}
	}
	return foundID, foundCompose, found
}

func dokployLogicalVolume(composeYAML, sourceName string) (string, bool) {
	names, err := deploy.NamedVolumes(composeYAML)
	if err != nil {
		return "", false
	}
	for _, name := range names {
		if name == sourceName {
			return name, true
		}
	}
	return "", false
}

type sourceBackupDestination struct {
	id, name, provider, accessKey, secretAccessKey string
	bucket, region, endpoint                       string
	additionalFlags                                []string
}

type sourceBackupPolicy struct {
	id, schedule, database, prefix, destinationID, backupType, databaseType string
	databaseID, composeID, serviceName                                      string
	metadata                                                                json.RawMessage
	retentionCount                                                          int
	enabled                                                                 bool
}

type composeBackupMetadata struct {
	Postgres *struct {
		DatabaseUser string `json:"databaseUser"`
	} `json:"postgres"`
	MariaDB *struct {
		DatabaseUser     string `json:"databaseUser"`
		DatabasePassword string `json:"databasePassword"`
	} `json:"mariadb"`
	MySQL *struct {
		DatabaseRootPassword string `json:"databaseRootPassword"`
	} `json:"mysql"`
	Mongo *struct {
		DatabaseUser     string `json:"databaseUser"`
		DatabasePassword string `json:"databasePassword"`
	} `json:"mongo"`
}

type sourceVolumeBackupPolicy struct {
	id, name, volumeName, prefix, serviceType, appName, serviceName string
	cronExpression, destinationID                                   string
	retentionCount                                                  int
	enabled, turnOff                                                bool
}

func prepareDokployBackupDestination(box *cryptox.Box, options DokployOptions, item sourceBackupDestination, prefix string) (preparedBackupDestination, error) {
	if strings.TrimSpace(item.name) == "" || strings.TrimSpace(item.bucket) == "" || strings.Contains(prefix, "..") || (prefix != "" && path.Clean(prefix) != strings.TrimSuffix(prefix, "/")) {
		return preparedBackupDestination{}, fmt.Errorf("invalid name, bucket, or object prefix")
	}
	endpoint, useTLS, err := normalizeS3Endpoint(item.endpoint)
	if err != nil {
		return preparedBackupDestination{}, err
	}
	accessKey, err := decryptDokploy(item.accessKey, options.EncryptionKeys)
	if err != nil {
		return preparedBackupDestination{}, fmt.Errorf("decrypt access key: %w", err)
	}
	secretKey, err := decryptDokploy(item.secretAccessKey, options.EncryptionKeys)
	if err != nil {
		return preparedBackupDestination{}, fmt.Errorf("decrypt secret access key: %w", err)
	}
	if accessKey == "" || secretKey == "" {
		return preparedBackupDestination{}, fmt.Errorf("access key and secret access key are required")
	}
	key := item.id + "\x00" + strings.Trim(prefix, "/")
	id := mappedID(options, "backup-destination", key)
	credentials, _ := json.Marshal(map[string]string{"accessKey": accessKey, "secretKey": secretKey, "sessionToken": ""})
	encrypted, err := box.Encrypt(credentials, cryptox.ResourceContext("backup-destination", id.String()))
	if err != nil {
		return preparedBackupDestination{}, err
	}
	name := strings.TrimSpace(item.name) + " (Dokploy " + strings.Split(id.String(), "-")[0] + ")"
	return preparedBackupDestination{sourceID: item.id, key: key, name: name, endpoint: endpoint, region: item.region, bucket: item.bucket, prefix: strings.Trim(prefix, "/"), id: id, reportID: id, useTLS: useTLS, encryptedCredentials: encrypted}, nil
}

func backupDestinationMetadata(item sourceBackupDestination, prefix string) map[string]any {
	return map[string]any{
		"name": item.name, "provider": item.provider, "endpoint": item.endpoint,
		"region": item.region, "bucket": item.bucket, "prefix": prefix,
		"hasAdditionalFlags": len(item.additionalFlags) > 0,
	}
}

func readBackupDestinations(ctx context.Context, db *pgxpool.Pool, organizationID string) ([]sourceBackupDestination, error) {
	rows, err := db.Query(ctx, `SELECT "destinationId",name,COALESCE(provider,''),"accessKey","secretAccessKey",bucket,region,endpoint,COALESCE("additionalFlags",ARRAY[]::text[]) FROM destination WHERE "organizationId"=$1 ORDER BY "destinationId"`, organizationID)
	if err != nil {
		return nil, fmt.Errorf("read Dokploy backup destinations: %w", err)
	}
	defer rows.Close()
	items := []sourceBackupDestination{}
	for rows.Next() {
		var item sourceBackupDestination
		if err = rows.Scan(&item.id, &item.name, &item.provider, &item.accessKey, &item.secretAccessKey, &item.bucket, &item.region, &item.endpoint, &item.additionalFlags); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func readBackupPolicies(ctx context.Context, db *pgxpool.Pool, organizationID string) ([]sourceBackupPolicy, error) {
	rows, err := db.Query(ctx, `SELECT b."backupId",b.schedule,COALESCE(b.enabled,false),b.database,b.prefix,b."destinationId",COALESCE(b."keepLatestCount",1),b."backupType"::text,b."databaseType"::text,
		CASE b."databaseType"::text WHEN 'postgres' THEN COALESCE(b."postgresId",'') WHEN 'mysql' THEN COALESCE(b."mysqlId",'') WHEN 'mariadb' THEN COALESCE(b."mariadbId",'') WHEN 'mongo' THEN COALESCE(b."mongoId",'') WHEN 'libsql' THEN COALESCE(b."libsqlId",'') ELSE '' END,
		COALESCE(b."composeId",''),COALESCE(b."serviceName",''),COALESCE(b.metadata,'{}'::jsonb)
		FROM backup b JOIN destination d ON d."destinationId"=b."destinationId" WHERE d."organizationId"=$1 ORDER BY COALESCE(b.enabled,false) DESC,b."backupId"`, organizationID)
	if err != nil {
		return nil, fmt.Errorf("read Dokploy backup policies: %w", err)
	}
	defer rows.Close()
	items := []sourceBackupPolicy{}
	for rows.Next() {
		var item sourceBackupPolicy
		if err = rows.Scan(&item.id, &item.schedule, &item.enabled, &item.database, &item.prefix, &item.destinationID, &item.retentionCount, &item.backupType, &item.databaseType, &item.databaseID, &item.composeID, &item.serviceName, &item.metadata); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func prepareComposeBackupCredentials(item sourceBackupPolicy, service sourceCompose, encryptionKeys [][]byte) (map[string]string, error) {
	var metadata composeBackupMetadata
	if err := json.Unmarshal(item.metadata, &metadata); err != nil {
		return nil, fmt.Errorf("invalid Compose backup metadata")
	}
	environment := map[string]string{}
	if service.env != "" {
		plain, err := decryptDokploy(service.env, encryptionKeys)
		if err != nil {
			return nil, fmt.Errorf("decrypt Compose environment: %w", err)
		}
		environment = parseEnv(plain)
	}
	serviceEnvironment, err := composeServiceEnvironment(service.compose, item.serviceName, environment)
	if err != nil {
		return nil, err
	}
	credentials := map[string]string{"database": strings.TrimSpace(item.database)}
	switch item.databaseType {
	case "postgres":
		if metadata.Postgres == nil {
			return nil, fmt.Errorf("PostgreSQL backup metadata is missing")
		}
		credentials["username"] = strings.TrimSpace(metadata.Postgres.DatabaseUser)
		credentials["password"] = firstEnvironmentValue(serviceEnvironment, "PGPASSWORD", "POSTGRES_PASSWORD")
	case "mysql":
		if metadata.MySQL == nil {
			return nil, fmt.Errorf("MySQL backup metadata is missing")
		}
		credentials["username"] = "root"
		credentials["password"] = metadata.MySQL.DatabaseRootPassword
	case "mariadb":
		if metadata.MariaDB == nil {
			return nil, fmt.Errorf("MariaDB backup metadata is missing")
		}
		credentials["username"] = strings.TrimSpace(metadata.MariaDB.DatabaseUser)
		credentials["password"] = metadata.MariaDB.DatabasePassword
	case "mongo":
		if metadata.Mongo == nil {
			return nil, fmt.Errorf("MongoDB backup metadata is missing")
		}
		credentials["username"] = strings.TrimSpace(metadata.Mongo.DatabaseUser)
		credentials["password"] = metadata.Mongo.DatabasePassword
	default:
		return nil, fmt.Errorf("Compose database engine %q is not supported", item.databaseType)
	}
	for _, key := range []string{"database", "username", "password"} {
		if credentials[key] == "" {
			return nil, fmt.Errorf("Compose database credential %q cannot be recovered", key)
		}
	}
	return credentials, nil
}

func composeServiceEnvironment(composeYAML, serviceName string, variables map[string]string) (map[string]string, error) {
	var document struct {
		Services map[string]struct {
			Environment any `yaml:"environment"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(composeYAML), &document); err != nil {
		return nil, fmt.Errorf("parse Compose document: %w", err)
	}
	service, found := document.Services[serviceName]
	if !found {
		return nil, fmt.Errorf("Compose service %q is not declared", serviceName)
	}
	result := map[string]string{}
	switch values := service.Environment.(type) {
	case map[string]any:
		for key, value := range values {
			result[key] = resolveComposeEnvironmentValue(fmt.Sprint(value), variables)
		}
	case []any:
		for _, raw := range values {
			key, value, found := strings.Cut(fmt.Sprint(raw), "=")
			if !found {
				value = variables[key]
			}
			result[key] = resolveComposeEnvironmentValue(value, variables)
		}
	case nil:
	default:
		return nil, fmt.Errorf("Compose service %q has an invalid environment", serviceName)
	}
	for key, value := range variables {
		if _, found := result[key]; !found {
			result[key] = value
		}
	}
	return result, nil
}

func composeServiceImage(composeYAML, serviceName string) string {
	var document struct {
		Services map[string]struct {
			Image string `yaml:"image"`
		} `yaml:"services"`
	}
	if yaml.Unmarshal([]byte(composeYAML), &document) != nil {
		return ""
	}
	return strings.TrimSpace(document.Services[serviceName].Image)
}

func resolveComposeEnvironmentValue(value string, variables map[string]string) string {
	if strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}") {
		expression := strings.TrimSuffix(strings.TrimPrefix(value, "${"), "}")
		if key, fallback, found := strings.Cut(expression, ":-"); found {
			if resolved := variables[key]; resolved != "" {
				return resolved
			}
			return fallback
		}
		return variables[expression]
	}
	if strings.HasPrefix(value, "$") && !strings.Contains(value[1:], "$") {
		return variables[strings.TrimPrefix(value, "$")]
	}
	return value
}

func firstEnvironmentValue(environment map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := environment[key]; strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func readVolumeBackupPolicies(ctx context.Context, db *pgxpool.Pool, organizationID string) ([]sourceVolumeBackupPolicy, error) {
	rows, err := db.Query(ctx, `SELECT v."volumeBackupId",v.name,v."volumeName",v.prefix,v."serviceType"::text,v."appName",COALESCE(v."serviceName",''),v."turnOff",v."cronExpression",COALESCE(v."keepLatestCount",1),COALESCE(v.enabled,false),v."destinationId"
		FROM volume_backup v JOIN destination d ON d."destinationId"=v."destinationId" WHERE d."organizationId"=$1 ORDER BY v."volumeBackupId"`, organizationID)
	if err != nil {
		return nil, fmt.Errorf("read Dokploy volume backup policies: %w", err)
	}
	defer rows.Close()
	items := []sourceVolumeBackupPolicy{}
	for rows.Next() {
		var item sourceVolumeBackupPolicy
		if err = rows.Scan(&item.id, &item.name, &item.volumeName, &item.prefix, &item.serviceType, &item.appName, &item.serviceName, &item.turnOff, &item.cronExpression, &item.retentionCount, &item.enabled, &item.destinationID); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// cronInterval converts only schedules whose spacing is constant in UTC. This
// deliberately rejects monthly and other calendar schedules because Dockyard's
// policy model stores a duration, not a cron expression.
func cronInterval(schedule string) (int, bool) {
	switch strings.TrimSpace(schedule) {
	case "@hourly":
		return 3600, true
	case "@daily", "@midnight":
		return 86400, true
	case "@weekly":
		return 604800, true
	}
	fields := strings.Fields(schedule)
	if len(fields) != 5 {
		return 0, false
	}
	minute, hour, day, month, weekday := fields[0], fields[1], fields[2], fields[3], fields[4]
	if day != "*" || month != "*" {
		return 0, false
	}
	if n, ok := stepValue(minute); ok && hour == "*" && weekday == "*" && n >= 15 && 60%n == 0 {
		return n * 60, true
	}
	if !boundedNumber(minute, 0, 59) {
		return 0, false
	}
	if hour == "*" && weekday == "*" {
		return 3600, true
	}
	if n, ok := stepValue(hour); ok && weekday == "*" && 24%n == 0 {
		return n * 3600, true
	}
	if !boundedNumber(hour, 0, 23) {
		return 0, false
	}
	if weekday == "*" {
		return 86400, true
	}
	if boundedNumber(weekday, 0, 7) {
		return 604800, true
	}
	return 0, false
}

func stepValue(value string) (int, bool) {
	if !strings.HasPrefix(value, "*/") {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(value, "*/"))
	return n, err == nil && n > 0
}

func boundedNumber(value string, minimum, maximum int) bool {
	n, err := strconv.Atoi(value)
	return err == nil && n >= minimum && n <= maximum
}

func normalizeS3Endpoint(value string) (string, bool, error) {
	value = strings.TrimSpace(value)
	if !strings.Contains(value, "://") {
		value = "https://" + value
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", false, fmt.Errorf("S3 endpoint %q is not an HTTP(S) origin", value)
	}
	return strings.TrimSuffix(parsed.String(), "/"), parsed.Scheme == "https", nil
}
