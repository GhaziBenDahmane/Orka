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
	"github.com/jackc/pgx/v5/pgxpool"
)

type sourceBackupDestination struct {
	id, name, provider, accessKey, secretAccessKey string
	bucket, region, endpoint                       string
	additionalFlags                                []string
}

type sourceBackupPolicy struct {
	id, schedule, database, prefix, destinationID, backupType, databaseType string
	databaseID                                                              string
	retentionCount                                                          int
	enabled                                                                 bool
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
		CASE b."databaseType"::text WHEN 'postgres' THEN COALESCE(b."postgresId",'') WHEN 'mysql' THEN COALESCE(b."mysqlId",'') WHEN 'mariadb' THEN COALESCE(b."mariadbId",'') WHEN 'mongo' THEN COALESCE(b."mongoId",'') WHEN 'libsql' THEN COALESCE(b."libsqlId",'') ELSE '' END
		FROM backup b JOIN destination d ON d."destinationId"=b."destinationId" WHERE d."organizationId"=$1 ORDER BY COALESCE(b.enabled,false) DESC,b."backupId"`, organizationID)
	if err != nil {
		return nil, fmt.Errorf("read Dokploy backup policies: %w", err)
	}
	defer rows.Close()
	items := []sourceBackupPolicy{}
	for rows.Next() {
		var item sourceBackupPolicy
		if err = rows.Scan(&item.id, &item.schedule, &item.enabled, &item.database, &item.prefix, &item.destinationID, &item.retentionCount, &item.backupType, &item.databaseType, &item.databaseID); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
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
