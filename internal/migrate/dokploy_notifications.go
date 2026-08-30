package migrate

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	maxMigratedNotificationNameBytes = 120
	maxMigratedNotificationURLBytes  = 16 << 10
	maxDokployEncryptedSecretBytes   = 64 << 10
	maxMigratedSMTPUsernameBytes     = 4 << 10
	maxMigratedSMTPPasswordBytes     = 16 << 10
	maxMigratedSMTPAddressBytes      = 1024
)

var migratedNotificationHostnameLabelPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

type sourceNotification struct {
	id, name, kind, webhookURL                                    string
	smtpServer, smtpUsername, smtpPassword, fromAddress           string
	smtpPort                                                      int
	toAddresses                                                   []string
	appDeploy, appBuildError, databaseBackup, volumeBackup        bool
	dokployRestart, dokployBackup, dockerCleanup, serverThreshold bool
}

type preparedNotification struct {
	source                                    sourceNotification
	id                                        uuid.UUID
	name, kind, encryptedURL, encryptedSecret string
	events                                    []string
}

func readNotifications(ctx context.Context, db *pgxpool.Pool, organizationID string) ([]sourceNotification, error) {
	rows, err := db.Query(ctx, `SELECT n."notificationId",n.name,n."notificationType"::text,n."appDeploy",n."appBuildError",n."databaseBackup",n."volumeBackup",n."dokployRestart",n."dokployBackup",n."dockerCleanup",n."serverThreshold",COALESCE(s."webhookUrl",''),COALESCE(e."smtpServer",''),COALESCE(e."smtpPort",0),COALESCE(e.username,''),COALESCE(e.password,''),COALESCE(e."fromAddress",''),COALESCE(e."toAddress",ARRAY[]::text[]) FROM notification n LEFT JOIN slack s ON s."slackId"=n."slackId" LEFT JOIN email e ON e."emailId"=n."emailId" WHERE n."organizationId"=$1 ORDER BY n."notificationId"`, organizationID)
	if err != nil {
		return nil, fmt.Errorf("read Dokploy notifications: %w", err)
	}
	defer rows.Close()
	items := []sourceNotification{}
	for rows.Next() {
		var item sourceNotification
		if err = rows.Scan(&item.id, &item.name, &item.kind, &item.appDeploy, &item.appBuildError, &item.databaseBackup, &item.volumeBackup, &item.dokployRestart, &item.dokployBackup, &item.dockerCleanup, &item.serverThreshold, &item.webhookURL, &item.smtpServer, &item.smtpPort, &item.smtpUsername, &item.smtpPassword, &item.fromAddress, &item.toAddresses); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func prepareNotification(box *cryptox.Box, options DokployOptions, item sourceNotification) (preparedNotification, []string, error) {
	id := mappedID(options, "notification", item.id)
	name, err := migratedNotificationName(item.name, id)
	if err != nil {
		return preparedNotification{}, nil, err
	}
	events := []string{}
	if item.appBuildError {
		events = append(events, "deployment.failed")
	}
	if item.databaseBackup || item.volumeBackup {
		events = append(events, "backup.failed")
	}
	warnings := []string{}
	if item.appDeploy || item.dokployRestart || item.dokployBackup || item.dockerCleanup || item.serverThreshold {
		warnings = append(warnings, fmt.Sprintf("notification %s has Dokploy event triggers without a Dockyard equivalent", item.id))
	}
	prepared := preparedNotification{source: item, id: id, name: name, events: events}
	if len(events) == 0 {
		return prepared, warnings, fmt.Errorf("notification has no convertible failure events")
	}
	var endpoint, secret string
	switch item.kind {
	case "slack":
		if len(item.webhookURL) > maxDokployEncryptedSecretBytes {
			return prepared, warnings, fmt.Errorf("Slack webhook configuration is too large")
		}
		endpoint, err = decryptDokploy(item.webhookURL, options.EncryptionKeys)
		if err != nil {
			return prepared, warnings, fmt.Errorf("decrypt Slack webhook URL: %w", err)
		}
		parsed, parseErr := url.Parse(endpoint)
		if parseErr != nil || endpoint != strings.TrimSpace(endpoint) || len(endpoint) > maxMigratedNotificationURLBytes || parsed.Scheme != "https" || !validMigratedNotificationURLHost(parsed) || parsed.User != nil || parsed.Fragment != "" || parsed.Opaque != "" {
			return prepared, warnings, fmt.Errorf("Slack webhook must be an HTTPS URL without user information or a fragment")
		}
	case "email":
		if len(item.smtpPassword) > maxDokployEncryptedSecretBytes {
			return prepared, warnings, fmt.Errorf("SMTP password configuration is too large")
		}
		secret, err = decryptDokploy(item.smtpPassword, options.EncryptionKeys)
		if err != nil {
			return prepared, warnings, fmt.Errorf("decrypt SMTP password: %w", err)
		}
		host := strings.TrimSpace(item.smtpServer)
		if !validMigratedNotificationHostname(host) || item.smtpPort < 1 || item.smtpPort > 65535 || (item.smtpUsername == "") != (secret == "") || len(item.smtpUsername) > maxMigratedSMTPUsernameBytes || len(secret) > maxMigratedSMTPPasswordBytes || strings.ContainsAny(item.smtpUsername, "\x00\r\n") || strings.ContainsAny(secret, "\x00\r\n") || len(item.fromAddress) == 0 || len(item.fromAddress) > maxMigratedSMTPAddressBytes || len(item.toAddresses) == 0 || len(item.toAddresses) > 100 {
			return prepared, warnings, fmt.Errorf("valid SMTP host, port, optional credential pair, sender, and recipients are required")
		}
		if _, err = mail.ParseAddress(item.fromAddress); err != nil {
			return prepared, warnings, fmt.Errorf("invalid SMTP sender")
		}
		for _, recipient := range item.toAddresses {
			if len(recipient) == 0 || len(recipient) > maxMigratedSMTPAddressBytes {
				return prepared, warnings, fmt.Errorf("invalid SMTP recipient")
			}
			if _, err = mail.ParseAddress(recipient); err != nil {
				return prepared, warnings, fmt.Errorf("invalid SMTP recipient")
			}
		}
		mode := "starttls"
		if item.smtpPort == 465 {
			mode = "tls"
		}
		endpoint = "smtp+" + mode + "://" + net.JoinHostPort(host, fmt.Sprint(item.smtpPort))
		material, _ := json.Marshal(map[string]any{"username": item.smtpUsername, "password": secret, "from": item.fromAddress, "to": item.toAddresses})
		secret = string(material)
	default:
		return prepared, warnings, fmt.Errorf("notification type %q is not supported", item.kind)
	}
	encryptedURL, err := box.Encrypt([]byte(endpoint), "notification-url:"+id.String())
	if err != nil {
		return prepared, warnings, err
	}
	encryptedSecret, err := box.Encrypt([]byte(secret), "notification-secret:"+id.String())
	if err != nil {
		return prepared, warnings, err
	}
	prepared.kind = map[string]string{"email": "smtp", "slack": "slack"}[item.kind]
	prepared.encryptedURL = encryptedURL
	prepared.encryptedSecret = encryptedSecret
	return prepared, warnings, nil
}

func migratedNotificationName(raw string, id uuid.UUID) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" || strings.ContainsAny(name, "\x00\r\n") {
		return "", fmt.Errorf("notification name must be a non-empty single-line value")
	}
	suffix := " (Dokploy " + strings.Split(id.String(), "-")[0] + ")"
	limit := maxMigratedNotificationNameBytes - len(suffix)
	for len(name) > limit {
		_, size := utf8.DecodeLastRuneInString(name)
		name = name[:len(name)-size]
	}
	return name + suffix, nil
}

func validMigratedNotificationURLHost(endpoint *url.URL) bool {
	if endpoint == nil || !validMigratedNotificationHostname(endpoint.Hostname()) || strings.HasSuffix(endpoint.Host, ":") {
		return false
	}
	if strings.HasPrefix(endpoint.Host, "[") && net.ParseIP(endpoint.Hostname()) == nil {
		return false
	}
	if port := endpoint.Port(); port != "" {
		value, err := strconv.Atoi(port)
		return err == nil && value >= 1 && value <= 65535
	}
	return true
}

func validMigratedNotificationHostname(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || !migratedNotificationHostnameLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func notificationMetadata(item sourceNotification, events []string) map[string]any {
	return map[string]any{"name": item.name, "type": item.kind, "events": events, "hasUnmappedTriggers": item.appDeploy || item.volumeBackup || item.dokployRestart || item.dokployBackup || item.dockerCleanup || item.serverThreshold}
}
