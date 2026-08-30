package migrate

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"strings"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type sourceNotification struct {
	id, name, kind, webhookURL                                    string
	smtpServer, smtpUsername, smtpPassword, fromAddress           string
	smtpPort                                                      int
	toAddresses                                                   []string
	appDeploy, appBuildError, databaseBackup, volumeBackup        bool
	dokployRestart, dokployBackup, dockerCleanup, serverThreshold bool
}

type preparedNotification struct {
	source                              sourceNotification
	id                                  uuid.UUID
	kind, encryptedURL, encryptedSecret string
	events                              []string
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
	prepared := preparedNotification{source: item, id: id, events: events}
	if len(events) == 0 {
		return prepared, warnings, fmt.Errorf("notification has no convertible failure events")
	}
	var endpoint, secret string
	switch item.kind {
	case "slack":
		var err error
		endpoint, err = decryptDokploy(item.webhookURL, options.EncryptionKeys)
		if err != nil {
			return prepared, warnings, fmt.Errorf("decrypt Slack webhook URL: %w", err)
		}
		parsed, parseErr := url.Parse(endpoint)
		if parseErr != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
			return prepared, warnings, fmt.Errorf("Slack webhook must be an HTTPS URL without user information or a fragment")
		}
	case "email":
		var err error
		secret, err = decryptDokploy(item.smtpPassword, options.EncryptionKeys)
		if err != nil {
			return prepared, warnings, fmt.Errorf("decrypt SMTP password: %w", err)
		}
		host := strings.TrimSpace(item.smtpServer)
		if host == "" || strings.ContainsAny(host, "/@ \t\r\n") || (strings.Contains(host, ":") && net.ParseIP(host) == nil) || item.smtpPort < 1 || item.smtpPort > 65535 || (item.smtpUsername == "") != (secret == "") || len(item.toAddresses) == 0 || len(item.toAddresses) > 100 {
			return prepared, warnings, fmt.Errorf("valid SMTP host, port, optional credential pair, sender, and recipients are required")
		}
		if _, err = mail.ParseAddress(item.fromAddress); err != nil {
			return prepared, warnings, fmt.Errorf("invalid SMTP sender")
		}
		for _, recipient := range item.toAddresses {
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

func notificationMetadata(item sourceNotification, events []string) map[string]any {
	return map[string]any{"name": item.name, "type": item.kind, "events": events, "hasUnmappedTriggers": item.appDeploy || item.volumeBackup || item.dokployRestart || item.dokployBackup || item.dockerCleanup || item.serverThreshold}
}
