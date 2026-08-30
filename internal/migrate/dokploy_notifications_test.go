package migrate

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/google/uuid"
)

func TestPrepareNotificationRejectsUnsupportedProvider(t *testing.T) {
	box, _ := cryptox.New(bytes.Repeat([]byte{1}, 32))
	options := DokployOptions{SourceOrganizationID: "source", TargetOrganizationID: uuid.New()}
	_, _, err := prepareNotification(box, options, sourceNotification{id: "n1", name: "Alerts", kind: "telegram", appBuildError: true})
	if err == nil || !strings.Contains(err.Error(), `notification type "telegram" is not supported`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPrepareNotificationRequiresHTTPSWebhook(t *testing.T) {
	box, _ := cryptox.New(bytes.Repeat([]byte{1}, 32))
	options := DokployOptions{SourceOrganizationID: "source", TargetOrganizationID: uuid.New()}
	for _, endpoint := range []string{"http://hooks.example.test/secret", "https://user:pass@hooks.example.test/secret", "not-a-url", " https://hooks.example.test/secret", "https://bad_label.example.test/secret", "https://hooks.example.test:0/secret", "https://hooks.example.test:65536/secret", "https://hooks.example.test/secret#fragment"} {
		_, _, err := prepareNotification(box, options, sourceNotification{id: "n1", name: "Slack", kind: "slack", webhookURL: endpoint, appBuildError: true})
		if err == nil || !strings.Contains(err.Error(), "Slack webhook must be an HTTPS URL") {
			t.Fatalf("endpoint %q error = %v", endpoint, err)
		}
	}
}

func TestPrepareNotificationBoundsImportedConfiguration(t *testing.T) {
	box, _ := cryptox.New(bytes.Repeat([]byte{1}, 32))
	options := DokployOptions{SourceOrganizationID: "source", TargetOrganizationID: uuid.New()}
	for _, item := range []sourceNotification{
		{id: "n1", name: "Slack", kind: "slack", webhookURL: "https://hooks.example.test/" + strings.Repeat("a", maxMigratedNotificationURLBytes), appBuildError: true},
		{id: "n2", name: "Mail", kind: "email", smtpServer: "bad_label.example.test", smtpPort: 587, fromAddress: "dockyard@example.test", toAddresses: []string{"ops@example.test"}, appBuildError: true},
		{id: "n3", name: "Mail", kind: "email", smtpServer: "smtp.example.test", smtpPort: 587, smtpUsername: "mailer\nadmin", smtpPassword: "secret", fromAddress: "dockyard@example.test", toAddresses: []string{"ops@example.test"}, appBuildError: true},
		{id: "n4", name: "Mail", kind: "email", smtpServer: "smtp.example.test", smtpPort: 587, fromAddress: "dockyard@example.test", toAddresses: []string{strings.Repeat("a", maxMigratedSMTPAddressBytes+1)}, appBuildError: true},
	} {
		if _, _, err := prepareNotification(box, options, item); err == nil {
			t.Errorf("unsafe imported notification %#v was accepted", item)
		}
	}
}

func TestMigratedNotificationNameIsSafeAndBounded(t *testing.T) {
	id := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	name, err := migratedNotificationName(strings.Repeat("é", 100), id)
	if err != nil || len(name) > maxMigratedNotificationNameBytes || !strings.HasSuffix(name, " (Dokploy 11111111)") || !utf8.ValidString(name) {
		t.Fatalf("migrated name %q has length %d: %v", name, len(name), err)
	}
	for _, value := range []string{"", "line\nbreak", "nul\x00byte"} {
		if _, err = migratedNotificationName(value, id); err == nil {
			t.Errorf("invalid migrated name %q was accepted", value)
		}
	}
}

func TestPrepareSMTPNotificationEncryptsMaterial(t *testing.T) {
	box, _ := cryptox.New(bytes.Repeat([]byte{2}, 32))
	sourceKey := bytes.Repeat([]byte{4}, 32)
	options := DokployOptions{SourceOrganizationID: "source", TargetOrganizationID: uuid.New(), EncryptionKeys: [][]byte{sourceKey}}
	prepared, warnings, err := prepareNotification(box, options, sourceNotification{
		id: "email1", name: "Email", kind: "email", databaseBackup: true,
		smtpServer: "smtp.example.test", smtpPort: 465, smtpUsername: "mailer", smtpPassword: encryptDokployFixture(t, sourceKey, "smtp-secret"),
		fromAddress: "Dockyard <dockyard@example.test>", toAddresses: []string{"Ops <ops@example.test>"},
	})
	if err != nil || len(warnings) != 0 || prepared.kind != "smtp" || len(prepared.events) != 1 || prepared.events[0] != "backup.failed" {
		t.Fatalf("prepared = %#v, warnings = %#v, err = %v", prepared, warnings, err)
	}
	endpoint, err := box.Decrypt(prepared.encryptedURL, "notification-url:"+prepared.id.String())
	if err != nil || string(endpoint) != "smtp+tls://smtp.example.test:465" {
		t.Fatalf("endpoint = %q, err = %v", endpoint, err)
	}
	materialJSON, err := box.Decrypt(prepared.encryptedSecret, "notification-secret:"+prepared.id.String())
	var material struct {
		Username string   `json:"username"`
		Password string   `json:"password"`
		From     string   `json:"from"`
		To       []string `json:"to"`
	}
	if err != nil || json.Unmarshal(materialJSON, &material) != nil || material.Username != "mailer" || material.Password != "smtp-secret" || material.From != "Dockyard <dockyard@example.test>" || len(material.To) != 1 || material.To[0] != "Ops <ops@example.test>" {
		t.Fatalf("material = %#v, err = %v", material, err)
	}
	if strings.Contains(prepared.encryptedSecret, "smtp-secret") {
		t.Fatal("SMTP password was not encrypted")
	}
}

func TestPrepareNotificationReportsUnmappedTriggers(t *testing.T) {
	box, _ := cryptox.New(bytes.Repeat([]byte{3}, 32))
	options := DokployOptions{SourceOrganizationID: "source", TargetOrganizationID: uuid.New()}
	prepared, warnings, err := prepareNotification(box, options, sourceNotification{id: "n1", name: "Slack", kind: "slack", webhookURL: "https://hooks.example.test/secret", appBuildError: true, appDeploy: true, dockerCleanup: true})
	if err != nil || len(prepared.events) != 1 || prepared.events[0] != "deployment.failed" || len(warnings) != 1 || !strings.Contains(warnings[0], "without a Dockyard equivalent") {
		t.Fatalf("prepared = %#v, warnings = %#v, err = %v", prepared, warnings, err)
	}
}

func TestPrepareNotificationMapsVolumeBackupFailure(t *testing.T) {
	box, _ := cryptox.New(bytes.Repeat([]byte{5}, 32))
	options := DokployOptions{SourceOrganizationID: "source", TargetOrganizationID: uuid.New()}
	prepared, warnings, err := prepareNotification(box, options, sourceNotification{id: "n1", name: "Slack", kind: "slack", webhookURL: "https://hooks.example.test/secret", volumeBackup: true})
	if err != nil || len(warnings) != 0 || len(prepared.events) != 1 || prepared.events[0] != "backup.failed" {
		t.Fatalf("prepared = %#v, warnings = %#v, err = %v", prepared, warnings, err)
	}
}
