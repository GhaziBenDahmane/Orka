package main

import (
	"net/http"
	"strings"
	"testing"
)

func TestCommandRequestMappings(t *testing.T) {
	tests := []struct {
		args   []string
		method string
		path   string
	}{
		{[]string{"projects"}, http.MethodGet, "/v1/projects"},
		{[]string{"members"}, http.MethodGet, "/v1/members"},
		{[]string{"update-member", "user-id", `{}`}, http.MethodPatch, "/v1/members/user-id"},
		{[]string{"delete-member", "user-id"}, http.MethodDelete, "/v1/members/user-id"},
		{[]string{"deploy-tokens", "service-id"}, http.MethodGet, "/v1/services/service-id/deploy-tokens"},
		{[]string{"create-deploy-token", "service-id", `{}`}, http.MethodPost, "/v1/services/service-id/deploy-tokens"},
		{[]string{"revoke-deploy-token", "service-id", "token-id"}, http.MethodDelete, "/v1/services/service-id/deploy-tokens/token-id"},
		{[]string{"invitations"}, http.MethodGet, "/v1/invitations"},
		{[]string{"invitation", "invitation-id"}, http.MethodGet, "/v1/invitations/invitation-id"},
		{[]string{"create-invitation", `{}`}, http.MethodPost, "/v1/invitations"},
		{[]string{"revoke-invitation", "invitation-id"}, http.MethodDelete, "/v1/invitations/invitation-id"},
		{[]string{"service-accounts"}, http.MethodGet, "/v1/service-accounts"},
		{[]string{"create-service-account", `{}`}, http.MethodPost, "/v1/service-accounts"},
		{[]string{"rotate-service-account", "account-id", `{}`}, http.MethodPost, "/v1/service-accounts/account-id/rotate"},
		{[]string{"disable-service-account", "account-id"}, http.MethodDelete, "/v1/service-accounts/account-id"},
		{[]string{"ai-audit-runs"}, http.MethodGet, "/v1/ai/audit-runs"},
		{[]string{"ai-audit-findings"}, http.MethodGet, "/v1/ai/audit-findings"},
		{[]string{"ai-audit-run-findings", "run-id"}, http.MethodGet, "/v1/ai/audit-runs/run-id/findings"},
		{[]string{"triage-ai-audit-finding", "finding-id", `{}`}, http.MethodPatch, "/v1/ai/audit-findings/finding-id"},
		{[]string{"audit-retention"}, http.MethodGet, "/v1/audit-retention"},
		{[]string{"put-audit-retention", `{}`}, http.MethodPut, "/v1/audit-retention"},
		{[]string{"audit-archives"}, http.MethodGet, "/v1/audit-archives"},
		{[]string{"audit-archive", "archive-id"}, http.MethodGet, "/v1/audit-archives/archive-id"},
		{[]string{"create-audit-archive", `{}`}, http.MethodPost, "/v1/audit-archives"},
		{[]string{"run-audit-archive", "archive-id"}, http.MethodPost, "/v1/audit-archives/archive-id/run"},
		{[]string{"audit-archive-batches", "archive-id"}, http.MethodGet, "/v1/audit-archives/archive-id/batches"},
		{[]string{"delete-audit-archive", "archive-id"}, http.MethodDelete, "/v1/audit-archives/archive-id"},
		{[]string{"oidc-providers"}, http.MethodGet, "/v1/sso/oidc-providers"},
		{[]string{"create-oidc-provider", `{}`}, http.MethodPost, "/v1/sso/oidc-providers"},
		{[]string{"update-oidc-provider", "provider-id", `{}`}, http.MethodPut, "/v1/sso/oidc-providers/provider-id"},
		{[]string{"enable-oidc-provider", "provider-id"}, http.MethodPost, "/v1/sso/oidc-providers/provider-id/enable"},
		{[]string{"disable-oidc-provider", "provider-id"}, http.MethodDelete, "/v1/sso/oidc-providers/provider-id"},
		{[]string{"sso-settings"}, http.MethodGet, "/v1/sso/settings"},
		{[]string{"put-sso-settings", `{}`}, http.MethodPut, "/v1/sso/settings"},
		{[]string{"scim-tokens"}, http.MethodGet, "/v1/scim/tokens"},
		{[]string{"create-scim-token", `{}`}, http.MethodPost, "/v1/scim/tokens"},
		{[]string{"revoke-scim-token", "token-id"}, http.MethodDelete, "/v1/scim/tokens/token-id"},
		{[]string{"project-grants", "project-id"}, http.MethodGet, "/v1/projects/project-id/grants"},
		{[]string{"put-project-grant", "project-id", "user-id", `{}`}, http.MethodPut, "/v1/projects/project-id/grants/user-id"},
		{[]string{"delete-project-grant", "project-id", "user-id"}, http.MethodDelete, "/v1/projects/project-id/grants/user-id"},
		{[]string{"environment-grants", "environment-id"}, http.MethodGet, "/v1/environments/environment-id/grants"},
		{[]string{"put-environment-grant", "environment-id", "user-id", `{}`}, http.MethodPut, "/v1/environments/environment-id/grants/user-id"},
		{[]string{"delete-environment-grant", "environment-id", "user-id"}, http.MethodDelete, "/v1/environments/environment-id/grants/user-id"},
		{[]string{"policy"}, http.MethodGet, "/v1/policy"},
		{[]string{"put-policy", `{}`}, http.MethodPut, "/v1/policy"},
		{[]string{"project-policy", "project-id"}, http.MethodGet, "/v1/projects/project-id/policy"},
		{[]string{"put-project-policy", "project-id", `{}`}, http.MethodPut, "/v1/projects/project-id/policy"},
		{[]string{"environment-policy", "environment-id"}, http.MethodGet, "/v1/environments/environment-id/policy"},
		{[]string{"put-environment-policy", "environment-id", `{}`}, http.MethodPut, "/v1/environments/environment-id/policy"},
		{[]string{"saml-providers"}, http.MethodGet, "/v1/sso/saml-providers"},
		{[]string{"create-saml-provider", `{}`}, http.MethodPost, "/v1/sso/saml-providers"},
		{[]string{"update-saml-provider", "provider-id", `{}`}, http.MethodPut, "/v1/sso/saml-providers/provider-id"},
		{[]string{"enable-saml-provider", "provider-id"}, http.MethodPost, "/v1/sso/saml-providers/provider-id/enable"},
		{[]string{"disable-saml-provider", "provider-id"}, http.MethodDelete, "/v1/sso/saml-providers/provider-id"},
		{[]string{"rotate-saml-certificate", "provider-id"}, http.MethodPost, "/v1/sso/saml-providers/provider-id/certificate-rotation"},
		{[]string{"promote-saml-certificate", "provider-id", "Workforce"}, http.MethodPost, "/v1/sso/saml-providers/provider-id/certificate-rotation/promote"},
		{[]string{"cancel-saml-certificate", "provider-id"}, http.MethodDelete, "/v1/sso/saml-providers/provider-id/certificate-rotation"},
		{[]string{"environments", "project-id"}, http.MethodGet, "/v1/projects/project-id/environments"},
		{[]string{"deploy", "service-id"}, http.MethodPost, "/v1/services/service-id/deployments"},
		{[]string{"database-engines"}, http.MethodGet, "/v1/database-engines"},
		{[]string{"backup-destinations"}, http.MethodGet, "/v1/backup-destinations"},
		{[]string{"create-backup-destination", `{}`}, http.MethodPost, "/v1/backup-destinations"},
		{[]string{"update-backup-destination", "destination-id", `{}`}, http.MethodPut, "/v1/backup-destinations/destination-id"},
		{[]string{"delete-backup-destination", "destination-id"}, http.MethodDelete, "/v1/backup-destinations/destination-id"},
		{[]string{"notification-endpoints"}, http.MethodGet, "/v1/notification-endpoints"},
		{[]string{"create-notification-endpoint", `{}`}, http.MethodPost, "/v1/notification-endpoints"},
		{[]string{"delete-notification-endpoint", "endpoint-id"}, http.MethodDelete, "/v1/notification-endpoints/endpoint-id"},
		{[]string{"databases", "environment-id"}, http.MethodGet, "/v1/environments/environment-id/databases"},
		{[]string{"database", "database-id"}, http.MethodGet, "/v1/databases/database-id"},
		{[]string{"backup-policy", "database-id"}, http.MethodGet, "/v1/databases/database-id/backup-policy"},
		{[]string{"delete-backup-policy", "database-id"}, http.MethodDelete, "/v1/databases/database-id/backup-policy"},
		{[]string{"database-backups", "database-id"}, http.MethodGet, "/v1/databases/database-id/backups"},
		{[]string{"backup-database", "database-id"}, http.MethodPost, "/v1/databases/database-id/backups"},
		{[]string{"database-restores", "database-id"}, http.MethodGet, "/v1/databases/database-id/restores"},
		{[]string{"database-backup", "backup-id"}, http.MethodGet, "/v1/database-backups/backup-id"},
		{[]string{"cancel-database-backup", "backup-id"}, http.MethodPost, "/v1/database-backups/backup-id/cancel"},
		{[]string{"restore-database", "backup-id", "database-slug"}, http.MethodPost, "/v1/database-backups/backup-id/restore"},
		{[]string{"database-restore", "restore-id"}, http.MethodGet, "/v1/database-restores/restore-id"},
		{[]string{"cancel-database-restore", "restore-id"}, http.MethodPost, "/v1/database-restores/restore-id/cancel"},
		{[]string{"volumes", "service-id"}, http.MethodGet, "/v1/services/service-id/volumes"},
		{[]string{"volume-policies", "service-id"}, http.MethodGet, "/v1/services/service-id/volume-backup-policies"},
		{[]string{"delete-volume-policy", "service-id", "uploads"}, http.MethodDelete, "/v1/services/service-id/volume-backup-policies/uploads"},
		{[]string{"volume-backups", "service-id"}, http.MethodGet, "/v1/services/service-id/volume-backups"},
		{[]string{"backup-volume", "service-id", "uploads"}, http.MethodPost, "/v1/services/service-id/volume-backups/uploads"},
		{[]string{"volume-restores", "service-id"}, http.MethodGet, "/v1/services/service-id/volume-restores"},
		{[]string{"volume-backup", "backup-id"}, http.MethodGet, "/v1/volume-backups/backup-id"},
		{[]string{"cancel-volume-backup", "backup-id"}, http.MethodPost, "/v1/volume-backups/backup-id/cancel"},
		{[]string{"restore-volume", "backup-id", "service-slug"}, http.MethodPost, "/v1/volume-backups/backup-id/restore"},
		{[]string{"volume-restore", "restore-id"}, http.MethodGet, "/v1/volume-restores/restore-id"},
		{[]string{"cancel-volume-restore", "restore-id"}, http.MethodPost, "/v1/volume-restores/restore-id/cancel"},
		{[]string{"templates"}, http.MethodGet, "/v1/templates?limit=200"},
		{[]string{"templates", "opaque+/cursor"}, http.MethodGet, "/v1/templates?limit=200&cursor=opaque%2B%2Fcursor"},
		{[]string{"template-repositories"}, http.MethodGet, "/v1/template-repositories"},
		{[]string{"create-template-repository", `{}`}, http.MethodPost, "/v1/template-repositories"},
		{[]string{"update-template-repository", "repository-id", `{}`}, http.MethodPatch, "/v1/template-repositories/repository-id"},
		{[]string{"sync-template-repository", "repository-id"}, http.MethodPost, "/v1/template-repositories/repository-id/sync"},
		{[]string{"rotate-template-repository-webhook", "repository-id"}, http.MethodPost, "/v1/template-repositories/repository-id/webhook-secret"},
		{[]string{"disable-template-repository-webhook", "repository-id"}, http.MethodDelete, "/v1/template-repositories/repository-id/webhook-secret"},
		{[]string{"delete-template-repository", "repository-id"}, http.MethodDelete, "/v1/template-repositories/repository-id"},
		{[]string{"preview-template", "template-id", `{}`}, http.MethodPost, "/v1/templates/template-id/preview"},
		{[]string{"template-versions", "service-id"}, http.MethodGet, "/v1/services/service-id/template-versions"},
		{[]string{"clusters"}, http.MethodGet, "/v1/clusters"},
		{[]string{"create-cluster", `{}`}, http.MethodPost, "/v1/clusters"},
		{[]string{"update-cluster", "cluster-id", `{}`}, http.MethodPatch, "/v1/clusters/cluster-id"},
		{[]string{"delete-cluster", "cluster-id"}, http.MethodDelete, "/v1/clusters/cluster-id"},
		{[]string{"cluster-token", "cluster-id"}, http.MethodPost, "/v1/clusters/cluster-id/enrollment-tokens"},
		{[]string{"agent-upgrade", "cluster-id", "repo/image@sha256:digest"}, http.MethodPost, "/v1/clusters/cluster-id/agent-upgrades"},
		{[]string{"cluster-command", "cluster-id", "command-id"}, http.MethodGet, "/v1/clusters/cluster-id/commands/command-id"},
		{[]string{"cancel-agent-upgrade", "cluster-id", "command-id"}, http.MethodDelete, "/v1/clusters/cluster-id/agent-upgrades/command-id"},
		{[]string{"request", "delete", "/v1/services/id"}, http.MethodDelete, "/v1/services/id"},
	}
	for _, test := range tests {
		method, path, _, err := commandRequest(test.args, strings.NewReader(""))
		if err != nil || method != test.method || path != test.path {
			t.Fatalf("args=%v method=%q path=%q err=%v", test.args, method, path, err)
		}
	}
}

func TestVolumeCommandBodies(t *testing.T) {
	method, path, input, err := commandRequest([]string{"put-volume-policy", "service-id", "uploads", `{"destinationId":"destination-id","intervalSeconds":3600}`}, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPut || path != "/v1/services/service-id/volume-backup-policies/uploads" {
		t.Fatalf("method=%q path=%q", method, path)
	}
	policy := input.(map[string]any)
	if policy["destinationId"] != "destination-id" || policy["intervalSeconds"] != float64(3600) {
		t.Fatalf("policy input=%#v", policy)
	}
	method, path, input, err = commandRequest([]string{"restore-volume", "backup-id", "production-api"}, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPost || path != "/v1/volume-backups/backup-id/restore" {
		t.Fatalf("method=%q path=%q", method, path)
	}
	confirmation := input.(map[string]string)
	if confirmation["confirm"] != "production-api" {
		t.Fatalf("restore input=%#v", confirmation)
	}
}

func TestDatabaseBackupCommandBodies(t *testing.T) {
	method, path, input, err := commandRequest([]string{"put-backup-policy", "database-id", `{"destinationId":"destination-id","intervalSeconds":3600}`}, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPut || path != "/v1/databases/database-id/backup-policy" {
		t.Fatalf("method=%q path=%q", method, path)
	}
	policy := input.(map[string]any)
	if policy["destinationId"] != "destination-id" || policy["intervalSeconds"] != float64(3600) {
		t.Fatalf("policy input=%#v", policy)
	}
	method, path, input, err = commandRequest([]string{"restore-database", "backup-id", "production-db"}, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPost || path != "/v1/database-backups/backup-id/restore" {
		t.Fatalf("method=%q path=%q", method, path)
	}
	confirmation := input.(map[string]string)
	if confirmation["confirm"] != "production-db" {
		t.Fatalf("restore input=%#v", confirmation)
	}
}

func TestBackupDestinationCommandBodies(t *testing.T) {
	method, path, input, err := commandRequest([]string{"create-backup-destination", "-"}, strings.NewReader(`{"name":"archive","accessKey":"access","secretKey":"secret"}`))
	if err != nil || method != http.MethodPost || path != "/v1/backup-destinations" {
		t.Fatalf("method=%q path=%q input=%#v err=%v", method, path, input, err)
	}
	destination := input.(map[string]any)
	if destination["name"] != "archive" || destination["accessKey"] != "access" || destination["secretKey"] != "secret" {
		t.Fatalf("destination input=%#v", destination)
	}
	method, path, input, err = commandRequest([]string{"update-backup-destination", "destination-id", `{"name":"rotated","accessKey":"new-access","secretKey":"new-secret"}`}, strings.NewReader(""))
	if err != nil || method != http.MethodPut || path != "/v1/backup-destinations/destination-id" {
		t.Fatalf("method=%q path=%q input=%#v err=%v", method, path, input, err)
	}
	destination = input.(map[string]any)
	if destination["name"] != "rotated" || destination["accessKey"] != "new-access" || destination["secretKey"] != "new-secret" {
		t.Fatalf("destination input=%#v", destination)
	}
}

func TestTemplateRepositoryCommandBodies(t *testing.T) {
	method, path, input, err := commandRequest([]string{"create-template-repository", "-"}, strings.NewReader(`{"name":"Community","slug":"community","repositoryUrl":"https://github.com/acme/templates"}`))
	if err != nil || method != http.MethodPost || path != "/v1/template-repositories" {
		t.Fatalf("method=%q path=%q input=%#v err=%v", method, path, input, err)
	}
	repository := input.(map[string]any)
	if repository["slug"] != "community" || repository["repositoryUrl"] != "https://github.com/acme/templates" {
		t.Fatalf("repository input=%#v", repository)
	}
	method, path, input, err = commandRequest([]string{"update-template-repository", "repository-id", `{"requireSignature":true,"syncIntervalSeconds":3600}`}, strings.NewReader(""))
	if err != nil || method != http.MethodPatch || path != "/v1/template-repositories/repository-id" {
		t.Fatalf("method=%q path=%q input=%#v err=%v", method, path, input, err)
	}
	repository = input.(map[string]any)
	if repository["requireSignature"] != true || repository["syncIntervalSeconds"] != float64(3600) {
		t.Fatalf("repository input=%#v", repository)
	}
}

func TestAIAuditAdministrationCommandBodies(t *testing.T) {
	method, path, input, err := commandRequest([]string{"create-service-account", "-"}, strings.NewReader(`{"name":"security-auditor","role":"auditor","expiresInDays":30}`))
	if err != nil || method != http.MethodPost || path != "/v1/service-accounts" {
		t.Fatalf("method=%q path=%q input=%#v err=%v", method, path, input, err)
	}
	account := input.(map[string]any)
	if account["role"] != "auditor" || account["expiresInDays"] != float64(30) {
		t.Fatalf("service account input=%#v", account)
	}
	method, path, input, err = commandRequest([]string{"triage-ai-audit-finding", "finding-id", `{"disposition":"acknowledged","note":"investigating"}`}, strings.NewReader(""))
	if err != nil || method != http.MethodPatch || path != "/v1/ai/audit-findings/finding-id" {
		t.Fatalf("method=%q path=%q input=%#v err=%v", method, path, input, err)
	}
	triage := input.(map[string]any)
	if triage["disposition"] != "acknowledged" || triage["note"] != "investigating" {
		t.Fatalf("triage input=%#v", triage)
	}
}

func TestChangePasswordCommandBody(t *testing.T) {
	method, path, input, err := commandRequest([]string{"change-password", "-"}, strings.NewReader(`{"currentPassword":"old-password","newPassword":"new-password"}`))
	if err != nil || method != http.MethodPut || path != "/v1/auth/password" {
		t.Fatalf("method=%q path=%q input=%#v err=%v", method, path, input, err)
	}
	passwords := input.(map[string]any)
	if passwords["currentPassword"] != "old-password" || passwords["newPassword"] != "new-password" {
		t.Fatalf("password input=%#v", passwords)
	}
}

func TestOIDCProviderCommandBodies(t *testing.T) {
	method, path, input, err := commandRequest([]string{"create-oidc-provider", "-"}, strings.NewReader(`{"name":"Workforce","issuer":"https://identity.example.com","clientId":"dockyard","clientSecret":"secret","domains":["example.com"]}`))
	if err != nil || method != http.MethodPost || path != "/v1/sso/oidc-providers" {
		t.Fatalf("method=%q path=%q input=%#v err=%v", method, path, input, err)
	}
	provider := input.(map[string]any)
	if provider["issuer"] != "https://identity.example.com" || provider["clientSecret"] != "secret" {
		t.Fatalf("OIDC provider input=%#v", provider)
	}
	method, path, input, err = commandRequest([]string{"update-oidc-provider", "provider-id", `{"name":"Workforce","clientSecret":"rotated"}`}, strings.NewReader(""))
	if err != nil || method != http.MethodPut || path != "/v1/sso/oidc-providers/provider-id" {
		t.Fatalf("method=%q path=%q input=%#v err=%v", method, path, input, err)
	}
	provider = input.(map[string]any)
	if provider["clientSecret"] != "rotated" {
		t.Fatalf("OIDC provider input=%#v", provider)
	}
	method, path, input, err = commandRequest([]string{"put-sso-settings", "-"}, strings.NewReader(`{"requireSso":true}`))
	if err != nil || method != http.MethodPut || path != "/v1/sso/settings" {
		t.Fatalf("method=%q path=%q input=%#v err=%v", method, path, input, err)
	}
	if input.(map[string]any)["requireSso"] != true {
		t.Fatalf("SSO settings input=%#v", input)
	}
}

func TestSAMLProviderCommandBodies(t *testing.T) {
	method, path, input, err := commandRequest([]string{"create-saml-provider", "-"}, strings.NewReader(`{"name":"Workforce","metadataXml":"<EntityDescriptor/>","domains":["example.com"]}`))
	if err != nil || method != http.MethodPost || path != "/v1/sso/saml-providers" {
		t.Fatalf("method=%q path=%q input=%#v err=%v", method, path, input, err)
	}
	provider := input.(map[string]any)
	if provider["metadataXml"] != "<EntityDescriptor/>" {
		t.Fatalf("SAML provider input=%#v", provider)
	}
	method, path, input, err = commandRequest([]string{"promote-saml-certificate", "provider-id", "Workforce"}, strings.NewReader(""))
	if err != nil || method != http.MethodPost || path != "/v1/sso/saml-providers/provider-id/certificate-rotation/promote" {
		t.Fatalf("method=%q path=%q input=%#v err=%v", method, path, input, err)
	}
	if input.(map[string]string)["confirm"] != "Workforce" {
		t.Fatalf("SAML promotion input=%#v", input)
	}
}

func TestSCIMTokenCommandBody(t *testing.T) {
	method, path, input, err := commandRequest([]string{"create-scim-token", "-"}, strings.NewReader(`{"name":"Workforce","defaultRole":"developer","expiresInDays":90}`))
	if err != nil || method != http.MethodPost || path != "/v1/scim/tokens" {
		t.Fatalf("method=%q path=%q input=%#v err=%v", method, path, input, err)
	}
	token := input.(map[string]any)
	if token["name"] != "Workforce" || token["expiresInDays"] != float64(90) {
		t.Fatalf("SCIM token input=%#v", token)
	}
}

func TestAccessGrantCommandBody(t *testing.T) {
	method, path, input, err := commandRequest([]string{"put-environment-grant", "environment-id", "user-id", "-"}, strings.NewReader(`{"role":"developer"}`))
	if err != nil || method != http.MethodPut || path != "/v1/environments/environment-id/grants/user-id" {
		t.Fatalf("method=%q path=%q input=%#v err=%v", method, path, input, err)
	}
	if input.(map[string]any)["role"] != "developer" {
		t.Fatalf("access grant input=%#v", input)
	}
}

func TestResourcePolicyCommandBody(t *testing.T) {
	method, path, input, err := commandRequest([]string{"put-project-policy", "project-id", "-"}, strings.NewReader(`{"maintenance":true,"maintenanceReason":"upgrade","maxServices":20}`))
	if err != nil || method != http.MethodPut || path != "/v1/projects/project-id/policy" {
		t.Fatalf("method=%q path=%q input=%#v err=%v", method, path, input, err)
	}
	policy := input.(map[string]any)
	if policy["maintenance"] != true || policy["maintenanceReason"] != "upgrade" || policy["maxServices"] != float64(20) {
		t.Fatalf("resource policy input=%#v", policy)
	}
}

func TestClusterCommandBodies(t *testing.T) {
	method, path, input, err := commandRequest([]string{"create-cluster", "-"}, strings.NewReader(`{"name":"Paris","labels":{"region":"eu-west"}}`))
	if err != nil || method != http.MethodPost || path != "/v1/clusters" || input.(map[string]any)["name"] != "Paris" {
		t.Fatalf("create cluster method=%q path=%q input=%#v err=%v", method, path, input, err)
	}
	method, path, input, err = commandRequest([]string{"update-cluster", "cluster-id", `{"state":"draining"}`}, strings.NewReader(""))
	if err != nil || method != http.MethodPatch || path != "/v1/clusters/cluster-id" || input.(map[string]any)["state"] != "draining" {
		t.Fatalf("update cluster method=%q path=%q input=%#v err=%v", method, path, input, err)
	}
}

func TestNotificationEndpointCommandBody(t *testing.T) {
	method, path, input, err := commandRequest([]string{"create-notification-endpoint", "-"}, strings.NewReader(`{"name":"On-call","kind":"pagerduty","pagerDutyIntegrationKey":"secret"}`))
	if err != nil || method != http.MethodPost || path != "/v1/notification-endpoints" {
		t.Fatalf("method=%q path=%q input=%#v err=%v", method, path, input, err)
	}
	endpoint := input.(map[string]any)
	if endpoint["kind"] != "pagerduty" || endpoint["pagerDutyIntegrationKey"] != "secret" {
		t.Fatalf("notification endpoint input=%#v", endpoint)
	}
}

func TestJSONFromStdin(t *testing.T) {
	method, path, input, err := commandRequest([]string{"create-service", "environment-id", "-"}, strings.NewReader(`{"name":"demo"}`))
	if err != nil || method != http.MethodPost || path != "/v1/environments/environment-id/services" {
		t.Fatalf("method=%q path=%q input=%#v err=%v", method, path, input, err)
	}
	value := input.(map[string]any)
	if value["name"] != "demo" {
		t.Fatalf("input=%#v", input)
	}
}
