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
		{[]string{"environments", "project-id"}, http.MethodGet, "/v1/projects/project-id/environments"},
		{[]string{"deploy", "service-id"}, http.MethodPost, "/v1/services/service-id/deployments"},
		{[]string{"database-engines"}, http.MethodGet, "/v1/database-engines"},
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
		{[]string{"preview-template", "template-id", `{}`}, http.MethodPost, "/v1/templates/template-id/preview"},
		{[]string{"template-versions", "service-id"}, http.MethodGet, "/v1/services/service-id/template-versions"},
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
