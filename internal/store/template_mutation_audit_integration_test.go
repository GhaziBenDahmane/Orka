package store

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

func TestTemplateMutationLifecycleCommitsWithAudit(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, userID := uuid.New(), uuid.New()
	projectID, environmentID := uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Template mutation audit',$2)`, []any{organizationID, "template-mutation-audit-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	principal := Principal{OrganizationID: organizationID, UserID: userID, Role: "owner"}
	invalidPrincipal := Principal{OrganizationID: organizationID, UserID: uuid.New(), Role: "owner"}
	failedTemplate := Template{Key: "audit-template", Version: "failed", Name: "Failed", ComposeYAML: "services: {}", Config: json.RawMessage(`{}`), Source: "dokploy", Checksum: "failed"}

	if _, err := db.CreateTemplateWithAudit(ctx, invalidPrincipal, failedTemplate, "127.0.0.1:1234"); err == nil {
		t.Fatal("template import succeeded without valid audit evidence")
	}
	var failedTemplateCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM templates WHERE organization_id=$1 AND template_key=$2 AND version=$3`, organizationID, failedTemplate.Key, failedTemplate.Version).Scan(&failedTemplateCount); err != nil || failedTemplateCount != 0 {
		t.Fatalf("failed evidence retained imported template: count=%d err=%v", failedTemplateCount, err)
	}

	first, err := db.CreateTemplateWithAudit(ctx, principal, Template{Key: "audit-template", Version: "1", Name: "Version 1", ComposeYAML: "services: {web: {image: nginx:1}}", Config: json.RawMessage(`{}`), Source: "dokploy", Checksum: "checksum-1"}, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	second, err := db.CreateTemplateWithAudit(ctx, principal, Template{Key: "audit-template", Version: "2", Name: "Version 2", ComposeYAML: "services: {web: {image: nginx:2}}", Config: json.RawMessage(`{}`), Source: "dokploy", Checksum: "checksum-2"}, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}

	serviceID := uuid.New()
	service := ComposeService{ID: serviceID, EnvironmentID: environmentID, Name: "Web", Slug: "web", StackName: "template-audit-" + serviceID.String(), ComposeYAML: first.ComposeYAML, EncryptedEnv: "encrypted-v1"}
	routes := []Route{{ServiceName: "web", Host: "v1.example.test", PathPrefix: "/", TargetPort: 80, TLS: true, CertificateResolver: "letsencrypt"}}
	instance := TemplateInstance{TemplateID: &first.ID, TemplateKey: first.Key, TemplateVersion: first.Version, TemplateChecksum: first.Checksum, AppliedComposeChecksum: "applied-1", EncryptedVariables: "variables-v1", EncryptedOverrides: "overrides-v1"}
	if _, _, err = db.CreateTemplateServiceWithAudit(ctx, invalidPrincipal, service, routes, instance, "127.0.0.1:1234"); err == nil {
		t.Fatal("template instantiation succeeded without valid audit evidence")
	}
	var serviceCount, routeCount, instanceCount int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM compose_services WHERE id=$1`, serviceID).Scan(&serviceCount); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM routes WHERE compose_service_id=$1`, serviceID).Scan(&routeCount); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM template_instances WHERE compose_service_id=$1`, serviceID).Scan(&instanceCount); err != nil || serviceCount != 0 || routeCount != 0 || instanceCount != 0 {
		t.Fatalf("failed evidence retained instantiated resources: services=%d routes=%d instances=%d err=%v", serviceCount, routeCount, instanceCount, err)
	}

	service, routes, err = db.CreateTemplateServiceWithAudit(ctx, principal, service, routes, instance, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	upgraded := service
	upgraded.ComposeYAML = second.ComposeYAML
	upgraded.EncryptedEnv = "encrypted-v2"
	upgradedRoutes := []Route{{ServiceName: "web", Host: "v2.example.test", PathPrefix: "/", TargetPort: 8080, TLS: true, CertificateResolver: "letsencrypt"}}
	upgradedInstance := TemplateInstance{TemplateID: &second.ID, TemplateKey: second.Key, TemplateVersion: second.Version, TemplateChecksum: second.Checksum, AppliedComposeChecksum: "applied-2", EncryptedVariables: "variables-v2", EncryptedOverrides: "overrides-v2"}
	if _, _, err = db.UpgradeTemplateServiceWithAudit(ctx, invalidPrincipal, service.Revision, upgraded, upgradedRoutes, upgradedInstance, "127.0.0.1:1234", map[string]any{"toTemplateId": second.ID}); err == nil {
		t.Fatal("template upgrade succeeded without valid audit evidence")
	}
	stored, storedRoutes, err := db.GetComposeService(ctx, organizationID, serviceID)
	if err != nil || stored.Revision != 1 || stored.ComposeYAML != first.ComposeYAML || stored.EncryptedEnv != "encrypted-v1" || len(storedRoutes) != 1 || storedRoutes[0].Host != "v1.example.test" {
		t.Fatalf("failed evidence changed instantiated service: service=%#v routes=%#v err=%v", stored, storedRoutes, err)
	}
	storedInstance, err := db.GetTemplateInstance(ctx, organizationID, serviceID)
	if err != nil || storedInstance.TemplateID == nil || *storedInstance.TemplateID != first.ID || storedInstance.TemplateVersion != "1" {
		t.Fatalf("failed evidence changed template provenance: instance=%#v err=%v", storedInstance, err)
	}

	stored, storedRoutes, err = db.UpgradeTemplateServiceWithAudit(ctx, principal, service.Revision, upgraded, upgradedRoutes, upgradedInstance, "127.0.0.1:1234", map[string]any{"fromTemplateId": first.ID, "toTemplateId": second.ID})
	if err != nil || stored.Revision != 2 || stored.ComposeYAML != second.ComposeYAML || stored.EncryptedEnv != "encrypted-v2" || len(storedRoutes) != 1 || storedRoutes[0].Host != "v2.example.test" {
		t.Fatalf("audited template upgrade: service=%#v routes=%#v err=%v", stored, storedRoutes, err)
	}
	storedInstance, err = db.GetTemplateInstance(ctx, organizationID, serviceID)
	if err != nil || storedInstance.TemplateID == nil || *storedInstance.TemplateID != second.ID || storedInstance.TemplateVersion != "2" {
		t.Fatalf("audited template provenance: instance=%#v err=%v", storedInstance, err)
	}

	var importAudits, instantiateAudits, upgradeAudits int
	if err = pool.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE action='template.import'),
		count(*) FILTER (WHERE action='template.instantiate'),
		count(*) FILTER (WHERE action='template.upgrade')
		FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2`, organizationID, userID).Scan(&importAudits, &instantiateAudits, &upgradeAudits); err != nil {
		t.Fatal(err)
	}
	if importAudits != 2 || instantiateAudits != 1 || upgradeAudits != 1 {
		t.Fatalf("template mutation evidence: imports=%d instantiations=%d upgrades=%d", importAudits, instantiateAudits, upgradeAudits)
	}
}
