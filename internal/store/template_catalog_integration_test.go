package store

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestUpsertGlobalTemplatesIsAtomic(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	prefix := "atomic-" + strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-"))
	items := []Template{
		{Key: prefix + "-one", Version: "1", Name: "One", ComposeYAML: "services: {}", Config: json.RawMessage(`{}`), Source: "builtin", SourcePath: "blueprints/one", Checksum: "one"},
		{Key: prefix + "-two", Version: "1", Name: "Two", ComposeYAML: "services: {}", Config: json.RawMessage(`{`), Source: "builtin", SourcePath: "blueprints/two", Checksum: "two"},
	}
	if err := db.UpsertGlobalTemplates(ctx, items); err == nil {
		t.Fatal("catalog publication accepted invalid JSON after its first entry")
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM templates WHERE template_key LIKE $1`, prefix+"%").Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed catalog left %d partial templates: %v", count, err)
	}
	items[1].Config = json.RawMessage(`{}`)
	if err := db.UpsertGlobalTemplates(ctx, items); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM templates WHERE template_key LIKE $1`, prefix+"%").Scan(&count); err != nil || count != 2 {
		t.Fatalf("valid catalog stored %d templates: %v", count, err)
	}
	items[0].Name = "Updated"
	items[0].SourcePath = "blueprints/renamed"
	if err := db.UpsertGlobalTemplates(ctx, items); err != nil {
		t.Fatal(err)
	}
	var name, sourcePath string
	if err := pool.QueryRow(ctx, `SELECT name,source_path FROM templates WHERE organization_id IS NULL AND template_key=$1 AND version='1'`, items[0].Key).Scan(&name, &sourcePath); err != nil || name != "Updated" || sourcePath != "blueprints/renamed" {
		t.Fatalf("updated template name=%q sourcePath=%q err=%v", name, sourcePath, err)
	}
	imported := Template{Key: prefix + "-imported", Version: "1", Name: "Imported", ComposeYAML: "services: {}", Config: json.RawMessage(`{}`), Source: "dokploy", SourcePath: "blueprints/imported", Checksum: "imported"}
	if _, err := db.CreateTemplate(ctx, imported); err != nil {
		t.Fatal(err)
	}
	var staleTemplateID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM templates WHERE organization_id IS NULL AND template_key=$1 AND version='1'`, items[1].Key).Scan(&staleTemplateID); err != nil {
		t.Fatal(err)
	}
	organizationID, projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Template provenance',$2)`, []any{organizationID, "template-provenance-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Environment','environment')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'Service','service',$3,'services: {}')`, []any{serviceID, environmentID, "template-provenance-" + serviceID.String()}},
		{`INSERT INTO template_instances(compose_service_id,template_id,template_key,template_version,template_checksum,encrypted_variables) VALUES($1,$2,$3,'1','two','encrypted')`, []any{serviceID, staleTemplateID, items[1].Key}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.UpsertGlobalTemplates(ctx, items[:1]); err != nil {
		t.Fatal(err)
	}
	var staleBuiltin, preservedImported int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM templates WHERE organization_id IS NULL AND template_key=$1 AND source='builtin'`, items[1].Key).Scan(&staleBuiltin); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM templates WHERE organization_id IS NULL AND template_key=$1 AND source='dokploy'`, imported.Key).Scan(&preservedImported); err != nil {
		t.Fatal(err)
	}
	if staleBuiltin != 0 || preservedImported != 1 {
		t.Fatalf("reconciled stale builtin=%d preserved imported=%d", staleBuiltin, preservedImported)
	}
	var retainedTemplateID *uuid.UUID
	var retainedKey, retainedVersion, retainedChecksum string
	if err := pool.QueryRow(ctx, `SELECT template_id,template_key,template_version,template_checksum FROM template_instances WHERE compose_service_id=$1`, serviceID).Scan(&retainedTemplateID, &retainedKey, &retainedVersion, &retainedChecksum); err != nil {
		t.Fatal(err)
	}
	if retainedTemplateID != nil || retainedKey != items[1].Key || retainedVersion != "1" || retainedChecksum != "two" {
		t.Fatalf("retired template provenance id=%v key=%q version=%q checksum=%q", retainedTemplateID, retainedKey, retainedVersion, retainedChecksum)
	}
	mixed := append([]Template(nil), items[:1]...)
	mixed = append(mixed, Template{ID: uuid.New(), Key: prefix + "-mixed", Version: "1", Name: "Mixed", ComposeYAML: "services: {}", Config: json.RawMessage(`{}`), Source: "dokploy", Checksum: "mixed"})
	if err := db.UpsertGlobalTemplates(ctx, mixed); err == nil {
		t.Fatal("mixed-source global catalog was accepted")
	}
}
