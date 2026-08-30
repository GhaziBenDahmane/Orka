package store

import (
	"encoding/json"
	"strings"
	"testing"
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
}
