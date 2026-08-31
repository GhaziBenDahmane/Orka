package store

import (
	"testing"

	"github.com/google/uuid"
)

func TestMigrationResourcePaginationIsCompleteAndTenantScoped(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	organizationID, otherOrganizationID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Target',$2),($3,'Other',$4)`, organizationID, "target-"+organizationID.String(), otherOrganizationID, "other-"+otherOrganizationID.String()); err != nil {
		t.Fatal(err)
	}
	for _, record := range []struct {
		organization     uuid.UUID
		source, kind, id string
	}{
		{organizationID, "source-a", "application", "app-2"},
		{organizationID, "source-a", "application", "app-1"},
		{organizationID, "source-a", "database", "db-1"},
		{organizationID, "source-b", "application", "app-1"},
		{otherOrganizationID, "source-a", "application", "private"},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO dokploy_migration_resources(target_organization_id,source_organization_id,source_kind,source_id,status) VALUES($1,$2,$3,$4,'imported')`, record.organization, record.source, record.kind, record.id); err != nil {
			t.Fatal(err)
		}
	}
	db := &Store{Pool: pool}
	first, hasMore, err := db.ListMigrationResourcesPage(ctx, organizationID, "", nil, 2)
	if err != nil || !hasMore || len(first) != 2 || first[0].SourceID != "app-1" || first[1].SourceID != "app-2" {
		t.Fatalf("first page=%#v hasMore=%v err=%v", first, hasMore, err)
	}
	last := first[len(first)-1]
	second, hasMore, err := db.ListMigrationResourcesPage(ctx, organizationID, "", &MigrationResourcePageCursor{SourceOrganizationID: last.SourceOrganizationID, SourceKind: last.SourceKind, SourceID: last.SourceID}, 2)
	if err != nil || hasMore || len(second) != 2 || second[0].SourceID != "db-1" || second[1].SourceOrganizationID != "source-b" {
		t.Fatalf("second page=%#v hasMore=%v err=%v", second, hasMore, err)
	}
	filtered, hasMore, err := db.ListMigrationResourcesPage(ctx, organizationID, "source-a", nil, 2)
	if err != nil || !hasMore || len(filtered) != 2 {
		t.Fatalf("filtered page=%#v hasMore=%v err=%v", filtered, hasMore, err)
	}
	all, err := db.ListMigrationResources(ctx, organizationID, "")
	if err != nil || len(all) != 4 {
		t.Fatalf("complete inventory=%#v err=%v", all, err)
	}
	if _, _, err = db.ListMigrationResourcesPage(ctx, organizationID, "", nil, 0); err == nil {
		t.Fatal("invalid page limit was accepted")
	}
}
