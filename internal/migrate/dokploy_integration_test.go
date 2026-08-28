package migrate

import (
	"bytes"
	"context"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/deploy"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestImportDokployDryRunAndIdempotence(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	destination, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(destination.Pool.Close)
	schema := "dokploy_fixture_" + uuid.NewString()[:8]
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	statements := []string{
		`CREATE SCHEMA ` + quotedSchema,
		`CREATE TABLE ` + quotedSchema + `.project ("projectId" text PRIMARY KEY,name text NOT NULL,description text,"organizationId" text NOT NULL)`,
		`CREATE TABLE ` + quotedSchema + `.environment ("environmentId" text PRIMARY KEY,"projectId" text NOT NULL,name text NOT NULL)`,
		`CREATE TABLE ` + quotedSchema + `.compose ("composeId" text PRIMARY KEY,"environmentId" text NOT NULL,name text NOT NULL,"appName" text NOT NULL,"composeFile" text NOT NULL,env text)`,
		`CREATE TABLE ` + quotedSchema + `.domain ("domainId" text PRIMARY KEY,"composeId" text,host text,path text,"serviceName" text,port integer,https boolean,enabled boolean,"customCertResolver" text)`,
		`CREATE TABLE ` + quotedSchema + `.application ("applicationId" text,"environmentId" text)`,
	}
	for _, table := range []string{"postgres", "mysql", "mariadb", "mongo", "redis", "libsql"} {
		statements = append(statements, `CREATE TABLE `+quotedSchema+`.`+pgx.Identifier{table}.Sanitize()+` ("environmentId" text)`)
	}
	for _, statement := range statements {
		if _, err = destination.Pool.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _, _ = destination.Pool.Exec(context.Background(), `DROP SCHEMA `+quotedSchema+` CASCADE`) })
	fixtureHost := "import-" + uuid.NewString()[:8] + ".example.test"
	_, err = destination.Pool.Exec(ctx, `INSERT INTO `+quotedSchema+`.project VALUES('p1','Imported Project','description','source-org'); INSERT INTO `+quotedSchema+`.environment VALUES('e1','p1','Production'); INSERT INTO `+quotedSchema+`.compose VALUES('c1','e1','Web','web','services:
  web:
    image: nginx:alpine
','A=one'); INSERT INTO `+quotedSchema+`.domain VALUES('d1','c1','`+fixtureHost+`','/','web',80,true,true,'letsencrypt')`)
	if err != nil {
		t.Fatal(err)
	}
	targetOrg := uuid.New()
	_, err = destination.Pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Migration Target',$2)`, targetOrg, "migration-"+targetOrg.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = destination.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, targetOrg)
	})
	box, _ := cryptox.New(bytes.Repeat([]byte{9}, 32))
	parsed, _ := url.Parse(databaseURL)
	query := parsed.Query()
	query.Set("options", "-csearch_path="+schema)
	parsed.RawQuery = query.Encode()
	options := DokployOptions{SourceURL: parsed.String(), SourceOrganizationID: "source-org", TargetOrganizationID: targetOrg, DryRun: true}
	report, err := ImportDokploy(ctx, destination, box, deploy.Compiler{PublicNetwork: "dockyard-public"}, options)
	if err != nil || report.Projects != 1 || report.Environments != 1 || report.Services != 1 || report.Routes != 1 {
		t.Fatalf("dry-run report = %#v, err = %v", report, err)
	}
	options.DryRun = false
	if _, err = ImportDokploy(ctx, destination, box, deploy.Compiler{PublicNetwork: "dockyard-public"}, options); err != nil {
		t.Fatal(err)
	}
	if _, err = ImportDokploy(ctx, destination, box, deploy.Compiler{PublicNetwork: "dockyard-public"}, options); err != nil {
		t.Fatal(err)
	}
	var projects, services, routes int
	if err = destination.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM projects WHERE organization_id=$1),(SELECT count(*) FROM compose_services s JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE p.organization_id=$1),(SELECT count(*) FROM routes r JOIN compose_services s ON s.id=r.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE p.organization_id=$1)`, targetOrg).Scan(&projects, &services, &routes); err != nil {
		t.Fatal(err)
	}
	if projects != 1 || services != 1 || routes != 1 {
		t.Fatalf("idempotent counts = %d/%d/%d", projects, services, routes)
	}
}
