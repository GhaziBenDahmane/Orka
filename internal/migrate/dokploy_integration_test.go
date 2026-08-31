package migrate

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strings"
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
		`CREATE TABLE ` + quotedSchema + `.tag ("tagId" text PRIMARY KEY,name text NOT NULL,color text,"organizationId" text NOT NULL)`,
		`CREATE TABLE ` + quotedSchema + `.project_tag (id text PRIMARY KEY,"projectId" text NOT NULL,"tagId" text NOT NULL)`,
		`CREATE TABLE ` + quotedSchema + `.network ("networkId" text PRIMARY KEY,name text NOT NULL,driver text NOT NULL,internal boolean NOT NULL,attachable boolean NOT NULL,"enableIPv4" boolean NOT NULL,"enableIPv6" boolean NOT NULL,mtu integer,ipam jsonb NOT NULL DEFAULT '{}'::jsonb,"organizationId" text NOT NULL,"serverId" text)`,
		`CREATE TABLE ` + quotedSchema + `.environment ("environmentId" text PRIMARY KEY,"projectId" text NOT NULL,name text NOT NULL)`,
		`CREATE TABLE ` + quotedSchema + `.git_provider ("gitProviderId" text PRIMARY KEY,name text NOT NULL,"providerType" text NOT NULL,"organizationId" text NOT NULL)`,
		`CREATE TABLE ` + quotedSchema + `.github ("githubId" text PRIMARY KEY,"githubUrl" text NOT NULL,"gitProviderId" text NOT NULL)`,
		`CREATE TABLE ` + quotedSchema + `.gitlab ("gitlabId" text PRIMARY KEY,"gitlabUrl" text NOT NULL,"gitlabInternalUrl" text,"access_token" text,"gitProviderId" text NOT NULL)`,
		`CREATE TABLE ` + quotedSchema + `.gitea ("giteaId" text PRIMARY KEY,"giteaUrl" text NOT NULL,"giteaInternalUrl" text,"access_token" text,"gitProviderId" text NOT NULL)`,
		`CREATE TABLE ` + quotedSchema + `.bitbucket ("bitbucketId" text PRIMARY KEY,"bitbucketUsername" text,"bitbucketEmail" text,"appPassword" text,"apiToken" text,"gitProviderId" text NOT NULL)`,
		`CREATE TABLE ` + quotedSchema + `.registry ("registryId" text PRIMARY KEY,"registryName" text NOT NULL,"registryUrl" text,username text NOT NULL,password text NOT NULL,"organizationId" text NOT NULL)`,
		`CREATE TABLE ` + quotedSchema + `.compose ("composeId" text PRIMARY KEY,"environmentId" text NOT NULL,name text NOT NULL,"appName" text NOT NULL,"composeFile" text NOT NULL,env text,"serviceNetworks" jsonb NOT NULL DEFAULT '[]'::jsonb)`,
		`CREATE TABLE ` + quotedSchema + `.domain ("domainId" text PRIMARY KEY,"composeId" text,"applicationId" text,host text,path text,"serviceName" text,port integer,https boolean,enabled boolean,"customCertResolver" text,"internalPath" text,"stripPath" boolean)`,
		`CREATE TABLE ` + quotedSchema + `.application ("applicationId" text PRIMARY KEY,"environmentId" text,name text,"appName" text,env text,"sourceType" text,"buildType" text,"dockerImage" text,username text,password text,command text,args text[],replicas integer,repository text,owner text,branch text,"buildPath" text,dockerfile text,"dockerBuildStage" text,"buildArgs" text,"buildSecrets" text,"enableSubmodules" boolean,"githubId" text,"gitlabId" text,"giteaId" text,"bitbucketId" text,"registryId" text,"buildRegistryId" text,"networkIds" text[] DEFAULT '{}')`,
		`CREATE TABLE ` + quotedSchema + `.destination ("destinationId" text PRIMARY KEY,name text NOT NULL,provider text,"accessKey" text NOT NULL,"secretAccessKey" text NOT NULL,bucket text NOT NULL,region text NOT NULL,endpoint text NOT NULL,"additionalFlags" text[],"organizationId" text NOT NULL)`,
		`CREATE TABLE ` + quotedSchema + `.backup ("backupId" text PRIMARY KEY,schedule text NOT NULL,enabled boolean,database text NOT NULL,prefix text NOT NULL,"destinationId" text NOT NULL,"keepLatestCount" integer,"backupType" text NOT NULL,"databaseType" text NOT NULL,"composeId" text,"serviceName" text,metadata jsonb,"postgresId" text,"mariadbId" text,"mysqlId" text,"mongoId" text,"libsqlId" text)`,
		`CREATE TABLE ` + quotedSchema + `.volume_backup ("volumeBackupId" text PRIMARY KEY,name text NOT NULL,"volumeName" text NOT NULL,prefix text NOT NULL,"serviceType" text NOT NULL,"appName" text NOT NULL,"serviceName" text,"turnOff" boolean NOT NULL,"cronExpression" text NOT NULL,"keepLatestCount" integer,enabled boolean,"destinationId" text NOT NULL)`,
		`CREATE TABLE ` + quotedSchema + `.slack ("slackId" text PRIMARY KEY,"webhookUrl" text NOT NULL,channel text)`,
		`CREATE TABLE ` + quotedSchema + `.email ("emailId" text PRIMARY KEY,"smtpServer" text NOT NULL,"smtpPort" integer NOT NULL,username text NOT NULL,password text NOT NULL,"fromAddress" text NOT NULL,"toAddress" text[] NOT NULL)`,
		`CREATE TABLE ` + quotedSchema + `.notification ("notificationId" text PRIMARY KEY,name text NOT NULL,"appDeploy" boolean NOT NULL DEFAULT false,"appBuildError" boolean NOT NULL DEFAULT false,"databaseBackup" boolean NOT NULL DEFAULT false,"volumeBackup" boolean NOT NULL DEFAULT false,"dokployRestart" boolean NOT NULL DEFAULT false,"dokployBackup" boolean NOT NULL DEFAULT false,"dockerCleanup" boolean NOT NULL DEFAULT false,"serverThreshold" boolean NOT NULL DEFAULT false,"notificationType" text NOT NULL,"slackId" text,"emailId" text,"organizationId" text NOT NULL)`,
	}
	statements = append(statements,
		`CREATE TABLE `+quotedSchema+`.postgres ("postgresId" text PRIMARY KEY,"environmentId" text,name text,"appName" text,"databaseName" text,"databaseUser" text,"databasePassword" text,"dockerImage" text,env text,"networkIds" text[] DEFAULT '{}')`,
		`CREATE TABLE `+quotedSchema+`.mysql ("mysqlId" text PRIMARY KEY,"environmentId" text,name text,"appName" text,"databaseName" text,"databaseUser" text,"databasePassword" text,"rootPassword" text,"dockerImage" text,env text)`,
		`CREATE TABLE `+quotedSchema+`.mariadb ("mariadbId" text PRIMARY KEY,"environmentId" text,name text,"appName" text,"databaseName" text,"databaseUser" text,"databasePassword" text,"rootPassword" text,"dockerImage" text,env text)`,
		`CREATE TABLE `+quotedSchema+`.mongo ("mongoId" text PRIMARY KEY,"environmentId" text,name text,"appName" text,"databaseUser" text,"databasePassword" text,"dockerImage" text,env text)`,
		`CREATE TABLE `+quotedSchema+`.redis ("redisId" text PRIMARY KEY,"environmentId" text,name text,"appName" text,password text,"dockerImage" text,env text)`,
		`CREATE TABLE `+quotedSchema+`.libsql ("libsqlId" text PRIMARY KEY,"environmentId" text,name text,"appName" text,"databaseUser" text,"databasePassword" text,"dockerImage" text,env text)`,
	)
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
    volumes:
      - uploads:/var/lib/uploads
  db:
    image: postgres:17
    environment:
      POSTGRES_DB: app
      POSTGRES_USER: app
      POSTGRES_PASSWORD: ${DB_PASSWORD}
volumes:
  uploads: {}
','A=one
DB_PASSWORD=compose-secret'); INSERT INTO `+quotedSchema+`.git_provider VALUES('gp1','GitHub App','github','source-org'); INSERT INTO `+quotedSchema+`.github VALUES('gh1','https://github.com','gp1'); INSERT INTO `+quotedSchema+`.application ("applicationId","environmentId",name,"appName",env,"sourceType","buildType","dockerImage",args,replicas) VALUES('a1','e1','Worker','legacy-worker','WORKERS=2','docker','dockerfile','ghcr.io/example/worker:1.2','{}',2); INSERT INTO `+quotedSchema+`.application ("applicationId","environmentId",name,"appName",env,"sourceType","buildType",args,replicas,repository,owner,branch,"buildPath",dockerfile,"dockerBuildStage","buildArgs","buildSecrets","enableSubmodules","githubId","buildRegistryId") VALUES('a2','e1','Git API','legacy-api','PORT=3000','github','dockerfile','{}',1,'api','example','main','/','Dockerfile','runtime','GO_VERSION=1.26','',true,'gh1','reg1'); INSERT INTO `+quotedSchema+`.domain ("domainId","composeId","applicationId",host,path,"serviceName",port,https,enabled,"customCertResolver","internalPath","stripPath") VALUES('d1','c1',NULL,'`+fixtureHost+`','/public','web',80,true,false,'letsencrypt','/internal',true),('d2',NULL,'a1','app-`+fixtureHost+`','/',NULL,8080,true,true,'letsencrypt','/',false)`)
	if err == nil {
		_, err = destination.Pool.Exec(ctx, `INSERT INTO `+quotedSchema+`.tag VALUES('tag1','Production','#22C55E','source-org'); INSERT INTO `+quotedSchema+`.project_tag VALUES('project-tag1','p1','tag1')`)
	}
	if err == nil {
		_, err = destination.Pool.Exec(ctx, `ALTER TABLE `+quotedSchema+`.compose ADD COLUMN "serverId" text; ALTER TABLE `+quotedSchema+`.application ADD COLUMN "serverId" text; INSERT INTO `+quotedSchema+`.network VALUES('network1','shared_backend','overlay',true,true,true,false,1450,'{"driver":"default","config":[{"subnet":"10.42.0.0/24","gateway":"10.42.0.1"}]}','source-org','source-server-1'); UPDATE `+quotedSchema+`.compose SET "serviceNetworks"='[{"serviceName":"web","networkIds":["network1"],"detachDokployNetwork":false}]',"serverId"='source-server-1'; UPDATE `+quotedSchema+`.application SET "serverId"='source-server-1'; UPDATE `+quotedSchema+`.application SET "networkIds"=ARRAY['network1'] WHERE "applicationId"='a1'`)
	}
	if err == nil {
		_, err = destination.Pool.Exec(ctx, `
			INSERT INTO `+quotedSchema+`.postgres VALUES('pg1','e1','Imported PostgreSQL','legacy-postgres','legacydb','legacyuser','legacy-secret','postgres:16','EXTRA=value');
			INSERT INTO `+quotedSchema+`.postgres VALUES('timescale1','e1','Imported TimescaleDB','legacy-timescale','metrics','legacyuser','legacy-secret','timescale/timescaledb:2.29.2-pg17','');
			INSERT INTO `+quotedSchema+`.mysql VALUES('mysql1','e1','Imported MySQL','legacy-mysql','legacydb','legacyuser','legacy-secret','legacy-root','mysql:8','');
			INSERT INTO `+quotedSchema+`.mariadb VALUES('maria1','e1','Imported MariaDB','legacy-mariadb','legacydb','legacyuser','legacy-secret','legacy-root','mariadb:11','');
			INSERT INTO `+quotedSchema+`.mongo VALUES('mongo1','e1','Imported MongoDB','legacy-mongo','legacyuser','legacy-secret','mongo:7','');
			INSERT INTO `+quotedSchema+`.redis VALUES('redis1','e1','Imported Redis','legacy-redis','legacy-secret','redis:7','');
			INSERT INTO `+quotedSchema+`.redis VALUES('valkey1','e1','Imported Valkey','legacy-valkey','legacy-secret','valkey/valkey:8','');
			INSERT INTO `+quotedSchema+`.libsql VALUES('libsql1','e1','Imported libSQL','legacy-libsql','legacyuser','legacy-secret','ghcr.io/tursodatabase/libsql-server:v0.24.32','');
			ALTER TABLE `+quotedSchema+`.postgres ADD COLUMN "serverId" text;
			ALTER TABLE `+quotedSchema+`.mysql ADD COLUMN "serverId" text;
			ALTER TABLE `+quotedSchema+`.mariadb ADD COLUMN "serverId" text;
			ALTER TABLE `+quotedSchema+`.mongo ADD COLUMN "serverId" text;
			ALTER TABLE `+quotedSchema+`.redis ADD COLUMN "serverId" text;
			ALTER TABLE `+quotedSchema+`.libsql ADD COLUMN "serverId" text`)
	}
	if err == nil {
		_, err = destination.Pool.Exec(ctx, `UPDATE `+quotedSchema+`.postgres SET "networkIds"=ARRAY['network1']; UPDATE `+quotedSchema+`.postgres SET "serverId"='source-server-1'; UPDATE `+quotedSchema+`.mysql SET "serverId"='source-server-1'; UPDATE `+quotedSchema+`.mariadb SET "serverId"='source-server-1'; UPDATE `+quotedSchema+`.mongo SET "serverId"='source-server-1'; UPDATE `+quotedSchema+`.redis SET "serverId"='source-server-1'; UPDATE `+quotedSchema+`.libsql SET "serverId"='source-server-1'`)
	}
	sourceKey := bytes.Repeat([]byte{3}, 32)
	if err == nil {
		_, err = destination.Pool.Exec(ctx, `UPDATE `+quotedSchema+`.application SET "buildSecrets"=$1 WHERE "applicationId"='a2'`, encryptDokployFixture(t, sourceKey, "NPM_TOKEN=legacy-build-secret"))
	}
	if err == nil {
		_, err = destination.Pool.Exec(ctx, `INSERT INTO `+quotedSchema+`.registry VALUES('reg1','Build Registry','registry.example.test','robot',$1,'source-org')`, encryptDokployFixture(t, sourceKey, "registry-secret"))
	}
	if err == nil {
		_, err = destination.Pool.Exec(ctx, `INSERT INTO `+quotedSchema+`.destination VALUES('dst1','Archive','s3',$1,$2,'migration-bucket','eu-west-1','https://s3.example.test',ARRAY[]::text[],'source-org')`, encryptDokployFixture(t, sourceKey, "legacy-access"), encryptDokployFixture(t, sourceKey, "legacy-secret-key"))
	}
	if err == nil {
		_, err = destination.Pool.Exec(ctx, `INSERT INTO `+quotedSchema+`.volume_backup VALUES('volume1','Uploads','uploads','volumes','compose','web','web',true,'0 3 * * *',5,true,'dst1')`)
	}
	if err == nil {
		_, err = destination.Pool.Exec(ctx, `INSERT INTO `+quotedSchema+`.backup ("backupId",schedule,enabled,database,prefix,"destinationId","keepLatestCount","backupType","databaseType","postgresId") VALUES('backup1','0 2 * * *',true,'legacydb','nightly','dst1',7,'database','postgres','pg1'); INSERT INTO `+quotedSchema+`.backup ("backupId",schedule,enabled,database,prefix,"destinationId","keepLatestCount","backupType","databaseType","composeId","serviceName",metadata) VALUES('backup-compose','0 4 * * *',true,'app','compose','dst1',7,'compose','postgres','c1','db','{"postgres":{"databaseUser":"app"}}')`)
	}
	if err == nil {
		_, err = destination.Pool.Exec(ctx, `INSERT INTO `+quotedSchema+`.slack VALUES('slack1',$1,'#operations')`, encryptDokployFixture(t, sourceKey, "https://hooks.slack.example.test/services/secret-token"))
	}
	if err == nil {
		_, err = destination.Pool.Exec(ctx, `INSERT INTO `+quotedSchema+`.notification ("notificationId",name,"appBuildError","databaseBackup","notificationType","slackId","organizationId") VALUES('notification1','Production alerts',true,true,'slack','slack1','source-org')`)
	}
	if err != nil {
		t.Fatal(err)
	}
	targetOrg := uuid.New()
	targetCluster := uuid.New()
	_, err = destination.Pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Migration Target',$2)`, targetOrg, "migration-"+targetOrg.String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = destination.Pool.Exec(ctx, `INSERT INTO clusters(id,organization_id,name,slug,state) VALUES($1,$2,'Migration Cluster',$3,'active')`, targetCluster, targetOrg, "migration-"+targetCluster.String()); err != nil {
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
	options := DokployOptions{SourceURL: parsed.String(), SourceOrganizationID: "source-org", TargetOrganizationID: targetOrg, RegistryPrefix: "registry.example.test/imports", ServerClusterMappings: map[string]uuid.UUID{"source-server-1": targetCluster}, DryRun: true, EncryptionKeys: [][]byte{sourceKey}}
	report, err := ImportDokploy(ctx, destination, box, deploy.Compiler{PublicNetwork: "dockyard-public"}, options)
	if err != nil || report.Projects != 1 || report.Environments != 1 || report.Services != 1 || report.Routes != 2 || report.Databases != 9 || report.Applications != 2 || report.BackupDestinations != 1 || report.BackupPolicies != 3 || report.SourceCredentials != 2 || report.NotificationEndpoints != 1 || report.Tags != 1 || report.ProjectTags != 1 || report.Networks != 1 || report.ServiceNetworks != 4 {
		t.Fatalf("dry-run report = %#v, err = %v", report, err)
	}
	kindCounts := map[string]int{}
	for _, resource := range report.Resources {
		kindCounts[resource.SourceKind]++
	}
	expectedKinds := map[string]int{"project": 1, "tag": 1, "project_tag": 1, "network": 1, "service_network": 4, "environment": 1, "compose": 1, "compose_route": 1, "application": 2, "application_route": 1, "database": 8, "compose_database": 1, "backup_destination": 1, "backup_policy": 2, "volume_backup": 1, "source_credential": 2, "notification": 1}
	if len(report.Resources) != 30 || !reflect.DeepEqual(kindCounts, expectedKinds) {
		t.Fatalf("migration parity resources = %#v", report.Resources)
	}
	encodedReport, _ := json.Marshal(report)
	if bytes.Contains(encodedReport, []byte("legacy-secret")) || bytes.Contains(encodedReport, []byte("compose-secret")) || bytes.Contains(encodedReport, []byte("registry-secret")) || bytes.Contains(encodedReport, []byte("secret-token")) {
		t.Fatal("dry-run report leaked source credentials")
	}
	options.DryRun = false
	if _, err = ImportDokploy(ctx, destination, box, deploy.Compiler{PublicNetwork: "dockyard-public"}, options); err != nil {
		t.Fatal(err)
	}
	controlPlaneVerification, err := VerifyDokployImport(ctx, destination, targetOrg, "source-org", false, nil)
	if err != nil || controlPlaneVerification.Ready || controlPlaneVerification.Verified != 29 || controlPlaneVerification.Blocked != 1 {
		t.Fatalf("control-plane verification=%#v err=%v", controlPlaneVerification, err)
	}
	if _, err = VerifyDokployImport(ctx, destination, targetOrg, "not-imported", false, nil); err == nil || !strings.Contains(err.Error(), "no persisted") {
		t.Fatalf("missing manifest verification error=%v", err)
	}
	acknowledgements := []string{"source_credential:github:gh1"}
	controlPlaneVerification, err = VerifyDokployImport(ctx, destination, targetOrg, "source-org", false, acknowledgements)
	if err != nil || !controlPlaneVerification.Ready || controlPlaneVerification.Verified != 29 || controlPlaneVerification.Acknowledged != 1 || controlPlaneVerification.Blocked != 0 {
		t.Fatalf("acknowledged control-plane verification=%#v err=%v", controlPlaneVerification, err)
	}
	operationalVerification, err := VerifyDokployImport(ctx, destination, targetOrg, "source-org", true, acknowledgements)
	if err != nil || operationalVerification.Ready || operationalVerification.Blocked != 15 {
		t.Fatalf("pre-deployment operational verification=%#v err=%v", operationalVerification, err)
	}
	// Simulate databases imported by an older controller before compatible
	// image detection existed. The idempotent rerun must promote their drivers
	// in place without changing deterministic resource IDs.
	for _, downgrade := range []struct {
		id     uuid.UUID
		engine string
	}{
		{mappedID(options, "database:postgres", "timescale1"), "postgres"},
		{mappedID(options, "database:redis", "valkey1"), "redis"},
	} {
		if _, err = destination.Pool.Exec(ctx, `UPDATE database_instances SET engine=$2 WHERE id=$1`, downgrade.id, downgrade.engine); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = ImportDokploy(ctx, destination, box, deploy.Compiler{PublicNetwork: "dockyard-public"}, options); err != nil {
		t.Fatal(err)
	}
	var projects, services, routes, databases, applicationSources, backupDestinations, backupPolicies, volumeBackupPolicies, sourceCredentials, notifications, tags, projectTags, managedNetworks, serviceNetworks int
	var encryptedCredentials, encryptedEnvironment string
	var storedConfig []byte
	if err = destination.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM projects WHERE organization_id=$1),(SELECT count(*) FROM compose_services s JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE p.organization_id=$1),(SELECT count(*) FROM routes r JOIN compose_services s ON s.id=r.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE p.organization_id=$1),(SELECT count(*) FROM database_instances d JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE p.organization_id=$1),(SELECT count(*) FROM application_sources a JOIN compose_services s ON s.id=a.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE p.organization_id=$1),(SELECT count(*) FROM backup_destinations WHERE organization_id=$1),(SELECT count(*) FROM backup_policies b JOIN database_instances d ON d.id=b.database_instance_id JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE p.organization_id=$1),(SELECT count(*) FROM volume_backup_policies policy JOIN compose_services service ON service.id=policy.compose_service_id JOIN environments e ON e.id=service.environment_id JOIN projects p ON p.id=e.project_id WHERE p.organization_id=$1),(SELECT count(*) FROM source_credentials WHERE organization_id=$1),(SELECT count(*) FROM notification_endpoints WHERE organization_id=$1),(SELECT count(*) FROM tags WHERE organization_id=$1),(SELECT count(*) FROM project_tags pt JOIN projects p ON p.id=pt.project_id WHERE p.organization_id=$1),(SELECT count(*) FROM managed_networks WHERE organization_id=$1),(SELECT count(*) FROM compose_service_networks sn JOIN managed_networks n ON n.id=sn.network_id WHERE n.organization_id=$1)`, targetOrg).Scan(&projects, &services, &routes, &databases, &applicationSources, &backupDestinations, &backupPolicies, &volumeBackupPolicies, &sourceCredentials, &notifications, &tags, &projectTags, &managedNetworks, &serviceNetworks); err != nil {
		t.Fatal(err)
	}
	if projects != 1 || services != 11 || routes != 2 || databases != 9 || applicationSources != 1 || backupDestinations != 4 || backupPolicies != 2 || volumeBackupPolicies != 1 || sourceCredentials != 1 || notifications != 1 || tags != 1 || projectTags != 1 || managedNetworks != 1 || serviceNetworks != 4 {
		t.Fatalf("idempotent counts = %d/%d/%d/%d/%d/%d/%d/%d/%d/%d/%d/%d/%d/%d", projects, services, routes, databases, applicationSources, backupDestinations, backupPolicies, volumeBackupPolicies, sourceCredentials, notifications, tags, projectTags, managedNetworks, serviceNetworks)
	}
	var importedEnvironmentCluster, importedNetworkCluster uuid.UUID
	if err = destination.Pool.QueryRow(ctx, `SELECT e.cluster_id,n.cluster_id FROM environments e CROSS JOIN managed_networks n WHERE e.id=$1 AND n.id=$2`, mappedID(options, "environment", "e1"), mappedID(options, "network", "network1")).Scan(&importedEnvironmentCluster, &importedNetworkCluster); err != nil || importedEnvironmentCluster != targetCluster || importedNetworkCluster != targetCluster {
		t.Fatalf("remote placement environment=%s network=%s want=%s err=%v", importedEnvironmentCluster, importedNetworkCluster, targetCluster, err)
	}
	var importedInternalPath string
	var importedStripPath, importedRouteEnabled bool
	if err = destination.Pool.QueryRow(ctx, `SELECT internal_path,strip_path,enabled FROM routes WHERE id=$1`, mappedID(options, "route", "d1")).Scan(&importedInternalPath, &importedStripPath, &importedRouteEnabled); err != nil || importedInternalPath != "/internal" || !importedStripPath || importedRouteEnabled {
		t.Fatalf("imported route controls internalPath=%q stripPath=%v enabled=%v err=%v", importedInternalPath, importedStripPath, importedRouteEnabled, err)
	}
	rows, err := destination.Pool.Query(ctx, `SELECT engine FROM database_instances d JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE p.organization_id=$1 ORDER BY engine`, targetOrg)
	if err != nil {
		t.Fatal(err)
	}
	var importedEngines []string
	for rows.Next() {
		var engine string
		if err = rows.Scan(&engine); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		importedEngines = append(importedEngines, engine)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	rows.Close()
	if expected := []string{"libsql", "mariadb", "mongo", "mysql", "postgres", "postgres", "redis", "timescaledb", "valkey"}; !reflect.DeepEqual(importedEngines, expected) {
		t.Fatalf("imported database engines = %v, want %v", importedEngines, expected)
	}
	var encryptedNotificationURL string
	notificationID := mappedID(options, "notification", "notification1")
	if err = destination.Pool.QueryRow(ctx, `SELECT encrypted_url FROM notification_endpoints WHERE id=$1 AND organization_id=$2`, notificationID, targetOrg).Scan(&encryptedNotificationURL); err != nil {
		t.Fatal(err)
	}
	notificationURL, err := box.Decrypt(encryptedNotificationURL, "notification-url:"+notificationID.String())
	if err != nil || string(notificationURL) != "https://hooks.slack.example.test/services/secret-token" {
		t.Fatalf("notification URL mismatch: %q, err=%v", notificationURL, err)
	}
	if err = destination.Pool.QueryRow(ctx, `SELECT d.encrypted_credentials,s.encrypted_env,d.config FROM database_instances d JOIN compose_services s ON s.id=d.compose_service_id JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE p.organization_id=$1 AND d.id=$2`, targetOrg, mappedID(options, "database:postgres", "pg1")).Scan(&encryptedCredentials, &encryptedEnvironment, &storedConfig); err != nil {
		t.Fatal(err)
	}
	credentialsJSON, err := box.Decrypt(encryptedCredentials, cryptox.ResourceContext("database-credentials", mappedID(options, "database:postgres", "pg1").String()))
	if err != nil || !bytes.Contains(credentialsJSON, []byte("legacy-secret")) {
		t.Fatalf("migrated credentials cannot be decrypted: %s, err = %v", credentialsJSON, err)
	}
	environmentJSON, err := box.Decrypt(encryptedEnvironment, cryptox.ResourceContext("compose-env", mappedID(options, "database-service:postgres", "pg1").String()))
	if err != nil || !bytes.Contains(environmentJSON, []byte(`"EXTRA":"value"`)) || !bytes.Contains(environmentJSON, []byte(`"POSTGRES_PASSWORD":"legacy-secret"`)) {
		t.Fatalf("migrated environment cannot be decrypted: %s, err = %v", environmentJSON, err)
	}
	if bytes.Contains(storedConfig, []byte("legacy-secret")) {
		t.Fatalf("database config contains a plaintext password: %s", storedConfig)
	}
	composeDatabaseID := mappedID(options, "compose-database", "backup-compose")
	var composeManagementKind, composeConnectionService, composeEncryptedCredentials string
	if err = destination.Pool.QueryRow(ctx, `SELECT management_kind,connection_service_name,encrypted_credentials FROM database_instances WHERE id=$1`, composeDatabaseID).Scan(&composeManagementKind, &composeConnectionService, &composeEncryptedCredentials); err != nil {
		t.Fatal(err)
	}
	composeCredentialsJSON, err := box.Decrypt(composeEncryptedCredentials, cryptox.ResourceContext("database-credentials", composeDatabaseID.String()))
	if err != nil || composeManagementKind != "compose" || composeConnectionService != "db" || !bytes.Contains(composeCredentialsJSON, []byte(`"password":"compose-secret"`)) {
		t.Fatalf("Compose database target mismatch: kind=%q service=%q credentials=%s err=%v", composeManagementKind, composeConnectionService, composeCredentialsJSON, err)
	}
	var destinationSecret, destinationPrefix string
	var policyInterval, policyRetention int
	if err = destination.Pool.QueryRow(ctx, `SELECT d.encrypted_credentials,d.prefix,p.interval_seconds,p.retention_count FROM backup_policies p JOIN backup_destinations d ON d.id=p.destination_id WHERE p.database_instance_id=$1`, mappedID(options, "database:postgres", "pg1")).Scan(&destinationSecret, &destinationPrefix, &policyInterval, &policyRetention); err != nil {
		t.Fatal(err)
	}
	destinationJSON, err := box.Decrypt(destinationSecret, cryptox.ResourceContext("backup-destination", mappedID(options, "backup-destination", "dst1\x00nightly").String()))
	if err != nil || !bytes.Contains(destinationJSON, []byte(`"accessKey":"legacy-access"`)) || destinationPrefix != "nightly" || policyInterval != 86400 || policyRetention != 7 {
		t.Fatalf("backup migration mismatch: credentials=%s prefix=%q interval=%d retention=%d err=%v", destinationJSON, destinationPrefix, policyInterval, policyRetention, err)
	}
	var volumeName, volumeDestinationPrefix string
	var volumeInterval, volumeRetention int
	var volumeQuiesce, volumeEnabled bool
	if err = destination.Pool.QueryRow(ctx, `SELECT policy.volume_name,destination.prefix,policy.interval_seconds,policy.retention_count,policy.quiesce,policy.enabled FROM volume_backup_policies policy JOIN backup_destinations destination ON destination.id=policy.destination_id WHERE policy.id=$1`, mappedID(options, "volume-backup-policy", "volume1")).Scan(&volumeName, &volumeDestinationPrefix, &volumeInterval, &volumeRetention, &volumeQuiesce, &volumeEnabled); err != nil {
		t.Fatal(err)
	}
	if volumeName != "uploads" || volumeDestinationPrefix != "volumes" || volumeInterval != 86400 || volumeRetention != 5 || !volumeQuiesce || !volumeEnabled {
		t.Fatalf("volume backup migration mismatch: volume=%q prefix=%q interval=%d retention=%d quiesce=%v enabled=%v", volumeName, volumeDestinationPrefix, volumeInterval, volumeRetention, volumeQuiesce, volumeEnabled)
	}
	var applicationCompose, applicationEnvironment string
	if err = destination.Pool.QueryRow(ctx, `SELECT s.compose_yaml,s.encrypted_env FROM compose_services s WHERE s.id=$1`, mappedID(options, "application-service", "a1")).Scan(&applicationCompose, &applicationEnvironment); err != nil {
		t.Fatal(err)
	}
	applicationEnvJSON, err := box.Decrypt(applicationEnvironment, cryptox.ResourceContext("compose-env", mappedID(options, "application-service", "a1").String()))
	if err != nil || !bytes.Contains(applicationEnvJSON, []byte(`"WORKERS":"2"`)) || !bytes.Contains([]byte(applicationCompose), []byte("ghcr.io/example/worker:1.2")) {
		t.Fatalf("application was not converted correctly: compose=%s env=%s err=%v", applicationCompose, applicationEnvJSON, err)
	}
	var repositoryURL, registryImage, registryCredentialSecret, buildTarget, encryptedBuildConfig string
	var enableSubmodules bool
	var gitCredentialID *uuid.UUID
	if err = destination.Pool.QueryRow(ctx, `SELECT a.repository_url,a.registry_image,a.git_credential_id,c.encrypted_secret,a.build_target,a.enable_submodules,a.encrypted_build_config FROM application_sources a JOIN source_credentials c ON c.id=a.registry_credential_id WHERE a.compose_service_id=$1`, mappedID(options, "application-service", "a2")).Scan(&repositoryURL, &registryImage, &gitCredentialID, &registryCredentialSecret, &buildTarget, &enableSubmodules, &encryptedBuildConfig); err != nil {
		t.Fatal(err)
	}
	registrySecret, err := box.Decrypt(registryCredentialSecret, cryptox.ResourceContext("source-credential", mappedID(options, "source-credential:registry", "reg1").String()))
	if repositoryURL != "https://github.com/example/api.git" || !strings.HasPrefix(registryImage, "registry.example.test/imports/") || gitCredentialID != nil || string(registrySecret) != "registry-secret" || buildTarget != "runtime" || !enableSubmodules || err != nil {
		t.Fatalf("Git source was not converted: repository=%q registry=%q", repositoryURL, registryImage)
	}
	buildConfigJSON, err := box.Decrypt(encryptedBuildConfig, "application-build-config:"+mappedID(options, "application-service", "a2").String())
	if err != nil || !bytes.Contains(buildConfigJSON, []byte(`"GO_VERSION":"1.26"`)) || !bytes.Contains(buildConfigJSON, []byte(`"NPM_TOKEN":"legacy-build-secret"`)) {
		t.Fatalf("application build settings were not re-encrypted: %s err=%v", buildConfigJSON, err)
	}
	var migrationRecords, applicationMigrationRecords int
	if err = destination.Pool.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE source_kind='application') FROM dokploy_migration_resources WHERE target_organization_id=$1 AND source_organization_id='source-org'`, targetOrg).Scan(&migrationRecords, &applicationMigrationRecords); err != nil || migrationRecords != 30 || applicationMigrationRecords != 2 {
		t.Fatalf("migration metadata records=%d application records=%d err=%v", migrationRecords, applicationMigrationRecords, err)
	}

	transferManifest := DokployDatabaseTransferManifest{Version: 1, Connections: []DokployDatabaseSourceConnection{
		{SourceID: "pg1", Host: "legacy-postgres.internal", Port: 15432, Username: "transfer-user", Password: "transfer-secret", Database: "legacydb"},
		{SourceID: "timescale1", Host: "legacy-timescale.internal", Port: 15433, Username: "transfer-user", Password: "transfer-secret", Database: "metrics"},
		{SourceID: "mysql1", Host: "legacy-mysql.internal", Port: 13306, Username: "transfer-user", Password: "transfer-secret", Database: "legacydb"},
		{SourceID: "maria1", Host: "legacy-mariadb.internal", Port: 13307, Username: "transfer-user", Password: "transfer-secret", Database: "legacydb"},
		{SourceID: "mongo1", Host: "legacy-mongo.internal", Port: 17017, Username: "transfer-user", Password: "transfer-secret", Database: "admin"},
		{SourceID: "redis1", Host: "legacy-redis.internal", Port: 16379, Password: "transfer-secret"},
		{SourceID: "valkey1", Host: "legacy-valkey.internal", Port: 16380, Password: "transfer-secret"},
		{SourceID: "libsql1", Host: "legacy-libsql.internal", Port: 18080, Username: "transfer-user", Password: "transfer-secret", Database: "app"},
	}}
	transferOptions := options
	transferOptions.DryRun = true
	transferReport, err := QueueDokployDatabaseTransfers(ctx, destination, box, transferOptions, transferManifest)
	if err != nil || transferReport.Planned != 8 || transferReport.Queued != 0 || len(transferReport.Items) != 8 {
		t.Fatalf("database transfer dry run=%#v err=%v", transferReport, err)
	}
	engines := []string{"postgres", "timescaledb", "mysql", "mariadb", "mongo", "redis", "valkey", "libsql"}
	sourceEngines := []string{"postgres", "postgres", "mysql", "mariadb", "mongo", "redis", "redis", "libsql"}
	for index, engine := range engines {
		if transferReport.Items[index].DatabaseInstanceID != mappedID(options, "database:"+sourceEngines[index], transferManifest.Connections[index].SourceID) || transferReport.Items[index].SourceEngine != engine {
			t.Fatalf("database transfer %d = %#v", index, transferReport.Items[index])
		}
	}
	encodedTransferReport, _ := json.Marshal(transferReport)
	if bytes.Contains(encodedTransferReport, []byte("transfer-secret")) || bytes.Contains(encodedTransferReport, []byte("transfer-user")) {
		t.Fatalf("database transfer report leaked connection credentials: %s", encodedTransferReport)
	}
	transferOptions.DryRun = false
	transferReport, err = QueueDokployDatabaseTransfers(ctx, destination, box, transferOptions, transferManifest)
	if err != nil || transferReport.Queued != 8 || len(transferReport.Items) != 8 {
		t.Fatalf("database transfer queue=%#v err=%v", transferReport, err)
	}
	var encryptedSource string
	if err = destination.Pool.QueryRow(ctx, `SELECT encrypted_source_config FROM database_migrations WHERE id=$1`, transferReport.Items[0].ID).Scan(&encryptedSource); err != nil {
		t.Fatal(err)
	}
	sourceJSON, err := box.Decrypt(encryptedSource, "database-migration-source:"+transferReport.Items[0].ID.String())
	if err != nil || !bytes.Contains(sourceJSON, []byte(`"password":"transfer-secret"`)) || !bytes.Contains(sourceJSON, []byte(`"port":15432`)) {
		t.Fatalf("database transfer source was not resource-bound and encrypted: %s err=%v", sourceJSON, err)
	}
	if _, err = destination.Pool.Exec(ctx, `UPDATE database_instances SET status='running' WHERE environment_id=$1`, mappedID(options, "environment", "e1")); err != nil {
		t.Fatal(err)
	}
	for _, item := range transferReport.Items {
		if _, err = destination.Pool.Exec(ctx, `UPDATE database_migrations SET status='succeeded',finished_at=now() WHERE id=$1`, item.ID); err != nil {
			t.Fatal(err)
		}
	}
	serviceIDs := []uuid.UUID{mappedID(options, "compose", "c1"), mappedID(options, "application-service", "a1"), mappedID(options, "application-service", "a2")}
	for _, item := range transferManifest.Connections {
		engine := ""
		for _, transfer := range transferReport.Items {
			if transfer.SourceID == item.SourceID {
				engine = transfer.SourceEngine
				break
			}
		}
		sourceEngine := engine
		if engine == "timescaledb" {
			sourceEngine = "postgres"
		} else if engine == "valkey" {
			sourceEngine = "redis"
		}
		serviceIDs = append(serviceIDs, mappedID(options, "database-service:"+sourceEngine, item.SourceID))
	}
	for _, serviceID := range serviceIDs {
		if _, err = destination.Pool.Exec(ctx, `INSERT INTO deployments(id,compose_service_id,revision,compose_snapshot,status,trigger,finished_at) SELECT $1,s.id,s.revision,s.compose_yaml,'succeeded','migration-verification',now() FROM compose_services s WHERE s.id=$2`, uuid.New(), serviceID); err != nil {
			t.Fatal(err)
		}
	}
	operationalVerification, err = VerifyDokployImport(ctx, destination, targetOrg, "source-org", true, acknowledgements)
	if err != nil || operationalVerification.Ready || operationalVerification.Blocked != 14 {
		t.Fatalf("operational verification without live observations=%#v err=%v", operationalVerification, err)
	}
	for _, serviceID := range serviceIDs {
		if _, err = destination.Pool.Exec(ctx, `INSERT INTO service_reconciliations(compose_service_id,state,consecutive_failures,detail,last_checked_at) VALUES($1,'healthy',0,'',now())`, serviceID); err != nil {
			t.Fatal(err)
		}
	}
	operationalVerification, err = VerifyDokployImport(ctx, destination, targetOrg, "source-org", true, acknowledgements)
	if err != nil || operationalVerification.Ready || operationalVerification.Blocked != 3 || !verificationReasonContains(operationalVerification, "volume_backup", "volume1", "storage-node binding") || !verificationReasonContains(operationalVerification, "backup_policy", "backup1", "successful encrypted backup") || !verificationReasonContains(operationalVerification, "backup_policy", "backup-compose", "successful encrypted backup") {
		t.Fatalf("volume backup binding verification=%#v err=%v", operationalVerification, err)
	}
	composeServiceID := mappedID(options, "compose", "c1")
	volumePolicyID := mappedID(options, "volume-backup-policy", "volume1")
	if _, err = destination.Pool.Exec(ctx, `UPDATE compose_services SET storage_node_id='nodeabc123' WHERE id=$1`, composeServiceID); err != nil {
		t.Fatal(err)
	}
	if _, err = destination.Pool.Exec(ctx, `INSERT INTO volume_backups(id,volume_backup_policy_id,compose_service_id,volume_name,storage_node_id,destination_id,quiesce,status,started_at,finished_at)
		SELECT $1,policy.id,policy.compose_service_id,policy.volume_name,'nodeabc123',policy.destination_id,policy.quiesce,'succeeded',now(),now()
		FROM volume_backup_policies policy WHERE policy.id=$2`, uuid.New(), volumePolicyID); err != nil {
		t.Fatal(err)
	}
	operationalVerification, err = VerifyDokployImport(ctx, destination, targetOrg, "source-org", true, acknowledgements)
	if err != nil || operationalVerification.Ready || operationalVerification.Blocked != 3 || !verificationReasonContains(operationalVerification, "volume_backup", "volume1", "successful encrypted backup") || !verificationReasonContains(operationalVerification, "backup_policy", "backup1", "successful encrypted backup") || !verificationReasonContains(operationalVerification, "backup_policy", "backup-compose", "successful encrypted backup") {
		t.Fatalf("volume backup evidence verification=%#v err=%v", operationalVerification, err)
	}
	if _, err = destination.Pool.Exec(ctx, `INSERT INTO volume_backups(id,volume_backup_policy_id,compose_service_id,volume_name,storage_node_id,destination_id,quiesce,status,object_key,size_bytes,sha256,plaintext_sha256,encrypted_data_key,started_at,finished_at)
		SELECT $1,policy.id,policy.compose_service_id,policy.volume_name,'nodeabc123',policy.destination_id,policy.quiesce,'succeeded','migration/volume.enc',42,$2,$3,'encrypted-data-key',now(),now()
		FROM volume_backup_policies policy WHERE policy.id=$4`, uuid.New(), strings.Repeat("a", 64), strings.Repeat("b", 64), volumePolicyID); err != nil {
		t.Fatal(err)
	}
	operationalVerification, err = VerifyDokployImport(ctx, destination, targetOrg, "source-org", true, acknowledgements)
	if err != nil || operationalVerification.Ready || operationalVerification.Blocked != 2 || !verificationReasonContains(operationalVerification, "backup_policy", "backup1", "successful encrypted backup") || !verificationReasonContains(operationalVerification, "backup_policy", "backup-compose", "successful encrypted backup") {
		t.Fatalf("database backup evidence verification=%#v err=%v", operationalVerification, err)
	}
	backupPolicyID := mappedID(options, "backup-policy", "backup1")
	if _, err = destination.Pool.Exec(ctx, `INSERT INTO database_backups(id,database_instance_id,status,format,destination_id,started_at,finished_at)
		SELECT $1,policy.database_instance_id,'succeeded','native',policy.destination_id,now(),now()
		FROM backup_policies policy WHERE policy.id=$2`, uuid.New(), backupPolicyID); err != nil {
		t.Fatal(err)
	}
	operationalVerification, err = VerifyDokployImport(ctx, destination, targetOrg, "source-org", true, acknowledgements)
	if err != nil || operationalVerification.Ready || operationalVerification.Blocked != 2 || !verificationReasonContains(operationalVerification, "backup_policy", "backup1", "successful encrypted backup") || !verificationReasonContains(operationalVerification, "backup_policy", "backup-compose", "successful encrypted backup") {
		t.Fatalf("unencrypted database backup verification=%#v err=%v", operationalVerification, err)
	}
	if _, err = destination.Pool.Exec(ctx, `INSERT INTO database_backups(id,database_instance_id,status,format,destination_id,object_key,size_bytes,sha256,encrypted,plaintext_sha256,encrypted_data_key,started_at,finished_at)
		SELECT $1,policy.database_instance_id,'succeeded','native',policy.destination_id,'migration/database.enc',42,$2,true,$3,'encrypted-data-key',now(),now()
		FROM backup_policies policy WHERE policy.id=$4`, uuid.New(), strings.Repeat("c", 64), strings.Repeat("d", 64), backupPolicyID); err != nil {
		t.Fatal(err)
	}
	operationalVerification, err = VerifyDokployImport(ctx, destination, targetOrg, "source-org", true, acknowledgements)
	if err != nil || operationalVerification.Ready || operationalVerification.Blocked != 1 || !verificationReasonContains(operationalVerification, "backup_policy", "backup-compose", "successful encrypted backup") {
		t.Fatalf("Compose database backup evidence verification=%#v err=%v", operationalVerification, err)
	}
	composeBackupPolicyID := mappedID(options, "backup-policy", "backup-compose")
	if _, err = destination.Pool.Exec(ctx, `INSERT INTO database_backups(id,database_instance_id,status,format,destination_id,object_key,size_bytes,sha256,encrypted,plaintext_sha256,encrypted_data_key,started_at,finished_at)
		SELECT $1,policy.database_instance_id,'succeeded','native',policy.destination_id,'migration/compose-database.enc',42,$2,true,$3,'encrypted-data-key',now(),now()
		FROM backup_policies policy WHERE policy.id=$4`, uuid.New(), strings.Repeat("e", 64), strings.Repeat("f", 64), composeBackupPolicyID); err != nil {
		t.Fatal(err)
	}
	operationalVerification, err = VerifyDokployImport(ctx, destination, targetOrg, "source-org", true, acknowledgements)
	if err != nil || !operationalVerification.Ready || operationalVerification.Verified != 29 || operationalVerification.Acknowledged != 1 || operationalVerification.Blocked != 0 {
		t.Fatalf("operational verification=%#v err=%v", operationalVerification, err)
	}
	if _, err = destination.Pool.Exec(ctx, `UPDATE service_reconciliations SET state='degraded',last_checked_at=now() WHERE compose_service_id=$1`, composeServiceID); err != nil {
		t.Fatal(err)
	}
	degradedVerification, err := VerifyDokployImport(ctx, destination, targetOrg, "source-org", true, acknowledgements)
	if err != nil || degradedVerification.Ready || degradedVerification.Blocked != 1 || !verificationReasonContains(degradedVerification, "compose", "c1", "degraded") {
		t.Fatalf("degraded runtime verification=%#v err=%v", degradedVerification, err)
	}
	if _, err = destination.Pool.Exec(ctx, `UPDATE service_reconciliations SET state='healthy',last_checked_at=now()-interval '6 minutes' WHERE compose_service_id=$1`, composeServiceID); err != nil {
		t.Fatal(err)
	}
	staleVerification, err := VerifyDokployImport(ctx, destination, targetOrg, "source-org", true, acknowledgements)
	if err != nil || staleVerification.Ready || staleVerification.Blocked != 1 || !verificationReasonContains(staleVerification, "compose", "c1", "stale") {
		t.Fatalf("stale runtime verification=%#v err=%v", staleVerification, err)
	}
	unknownManifest := transferManifest
	unknownManifest.Connections = []DokployDatabaseSourceConnection{{SourceID: "not-owned", Host: "db.internal", Username: "u", Password: "p", Database: "d"}}
	if _, err = QueueDokployDatabaseTransfers(ctx, destination, box, transferOptions, unknownManifest); err == nil || !strings.Contains(err.Error(), "does not belong") {
		t.Fatalf("unknown source ownership error=%v", err)
	}
	if os.Getenv("DOCKYARD_MIGRATION_CONFORMANCE") == "1" {
		evidence, _ := json.Marshal(map[string]any{
			"status": "passed", "postgresBacked": true, "dryRunSecretSafe": true,
			"controlPlaneImported": true, "idempotentImport": true,
			"composeImported": true, "applicationsImported": true,
			"routesImported": true, "databasesImported": 9,
			"composeDatabaseBackupImported": true,
			"backupConfigurationImported":   true, "sourceCredentialsReencrypted": true,
			"notificationsReencrypted": true, "databaseTransfersQueued": 8,
			"transferSecretsEncrypted": true, "tenantOwnershipEnforced": true,
			"manualAcknowledgementsExplicit": true, "operationalVerifierFailClosed": true,
			"databaseBackupCutoverVerified": true, "volumeBackupCutoverVerified": true,
		})
		fmt.Printf("MIGRATION_EVIDENCE %s\n", evidence)
	}
}

func verificationReasonContains(report DokployVerification, kind, sourceID, fragment string) bool {
	for _, check := range report.Checks {
		if check.SourceKind == kind && check.SourceID == sourceID {
			return strings.Contains(check.Reason, fragment)
		}
	}
	return false
}

func encryptDokployFixture(t *testing.T, key []byte, value string) string {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{7}, aead.NonceSize())
	sealed := aead.Seal(nil, nonce, []byte(value), nil)
	tagStart := len(sealed) - aead.Overhead()
	payload := append(append(append([]byte{}, nonce...), sealed[tagStart:]...), sealed[:tagStart]...)
	return "enc:v1:" + base64.StdEncoding.EncodeToString(payload)
}
