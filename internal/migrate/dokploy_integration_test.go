package migrate

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
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
		`CREATE TABLE ` + quotedSchema + `.environment ("environmentId" text PRIMARY KEY,"projectId" text NOT NULL,name text NOT NULL)`,
		`CREATE TABLE ` + quotedSchema + `.git_provider ("gitProviderId" text PRIMARY KEY,name text NOT NULL,"providerType" text NOT NULL,"organizationId" text NOT NULL)`,
		`CREATE TABLE ` + quotedSchema + `.github ("githubId" text PRIMARY KEY,"githubUrl" text NOT NULL,"gitProviderId" text NOT NULL)`,
		`CREATE TABLE ` + quotedSchema + `.gitlab ("gitlabId" text PRIMARY KEY,"gitlabUrl" text NOT NULL,"gitlabInternalUrl" text,"access_token" text,"gitProviderId" text NOT NULL)`,
		`CREATE TABLE ` + quotedSchema + `.gitea ("giteaId" text PRIMARY KEY,"giteaUrl" text NOT NULL,"giteaInternalUrl" text,"access_token" text,"gitProviderId" text NOT NULL)`,
		`CREATE TABLE ` + quotedSchema + `.bitbucket ("bitbucketId" text PRIMARY KEY,"bitbucketUsername" text,"bitbucketEmail" text,"appPassword" text,"apiToken" text,"gitProviderId" text NOT NULL)`,
		`CREATE TABLE ` + quotedSchema + `.registry ("registryId" text PRIMARY KEY,"registryName" text NOT NULL,"registryUrl" text,username text NOT NULL,password text NOT NULL,"organizationId" text NOT NULL)`,
		`CREATE TABLE ` + quotedSchema + `.compose ("composeId" text PRIMARY KEY,"environmentId" text NOT NULL,name text NOT NULL,"appName" text NOT NULL,"composeFile" text NOT NULL,env text)`,
		`CREATE TABLE ` + quotedSchema + `.domain ("domainId" text PRIMARY KEY,"composeId" text,"applicationId" text,host text,path text,"serviceName" text,port integer,https boolean,enabled boolean,"customCertResolver" text)`,
		`CREATE TABLE ` + quotedSchema + `.application ("applicationId" text PRIMARY KEY,"environmentId" text,name text,"appName" text,env text,"sourceType" text,"buildType" text,"dockerImage" text,username text,password text,command text,args text[],replicas integer,repository text,owner text,branch text,"buildPath" text,dockerfile text,"dockerBuildStage" text,"buildArgs" text,"buildSecrets" text,"enableSubmodules" boolean,"githubId" text,"gitlabId" text,"giteaId" text,"bitbucketId" text,"registryId" text,"buildRegistryId" text)`,
		`CREATE TABLE ` + quotedSchema + `.destination ("destinationId" text PRIMARY KEY,name text NOT NULL,provider text,"accessKey" text NOT NULL,"secretAccessKey" text NOT NULL,bucket text NOT NULL,region text NOT NULL,endpoint text NOT NULL,"additionalFlags" text[],"organizationId" text NOT NULL)`,
		`CREATE TABLE ` + quotedSchema + `.backup ("backupId" text PRIMARY KEY,schedule text NOT NULL,enabled boolean,database text NOT NULL,prefix text NOT NULL,"destinationId" text NOT NULL,"keepLatestCount" integer,"backupType" text NOT NULL,"databaseType" text NOT NULL,"composeId" text,"postgresId" text,"mariadbId" text,"mysqlId" text,"mongoId" text,"libsqlId" text)`,
		`CREATE TABLE ` + quotedSchema + `.slack ("slackId" text PRIMARY KEY,"webhookUrl" text NOT NULL,channel text)`,
		`CREATE TABLE ` + quotedSchema + `.email ("emailId" text PRIMARY KEY,"smtpServer" text NOT NULL,"smtpPort" integer NOT NULL,username text NOT NULL,password text NOT NULL,"fromAddress" text NOT NULL,"toAddress" text[] NOT NULL)`,
		`CREATE TABLE ` + quotedSchema + `.notification ("notificationId" text PRIMARY KEY,name text NOT NULL,"appDeploy" boolean NOT NULL DEFAULT false,"appBuildError" boolean NOT NULL DEFAULT false,"databaseBackup" boolean NOT NULL DEFAULT false,"volumeBackup" boolean NOT NULL DEFAULT false,"dokployRestart" boolean NOT NULL DEFAULT false,"dokployBackup" boolean NOT NULL DEFAULT false,"dockerCleanup" boolean NOT NULL DEFAULT false,"serverThreshold" boolean NOT NULL DEFAULT false,"notificationType" text NOT NULL,"slackId" text,"emailId" text,"organizationId" text NOT NULL)`,
	}
	statements = append(statements,
		`CREATE TABLE `+quotedSchema+`.postgres ("postgresId" text PRIMARY KEY,"environmentId" text,name text,"appName" text,"databaseName" text,"databaseUser" text,"databasePassword" text,"dockerImage" text,env text)`,
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
','A=one'); INSERT INTO `+quotedSchema+`.git_provider VALUES('gp1','GitHub App','github','source-org'); INSERT INTO `+quotedSchema+`.github VALUES('gh1','https://github.com','gp1'); INSERT INTO `+quotedSchema+`.application ("applicationId","environmentId",name,"appName",env,"sourceType","buildType","dockerImage",args,replicas) VALUES('a1','e1','Worker','legacy-worker','WORKERS=2','docker','dockerfile','ghcr.io/example/worker:1.2','{}',2); INSERT INTO `+quotedSchema+`.application ("applicationId","environmentId",name,"appName",env,"sourceType","buildType",args,replicas,repository,owner,branch,"buildPath",dockerfile,"dockerBuildStage","buildArgs","buildSecrets","enableSubmodules","githubId","buildRegistryId") VALUES('a2','e1','Git API','legacy-api','PORT=3000','github','dockerfile','{}',1,'api','example','main','/','Dockerfile','runtime','GO_VERSION=1.26','',true,'gh1','reg1'); INSERT INTO `+quotedSchema+`.domain VALUES('d1','c1',NULL,'`+fixtureHost+`','/','web',80,true,true,'letsencrypt'),('d2',NULL,'a1','app-`+fixtureHost+`','/',NULL,8080,true,true,'letsencrypt')`)
	if err == nil {
		_, err = destination.Pool.Exec(ctx, `INSERT INTO `+quotedSchema+`.postgres VALUES('pg1','e1','Imported DB','legacy-postgres','legacydb','legacyuser','legacy-secret','postgres:16','EXTRA=value')`)
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
		_, err = destination.Pool.Exec(ctx, `INSERT INTO `+quotedSchema+`.backup VALUES('backup1','0 2 * * *',true,'legacydb','nightly','dst1',7,'database','postgres',NULL,'pg1',NULL,NULL,NULL,NULL)`)
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
	options := DokployOptions{SourceURL: parsed.String(), SourceOrganizationID: "source-org", TargetOrganizationID: targetOrg, RegistryPrefix: "registry.example.test/imports", DryRun: true, EncryptionKeys: [][]byte{sourceKey}}
	report, err := ImportDokploy(ctx, destination, box, deploy.Compiler{PublicNetwork: "dockyard-public"}, options)
	if err != nil || report.Projects != 1 || report.Environments != 1 || report.Services != 1 || report.Routes != 2 || report.Databases != 1 || report.Applications != 2 || report.BackupDestinations != 1 || report.BackupPolicies != 1 || report.SourceCredentials != 2 || report.NotificationEndpoints != 1 {
		t.Fatalf("dry-run report = %#v, err = %v", report, err)
	}
	if len(report.Resources) != 7 || report.Resources[0].SourceKind != "application" || report.Resources[2].SourceKind != "backup_destination" || report.Resources[3].SourceKind != "backup_policy" || report.Resources[4].SourceKind != "source_credential" || report.Resources[6].SourceKind != "notification" {
		t.Fatalf("migration parity resources = %#v", report.Resources)
	}
	encodedReport, _ := json.Marshal(report)
	if bytes.Contains(encodedReport, []byte("legacy-secret")) || bytes.Contains(encodedReport, []byte("registry-secret")) || bytes.Contains(encodedReport, []byte("secret-token")) {
		t.Fatal("dry-run report leaked source credentials")
	}
	options.DryRun = false
	if _, err = ImportDokploy(ctx, destination, box, deploy.Compiler{PublicNetwork: "dockyard-public"}, options); err != nil {
		t.Fatal(err)
	}
	if _, err = ImportDokploy(ctx, destination, box, deploy.Compiler{PublicNetwork: "dockyard-public"}, options); err != nil {
		t.Fatal(err)
	}
	var projects, services, routes, databases, applicationSources, backupDestinations, backupPolicies, sourceCredentials, notifications int
	var encryptedCredentials, encryptedEnvironment string
	var storedConfig []byte
	if err = destination.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM projects WHERE organization_id=$1),(SELECT count(*) FROM compose_services s JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE p.organization_id=$1),(SELECT count(*) FROM routes r JOIN compose_services s ON s.id=r.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE p.organization_id=$1),(SELECT count(*) FROM database_instances d JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE p.organization_id=$1),(SELECT count(*) FROM application_sources a JOIN compose_services s ON s.id=a.compose_service_id JOIN environments e ON e.id=s.environment_id JOIN projects p ON p.id=e.project_id WHERE p.organization_id=$1),(SELECT count(*) FROM backup_destinations WHERE organization_id=$1),(SELECT count(*) FROM backup_policies b JOIN database_instances d ON d.id=b.database_instance_id JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE p.organization_id=$1),(SELECT count(*) FROM source_credentials WHERE organization_id=$1),(SELECT count(*) FROM notification_endpoints WHERE organization_id=$1)`, targetOrg).Scan(&projects, &services, &routes, &databases, &applicationSources, &backupDestinations, &backupPolicies, &sourceCredentials, &notifications); err != nil {
		t.Fatal(err)
	}
	if projects != 1 || services != 4 || routes != 2 || databases != 1 || applicationSources != 1 || backupDestinations != 2 || backupPolicies != 1 || sourceCredentials != 1 || notifications != 1 {
		t.Fatalf("idempotent counts = %d/%d/%d/%d/%d/%d/%d/%d/%d", projects, services, routes, databases, applicationSources, backupDestinations, backupPolicies, sourceCredentials, notifications)
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
	if err = destination.Pool.QueryRow(ctx, `SELECT d.encrypted_credentials,s.encrypted_env,d.config FROM database_instances d JOIN compose_services s ON s.id=d.compose_service_id JOIN environments e ON e.id=d.environment_id JOIN projects p ON p.id=e.project_id WHERE p.organization_id=$1`, targetOrg).Scan(&encryptedCredentials, &encryptedEnvironment, &storedConfig); err != nil {
		t.Fatal(err)
	}
	credentialsJSON, err := box.Decrypt(encryptedCredentials, "database-credentials")
	if err != nil || !bytes.Contains(credentialsJSON, []byte("legacy-secret")) {
		t.Fatalf("migrated credentials cannot be decrypted: %s, err = %v", credentialsJSON, err)
	}
	environmentJSON, err := box.Decrypt(encryptedEnvironment, "compose-env")
	if err != nil || !bytes.Contains(environmentJSON, []byte(`"EXTRA":"value"`)) || !bytes.Contains(environmentJSON, []byte(`"POSTGRES_PASSWORD":"legacy-secret"`)) {
		t.Fatalf("migrated environment cannot be decrypted: %s, err = %v", environmentJSON, err)
	}
	if bytes.Contains(storedConfig, []byte("legacy-secret")) {
		t.Fatalf("database config contains a plaintext password: %s", storedConfig)
	}
	var destinationSecret, destinationPrefix string
	var policyInterval, policyRetention int
	if err = destination.Pool.QueryRow(ctx, `SELECT d.encrypted_credentials,d.prefix,p.interval_seconds,p.retention_count FROM backup_policies p JOIN backup_destinations d ON d.id=p.destination_id WHERE p.database_instance_id=$1`, mappedID(options, "database:postgres", "pg1")).Scan(&destinationSecret, &destinationPrefix, &policyInterval, &policyRetention); err != nil {
		t.Fatal(err)
	}
	destinationJSON, err := box.Decrypt(destinationSecret, "backup-destination")
	if err != nil || !bytes.Contains(destinationJSON, []byte(`"accessKey":"legacy-access"`)) || destinationPrefix != "nightly" || policyInterval != 86400 || policyRetention != 7 {
		t.Fatalf("backup migration mismatch: credentials=%s prefix=%q interval=%d retention=%d err=%v", destinationJSON, destinationPrefix, policyInterval, policyRetention, err)
	}
	var applicationCompose, applicationEnvironment string
	if err = destination.Pool.QueryRow(ctx, `SELECT s.compose_yaml,s.encrypted_env FROM compose_services s WHERE s.id=$1`, mappedID(options, "application-service", "a1")).Scan(&applicationCompose, &applicationEnvironment); err != nil {
		t.Fatal(err)
	}
	applicationEnvJSON, err := box.Decrypt(applicationEnvironment, "compose-env")
	if err != nil || !bytes.Contains(applicationEnvJSON, []byte(`"WORKERS":"2"`)) || !bytes.Contains([]byte(applicationCompose), []byte("ghcr.io/example/worker:1.2")) {
		t.Fatalf("application was not converted correctly: compose=%s env=%s err=%v", applicationCompose, applicationEnvJSON, err)
	}
	var repositoryURL, registryImage, registryCredentialSecret, buildTarget, encryptedBuildConfig string
	var enableSubmodules bool
	var gitCredentialID *uuid.UUID
	if err = destination.Pool.QueryRow(ctx, `SELECT a.repository_url,a.registry_image,a.git_credential_id,c.encrypted_secret,a.build_target,a.enable_submodules,a.encrypted_build_config FROM application_sources a JOIN source_credentials c ON c.id=a.registry_credential_id WHERE a.compose_service_id=$1`, mappedID(options, "application-service", "a2")).Scan(&repositoryURL, &registryImage, &gitCredentialID, &registryCredentialSecret, &buildTarget, &enableSubmodules, &encryptedBuildConfig); err != nil {
		t.Fatal(err)
	}
	registrySecret, err := box.Decrypt(registryCredentialSecret, "source-credential")
	if repositoryURL != "https://github.com/example/api.git" || !strings.HasPrefix(registryImage, "registry.example.test/imports/") || gitCredentialID != nil || string(registrySecret) != "registry-secret" || buildTarget != "runtime" || !enableSubmodules || err != nil {
		t.Fatalf("Git source was not converted: repository=%q registry=%q", repositoryURL, registryImage)
	}
	buildConfigJSON, err := box.Decrypt(encryptedBuildConfig, "application-build-config:"+mappedID(options, "application-service", "a2").String())
	if err != nil || !bytes.Contains(buildConfigJSON, []byte(`"GO_VERSION":"1.26"`)) || !bytes.Contains(buildConfigJSON, []byte(`"NPM_TOKEN":"legacy-build-secret"`)) {
		t.Fatalf("application build settings were not re-encrypted: %s err=%v", buildConfigJSON, err)
	}
	var migrationRecords int
	if err = destination.Pool.QueryRow(ctx, `SELECT count(*) FROM dokploy_migration_resources WHERE target_organization_id=$1 AND source_organization_id='source-org' AND source_kind='application'`, targetOrg).Scan(&migrationRecords); err != nil || migrationRecords != 2 {
		t.Fatalf("migration metadata records=%d err=%v", migrationRecords, err)
	}

	transferManifest := DokployDatabaseTransferManifest{Version: 1, Connections: []DokployDatabaseSourceConnection{{SourceID: "pg1", Host: "legacy-postgres.internal", Port: 15432, Username: "transfer-user", Password: "transfer-secret", Database: "legacydb"}}}
	transferOptions := options
	transferOptions.DryRun = true
	transferReport, err := QueueDokployDatabaseTransfers(ctx, destination, box, transferOptions, transferManifest)
	if err != nil || transferReport.Planned != 1 || transferReport.Queued != 0 || transferReport.Items[0].DatabaseInstanceID != mappedID(options, "database:postgres", "pg1") {
		t.Fatalf("database transfer dry run=%#v err=%v", transferReport, err)
	}
	encodedTransferReport, _ := json.Marshal(transferReport)
	if bytes.Contains(encodedTransferReport, []byte("transfer-secret")) || bytes.Contains(encodedTransferReport, []byte("transfer-user")) {
		t.Fatalf("database transfer report leaked connection credentials: %s", encodedTransferReport)
	}
	transferOptions.DryRun = false
	transferReport, err = QueueDokployDatabaseTransfers(ctx, destination, box, transferOptions, transferManifest)
	if err != nil || transferReport.Queued != 1 {
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
	unknownManifest := transferManifest
	unknownManifest.Connections = []DokployDatabaseSourceConnection{{SourceID: "not-owned", Host: "db.internal", Username: "u", Password: "p", Database: "d"}}
	if _, err = QueueDokployDatabaseTransfers(ctx, destination, box, transferOptions, unknownManifest); err == nil || !strings.Contains(err.Error(), "does not belong") {
		t.Fatalf("unknown source ownership error=%v", err)
	}
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
