package store

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestServiceAndSourceMutationsCommitWithAudit(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, userID, serviceAccountID := uuid.New(), uuid.New(), uuid.New()
	projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Service source audit',$2)`, []any{organizationID, "service-source-audit-" + organizationID.String()}},
		{`INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, []any{userID, userID.String() + "@example.test"}},
		{`INSERT INTO service_accounts(id,organization_id,name,role) VALUES($1,$2,'source-operator','admin')`, []any{serviceAccountID, organizationID}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml,encrypted_env) VALUES($1,$2,'API','api',$3,'services: {}','original-env')`, []any{serviceID, environmentID, "service-source-audit-" + serviceID.String()}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	originalSource := ApplicationSource{ComposeServiceID: serviceID, SourceType: "git", RepositoryURL: "https://github.com/example/original.git", GitRef: "main", ContextDirectory: ".", Dockerfile: "Dockerfile", BuildType: "dockerfile", EncryptedBuildConfig: "original-build-config", TargetService: "api", RegistryImage: "ghcr.io/example/api"}
	if _, err := db.UpsertApplicationSource(ctx, organizationID, originalSource); err != nil {
		t.Fatal(err)
	}
	originalArtifact := ApplicationArtifact{ComposeServiceID: serviceID, EncryptedArchive: "original-archive", Filename: "original.zip", SHA256: strings.Repeat("a", 64), CompressedSize: 10}
	if _, err := db.UpsertApplicationArtifact(ctx, organizationID, originalArtifact); err != nil {
		t.Fatal(err)
	}
	principal := Principal{OrganizationID: organizationID, UserID: userID, Role: "owner"}
	servicePrincipal := Principal{OrganizationID: organizationID, ServiceAccountID: &serviceAccountID, Role: "admin"}
	if _, err := pool.Exec(ctx, `CREATE FUNCTION reject_service_source_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action IN ('service.update','source.update','source.artifact.update') THEN RAISE EXCEPTION 'forced audit failure'; END IF; RETURN NEW; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `CREATE TRIGGER reject_service_source_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_service_source_audit()`); err != nil {
		t.Fatal(err)
	}
	failedEnvironment := "failed-env"
	if _, err := db.UpdateComposeServiceConfigurationWithAudit(ctx, principal, serviceID, "services: {failed: {}}", &failedEnvironment, "127.0.0.1:1234"); err == nil {
		t.Fatal("service update succeeded after audit rejection")
	}
	assertStoredServiceConfiguration(t, pool, ctx, serviceID, "services: {}", "original-env", 1)
	failedSource := originalSource
	failedSource.RepositoryURL = "https://github.com/example/failed.git"
	failedSource.GitRef = "failed"
	failedSource.EncryptedBuildConfig = "failed-build-config"
	if _, err := db.UpsertApplicationSourceWithAudit(ctx, servicePrincipal, failedSource, "127.0.0.1:1234"); err == nil {
		t.Fatal("application source update succeeded after audit rejection")
	}
	assertStoredApplicationSource(t, pool, ctx, serviceID, originalSource.RepositoryURL, originalSource.GitRef, originalSource.EncryptedBuildConfig)
	failedArtifact := originalArtifact
	failedArtifact.EncryptedArchive = "failed-archive"
	failedArtifact.Filename = "failed.zip"
	failedArtifact.SHA256 = strings.Repeat("b", 64)
	failedArtifact.CompressedSize = 20
	if _, err := db.UpsertApplicationArtifactWithAudit(ctx, principal, failedArtifact, "127.0.0.1:1234"); err == nil {
		t.Fatal("application artifact update succeeded after audit rejection")
	}
	assertStoredApplicationArtifact(t, pool, ctx, serviceID, "original-archive", "original.zip", strings.Repeat("a", 64), 10)

	if _, err := pool.Exec(ctx, `DROP TRIGGER reject_service_source_audit ON audit_events`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DROP FUNCTION reject_service_source_audit()`); err != nil {
		t.Fatal(err)
	}
	replacementEnvironment := "replacement-env"
	service, err := db.UpdateComposeServiceConfigurationWithAudit(ctx, principal, serviceID, "services: {api: {}}", &replacementEnvironment, "127.0.0.1:1234")
	if err != nil {
		t.Fatal(err)
	}
	replacementSource := originalSource
	replacementSource.RepositoryURL = "https://github.com/example/replacement.git"
	replacementSource.GitRef = "release"
	replacementSource.EncryptedBuildConfig = "replacement-build-config"
	if _, err = db.UpsertApplicationSourceWithAudit(ctx, servicePrincipal, replacementSource, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	replacementArtifact := originalArtifact
	replacementArtifact.EncryptedArchive = "replacement-archive"
	replacementArtifact.Filename = "replacement.zip"
	replacementArtifact.SHA256 = strings.Repeat("c", 64)
	replacementArtifact.CompressedSize = 30
	if _, err = db.UpsertApplicationArtifactWithAudit(ctx, principal, replacementArtifact, "127.0.0.1:1234"); err != nil {
		t.Fatal(err)
	}
	assertStoredServiceConfiguration(t, pool, ctx, serviceID, "services: {api: {}}", replacementEnvironment, service.Revision)
	assertStoredApplicationSource(t, pool, ctx, serviceID, replacementSource.RepositoryURL, replacementSource.GitRef, replacementSource.EncryptedBuildConfig)
	assertStoredApplicationArtifact(t, pool, ctx, serviceID, replacementArtifact.EncryptedArchive, replacementArtifact.Filename, replacementArtifact.SHA256, replacementArtifact.CompressedSize)
	var userAudits, serviceAudits int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id=$2 AND actor_service_account_id IS NULL AND resource_id=$3 AND action IN ('service.update','source.artifact.update')`, organizationID, userID, serviceID.String()).Scan(&userAudits); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND actor_user_id IS NULL AND actor_service_account_id=$2 AND resource_id=$3 AND action='source.update'`, organizationID, serviceAccountID, serviceID.String()).Scan(&serviceAudits); err != nil {
		t.Fatal(err)
	}
	if userAudits != 2 || serviceAudits != 1 {
		t.Fatalf("service source audit counts: user=%d service=%d", userAudits, serviceAudits)
	}
}

func assertStoredServiceConfiguration(t *testing.T, pool interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}, ctx context.Context, serviceID uuid.UUID, compose, environment string, revision int64) {
	t.Helper()
	var storedCompose, storedEnvironment string
	var storedRevision int64
	if err := pool.QueryRow(ctx, `SELECT compose_yaml,encrypted_env,revision FROM compose_services WHERE id=$1`, serviceID).Scan(&storedCompose, &storedEnvironment, &storedRevision); err != nil {
		t.Fatal(err)
	}
	if storedCompose != compose || storedEnvironment != environment || storedRevision != revision {
		t.Fatalf("service configuration: compose=%q environment=%q revision=%d", storedCompose, storedEnvironment, storedRevision)
	}
}

func assertStoredApplicationSource(t *testing.T, pool interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}, ctx context.Context, serviceID uuid.UUID, repository, ref, encryptedConfig string) {
	t.Helper()
	var storedRepository, storedRef, storedConfig string
	if err := pool.QueryRow(ctx, `SELECT repository_url,git_ref,encrypted_build_config FROM application_sources WHERE compose_service_id=$1`, serviceID).Scan(&storedRepository, &storedRef, &storedConfig); err != nil {
		t.Fatal(err)
	}
	if storedRepository != repository || storedRef != ref || storedConfig != encryptedConfig {
		t.Fatalf("application source: repository=%q ref=%q config=%q", storedRepository, storedRef, storedConfig)
	}
}

func assertStoredApplicationArtifact(t *testing.T, pool interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}, ctx context.Context, serviceID uuid.UUID, archive, filename, sha string, size int64) {
	t.Helper()
	var storedArchive, storedFilename, storedSHA string
	var storedSize int64
	if err := pool.QueryRow(ctx, `SELECT encrypted_archive,filename,sha256,compressed_size FROM application_artifacts WHERE compose_service_id=$1`, serviceID).Scan(&storedArchive, &storedFilename, &storedSHA, &storedSize); err != nil {
		t.Fatal(err)
	}
	if storedArchive != archive || storedFilename != filename || storedSHA != sha || storedSize != size {
		t.Fatalf("application artifact: archive=%q filename=%q sha=%q size=%d", storedArchive, storedFilename, storedSHA, storedSize)
	}
}
