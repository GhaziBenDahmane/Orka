package store

import (
	"testing"

	"github.com/google/uuid"
)

func TestQueueDeploymentSnapshotsRegistryCredential(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	credentialID := uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'registry snapshot',$2)`, []any{organizationID, "registry-snapshot-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'app','app',$3,'services: {}')`, []any{serviceID, environmentID, "registry-snapshot-" + serviceID.String()}},
		{`INSERT INTO source_credentials(id,organization_id,kind,name,server,username,encrypted_secret) VALUES($1,$2,'registry','registry','registry.example.test','robot','ciphertext')`, []any{credentialID, organizationID}},
		{`INSERT INTO application_sources(compose_service_id,repository_url,target_service,registry_image,registry_credential_id) VALUES($1,'https://github.com/acme/app','web','registry.example.test/acme/app',$2)`, []any{serviceID, credentialID}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	deployment, err := db.QueueDeployment(ctx, organizationID, serviceID, uuid.Nil, "manual")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE deployments SET status='succeeded',finished_at=now() WHERE id=$1`, deployment.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE jobs SET status='succeeded',finished_at=now() WHERE kind='deploy.compose' AND payload->>'deploymentId'=$1::text`, deployment.ID); err != nil {
		t.Fatal(err)
	}
	if err = db.DeleteSourceCredential(ctx, organizationID, credentialID); err != nil {
		t.Fatal(err)
	}
	var gotID *uuid.UUID
	var server, username, encrypted string
	if err = pool.QueryRow(ctx, `SELECT registry_credential_id,registry_credential_server,registry_credential_username,encrypted_registry_credential FROM deployments WHERE id=$1`, deployment.ID).Scan(&gotID, &server, &username, &encrypted); err != nil {
		t.Fatal(err)
	}
	if gotID == nil || *gotID != credentialID || server != "registry.example.test" || username != "robot" || encrypted != "ciphertext" {
		t.Fatalf("credential snapshot id=%v server=%q username=%q encrypted=%q", gotID, server, username, encrypted)
	}
}
