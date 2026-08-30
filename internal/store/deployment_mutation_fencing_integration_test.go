package store

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestActiveDeploymentFencesMutableExecutionInputs(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	organizationID, projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	credentialID, routeID, routeAuthID := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'deployment fence',$2)`, []any{organizationID, "deployment-fence-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'app','app',$3,'services: {web: {image: example/app:1}}')`, []any{serviceID, environmentID, "deployment-fence-" + serviceID.String()}},
		{`INSERT INTO source_credentials(id,organization_id,kind,name,server,username,encrypted_secret) VALUES($1,$2,'git','git','github.com','robot','ciphertext')`, []any{credentialID, organizationID}},
		{`INSERT INTO application_sources(compose_service_id,repository_url,target_service,registry_image,git_credential_id) VALUES($1,'https://github.com/acme/app','web','registry.example.test/acme/app',$2)`, []any{serviceID, credentialID}},
		{`INSERT INTO application_artifacts(compose_service_id,encrypted_archive,filename,sha256,compressed_size) VALUES($1,'archive','source.zip',$2,7)`, []any{serviceID, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
		{`INSERT INTO routes(id,compose_service_id,service_name,host,target_port) VALUES($1,$2,'web','app.example.test',8080)`, []any{routeID, serviceID}},
		{`INSERT INTO route_basic_auth_users(id,compose_service_id,username,password_hash) VALUES($1,$2,'operator','$2a$12$C6UzMDM.H6dfI/f/IKxGhuVvZ4GuGNmi1wT7dSx.QcpQo.eN8wxQe')`, []any{routeAuthID, serviceID}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	deployment, err := db.QueueDeployment(ctx, organizationID, serviceID, uuid.Nil, "manual")
	if err != nil {
		t.Fatal(err)
	}
	assertActive := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, ErrDeploymentActive) {
			t.Fatalf("%s during active deployment: got %v, want ErrDeploymentActive", name, err)
		}
	}
	_, err = db.UpdateComposeService(ctx, organizationID, serviceID, "services: {web: {image: example/app:2}}", "changed")
	assertActive("service update", err)
	_, err = db.UpsertApplicationSource(ctx, organizationID, ApplicationSource{ComposeServiceID: serviceID, RepositoryURL: "https://github.com/acme/changed", TargetService: "web", RegistryImage: "registry.example.test/acme/app", GitCredentialID: &credentialID})
	assertActive("source update", err)
	_, err = db.UpsertApplicationArtifact(ctx, organizationID, ApplicationArtifact{ComposeServiceID: serviceID, EncryptedArchive: "changed", Filename: "changed.zip", SHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", CompressedSize: 7})
	assertActive("artifact update", err)
	_, err = db.AddRoute(ctx, organizationID, Route{ComposeServiceID: serviceID, ServiceName: "web", Host: "new.example.test", PathPrefix: "/", TargetPort: 8080, TLS: true})
	assertActive("route addition", err)
	_, err = db.UpdateRoute(ctx, organizationID, Route{ID: routeID, ServiceName: "web", Host: "app.example.test", PathPrefix: "/", InternalPath: "/internal", TargetPort: 8080, TLS: true})
	assertActive("route update", err)
	_, err = db.UpdateRouteBasicAuthUser(ctx, organizationID, serviceID, routeAuthID, "operator", "")
	assertActive("route basic-auth update", err)
	assertActive("route basic-auth deletion", db.DeleteRouteBasicAuthUser(ctx, organizationID, serviceID, routeAuthID))
	assertActive("route deletion", db.DeleteRoute(ctx, organizationID, routeID))
	assertActive("credential deletion", db.DeleteSourceCredential(ctx, organizationID, credentialID))

	if err = db.CancelDeployment(ctx, organizationID, deployment.ID); err != nil {
		t.Fatal(err)
	}
	if err = db.DeleteRoute(ctx, organizationID, routeID); err != nil {
		t.Fatalf("route deletion after cancellation: %v", err)
	}
	if err = db.DeleteSourceCredential(ctx, organizationID, credentialID); err != nil {
		t.Fatalf("credential deletion after cancellation: %v", err)
	}
}
