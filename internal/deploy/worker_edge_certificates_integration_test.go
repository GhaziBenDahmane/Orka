package deploy

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

type edgeCertificateRecordingScheduler struct {
	stopRecordingScheduler
	proxy        EdgeProxySpec
	certificates []EdgeCertificateMaterial
}

type deploymentCountingScheduler struct {
	stopRecordingScheduler
	deployments int
}

func (s *deploymentCountingScheduler) Deploy(context.Context, string, string, map[string]string, *Credential) (DeploymentResult, error) {
	s.deployments++
	return DeploymentResult{}, nil
}

func (s *edgeCertificateRecordingScheduler) ReconcileEdgeCertificates(_ context.Context, proxy EdgeProxySpec, certificates []EdgeCertificateMaterial) error {
	s.proxy = proxy
	s.certificates = append([]EdgeCertificateMaterial(nil), certificates...)
	return nil
}

func TestEdgeCertificateWorkerDecryptsMaterialAndMarksTargetReady(t *testing.T) {
	db, ctx := recoveryTestStore(t)
	box, err := cryptox.New(bytes.Repeat([]byte{53}, 32))
	if err != nil {
		t.Fatal(err)
	}
	organizationID, projectID, environmentID, serviceID, certificateID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	certificatePEM, privateKeyPEM := "certificate-chain-marker", "private-key-marker"
	encryptedCertificate, err := box.Encrypt([]byte(certificatePEM), cryptox.ResourceContext("custom-tls-certificate-certificate", certificateID.String()))
	if err != nil {
		t.Fatal(err)
	}
	encryptedPrivateKey, err := box.Encrypt([]byte(privateKeyPEM), cryptox.ResourceContext("custom-tls-certificate-private-key", certificateID.String()))
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Edge certificate worker',$2)`, []any{organizationID, "edge-certificate-worker-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'Web','web',$3,'services: {web: {image: nginx}}')`, []any{serviceID, environmentID, "edge-certificate-worker-" + serviceID.String()}},
	} {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	certificate, err := db.CreateCustomTLSCertificate(ctx, store.CustomTLSCertificate{ID: certificateID, OrganizationID: organizationID, Name: "Production", EncryptedCertificate: encryptedCertificate, EncryptedPrivateKey: encryptedPrivateKey, Fingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CommonName: "app.example.test", DNSNames: []string{"app.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.AddRoute(ctx, organizationID, store.Route{ComposeServiceID: serviceID, ServiceName: "web", Host: "app.example.test", PathPrefix: "/", InternalPath: "/", TargetPort: 80, TLS: true, CustomCertificateID: &certificate.ID}); err != nil {
		t.Fatal(err)
	}
	claimed, err := (&Worker{Store: db, ID: "edge-certificate-test"}).claim(ctx)
	if err != nil || claimed.Kind != "edge-certificates.reconcile" {
		t.Fatalf("claimed=%#v error=%v", claimed, err)
	}
	scheduler := &edgeCertificateRecordingScheduler{}
	worker := &Worker{Store: db, Box: box, ID: "edge-certificate-test", Swarm: scheduler, LocalEdgeProxy: EdgeProxySpec{ServiceName: "dockyard-traefik", DynamicConfigurationPath: "/etc/traefik/dynamic"}}
	if err = worker.execute(ctx, claimed); err != nil {
		t.Fatal(err)
	}
	if err = worker.finish(ctx, claimed, nil); err != nil {
		t.Fatal(err)
	}
	if scheduler.proxy != worker.LocalEdgeProxy || len(scheduler.certificates) != 1 {
		t.Fatalf("proxy=%#v certificates=%#v", scheduler.proxy, scheduler.certificates)
	}
	material := scheduler.certificates[0]
	if material.ID != certificateID || material.Revision != 1 || material.Fingerprint != certificate.Fingerprint || material.CertificatePEM != certificatePEM || material.PrivateKeyPEM != privateKeyPEM {
		t.Fatalf("reconciled material=%#v", material)
	}
	target, err := db.GetEdgeCertificateTarget(ctx, "local")
	if err != nil || target.Status != "ready" || target.Generation != target.AppliedGeneration {
		t.Fatalf("target=%#v error=%v", target, err)
	}
}

func TestDeploymentWaitsForEnabledCustomCertificateReconciliation(t *testing.T) {
	db, ctx := recoveryTestStore(t)
	organizationID, projectID, environmentID, serviceID, certificateID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Edge deployment gate',$2)`, []any{organizationID, "edge-deployment-gate-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'Web','web',$3,'services: {web: {image: nginx:1.27}}')`, []any{serviceID, environmentID, "edge-deployment-gate-" + serviceID.String()}},
		{`INSERT INTO custom_tls_certificates(id,organization_id,name,encrypted_certificate,encrypted_private_key,fingerprint,common_name,dns_names,not_before,not_after) VALUES($1,$2,'Production','encrypted-cert','encrypted-key',$3,'app.example.test','{app.example.test}',now()-interval '1 hour',now()+interval '2 days')`, []any{certificateID, organizationID, "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},
		{`INSERT INTO routes(id,compose_service_id,service_name,host,path_prefix,internal_path,enabled,target_port,tls,certificate_resolver,custom_certificate_id) VALUES($1,$2,'web','app.example.test','/','/',true,80,true,'',$3)`, []any{uuid.New(), serviceID, certificateID}},
		{`INSERT INTO edge_certificate_targets(target_key,status,generation,applied_generation) VALUES('local','pending',2,1)`, nil},
	} {
		if _, err := db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	deployment, err := db.QueueDeployment(ctx, organizationID, serviceID, uuid.Nil, "manual")
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := (&Worker{Store: db, ID: "edge-deployment-gate"}).claim(ctx)
	if err != nil || claimed.Kind != "deploy.compose" {
		t.Fatalf("claimed=%#v error=%v", claimed, err)
	}
	scheduler := &deploymentCountingScheduler{}
	worker := &Worker{Store: db, ID: "edge-deployment-gate", Swarm: scheduler, Compiler: Compiler{PublicNetwork: "dockyard-public"}, Logger: slog.Default()}
	waitCtx, cancel := context.WithTimeout(ctx, 25*time.Millisecond)
	defer cancel()
	if err = worker.execute(waitCtx, claimed); err == nil {
		t.Fatal("deployment bypassed pending custom-certificate reconciliation")
	}
	if scheduler.deployments != 0 {
		t.Fatalf("scheduler received %d deployments before edge TLS was ready", scheduler.deployments)
	}
	var status string
	if err = db.Pool.QueryRow(ctx, `SELECT status FROM deployments WHERE id=$1`, deployment.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status == "succeeded" {
		t.Fatalf("deployment status=%q after edge TLS gate failure", status)
	}
}
