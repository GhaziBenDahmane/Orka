package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCustomTLSCertificateRouteLifecycleQueuesEdgeReconciliation(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	var err error
	organizationID, projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Custom TLS',$2)`, []any{organizationID, "custom-tls-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'Web','web',$3,'services: {web: {image: nginx}}')`, []any{serviceID, environmentID, "tls-" + serviceID.String()}},
	}
	for _, statement := range statements {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	certificate, err := db.CreateCustomTLSCertificate(ctx, CustomTLSCertificate{OrganizationID: organizationID, Name: "Wildcard", EncryptedCertificate: "encrypted-cert", EncryptedPrivateKey: "encrypted-key", Fingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", CommonName: "*.example.test", DNSNames: []string{"*.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	route, err := db.AddRoute(ctx, organizationID, Route{ComposeServiceID: serviceID, ServiceName: "web", Host: "app.example.test", PathPrefix: "/", InternalPath: "/", TargetPort: 80, TLS: true, CustomCertificateID: &certificate.ID})
	if err != nil {
		t.Fatal(err)
	}
	if route.CustomCertificateID == nil || *route.CustomCertificateID != certificate.ID || route.CertificateResolver != "" {
		t.Fatalf("route=%#v", route)
	}
	target, err := db.GetEdgeCertificateTarget(ctx, "local")
	if err != nil || target.Status != "pending" || target.Generation != 1 {
		t.Fatalf("target=%#v error=%v", target, err)
	}
	desired, err := db.ListDesiredEdgeCertificates(ctx, target)
	if err != nil || len(desired) != 1 || desired[0].ID != certificate.ID {
		t.Fatalf("desired=%#v error=%v", desired, err)
	}
	snapshot, err := db.BuildAIAuditSnapshot(ctx, organizationID)
	if err != nil || len(snapshot.CustomTLSPosture) != 1 || snapshot.CustomTLSPosture[0].ID != certificate.ID || snapshot.CustomTLSPosture[0].AttachedRoutes != 1 || snapshot.CustomTLSPosture[0].EnabledRoutes != 1 || len(snapshot.EdgeTLSPosture) != 1 || snapshot.EdgeTLSPosture[0].TargetKey != "local" || snapshot.Routes[0].CustomCertificateID == nil {
		t.Fatalf("custom TLS audit posture=%#v/%#v routes=%#v error=%v", snapshot.CustomTLSPosture, snapshot.EdgeTLSPosture, snapshot.Routes, err)
	}
	encodedSnapshot, err := json.Marshal(snapshot)
	if err != nil || bytes.Contains(encodedSnapshot, []byte("encrypted-cert")) || bytes.Contains(encodedSnapshot, []byte("encrypted-key")) {
		t.Fatalf("AI snapshot leaked custom TLS material: error=%v body=%s", err, encodedSnapshot)
	}
	if err = db.DeleteCustomTLSCertificate(ctx, organizationID, certificate.ID); !errors.Is(err, ErrBusy) {
		t.Fatalf("delete associated certificate error=%v", err)
	}
	certificate.Name = "Wildcard rotated"
	certificate.Fingerprint = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	certificate.EncryptedCertificate = "rotated-cert"
	certificate.EncryptedPrivateKey = "rotated-key"
	certificate, err = db.UpdateCustomTLSCertificate(ctx, certificate)
	if err != nil || certificate.Revision != 2 {
		t.Fatalf("rotated=%#v error=%v", certificate, err)
	}
	target, err = db.GetEdgeCertificateTarget(ctx, "local")
	if err != nil || target.Generation != 2 {
		t.Fatalf("rotated target=%#v error=%v", target, err)
	}
	if err = db.DeleteRoute(ctx, organizationID, route.ID); err != nil {
		t.Fatal(err)
	}
	target, err = db.GetEdgeCertificateTarget(ctx, "local")
	if err != nil || target.Generation != 3 {
		t.Fatalf("detached target=%#v error=%v", target, err)
	}
	if err = db.DeleteCustomTLSCertificate(ctx, organizationID, certificate.ID); err != nil {
		t.Fatal(err)
	}
}

func TestCustomTLSCertificateRouteRejectsWrongHostname(t *testing.T) {
	pool, ctx := migrationTestPool(t)
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := &Store{Pool: pool}
	var err error
	organizationID, projectID, environmentID, serviceID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'Custom TLS mismatch',$2)`, []any{organizationID, "custom-tls-mismatch-" + organizationID.String()}},
		{`INSERT INTO projects(id,organization_id,name,slug) VALUES($1,$2,'Project','project')`, []any{projectID, organizationID}},
		{`INSERT INTO environments(id,project_id,name,slug) VALUES($1,$2,'Production','production')`, []any{environmentID, projectID}},
		{`INSERT INTO compose_services(id,environment_id,name,slug,stack_name,compose_yaml) VALUES($1,$2,'Web','web',$3,'services: {web: {image: nginx}}')`, []any{serviceID, environmentID, "tls-" + serviceID.String()}},
	} {
		if _, err = db.Pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	certificate, err := db.CreateCustomTLSCertificate(ctx, CustomTLSCertificate{OrganizationID: organizationID, Name: "Only API", EncryptedCertificate: "cert", EncryptedPrivateKey: "key", Fingerprint: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", DNSNames: []string{"api.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.AddRoute(ctx, organizationID, Route{ComposeServiceID: serviceID, ServiceName: "web", Host: "other.example.test", PathPrefix: "/", TargetPort: 80, TLS: true, CustomCertificateID: &certificate.ID})
	if !errors.Is(err, ErrInvalidRouteCertificate) {
		t.Fatalf("wrong-host certificate error=%v", err)
	}
}
