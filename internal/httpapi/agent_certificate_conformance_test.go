package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/agentpki"
	"github.com/bendahma/dokploy-go/internal/observability"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func TestAgentCertificateMTLSConformance(t *testing.T) {
	if os.Getenv("DOCKYARD_AGENT_CERTIFICATE_CONFORMANCE") == "" {
		t.Skip("DOCKYARD_AGENT_CERTIFICATE_CONFORMANCE is not set")
	}
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("DOCKYARD_TEST_DATABASE_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	db, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)

	now := time.Now().UTC()
	caPEM, caKeyPEM, err := agentpki.NewCA(now, 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	serverCertificatePEM, serverKeyPEM := conformanceServerIdentity(t, caPEM, caKeyPEM, now)
	clusterID, organizationID := uuid.New(), uuid.New()
	oldCertificatePEM, oldKeyPEM, oldCertificate := conformanceAgentIdentity(t, caPEM, caKeyPEM, clusterID, now, time.Hour)
	oldSerial := hex.EncodeToString(oldCertificate.SerialNumber.Bytes())
	if _, err = db.Pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Agent certificate conformance',$2)`, organizationID, "agent-certificate-"+organizationID.String()); err == nil {
		_, err = db.Pool.Exec(ctx, `INSERT INTO clusters(id,organization_id,name,slug,state,certificate_serial,certificate_not_after,last_seen_at) VALUES($1,$2,'Remote','remote','active',$3,$4,now())`, clusterID, organizationID, oldSerial, oldCertificate.NotAfter)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
	})

	api := &Server{Store: db, AgentCACertificate: caPEM, AgentCAKey: caKeyPEM, AgentCertificateTTL: 7 * 24 * time.Hour}
	clientRoots, err := AgentTLSConfig(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	serverPair, err := tls.X509KeyPair(serverCertificatePEM, serverKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	tlsServer := httptest.NewUnstartedServer(api.AgentHandler())
	tlsServer.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverPair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientRoots,
	}
	tlsServer.StartTLS()
	defer tlsServer.Close()

	oldClient := conformanceMTLSClient(t, caPEM, oldCertificatePEM, oldKeyPEM)
	heartbeat := []byte(`{"agentVersion":"conformance","dockerVersion":"29.0.0","capacity":{"nodes":1}}`)
	status, body, err := conformanceAgentRequest(ctx, oldClient, http.MethodPost, tlsServer.URL+"/v1/agent/heartbeat", heartbeat)
	if err != nil || status != http.StatusOK {
		t.Fatalf("initial old-certificate heartbeat status=%d body=%s err=%v", status, body, err)
	}

	replacementKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	replacementCSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "dockyard-agent"}}, replacementKey)
	if err != nil {
		t.Fatal(err)
	}
	rotationBody, _ := json.Marshal(map[string]string{"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: replacementCSR}))})
	status, body, err = conformanceAgentRequest(ctx, oldClient, http.MethodPost, tlsServer.URL+"/v1/agent/rotate", rotationBody)
	if err != nil || status != http.StatusOK {
		t.Fatalf("rotation status=%d body=%s err=%v", status, body, err)
	}
	var rotation struct {
		Certificate string    `json:"certificate"`
		ExpiresAt   time.Time `json:"expiresAt"`
	}
	if err = json.Unmarshal(body, &rotation); err != nil {
		t.Fatal(err)
	}
	replacementBlock, rest := pem.Decode([]byte(rotation.Certificate))
	if replacementBlock == nil || replacementBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("rotation response did not contain exactly one PEM certificate")
	}
	replacementCertificate, err := x509.ParseCertificate(replacementBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if identity, identityErr := agentpki.ClusterIdentity(replacementCertificate); identityErr != nil || identity != clusterID {
		t.Fatalf("replacement identity=%s err=%v", identity, identityErr)
	}
	if !replacementCertificate.PublicKey.(*rsa.PublicKey).Equal(&replacementKey.PublicKey) {
		t.Fatal("replacement certificate does not match the submitted CSR key")
	}
	replacementSerial := hex.EncodeToString(replacementCertificate.SerialNumber.Bytes())

	var activeSerial, pendingSerial string
	if err = db.Pool.QueryRow(ctx, `SELECT certificate_serial,pending_certificate_serial FROM clusters WHERE id=$1`, clusterID).Scan(&activeSerial, &pendingSerial); err != nil {
		t.Fatal(err)
	}
	if activeSerial != oldSerial || pendingSerial != replacementSerial {
		t.Fatalf("rotation was not staged: active=%q pending=%q", activeSerial, pendingSerial)
	}
	metricsBefore := conformanceCertificateMetrics(t, db)
	pendingMetric := `dockyard_cluster_certificate_rotation_pending_age_seconds{organization="` + organizationID.String() + `",cluster="remote"}`
	activeMetric := `dockyard_cluster_certificate_expiry_seconds{organization="` + organizationID.String() + `",cluster="remote"}`
	if !strings.Contains(metricsBefore, pendingMetric) || !strings.Contains(metricsBefore, activeMetric) {
		t.Fatalf("pending rotation metrics missing:\n%s", metricsBefore)
	}

	status, body, err = conformanceAgentRequest(ctx, oldClient, http.MethodPost, tlsServer.URL+"/v1/agent/heartbeat", heartbeat)
	if err != nil || status != http.StatusOK {
		t.Fatalf("old certificate was revoked before replacement confirmation: status=%d body=%s err=%v", status, body, err)
	}

	replacementKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(replacementKey)})
	replacementClient := conformanceMTLSClient(t, caPEM, []byte(rotation.Certificate), replacementKeyPEM)
	status, body, err = conformanceAgentRequest(ctx, replacementClient, http.MethodPost, tlsServer.URL+"/v1/agent/heartbeat", heartbeat)
	if err != nil || status != http.StatusOK {
		t.Fatalf("replacement confirmation status=%d body=%s err=%v", status, body, err)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT certificate_serial,pending_certificate_serial FROM clusters WHERE id=$1`, clusterID).Scan(&activeSerial, &pendingSerial); err != nil {
		t.Fatal(err)
	}
	if activeSerial != replacementSerial || pendingSerial != "" {
		t.Fatalf("replacement was not promoted: active=%q pending=%q", activeSerial, pendingSerial)
	}
	metricsAfter := conformanceCertificateMetrics(t, db)
	if strings.Contains(metricsAfter, pendingMetric) || !strings.Contains(metricsAfter, activeMetric) {
		t.Fatalf("rotation metrics did not converge after promotion:\n%s", metricsAfter)
	}

	status, body, err = conformanceAgentRequest(ctx, oldClient, http.MethodPost, tlsServer.URL+"/v1/agent/heartbeat", heartbeat)
	if err != nil || status != http.StatusUnauthorized || !bytes.Contains(body, []byte(`"code":"invalid_agent_certificate"`)) {
		t.Fatalf("superseded certificate status=%d body=%s err=%v", status, body, err)
	}

	wrongCertificatePEM, wrongKeyPEM, _ := conformanceAgentIdentity(t, caPEM, caKeyPEM, uuid.New(), now, time.Hour)
	wrongClient := conformanceMTLSClient(t, caPEM, wrongCertificatePEM, wrongKeyPEM)
	status, body, err = conformanceAgentRequest(ctx, wrongClient, http.MethodPost, tlsServer.URL+"/v1/agent/heartbeat", heartbeat)
	if err != nil || status != http.StatusUnauthorized || !bytes.Contains(body, []byte(`"code":"invalid_agent_certificate"`)) {
		t.Fatalf("wrong-cluster certificate status=%d body=%s err=%v", status, body, err)
	}

	untrustedCA, untrustedCAKey, err := agentpki.NewCA(now, 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	untrustedCertificatePEM, untrustedKeyPEM, _ := conformanceAgentIdentity(t, untrustedCA, untrustedCAKey, clusterID, now, time.Hour)
	untrustedClient := conformanceMTLSClient(t, caPEM, untrustedCertificatePEM, untrustedKeyPEM)
	if status, body, err = conformanceAgentRequest(ctx, untrustedClient, http.MethodPost, tlsServer.URL+"/v1/agent/heartbeat", heartbeat); err == nil {
		t.Fatalf("untrusted certificate reached HTTP handler: status=%d body=%s", status, body)
	}

	expiredCertificatePEM, expiredKeyPEM := conformanceExpiredAgentIdentity(t, caPEM, caKeyPEM, clusterID, now)
	expiredClient := conformanceMTLSClient(t, caPEM, expiredCertificatePEM, expiredKeyPEM)
	if status, body, err = conformanceAgentRequest(ctx, expiredClient, http.MethodPost, tlsServer.URL+"/v1/agent/heartbeat", heartbeat); err == nil {
		t.Fatalf("expired certificate reached HTTP handler: status=%d body=%s", status, body)
	}

	if _, err = tls.X509KeyPair([]byte(rotation.Certificate), oldKeyPEM); err == nil {
		t.Fatal("mismatched replacement certificate and private key were accepted")
	}

	newCAPEM, newCAKeyPEM, err := agentpki.NewCA(now, 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	newCAFingerprint, err := agentpki.CertificateFingerprint(newCAPEM)
	if err != nil {
		t.Fatal(err)
	}
	trustBundle := append(append([]byte{}, newCAPEM...), caPEM...)
	rolloverAPI := &Server{Store: db, AgentCACertificate: newCAPEM, AgentCATrustBundle: trustBundle, AgentCAKey: newCAKeyPEM, AgentCertificateTTL: 7 * 24 * time.Hour}
	rolloverRoots, err := AgentTLSConfig(trustBundle)
	if err != nil {
		t.Fatal(err)
	}
	rolloverServer := httptest.NewUnstartedServer(rolloverAPI.AgentHandler())
	rolloverServer.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverPair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: rolloverRoots}
	rolloverServer.StartTLS()
	defer rolloverServer.Close()
	status, body, err = conformanceAgentRequest(ctx, replacementClient, http.MethodPost, rolloverServer.URL+"/v1/agent/heartbeat", heartbeat)
	var rolloverTrust struct {
		CACertificate        string `json:"caCertificate"`
		SigningCACertificate string `json:"signingCaCertificate"`
		SigningCAFingerprint string `json:"signingCaFingerprint"`
	}
	decodeTrustErr := json.Unmarshal(body, &rolloverTrust)
	if err != nil || status != http.StatusOK || decodeTrustErr != nil || rolloverTrust.SigningCACertificate != string(newCAPEM) || rolloverTrust.CACertificate != string(trustBundle) || rolloverTrust.SigningCAFingerprint != newCAFingerprint {
		t.Fatalf("dual-trust heartbeat status=%d body=%s err=%v", status, body, err)
	}
	caReplacementKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caReplacementCSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "dockyard-agent"}}, caReplacementKey)
	if err != nil {
		t.Fatal(err)
	}
	caRotationBody, _ := json.Marshal(map[string]string{"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: caReplacementCSR}))})
	status, body, err = conformanceAgentRequest(ctx, replacementClient, http.MethodPost, rolloverServer.URL+"/v1/agent/rotate", caRotationBody)
	if err != nil || status != http.StatusOK {
		t.Fatalf("CA rollover issuance status=%d body=%s err=%v", status, body, err)
	}
	var caRotation struct {
		Certificate string `json:"certificate"`
	}
	if err = json.Unmarshal(body, &caRotation); err != nil {
		t.Fatal(err)
	}
	caReplacementKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caReplacementKey)})
	caReplacementClient := conformanceMTLSClient(t, trustBundle, []byte(caRotation.Certificate), caReplacementKeyPEM)
	status, body, err = conformanceAgentRequest(ctx, caReplacementClient, http.MethodPost, rolloverServer.URL+"/v1/agent/heartbeat", heartbeat)
	if err != nil || status != http.StatusOK {
		t.Fatalf("new-CA confirmation status=%d body=%s err=%v", status, body, err)
	}
	var activeCAFingerprint, pendingCAFingerprint string
	if err = db.Pool.QueryRow(ctx, `SELECT certificate_ca_fingerprint,pending_certificate_ca_fingerprint FROM clusters WHERE id=$1`, clusterID).Scan(&activeCAFingerprint, &pendingCAFingerprint); err != nil {
		t.Fatal(err)
	}
	if activeCAFingerprint != newCAFingerprint || pendingCAFingerprint != "" {
		t.Fatalf("CA fingerprint did not converge: active=%q pending=%q want=%q", activeCAFingerprint, pendingCAFingerprint, newCAFingerprint)
	}
	status, body, err = conformanceAgentRequest(ctx, replacementClient, http.MethodPost, rolloverServer.URL+"/v1/agent/heartbeat", heartbeat)
	if err != nil || status != http.StatusUnauthorized || !bytes.Contains(body, []byte(`"code":"invalid_agent_certificate"`)) {
		t.Fatalf("old-CA identity after promotion status=%d body=%s err=%v", status, body, err)
	}

	newServerCertificatePEM, newServerKeyPEM := conformanceServerIdentity(t, newCAPEM, newCAKeyPEM, now)
	newServerPair, err := tls.X509KeyPair(newServerCertificatePEM, newServerKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	newRoots, err := AgentTLSConfig(newCAPEM)
	if err != nil {
		t.Fatal(err)
	}
	finalAPI := &Server{Store: db, AgentCACertificate: newCAPEM, AgentCATrustBundle: newCAPEM, AgentCAKey: newCAKeyPEM, AgentCertificateTTL: 7 * 24 * time.Hour}
	finalServer := httptest.NewUnstartedServer(finalAPI.AgentHandler())
	finalServer.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{newServerPair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: newRoots}
	finalServer.StartTLS()
	defer finalServer.Close()
	finalClient := conformanceMTLSClient(t, newCAPEM, []byte(caRotation.Certificate), caReplacementKeyPEM)
	status, body, err = conformanceAgentRequest(ctx, finalClient, http.MethodPost, finalServer.URL+"/v1/agent/heartbeat", heartbeat)
	if err != nil || status != http.StatusOK {
		t.Fatalf("new-only listener heartbeat status=%d body=%s err=%v", status, body, err)
	}
	retiredIdentityClient := conformanceMTLSClient(t, newCAPEM, []byte(rotation.Certificate), replacementKeyPEM)
	if status, body, err = conformanceAgentRequest(ctx, retiredIdentityClient, http.MethodPost, finalServer.URL+"/v1/agent/heartbeat", heartbeat); err == nil {
		t.Fatalf("retired CA identity reached new-only listener: status=%d body=%s", status, body)
	}

	evidence, _ := json.Marshal(map[string]any{
		"status":                         "passed",
		"tlsVersion":                     "1.3",
		"oldCertificateAuthenticated":    true,
		"replacementIssuedPending":       true,
		"oldValidBeforeConfirmation":     true,
		"replacementPromotedOnHeartbeat": true,
		"oldRejectedAfterPromotion":      true,
		"wrongClusterRejected":           true,
		"untrustedCARejected":            true,
		"expiredCertificateRejected":     true,
		"mismatchedKeyRejected":          true,
		"pendingMetricsConverged":        true,
		"caDualTrustMigrationVerified":   true,
		"caFingerprintConverged":         true,
		"newOnlyListenerVerified":        true,
		"retiredCARejected":              true,
	})
	fmt.Printf("AGENT_CERTIFICATE_EVIDENCE %s\n", evidence)
}

func conformanceServerIdentity(t *testing.T, caPEM, caKeyPEM []byte, now time.Time) ([]byte, []byte) {
	t.Helper()
	caBlock, _ := pem.Decode(caPEM)
	keyBlock, _ := pem.Decode(caKeyPEM)
	if caBlock == nil || keyBlock == nil {
		t.Fatal("invalid conformance CA")
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func conformanceAgentIdentity(t *testing.T, caPEM, caKeyPEM []byte, clusterID uuid.UUID, now time.Time, lifetime time.Duration) ([]byte, []byte, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "dockyard-agent"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM, certificate, err := agentpki.SignAgentCSR(caPEM, caKeyPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), clusterID, now, lifetime)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certificatePEM, keyPEM, certificate
}

func conformanceExpiredAgentIdentity(t *testing.T, caPEM, caKeyPEM []byte, clusterID uuid.UUID, now time.Time) ([]byte, []byte) {
	t.Helper()
	caBlock, _ := pem.Decode(caPEM)
	keyBlock, _ := pem.Decode(caKeyPEM)
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := url.Parse("spiffe://dockyard/cluster/" + clusterID.String())
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "dockyard-agent-" + clusterID.String()},
		URIs:         []*url.URL{identity},
		NotBefore:    now.Add(-2 * time.Hour),
		NotAfter:     now.Add(-time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func conformanceMTLSClient(t *testing.T, caPEM, certificatePEM, keyPEM []byte) *http.Client {
	t.Helper()
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("invalid conformance root CA")
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{certificate}}}}
}

func conformanceAgentRequest(ctx context.Context, client *http.Client, method, endpoint string, body []byte) (int, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	return response.StatusCode, data, err
}

func conformanceCertificateMetrics(t *testing.T, db *store.Store) string {
	t.Helper()
	recorder := httptest.NewRecorder()
	observability.NewMetrics().Handler(db.Pool).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("metrics status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	return recorder.Body.String()
}
