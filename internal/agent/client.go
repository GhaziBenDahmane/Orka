package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/bendahma/dokploy-go/internal/agentpki"
	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/deploy"
	"github.com/google/uuid"
)

type Config struct {
	EnrollmentURL       string
	AgentURL            string
	EnrollmentToken     string
	EnrollmentTokenFile string
	StateDirectory      string
	DockerBin           string
	Network             string
	Version             string
	ServiceName         string
}

type Client struct {
	cfg          Config
	swarm        deploy.Scheduler
	http         *http.Client
	serviceState func(context.Context) (string, string, error)
}

type command struct {
	ID             uuid.UUID       `json:"id"`
	Kind           string          `json:"kind"`
	Payload        json.RawMessage `json:"payload"`
	LeaseID        uuid.UUID       `json:"leaseId"`
	LeaseExpiresAt time.Time       `json:"leaseExpiresAt"`
}

type agentTrustUpdate struct {
	CACertificate        string `json:"caCertificate"`
	SigningCACertificate string `json:"signingCaCertificate"`
}

func Run(ctx context.Context, cfg Config) error {
	if cfg.EnrollmentURL == "" || cfg.AgentURL == "" || !filepath.IsAbs(cfg.StateDirectory) {
		return errors.New("agent enrollment URL, agent URL, and absolute state directory are required")
	}
	if err := validateAgentEndpoint("agent enrollment URL", cfg.EnrollmentURL); err != nil {
		return err
	}
	if err := validateAgentEndpoint("agent mTLS URL", cfg.AgentURL); err != nil {
		return err
	}
	if cfg.DockerBin == "" {
		cfg.DockerBin = "docker"
	}
	if cfg.Network == "" {
		cfg.Network = "dockyard-public"
	}
	if !serviceNamePattern.MatchString(cfg.ServiceName) {
		return errors.New("agent Swarm service name is required and must be a valid service name")
	}
	if err := os.MkdirAll(cfg.StateDirectory, 0700); err != nil {
		return err
	}
	if err := ensureIdentity(ctx, cfg); err != nil {
		return err
	}
	httpClient, err := mTLSClient(cfg.StateDirectory)
	if err != nil {
		return err
	}
	httpClient, err = rotateIfNeeded(ctx, cfg, httpClient)
	if err != nil {
		if httpClient == nil {
			return err
		}
		slog.Warn("agent certificate rotation deferred", "error", err)
	}
	c := &Client{cfg: cfg, swarm: deploy.Swarm{DockerBin: cfg.DockerBin, Network: cfg.Network, Timeout: 5 * time.Minute, ServiceName: cfg.ServiceName}, http: httpClient}
	c.serviceState = c.inspectServiceState
	return c.loop(ctx)
}

func validateAgentEndpoint(label, rawURL string) error {
	trimmed := strings.TrimSpace(rawURL)
	parsed, err := url.Parse(trimmed)
	if err != nil || rawURL != trimmed || parsed.Scheme != "https" || !validEndpointHostname(parsed.Hostname()) || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" || strings.HasSuffix(parsed.Host, ":") {
		return fmt.Errorf("%s must be an HTTPS origin without credentials, path, query, or fragment and with a valid host and port", label)
	}
	if port := parsed.Port(); port != "" {
		value, parseErr := strconv.Atoi(port)
		if parseErr != nil || value < 1 || value > 65535 {
			return fmt.Errorf("%s must be an HTTPS origin without credentials, path, query, or fragment and with a valid host and port", label)
		}
	}
	return nil
}

func validEndpointHostname(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || !endpointHostnameLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func rejectRedirect(*http.Request, []*http.Request) error {
	return errors.New("agent API redirects are disabled")
}

func rotateIfNeeded(ctx context.Context, cfg Config, current *http.Client) (*http.Client, error) {
	return rotateCertificate(ctx, cfg, current, false, nil)
}

func rotateCertificate(ctx context.Context, cfg Config, current *http.Client, force bool, expectedSigningCA []byte) (*http.Client, error) {
	certPath, keyPath, caPath := identityPaths(cfg.StateDirectory)
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	certificate, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	if time.Until(certificate.NotAfter) <= 0 {
		return nil, errors.New("agent certificate expired before it could be rotated")
	}
	rotationWindow := certificate.NotAfter.Sub(certificate.NotBefore) / 3
	if rotationWindow > 24*time.Hour {
		rotationWindow = 24 * time.Hour
	}
	if rotationWindow < time.Minute {
		rotationWindow = time.Minute
	}
	if !force && time.Until(certificate.NotAfter) > rotationWindow {
		return current, nil
	}
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return current, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "dockyard-agent"}}, key)
	if err != nil {
		return current, err
	}
	body, _ := json.Marshal(map[string]string{"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(cfg.AgentURL, "/")+"/v1/agent/rotate", bytes.NewReader(body))
	if err != nil {
		return current, err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := current.Do(req)
	if err != nil {
		return current, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return current, fmt.Errorf("agent certificate rotation returned HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(data)))
	}
	var rotated struct {
		Certificate          string `json:"certificate"`
		CACertificate        string `json:"caCertificate"`
		SigningCACertificate string `json:"signingCaCertificate"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&rotated); err != nil {
		return current, err
	}
	verificationCA := expectedSigningCA
	if len(verificationCA) == 0 && rotated.SigningCACertificate != "" {
		verificationCA = []byte(rotated.SigningCACertificate)
	}
	if len(verificationCA) == 0 {
		verificationCA, err = os.ReadFile(caPath)
		if err != nil {
			return current, fmt.Errorf("read saved agent CA: %w", err)
		}
	}
	if err := validateRotatedCertificate([]byte(rotated.Certificate), key, certificate, verificationCA); err != nil {
		return current, err
	}
	if rotated.CACertificate != "" {
		if err := validateTrustUpdate([]byte(rotated.CACertificate), verificationCA); err != nil {
			return current, err
		}
		if err := writeIdentityFile(caPath, []byte(rotated.CACertificate), 0644); err != nil {
			return current, err
		}
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	identityPEM := append([]byte(rotated.Certificate), keyPEM...)
	if err := writeIdentityFile(certPath, identityPEM, 0600); err != nil {
		return current, err
	}
	return mTLSClient(cfg.StateDirectory)
}

func validateRotatedCertificate(certificatePEM []byte, key *rsa.PrivateKey, previous *x509.Certificate, caPEM []byte) error {
	block, rest := pem.Decode(certificatePEM)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("agent rotation returned an invalid certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.New("agent rotation returned an invalid certificate")
	}
	publicKey, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok || !publicKey.Equal(&key.PublicKey) {
		return errors.New("rotated agent certificate does not match the generated private key")
	}
	previousCluster, err := agentpki.ClusterIdentity(previous)
	if err != nil {
		return fmt.Errorf("read current agent identity: %w", err)
	}
	rotatedCluster, err := agentpki.ClusterIdentity(certificate)
	if err != nil || rotatedCluster != previousCluster {
		return errors.New("rotated agent certificate changed the cluster identity")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return errors.New("invalid saved agent CA")
	}
	if _, err = certificate.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("verify rotated agent certificate: %w", err)
	}
	return nil
}

func ensureIdentity(ctx context.Context, cfg Config) error {
	certPath, keyPath, caPath := identityPaths(cfg.StateDirectory)
	if validateSavedAgentIdentity(certPath, keyPath, caPath, time.Now()) == nil {
		return nil
	}
	token := strings.TrimSpace(cfg.EnrollmentToken)
	if token == "" && cfg.EnrollmentTokenFile != "" {
		contents, err := os.ReadFile(cfg.EnrollmentTokenFile)
		if err != nil {
			return fmt.Errorf("read agent enrollment token: %w", err)
		}
		token = strings.TrimSpace(string(contents))
	}
	if token == "" {
		return errors.New("agent identity missing and DOCKYARD_AGENT_ENROLLMENT_TOKEN is empty")
	}
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "dockyard-agent"}}, key)
	if err != nil {
		return err
	}
	requestBody, _ := json.Marshal(map[string]string{"token": token, "csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(cfg.EnrollmentURL, "/")+"/v1/agent/enroll", bytes.NewReader(requestBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := (&http.Client{Timeout: 30 * time.Second, CheckRedirect: rejectRedirect}).Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("agent enrollment returned HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	var enrolled struct {
		Certificate   string `json:"certificate"`
		CACertificate string `json:"caCertificate"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&enrolled); err != nil {
		return err
	}
	if err := validateEnrolledAgentIdentity([]byte(enrolled.Certificate), key, []byte(enrolled.CACertificate), time.Now()); err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	identityPEM := append([]byte(enrolled.Certificate), keyPEM...)
	// Write trust first and the identity last. The identity is the commit marker
	// checked on startup, so an interrupted write cannot make a partial pair
	// appear usable.
	if err := writeIdentityFile(caPath, []byte(enrolled.CACertificate), 0644); err != nil {
		return err
	}
	return writeIdentityFile(certPath, identityPEM, 0600)
}

func validateSavedAgentIdentity(certPath, keyPath, caPath string, now time.Time) error {
	identityPEM, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	pair, err := tls.X509KeyPair(identityPEM, identityPEM)
	if err != nil || len(pair.Certificate) != 1 {
		return errors.New("invalid saved agent certificate or private key")
	}
	certificate, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return errors.New("invalid saved agent certificate")
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return err
	}
	return validateAgentClientCertificate(certificate, caPEM, now)
}

func validateEnrolledAgentIdentity(certificatePEM []byte, key *rsa.PrivateKey, caPEM []byte, now time.Time) error {
	block, rest := pem.Decode(certificatePEM)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("agent enrollment returned an invalid certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.New("agent enrollment returned an invalid certificate")
	}
	publicKey, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok || !publicKey.Equal(&key.PublicKey) {
		return errors.New("enrolled agent certificate does not match the generated private key")
	}
	if err = validateAgentClientCertificate(certificate, caPEM, now); err != nil {
		return fmt.Errorf("validate enrolled agent identity: %w", err)
	}
	return nil
}

func validateAgentClientCertificate(certificate *x509.Certificate, caPEM []byte, now time.Time) error {
	if certificate == nil || certificate.IsCA {
		return errors.New("agent identity must be a leaf certificate")
	}
	if _, err := agentpki.ClusterIdentity(certificate); err != nil {
		return err
	}
	roots, _, err := agentpki.ValidateTrustBundle(caPEM, now)
	if err != nil {
		return fmt.Errorf("validate agent CA trust bundle: %w", err)
	}
	if _, err = certificate.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("verify agent client certificate: %w", err)
	}
	return nil
}

func writeIdentityFile(path string, data []byte, mode os.FileMode) error {
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(temporary, mode); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func identityPaths(directory string) (string, string, string) {
	identity := filepath.Join(directory, "identity.pem")
	return identity, identity, filepath.Join(directory, "ca.crt")
}

func mTLSClient(directory string) (*http.Client, error) {
	certPath, keyPath, caPath := identityPaths(directory)
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("invalid saved agent CA")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{certificate}}}
	return &http.Client{Transport: transport, Timeout: 40 * time.Second, CheckRedirect: rejectRedirect}, nil
}

func (c *Client) loop(ctx context.Context) error {
	heartbeat := time.NewTicker(30 * time.Second)
	poll := time.NewTicker(time.Second)
	rotation := time.NewTicker(time.Minute)
	defer heartbeat.Stop()
	defer poll.Stop()
	defer rotation.Stop()
	if err := c.heartbeat(ctx); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-heartbeat.C:
			_ = c.heartbeat(ctx)
		case <-rotation.C:
			client, err := rotateIfNeeded(ctx, c.cfg, c.http)
			if err != nil {
				if client == nil {
					return err
				}
				slog.Warn("agent certificate rotation deferred", "error", err)
				continue
			}
			c.http = client
		case <-poll.C:
			cmd, err := c.claim(ctx)
			if err != nil || cmd == nil {
				continue
			}
			c.execute(ctx, *cmd)
		}
	}
}

func (c *Client) heartbeat(ctx context.Context) error {
	nodes, err := c.swarm.Nodes(ctx)
	if err != nil {
		return err
	}
	dockerVersion := ""
	if len(nodes) > 0 {
		dockerVersion = nodes[0].EngineVersion
	}
	agentImage, agentUpdateState := "", ""
	if c.serviceState != nil {
		agentImage, agentUpdateState, err = c.serviceState(ctx)
		if err != nil {
			return err
		}
	}
	capacity := map[string]any{"nodes": len(nodes), "readyNodes": 0, "activeNodes": 0, "schedulableNodes": 0, "managers": 0, "nanoCpus": int64(0), "memoryBytes": int64(0)}
	for _, node := range nodes {
		if strings.EqualFold(node.Status, "ready") {
			capacity["readyNodes"] = capacity["readyNodes"].(int) + 1
		}
		if strings.EqualFold(node.Availability, "active") {
			capacity["activeNodes"] = capacity["activeNodes"].(int) + 1
		}
		if strings.EqualFold(node.Status, "ready") && strings.EqualFold(node.Availability, "active") {
			capacity["schedulableNodes"] = capacity["schedulableNodes"].(int) + 1
			capacity["nanoCpus"] = capacity["nanoCpus"].(int64) + node.NanoCPUs
			capacity["memoryBytes"] = capacity["memoryBytes"].(int64) + node.MemoryBytes
		}
		if node.ManagerStatus != "" {
			capacity["managers"] = capacity["managers"].(int) + 1
		}
	}
	var trust agentTrustUpdate
	if err := c.request(ctx, http.MethodPost, "/v1/agent/heartbeat", map[string]any{"agentVersion": c.cfg.Version, "agentImage": agentImage, "agentUpdateState": agentUpdateState, "dockerVersion": dockerVersion, "capacity": capacity}, &trust, ""); err != nil {
		return err
	}
	if trust.CACertificate == "" && trust.SigningCACertificate == "" {
		return nil
	}
	client, err := reconcileAgentTrust(ctx, c.cfg, c.http, []byte(trust.CACertificate), []byte(trust.SigningCACertificate))
	if err != nil {
		return err
	}
	c.http = client
	return nil
}

func reconcileAgentTrust(ctx context.Context, cfg Config, current *http.Client, trustBundle, signingCA []byte) (*http.Client, error) {
	if err := validateTrustUpdate(trustBundle, signingCA); err != nil {
		return current, err
	}
	_, signingAuthorities, _ := agentpki.ValidateTrustBundle(signingCA, time.Now())
	certPath, _, caPath := identityPaths(cfg.StateDirectory)
	pair, err := tls.LoadX509KeyPair(certPath, certPath)
	if err != nil || len(pair.Certificate) == 0 {
		return current, errors.New("load current agent identity")
	}
	certificate, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return current, errors.New("parse current agent identity")
	}
	existing, readErr := os.ReadFile(caPath)
	if readErr != nil || !bytes.Equal(bytes.TrimSpace(existing), bytes.TrimSpace(trustBundle)) {
		if err = writeIdentityFile(caPath, trustBundle, 0644); err != nil {
			return current, fmt.Errorf("save agent CA trust bundle: %w", err)
		}
		current, err = mTLSClient(cfg.StateDirectory)
		if err != nil {
			return nil, err
		}
	}
	if certificate.CheckSignatureFrom(signingAuthorities[0]) == nil {
		return current, nil
	}
	return rotateCertificate(ctx, cfg, current, true, signingCA)
}

func validateTrustUpdate(trustBundle, signingCA []byte) error {
	_, trusted, err := agentpki.ValidateTrustBundle(trustBundle, time.Now())
	if err != nil {
		return fmt.Errorf("validate agent CA trust update: %w", err)
	}
	_, signing, err := agentpki.ValidateTrustBundle(signingCA, time.Now())
	if err != nil || len(signing) != 1 {
		return errors.New("agent trust update has an invalid signing CA")
	}
	for _, certificate := range trusted {
		if certificate.Equal(signing[0]) {
			return nil
		}
	}
	return errors.New("agent trust update does not contain its signing CA")
}

func (c *Client) inspectServiceState(ctx context.Context) (string, string, error) {
	output, err := exec.CommandContext(ctx, c.cfg.DockerBin, "service", "inspect", "--format", "{{.Spec.TaskTemplate.ContainerSpec.Image}}|{{if .UpdateStatus}}{{.UpdateStatus.State}}{{end}}", c.cfg.ServiceName).CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("inspect agent service: %s: %w", strings.TrimSpace(string(output)), err)
	}
	parts := strings.SplitN(strings.TrimSpace(string(output)), "|", 2)
	if len(parts) != 2 || parts[0] == "" {
		return "", "", errors.New("inspect agent service returned invalid state")
	}
	return parts[0], parts[1], nil
}

func (c *Client) claim(ctx context.Context) (*command, error) {
	var cmd command
	err := c.request(ctx, http.MethodGet, "/v1/agent/commands/next", nil, &cmd, "")
	if errors.Is(err, errNoCommand) {
		return nil, nil
	}
	return &cmd, err
}

var errNoCommand = errors.New("no cluster command")

func (c *Client) execute(parent context.Context, cmd command) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if c.request(ctx, http.MethodPost, "/v1/agent/commands/"+cmd.ID.String()+"/lease", nil, nil, cmd.LeaseID.String()) != nil {
					cancel()
					return
				}
				_ = c.heartbeat(ctx)
			}
		}
	}()
	output, commandErr := c.executeCommand(ctx, cmd)
	close(done)
	result := map[string]string{"output": output}
	if commandErr != nil {
		result["error"] = commandErr.Error()
	}
	_ = c.request(parent, http.MethodPost, "/v1/agent/commands/"+cmd.ID.String()+"/complete", result, nil, cmd.LeaseID.String())
}

func (c *Client) executeCommand(ctx context.Context, cmd command) (string, error) {
	var payload struct {
		StackName          string             `json:"stackName"`
		VolumeName         string             `json:"volumeName"`
		Compose            string             `json:"compose"`
		Environment        map[string]string  `json:"environment"`
		Tail               int                `json:"tail"`
		Command            []string           `json:"command"`
		Network            string             `json:"network"`
		Image              string             `json:"image"`
		RegistryCredential *deploy.Credential `json:"registryCredential"`
	}
	if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
		return "", err
	}
	switch cmd.Kind {
	case "swarm.deploy":
		return c.swarm.Deploy(ctx, payload.StackName, payload.Compose, payload.Environment, payload.RegistryCredential)
	case "swarm.remove":
		return c.swarm.Remove(ctx, payload.StackName)
	case "swarm.prune-volumes":
		return c.swarm.RemoveVolumes(ctx, payload.StackName)
	case "swarm.logs":
		return c.swarm.Logs(ctx, payload.StackName, payload.Tail)
	case "swarm.status":
		inspector, ok := c.swarm.(deploy.StackInspector)
		if !ok {
			return "", errors.New("scheduler does not support stack inspection")
		}
		status, err := inspector.Status(ctx, payload.StackName)
		encoded, _ := json.Marshal(status)
		return string(encoded), err
	case "swarm.nodes":
		nodes, err := c.swarm.Nodes(ctx)
		encoded, _ := json.Marshal(nodes)
		return string(encoded), err
	case "swarm.storage-node":
		resolver, ok := c.swarm.(deploy.StorageNodeResolver)
		if !ok {
			return "", errors.New("scheduler does not support storage-node resolution")
		}
		return resolver.ResolveStorageNode(ctx, payload.StackName)
	case "swarm.volume-node":
		resolver, ok := c.swarm.(deploy.VolumeNodeResolver)
		if !ok {
			return "", errors.New("scheduler does not support volume-node resolution")
		}
		return resolver.ResolveVolumeNode(ctx, payload.StackName, payload.VolumeName)
	case "swarm.volume-artifact":
		var job deploy.VolumeArtifactJob
		if err := json.Unmarshal(cmd.Payload, &job); err != nil {
			return "", err
		}
		runner, ok := c.swarm.(deploy.VolumeArtifactRunner)
		if !ok {
			return "", errors.New("scheduler does not support volume artifact jobs")
		}
		result, err := runner.RunVolumeArtifact(ctx, job)
		encoded, _ := json.Marshal(result)
		return string(encoded), err
	case "container.run":
		return c.swarm.RunContainerJob(ctx, payload.Network, payload.Image, "", payload.Environment, payload.Command)
	case "database.utility":
		return c.executeArtifactJob(ctx, cmd.Payload)
	case "database.transfer":
		var job deploy.DatabaseTransferJob
		if err := json.Unmarshal(cmd.Payload, &job); err != nil {
			return "", err
		}
		if err := deploy.ValidateDatabaseTransferJob(job); err != nil {
			return "", err
		}
		transferScheduler, ok := c.swarm.(interface {
			RunDatabaseTransfer(context.Context, deploy.DatabaseTransferJob) (deploy.DatabaseTransferResult, error)
		})
		if !ok {
			return "", errors.New("scheduler does not support database transfers")
		}
		result, err := transferScheduler.RunDatabaseTransfer(ctx, job)
		encoded, _ := json.Marshal(result)
		return string(encoded), err
	case "agent.upgrade":
		if !digestImagePattern.MatchString(payload.Image) {
			return "", errors.New("agent upgrade image must be pinned by sha256 digest")
		}
		output, err := exec.CommandContext(ctx, c.cfg.DockerBin, "service", "update", "--detach=true", "--update-order", "start-first", "--with-registry-auth", "--image", payload.Image, c.cfg.ServiceName).CombinedOutput()
		return string(output), err
	default:
		return "", fmt.Errorf("unsupported command kind %q", cmd.Kind)
	}
}

var (
	serviceNamePattern           = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	endpointHostnameLabelPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$`)
)
var digestImagePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[a-f0-9]{64}$`)

func (c *Client) executeArtifactJob(ctx context.Context, raw json.RawMessage) (string, error) {
	var job deploy.RemoteArtifactJob
	if err := json.Unmarshal(raw, &job); err != nil {
		return "", err
	}
	if err := deploy.ValidateRemoteArtifactJob(job); err != nil {
		return "", err
	}
	key, err := base64.RawStdEncoding.DecodeString(job.EncryptionKey)
	if err != nil || len(key) != 32 {
		return "", errors.New("invalid artifact encryption key")
	}
	defer clear(key)
	box, err := cryptox.New(key)
	if err != nil {
		return "", err
	}
	directory, err := os.MkdirTemp(c.cfg.StateDirectory, "utility-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(directory)
	for name, contents := range job.Files {
		path := filepath.Join(directory, name)
		file, createErr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if createErr != nil {
			return "", createErr
		}
		_, writeErr := io.WriteString(file, contents)
		closeErr := file.Close()
		if writeErr != nil {
			return "", writeErr
		}
		if closeErr != nil {
			return "", closeErr
		}
	}
	plainPath := filepath.Join(directory, job.ArtifactName)
	encryptedPath := plainPath + ".enc"
	if job.Mode == "download" {
		if err = transfer(ctx, http.MethodGet, job.TransferURL, encryptedPath); err != nil {
			return "", err
		}
		if sum, size, hashErr := fileHash(encryptedPath); hashErr != nil || sum != job.SHA256 || (job.SizeBytes > 0 && size != job.SizeBytes) {
			if hashErr != nil {
				return "", hashErr
			}
			return "", errors.New("encrypted artifact checksum or size mismatch")
		}
		if err = transformFile(box, encryptedPath, plainPath, job.EncryptionAAD, false); err != nil {
			return "", err
		}
		if sum, _, hashErr := fileHash(plainPath); hashErr != nil || sum != job.PlaintextSHA256 {
			if hashErr != nil {
				return "", hashErr
			}
			return "", errors.New("plaintext artifact checksum mismatch")
		}
	}
	output, err := c.swarm.RunContainerJob(ctx, job.Network, job.Image, directory, job.Environment, job.Command)
	if err != nil {
		return output, err
	}
	result := deploy.RemoteArtifactResult{Output: output}
	if job.Mode == "upload" {
		result.PlaintextSHA256, _, err = fileHash(plainPath)
		if err == nil {
			err = transformFile(box, plainPath, encryptedPath, job.EncryptionAAD, true)
		}
		if err == nil {
			result.SHA256, result.SizeBytes, err = fileHash(encryptedPath)
		}
		if err == nil {
			err = transfer(ctx, http.MethodPut, job.TransferURL, encryptedPath)
		}
		if err != nil {
			return output, err
		}
	}
	encoded, err := json.Marshal(result)
	return string(encoded), err
}

func transfer(ctx context.Context, method, rawURL, filename string) error {
	var body io.ReadCloser
	if method == http.MethodPut {
		file, err := os.Open(filename)
		if err != nil {
			return err
		}
		body = file
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		if body != nil {
			_ = body.Close()
		}
		return err
	}
	if body != nil {
		info, statErr := os.Stat(filename)
		if statErr != nil {
			_ = body.Close()
			return statErr
		}
		req.ContentLength = info.Size()
		defer body.Close()
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("artifact redirects are disabled") }}
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return fmt.Errorf("artifact transfer returned HTTP %d", response.StatusCode)
	}
	if method == http.MethodGet {
		file, createErr := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if createErr != nil {
			return createErr
		}
		_, copyErr := io.Copy(file, response.Body)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	}
	return nil
}

func fileHash(filename string) (string, int64, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	return hex.EncodeToString(hash.Sum(nil)), size, err
}

func transformFile(box *cryptox.Box, source, destination, aad string, encrypt bool) (err error) {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(destination)
		}
		_ = output.Close()
	}()
	if encrypt {
		err = box.EncryptStream(output, input, aad)
	} else {
		err = box.DecryptStream(output, input, aad)
	}
	if err == nil {
		err = output.Sync()
	}
	return err
}

func (c *Client) request(ctx context.Context, method, path string, input, output any, leaseID string) error {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.cfg.AgentURL, "/")+path, body)
	if err != nil {
		return err
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if leaseID != "" {
		req.Header.Set("X-Dockyard-Lease-ID", leaseID)
	}
	response, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNoContent {
		if method == http.MethodGet {
			return errNoCommand
		}
		return nil
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("agent API returned HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(data)))
	}
	if output != nil {
		return json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(output)
	}
	return nil
}
