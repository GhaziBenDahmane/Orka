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
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

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
	cfg   Config
	swarm deploy.Scheduler
	http  *http.Client
}

type command struct {
	ID             uuid.UUID       `json:"id"`
	Kind           string          `json:"kind"`
	Payload        json.RawMessage `json:"payload"`
	LeaseID        uuid.UUID       `json:"leaseId"`
	LeaseExpiresAt time.Time       `json:"leaseExpiresAt"`
}

func Run(ctx context.Context, cfg Config) error {
	if cfg.EnrollmentURL == "" || cfg.AgentURL == "" || !filepath.IsAbs(cfg.StateDirectory) {
		return errors.New("agent enrollment URL, agent URL, and absolute state directory are required")
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
		return err
	}
	c := &Client{cfg: cfg, swarm: deploy.Swarm{DockerBin: cfg.DockerBin, Network: cfg.Network, Timeout: 5 * time.Minute}, http: httpClient}
	return c.loop(ctx)
}

func rotateIfNeeded(ctx context.Context, cfg Config, current *http.Client) (*http.Client, error) {
	certPath, keyPath, _ := identityPaths(cfg.StateDirectory)
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	certificate, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	if time.Until(certificate.NotAfter) > 24*time.Hour {
		return current, nil
	}
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "dockyard-agent"}}, key)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]string{"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(cfg.AgentURL, "/")+"/v1/agent/rotate", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := current.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return nil, fmt.Errorf("agent certificate rotation returned HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(data)))
	}
	var rotated struct {
		Certificate string `json:"certificate"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&rotated); err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	identityPEM := append([]byte(rotated.Certificate), keyPEM...)
	if err := writeIdentityFile(certPath, identityPEM, 0600); err != nil {
		return nil, err
	}
	return mTLSClient(cfg.StateDirectory)
}

func ensureIdentity(ctx context.Context, cfg Config) error {
	certPath, keyPath, caPath := identityPaths(cfg.StateDirectory)
	if pair, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil && len(pair.Certificate) > 0 {
		if certificate, parseErr := x509.ParseCertificate(pair.Certificate[0]); parseErr == nil && time.Until(certificate.NotAfter) > 0 {
			if ca, readErr := os.ReadFile(caPath); readErr == nil && len(ca) > 0 {
				return nil
			}
		}
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
	response, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
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
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	identityPEM := append([]byte(enrolled.Certificate), keyPEM...)
	if err := writeIdentityFile(certPath, identityPEM, 0600); err != nil {
		return err
	}
	return writeIdentityFile(caPath, []byte(enrolled.CACertificate), 0644)
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
	return &http.Client{Transport: transport, Timeout: 40 * time.Second}, nil
}

func (c *Client) loop(ctx context.Context) error {
	heartbeat := time.NewTicker(30 * time.Second)
	poll := time.NewTicker(time.Second)
	rotation := time.NewTicker(time.Hour)
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
				return err
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
	return c.request(ctx, http.MethodPost, "/v1/agent/heartbeat", map[string]any{"agentVersion": c.cfg.Version, "dockerVersion": dockerVersion, "capacity": capacity}, nil, "")
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

var serviceNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
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
	if response.StatusCode == http.StatusNoContent && method == http.MethodGet {
		return errNoCommand
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
