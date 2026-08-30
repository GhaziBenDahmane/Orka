package deploy

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/database"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/bendahma/dokploy-go/internal/volumeartifact"
	"github.com/google/uuid"
)

type RemoteSwarm struct {
	Store     *store.Store
	Box       *cryptox.Box
	ClusterID uuid.UUID
	Timeout   time.Duration
}

type remoteCommandOwner struct {
	jobID   uuid.UUID
	leaseID uuid.UUID
}

type remoteCommandOwnerContextKey struct{}

func withRemoteCommandOwner(ctx context.Context, jobID, leaseID uuid.UUID) context.Context {
	return context.WithValue(ctx, remoteCommandOwnerContextKey{}, remoteCommandOwner{jobID: jobID, leaseID: leaseID})
}

func remoteCommandOwnerFromContext(ctx context.Context) (remoteCommandOwner, bool) {
	owner, ok := ctx.Value(remoteCommandOwnerContextKey{}).(remoteCommandOwner)
	return owner, ok && owner.jobID != uuid.Nil && owner.leaseID != uuid.Nil
}

func (s RemoteSwarm) Deploy(ctx context.Context, stackName, compose string, environment map[string]string, registryCredential *Credential) (DeploymentResult, error) {
	output, err := s.run(ctx, "swarm.deploy", map[string]any{"stackName": stackName, "compose": compose, "environment": environment, "registryCredential": registryCredential})
	if err != nil {
		return DeploymentResult{}, err
	}
	var result DeploymentResult
	if err = json.Unmarshal([]byte(output), &result); err != nil {
		return DeploymentResult{}, fmt.Errorf("decode remote deployment result: %w", err)
	}
	return result, nil
}

func (s RemoteSwarm) Remove(ctx context.Context, stackName string) (string, error) {
	return s.run(ctx, "swarm.remove", map[string]any{"stackName": stackName})
}

func (s RemoteSwarm) RemoveVolumes(ctx context.Context, stackName string) (string, error) {
	return s.run(ctx, "swarm.prune-volumes", map[string]any{"stackName": stackName})
}

func (s RemoteSwarm) Logs(ctx context.Context, stackName string, tail int) (string, error) {
	return s.run(ctx, "swarm.logs", map[string]any{"stackName": stackName, "tail": tail})
}

func (s RemoteSwarm) Status(ctx context.Context, stackName string) (StackStatus, error) {
	output, err := s.run(ctx, "swarm.status", map[string]any{"stackName": stackName})
	if err != nil {
		return StackStatus{}, err
	}
	var status StackStatus
	if err = json.Unmarshal([]byte(output), &status); err != nil {
		return StackStatus{}, fmt.Errorf("decode remote stack status: %w", err)
	}
	return status, nil
}

func (s RemoteSwarm) Nodes(ctx context.Context) ([]Node, error) {
	output, err := s.run(ctx, "swarm.nodes", map[string]any{})
	if err != nil {
		return nil, err
	}
	var nodes []Node
	return nodes, json.Unmarshal([]byte(output), &nodes)
}

func (s RemoteSwarm) ResolveStorageNode(ctx context.Context, stackName string) (string, error) {
	return s.run(ctx, "swarm.storage-node", map[string]string{"stackName": stackName})
}

func (s RemoteSwarm) ResolveVolumeNode(ctx context.Context, stackName, volumeName string) (string, error) {
	return s.run(ctx, "swarm.volume-node", map[string]string{"stackName": stackName, "volumeName": volumeName})
}

func (s RemoteSwarm) RunContainerJob(ctx context.Context, network, image, mountSource string, environment map[string]string, command []string) (string, error) {
	if mountSource != "" {
		return "", errors.New("remote container jobs cannot mount controller paths")
	}
	if err := database.ValidateUtilityPlan(database.BackupPlan{Image: image, Command: command, Environment: environment}); err != nil {
		return "", err
	}
	return s.run(ctx, "container.run", map[string]any{"network": network, "image": image, "environment": environment, "command": command})
}

type RemoteArtifactJob struct {
	Mode            string            `json:"mode"`
	Network         string            `json:"network"`
	Image           string            `json:"image"`
	Environment     map[string]string `json:"environment"`
	Command         []string          `json:"command"`
	Files           map[string]string `json:"files,omitempty"`
	ArtifactName    string            `json:"artifactName"`
	TransferURL     string            `json:"transferUrl"`
	EncryptionKey   string            `json:"encryptionKey"`
	EncryptionAAD   string            `json:"encryptionAad"`
	SHA256          string            `json:"sha256,omitempty"`
	PlaintextSHA256 string            `json:"plaintextSha256,omitempty"`
	SizeBytes       int64             `json:"sizeBytes,omitempty"`
}

type RemoteArtifactResult struct {
	Output          string `json:"output"`
	SHA256          string `json:"sha256"`
	PlaintextSHA256 string `json:"plaintextSha256"`
	SizeBytes       int64  `json:"sizeBytes"`
}

const (
	MaxRemoteCommandOutputBytes  = 1 << 20
	MaxRemoteCommandErrorBytes   = 8 << 10
	MaxRemoteCommandRequestBytes = 8 << 20
)

type DatabaseTransferJob struct {
	Network      string               `json:"network"`
	ArtifactName string               `json:"artifactName"`
	Backup       database.BackupPlan  `json:"backup"`
	Restore      database.RestorePlan `json:"restore"`
}

type DatabaseTransferResult struct {
	Output    string `json:"output"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"sizeBytes"`
}

func (s RemoteSwarm) RunArtifactJob(ctx context.Context, job RemoteArtifactJob) (RemoteArtifactResult, error) {
	var result RemoteArtifactResult
	if err := ValidateRemoteArtifactJob(job); err != nil {
		return result, err
	}
	output, err := s.run(ctx, "database.utility", job)
	if err != nil {
		return result, err
	}
	if err = json.Unmarshal([]byte(output), &result); err != nil {
		return result, fmt.Errorf("decode remote artifact result: %w", err)
	}
	return result, nil
}

func (s RemoteSwarm) RunVolumeArtifact(ctx context.Context, job VolumeArtifactJob) (volumeartifact.Result, error) {
	var result volumeartifact.Result
	if err := ValidateVolumeArtifactJob(job); err != nil {
		return result, err
	}
	output, err := s.run(ctx, "swarm.volume-artifact", job)
	if err != nil {
		return result, err
	}
	if err = json.Unmarshal([]byte(output), &result); err != nil {
		return result, fmt.Errorf("decode remote volume artifact result: %w", err)
	}
	return result, nil
}

func (s RemoteSwarm) RunDatabaseTransfer(ctx context.Context, job DatabaseTransferJob) (DatabaseTransferResult, error) {
	var result DatabaseTransferResult
	if err := ValidateDatabaseTransferJob(job); err != nil {
		return result, err
	}
	if s.Timeout < 2*time.Hour {
		s.Timeout = 2 * time.Hour
	}
	output, err := s.run(ctx, "database.transfer", job)
	if err != nil {
		return result, err
	}
	if err = json.Unmarshal([]byte(output), &result); err != nil {
		return result, fmt.Errorf("decode remote database transfer result: %w", err)
	}
	return result, nil
}

func ValidateRemoteArtifactJob(job RemoteArtifactJob) error {
	if job.Mode != "upload" && job.Mode != "download" {
		return errors.New("invalid artifact transfer mode")
	}
	if !safeName.MatchString(job.Network) {
		return errors.New("invalid artifact network")
	}
	if err := database.ValidateUtilityFileName(job.ArtifactName); err != nil {
		return errors.New("invalid artifact name")
	}
	if _, exists := job.Files[job.ArtifactName]; exists {
		return errors.New("utility file conflicts with artifact name")
	}
	parsed, err := url.Parse(job.TransferURL)
	if err != nil || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return errors.New("artifact transfer URL must be HTTP(S) without credentials or a fragment")
	}
	key, err := base64.RawStdEncoding.DecodeString(job.EncryptionKey)
	if err != nil || len(key) != 32 || job.EncryptionAAD == "" {
		return errors.New("invalid artifact encryption parameters")
	}
	if job.Mode == "download" {
		sha256Bytes, sha256Err := hex.DecodeString(job.SHA256)
		plaintextBytes, plaintextErr := hex.DecodeString(job.PlaintextSHA256)
		if job.SizeBytes <= 0 || sha256Err != nil || len(sha256Bytes) != 32 || plaintextErr != nil || len(plaintextBytes) != 32 {
			return errors.New("artifact download requires SHA-256 checksums and size")
		}
	}
	return database.ValidateUtilityPlan(database.BackupPlan{Image: job.Image, Command: job.Command, Environment: job.Environment, Files: job.Files})
}

func ValidateDatabaseTransferJob(job DatabaseTransferJob) error {
	if !safeName.MatchString(job.Network) {
		return errors.New("invalid database transfer network")
	}
	if err := database.ValidateUtilityFileName(job.ArtifactName); err != nil {
		return errors.New("invalid database transfer artifact name")
	}
	if _, exists := job.Backup.Files[job.ArtifactName]; exists {
		return errors.New("backup utility file conflicts with artifact name")
	}
	if _, exists := job.Restore.Files[job.ArtifactName]; exists {
		return errors.New("restore utility file conflicts with artifact name")
	}
	if err := database.ValidateUtilityPlan(job.Backup); err != nil {
		return fmt.Errorf("invalid backup utility plan: %w", err)
	}
	if err := database.ValidateUtilityPlan(job.Restore); err != nil {
		return fmt.Errorf("invalid restore utility plan: %w", err)
	}
	return nil
}

func (s RemoteSwarm) run(ctx context.Context, kind string, payload any) (string, error) {
	commandID := uuid.New()
	plain, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	encrypted, err := s.Box.Encrypt(plain, "cluster-command:"+commandID.String())
	if err != nil {
		return "", err
	}
	if owner, owned := remoteCommandOwnerFromContext(ctx); owned {
		_, err = s.Store.EnqueueOwnedClusterCommand(ctx, s.ClusterID, commandID, kind, encrypted, owner.jobID, owner.leaseID)
	} else {
		_, err = s.Store.EnqueueClusterCommand(ctx, s.ClusterID, commandID, kind, encrypted)
	}
	if err != nil {
		return "", err
	}
	timeout := s.Timeout
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	completed := false
	defer func() {
		if !completed {
			_ = s.Store.CancelClusterCommand(context.Background(), s.ClusterID, commandID)
		}
	}()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		command, err := s.Store.GetClusterCommand(waitCtx, s.ClusterID, commandID)
		if err != nil {
			return "", err
		}
		switch command.Status {
		case "succeeded":
			result, err := s.result(command)
			if err != nil {
				return "", err
			}
			completed = true
			return result.Output, nil
		case "failed", "cancelled":
			completed = true
			result, decryptErr := s.result(command)
			if decryptErr == nil && result.Error != "" {
				return result.Output, fmt.Errorf("remote %s failed: %s", kind, result.Error)
			}
			return "", fmt.Errorf("remote %s failed: %s", kind, command.LastError)
		}
		select {
		case <-waitCtx.Done():
			return "", fmt.Errorf("wait for remote %s: %w", kind, waitCtx.Err())
		case <-ticker.C:
		}
	}
}

type commandResult struct {
	Output string `json:"output"`
	Error  string `json:"error"`
}

func (s RemoteSwarm) result(command store.ClusterCommand) (commandResult, error) {
	var result commandResult
	if command.EncryptedResult == "" {
		return result, errors.New(command.LastError)
	}
	plain, err := s.Box.Decrypt(command.EncryptedResult, "cluster-command-result:"+command.ID.String())
	if err != nil {
		return result, err
	}
	return result, json.Unmarshal(plain, &result)
}

var _ Scheduler = RemoteSwarm{}
var _ VolumeArtifactRunner = RemoteSwarm{}
var _ VolumeNodeResolver = RemoteSwarm{}
