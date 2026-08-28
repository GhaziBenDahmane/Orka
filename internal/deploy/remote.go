package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

type RemoteSwarm struct {
	Store     *store.Store
	Box       *cryptox.Box
	ClusterID uuid.UUID
	Timeout   time.Duration
}

func (s RemoteSwarm) Deploy(ctx context.Context, stackName, compose string, environment map[string]string) (string, error) {
	return s.run(ctx, "swarm.deploy", map[string]any{"stackName": stackName, "compose": compose, "environment": environment})
}

func (s RemoteSwarm) Remove(ctx context.Context, stackName string) (string, error) {
	return s.run(ctx, "swarm.remove", map[string]any{"stackName": stackName})
}

func (s RemoteSwarm) Logs(ctx context.Context, stackName string, tail int) (string, error) {
	return s.run(ctx, "swarm.logs", map[string]any{"stackName": stackName, "tail": tail})
}

func (s RemoteSwarm) Nodes(ctx context.Context) ([]Node, error) {
	output, err := s.run(ctx, "swarm.nodes", map[string]any{})
	if err != nil {
		return nil, err
	}
	var nodes []Node
	return nodes, json.Unmarshal([]byte(output), &nodes)
}

func (s RemoteSwarm) RunContainerJob(context.Context, string, string, string, map[string]string, []string) (string, error) {
	return "", errors.New("remote database utility jobs require object-storage transport")
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
	if _, err = s.Store.EnqueueClusterCommand(ctx, s.ClusterID, commandID, kind, encrypted); err != nil {
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
