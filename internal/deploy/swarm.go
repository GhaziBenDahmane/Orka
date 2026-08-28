package deploy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Swarm struct {
	DockerBin string
	Network   string
	Timeout   time.Duration
}

// Scheduler is the execution boundary between the control plane and a Swarm
// manager. The local CLI adapter and outbound cluster agents implement the
// same contract so Compose remains the workload format in either topology.
type Scheduler interface {
	Deploy(context.Context, string, string, map[string]string, *Credential) (string, error)
	Remove(context.Context, string) (string, error)
	RemoveVolumes(context.Context, string) (string, error)
	Logs(context.Context, string, int) (string, error)
	Nodes(context.Context) ([]Node, error)
	RunContainerJob(context.Context, string, string, string, map[string]string, []string) (string, error)
}

var _ Scheduler = Swarm{}

type Node struct {
	ID            string `json:"id"`
	Hostname      string `json:"hostname"`
	Status        string `json:"status"`
	Availability  string `json:"availability"`
	ManagerStatus string `json:"managerStatus"`
	EngineVersion string `json:"engineVersion"`
	NanoCPUs      int64  `json:"nanoCpus"`
	MemoryBytes   int64  `json:"memoryBytes"`
}

func (s Swarm) EnsureReady(ctx context.Context) error {
	state, err := s.run(ctx, "info", "--format", "{{.Swarm.LocalNodeState}}")
	if err != nil {
		return fmt.Errorf("docker daemon unavailable: %w", err)
	}
	if strings.TrimSpace(state) != "active" {
		return errors.New("docker swarm is not active")
	}
	if _, err = s.run(ctx, "network", "inspect", s.Network); err == nil {
		return nil
	}
	_, err = s.run(ctx, "network", "create", "--driver", "overlay", "--attachable", s.Network)
	return err
}

func (s Swarm) Deploy(ctx context.Context, stackName, compose string, env map[string]string, registryCredential *Credential) (string, error) {
	if !safeName.MatchString(stackName) {
		return "", fmt.Errorf("invalid stack name %q", stackName)
	}
	if err := s.EnsureReady(ctx); err != nil {
		return "", err
	}
	directory, err := os.MkdirTemp("", "dockyard-stack-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(directory)
	compose, err = materializeInlineFiles(directory, compose)
	if err != nil {
		return "", err
	}
	path := filepath.Join(directory, "compose.yml")
	if err = os.WriteFile(path, []byte(compose), 0600); err != nil {
		return "", err
	}
	processEnv := make(map[string]string, len(env)+1)
	for key, value := range env {
		processEnv[key] = value
	}
	args := []string{"stack", "deploy", "--compose-file", path, "--prune", "--resolve-image", "always"}
	if registryCredential != nil && registryCredential.Secret != "" {
		configDirectory, configErr := writeDockerConfig(*registryCredential)
		if configErr != nil {
			return "", configErr
		}
		defer os.RemoveAll(configDirectory)
		processEnv["DOCKER_CONFIG"] = configDirectory
		args = append(args, "--with-registry-auth")
	}
	args = append(args, stackName)
	output, err := s.runEnv(ctx, processEnv, args...)
	if err != nil {
		return output, err
	}
	waitOutput, err := s.waitConverged(ctx, stackName)
	return output + waitOutput, err
}

func materializeInlineFiles(directory, compose string) (string, error) {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(compose), &doc); err != nil {
		return "", err
	}
	raw, ok := doc["x-dockyard-files"]
	if !ok {
		return compose, nil
	}
	files, ok := raw.(map[string]any)
	if !ok {
		return "", errors.New("x-dockyard-files must be an object")
	}
	targetDir := filepath.Join(directory, ".dockyard-files")
	if err := os.MkdirAll(targetDir, 0700); err != nil {
		return "", err
	}
	for name, value := range files {
		if !safeName.MatchString(name) {
			return "", fmt.Errorf("invalid inline file name %q", name)
		}
		content, ok := value.(string)
		if !ok {
			return "", fmt.Errorf("inline file %q must be a string", name)
		}
		if err := os.WriteFile(filepath.Join(targetDir, name), []byte(content), 0600); err != nil {
			return "", err
		}
	}
	delete(doc, "x-dockyard-files")
	out, err := yaml.Marshal(doc)
	return string(out), err
}

func (s Swarm) Remove(ctx context.Context, stackName string) (string, error) {
	if !safeName.MatchString(stackName) {
		return "", errors.New("invalid stack name")
	}
	output, err := s.run(ctx, "stack", "rm", stackName)
	if err != nil && (strings.Contains(output, "Nothing found in stack") || strings.Contains(err.Error(), "Nothing found in stack")) {
		return output, nil
	}
	return output, err
}

func (s Swarm) RemoveVolumes(ctx context.Context, stackName string) (string, error) {
	if !safeName.MatchString(stackName) {
		return "", errors.New("invalid stack name")
	}
	output, err := s.run(ctx, "volume", "ls", "--filter", "label=com.docker.stack.namespace="+stackName, "--format", "{{.Name}}")
	if err != nil {
		return output, err
	}
	var combined strings.Builder
	for _, volume := range strings.Fields(output) {
		if !strings.HasPrefix(volume, stackName+"_") {
			return combined.String(), fmt.Errorf("refusing to remove volume %q outside stack namespace", volume)
		}
		removed, removeErr := s.run(ctx, "volume", "rm", volume)
		combined.WriteString(removed)
		if removeErr != nil {
			return combined.String(), removeErr
		}
	}
	return combined.String(), nil
}

func (s Swarm) Logs(ctx context.Context, stackName string, tail int) (string, error) {
	if !safeName.MatchString(stackName) {
		return "", errors.New("invalid stack name")
	}
	if tail < 1 || tail > 5000 {
		tail = 500
	}
	services, err := s.run(ctx, "stack", "services", stackName, "--format", "{{.Name}}")
	if err != nil {
		return "", err
	}
	var all strings.Builder
	for _, service := range strings.Fields(services) {
		output, logErr := s.run(ctx, "service", "logs", "--raw", "--timestamps", "--tail", strconv.Itoa(tail), service)
		if logErr != nil {
			all.WriteString(logErr.Error())
		} else {
			all.WriteString(output)
		}
		all.WriteByte('\n')
	}
	return all.String(), nil
}

func (s Swarm) Nodes(ctx context.Context) ([]Node, error) {
	output, err := s.run(ctx, "node", "ls", "--format", "{{json .}}")
	if err != nil {
		return nil, err
	}
	items := []Node{}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line == "" {
			continue
		}
		var raw map[string]string
		if err = json.Unmarshal([]byte(line), &raw); err != nil {
			return nil, err
		}
		items = append(items, Node{ID: raw["ID"], Hostname: raw["Hostname"], Status: raw["Status"], Availability: raw["Availability"], ManagerStatus: raw["ManagerStatus"], EngineVersion: raw["EngineVersion"]})
	}
	for index := range items {
		resourceOutput, inspectErr := s.run(ctx, "node", "inspect", items[index].ID, "--format", "{{json .Description.Resources}}")
		if inspectErr != nil {
			return nil, fmt.Errorf("inspect node %s resources: %w", items[index].ID, inspectErr)
		}
		var resources struct {
			NanoCPUs    int64 `json:"NanoCPUs"`
			MemoryBytes int64 `json:"MemoryBytes"`
		}
		if err = json.Unmarshal([]byte(strings.TrimSpace(resourceOutput)), &resources); err != nil {
			return nil, fmt.Errorf("decode node %s resources: %w", items[index].ID, err)
		}
		items[index].NanoCPUs, items[index].MemoryBytes = resources.NanoCPUs, resources.MemoryBytes
	}
	return items, nil
}

func (s Swarm) RunContainerJob(ctx context.Context, network, image, mountSource string, environment map[string]string, command []string) (string, error) {
	if !safeName.MatchString(network) {
		return "", fmt.Errorf("invalid network name %q", network)
	}
	if len(command) == 0 || !safeName.MatchString(command[0]) {
		return "", errors.New("container job command is required")
	}
	// Official database tool images use different unprivileged UIDs. Run the
	// short-lived tool as container root so it can access the controller-owned
	// mode-0700 backup directory; the container has no Docker socket or host
	// mounts other than that directory.
	args := []string{"run", "--rm", "--user", "0:0", "--network", network}
	if mountSource != "" {
		args = append(args, "--volume", mountSource+":/backup")
	}
	args = append(args, "--entrypoint", command[0])
	keys := make([]string, 0, len(environment))
	for key := range environment {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		args = append(args, "--env", key)
	}
	args = append(args, image)
	args = append(args, command[1:]...)
	return s.runEnv(ctx, environment, args...)
}

func (s Swarm) waitConverged(parent context.Context, stack string) (string, error) {
	timeout := s.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	var last string
	for {
		output, err := s.run(ctx, "service", "ls", "--filter", "label=com.docker.stack.namespace="+stack, "--format", "{{.Name}} {{.Replicas}}")
		if err == nil && strings.TrimSpace(output) != "" {
			last = output
			all := true
			for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
				fields := strings.Fields(line)
				if len(fields) < 2 {
					all = false
					continue
				}
				parts := strings.SplitN(fields[len(fields)-1], "/", 2)
				if len(parts) != 2 {
					all = false
					continue
				}
				current, e1 := strconv.Atoi(parts[0])
				desired, e2 := strconv.Atoi(parts[1])
				if e1 != nil || e2 != nil || current != desired {
					all = false
				}
			}
			if all {
				return "\n" + last, nil
			}
		}
		select {
		case <-ctx.Done():
			return "\n" + last, fmt.Errorf("stack did not converge: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func (s Swarm) run(ctx context.Context, args ...string) (string, error) {
	return s.runEnv(ctx, nil, args...)
}
func (s Swarm) runEnv(ctx context.Context, env map[string]string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, s.DockerBin, args...)
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	if err != nil {
		return output.String(), fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(output.String()))
	}
	return output.String(), nil
}
