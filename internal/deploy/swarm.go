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
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bendahma/dokploy-go/internal/database"
	"github.com/bendahma/dokploy-go/internal/ociref"
	"gopkg.in/yaml.v3"
)

type Swarm struct {
	DockerBin string
	Network   string
	Timeout   time.Duration
	// ServiceName identifies the currently running, digest-pinned Dockyard or
	// agent service whose image is reused for privileged one-shot helpers.
	ServiceName string
}

// Scheduler is the execution boundary between the control plane and a Swarm
// manager. The local CLI adapter and outbound cluster agents implement the
// same contract so Compose remains the workload format in either topology.
type Scheduler interface {
	Deploy(context.Context, string, string, map[string]string, *Credential) (DeploymentResult, error)
	Remove(context.Context, string) (string, error)
	RemoveVolumes(context.Context, string) (string, error)
	Logs(context.Context, string, int) (string, error)
	Nodes(context.Context) ([]Node, error)
	RunContainerJob(context.Context, string, string, string, map[string]string, []string) (string, error)
}

// DeploymentResult carries operator-facing output and the image identities
// observed from Swarm so the controller can build an immutable snapshot.
type DeploymentResult struct {
	Output         string            `json:"output"`
	ResolvedImages map[string]string `json:"resolvedImages"`
}

type StackStatus struct {
	Exists          bool     `json:"exists"`
	Services        int      `json:"services"`
	HealthyServices int      `json:"healthyServices"`
	RunningTasks    int      `json:"runningTasks"`
	DesiredTasks    int      `json:"desiredTasks"`
	Degraded        []string `json:"degraded,omitempty"`
}

type StackInspector interface {
	Status(context.Context, string) (StackStatus, error)
}

type StorageNodeResolver interface {
	ResolveStorageNode(context.Context, string) (string, error)
}

type VolumeNodeResolver interface {
	ResolveVolumeNode(context.Context, string, string) (string, error)
}

var _ Scheduler = Swarm{}
var _ VolumeArtifactRunner = Swarm{}
var _ VolumeNodeResolver = Swarm{}

var safeRuntimeServiceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

const maxDockerCommandOutputBytes = 1 << 20

const dockerOutputTruncatedMarker = "\n...[docker output truncated]"

type boundedCommandOutput struct {
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func newBoundedCommandOutput(limit int) *boundedCommandOutput {
	return &boundedCommandOutput{limit: limit}
}

func (w *boundedCommandOutput) Write(value []byte) (int, error) {
	original := len(value)
	remaining := w.limit - w.buffer.Len()
	if remaining <= 0 {
		w.truncated = w.truncated || original > 0
		return original, nil
	}
	if len(value) > remaining {
		value = value[:remaining]
		w.truncated = true
	}
	_, _ = w.buffer.Write(value)
	return original, nil
}

func (w *boundedCommandOutput) String() string { return w.buffer.String() }

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
	properties, inspectErr := s.run(ctx, "network", "inspect", "--format", `{{.Driver}}|{{.Scope}}|{{.Attachable}}|{{json .Options}}`, s.Network)
	if inspectErr == nil {
		parts := strings.SplitN(strings.TrimSpace(properties), "|", 4)
		if len(parts) != 4 || parts[0] != "overlay" || parts[1] != "swarm" || parts[2] != "true" {
			return fmt.Errorf("Docker network %s must be an attachable Swarm overlay", s.Network)
		}
		var options map[string]string
		if json.Unmarshal([]byte(parts[3]), &options) != nil {
			return fmt.Errorf("inspect Docker network %s options", s.Network)
		}
		if _, encrypted := options["encrypted"]; !encrypted {
			return fmt.Errorf("Docker network %s must enable encrypted overlay traffic", s.Network)
		}
		return nil
	}
	_, err = s.run(ctx, "network", "create", "--driver", "overlay", "--opt", "encrypted", "--attachable", s.Network)
	return err
}

func (s Swarm) Deploy(ctx context.Context, stackName, compose string, env map[string]string, registryCredential *Credential) (DeploymentResult, error) {
	if !safeName.MatchString(stackName) {
		return DeploymentResult{}, fmt.Errorf("invalid stack name %q", stackName)
	}
	if err := s.EnsureReady(ctx); err != nil {
		return DeploymentResult{}, err
	}
	directory, err := os.MkdirTemp("", "dockyard-stack-*")
	if err != nil {
		return DeploymentResult{}, err
	}
	defer os.RemoveAll(directory)
	processEnv := make(map[string]string, len(env)+1)
	for key, value := range env {
		processEnv[key] = value
	}
	compose, err = materializeInlineFiles(directory, compose, processEnv)
	if err != nil {
		return DeploymentResult{}, err
	}
	path := filepath.Join(directory, "compose.yml")
	if err = os.WriteFile(path, []byte(compose), 0600); err != nil {
		return DeploymentResult{}, err
	}
	args := []string{"stack", "deploy", "--compose-file", path, "--prune", "--resolve-image", "always"}
	if registryCredential != nil && registryCredential.Secret != "" {
		configDirectory, configErr := writeDockerConfig(*registryCredential)
		if configErr != nil {
			return DeploymentResult{}, configErr
		}
		defer os.RemoveAll(configDirectory)
		processEnv["DOCKER_CONFIG"] = configDirectory
		args = append(args, "--with-registry-auth")
	}
	args = append(args, stackName)
	startedAt := time.Now().UTC()
	output, err := s.runEnv(ctx, processEnv, args...)
	if err != nil {
		return DeploymentResult{Output: output}, err
	}
	waitOutput, err := s.waitConverged(ctx, stackName, startedAt)
	result := DeploymentResult{Output: output + waitOutput}
	if err != nil {
		return result, err
	}
	result.ResolvedImages, err = s.captureResolvedImages(ctx, stackName)
	return result, err
}

func (s Swarm) captureResolvedImages(ctx context.Context, stackName string) (map[string]string, error) {
	output, err := s.run(ctx, "stack", "services", "--format", "{{.Name}}\t{{.Image}}", stackName)
	if err != nil {
		return nil, fmt.Errorf("inspect deployed images: %w", err)
	}
	images := map[string]string{}
	prefix := stackName + "_"
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 || !strings.HasPrefix(parts[0], prefix) || strings.TrimSpace(parts[1]) == "" {
			return nil, fmt.Errorf("inspect deployed images: unexpected service record %q", line)
		}
		images[strings.TrimPrefix(parts[0], prefix)] = strings.TrimSpace(parts[1])
	}
	if len(images) == 0 {
		return nil, errors.New("inspect deployed images: stack has no services")
	}
	return images, nil
}

func ApplyResolvedImages(compose string, images map[string]string) (string, error) {
	var document map[string]any
	if err := yaml.Unmarshal([]byte(compose), &document); err != nil {
		return "", fmt.Errorf("parse deployed Compose: %w", err)
	}
	services, ok := document["services"].(map[string]any)
	if !ok {
		return "", errors.New("parse deployed Compose: services must be an object")
	}
	changed := false
	for name, raw := range services {
		service, ok := raw.(map[string]any)
		if !ok {
			return "", fmt.Errorf("parse deployed Compose service %q", name)
		}
		if _, hasImage := service["image"]; !hasImage {
			continue
		}
		original, _ := service["image"].(string)
		image, found := images[name]
		if !found {
			image = original
		}
		if !ociref.IsDigestPinned(image) {
			return "", fmt.Errorf("inspect deployed images: service %q image is not digest-pinned", name)
		}
		if image != original {
			service["image"] = image
			changed = true
		}
	}
	if !changed {
		return compose, nil
	}
	encoded, err := yaml.Marshal(document)
	if err != nil {
		return "", fmt.Errorf("encode effective Compose: %w", err)
	}
	return string(encoded), nil
}

func materializeInlineFiles(directory, compose string, environment map[string]string) (string, error) {
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
	if len(files) == 0 || len(files) > MaxInlineFiles {
		return "", errors.New("x-dockyard-files exceeds entry limits")
	}
	targetDir := filepath.Join(directory, ".dockyard-files")
	if err := os.MkdirAll(targetDir, 0700); err != nil {
		return "", err
	}
	totalBytes := 0
	for name, value := range files {
		if !safeName.MatchString(name) {
			return "", fmt.Errorf("invalid inline file name %q", name)
		}
		reference, ok := value.(string)
		if !ok {
			return "", fmt.Errorf("inline file %q reference must be a string", name)
		}
		content := reference
		if environmentName := strings.TrimPrefix(reference, InlineFileReferencePrefix); environmentName != reference {
			if !inlineFileEnvironmentName.MatchString(environmentName) {
				return "", fmt.Errorf("inline file %q has an invalid encrypted reference", name)
			}
			var exists bool
			content, exists = environment[environmentName]
			if !exists {
				return "", fmt.Errorf("inline file %q encrypted content is unavailable", name)
			}
			delete(environment, environmentName)
		}
		if len(content) > MaxInlineFileBytes {
			return "", fmt.Errorf("inline file %q exceeds size limit", name)
		}
		totalBytes += len(content)
		if totalBytes > MaxInlineFilesBytes {
			return "", errors.New("inline files exceed total size limit")
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
	all := newBoundedCommandOutput(maxDockerCommandOutputBytes - len(dockerOutputTruncatedMarker))
	for _, service := range strings.Fields(services) {
		output, logErr := s.runAllowTruncated(ctx, "service", "logs", "--raw", "--timestamps", "--tail", strconv.Itoa(tail), service)
		if logErr != nil {
			_, _ = all.Write([]byte(logErr.Error()))
		} else {
			_, _ = all.Write([]byte(output))
		}
		_, _ = all.Write([]byte{'\n'})
		if all.truncated {
			break
		}
	}
	result := all.String()
	if all.truncated {
		result += dockerOutputTruncatedMarker
	}
	return result, nil
}

func (s Swarm) Status(ctx context.Context, stackName string) (StackStatus, error) {
	if !safeName.MatchString(stackName) {
		return StackStatus{}, errors.New("invalid stack name")
	}
	output, err := s.run(ctx, "service", "ls", "--filter", "label=com.docker.stack.namespace="+stackName, "--format", "{{.Name}} {{.Replicas}}")
	if err != nil {
		return StackStatus{}, err
	}
	status := StackStatus{Degraded: []string{}}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return StackStatus{}, fmt.Errorf("invalid Swarm service status %q", line)
		}
		parts := strings.SplitN(fields[1], "/", 2)
		if len(parts) != 2 {
			return StackStatus{}, fmt.Errorf("invalid replica status for service %s", fields[0])
		}
		running, runningErr := strconv.Atoi(parts[0])
		desired, desiredErr := strconv.Atoi(parts[1])
		if runningErr != nil || desiredErr != nil {
			return StackStatus{}, fmt.Errorf("invalid replica status for service %s", fields[0])
		}
		status.Exists = true
		status.Services++
		status.RunningTasks += running
		status.DesiredTasks += desired
		healthy := running == desired
		if len(fields) >= 4 && strings.HasPrefix(fields[2], "(") && fields[3] == "completed)" {
			completed := strings.TrimPrefix(fields[2], "(")
			completedParts := strings.SplitN(completed, "/", 2)
			if len(completedParts) == 2 {
				done, doneErr := strconv.Atoi(completedParts[0])
				total, totalErr := strconv.Atoi(completedParts[1])
				healthy = doneErr == nil && totalErr == nil && done == total
			}
		}
		if healthy {
			status.HealthyServices++
		} else {
			status.Degraded = append(status.Degraded, fields[0])
		}
	}
	return status, nil
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

// ResolveStorageNode returns the node already hosting a stack, or chooses a
// deterministic ready node before its first deployment. Existing multi-node
// stacks are rejected because their node-local volumes are ambiguous.
func (s Swarm) ResolveStorageNode(ctx context.Context, stackName string) (string, error) {
	if !safeName.MatchString(stackName) {
		return "", errors.New("invalid stack name")
	}
	servicesOutput, err := s.run(ctx, "service", "ls", "--filter", "label=com.docker.stack.namespace="+stackName, "--format", "{{.Name}}")
	if err != nil {
		return "", err
	}
	nodes, err := s.Nodes(ctx)
	if err != nil {
		return "", err
	}
	byHostname := make(map[string]string, len(nodes))
	for _, node := range nodes {
		byHostname[node.Hostname] = node.ID
	}
	services := strings.Fields(servicesOutput)
	if len(services) > 0 {
		assigned := map[string]bool{}
		for _, service := range services {
			if !safeRuntimeServiceName.MatchString(service) {
				return "", fmt.Errorf("invalid service name returned for stack %q", stackName)
			}
			output, inspectErr := s.run(ctx, "service", "ps", "--filter", "desired-state=running", "--format", "{{.Node}}", service)
			if inspectErr != nil {
				return "", inspectErr
			}
			for _, hostname := range strings.Fields(output) {
				nodeID := byHostname[hostname]
				if nodeID == "" {
					return "", fmt.Errorf("stack %q runs on unknown node %q", stackName, hostname)
				}
				assigned[nodeID] = true
			}
		}
		if len(assigned) != 1 {
			return "", fmt.Errorf("stack %q must have running tasks on exactly one storage node", stackName)
		}
		for nodeID := range assigned {
			return nodeID, nil
		}
	}
	candidates := make([]string, 0, len(nodes))
	for _, node := range nodes {
		if strings.EqualFold(node.Status, "ready") && strings.EqualFold(node.Availability, "active") && safeNodeID.MatchString(node.ID) {
			candidates = append(candidates, node.ID)
		}
	}
	if len(candidates) == 0 {
		return "", errors.New("no ready active Swarm node is available for database storage")
	}
	sort.Strings(candidates)
	return candidates[0], nil
}

func (s Swarm) ResolveVolumeNode(ctx context.Context, stackName, volumeName string) (string, error) {
	if !safeName.MatchString(stackName) || !safeVolumeSource.MatchString(volumeName) {
		return "", errors.New("invalid stack or volume name")
	}
	servicesOutput, err := s.run(ctx, "service", "ls", "--filter", "label=com.docker.stack.namespace="+stackName, "--format", "{{.Name}}")
	if err != nil {
		return "", err
	}
	nodes, err := s.Nodes(ctx)
	if err != nil {
		return "", err
	}
	byHostname := make(map[string]string, len(nodes))
	for _, node := range nodes {
		byHostname[node.Hostname] = node.ID
	}
	assigned, mounted := map[string]bool{}, false
	for _, service := range strings.Fields(servicesOutput) {
		if !safeRuntimeServiceName.MatchString(service) {
			return "", fmt.Errorf("invalid service name returned for stack %q", stackName)
		}
		mountsJSON, inspectErr := s.run(ctx, "service", "inspect", "--format", "{{json .Spec.TaskTemplate.ContainerSpec.Mounts}}", service)
		if inspectErr != nil {
			return "", inspectErr
		}
		var mounts []struct{ Type, Source string }
		if err = json.Unmarshal([]byte(strings.TrimSpace(mountsJSON)), &mounts); err != nil {
			return "", fmt.Errorf("decode mounts for service %q: %w", service, err)
		}
		usesVolume := false
		for _, mount := range mounts {
			if strings.EqualFold(mount.Type, "volume") && mount.Source == volumeName {
				usesVolume, mounted = true, true
				break
			}
		}
		if !usesVolume {
			continue
		}
		output, inspectErr := s.run(ctx, "service", "ps", "--filter", "desired-state=running", "--format", "{{.Node}}", service)
		if inspectErr != nil {
			return "", inspectErr
		}
		for _, hostname := range strings.Fields(output) {
			nodeID := byHostname[hostname]
			if nodeID == "" {
				return "", fmt.Errorf("volume %q is mounted on unknown node %q", volumeName, hostname)
			}
			assigned[nodeID] = true
		}
	}
	if !mounted || len(assigned) != 1 {
		return "", fmt.Errorf("volume %q must have running tasks on exactly one storage node", volumeName)
	}
	for nodeID := range assigned {
		return nodeID, nil
	}
	return "", errors.New("volume storage node could not be resolved")
}

func (s Swarm) RunContainerJob(ctx context.Context, network, image, mountSource string, environment map[string]string, command []string) (string, error) {
	if !safeName.MatchString(network) {
		return "", fmt.Errorf("invalid network name %q", network)
	}
	if err := database.ValidateUtilityPlan(database.BackupPlan{Image: image, Command: command, Environment: environment}); err != nil {
		return "", err
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

func (s Swarm) RunDatabaseTransfer(ctx context.Context, job DatabaseTransferJob) (DatabaseTransferResult, error) {
	var result DatabaseTransferResult
	if err := ValidateDatabaseTransferJob(job); err != nil {
		return result, err
	}
	directory, err := os.MkdirTemp("", "dockyard-database-transfer-*")
	if err != nil {
		return result, err
	}
	defer os.RemoveAll(directory)
	if err = writePlanFiles(directory, job.Backup.Files); err != nil {
		return result, err
	}
	backupOutput, err := s.RunContainerJob(ctx, job.Network, job.Backup.Image, directory, job.Backup.Environment, job.Backup.Command)
	result.Output = backupOutput
	removePlanFiles(directory, job.Backup.Files)
	if err != nil {
		return result, fmt.Errorf("source backup failed: %w", err)
	}
	artifactPath := filepath.Join(directory, job.ArtifactName)
	result.SHA256, result.SizeBytes, err = checksumFile(artifactPath)
	if err != nil || result.SizeBytes == 0 {
		if err == nil {
			err = errors.New("source backup produced an empty artifact")
		}
		return result, err
	}
	if err = writePlanFiles(directory, job.Restore.Files); err != nil {
		return result, err
	}
	defer removePlanFiles(directory, job.Restore.Files)
	restoreOutput, err := s.RunContainerJob(ctx, job.Network, job.Restore.Image, directory, job.Restore.Environment, job.Restore.Command)
	result.Output += restoreOutput
	if err != nil {
		return result, fmt.Errorf("target restore failed: %w", err)
	}
	return result, nil
}

func (s Swarm) waitConverged(parent context.Context, stack string, startedAt time.Time) (string, error) {
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
		done, output, err := s.convergenceStatus(ctx, stack, startedAt)
		if output != "" {
			last = output
		}
		if err != nil {
			var terminal *rolloutFailure
			if errors.As(err, &terminal) {
				return "\n" + last, err
			}
		} else if done {
			return "\n" + last, nil
		}
		select {
		case <-ctx.Done():
			if err != nil {
				return "\n" + last, fmt.Errorf("stack did not converge: %w: last inspection: %v", ctx.Err(), err)
			}
			return "\n" + last, fmt.Errorf("stack did not converge: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

type rolloutFailure struct{ message string }

func (e *rolloutFailure) Error() string { return e.message }

type swarmUpdateStatus struct {
	State     string    `json:"State"`
	Message   string    `json:"Message"`
	StartedAt time.Time `json:"StartedAt"`
}

func (s Swarm) convergenceStatus(ctx context.Context, stack string, startedAt time.Time) (bool, string, error) {
	output, err := s.run(ctx, "service", "ls", "--filter", "label=com.docker.stack.namespace="+stack, "--format", "{{.Name}} {{.Replicas}}")
	if err != nil {
		return false, output, err
	}
	if strings.TrimSpace(output) == "" {
		return false, output, errors.New("stack has no services")
	}
	all := true
	var details strings.Builder
	details.WriteString(output)
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return false, details.String(), &rolloutFailure{message: fmt.Sprintf("invalid Swarm service status %q", line)}
		}
		parts := strings.SplitN(fields[1], "/", 2)
		if len(parts) != 2 {
			return false, details.String(), &rolloutFailure{message: fmt.Sprintf("invalid replica status for service %s", fields[0])}
		}
		current, currentErr := strconv.Atoi(parts[0])
		desired, desiredErr := strconv.Atoi(parts[1])
		if currentErr != nil || desiredErr != nil || current != desired {
			all = false
		}

		statusJSON, inspectErr := s.run(ctx, "service", "inspect", fields[0], "--format", "{{json .UpdateStatus}}")
		if inspectErr != nil {
			return false, details.String(), inspectErr
		}
		statusJSON = strings.TrimSpace(statusJSON)
		if statusJSON == "" || statusJSON == "null" || statusJSON == "<nil>" {
			continue
		}
		var status swarmUpdateStatus
		if err = json.Unmarshal([]byte(statusJSON), &status); err != nil {
			return false, details.String(), &rolloutFailure{message: fmt.Sprintf("decode update status for service %s: %v", fields[0], err)}
		}
		details.WriteString(fmt.Sprintf("%s update=%s message=%s\n", fields[0], status.State, status.Message))
		if !startedAt.IsZero() && !status.StartedAt.IsZero() && status.StartedAt.Before(startedAt) {
			continue
		}
		switch status.State {
		case "", "completed":
		case "updating", "rollback_started":
			all = false
		case "paused", "rollback_paused", "rollback_completed":
			return false, details.String(), &rolloutFailure{message: fmt.Sprintf("service %s update entered %s: %s", fields[0], status.State, status.Message)}
		default:
			return false, details.String(), &rolloutFailure{message: fmt.Sprintf("service %s returned unknown update state %q", fields[0], status.State)}
		}
	}
	return all, details.String(), nil
}

func (s Swarm) run(ctx context.Context, args ...string) (string, error) {
	return s.runEnvMode(ctx, nil, false, args...)
}
func (s Swarm) runEnv(ctx context.Context, env map[string]string, args ...string) (string, error) {
	return s.runEnvMode(ctx, env, false, args...)
}
func (s Swarm) runAllowTruncated(ctx context.Context, args ...string) (string, error) {
	return s.runEnvMode(ctx, nil, true, args...)
}
func (s Swarm) runEnvMode(ctx context.Context, env map[string]string, allowTruncated bool, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, s.DockerBin, args...)
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	output := newBoundedCommandOutput(maxDockerCommandOutputBytes - len(dockerOutputTruncatedMarker))
	cmd.Stdout = output
	cmd.Stderr = output
	err := cmd.Run()
	captured := output.String()
	if output.truncated {
		captured += dockerOutputTruncatedMarker
	}
	if err != nil {
		return captured, fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(captured))
	}
	if output.truncated && !allowTruncated {
		return captured, fmt.Errorf("docker %s: output exceeded %d bytes", strings.Join(args, " "), maxDockerCommandOutputBytes)
	}
	return captured, nil
}
