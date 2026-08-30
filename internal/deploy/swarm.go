package deploy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
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
	DockerBin                         string
	Network                           string
	Timeout                           time.Duration
	EdgeProxyServiceName              string
	EdgeProxyDynamicConfigurationPath string
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

// ServiceCommandRunner executes a bounded command inside one running task of a
// Compose service. It is optional so storage-only schedulers remain small.
type ServiceCommandRunner interface {
	RunServiceCommand(context.Context, string, string, string, string) (string, error)
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

type NetworkIPAMConfig struct {
	Subnet  string `json:"subnet,omitempty"`
	Gateway string `json:"gateway,omitempty"`
	IPRange string `json:"ipRange,omitempty"`
}

type ManagedNetworkSpec struct {
	ID         string              `json:"id"`
	Name       string              `json:"name"`
	Driver     string              `json:"driver"`
	Internal   bool                `json:"internal"`
	Attachable bool                `json:"attachable"`
	EnableIPv4 bool                `json:"enableIpv4"`
	EnableIPv6 bool                `json:"enableIpv6"`
	MTU        *int                `json:"mtu,omitempty"`
	IPAM       []NetworkIPAMConfig `json:"ipam"`
}

type ManagedNetworkResult struct {
	DockerID string `json:"dockerId"`
}

type NetworkManager interface {
	CreateManagedNetwork(context.Context, ManagedNetworkSpec) (ManagedNetworkResult, error)
	RemoveManagedNetwork(context.Context, ManagedNetworkSpec) error
}

var _ Scheduler = Swarm{}
var _ ServiceCommandRunner = Swarm{}
var _ VolumeArtifactRunner = Swarm{}
var _ VolumeNodeResolver = Swarm{}
var _ NetworkManager = Swarm{}

var safeRuntimeServiceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var safeManagedNetworkName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

var reservedManagedNetworkNames = map[string]bool{"bridge": true, "host": true, "none": true, "ingress": true, "docker_gwbridge": true}
var errManagedNetworkNotFound = errors.New("managed Docker network not found")

const maxDockerCommandOutputBytes = 1 << 20

const dockerOutputTruncatedMarker = "\n...[docker output truncated]"

func ValidateManagedNetworkSpec(spec ManagedNetworkSpec) error {
	if spec.ID == "" || !safeManagedNetworkName.MatchString(spec.Name) || reservedManagedNetworkNames[spec.Name] {
		return errors.New("invalid or reserved managed network name")
	}
	if spec.Driver != "overlay" && spec.Driver != "bridge" {
		return errors.New("managed network driver must be overlay or bridge")
	}
	if !spec.EnableIPv4 && !spec.EnableIPv6 {
		return errors.New("managed network must enable IPv4 or IPv6")
	}
	if spec.MTU != nil && (*spec.MTU < 576 || *spec.MTU > 65535) {
		return errors.New("managed network MTU must be between 576 and 65535")
	}
	if len(spec.IPAM) > 8 {
		return errors.New("managed network may define at most 8 IPAM ranges")
	}
	for _, config := range spec.IPAM {
		if config.Subnet == "" {
			if config.Gateway != "" || config.IPRange != "" {
				return errors.New("managed network gateway and IP range require a subnet")
			}
			continue
		}
		subnet, err := netip.ParsePrefix(config.Subnet)
		if err != nil || subnet.Masked().String() != config.Subnet {
			return errors.New("managed network subnet must be a canonical CIDR")
		}
		if config.Gateway != "" {
			address, parseErr := netip.ParseAddr(config.Gateway)
			if parseErr != nil || !subnet.Contains(address) {
				return errors.New("managed network gateway must be an address within the subnet")
			}
		}
		if config.IPRange != "" {
			rangePrefix, parseErr := netip.ParsePrefix(config.IPRange)
			if parseErr != nil || rangePrefix.Masked().String() != config.IPRange || rangePrefix.Addr().BitLen() != subnet.Addr().BitLen() || rangePrefix.Bits() < subnet.Bits() || !subnet.Contains(rangePrefix.Addr()) {
				return errors.New("managed network IP range must be a canonical CIDR within the subnet")
			}
		}
	}
	return nil
}

func (s Swarm) CreateManagedNetwork(ctx context.Context, spec ManagedNetworkSpec) (ManagedNetworkResult, error) {
	if err := ValidateManagedNetworkSpec(spec); err != nil {
		return ManagedNetworkResult{}, err
	}
	if err := s.EnsureReady(ctx); err != nil {
		return ManagedNetworkResult{}, err
	}
	if current, err := s.inspectManagedNetwork(ctx, spec.Name); err == nil {
		if current.Labels["com.dockyard.network-id"] != spec.ID {
			return ManagedNetworkResult{}, fmt.Errorf("Docker network %s already exists and is not owned by this resource", spec.Name)
		}
		if current.Driver != spec.Driver || current.Internal != spec.Internal || current.Attachable != spec.Attachable || current.EnableIPv6 != spec.EnableIPv6 {
			return ManagedNetworkResult{}, fmt.Errorf("Docker network %s configuration drift requires deletion and recreation", spec.Name)
		}
		return ManagedNetworkResult{DockerID: current.ID}, nil
	} else if !errors.Is(err, errManagedNetworkNotFound) {
		return ManagedNetworkResult{}, err
	}
	args := []string{"network", "create", "--driver", spec.Driver, "--label", "com.dockyard.managed=true", "--label", "com.dockyard.network-id=" + spec.ID}
	if spec.Internal {
		args = append(args, "--internal")
	}
	if spec.Attachable {
		args = append(args, "--attachable")
	}
	if !spec.EnableIPv4 {
		args = append(args, "--ipv4=false")
	}
	if spec.EnableIPv6 {
		args = append(args, "--ipv6")
	}
	if spec.Driver == "overlay" {
		args = append(args, "--opt", "encrypted")
	}
	if spec.MTU != nil {
		args = append(args, "--opt", "com.docker.network.driver.mtu="+strconv.Itoa(*spec.MTU))
	}
	for _, config := range spec.IPAM {
		if config.Subnet != "" {
			args = append(args, "--subnet", config.Subnet)
		}
		if config.Gateway != "" {
			args = append(args, "--gateway", config.Gateway)
		}
		if config.IPRange != "" {
			args = append(args, "--ip-range", config.IPRange)
		}
	}
	args = append(args, spec.Name)
	id, err := s.run(ctx, args...)
	return ManagedNetworkResult{DockerID: strings.TrimSpace(id)}, err
}

func (s Swarm) RemoveManagedNetwork(ctx context.Context, spec ManagedNetworkSpec) error {
	if err := ValidateManagedNetworkSpec(spec); err != nil {
		return err
	}
	current, err := s.inspectManagedNetwork(ctx, spec.Name)
	if errors.Is(err, errManagedNetworkNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if current.Labels["com.dockyard.network-id"] != spec.ID {
		return fmt.Errorf("refusing to remove Docker network %s because ownership does not match", spec.Name)
	}
	_, err = s.run(ctx, "network", "rm", current.ID)
	return err
}

type inspectedManagedNetwork struct {
	ID         string            `json:"Id"`
	Name       string            `json:"Name"`
	Driver     string            `json:"Driver"`
	Internal   bool              `json:"Internal"`
	Attachable bool              `json:"Attachable"`
	EnableIPv6 bool              `json:"EnableIPv6"`
	Labels     map[string]string `json:"Labels"`
}

func (s Swarm) inspectManagedNetwork(ctx context.Context, name string) (inspectedManagedNetwork, error) {
	output, err := s.run(ctx, "network", "inspect", name)
	if err != nil {
		if strings.Contains(strings.ToLower(output+" "+err.Error()), "no such network") {
			return inspectedManagedNetwork{}, errManagedNetworkNotFound
		}
		return inspectedManagedNetwork{}, err
	}
	var items []inspectedManagedNetwork
	if err = json.Unmarshal([]byte(output), &items); err != nil || len(items) != 1 {
		return inspectedManagedNetwork{}, errors.New("decode Docker network inspection")
	}
	return items[0], nil
}

func (s Swarm) RunServiceCommand(ctx context.Context, stackName, targetService, shell, command string) (string, error) {
	if !safeName.MatchString(stackName) || !safeRuntimeServiceName.MatchString(targetService) {
		return "", errors.New("invalid scheduled-command target")
	}
	if shell != "sh" && shell != "bash" {
		return "", errors.New("scheduled-command shell must be sh or bash")
	}
	if command == "" || len(command) > 16384 || strings.ContainsRune(command, 0) {
		return "", errors.New("scheduled command must contain 1 to 16384 bytes")
	}
	if err := s.EnsureReady(ctx); err != nil {
		return "", err
	}
	serviceName := stackName + "_" + targetService
	taskState, err := s.run(ctx, "service", "ps", "--filter", "desired-state=running", "--format", "{{.CurrentState}}", serviceName)
	if err != nil {
		return taskState, err
	}
	running := false
	for _, state := range strings.Split(strings.TrimSpace(taskState), "\n") {
		running = running || strings.HasPrefix(state, "Running")
	}
	if !running {
		return "", fmt.Errorf("no running task found for service %s", targetService)
	}
	inspectOutput, err := s.run(ctx, "service", "inspect", serviceName)
	if err != nil {
		return inspectOutput, err
	}
	var inspected []scheduledServiceSpec
	if err = json.Unmarshal([]byte(inspectOutput), &inspected); err != nil || len(inspected) != 1 {
		return "", errors.New("decode scheduled-command target service")
	}
	container := inspected[0].Spec.TaskTemplate.ContainerSpec
	if container.Image == "" {
		return "", errors.New("scheduled-command target has no image")
	}
	directory, err := os.MkdirTemp("", "dockyard-schedule-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(directory)
	args := []string{"service", "create", "--detach=true", "--mode", "replicated-job", "--replicas", "1", "--max-concurrent", "1", "--restart-condition", "none", "--no-healthcheck", "--name", fmt.Sprintf("dockyard-schedule-%d", time.Now().UnixNano()), "--label", "com.dockyard.kind=scheduled-command"}
	if len(container.Env) > 0 {
		for _, value := range container.Env {
			if strings.ContainsAny(value, "\x00\r\n") {
				return "", errors.New("target environment contains a value that cannot be safely materialized")
			}
		}
		envPath := filepath.Join(directory, "environment")
		if err = os.WriteFile(envPath, []byte(strings.Join(container.Env, "\n")+"\n"), 0600); err != nil {
			return "", err
		}
		args = append(args, "--env-file", envPath)
	}
	args = appendScheduledContainerOptions(args, inspected[0].Spec.TaskTemplate)
	args = append(args, "--entrypoint", shell, container.Image, "-lc", command)
	serviceID, err := s.run(ctx, args...)
	serviceID = strings.TrimSpace(serviceID)
	if err != nil {
		return serviceID, err
	}
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cleanupCancel()
	defer s.run(cleanupCtx, "service", "rm", serviceID)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		stateOutput, stateErr := s.run(ctx, "service", "ps", "--no-trunc", "--format", "{{.CurrentState}}|{{.Error}}", serviceID)
		if stateErr != nil {
			return stateOutput, stateErr
		}
		for _, line := range strings.Split(strings.TrimSpace(stateOutput), "\n") {
			state, detail, _ := strings.Cut(line, "|")
			switch {
			case strings.HasPrefix(state, "Complete"):
				return s.run(ctx, "service", "logs", "--raw", "--no-task-ids", serviceID)
			case strings.HasPrefix(state, "Failed"), strings.HasPrefix(state, "Rejected"):
				logs, _ := s.run(ctx, "service", "logs", "--raw", "--no-task-ids", serviceID)
				if detail == "" {
					detail = state
				}
				return logs, fmt.Errorf("scheduled command task failed: %s", detail)
			}
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-ticker.C:
		}
	}
}

type scheduledServiceSpec struct {
	Spec struct {
		TaskTemplate scheduledTaskTemplate `json:"TaskTemplate"`
	} `json:"Spec"`
}

type scheduledTaskTemplate struct {
	ContainerSpec struct {
		Image          string   `json:"Image"`
		Env            []string `json:"Env"`
		Dir            string   `json:"Dir"`
		User           string   `json:"User"`
		Groups         []string `json:"Groups"`
		ReadOnly       bool     `json:"ReadOnly"`
		StopSignal     string   `json:"StopSignal"`
		CapabilityAdd  []string `json:"CapabilityAdd"`
		CapabilityDrop []string `json:"CapabilityDrop"`
		Hosts          []string `json:"Hosts"`
		Mounts         []struct {
			Type, Source, Target, Consistency string
			ReadOnly                          bool
			VolumeOptions                     *struct{ NoCopy bool } `json:"VolumeOptions"`
			TmpfsOptions                      *struct {
				SizeBytes int64
				Mode      uint32
			} `json:"TmpfsOptions"`
		} `json:"Mounts"`
		Secrets []struct {
			SecretID string
			File     *struct {
				Name, UID, GID string
				Mode           uint32
			}
		} `json:"Secrets"`
		Configs []struct {
			ConfigID string
			File     *struct {
				Name, UID, GID string
				Mode           uint32
			}
		} `json:"Configs"`
		DNSConfig *struct {
			Nameservers, Search, Options []string
		} `json:"DNSConfig"`
		Init *bool `json:"Init"`
	} `json:"ContainerSpec"`
	Resources struct {
		Limits, Reservations struct {
			NanoCPUs, MemoryBytes int64
			Pids                  int64
		}
	} `json:"Resources"`
	Placement struct {
		Constraints []string
		Preferences []struct {
			Spread *struct{ SpreadDescriptor string }
		}
		MaxReplicas int64
	} `json:"Placement"`
	Networks []struct {
		Target  string
		Aliases []string
	} `json:"Networks"`
}

func appendScheduledContainerOptions(args []string, task scheduledTaskTemplate) []string {
	container := task.ContainerSpec
	for _, network := range task.Networks {
		value := "name=" + network.Target
		args = append(args, "--network", value)
	}
	for _, mount := range container.Mounts {
		value := "type=" + mount.Type + ",target=" + mount.Target
		if mount.Source != "" {
			value += ",source=" + mount.Source
		}
		if mount.ReadOnly {
			value += ",readonly"
		}
		if mount.VolumeOptions != nil && mount.VolumeOptions.NoCopy {
			value += ",volume-nocopy"
		}
		if mount.TmpfsOptions != nil {
			if mount.TmpfsOptions.SizeBytes > 0 {
				value += ",tmpfs-size=" + strconv.FormatInt(mount.TmpfsOptions.SizeBytes, 10)
			}
			if mount.TmpfsOptions.Mode > 0 {
				value += ",tmpfs-mode=" + fmt.Sprintf("%#o", mount.TmpfsOptions.Mode)
			}
		}
		args = append(args, "--mount", value)
	}
	for _, secret := range container.Secrets {
		if secret.File != nil {
			args = append(args, "--secret", fmt.Sprintf("source=%s,target=%s,uid=%s,gid=%s,mode=%#o", secret.SecretID, secret.File.Name, secret.File.UID, secret.File.GID, secret.File.Mode))
		}
	}
	for _, config := range container.Configs {
		if config.File != nil {
			args = append(args, "--config", fmt.Sprintf("source=%s,target=%s,uid=%s,gid=%s,mode=%#o", config.ConfigID, config.File.Name, config.File.UID, config.File.GID, config.File.Mode))
		}
	}
	for _, constraint := range task.Placement.Constraints {
		args = append(args, "--constraint", constraint)
	}
	for _, preference := range task.Placement.Preferences {
		if preference.Spread != nil {
			args = append(args, "--placement-pref", "spread="+preference.Spread.SpreadDescriptor)
		}
	}
	if task.Placement.MaxReplicas > 0 {
		args = append(args, "--replicas-max-per-node", strconv.FormatInt(task.Placement.MaxReplicas, 10))
	}
	if task.Resources.Limits.NanoCPUs > 0 {
		args = append(args, "--limit-cpu", strconv.FormatFloat(float64(task.Resources.Limits.NanoCPUs)/1e9, 'f', 3, 64))
	}
	if task.Resources.Limits.MemoryBytes > 0 {
		args = append(args, "--limit-memory", strconv.FormatInt(task.Resources.Limits.MemoryBytes, 10))
	}
	if task.Resources.Limits.Pids > 0 {
		args = append(args, "--limit-pids", strconv.FormatInt(task.Resources.Limits.Pids, 10))
	}
	if task.Resources.Reservations.NanoCPUs > 0 {
		args = append(args, "--reserve-cpu", strconv.FormatFloat(float64(task.Resources.Reservations.NanoCPUs)/1e9, 'f', 3, 64))
	}
	if task.Resources.Reservations.MemoryBytes > 0 {
		args = append(args, "--reserve-memory", strconv.FormatInt(task.Resources.Reservations.MemoryBytes, 10))
	}
	if container.User != "" {
		args = append(args, "--user", container.User)
	}
	if container.Dir != "" {
		args = append(args, "--workdir", container.Dir)
	}
	if container.ReadOnly {
		args = append(args, "--read-only")
	}
	if container.Init != nil && *container.Init {
		args = append(args, "--init")
	}
	if container.StopSignal != "" {
		args = append(args, "--stop-signal", container.StopSignal)
	}
	for _, group := range container.Groups {
		args = append(args, "--group", group)
	}
	for _, capability := range container.CapabilityAdd {
		args = append(args, "--cap-add", capability)
	}
	for _, capability := range container.CapabilityDrop {
		args = append(args, "--cap-drop", capability)
	}
	for _, host := range container.Hosts {
		args = append(args, "--host", host)
	}
	if container.DNSConfig != nil {
		for _, server := range container.DNSConfig.Nameservers {
			args = append(args, "--dns", server)
		}
		for _, search := range container.DNSConfig.Search {
			args = append(args, "--dns-search", search)
		}
		for _, option := range container.DNSConfig.Options {
			args = append(args, "--dns-option", option)
		}
	}
	return args
}

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
