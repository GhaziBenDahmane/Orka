package deploy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/bendahma/dokploy-go/internal/volumeartifact"
	"github.com/google/uuid"
)

var pinnedRuntimeImage = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[a-f0-9]{64}$`)
var artifactSHA256 = regexp.MustCompile(`^[a-f0-9]{64}$`)

type VolumeArtifactJob struct {
	volumeartifact.Job
	VolumeName string `json:"volumeName"`
	NodeID     string `json:"nodeId"`
	Network    string `json:"network,omitempty"`
	StackName  string `json:"stackName"`
	Quiesce    bool   `json:"quiesce"`
}

type VolumeArtifactRunner interface {
	RunVolumeArtifact(context.Context, VolumeArtifactJob) (volumeartifact.Result, error)
}

func ValidateVolumeArtifactJob(job VolumeArtifactJob) error {
	if err := volumeartifact.ValidateJob(job.Job); err != nil {
		return err
	}
	if !safeVolumeSource.MatchString(job.VolumeName) || strings.ContainsAny(job.VolumeName, "/\\") {
		return errors.New("invalid Docker volume name")
	}
	if !safeNodeID.MatchString(job.NodeID) {
		return errors.New("invalid volume storage node ID")
	}
	if job.Network != "" && !safeName.MatchString(job.Network) {
		return errors.New("invalid volume artifact network")
	}
	if !safeName.MatchString(job.StackName) {
		return errors.New("invalid volume artifact stack name")
	}
	if job.Mode == "restore" && !job.Quiesce {
		return errors.New("volume restores must quiesce mounting services")
	}
	return nil
}

// RunVolumeArtifact creates a one-shot Swarm service on the node that owns the
// local volume. The presigned URL and data key travel in a temporary Swarm
// secret, never in service arguments, environment variables, or task logs.
func (s Swarm) RunVolumeArtifact(ctx context.Context, job VolumeArtifactJob) (result volumeartifact.Result, err error) {
	if err := ValidateVolumeArtifactJob(job); err != nil {
		return result, err
	}
	if !safeRuntimeServiceName.MatchString(s.ServiceName) {
		return result, errors.New("Swarm service name is required for volume artifact jobs")
	}
	image, err := s.run(ctx, "service", "inspect", "--format", "{{.Spec.TaskTemplate.ContainerSpec.Image}}", s.ServiceName)
	image = strings.TrimSpace(image)
	if err != nil {
		return result, fmt.Errorf("inspect volume helper image: %w", err)
	}
	if !pinnedRuntimeImage.MatchString(image) {
		return result, errors.New("volume artifact helper image is not pinned by sha256 digest")
	}
	var scaled map[string]int
	if job.Quiesce {
		scaled, err = s.scaleVolumeServices(ctx, job.StackName, job.VolumeName, 0)
		if err != nil {
			return result, fmt.Errorf("quiesce volume services: %w", err)
		}
		defer func() {
			resumeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			if resumeErr := s.restoreServiceScale(resumeCtx, scaled); resumeErr != nil {
				err = errors.Join(err, fmt.Errorf("resume volume services: %w", resumeErr))
			}
		}()
	}
	payload, err := json.Marshal(job.Job)
	if err != nil {
		return result, err
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	serviceName, secretName := "dockyard-volume-"+suffix, "dockyard-volume-job-"+suffix
	if _, err = s.runInput(ctx, payload, "secret", "create", secretName, "-"); err != nil {
		return result, fmt.Errorf("create volume artifact secret: %w", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = s.run(cleanupCtx, "service", "rm", serviceName)
		for cleanupCtx.Err() == nil {
			if _, removeErr := s.run(cleanupCtx, "secret", "rm", secretName); removeErr == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()
	args := []string{"service", "create", "--quiet", "--name", serviceName, "--constraint", "node.id==" + job.NodeID, "--restart-condition", "none", "--mount", "type=volume,source=" + job.VolumeName + ",target=/volume", "--secret", "source=" + secretName + ",target=volume-job.json,mode=0400"}
	if job.Network != "" {
		args = append(args, "--network", job.Network)
	}
	args = append(args, image, "volume-artifact", "--job-file", "/run/secrets/volume-job.json")
	if _, err = s.run(ctx, args...); err != nil {
		return result, fmt.Errorf("create volume artifact service: %w", err)
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		status, statusErr := s.run(waitCtx, "service", "ps", "--no-trunc", "--format", "{{.CurrentState}}|{{.Error}}", serviceName)
		if statusErr != nil {
			return result, statusErr
		}
		line := strings.TrimSpace(strings.Split(status, "\n")[0])
		fields := strings.SplitN(line, "|", 2)
		stateFields := strings.Fields(fields[0])
		if len(stateFields) == 0 {
			select {
			case <-waitCtx.Done():
				return result, fmt.Errorf("wait for volume artifact service: %w", waitCtx.Err())
			case <-time.After(500 * time.Millisecond):
				continue
			}
		}
		state := strings.ToLower(stateFields[0])
		switch state {
		case "complete":
			logs, logErr := s.run(waitCtx, "service", "logs", "--raw", serviceName)
			if logErr != nil {
				return result, logErr
			}
			for _, candidate := range reverseNonEmptyLines(logs) {
				if json.Unmarshal([]byte(candidate), &result) == nil && artifactSHA256.MatchString(result.SHA256) && artifactSHA256.MatchString(result.PlaintextSHA256) && result.SizeBytes > 0 && (job.Mode != "restore" || result.SHA256 == job.SHA256 && result.PlaintextSHA256 == job.PlaintextSHA256 && result.SizeBytes == job.SizeBytes) {
					return result, nil
				}
			}
			return result, errors.New("volume artifact service returned no result")
		case "failed", "rejected", "orphaned", "shutdown":
			detail := ""
			if len(fields) == 2 {
				detail = strings.TrimSpace(fields[1])
			}
			return result, fmt.Errorf("volume artifact service %s: %s", state, detail)
		}
		select {
		case <-waitCtx.Done():
			return result, fmt.Errorf("wait for volume artifact service: %w", waitCtx.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (s Swarm) scaleVolumeServices(ctx context.Context, stackName, volumeName string, replicas int) (map[string]int, error) {
	servicesOutput, err := s.run(ctx, "service", "ls", "--filter", "label=com.docker.stack.namespace="+stackName, "--format", "{{.Name}}")
	if err != nil {
		return nil, err
	}
	original := map[string]int{}
	for _, service := range strings.Fields(servicesOutput) {
		mountsJSON, inspectErr := s.run(ctx, "service", "inspect", "--format", "{{json .Spec.TaskTemplate.ContainerSpec.Mounts}}", service)
		if inspectErr != nil {
			return original, errors.Join(inspectErr, s.restoreServiceScale(ctx, original))
		}
		var mounts []struct{ Type, Source string }
		if inspectErr = json.Unmarshal([]byte(strings.TrimSpace(mountsJSON)), &mounts); inspectErr != nil {
			return original, errors.Join(inspectErr, s.restoreServiceScale(ctx, original))
		}
		mounted := false
		for _, mount := range mounts {
			if strings.EqualFold(mount.Type, "volume") && mount.Source == volumeName {
				mounted = true
				break
			}
		}
		if !mounted {
			continue
		}
		replicasText, inspectErr := s.run(ctx, "service", "inspect", "--format", "{{.Spec.Mode.Replicated.Replicas}}", service)
		current, parseErr := strconv.Atoi(strings.TrimSpace(replicasText))
		if inspectErr != nil || parseErr != nil {
			return original, errors.Join(inspectErr, parseErr, s.restoreServiceScale(ctx, original))
		}
		original[service] = current
		if _, inspectErr = s.run(ctx, "service", "scale", "--detach=false", fmt.Sprintf("%s=%d", service, replicas)); inspectErr != nil {
			return original, errors.Join(inspectErr, s.restoreServiceScale(ctx, original))
		}
	}
	if len(original) == 0 {
		return nil, fmt.Errorf("volume %q is not mounted by stack %q", volumeName, stackName)
	}
	return original, nil
}

func (s Swarm) restoreServiceScale(ctx context.Context, services map[string]int) error {
	var result error
	for service, replicas := range services {
		if _, err := s.run(ctx, "service", "scale", "--detach=false", fmt.Sprintf("%s=%d", service, replicas)); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}

func (s Swarm) runInput(ctx context.Context, input []byte, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, s.DockerBin, args...)
	cmd.Env = os.Environ()
	cmd.Stdin = bytes.NewReader(input)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Run(); err != nil {
		return output.String(), fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(output.String()))
	}
	return output.String(), nil
}

func reverseNonEmptyLines(value string) []string {
	lines := strings.Split(strings.TrimSpace(value), "\n")
	result := make([]string, 0, len(lines))
	for index := len(lines) - 1; index >= 0; index-- {
		if line := strings.TrimSpace(lines[index]); line != "" {
			result = append(result, line)
		}
	}
	return result
}
