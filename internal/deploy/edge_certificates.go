package deploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/GhaziBenDahmane/Orka/internal/tlscert"
	"github.com/google/uuid"
)

const edgeCertificateLabel = "com.dockyard.edge-tls"

type EdgeProxySpec struct {
	ServiceName              string `json:"serviceName"`
	DynamicConfigurationPath string `json:"dynamicConfigurationPath"`
}

type EdgeCertificateMaterial struct {
	ID             uuid.UUID `json:"id"`
	Revision       int64     `json:"revision"`
	Fingerprint    string    `json:"fingerprint"`
	CertificatePEM string    `json:"certificatePem"`
	PrivateKeyPEM  string    `json:"privateKeyPem"`
}

type desiredEdgeCertificate struct {
	certificateName string
	privateKeyName  string
	certificatePEM  []byte
	privateKeyPEM   []byte
}

type EdgeCertificateManager interface {
	ReconcileEdgeCertificates(context.Context, EdgeProxySpec, []EdgeCertificateMaterial) error
}

func (s Swarm) ReconcileEdgeCertificates(ctx context.Context, proxy EdgeProxySpec, certificates []EdgeCertificateMaterial) error {
	if !safeRuntimeServiceName.MatchString(proxy.ServiceName) || !validDynamicConfigurationPath(proxy.DynamicConfigurationPath) || len(certificates) > 100 {
		return errors.New("invalid edge certificate reconciliation request")
	}
	if err := s.verifyEdgeProxyContract(ctx, proxy); err != nil {
		return err
	}
	desired := make([]desiredEdgeCertificate, 0, len(certificates))
	seen := map[uuid.UUID]bool{}
	totalBytes := 0
	for _, material := range certificates {
		if material.ID == uuid.Nil || material.Revision < 1 || seen[material.ID] {
			return errors.New("invalid or duplicate edge certificate identity")
		}
		seen[material.ID] = true
		certificatePEM, privateKeyPEM := []byte(material.CertificatePEM), []byte(material.PrivateKeyPEM)
		totalBytes += len(certificatePEM) + len(privateKeyPEM)
		if totalBytes > 3<<20 {
			return errors.New("edge certificate material exceeds 3 MiB")
		}
		metadata, err := tlscert.Validate(certificatePEM, privateKeyPEM, time.Now())
		if err != nil || metadata.Fingerprint != material.Fingerprint {
			return fmt.Errorf("certificate %s failed independent validation", material.ID)
		}
		digest := sha256.Sum256(append(append(append([]byte{}, certificatePEM...), 0), privateKeyPEM...))
		prefix := strings.ReplaceAll(material.ID.String(), "-", "")[:12] + "-" + hex.EncodeToString(digest[:8])
		desired = append(desired, desiredEdgeCertificate{certificateName: "dockyard-tls-" + prefix + "-cert", privateKeyName: "dockyard-tls-" + prefix + "-key", certificatePEM: certificatePEM, privateKeyPEM: privateKeyPEM})
	}
	sort.Slice(desired, func(i, j int) bool { return desired[i].certificateName < desired[j].certificateName })
	serviceLabel := "com.dockyard.edge-service=" + proxy.ServiceName
	for _, item := range desired {
		if err := s.ensureEdgeSecret(ctx, item.certificateName, item.certificatePEM, serviceLabel); err != nil {
			return err
		}
		if err := s.ensureEdgeSecret(ctx, item.privateKeyName, item.privateKeyPEM, serviceLabel); err != nil {
			return err
		}
	}
	configuration := edgeCertificateConfiguration(desired)
	configurationHash := sha256.Sum256(configuration)
	configurationName := "dockyard-edge-tls-" + hex.EncodeToString(configurationHash[:8])
	if err := s.ensureEdgeConfig(ctx, configurationName, configuration, serviceLabel); err != nil {
		return err
	}
	currentSecrets, err := s.edgeServiceReferences(ctx, proxy.ServiceName, "Secrets", "SecretName")
	if err != nil {
		return err
	}
	currentConfigs, err := s.edgeServiceReferences(ctx, proxy.ServiceName, "Configs", "ConfigName")
	if err != nil {
		return err
	}
	desiredSecrets := map[string]bool{}
	for _, item := range desired {
		desiredSecrets[item.certificateName], desiredSecrets[item.privateKeyName] = true, true
	}
	desiredConfigs := map[string]bool{configurationName: true}
	arguments := []string{"service", "update", "--detach=true", "--update-order", "stop-first", "--update-failure-action", "rollback"}
	changed := false
	for name := range currentSecrets {
		if strings.HasPrefix(name, "dockyard-tls-") && !desiredSecrets[name] {
			arguments = append(arguments, "--secret-rm", name)
			changed = true
		}
	}
	for _, item := range desired {
		for _, name := range []string{item.certificateName, item.privateKeyName} {
			if !currentSecrets[name] {
				arguments = append(arguments, "--secret-add", "source="+name+",target="+name+",mode=0400")
				changed = true
			}
		}
	}
	for name := range currentConfigs {
		if strings.HasPrefix(name, "dockyard-edge-tls-") && !desiredConfigs[name] {
			arguments = append(arguments, "--config-rm", name)
			changed = true
		}
	}
	if !currentConfigs[configurationName] {
		arguments = append(arguments, "--config-add", "source="+configurationName+",target="+path.Join(proxy.DynamicConfigurationPath, "dockyard-certificates.yml")+",mode=0444")
		changed = true
	}
	if changed {
		arguments = append(arguments, proxy.ServiceName)
		if _, err = s.run(ctx, arguments...); err != nil {
			return fmt.Errorf("update edge proxy certificate mounts: %w", err)
		}
		if err = s.waitForEdgeProxyUpdate(ctx, proxy.ServiceName); err != nil {
			return err
		}
	}
	s.cleanupEdgeResources(ctx, "secret", proxy.ServiceName, desiredSecrets)
	s.cleanupEdgeResources(ctx, "config", proxy.ServiceName, desiredConfigs)
	return nil
}

func (s Swarm) verifyEdgeProxyContract(ctx context.Context, proxy EdgeProxySpec) error {
	output, err := s.run(ctx, "service", "inspect", proxy.ServiceName)
	if err != nil {
		return fmt.Errorf("inspect edge proxy: %w", err)
	}
	var services []struct {
		Spec struct {
			TaskTemplate struct {
				ContainerSpec struct {
					Args []string `json:"Args"`
				} `json:"ContainerSpec"`
				Networks []struct {
					Target string `json:"Target"`
				} `json:"Networks"`
			} `json:"TaskTemplate"`
		} `json:"Spec"`
	}
	if json.Unmarshal([]byte(output), &services) != nil || len(services) != 1 {
		return errors.New("decode edge proxy service contract")
	}
	wantedFlag := "--providers.file.directory=" + proxy.DynamicConfigurationPath
	if !containsString(services[0].Spec.TaskTemplate.ContainerSpec.Args, wantedFlag) {
		return errors.New("edge proxy does not expose the registered dynamic file provider")
	}
	networkOutput, err := s.run(ctx, "network", "inspect", "--format", "{{.ID}}", s.Network)
	if err != nil {
		return fmt.Errorf("inspect edge proxy public network: %w", err)
	}
	wantedNetwork := strings.TrimSpace(networkOutput)
	for _, network := range services[0].Spec.TaskTemplate.Networks {
		if wantedNetwork != "" && network.Target == wantedNetwork {
			return nil
		}
	}
	return errors.New("edge proxy is not attached to the configured public network")
}

func (s Swarm) waitForEdgeProxyUpdate(ctx context.Context, serviceName string) error {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		output, err := s.run(waitCtx, "service", "inspect", "--format", "{{json .UpdateStatus}}", serviceName)
		if err != nil {
			return fmt.Errorf("inspect edge proxy update: %w", err)
		}
		var status swarmUpdateStatus
		if strings.TrimSpace(output) != "null" && json.Unmarshal([]byte(output), &status) != nil {
			return errors.New("decode edge proxy update status")
		}
		switch status.State {
		case "completed":
			return nil
		case "paused", "rollback_started", "rollback_paused", "rollback_completed":
			return fmt.Errorf("edge proxy update entered %s: %s", status.State, status.Message)
		}
		select {
		case <-waitCtx.Done():
			return fmt.Errorf("wait for edge proxy update: %w", waitCtx.Err())
		case <-ticker.C:
		}
	}
}

func (s Swarm) ensureEdgeSecret(ctx context.Context, name string, value []byte, serviceLabel string) error {
	if output, err := s.run(ctx, "secret", "inspect", "--format", `{{index .Spec.Labels "com.dockyard.edge-tls"}}|{{index .Spec.Labels "com.dockyard.edge-service"}}`, name); err == nil {
		if strings.TrimSpace(output) != "true|"+strings.TrimPrefix(serviceLabel, "com.dockyard.edge-service=") {
			return fmt.Errorf("Docker secret %s exists without matching Dockyard ownership", name)
		}
		return nil
	}
	_, err := s.runInput(ctx, value, "secret", "create", "--label", edgeCertificateLabel+"=true", "--label", serviceLabel, name, "-")
	return err
}

func (s Swarm) ensureEdgeConfig(ctx context.Context, name string, value []byte, serviceLabel string) error {
	if output, err := s.run(ctx, "config", "inspect", "--format", `{{index .Spec.Labels "com.dockyard.edge-tls"}}|{{index .Spec.Labels "com.dockyard.edge-service"}}`, name); err == nil {
		if strings.TrimSpace(output) != "true|"+strings.TrimPrefix(serviceLabel, "com.dockyard.edge-service=") {
			return fmt.Errorf("Docker config %s exists without matching Dockyard ownership", name)
		}
		return nil
	}
	_, err := s.runInput(ctx, value, "config", "create", "--label", edgeCertificateLabel+"=true", "--label", serviceLabel, name, "-")
	return err
}

func (s Swarm) edgeServiceReferences(ctx context.Context, serviceName, field, nameField string) (map[string]bool, error) {
	output, err := s.run(ctx, "service", "inspect", "--format", "{{json .Spec.TaskTemplate.ContainerSpec."+field+"}}", serviceName)
	if err != nil {
		return nil, err
	}
	var references []map[string]any
	if strings.TrimSpace(output) != "null" && json.Unmarshal([]byte(output), &references) != nil {
		return nil, errors.New("decode edge proxy resource references")
	}
	result := map[string]bool{}
	for _, reference := range references {
		if name, ok := reference[nameField].(string); ok && name != "" {
			result[name] = true
		}
	}
	return result, nil
}

func (s Swarm) cleanupEdgeResources(ctx context.Context, kind, serviceName string, desired map[string]bool) {
	output, err := s.run(ctx, kind, "ls", "--filter", "label="+edgeCertificateLabel+"=true", "--filter", "label=com.dockyard.edge-service="+serviceName, "--format", "{{.Name}}")
	if err != nil {
		return
	}
	for _, name := range strings.Fields(output) {
		if !desired[name] && (strings.HasPrefix(name, "dockyard-tls-") || strings.HasPrefix(name, "dockyard-edge-tls-")) {
			_, _ = s.run(ctx, kind, "rm", name)
		}
	}
}

func edgeCertificateConfiguration(certificates []desiredEdgeCertificate) []byte {
	var value strings.Builder
	value.WriteString("tls:\n  certificates:\n")
	for _, certificate := range certificates {
		value.WriteString("    - certFile: /run/secrets/")
		value.WriteString(certificate.certificateName)
		value.WriteString("\n      keyFile: /run/secrets/")
		value.WriteString(certificate.privateKeyName)
		value.WriteByte('\n')
	}
	if len(certificates) == 0 {
		return []byte("tls: {}\n")
	}
	return []byte(value.String())
}

func validDynamicConfigurationPath(value string) bool {
	return strings.HasPrefix(value, "/") && value != "/" && path.Clean(value) == value && !strings.ContainsAny(value, "\x00\r\n,=")
}

var _ EdgeCertificateManager = Swarm{}
