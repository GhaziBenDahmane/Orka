package clustercontract

import (
	"errors"
	"path"
	"regexp"
	"strings"
)

const ProtocolVersion = 1

var resourceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

type Capabilities struct {
	ProtocolVersion int                  `json:"protocolVersion,omitempty"`
	DockerSwarm     bool                 `json:"dockerSwarm,omitempty"`
	DockerCompose   bool                 `json:"dockerCompose,omitempty"`
	EdgeProxy       *EdgeProxyCapability `json:"edgeProxy,omitempty"`
}

type EdgeProxyCapability struct {
	Provider                   string `json:"provider"`
	ManagementMode             string `json:"managementMode"`
	ServiceName                string `json:"serviceName"`
	PublicNetwork              string `json:"publicNetwork"`
	DynamicConfigurationMode   string `json:"dynamicConfigurationMode"`
	DynamicConfigurationPath   string `json:"dynamicConfigurationPath"`
	Ready                      bool   `json:"ready"`
	Status                     string `json:"status"`
	SupportsCustomCertificates bool   `json:"supportsCustomCertificates"`
}

func Baseline() Capabilities {
	return Capabilities{ProtocolVersion: ProtocolVersion, DockerSwarm: true, DockerCompose: true}
}

func Validate(capabilities Capabilities) error {
	if capabilities.ProtocolVersion != ProtocolVersion || !capabilities.DockerSwarm || !capabilities.DockerCompose {
		return errors.New("unsupported agent capability contract")
	}
	if capabilities.EdgeProxy == nil {
		return nil
	}
	edge := capabilities.EdgeProxy
	if edge.Provider != "traefik" || edge.ManagementMode != "external" || !resourceName.MatchString(edge.ServiceName) || !resourceName.MatchString(edge.PublicNetwork) {
		return errors.New("invalid edge proxy capability identity")
	}
	if edge.DynamicConfigurationMode != "file" || !validContainerDirectory(edge.DynamicConfigurationPath) {
		return errors.New("invalid edge proxy dynamic configuration contract")
	}
	if !contains([]string{"ready", "inspection_failed", "service_unavailable", "file_provider_missing", "network_missing"}, edge.Status) {
		return errors.New("invalid edge proxy capability status")
	}
	if edge.Ready != (edge.Status == "ready") || edge.SupportsCustomCertificates != edge.Ready {
		return errors.New("inconsistent edge proxy capability status")
	}
	return nil
}

func validContainerDirectory(value string) bool {
	return strings.HasPrefix(value, "/") && value != "/" && path.Clean(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
