package httpapi

import (
	"errors"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const (
	maxSourceCredentialNameBytes        = 120
	maxSourceCredentialServerBytes      = 512
	maxSourceCredentialUsernameBytes    = 4 << 10
	maxSourceCredentialSecretBytes      = 64 << 10
	maxSourceCredentialSSHMaterialBytes = 2 << 20
)

var endpointHostnameLabelPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

func validEndpointURLHost(endpoint *url.URL) bool {
	if endpoint == nil || !validEndpointHostname(endpoint.Hostname()) || strings.HasSuffix(endpoint.Host, ":") {
		return false
	}
	if strings.HasPrefix(endpoint.Host, "[") && net.ParseIP(endpoint.Hostname()) == nil {
		return false
	}
	if port := endpoint.Port(); port != "" {
		value, err := strconv.Atoi(port)
		return err == nil && value >= 1 && value <= 65535
	}
	return true
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

func normalizeCredentialServer(raw string) (string, error) {
	if raw == "" || raw != strings.TrimSpace(raw) || len(raw) > maxSourceCredentialServerBytes || strings.ContainsAny(raw, "\x00\r\n") {
		return "", errors.New("credential server must be a valid host with an optional port")
	}
	endpoint, err := url.Parse("https://" + raw)
	if err != nil || endpoint.Scheme != "https" || !validEndpointURLHost(endpoint) || endpoint.User != nil || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Opaque != "" {
		return "", errors.New("credential server must be a valid host with an optional port")
	}
	return strings.ToLower(endpoint.Host), nil
}

func validSourceCredentialIdentity(kind, name, username string) bool {
	return contains([]string{"git", "git-ssh", "registry"}, kind) && validDisplayLabel(name, maxSourceCredentialNameBytes) && username != "" && len(username) <= maxSourceCredentialUsernameBytes && !strings.ContainsAny(username, "\x00\r\n")
}

func credentialServerHostname(server string) string {
	endpoint, err := url.Parse("https://" + server)
	if err != nil {
		return ""
	}
	return strings.ToLower(endpoint.Hostname())
}
