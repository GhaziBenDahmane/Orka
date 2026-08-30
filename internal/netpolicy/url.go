package netpolicy

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ValidateHTTPURL checks the syntax of an outbound HTTP(S) URL without
// resolving it. Callers must still use Policy.Transport or Policy.DialContext
// when the destination is tenant-controlled so DNS rebinding is blocked at
// connection time.
func ValidateHTTPURL(raw string, maxBytes int) (*url.URL, error) {
	if raw == "" || raw != strings.TrimSpace(raw) || maxBytes <= 0 || len(raw) > maxBytes || strings.ContainsAny(raw, "\x00\r\n") {
		return nil, errors.New("URL is empty, oversized, or contains surrounding whitespace or control characters")
	}
	endpoint, err := url.Parse(raw)
	if err != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.User != nil || endpoint.Fragment != "" || endpoint.Opaque != "" || !ValidURLHost(endpoint) {
		return nil, errors.New("URL must be an absolute HTTP(S) URL without credentials or a fragment and with a valid host and port")
	}
	return endpoint, nil
}

// ValidURLHost verifies DNS/IP syntax and an optional TCP port without doing
// resolution. It is useful for non-HTTP URL schemes that share URL authority
// syntax.
func ValidURLHost(endpoint *url.URL) bool {
	host := endpoint.Hostname()
	if strings.HasPrefix(endpoint.Host, "[") && net.ParseIP(host) == nil {
		return false
	}
	if net.ParseIP(host) == nil {
		if len(host) == 0 || len(host) > 253 {
			return false
		}
		for _, label := range strings.Split(host, ".") {
			if !dnsLabel.MatchString(label) {
				return false
			}
		}
	}
	if strings.HasSuffix(endpoint.Host, ":") {
		return false
	}
	if port := endpoint.Port(); port != "" {
		value, err := strconv.Atoi(port)
		return err == nil && value >= 1 && value <= 65535
	}
	return true
}
