package apiclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	pathpkg "path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	BaseURL          *url.URL
	Token            string
	OrganizationID   string
	HTTPClient       *http.Client
	MaxResponseBytes int64
}

const (
	DefaultMaxResponseBytes int64 = 32 << 20
	maxBaseURLBytes               = 16 << 10
	maxClientTokenBytes           = 16 << 10
	maxOrganizationIDBytes        = 128
	maxAPIPathBytes               = 16 << 10
)

var ErrResponseTooLarge = errors.New("Dockyard API response exceeds configured limit")

var apiHostnameLabelPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("Dockyard API returned HTTP %d", e.Status)
	}
	return fmt.Sprintf("Dockyard API %s: %s", e.Code, e.Message)
}

func New(rawURL, token, organizationID string) (*Client, error) {
	trimmedURL := strings.TrimSpace(rawURL)
	if len(trimmedURL) > maxBaseURLBytes {
		return nil, errors.New("Dockyard URL is too long")
	}
	parsed, err := url.Parse(trimmedURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || !validAPIURLHost(parsed) || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" || parsed.RawPath != "" {
		return nil, errors.New("Dockyard URL must be an HTTP(S) URL without user information, query, or fragment and with a valid host and port")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	if parsed.Path != "" && (pathpkg.Clean(parsed.Path) != parsed.Path || strings.Contains(parsed.Path, "//")) {
		return nil, errors.New("Dockyard URL path prefix must not contain empty, dot, or parent segments")
	}
	if parsed.Scheme == "http" && !isLoopbackAPIHost(parsed.Hostname()) {
		return nil, errors.New("unencrypted HTTP is only allowed for a loopback Dockyard URL")
	}
	token = strings.TrimSpace(token)
	organizationID = strings.TrimSpace(organizationID)
	if len(token) > maxClientTokenBytes || strings.ContainsAny(token, "\x00\r\n") || len(organizationID) > maxOrganizationIDBytes || strings.ContainsAny(organizationID, "\x00\r\n") {
		return nil, errors.New("Dockyard token or organization ID is invalid")
	}
	return &Client{BaseURL: parsed, Token: token, OrganizationID: organizationID, HTTPClient: &http.Client{Timeout: 60 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("API redirects are disabled") }}, MaxResponseBytes: DefaultMaxResponseBytes}, nil
}

func (c *Client) Do(ctx context.Context, method, apiPath string, input any, output io.Writer) error {
	relative, err := url.Parse(apiPath)
	if err != nil || len(apiPath) > maxAPIPathBytes || relative.IsAbs() || relative.Host != "" || relative.User != nil || relative.Opaque != "" || relative.Fragment != "" || relative.RawPath != "" || !strings.HasPrefix(relative.Path, "/") || pathpkg.Clean(relative.Path) != relative.Path || strings.Contains(relative.Path, "//") {
		return errors.New("API path must be a canonical absolute path without a host or fragment")
	}
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	requestURL := *c.BaseURL
	requestURL.Path = strings.TrimRight(c.BaseURL.Path, "/") + relative.Path
	requestURL.RawPath = ""
	requestURL.RawQuery = relative.RawQuery
	requestURL.ForceQuery = relative.ForceQuery
	req, err := http.NewRequestWithContext(ctx, method, requestURL.String(), body)
	if err != nil {
		return err
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if c.OrganizationID != "" {
		req.Header.Set("X-Organization-ID", c.OrganizationID)
	}
	response, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var envelope struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&envelope)
		return &APIError{Status: response.StatusCode, Code: envelope.Error.Code, Message: envelope.Error.Message}
	}
	limit := c.MaxResponseBytes
	if limit <= 0 {
		limit = DefaultMaxResponseBytes
	}
	if response.ContentLength > limit {
		return fmt.Errorf("%w (%d bytes)", ErrResponseTooLarge, limit)
	}
	if output == nil || response.StatusCode == http.StatusNoContent {
		output = io.Discard
	}
	written, err := io.Copy(output, io.LimitReader(response.Body, limit+1))
	if err != nil {
		return err
	}
	if written > limit {
		return fmt.Errorf("%w (%d bytes)", ErrResponseTooLarge, limit)
	}
	return nil
}

func validAPIURLHost(endpoint *url.URL) bool {
	if endpoint == nil || !validAPIHostname(endpoint.Hostname()) || strings.HasSuffix(endpoint.Host, ":") {
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

func validAPIHostname(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || !apiHostnameLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func isLoopbackAPIHost(host string) bool {
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}
