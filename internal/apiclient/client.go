package apiclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

const DefaultMaxResponseBytes int64 = 32 << 20

var ErrResponseTooLarge = errors.New("Dockyard API response exceeds configured limit")

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
	parsed, err := url.Parse(strings.TrimRight(strings.TrimSpace(rawURL), "/"))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil {
		return nil, errors.New("Dockyard URL must be an HTTP(S) URL without user information")
	}
	if parsed.Scheme == "http" && parsed.Hostname() != "localhost" && parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "::1" {
		return nil, errors.New("unencrypted HTTP is only allowed for a loopback Dockyard URL")
	}
	return &Client{BaseURL: parsed, Token: strings.TrimSpace(token), OrganizationID: strings.TrimSpace(organizationID), HTTPClient: &http.Client{Timeout: 60 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("API redirects are disabled") }}, MaxResponseBytes: DefaultMaxResponseBytes}, nil
}

func (c *Client) Do(ctx context.Context, method, path string, input any, output io.Writer) error {
	relative, err := url.Parse(path)
	if err != nil || relative.IsAbs() || !strings.HasPrefix(relative.Path, "/") {
		return errors.New("API path must be an absolute path without a host")
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
	requestURL.RawQuery = relative.RawQuery
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
