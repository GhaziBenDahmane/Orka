package deploy

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
	"regexp"
	"strconv"
	"strings"

	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

const (
	maxCommitStatusRepositoryURLBytes = 16 << 10
	maxCommitStatusServerBytes        = 512
	maxCommitStatusTokenBytes         = 16 << 10
	maxCommitStatusUsernameBytes      = 4 << 10
	maxCommitStatusContextBytes       = 100
	maxCommitStatusRepositoryPath     = 4 << 10
	maxCommitStatusPathSegmentBytes   = 255
)

var (
	commitStatusHostnameLabelPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	commitStatusContextPattern       = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
)

func (w *Worker) deliverCommitStatus(ctx context.Context, j job) error {
	var payload struct {
		DeliveryID string `json:"deliveryId"`
	}
	if err := json.Unmarshal(j.Payload, &payload); err != nil {
		return err
	}
	id, err := uuid.Parse(payload.DeliveryID)
	if err != nil {
		return err
	}
	delivery, err := w.Store.GetCommitStatusDeliveryForJob(ctx, j.ID, j.LeaseID, id)
	if err != nil {
		return err
	}
	credentialID := ""
	if delivery.CredentialID != nil {
		credentialID = delivery.CredentialID.String()
	}
	token, err := w.Box.DecryptResource(delivery.EncryptedCredential, "source-credential", credentialID, "source-credential")
	if err != nil {
		return errors.Join(err, w.Store.FinishCommitStatusDeliveryForJob(ctx, j.ID, j.LeaseID, id, 0, err))
	}
	req, err := commitStatusRequest(ctx, delivery, string(token))
	if err != nil {
		return errors.Join(err, w.Store.FinishCommitStatusDeliveryForJob(ctx, j.ID, j.LeaseID, id, 0, err))
	}
	response, err := w.notificationClient().Do(req)
	code := 0
	if response != nil {
		code = response.StatusCode
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		_ = response.Body.Close()
	}
	if err == nil && (code < 200 || code >= 300) {
		err = fmt.Errorf("commit status provider returned HTTP %d", code)
	}
	return errors.Join(err, w.Store.FinishCommitStatusDeliveryForJob(ctx, j.ID, j.LeaseID, id, code, err))
}

func commitStatusRequest(ctx context.Context, delivery store.CommitStatusDelivery, token string) (*http.Request, error) {
	if !validCommitForStatus(delivery.CommitSHA) || token == "" || len(token) > maxCommitStatusTokenBytes || strings.ContainsAny(token, "\x00\r\n") || len(delivery.Context) > maxCommitStatusContextBytes || !commitStatusContextPattern.MatchString(delivery.Context) || !containsCommitStatusState(delivery.State) || len(delivery.CredentialUsername) > maxCommitStatusUsernameBytes || strings.ContainsAny(delivery.CredentialUsername, "\x00\r\n") {
		return nil, errors.New("commit status has invalid credentials, state, context, or commit SHA")
	}
	repositoryURL := strings.TrimSpace(delivery.RepositoryURL)
	repository, err := url.Parse(repositoryURL)
	if err != nil || repositoryURL != delivery.RepositoryURL || len(repositoryURL) > maxCommitStatusRepositoryURLBytes || (repository.Scheme != "https" && repository.Scheme != "ssh") || !validCommitStatusURLHost(repository) || repository.User != nil && repository.Scheme == "https" || repository.RawQuery != "" || repository.Fragment != "" || repository.Opaque != "" {
		return nil, errors.New("repository URL cannot be mapped to a provider API")
	}
	if repository.User != nil {
		_, hasPassword := repository.User.Password()
		if repository.User.Username() == "" || hasPassword {
			return nil, errors.New("repository URL cannot contain embedded credentials")
		}
	}
	credentialAuthority, credentialHost, err := parseCommitStatusServer(delivery.CredentialServer)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(repository.Hostname(), credentialHost) {
		return nil, errors.New("status credential server does not match repository host")
	}
	repositoryPath := strings.TrimSuffix(strings.Trim(repository.Path, "/"), ".git")
	parts := strings.Split(repositoryPath, "/")
	if len(repositoryPath) == 0 || len(repositoryPath) > maxCommitStatusRepositoryPath || len(parts) < 2 || !validCommitStatusPath(parts) {
		return nil, errors.New("repository URL has no owner and repository path")
	}
	description := "Dockyard deployment " + delivery.State
	var endpoint string
	var body []byte
	contentType := "application/json"
	state := delivery.State
	switch delivery.Provider {
	case "github":
		if !strings.EqualFold(credentialAuthority, "github.com") || len(parts) != 2 {
			return nil, errors.New("GitHub statuses require a github.com owner/repository URL")
		}
		endpoint = "https://api.github.com/repos/" + url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1]) + "/statuses/" + delivery.CommitSHA
		body, _ = json.Marshal(map[string]string{"state": state, "context": delivery.Context, "description": description})
	case "gitea":
		if len(parts) != 2 {
			return nil, errors.New("Gitea statuses require an owner/repository URL")
		}
		endpoint = "https://" + credentialAuthority + "/api/v1/repos/" + url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1]) + "/statuses/" + delivery.CommitSHA
		body, _ = json.Marshal(map[string]string{"state": state, "context": delivery.Context, "description": description})
	case "gitlab":
		endpoint = "https://" + credentialAuthority + "/api/v4/projects/" + url.PathEscape(repositoryPath) + "/statuses/" + delivery.CommitSHA
		values := url.Values{"state": {map[string]string{"failure": "failed", "error": "failed"}[state]}, "name": {delivery.Context}, "description": {description}}
		if state == "pending" || state == "success" {
			values.Set("state", state)
		}
		body, contentType = []byte(values.Encode()), "application/x-www-form-urlencoded"
	case "bitbucket":
		if !strings.EqualFold(credentialAuthority, "bitbucket.org") || len(parts) != 2 {
			return nil, errors.New("Bitbucket statuses require a bitbucket.org workspace/repository URL")
		}
		endpoint = "https://api.bitbucket.org/2.0/repositories/" + url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1]) + "/commit/" + delivery.CommitSHA + "/statuses/build"
		mapped := map[string]string{"pending": "INPROGRESS", "success": "SUCCESSFUL", "failure": "FAILED", "error": "FAILED"}[state]
		key := strings.ReplaceAll(delivery.Context, "/", "-")
		if len(key) > 40 {
			key = key[:40]
		}
		body, _ = json.Marshal(map[string]string{"state": mapped, "key": key, "name": delivery.Context, "description": description})
	default:
		return nil, errors.New("unsupported commit status provider")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "Dockyard-Commit-Status/1.0")
	switch delivery.Provider {
	case "github":
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github+json")
	case "gitlab":
		req.Header.Set("PRIVATE-TOKEN", token)
	case "gitea":
		req.Header.Set("Authorization", "token "+token)
	case "bitbucket":
		req.SetBasicAuth(delivery.CredentialUsername, token)
	}
	return req, nil
}

func validCommitForStatus(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, char := range value {
		if !strings.ContainsRune("0123456789abcdef", char) {
			return false
		}
	}
	return strings.Trim(value, "0") != ""
}

func containsCommitStatusState(state string) bool {
	return state == "pending" || state == "success" || state == "failure" || state == "error"
}

func parseCommitStatusServer(raw string) (authority, hostname string, err error) {
	if raw == "" || raw != strings.TrimSpace(raw) || len(raw) > maxCommitStatusServerBytes || strings.ContainsAny(raw, "\x00\r\n") {
		return "", "", errors.New("status credential server is invalid")
	}
	endpoint, parseErr := url.Parse("https://" + raw)
	if parseErr != nil || endpoint.Scheme != "https" || !validCommitStatusURLHost(endpoint) || endpoint.User != nil || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Opaque != "" {
		return "", "", errors.New("status credential server is invalid")
	}
	return endpoint.Host, strings.ToLower(endpoint.Hostname()), nil
}

func validCommitStatusURLHost(endpoint *url.URL) bool {
	if endpoint == nil || !validCommitStatusHostname(endpoint.Hostname()) || strings.HasSuffix(endpoint.Host, ":") {
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

func validCommitStatusHostname(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || !commitStatusHostnameLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func validCommitStatusPath(parts []string) bool {
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || len(part) > maxCommitStatusPathSegmentBytes || strings.ContainsAny(part, "\x00\r\n") {
			return false
		}
	}
	return true
}
