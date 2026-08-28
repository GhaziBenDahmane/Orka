package deploy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
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
	token, err := w.Box.Decrypt(delivery.EncryptedCredential, "source-credential")
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
	repository, err := url.Parse(delivery.RepositoryURL)
	if err != nil || (repository.Scheme != "https" && repository.Scheme != "ssh") || repository.Hostname() == "" || repository.User != nil && repository.Scheme == "https" || repository.RawQuery != "" || repository.Fragment != "" {
		return nil, errors.New("repository URL cannot be mapped to a provider API")
	}
	credentialHost := strings.ToLower(strings.TrimSpace(strings.Split(delivery.CredentialServer, ":")[0]))
	if !strings.EqualFold(repository.Hostname(), credentialHost) {
		return nil, errors.New("status credential server does not match repository host")
	}
	repositoryPath := strings.TrimSuffix(strings.Trim(repository.Path, "/"), ".git")
	parts := strings.Split(repositoryPath, "/")
	if len(parts) < 2 || strings.Contains(repositoryPath, "..") {
		return nil, errors.New("repository URL has no owner and repository path")
	}
	description := "Dockyard deployment " + delivery.State
	var endpoint string
	var body []byte
	contentType := "application/json"
	state := delivery.State
	switch delivery.Provider {
	case "github":
		if credentialHost != "github.com" || len(parts) != 2 {
			return nil, errors.New("GitHub statuses require a github.com owner/repository URL")
		}
		endpoint = "https://api.github.com/repos/" + url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1]) + "/statuses/" + delivery.CommitSHA
		body, _ = json.Marshal(map[string]string{"state": state, "context": delivery.Context, "description": description})
	case "gitea":
		if len(parts) != 2 {
			return nil, errors.New("Gitea statuses require an owner/repository URL")
		}
		endpoint = "https://" + delivery.CredentialServer + "/api/v1/repos/" + url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1]) + "/statuses/" + delivery.CommitSHA
		body, _ = json.Marshal(map[string]string{"state": state, "context": delivery.Context, "description": description})
	case "gitlab":
		endpoint = "https://" + delivery.CredentialServer + "/api/v4/projects/" + url.PathEscape(repositoryPath) + "/statuses/" + delivery.CommitSHA
		values := url.Values{"state": {map[string]string{"failure": "failed", "error": "failed"}[state]}, "name": {delivery.Context}, "description": {description}}
		if state == "pending" || state == "success" {
			values.Set("state", state)
		}
		body, contentType = []byte(values.Encode()), "application/x-www-form-urlencoded"
	case "bitbucket":
		if credentialHost != "bitbucket.org" || len(parts) != 2 {
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
	if !validCommitForStatus(delivery.CommitSHA) || token == "" {
		return nil, errors.New("commit status has invalid credentials or commit SHA")
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
	if (len(value) != 40 && len(value) != 64) || path.Clean(value) != value {
		return false
	}
	for _, char := range value {
		if !strings.ContainsRune("0123456789abcdef", char) {
			return false
		}
	}
	return strings.Trim(value, "0") != ""
}
