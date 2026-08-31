package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/bendahma/dokploy-go/internal/auth"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

var webhookBranchPattern = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,200}$`)
var errWebhookIgnored = errors.New("webhook event does not match the configured branch")

type webhookRef struct {
	Branch    string
	CommitSHA string
}

func (s *Server) createWebhookIntegration(w http.ResponseWriter, r *http.Request) {
	serviceID, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid service id")
		return
	}
	var in struct {
		Name     string `json:"name"`
		Provider string `json:"provider"`
		Branch   string `json:"branch"`
	}
	if !decode(w, r, &in) {
		return
	}
	name, nameErr := normalizeResourceName(in.Name)
	in.Name = name
	in.Provider = strings.ToLower(strings.TrimSpace(in.Provider))
	in.Branch = strings.TrimPrefix(strings.TrimSpace(in.Branch), "refs/heads/")
	if nameErr != nil || !contains([]string{"github", "gitlab", "gitea", "bitbucket"}, in.Provider) || !webhookBranchPattern.MatchString(in.Branch) || strings.Contains(in.Branch, "..") {
		writeError(w, 400, "invalid_webhook", "name, supported provider, and branch are required")
		return
	}
	secret, err := auth.NewToken()
	if err != nil {
		s.writeInternalError(w, r, 500, "token_failed", "webhook secret could not be generated", err)
		return
	}
	id := uuid.New()
	encrypted, err := s.Box.Encrypt([]byte(secret), "webhook-secret:"+id.String())
	if err != nil {
		s.writeInternalError(w, r, 500, "encryption_failed", "webhook secret could not be encrypted", err)
		return
	}
	p := principal(r)
	item, err := s.Store.CreateWebhookIntegrationWithAudit(r.Context(), p, store.WebhookIntegration{ID: id, ComposeServiceID: serviceID, Name: in.Name, Provider: in.Provider, Branch: in.Branch, EncryptedSecret: encrypted}, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 201, map[string]any{"integration": item, "secret": secret, "url": s.PublicURL + "/v1/hooks/provider/" + item.ID.String()})
}

func (s *Server) listWebhookIntegrations(w http.ResponseWriter, r *http.Request) {
	serviceID, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid service id")
		return
	}
	items, err := s.Store.ListWebhookIntegrations(r.Context(), principal(r).OrganizationID, serviceID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) deleteWebhookIntegration(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("integrationID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid webhook integration id")
		return
	}
	p := principal(r)
	if err = s.Store.DisableWebhookIntegrationWithAudit(r.Context(), p, id, r.RemoteAddr); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) providerWebhook(w http.ResponseWriter, r *http.Request) {
	rawID := r.PathValue("integrationID")
	if !s.allowPublicWebhookAttempt(w, r, "provider", rawID) {
		return
	}
	id, err := uuid.Parse(rawID)
	if err != nil {
		writeError(w, 404, "not_found", "webhook integration not found")
		return
	}
	integration, err := s.Store.GetWebhookIntegration(r.Context(), id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	secret, err := s.Box.Decrypt(integration.EncryptedSecret, "webhook-secret:"+integration.ID.String())
	if err != nil {
		writeError(w, 500, "decryption_failed", "webhook configuration cannot be decrypted")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large", "webhook body exceeds 2 MiB")
		} else {
			writeError(w, 400, "invalid_payload", "webhook body could not be read")
		}
		return
	}
	deliveryID, refs, err := verifyProviderWebhook(integration.Provider, string(secret), r.Header, body)
	if errors.Is(err, errWebhookIgnored) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		writeError(w, 401, "invalid_webhook", "webhook signature or payload is invalid")
		return
	}
	commitSHA := ""
	for _, ref := range refs {
		if strings.EqualFold(strings.TrimPrefix(ref.Branch, "refs/heads/"), integration.Branch) {
			commitSHA = ref.CommitSHA
			break
		}
	}
	if commitSHA == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	deployment, err := s.Store.QueueWebhookDeploymentWithAudit(r.Context(), integration.ID, deliveryID, commitSHA, r.RemoteAddr)
	if errors.Is(err, store.ErrDuplicateDelivery) {
		writeError(w, 409, "duplicate_delivery", err.Error())
		return
	}
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, deployment)
}

func verifyProviderWebhook(provider, secret string, header http.Header, body []byte) (string, []webhookRef, error) {
	var deliveryID, event string
	switch provider {
	case "github":
		if !validHMACSignature(secret, body, header.Get("X-Hub-Signature-256")) {
			return "", nil, errors.New("invalid signature")
		}
		deliveryID, event = header.Get("X-GitHub-Delivery"), header.Get("X-GitHub-Event")
	case "gitea":
		signature := header.Get("X-Gitea-Signature")
		if signature == "" {
			signature = header.Get("X-Hub-Signature-256")
		}
		if !validHMACSignature(secret, body, signature) {
			return "", nil, errors.New("invalid signature")
		}
		deliveryID, event = header.Get("X-Gitea-Delivery"), header.Get("X-Gitea-Event")
	case "gitlab":
		if !hmac.Equal([]byte(header.Get("X-Gitlab-Token")), []byte(secret)) {
			return "", nil, errors.New("invalid token")
		}
		deliveryID, event = header.Get("X-Gitlab-Event-UUID"), header.Get("X-Gitlab-Event")
	case "bitbucket":
		if !validHMACSignature(secret, body, header.Get("X-Hub-Signature")) {
			return "", nil, errors.New("invalid signature")
		}
		deliveryID, event = header.Get("X-Request-UUID"), header.Get("X-Event-Key")
	default:
		return "", nil, errors.New("unsupported provider")
	}
	deliveryID = strings.TrimSpace(deliveryID)
	if deliveryID == "" || len(deliveryID) > 255 {
		return "", nil, errors.New("missing delivery id")
	}
	if !isPushEvent(provider, event) {
		return "", nil, errWebhookIgnored
	}
	if provider == "bitbucket" {
		var payload struct {
			Push struct {
				Changes []struct {
					New *struct {
						Name   string `json:"name"`
						Type   string `json:"type"`
						Target struct {
							Hash string `json:"hash"`
						} `json:"target"`
					} `json:"new"`
				} `json:"changes"`
			} `json:"push"`
		}
		if json.Unmarshal(body, &payload) != nil {
			return "", nil, errors.New("invalid payload")
		}
		refs := []webhookRef{}
		for _, change := range payload.Push.Changes {
			if change.New != nil && change.New.Type == "branch" && change.New.Name != "" && validCommitSHA(change.New.Target.Hash) {
				refs = append(refs, webhookRef{Branch: change.New.Name, CommitSHA: strings.ToLower(change.New.Target.Hash)})
			}
		}
		if len(refs) == 0 {
			return "", nil, errWebhookIgnored
		}
		return deliveryID, refs, nil
	}
	var payload struct {
		Ref     string `json:"ref"`
		After   string `json:"after"`
		Deleted bool   `json:"deleted"`
	}
	if json.Unmarshal(body, &payload) != nil || payload.Ref == "" || !validCommitSHA(payload.After) {
		return "", nil, errors.New("invalid payload")
	}
	if payload.Deleted {
		return "", nil, errWebhookIgnored
	}
	return deliveryID, []webhookRef{{Branch: payload.Ref, CommitSHA: strings.ToLower(payload.After)}}, nil
}

func validCommitSHA(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, char := range value {
		if !strings.ContainsRune("0123456789abcdefABCDEF", char) {
			return false
		}
	}
	return strings.Trim(value, "0") != ""
}

func validHMACSignature(secret string, body []byte, signature string) bool {
	signature = strings.TrimPrefix(strings.TrimSpace(signature), "sha256=")
	received, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return hmac.Equal(received, mac.Sum(nil))
}

func isPushEvent(provider, event string) bool {
	switch provider {
	case "github", "gitea":
		return strings.EqualFold(event, "push")
	case "gitlab":
		return strings.EqualFold(event, "Push Hook")
	case "bitbucket":
		return strings.EqualFold(event, "repo:push")
	default:
		return false
	}
}
