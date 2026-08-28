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
	in.Name = strings.TrimSpace(in.Name)
	in.Provider = strings.ToLower(strings.TrimSpace(in.Provider))
	in.Branch = strings.TrimPrefix(strings.TrimSpace(in.Branch), "refs/heads/")
	if in.Name == "" || !contains([]string{"github", "gitlab", "gitea", "bitbucket"}, in.Provider) || !webhookBranchPattern.MatchString(in.Branch) || strings.Contains(in.Branch, "..") {
		writeError(w, 400, "invalid_webhook", "name, supported provider, and branch are required")
		return
	}
	secret, err := auth.NewToken()
	if err != nil {
		writeError(w, 500, "token_failed", err.Error())
		return
	}
	id := uuid.New()
	encrypted, err := s.Box.Encrypt([]byte(secret), "webhook-secret:"+id.String())
	if err != nil {
		writeError(w, 500, "encryption_failed", err.Error())
		return
	}
	p := principal(r)
	item, err := s.Store.CreateWebhookIntegration(r.Context(), p.OrganizationID, store.WebhookIntegration{ID: id, ComposeServiceID: serviceID, Name: in.Name, Provider: in.Provider, Branch: in.Branch, EncryptedSecret: encrypted})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "webhook.create", "webhook_integration", item.ID.String(), r.RemoteAddr, map[string]any{"provider": item.Provider, "branch": item.Branch})
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
	if err = s.Store.DisableWebhookIntegration(r.Context(), p.OrganizationID, id); err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "webhook.disable", "webhook_integration", id.String(), r.RemoteAddr, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) providerWebhook(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("integrationID"))
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
		writeError(w, 400, "invalid_payload", "webhook body is too large")
		return
	}
	deliveryID, branches, err := verifyProviderWebhook(integration.Provider, string(secret), r.Header, body)
	if errors.Is(err, errWebhookIgnored) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		writeError(w, 401, "invalid_webhook", "webhook signature or payload is invalid")
		return
	}
	matchesBranch := false
	for _, branch := range branches {
		if strings.EqualFold(strings.TrimPrefix(branch, "refs/heads/"), integration.Branch) {
			matchesBranch = true
			break
		}
	}
	if !matchesBranch {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	deployment, err := s.Store.QueueWebhookDeployment(r.Context(), integration.ID, deliveryID)
	if errors.Is(err, store.ErrDuplicateDelivery) {
		writeError(w, 409, "duplicate_delivery", err.Error())
		return
	}
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.AuditOrganization(r.Context(), integration.OrganizationID, "deployment.webhook", "deployment", deployment.ID.String(), r.RemoteAddr, map[string]any{"provider": integration.Provider, "deliveryId": deliveryID})
	writeJSON(w, http.StatusAccepted, deployment)
}

func verifyProviderWebhook(provider, secret string, header http.Header, body []byte) (string, []string, error) {
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
						Name string `json:"name"`
						Type string `json:"type"`
					} `json:"new"`
				} `json:"changes"`
			} `json:"push"`
		}
		if json.Unmarshal(body, &payload) != nil {
			return "", nil, errors.New("invalid payload")
		}
		branches := []string{}
		for _, change := range payload.Push.Changes {
			if change.New != nil && change.New.Type == "branch" && change.New.Name != "" {
				branches = append(branches, change.New.Name)
			}
		}
		if len(branches) == 0 {
			return "", nil, errWebhookIgnored
		}
		return deliveryID, branches, nil
	}
	var payload struct {
		Ref     string `json:"ref"`
		Deleted bool   `json:"deleted"`
	}
	if json.Unmarshal(body, &payload) != nil || payload.Ref == "" {
		return "", nil, errors.New("invalid payload")
	}
	if payload.Deleted {
		return "", nil, errWebhookIgnored
	}
	return deliveryID, []string{payload.Ref}, nil
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
