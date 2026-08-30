package httpapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/bendahma/dokploy-go/internal/auth"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/bendahma/dokploy-go/internal/templates"
	"github.com/google/uuid"
)

const maxTemplateRepositoryNameBytes = 120

func (s *Server) createTemplateRepository(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name, Slug, RepositoryURL, GitRef, CatalogPath string
		TrustedPublicKey                               string
		RequireSignature                               bool
		CredentialID                                   string
		SyncIntervalSeconds                            int
	}
	if !decode(w, r, &in) {
		return
	}
	in.Name, in.Slug = strings.TrimSpace(in.Name), strings.TrimSpace(in.Slug)
	if in.GitRef == "" {
		in.GitRef = "main"
	}
	cleanPath, pathErr := templates.NormalizeCatalogPath(in.CatalogPath)
	if in.Name == "" || len(in.Name) > maxTemplateRepositoryNameBytes || strings.ContainsAny(in.Name, "\x00\r\n") || !slugPattern.MatchString(in.Slug) || pathErr != nil {
		writeError(w, 400, "invalid_template_repository", "name, slug, and a safe relative catalogPath are required")
		return
	}
	if _, err := templates.GitHubArchiveURL(in.RepositoryURL, in.GitRef); err != nil {
		writeError(w, 400, "invalid_template_repository", err.Error())
		return
	}
	in.TrustedPublicKey = strings.TrimSpace(in.TrustedPublicKey)
	if len(in.TrustedPublicKey) > 16<<10 {
		writeError(w, 400, "invalid_template_repository", "trustedPublicKey exceeds 16 KiB")
		return
	}
	if in.RequireSignature && in.TrustedPublicKey == "" {
		writeError(w, 400, "invalid_template_repository", "trustedPublicKey is required when requireSignature is enabled")
		return
	}
	if !validTemplateSyncInterval(in.SyncIntervalSeconds) {
		writeError(w, 400, "invalid_template_repository", "syncIntervalSeconds must be zero or between 300 and 604800")
		return
	}
	credentialID, err := s.templateRepositoryCredential(r.Context(), principal(r).OrganizationID, in.CredentialID)
	if err != nil {
		writeError(w, 400, "invalid_template_repository", err.Error())
		return
	}
	signerFingerprint := ""
	if in.TrustedPublicKey != "" {
		key, keyErr := templates.ParsePublicKey([]byte(in.TrustedPublicKey))
		if keyErr != nil {
			writeError(w, 400, "invalid_template_repository", keyErr.Error())
			return
		}
		signerFingerprint = templates.PublicKeyFingerprint(key)
	}
	p := principal(r)
	item, err := s.Store.CreateTemplateRepository(r.Context(), store.TemplateRepository{OrganizationID: p.OrganizationID, Name: in.Name, Slug: in.Slug, RepositoryURL: strings.TrimSpace(in.RepositoryURL), GitRef: strings.TrimSpace(in.GitRef), CatalogPath: cleanPath, TrustedPublicKey: in.TrustedPublicKey, RequireSignature: in.RequireSignature, CredentialID: credentialID, SyncIntervalSeconds: in.SyncIntervalSeconds})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "template_repository.create", "template_repository", item.ID.String(), r.RemoteAddr, map[string]any{"repositoryUrl": item.RepositoryURL, "gitRef": item.GitRef, "requireSignature": item.RequireSignature, "signerFingerprint": signerFingerprint, "credentialId": item.CredentialID, "syncIntervalSeconds": item.SyncIntervalSeconds})
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) listTemplateRepositories(w http.ResponseWriter, r *http.Request) {
	items, err := s.Store.ListTemplateRepositories(r.Context(), principal(r).OrganizationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) updateTemplateRepositorySettings(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("repositoryID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid template repository id")
		return
	}
	var in struct {
		TrustedPublicKey    string
		RequireSignature    bool
		CredentialID        string
		SyncIntervalSeconds int
	}
	if !decode(w, r, &in) {
		return
	}
	in.TrustedPublicKey = strings.TrimSpace(in.TrustedPublicKey)
	if len(in.TrustedPublicKey) > 16<<10 {
		writeError(w, 400, "invalid_template_repository", "trustedPublicKey exceeds 16 KiB")
		return
	}
	if in.RequireSignature && in.TrustedPublicKey == "" {
		writeError(w, 400, "invalid_template_repository", "trustedPublicKey is required when requireSignature is enabled")
		return
	}
	if !validTemplateSyncInterval(in.SyncIntervalSeconds) {
		writeError(w, 400, "invalid_template_repository", "syncIntervalSeconds must be zero or between 300 and 604800")
		return
	}
	credentialID, err := s.templateRepositoryCredential(r.Context(), principal(r).OrganizationID, in.CredentialID)
	if err != nil {
		writeError(w, 400, "invalid_template_repository", err.Error())
		return
	}
	fingerprint := ""
	if in.TrustedPublicKey != "" {
		key, keyErr := templates.ParsePublicKey([]byte(in.TrustedPublicKey))
		if keyErr != nil {
			writeError(w, 400, "invalid_template_repository", keyErr.Error())
			return
		}
		fingerprint = templates.PublicKeyFingerprint(key)
	}
	p := principal(r)
	if err = s.Store.UpdateTemplateRepositorySettings(r.Context(), p.OrganizationID, id, in.TrustedPublicKey, in.RequireSignature, credentialID, in.SyncIntervalSeconds); err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "template_repository.settings.update", "template_repository", id.String(), r.RemoteAddr, map[string]any{"requireSignature": in.RequireSignature, "signerFingerprint": fingerprint, "credentialId": credentialID, "syncIntervalSeconds": in.SyncIntervalSeconds})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) templateRepositoryCredential(ctx context.Context, organizationID uuid.UUID, raw string) (*uuid.UUID, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		return nil, errors.New("credentialId must be a UUID")
	}
	credential, err := s.Store.GetSourceCredential(ctx, organizationID, id)
	if err != nil {
		return nil, errors.New("credentialId must reference an organization credential")
	}
	if credential.Kind != "git" || !strings.EqualFold(strings.TrimSpace(credential.Server), "github.com") {
		return nil, errors.New("credentialId must reference a GitHub HTTPS token credential")
	}
	return &id, nil
}

func validTemplateSyncInterval(seconds int) bool {
	return seconds == 0 || seconds >= 300 && seconds <= 604800
}

func (s *Server) rotateTemplateRepositoryWebhookSecret(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("repositoryID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid template repository id")
		return
	}
	secret, err := auth.NewToken()
	if err != nil {
		s.writeInternalError(w, r, 500, "token_failed", "template webhook secret could not be generated", err)
		return
	}
	encrypted, err := s.Box.Encrypt([]byte(secret), "template-repository-webhook:"+id.String())
	if err != nil {
		writeError(w, 500, "encryption_failed", "template repository webhook secret could not be encrypted")
		return
	}
	p := principal(r)
	if err = s.Store.SetTemplateRepositoryWebhookSecret(r.Context(), p.OrganizationID, id, encrypted); err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "template_repository.webhook.rotate", "template_repository", id.String(), r.RemoteAddr, nil)
	writeJSON(w, http.StatusCreated, map[string]any{"secret": secret, "url": s.PublicURL + "/v1/hooks/template-repositories/" + id.String()})
}

func (s *Server) disableTemplateRepositoryWebhook(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("repositoryID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid template repository id")
		return
	}
	p := principal(r)
	if err = s.Store.ClearTemplateRepositoryWebhookSecret(r.Context(), p.OrganizationID, id); err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "template_repository.webhook.disable", "template_repository", id.String(), r.RemoteAddr, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) templateRepositoryWebhook(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("repositoryID"))
	if err != nil {
		writeError(w, 404, "not_found", "template repository webhook not found")
		return
	}
	repository, err := s.Store.GetTemplateRepositoryForWebhook(r.Context(), id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	secret, err := s.Box.Decrypt(repository.EncryptedWebhookSecret, "template-repository-webhook:"+id.String())
	if err != nil {
		writeError(w, 500, "decryption_failed", "template repository webhook configuration cannot be decrypted")
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
	deliveryID, refs, err := verifyProviderWebhook("github", string(secret), r.Header, body)
	if errors.Is(err, errWebhookIgnored) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		writeError(w, 401, "invalid_webhook", "webhook signature or payload is invalid")
		return
	}
	matched := false
	wanted := strings.TrimPrefix(strings.TrimPrefix(repository.GitRef, "refs/heads/"), "refs/tags/")
	for _, ref := range refs {
		actual := strings.TrimPrefix(strings.TrimPrefix(ref.Branch, "refs/heads/"), "refs/tags/")
		if actual == wanted || strings.EqualFold(ref.CommitSHA, repository.GitRef) {
			matched = true
			break
		}
	}
	if !matched {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err = s.Store.RequestTemplateRepositorySync(r.Context(), id, deliveryID); errors.Is(err, store.ErrDuplicateDelivery) {
		writeError(w, 409, "duplicate_delivery", err.Error())
		return
	} else if err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.AuditOrganization(r.Context(), repository.OrganizationID, "template_repository.webhook", "template_repository", id.String(), r.RemoteAddr, map[string]any{"deliveryId": deliveryID, "gitRef": repository.GitRef})
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "queued"})
}

func (s *Server) syncTemplateRepository(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("repositoryID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid template repository id")
		return
	}
	p := principal(r)
	requestedAt, err := s.Store.QueueTemplateRepositorySync(r.Context(), p.OrganizationID, id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "template_repository.sync.queued", "template_repository", id.String(), r.RemoteAddr, map[string]any{"requestedAt": requestedAt})
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "queued", "requestedAt": requestedAt})
}

func (s *Server) deleteTemplateRepository(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("repositoryID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid template repository id")
		return
	}
	p := principal(r)
	if err = s.Store.DeleteTemplateRepository(r.Context(), p.OrganizationID, id); err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "template_repository.delete", "template_repository", id.String(), r.RemoteAddr, nil)
	w.WriteHeader(http.StatusNoContent)
}
