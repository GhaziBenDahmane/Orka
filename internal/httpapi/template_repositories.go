package httpapi

import (
	"errors"
	"net/http"
	"path"
	"strings"

	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/bendahma/dokploy-go/internal/templates"
	"github.com/google/uuid"
)

func (s *Server) createTemplateRepository(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name, Slug, RepositoryURL, GitRef, CatalogPath string
		TrustedPublicKey                               string
		RequireSignature                               bool
		SyncIntervalSeconds                            int
	}
	if !decode(w, r, &in) {
		return
	}
	in.Name, in.Slug = strings.TrimSpace(in.Name), strings.TrimSpace(in.Slug)
	if in.GitRef == "" {
		in.GitRef = "main"
	}
	in.CatalogPath = strings.Trim(strings.TrimSpace(in.CatalogPath), "/")
	cleanPath := path.Clean(in.CatalogPath)
	if cleanPath == "." {
		cleanPath = ""
	}
	if in.Name == "" || !slugPattern.MatchString(in.Slug) || cleanPath == ".." || strings.HasPrefix(cleanPath, "../") {
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
	item, err := s.Store.CreateTemplateRepository(r.Context(), store.TemplateRepository{OrganizationID: p.OrganizationID, Name: in.Name, Slug: in.Slug, RepositoryURL: strings.TrimSpace(in.RepositoryURL), GitRef: strings.TrimSpace(in.GitRef), CatalogPath: cleanPath, TrustedPublicKey: in.TrustedPublicKey, RequireSignature: in.RequireSignature, SyncIntervalSeconds: in.SyncIntervalSeconds})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "template_repository.create", "template_repository", item.ID.String(), r.RemoteAddr, map[string]any{"repositoryUrl": item.RepositoryURL, "gitRef": item.GitRef, "requireSignature": item.RequireSignature, "signerFingerprint": signerFingerprint, "syncIntervalSeconds": item.SyncIntervalSeconds})
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
	if err = s.Store.UpdateTemplateRepositorySettings(r.Context(), p.OrganizationID, id, in.TrustedPublicKey, in.RequireSignature, in.SyncIntervalSeconds); err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "template_repository.settings.update", "template_repository", id.String(), r.RemoteAddr, map[string]any{"requireSignature": in.RequireSignature, "signerFingerprint": fingerprint, "syncIntervalSeconds": in.SyncIntervalSeconds})
	w.WriteHeader(http.StatusNoContent)
}

func validTemplateSyncInterval(seconds int) bool {
	return seconds == 0 || seconds >= 300 && seconds <= 604800
}

func (s *Server) syncTemplateRepository(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("repositoryID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid template repository id")
		return
	}
	p := principal(r)
	repository, err := s.Store.GetTemplateRepository(r.Context(), p.OrganizationID, id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if !repository.Enabled {
		writeError(w, 409, "repository_disabled", "template repository is disabled")
		return
	}
	repository, err = s.Store.BeginTemplateRepositorySync(r.Context(), p.OrganizationID, id)
	if errors.Is(err, store.ErrBusy) {
		writeError(w, 409, "repository_sync_running", "template repository sync is already running")
		return
	}
	if err != nil {
		writeStoreError(w, err)
		return
	}
	report, err := templates.SyncClaimedRepository(r.Context(), s.Store, nil, repository)
	if err != nil {
		writeError(w, 422, "template_repository_sync_failed", err.Error())
		return
	}
	s.Store.Audit(r.Context(), &p, "template_repository.sync", "template_repository", id.String(), r.RemoteAddr, map[string]any{"imported": report.Imported, "failed": len(report.Failed), "scheduled": false})
	writeJSON(w, 200, report)
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
