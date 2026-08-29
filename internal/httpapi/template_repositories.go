package httpapi

import (
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/bendahma/dokploy-go/internal/templates"
	"github.com/google/uuid"
)

func (s *Server) createTemplateRepository(w http.ResponseWriter, r *http.Request) {
	var in struct{ Name, Slug, RepositoryURL, GitRef, CatalogPath string }
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
	p := principal(r)
	item, err := s.Store.CreateTemplateRepository(r.Context(), store.TemplateRepository{OrganizationID: p.OrganizationID, Name: in.Name, Slug: in.Slug, RepositoryURL: strings.TrimSpace(in.RepositoryURL), GitRef: strings.TrimSpace(in.GitRef), CatalogPath: cleanPath})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "template_repository.create", "template_repository", item.ID.String(), r.RemoteAddr, map[string]any{"repositoryUrl": item.RepositoryURL, "gitRef": item.GitRef})
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
	if err = s.Store.SetTemplateRepositorySync(r.Context(), p.OrganizationID, id, "running", ""); err != nil {
		writeStoreError(w, err)
		return
	}
	client := &http.Client{Timeout: 45 * time.Second}
	root, cleanup, err := templates.FetchGitHubCatalog(r.Context(), client, repository.RepositoryURL, repository.GitRef)
	if err == nil {
		defer cleanup()
		var report templates.ImportReport
		report, err = templates.ImportRepositoryCatalog(r.Context(), s.Store, repository, root)
		if err == nil {
			_ = s.Store.SetTemplateRepositorySync(r.Context(), p.OrganizationID, id, "succeeded", "")
			s.Store.Audit(r.Context(), &p, "template_repository.sync", "template_repository", id.String(), r.RemoteAddr, map[string]any{"imported": report.Imported, "failed": len(report.Failed)})
			writeJSON(w, 200, report)
			return
		}
	}
	message := err.Error()
	if len(message) > 1000 {
		message = message[:1000]
	}
	_ = s.Store.SetTemplateRepositorySync(r.Context(), p.OrganizationID, id, "failed", message)
	writeError(w, 422, "template_repository_sync_failed", message)
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
