package httpapi

import (
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/GhaziBenDahmane/Orka/internal/store"
	"github.com/google/uuid"
)

var tagColorPattern = regexp.MustCompile(`^#[0-9A-Fa-f]{6}$`)

type tagInput struct {
	Name  string `json:"name"`
	Color string `json:"color"`
}

func validateTagInput(input *tagInput) bool {
	input.Name = strings.TrimSpace(input.Name)
	input.Color = strings.ToUpper(strings.TrimSpace(input.Color))
	return input.Name != "" && utf8.ValidString(input.Name) && utf8.RuneCountInString(input.Name) <= 64 && !strings.ContainsAny(input.Name, "\x00\r\n\t") && tagColorPattern.MatchString(input.Color)
}

func (s *Server) listTags(w http.ResponseWriter, r *http.Request) {
	items, err := s.Store.ListTags(r.Context(), principal(r).OrganizationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) getTag(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("tagID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid tag id")
		return
	}
	item, err := s.Store.GetTag(r.Context(), principal(r).OrganizationID, id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) createTag(w http.ResponseWriter, r *http.Request) {
	var input tagInput
	if !decode(w, r, &input) {
		return
	}
	if !validateTagInput(&input) {
		writeError(w, http.StatusBadRequest, "invalid_tag", "tag name must be 1-64 characters and color must be a six-digit hex value")
		return
	}
	p := principal(r)
	item, err := s.Store.CreateTagWithAudit(r.Context(), p, store.Tag{Name: input.Name, Color: input.Color}, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) updateTag(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("tagID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid tag id")
		return
	}
	var input tagInput
	if !decode(w, r, &input) {
		return
	}
	if !validateTagInput(&input) {
		writeError(w, http.StatusBadRequest, "invalid_tag", "tag name must be 1-64 characters and color must be a six-digit hex value")
		return
	}
	p := principal(r)
	item, err := s.Store.UpdateTagWithAudit(r.Context(), p, id, input.Name, input.Color, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) deleteTag(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("tagID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid tag id")
		return
	}
	p := principal(r)
	if err = s.Store.DeleteTagWithAudit(r.Context(), p, id, r.RemoteAddr); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listServiceTags(w http.ResponseWriter, r *http.Request) {
	serviceID, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid service id")
		return
	}
	items, err := s.Store.ListServiceTags(r.Context(), principal(r).OrganizationID, serviceID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) replaceServiceTags(w http.ResponseWriter, r *http.Request) {
	serviceID, err := uuid.Parse(r.PathValue("serviceID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid service id")
		return
	}
	var input struct {
		TagIDs []uuid.UUID `json:"tagIds"`
	}
	if !decode(w, r, &input) {
		return
	}
	if len(input.TagIDs) > 32 {
		writeError(w, http.StatusBadRequest, "invalid_tags", "a service may have at most 32 tags")
		return
	}
	seen := make(map[uuid.UUID]struct{}, len(input.TagIDs))
	for _, id := range input.TagIDs {
		if id == uuid.Nil {
			writeError(w, http.StatusBadRequest, "invalid_tags", "tag ids must be non-zero UUIDs")
			return
		}
		if _, exists := seen[id]; exists {
			writeError(w, http.StatusBadRequest, "invalid_tags", "tag ids must be unique")
			return
		}
		seen[id] = struct{}{}
	}
	p := principal(r)
	items, err := s.Store.ReplaceServiceTagsWithAudit(r.Context(), p, serviceID, input.TagIDs, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) listProjectTags(w http.ResponseWriter, r *http.Request) {
	projectID, err := uuid.Parse(r.PathValue("projectID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid project id")
		return
	}
	items, err := s.Store.ListProjectTags(r.Context(), principal(r).OrganizationID, projectID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) replaceProjectTags(w http.ResponseWriter, r *http.Request) {
	projectID, err := uuid.Parse(r.PathValue("projectID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid project id")
		return
	}
	var input struct {
		TagIDs []uuid.UUID `json:"tagIds"`
	}
	if !decode(w, r, &input) {
		return
	}
	if len(input.TagIDs) > 32 {
		writeError(w, http.StatusBadRequest, "invalid_tags", "a project may have at most 32 tags")
		return
	}
	seen := make(map[uuid.UUID]struct{}, len(input.TagIDs))
	for _, id := range input.TagIDs {
		if id == uuid.Nil {
			writeError(w, http.StatusBadRequest, "invalid_tags", "tag ids must be non-zero UUIDs")
			return
		}
		if _, exists := seen[id]; exists {
			writeError(w, http.StatusBadRequest, "invalid_tags", "tag ids must be unique")
			return
		}
		seen[id] = struct{}{}
	}
	p := principal(r)
	items, err := s.Store.ReplaceProjectTagsWithAudit(r.Context(), p, projectID, input.TagIDs, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
