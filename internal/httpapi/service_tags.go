package httpapi

import (
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/bendahma/dokploy-go/internal/store"
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
	item, err := s.Store.CreateTag(r.Context(), p.OrganizationID, store.Tag{Name: input.Name, Color: input.Color})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "tag.create", "tag", item.ID.String(), r.RemoteAddr, map[string]any{"name": item.Name})
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
	item, err := s.Store.UpdateTag(r.Context(), p.OrganizationID, id, input.Name, input.Color)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "tag.update", "tag", id.String(), r.RemoteAddr, map[string]any{"name": item.Name})
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) deleteTag(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("tagID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid tag id")
		return
	}
	p := principal(r)
	if err = s.Store.DeleteTag(r.Context(), p.OrganizationID, id); err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "tag.delete", "tag", id.String(), r.RemoteAddr, nil)
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
	items, err := s.Store.ReplaceServiceTags(r.Context(), p.OrganizationID, serviceID, input.TagIDs)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "service.tags.replace", "compose_service", serviceID.String(), r.RemoteAddr, map[string]any{"count": len(items)})
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
