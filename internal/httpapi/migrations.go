package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	dockyardmigrate "github.com/bendahma/dokploy-go/internal/migrate"
	"github.com/bendahma/dokploy-go/internal/store"
)

func (s *Server) listMigrationResources(w http.ResponseWriter, r *http.Request) {
	sourceOrganizationID := strings.TrimSpace(r.URL.Query().Get("sourceOrganizationId"))
	if len(sourceOrganizationID) > 255 {
		writeError(w, http.StatusBadRequest, "invalid_source_organization", "sourceOrganizationId is too long")
		return
	}
	limit := 250
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 500 {
			writeError(w, http.StatusBadRequest, "invalid_page", "limit must be between 1 and 500")
			return
		}
		limit = parsed
	}
	var cursor *store.MigrationResourcePageCursor
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		parsed, err := decodeMigrationResourceCursor(raw, sourceOrganizationID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_cursor", "migration resource cursor is invalid")
			return
		}
		cursor = parsed
	}
	items, hasMore, err := s.Store.ListMigrationResourcesPage(r.Context(), principal(r).OrganizationID, sourceOrganizationID, cursor, limit)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	nextCursor := ""
	if hasMore && len(items) > 0 {
		last := items[len(items)-1]
		nextCursor, err = encodeMigrationResourceCursor(sourceOrganizationID, store.MigrationResourcePageCursor{SourceOrganizationID: last.SourceOrganizationID, SourceKind: last.SourceKind, SourceID: last.SourceID})
		if err != nil {
			s.writeInternalError(w, r, http.StatusInternalServerError, "cursor_failed", "migration resource cursor could not be created", err)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "nextCursor": nextCursor})
}

type migrationResourceCursorPayload struct {
	Filter               string `json:"f"`
	SourceOrganizationID string `json:"o"`
	SourceKind           string `json:"k"`
	SourceID             string `json:"i"`
}

func encodeMigrationResourceCursor(filter string, cursor store.MigrationResourcePageCursor) (string, error) {
	payload, err := json.Marshal(migrationResourceCursorPayload{Filter: filter, SourceOrganizationID: cursor.SourceOrganizationID, SourceKind: cursor.SourceKind, SourceID: cursor.SourceID})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func decodeMigrationResourceCursor(raw, filter string) (*store.MigrationResourcePageCursor, error) {
	if len(raw) > 8192 {
		return nil, errors.New("cursor is too long")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	var payload migrationResourceCursorPayload
	if err = json.Unmarshal(decoded, &payload); err != nil {
		return nil, err
	}
	if payload.Filter != filter || payload.SourceOrganizationID == "" || payload.SourceKind == "" || payload.SourceID == "" {
		return nil, errors.New("cursor payload is invalid")
	}
	return &store.MigrationResourcePageCursor{SourceOrganizationID: payload.SourceOrganizationID, SourceKind: payload.SourceKind, SourceID: payload.SourceID}, nil
}

func (s *Server) verifyDokployMigration(w http.ResponseWriter, r *http.Request) {
	var input struct {
		SourceOrganizationID string   `json:"sourceOrganizationId"`
		RequireOperational   *bool    `json:"requireOperational"`
		Acknowledgements     []string `json:"acknowledgements"`
	}
	if !decode(w, r, &input) {
		return
	}
	input.SourceOrganizationID = strings.TrimSpace(input.SourceOrganizationID)
	if input.SourceOrganizationID == "" || len(input.SourceOrganizationID) > 255 {
		writeError(w, http.StatusBadRequest, "invalid_source_organization", "sourceOrganizationId is required and must not exceed 255 bytes")
		return
	}
	acknowledgements, err := normalizeMigrationAcknowledgements(input.Acknowledgements)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_acknowledgement", err.Error())
		return
	}
	requireOperational := true
	if input.RequireOperational != nil {
		requireOperational = *input.RequireOperational
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	p := principal(r)
	report, err := dockyardmigrate.VerifyDokployImport(ctx, s.Store, p.OrganizationID, input.SourceOrganizationID, requireOperational, acknowledgements)
	if errors.Is(err, dockyardmigrate.ErrDokployManifestNotFound) || errors.Is(err, dockyardmigrate.ErrDokployManifestOutdated) {
		writeError(w, http.StatusConflict, "migration_verification_unavailable", err.Error())
		return
	}
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if err = s.Store.RecordDokployVerificationWithAudit(ctx, p, input.SourceOrganizationID, requireOperational, report.Verified, report.Acknowledged, report.Blocked, report.Ready, r.RemoteAddr); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func normalizeMigrationAcknowledgements(values []string) ([]string, error) {
	if len(values) > 1000 {
		return nil, errors.New("at most 1000 acknowledgements are allowed")
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		kind, sourceID, found := strings.Cut(value, ":")
		if !found || kind == "" || sourceID == "" || len(value) > 1024 {
			return nil, errors.New("each acknowledgement must use kind:source-id and not exceed 1024 bytes")
		}
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result, nil
}
