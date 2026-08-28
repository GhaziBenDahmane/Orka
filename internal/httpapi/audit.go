package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
)

func auditPage(r *http.Request, ascending bool) (int64, int, error) {
	cursorName := "beforeId"
	if ascending {
		cursorName = "afterId"
	}
	var cursor int64
	var err error
	if raw := r.URL.Query().Get(cursorName); raw != "" {
		cursor, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || cursor < 0 {
			return 0, 0, errors.New(cursorName + " must be a non-negative integer")
		}
	}
	limit := 200
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 10000 {
			return 0, 0, errors.New("limit must be between 1 and 10000")
		}
	}
	return cursor, limit, nil
}

func (s *Server) exportAuditEvents(w http.ResponseWriter, r *http.Request) {
	afterID, limit, err := auditPage(r, true)
	if err != nil {
		writeError(w, 400, "invalid_cursor", err.Error())
		return
	}
	items, err := s.Store.ListAuditEvents(r.Context(), principal(r).OrganizationID, afterID, limit, true)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	var payload bytes.Buffer
	encoder := json.NewEncoder(&payload)
	for _, item := range items {
		if err = encoder.Encode(item); err != nil {
			writeError(w, 500, "export_failed", err.Error())
			return
		}
	}
	digest := sha256.Sum256(payload.Bytes())
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", `attachment; filename="dockyard-audit.ndjson"`)
	w.Header().Set("X-Content-SHA256", hex.EncodeToString(digest[:]))
	if len(items) > 0 {
		w.Header().Set("X-Next-After-ID", strconv.FormatInt(items[len(items)-1].ID, 10))
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload.Bytes())
}

func (s *Server) getAuditRetention(w http.ResponseWriter, r *http.Request) {
	item, err := s.Store.GetAuditRetentionPolicy(r.Context(), principal(r).OrganizationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, item)
}

func (s *Server) putAuditRetention(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RetentionDays int `json:"retentionDays"`
	}
	if !decode(w, r, &in) {
		return
	}
	p := principal(r)
	item, err := s.Store.UpsertAuditRetentionPolicy(r.Context(), p.OrganizationID, in.RetentionDays)
	if err != nil {
		writeError(w, 400, "invalid_retention", err.Error())
		return
	}
	s.Store.Audit(r.Context(), &p, "audit.retention.update", "organization", p.OrganizationID.String(), r.RemoteAddr, map[string]any{"retentionDays": in.RetentionDays})
	writeJSON(w, 200, item)
}
