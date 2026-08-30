package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	backupstore "github.com/bendahma/dokploy-go/internal/backup"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
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

func (s *Server) createAuditArchive(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name                string    `json:"name"`
		BackupDestinationID uuid.UUID `json:"backupDestinationId"`
		ObjectPrefix        string    `json:"objectPrefix"`
		RetentionDays       int       `json:"retentionDays"`
	}
	if !decode(w, r, &input) {
		return
	}
	input.Name, input.ObjectPrefix = strings.TrimSpace(input.Name), strings.Trim(strings.TrimSpace(input.ObjectPrefix), "/")
	if input.ObjectPrefix == "" {
		input.ObjectPrefix = "audit"
	}
	if input.Name == "" || input.BackupDestinationID == uuid.Nil || input.RetentionDays < 30 || input.RetentionDays > 3650 || len(input.ObjectPrefix) > 200 || path.Clean(input.ObjectPrefix) != input.ObjectPrefix || strings.Contains(input.ObjectPrefix, "..") {
		writeError(w, 400, "invalid_audit_archive", "name, backup destination, safe object prefix, and 30-3650 retention days are required")
		return
	}
	p := principal(r)
	destination, err := s.Store.GetBackupDestination(r.Context(), p.OrganizationID, input.BackupDestinationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if !destination.UseTLS {
		writeError(w, 400, "invalid_audit_archive", "audit archives require a TLS S3 destination")
		return
	}
	credentialsJSON, err := s.Box.DecryptResource(destination.EncryptedCredentials, "backup-destination", destination.ID.String(), "backup-destination")
	if err != nil {
		writeError(w, 500, "decryption_failed", "backup destination cannot be decrypted")
		return
	}
	var credentials map[string]string
	if err = json.Unmarshal(credentialsJSON, &credentials); err != nil {
		writeError(w, 500, "decryption_failed", "backup destination is invalid")
		return
	}
	archive, err := backupstore.NewS3(backupstore.S3Config{Endpoint: destination.Endpoint, Region: destination.Region, Bucket: destination.Bucket, Prefix: destination.Prefix, UseTLS: destination.UseTLS, AccessKey: credentials["accessKey"], SecretKey: credentials["secretKey"], SessionToken: credentials["sessionToken"]})
	if err != nil {
		writeError(w, 400, "invalid_audit_archive", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err = archive.CheckObjectLock(ctx); err != nil {
		writeError(w, 400, "object_lock_required", err.Error())
		return
	}
	item, err := s.Store.CreateAuditArchiveDestination(r.Context(), store.AuditArchiveDestination{OrganizationID: p.OrganizationID, BackupDestinationID: input.BackupDestinationID, Name: input.Name, ObjectPrefix: input.ObjectPrefix, RetentionDays: input.RetentionDays})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "audit.archive.create", "audit_archive", item.ID.String(), r.RemoteAddr, map[string]any{"retentionDays": item.RetentionDays})
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) listAuditArchives(w http.ResponseWriter, r *http.Request) {
	items, err := s.Store.ListAuditArchiveDestinations(r.Context(), principal(r).OrganizationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) deleteAuditArchive(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("archiveID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid audit archive id")
		return
	}
	p := principal(r)
	if err = s.Store.DisableAuditArchiveDestination(r.Context(), p.OrganizationID, id); err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "audit.archive.disable", "audit_archive", id.String(), r.RemoteAddr, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) runAuditArchive(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("archiveID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid audit archive id")
		return
	}
	p := principal(r)
	batch, err := s.Store.QueueAuditArchive(r.Context(), p.OrganizationID, id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "audit.archive.run", "audit_archive_batch", batch.ID.String(), r.RemoteAddr, nil)
	writeJSON(w, http.StatusAccepted, batch)
}

func (s *Server) listAuditArchiveBatches(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("archiveID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid audit archive id")
		return
	}
	items, err := s.Store.ListAuditArchiveBatches(r.Context(), principal(r).OrganizationID, id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
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
			s.writeInternalError(w, r, 500, "export_failed", "audit export could not be encoded", err)
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
