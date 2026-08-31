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

const maxAuditExportBytes = 32 << 20

var errAuditExportTooLarge = errors.New("audit export exceeds response limit")

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
	archive, err := backupstore.NewS3(backupstore.S3Config{Endpoint: destination.Endpoint, Region: destination.Region, Bucket: destination.Bucket, Prefix: destination.Prefix, UseTLS: destination.UseTLS, AccessKey: credentials["accessKey"], SecretKey: credentials["secretKey"], SessionToken: credentials["sessionToken"], Transport: s.EgressTransport})
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
	item, err := s.Store.CreateAuditArchiveDestinationWithAudit(r.Context(), p, store.AuditArchiveDestination{BackupDestinationID: input.BackupDestinationID, Name: input.Name, ObjectPrefix: input.ObjectPrefix, RetentionDays: input.RetentionDays}, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
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

func (s *Server) getAuditArchive(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("archiveID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid audit archive id")
		return
	}
	item, err := s.Store.GetAuditArchiveDestination(r.Context(), principal(r).OrganizationID, id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) deleteAuditArchive(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("archiveID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid audit archive id")
		return
	}
	p := principal(r)
	if err = s.Store.DisableAuditArchiveDestinationWithAudit(r.Context(), p, id, r.RemoteAddr); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) runAuditArchive(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("archiveID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid audit archive id")
		return
	}
	p := principal(r)
	batch, err := s.Store.QueueAuditArchiveWithAudit(r.Context(), p, id, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
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
	payload, err := encodeAuditExport(items, maxAuditExportBytes)
	if errors.Is(err, errAuditExportTooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, "export_too_large", "audit export exceeds 32 MiB; request a smaller limit and continue with afterId")
		return
	}
	if err != nil {
		s.writeInternalError(w, r, 500, "export_failed", "audit export could not be encoded", err)
		return
	}
	digest := sha256.Sum256(payload)
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", `attachment; filename="dockyard-audit.ndjson"`)
	w.Header().Set("X-Content-SHA256", hex.EncodeToString(digest[:]))
	if len(items) > 0 {
		w.Header().Set("X-Next-After-ID", strconv.FormatInt(items[len(items)-1].ID, 10))
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

func encodeAuditExport(items []store.AuditEvent, limit int) ([]byte, error) {
	var payload bytes.Buffer
	for _, item := range items {
		encoded, err := json.Marshal(item)
		if err != nil {
			return nil, err
		}
		if len(encoded)+1 > limit-payload.Len() {
			return nil, errAuditExportTooLarge
		}
		_, _ = payload.Write(encoded)
		_ = payload.WriteByte('\n')
	}
	return payload.Bytes(), nil
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
	item, err := s.Store.UpsertAuditRetentionPolicyWithAudit(r.Context(), p, in.RetentionDays, r.RemoteAddr)
	if err != nil {
		writeError(w, 400, "invalid_retention", err.Error())
		return
	}
	writeJSON(w, 200, item)
}
