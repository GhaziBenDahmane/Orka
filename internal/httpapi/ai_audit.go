package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/bendahma/dokploy-go/internal/agentpki"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

func (s *Server) requireAuditor(next http.Handler) http.Handler {
	return s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := principal(r)
		if p.Role != "auditor" || p.ServiceAccountID == nil {
			writeError(w, 403, "forbidden", "an auditor service account is required")
			return
		}
		next.ServeHTTP(w, r)
	}))
}

func (s *Server) aiAuditSnapshot(w http.ResponseWriter, r *http.Request) {
	snapshot, err := s.Store.BuildAIAuditSnapshot(r.Context(), principal(r).OrganizationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if s.Databases != nil {
		for _, engine := range s.Databases.Engines() {
			snapshot.DatabaseEngines = append(snapshot.DatabaseEngines, store.AIAuditDatabaseEngineInfo{
				Name: engine.Name, DefaultVersion: engine.DefaultVersion, Source: engine.Source, ArtifactDigest: engine.ArtifactDigest,
				BackupCapable: engine.BackupCapable, BackupExtension: engine.BackupExtension,
			})
		}
	}
	if s.LocalClusterPosture != nil {
		posture := s.LocalClusterPosture()
		snapshot.LocalCluster = &posture
	}
	if len(s.AgentCACertificate) != 0 {
		activeFingerprint, fingerprintErr := agentpki.CertificateFingerprint(s.AgentCACertificate)
		if fingerprintErr != nil {
			writeError(w, http.StatusInternalServerError, "agent_ca_invalid", "agent certificate authority posture is unavailable")
			return
		}
		snapshot.AgentCAPosture.Configured = true
		snapshot.AgentCAPosture.ActiveFingerprint = activeFingerprint
	}
	if len(s.AgentPreviousCACertificate) != 0 {
		previousFingerprint, fingerprintErr := agentpki.CertificateFingerprint(s.AgentPreviousCACertificate)
		if fingerprintErr != nil {
			writeError(w, http.StatusInternalServerError, "agent_ca_invalid", "previous agent certificate authority posture is unavailable")
			return
		}
		snapshot.AgentCAPosture.PreviousFingerprint = previousFingerprint
		snapshot.AgentCAPosture.RolloverActive = true
	}
	writeJSON(w, 200, snapshot)
}

func (s *Server) createAIAuditRun(w http.ResponseWriter, r *http.Request) {
	var in struct {
		AgentName    string          `json:"agentName"`
		AgentVersion string          `json:"agentVersion"`
		Model        string          `json:"model"`
		Scope        json.RawMessage `json:"scope"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.AgentName = strings.TrimSpace(in.AgentName)
	in.AgentVersion = strings.TrimSpace(in.AgentVersion)
	in.Model = strings.TrimSpace(in.Model)
	if len(in.Scope) == 0 {
		in.Scope = json.RawMessage(`{}`)
	}
	if !validDisplayLabel(in.AgentName, 120) || len(in.AgentVersion) > 200 || len(in.Model) > 300 || !validAuditObject(in.Scope, 64<<10) {
		writeError(w, 400, "invalid_audit_run", "audit run metadata is invalid or exceeds safety limits")
		return
	}
	p := principal(r)
	item, err := s.Store.CreateAIAuditRunWithAudit(r.Context(), p, in.AgentName, in.AgentVersion, in.Model, in.Scope, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 201, item)
}

func (s *Server) createAIAuditFinding(w http.ResponseWriter, r *http.Request) {
	runID, err := uuid.Parse(r.PathValue("runID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid audit run id")
		return
	}
	var in store.AIAuditFinding
	if !decode(w, r, &in) {
		return
	}
	valid := map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}
	in.Severity = strings.ToLower(strings.TrimSpace(in.Severity))
	in.Category = strings.TrimSpace(in.Category)
	in.Title = strings.TrimSpace(in.Title)
	in.Description = strings.TrimSpace(in.Description)
	in.ResourceType = strings.TrimSpace(in.ResourceType)
	in.ResourceID = strings.TrimSpace(in.ResourceID)
	in.Remediation = strings.TrimSpace(in.Remediation)
	in.Fingerprint = strings.TrimSpace(in.Fingerprint)
	if len(in.Evidence) == 0 {
		in.Evidence = json.RawMessage(`{}`)
	}
	if !valid[in.Severity] || in.Category == "" || len(in.Category) > 120 || in.Title == "" || len(in.Title) > 300 || in.Description == "" || len(in.Description) > 8000 || len(in.ResourceType) > 120 || len(in.ResourceID) > 200 || len(in.Remediation) > 8000 || len(in.Fingerprint) > 200 || !validAuditObject(in.Evidence, 64<<10) {
		writeError(w, 400, "invalid_finding", "audit finding is invalid or exceeds safety limits")
		return
	}
	in.RunID = runID
	if in.Fingerprint == "" {
		sum := sha256.Sum256([]byte(in.Category + "\x00" + in.Title + "\x00" + in.ResourceType + "\x00" + in.ResourceID))
		in.Fingerprint = hex.EncodeToString(sum[:])
	}
	p := principal(r)
	item, err := s.Store.AddAIAuditFinding(r.Context(), p.OrganizationID, *p.ServiceAccountID, in)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 201, item)
}

func (s *Server) finishAIAuditRun(w http.ResponseWriter, r *http.Request) {
	runID, err := uuid.Parse(r.PathValue("runID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid audit run id")
		return
	}
	var in struct {
		Status  string `json:"status"`
		Summary string `json:"summary"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Status != "completed" && in.Status != "failed" {
		writeError(w, 400, "invalid_status", "status must be completed or failed")
		return
	}
	in.Summary = strings.TrimSpace(in.Summary)
	if len(in.Summary) > 8000 {
		writeError(w, 400, "invalid_summary", "summary exceeds 8000 bytes")
		return
	}
	p := principal(r)
	if err = s.Store.FinishAIAuditRunWithAudit(r.Context(), p, runID, in.Status, in.Summary, r.RemoteAddr); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func validAuditObject(value json.RawMessage, maxBytes int) bool {
	if len(value) == 0 || len(value) > maxBytes {
		return false
	}
	var object map[string]any
	return json.Unmarshal(value, &object) == nil && object != nil
}

func (s *Server) listAIAuditRuns(w http.ResponseWriter, r *http.Request) {
	items, err := s.Store.ListAIAuditRuns(r.Context(), principal(r).OrganizationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) listOwnAIAuditRuns(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	items, err := s.Store.ListOwnAIAuditRuns(r.Context(), p.OrganizationID, *p.ServiceAccountID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
func (s *Server) listAIAuditFindings(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("runID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid audit run id")
		return
	}
	items, err := s.Store.ListAIAuditFindings(r.Context(), principal(r).OrganizationID, id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) listCurrentAIAuditFindings(w http.ResponseWriter, r *http.Request) {
	disposition := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("disposition")))
	severity := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("severity")))
	if disposition != "" && disposition != "active" && disposition != "open" && disposition != "acknowledged" && disposition != "resolved" {
		writeError(w, http.StatusBadRequest, "invalid_disposition", "disposition must be active, open, acknowledged, or resolved")
		return
	}
	if severity != "" && severity != "info" && severity != "low" && severity != "medium" && severity != "high" && severity != "critical" {
		writeError(w, http.StatusBadRequest, "invalid_severity", "severity must be info, low, medium, high, or critical")
		return
	}
	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 200 {
			writeError(w, http.StatusBadRequest, "invalid_limit", "limit must be between 1 and 200")
			return
		}
		limit = parsed
	}
	items, err := s.Store.ListCurrentAIAuditFindings(r.Context(), principal(r).OrganizationID, disposition, severity, limit)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) updateAIAuditFindingDisposition(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("findingID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid audit finding id")
		return
	}
	var in struct {
		Disposition string `json:"disposition"`
		Note        string `json:"note"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Disposition = strings.ToLower(strings.TrimSpace(in.Disposition))
	in.Note = strings.TrimSpace(in.Note)
	if (in.Disposition != "open" && in.Disposition != "acknowledged" && in.Disposition != "resolved") || len(in.Note) > 2000 {
		writeError(w, http.StatusBadRequest, "invalid_disposition", "disposition must be open, acknowledged, or resolved and note must not exceed 2000 bytes")
		return
	}
	p := principal(r)
	item, err := s.Store.UpdateAIAuditFindingDisposition(r.Context(), p, id, in.Disposition, in.Note, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}
