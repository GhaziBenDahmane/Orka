package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

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
	if in.AgentName == "" || len(in.AgentName) > 120 {
		writeError(w, 400, "invalid_audit_run", "agentName is required")
		return
	}
	p := principal(r)
	item, err := s.Store.CreateAIAuditRun(r.Context(), p.OrganizationID, *p.ServiceAccountID, in.AgentName, strings.TrimSpace(in.AgentVersion), strings.TrimSpace(in.Model), in.Scope)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "ai_audit.start", "ai_audit_run", item.ID.String(), r.RemoteAddr, nil)
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
	if !valid[in.Severity] || in.Category == "" || in.Title == "" || in.Description == "" {
		writeError(w, 400, "invalid_finding", "severity, category, title, and description are required")
		return
	}
	in.RunID = runID
	if len(in.Evidence) == 0 {
		in.Evidence = json.RawMessage(`{}`)
	}
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
	p := principal(r)
	if err = s.Store.FinishAIAuditRun(r.Context(), p.OrganizationID, *p.ServiceAccountID, runID, in.Status, in.Summary); err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "ai_audit."+in.Status, "ai_audit_run", runID.String(), r.RemoteAddr, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listAIAuditRuns(w http.ResponseWriter, r *http.Request) {
	items, err := s.Store.ListAIAuditRuns(r.Context(), principal(r).OrganizationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
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
