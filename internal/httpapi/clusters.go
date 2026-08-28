package httpapi

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/bendahma/dokploy-go/internal/agentpki"
	"github.com/bendahma/dokploy-go/internal/auth"
	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
)

type clusterContextKey string

const clusterIDKey clusterContextKey = "cluster-id"

func (s *Server) AgentHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/agent/heartbeat", s.agentHeartbeat)
	return s.requestIDMiddleware(s.requireAgentCertificate(mux))
}

func (s *Server) requireAgentCertificate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
			writeError(w, http.StatusUnauthorized, "agent_certificate_required", "a verified agent client certificate is required")
			return
		}
		certificate := r.TLS.PeerCertificates[0]
		clusterID, err := agentpki.ClusterIdentity(certificate)
		if err != nil || s.Store.AuthenticateClusterCertificate(r.Context(), clusterID, hex.EncodeToString(certificate.SerialNumber.Bytes())) != nil {
			writeError(w, http.StatusUnauthorized, "invalid_agent_certificate", "agent certificate is invalid, expired, or superseded")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), clusterIDKey, clusterID)))
	})
}

func (s *Server) agentHeartbeat(w http.ResponseWriter, r *http.Request) {
	var input struct {
		AgentVersion  string         `json:"agentVersion"`
		DockerVersion string         `json:"dockerVersion"`
		Capacity      map[string]any `json:"capacity"`
	}
	if !decode(w, r, &input) {
		return
	}
	if len(input.AgentVersion) > 100 || len(input.DockerVersion) > 100 || len(input.Capacity) > 64 {
		writeError(w, 400, "invalid_heartbeat", "heartbeat metadata exceeds limits")
		return
	}
	clusterID := r.Context().Value(clusterIDKey).(uuid.UUID)
	if err := s.Store.RecordClusterHeartbeat(r.Context(), clusterID, input.AgentVersion, input.DockerVersion, input.Capacity); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func AgentTLSConfig(caCertificate []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCertificate) {
		return nil, errors.New("invalid agent CA certificate")
	}
	return pool, nil
}

func (s *Server) createCluster(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name   string         `json:"name"`
		Slug   string         `json:"slug"`
		Labels map[string]any `json:"labels"`
	}
	if !decode(w, r, &input) {
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	if input.Slug == "" {
		input.Slug = slugify(input.Name)
	}
	if input.Name == "" || !slugPattern.MatchString(input.Slug) || len(input.Labels) > 64 {
		writeError(w, 400, "invalid_cluster", "valid name, slug, and at most 64 labels are required")
		return
	}
	p := principal(r)
	item, err := s.Store.CreateCluster(r.Context(), store.Cluster{OrganizationID: p.OrganizationID, Name: input.Name, Slug: input.Slug, Labels: input.Labels})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "cluster.create", "cluster", item.ID.String(), r.RemoteAddr, nil)
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) listClusters(w http.ResponseWriter, r *http.Request) {
	items, err := s.Store.ListClusters(r.Context(), principal(r).OrganizationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) createClusterEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	clusterID, err := uuid.Parse(r.PathValue("clusterID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid cluster id")
		return
	}
	token, err := auth.NewToken()
	if err != nil {
		writeError(w, 500, "token_failed", err.Error())
		return
	}
	p := principal(r)
	expiresAt := time.Now().Add(15 * time.Minute)
	if err = s.Store.CreateClusterEnrollmentToken(r.Context(), p.OrganizationID, clusterID, p.UserID, cryptox.Digest(token), expiresAt); err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "cluster.enrollment_token.create", "cluster", clusterID.String(), r.RemoteAddr, map[string]any{"expiresAt": expiresAt})
	writeJSON(w, http.StatusCreated, map[string]any{"token": token, "expiresAt": expiresAt})
}

func (s *Server) enrollClusterAgent(w http.ResponseWriter, r *http.Request) {
	if len(s.AgentCACertificate) == 0 || len(s.AgentCAKey) == 0 {
		writeError(w, http.StatusServiceUnavailable, "agent_enrollment_disabled", "agent certificate authority is not configured")
		return
	}
	var input struct {
		Token string `json:"token"`
		CSR   string `json:"csr"`
	}
	if !decode(w, r, &input) {
		return
	}
	tokenHash := cryptox.Digest(strings.TrimSpace(input.Token))
	cluster, err := s.Store.LookupClusterEnrollmentToken(r.Context(), tokenHash)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_enrollment_token", "enrollment token is invalid, expired, or already used")
		return
	}
	ttl := s.AgentCertificateTTL
	if ttl == 0 {
		ttl = 7 * 24 * time.Hour
	}
	certificate, parsed, err := agentpki.SignAgentCSR(s.AgentCACertificate, s.AgentCAKey, []byte(input.CSR), cluster.ID, time.Now(), ttl)
	if err != nil {
		writeError(w, 400, "invalid_csr", err.Error())
		return
	}
	if err = s.Store.ConsumeClusterEnrollmentToken(r.Context(), tokenHash, hex.EncodeToString(parsed.SerialNumber.Bytes()), parsed.NotAfter); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_enrollment_token", "enrollment token is invalid, expired, or already used")
		return
	}
	s.Store.AuditOrganization(r.Context(), cluster.OrganizationID, "cluster.enroll", "cluster", cluster.ID.String(), r.RemoteAddr, map[string]any{"certificateNotAfter": parsed.NotAfter})
	writeJSON(w, 200, map[string]any{"clusterId": cluster.ID, "certificate": string(certificate), "caCertificate": string(s.AgentCACertificate), "expiresAt": parsed.NotAfter})
}
