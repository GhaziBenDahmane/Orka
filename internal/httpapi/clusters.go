package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bendahma/dokploy-go/internal/agentpki"
	"github.com/bendahma/dokploy-go/internal/auth"
	"github.com/bendahma/dokploy-go/internal/clustercontract"
	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/deploy"
	"github.com/bendahma/dokploy-go/internal/observability"
	"github.com/bendahma/dokploy-go/internal/ociref"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

type clusterContextKey string

const clusterIDKey clusterContextKey = "cluster-id"

func (s *Server) AgentHandler() http.Handler {
	if s.Metrics == nil {
		s.Metrics = observability.NewMetrics()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/agent/heartbeat", s.agentHeartbeat)
	mux.HandleFunc("POST /v1/agent/rotate", s.agentRotateCertificate)
	mux.HandleFunc("GET /v1/agent/commands/next", s.agentNextCommand)
	mux.HandleFunc("POST /v1/agent/commands/{commandID}/lease", s.agentRenewCommand)
	mux.HandleFunc("POST /v1/agent/commands/{commandID}/complete", s.agentCompleteCommand)
	protected := s.requireAgentCertificate(mux)
	instrumented := otelhttp.NewHandler(s.middleware(protected), "dockyard.agent_http")
	return s.requestIDMiddleware(instrumented)
}

func (s *Server) agentRotateCertificate(w http.ResponseWriter, r *http.Request) {
	clusterID := r.Context().Value(clusterIDKey).(uuid.UUID)
	var input struct {
		CSR string `json:"csr"`
	}
	if !decode(w, r, &input) {
		return
	}
	ttl := s.AgentCertificateTTL
	if ttl == 0 {
		ttl = 7 * 24 * time.Hour
	}
	certificate, parsed, err := agentpki.SignAgentCSR(s.AgentCACertificate, s.AgentCAKey, []byte(input.CSR), clusterID, time.Now(), ttl)
	if err != nil {
		writeError(w, 400, "invalid_csr", err.Error())
		return
	}
	caFingerprint, err := agentpki.CertificateFingerprint(s.AgentCACertificate)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "agent_ca_invalid", "agent certificate authority is invalid")
		return
	}
	oldSerial := hex.EncodeToString(r.TLS.PeerCertificates[0].SerialNumber.Bytes())
	if err = s.Store.RotateClusterCertificate(r.Context(), clusterID, oldSerial, hex.EncodeToString(parsed.SerialNumber.Bytes()), parsed.NotAfter, caFingerprint); err != nil {
		writeError(w, http.StatusConflict, "certificate_superseded", "agent certificate was already superseded")
		return
	}
	writeJSON(w, 200, map[string]any{"certificate": string(certificate), "caCertificate": string(s.agentTrustBundle()), "signingCaCertificate": string(s.AgentCACertificate), "signingCaFingerprint": caFingerprint, "expiresAt": parsed.NotAfter})
}

func (s *Server) agentNextCommand(w http.ResponseWriter, r *http.Request) {
	clusterID := r.Context().Value(clusterIDKey).(uuid.UUID)
	command, err := s.Store.ClaimClusterCommand(r.Context(), clusterID, 45*time.Second)
	if errors.Is(err, store.ErrNotFound) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		writeStoreError(w, err)
		return
	}
	payload, err := s.Box.Decrypt(command.EncryptedPayload, "cluster-command:"+command.ID.String())
	if err != nil {
		result, _ := s.Box.Encrypt([]byte(`{"error":"command payload cannot be decrypted"}`), "cluster-command-result:"+command.ID.String())
		_ = s.Store.CompleteClusterCommand(r.Context(), clusterID, command.ID, *command.LeaseID, result, true)
		writeError(w, 500, "command_decryption_failed", "cluster command cannot be decrypted")
		return
	}
	writeJSON(w, 200, map[string]any{"id": command.ID, "kind": command.Kind, "payload": json.RawMessage(payload), "leaseId": command.LeaseID, "leaseExpiresAt": command.LeaseExpiresAt})
}

func (s *Server) agentRenewCommand(w http.ResponseWriter, r *http.Request) {
	clusterID := r.Context().Value(clusterIDKey).(uuid.UUID)
	commandID, leaseID, ok := commandLeaseIDs(w, r)
	if !ok {
		return
	}
	if err := s.Store.RenewClusterCommand(r.Context(), clusterID, commandID, leaseID, 45*time.Second); err != nil {
		if errors.Is(err, store.ErrLeaseLost) {
			writeError(w, http.StatusConflict, "lease_lost", err.Error())
			return
		}
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) agentCompleteCommand(w http.ResponseWriter, r *http.Request) {
	clusterID := r.Context().Value(clusterIDKey).(uuid.UUID)
	commandID, leaseID, ok := commandLeaseIDs(w, r)
	if !ok {
		return
	}
	var input struct {
		Output string `json:"output"`
		Error  string `json:"error"`
	}
	if !decodeLimit(w, r, &input, deploy.MaxRemoteCommandRequestBytes) {
		return
	}
	if !validAgentCommandResult(input.Output, input.Error) {
		writeError(w, 400, "result_too_large", "command result exceeds limits")
		return
	}
	resultJSON, _ := json.Marshal(input)
	encryptedResult, err := s.Box.Encrypt(resultJSON, "cluster-command-result:"+commandID.String())
	if err != nil {
		writeError(w, 500, "encryption_failed", "command result cannot be encrypted")
		return
	}
	if err := s.Store.CompleteClusterCommand(r.Context(), clusterID, commandID, leaseID, encryptedResult, input.Error != ""); err != nil {
		if errors.Is(err, store.ErrLeaseLost) {
			writeError(w, http.StatusConflict, "lease_lost", err.Error())
			return
		}
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func validAgentCommandResult(output, commandError string) bool {
	return len(output) <= deploy.MaxRemoteCommandOutputBytes && len(commandError) <= deploy.MaxRemoteCommandErrorBytes
}

func commandLeaseIDs(w http.ResponseWriter, r *http.Request) (uuid.UUID, uuid.UUID, bool) {
	commandID, err := uuid.Parse(r.PathValue("commandID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid command id")
		return uuid.Nil, uuid.Nil, false
	}
	leaseID, err := uuid.Parse(r.Header.Get("X-Dockyard-Lease-ID"))
	if err != nil {
		writeError(w, 400, "invalid_lease", "valid X-Dockyard-Lease-ID required")
		return uuid.Nil, uuid.Nil, false
	}
	return commandID, leaseID, true
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
		AgentVersion     string                       `json:"agentVersion"`
		AgentImage       string                       `json:"agentImage"`
		AgentUpdateState string                       `json:"agentUpdateState"`
		DockerVersion    string                       `json:"dockerVersion"`
		Capacity         map[string]any               `json:"capacity"`
		Capabilities     clustercontract.Capabilities `json:"capabilities"`
	}
	if !decode(w, r, &input) {
		return
	}
	input.AgentImage = strings.TrimSpace(input.AgentImage)
	input.AgentUpdateState = strings.TrimSpace(input.AgentUpdateState)
	validUpdateState := contains([]string{"", "updating", "paused", "completed", "rollback_started", "rollback_paused", "rollback_completed"}, input.AgentUpdateState)
	capabilitiesInvalid := input.Capabilities.ProtocolVersion != 0 && clustercontract.Validate(input.Capabilities) != nil
	if len(input.AgentVersion) > 100 || len(input.AgentImage) > 500 || strings.ContainsAny(input.AgentImage, "\r\n") || !validUpdateState || len(input.DockerVersion) > 100 || len(input.Capacity) > 64 || capabilitiesInvalid {
		writeError(w, 400, "invalid_heartbeat", "heartbeat metadata exceeds limits")
		return
	}
	clusterID := r.Context().Value(clusterIDKey).(uuid.UUID)
	if err := s.Store.RecordClusterHeartbeat(r.Context(), clusterID, input.AgentVersion, input.AgentImage, input.AgentUpdateState, input.DockerVersion, input.Capacity, input.Capabilities); err != nil {
		writeStoreError(w, err)
		return
	}
	caFingerprint, _ := agentpki.CertificateFingerprint(s.AgentCACertificate)
	writeJSON(w, http.StatusOK, map[string]any{"caCertificate": string(s.agentTrustBundle()), "signingCaCertificate": string(s.AgentCACertificate), "signingCaFingerprint": caFingerprint})
}

func AgentTLSConfig(caCertificate []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCertificate) {
		return nil, errors.New("invalid agent CA certificate")
	}
	return pool, nil
}

func (s *Server) agentTrustBundle() []byte {
	if len(s.AgentCATrustBundle) != 0 {
		return s.AgentCATrustBundle
	}
	return s.AgentCACertificate
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
	item, err := s.Store.CreateClusterWithAudit(r.Context(), p, store.Cluster{Name: input.Name, Slug: input.Slug, Labels: input.Labels}, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
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

func (s *Server) updateCluster(w http.ResponseWriter, r *http.Request) {
	clusterID, err := uuid.Parse(r.PathValue("clusterID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid cluster id")
		return
	}
	var input struct {
		State               string     `json:"state"`
		MaintenanceStartsAt *time.Time `json:"maintenanceStartsAt"`
		MaintenanceEndsAt   *time.Time `json:"maintenanceEndsAt"`
	}
	if !decode(w, r, &input) {
		return
	}
	if !contains([]string{"active", "draining", "disabled"}, input.State) {
		writeError(w, 400, "invalid_cluster_state", "state must be active, draining, or disabled")
		return
	}
	p := principal(r)
	item, err := s.Store.UpdateClusterConfigurationWithAudit(r.Context(), p, clusterID, input.State, input.MaintenanceStartsAt, input.MaintenanceEndsAt, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, item)
}

func (s *Server) deleteCluster(w http.ResponseWriter, r *http.Request) {
	clusterID, err := uuid.Parse(r.PathValue("clusterID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid cluster id")
		return
	}
	p := principal(r)
	if err = s.Store.QueueClusterDeletionWithAudit(r.Context(), p, clusterID, r.RemoteAddr); err != nil {
		if errors.Is(err, store.ErrBusy) {
			writeError(w, http.StatusConflict, "cluster_busy", "move or delete assigned environments before deleting the cluster")
			return
		}
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "deletion_queued"})
}

func (s *Server) clusterNodes(w http.ResponseWriter, r *http.Request) {
	clusterID, err := uuid.Parse(r.PathValue("clusterID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid cluster id")
		return
	}
	if _, err = s.Store.GetCluster(r.Context(), principal(r).OrganizationID, clusterID); err != nil {
		writeStoreError(w, err)
		return
	}
	items, err := (deploy.RemoteSwarm{Store: s.Store, Box: s.Box, ClusterID: clusterID, Timeout: 30 * time.Second}).Nodes(r.Context())
	if err != nil {
		s.writeInternalError(w, r, http.StatusBadGateway, "cluster_unavailable", "remote cluster node inventory is unavailable", err)
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
		s.writeInternalError(w, r, 500, "token_failed", "cluster enrollment token could not be generated", err)
		return
	}
	p := principal(r)
	expiresAt := time.Now().Add(15 * time.Minute)
	if err = s.Store.CreateClusterEnrollmentTokenWithAudit(r.Context(), p, clusterID, cryptox.Digest(token), expiresAt, r.RemoteAddr); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"token": token, "expiresAt": expiresAt})
}

func (s *Server) upgradeClusterAgent(w http.ResponseWriter, r *http.Request) {
	clusterID, err := uuid.Parse(r.PathValue("clusterID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid cluster id")
		return
	}
	var input struct {
		Image string `json:"image"`
	}
	if !decode(w, r, &input) {
		return
	}
	input.Image = strings.TrimSpace(input.Image)
	if !ociref.IsDigestPinned(input.Image) {
		writeError(w, http.StatusBadRequest, "invalid_image", "agent image must use repository@sha256:digest form")
		return
	}
	p := principal(r)
	if _, err = s.Store.GetCluster(r.Context(), p.OrganizationID, clusterID); err != nil {
		writeStoreError(w, err)
		return
	}
	commandID := uuid.New()
	payload, _ := json.Marshal(map[string]string{"image": input.Image})
	encrypted, err := s.Box.Encrypt(payload, "cluster-command:"+commandID.String())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encryption_failed", "upgrade command cannot be encrypted")
		return
	}
	command, err := s.Store.EnqueueAgentUpgradeWithAudit(r.Context(), p, clusterID, commandID, encrypted, input.Image, r.RemoteAddr)
	if err != nil {
		if errors.Is(err, store.ErrBusy) {
			writeError(w, http.StatusConflict, "agent_upgrade_running", "an agent upgrade is already pending or being verified")
			return
		}
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, command)
}

func (s *Server) getClusterCommand(w http.ResponseWriter, r *http.Request) {
	clusterID, err := uuid.Parse(r.PathValue("clusterID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid cluster id")
		return
	}
	commandID, err := uuid.Parse(r.PathValue("commandID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid command id")
		return
	}
	if _, err = s.Store.GetCluster(r.Context(), principal(r).OrganizationID, clusterID); err != nil {
		writeStoreError(w, err)
		return
	}
	command, err := s.Store.GetClusterCommand(r.Context(), clusterID, commandID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, command)
}

func (s *Server) listAgentUpgrades(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		var err error
		limit, err = strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 200 {
			writeError(w, http.StatusBadRequest, "invalid_limit", "limit must be between 1 and 200")
			return
		}
	}
	items, err := s.Store.ListAgentUpgrades(r.Context(), principal(r).OrganizationID, limit)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) cancelAgentUpgrade(w http.ResponseWriter, r *http.Request) {
	clusterID, err := uuid.Parse(r.PathValue("clusterID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid cluster id")
		return
	}
	commandID, err := uuid.Parse(r.PathValue("commandID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid command id")
		return
	}
	p := principal(r)
	if err = s.Store.CancelPendingAgentUpgradeWithAudit(r.Context(), p, clusterID, commandID, r.RemoteAddr); err != nil {
		if errors.Is(err, store.ErrNotCancellable) {
			writeError(w, http.StatusConflict, "not_cancellable", "an agent upgrade can only be cancelled before execution starts")
			return
		}
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "cancelled"})
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
	token := strings.TrimSpace(input.Token)
	if !validPublicOpaqueValue(token, maxPublicCredentialBytes) {
		writeError(w, http.StatusUnauthorized, "invalid_enrollment_token", "enrollment token is invalid, expired, or already used")
		return
	}
	if !s.allowAuthenticationAttempt(w, r, "agent-enroll-client", authenticationClientKey(r), 120) || !s.allowAuthenticationAttempt(w, r, "agent-enroll-token", cryptox.Digest(token), 20) {
		return
	}
	tokenHash := cryptox.Digest(token)
	csrHash := sha256.Sum256([]byte(input.CSR))
	enrollment, err := s.Store.LookupClusterEnrollmentToken(r.Context(), tokenHash, csrHash[:])
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_enrollment_token", "enrollment token is invalid, expired, or already used")
		return
	}
	if enrollment.Artifacts.Certificate != "" {
		s.writeClusterEnrollment(w, r, enrollment.Cluster, enrollment.Artifacts)
		return
	}
	ttl := s.AgentCertificateTTL
	if ttl == 0 {
		ttl = 7 * 24 * time.Hour
	}
	certificate, parsed, err := agentpki.SignAgentCSR(s.AgentCACertificate, s.AgentCAKey, []byte(input.CSR), enrollment.Cluster.ID, time.Now(), ttl)
	if err != nil {
		writeError(w, 400, "invalid_csr", err.Error())
		return
	}
	caFingerprint, err := agentpki.CertificateFingerprint(s.AgentCACertificate)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "agent_ca_invalid", "agent certificate authority is invalid")
		return
	}
	artifacts := store.ClusterEnrollmentArtifacts{Certificate: string(certificate), CABundle: string(s.agentTrustBundle()), SigningCACertificate: string(s.AgentCACertificate), SigningCAFingerprint: caFingerprint}
	artifacts, _, err = s.Store.CompleteClusterEnrollmentWithAudit(r.Context(), tokenHash, csrHash[:], artifacts, hex.EncodeToString(parsed.SerialNumber.Bytes()), parsed.NotAfter, r.RemoteAddr)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_enrollment_token", "enrollment token is invalid, expired, or already used")
		return
	}
	s.writeClusterEnrollment(w, r, enrollment.Cluster, artifacts)
}

func (s *Server) writeClusterEnrollment(w http.ResponseWriter, r *http.Request, cluster store.Cluster, artifacts store.ClusterEnrollmentArtifacts) {
	block, rest := pem.Decode([]byte(artifacts.Certificate))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		s.writeInternalError(w, r, http.StatusInternalServerError, "enrollment_state_invalid", "stored agent enrollment certificate is invalid", errors.New("invalid stored enrollment certificate PEM"))
		return
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		s.writeInternalError(w, r, http.StatusInternalServerError, "enrollment_state_invalid", "stored agent enrollment certificate is invalid", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"clusterId": cluster.ID, "certificate": artifacts.Certificate, "caCertificate": artifacts.CABundle, "signingCaCertificate": artifacts.SigningCACertificate, "signingCaFingerprint": artifacts.SigningCAFingerprint, "expiresAt": certificate.NotAfter})
}
