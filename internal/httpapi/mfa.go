package httpapi

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/bendahma/dokploy-go/internal/auth"
	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/store"
)

const maxMFAProofBytes = 128

func (s *Server) getMFAStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	status, err := s.Store.MFAStatus(r.Context(), principal(r))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) beginMFAEnrollment(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var in struct {
		CurrentPassword string `json:"currentPassword"`
	}
	if !decode(w, r, &in) {
		return
	}
	if len(in.CurrentPassword) > auth.MaxPasswordBytes {
		writeError(w, http.StatusBadRequest, "invalid_password", "current password is invalid")
		return
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		s.writeInternalError(w, r, 500, "mfa_enrollment_failed", "MFA enrollment could not be started", err)
		return
	}
	p := principal(r)
	encrypted, err := s.Box.Encrypt([]byte(secret), cryptox.ResourceContext("user-totp", p.UserID.String()))
	if err != nil {
		s.writeInternalError(w, r, 500, "mfa_enrollment_failed", "MFA enrollment could not be started", err)
		return
	}
	if err = s.Store.BeginMFAEnrollment(r.Context(), p, in.CurrentPassword, encrypted, r.RemoteAddr); err != nil {
		writeMFAStoreError(w, err)
		return
	}
	uri, err := auth.TOTPURI(secret, "Orka", p.Email)
	if err != nil {
		s.writeInternalError(w, r, 500, "mfa_enrollment_failed", "MFA enrollment could not be started", err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"secret": secret, "otpauthUri": uri})
}

func (s *Server) confirmMFAEnrollment(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var in struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &in) {
		return
	}
	if len(in.Code) > maxMFAProofBytes {
		writeError(w, 400, "invalid_mfa", store.ErrInvalidMFAProof.Error())
		return
	}
	p := principal(r)
	encrypted, err := s.Store.PendingMFASecret(r.Context(), p)
	if err != nil {
		writeMFAStoreError(w, err)
		return
	}
	secret, err := s.Box.Decrypt(encrypted, cryptox.ResourceContext("user-totp", p.UserID.String()))
	if err != nil {
		s.writeInternalError(w, r, 500, "mfa_secret_invalid", "stored MFA material could not be authenticated", err)
		return
	}
	defer clear(secret)
	counter, valid := auth.VerifyTOTP(string(secret), strings.TrimSpace(in.Code), time.Now())
	if !valid {
		writeError(w, http.StatusForbidden, "invalid_mfa", store.ErrInvalidMFAProof.Error())
		return
	}
	codes, err := auth.NewRecoveryCodes()
	if err != nil {
		s.writeInternalError(w, r, 500, "mfa_enrollment_failed", "recovery codes could not be generated", err)
		return
	}
	digests := recoveryCodeDigests(codes)
	revoked, err := s.Store.ConfirmMFAEnrollment(r.Context(), p, encrypted, counter, digests, r.RemoteAddr)
	if err != nil {
		writeMFAStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recoveryCodes": codes, "revokedSessions": revoked})
}

func (s *Server) disableMFA(w http.ResponseWriter, r *http.Request) {
	s.updateMFA(w, r, true)
}

func (s *Server) regenerateMFARecoveryCodes(w http.ResponseWriter, r *http.Request) {
	s.updateMFA(w, r, false)
}

func (s *Server) updateMFA(w http.ResponseWriter, r *http.Request, disable bool) {
	w.Header().Set("Cache-Control", "no-store")
	var in struct{ CurrentPassword, Code, RecoveryCode string }
	if !decode(w, r, &in) {
		return
	}
	if len(in.CurrentPassword) > auth.MaxPasswordBytes || len(in.Code) > maxMFAProofBytes || len(in.RecoveryCode) > maxMFAProofBytes {
		writeError(w, http.StatusBadRequest, "invalid_mfa", store.ErrInvalidMFAProof.Error())
		return
	}
	p := principal(r)
	encrypted, err := s.Store.ActiveMFASecret(r.Context(), p)
	if err != nil {
		writeMFAStoreError(w, err)
		return
	}
	counter, recoveryDigest, valid, err := s.verifyMFAProof(p.UserID.String(), encrypted, in.Code, in.RecoveryCode)
	if err != nil {
		s.writeInternalError(w, r, 500, "mfa_secret_invalid", "stored MFA material could not be authenticated", err)
		return
	}
	if !valid {
		writeError(w, http.StatusForbidden, "invalid_mfa", store.ErrInvalidMFAProof.Error())
		return
	}
	var codes []string
	var digests [][]byte
	if !disable {
		codes, err = auth.NewRecoveryCodes()
		if err != nil {
			s.writeInternalError(w, r, 500, "mfa_update_failed", "recovery codes could not be generated", err)
			return
		}
		digests = recoveryCodeDigests(codes)
	}
	var revoked int64
	if disable {
		revoked, err = s.Store.DisableMFA(r.Context(), p, in.CurrentPassword, encrypted, counter, recoveryDigest, r.RemoteAddr)
	} else {
		revoked, err = s.Store.ReplaceMFARecoveryCodes(r.Context(), p, in.CurrentPassword, encrypted, counter, recoveryDigest, digests, r.RemoteAddr)
	}
	if err != nil {
		writeMFAStoreError(w, err)
		return
	}
	if disable {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "revokedSessions": revoked})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recoveryCodes": codes, "revokedSessions": revoked})
}

func (s *Server) verifyMFAProof(userID, encrypted, code, recoveryCode string) (*int64, []byte, bool, error) {
	code, recoveryCode = strings.TrimSpace(code), strings.TrimSpace(recoveryCode)
	if (code == "") == (recoveryCode == "") {
		return nil, nil, false, nil
	}
	if recoveryCode != "" {
		normalized := auth.NormalizeRecoveryCode(recoveryCode)
		if len(normalized) != 16 {
			return nil, nil, false, nil
		}
		return nil, cryptox.Digest(normalized), true, nil
	}
	secret, err := s.Box.Decrypt(encrypted, cryptox.ResourceContext("user-totp", userID))
	if err != nil {
		return nil, nil, false, err
	}
	defer clear(secret)
	counter, valid := auth.VerifyTOTP(string(secret), code, time.Now())
	if !valid {
		return nil, nil, false, nil
	}
	return &counter, nil, true, nil
}

func recoveryCodeDigests(codes []string) [][]byte {
	digests := make([][]byte, len(codes))
	for i, code := range codes {
		digests[i] = cryptox.Digest(auth.NormalizeRecoveryCode(code))
	}
	return digests
}

func (s *Server) newMFASession(r *http.Request, credential store.LocalLoginCredential, counter *int64, recoveryDigest []byte) (string, error) {
	token, err := auth.NewToken()
	if err != nil {
		return "", err
	}
	ipAddress := r.RemoteAddr
	if host, _, splitErr := net.SplitHostPort(r.RemoteAddr); splitErr == nil {
		ipAddress = host
	}
	_, err = s.Store.CreateMFASessionWithAudit(r.Context(), credential, cryptox.Digest(token), time.Now().Add(s.SessionTTL), counter, recoveryDigest, truncateText(r.UserAgent(), 512), truncateText(ipAddress, 128), r.RemoteAddr)
	if err != nil {
		return "", err
	}
	return token, nil
}

func writeMFAStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrLocalSessionRequired):
		writeError(w, http.StatusForbidden, "local_session_required", err.Error())
	case errors.Is(err, store.ErrInvalidCurrentPassword):
		writeError(w, http.StatusForbidden, "invalid_current_password", err.Error())
	case errors.Is(err, store.ErrInvalidMFAProof):
		writeError(w, http.StatusForbidden, "invalid_mfa", err.Error())
	case errors.Is(err, store.ErrMFAAlreadyEnabled):
		writeError(w, http.StatusConflict, "mfa_already_enabled", err.Error())
	case errors.Is(err, store.ErrMFANotEnabled):
		writeError(w, http.StatusConflict, "mfa_not_enabled", err.Error())
	case errors.Is(err, store.ErrMFAEnrollmentMissing):
		writeError(w, http.StatusConflict, "mfa_enrollment_missing", err.Error())
	case errors.Is(err, store.ErrAuthenticationStateChanged):
		writeError(w, http.StatusConflict, "authentication_state_changed", err.Error())
	default:
		writeStoreError(w, err)
	}
}
