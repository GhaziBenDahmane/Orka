package httpapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/bendahma/dokploy-go/internal/tlscert"
	"github.com/google/uuid"
)

type customTLSCertificateInput struct {
	Name           string `json:"name"`
	CertificatePEM string `json:"certificatePem"`
	PrivateKeyPEM  string `json:"privateKeyPem"`
	Revision       int64  `json:"revision"`
}

func (s *Server) createCustomTLSCertificate(w http.ResponseWriter, r *http.Request) {
	var input customTLSCertificateInput
	if !decode(w, r, &input) {
		return
	}
	item, ok := s.customTLSCertificateFromInput(w, r, uuid.New(), 1, input)
	if !ok {
		return
	}
	item, err := s.Store.CreateCustomTLSCertificate(r.Context(), item)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	p := principal(r)
	s.Store.Audit(r.Context(), &p, "custom_tls_certificate.create", "custom_tls_certificate", item.ID.String(), r.RemoteAddr, map[string]any{"fingerprint": item.Fingerprint, "notAfter": item.NotAfter})
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) listCustomTLSCertificates(w http.ResponseWriter, r *http.Request) {
	items, err := s.Store.ListCustomTLSCertificates(r.Context(), principal(r).OrganizationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) updateCustomTLSCertificate(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("certificateID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid certificate id")
		return
	}
	var input customTLSCertificateInput
	if !decode(w, r, &input) {
		return
	}
	if input.Revision < 1 {
		writeError(w, http.StatusBadRequest, "invalid_revision", "current certificate revision is required")
		return
	}
	item, ok := s.customTLSCertificateFromInput(w, r, id, input.Revision, input)
	if !ok {
		return
	}
	item, err = s.Store.UpdateCustomTLSCertificate(r.Context(), item)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	p := principal(r)
	s.Store.Audit(r.Context(), &p, "custom_tls_certificate.rotate", "custom_tls_certificate", item.ID.String(), r.RemoteAddr, map[string]any{"fingerprint": item.Fingerprint, "notAfter": item.NotAfter, "revision": item.Revision})
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) deleteCustomTLSCertificate(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("certificateID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid certificate id")
		return
	}
	p := principal(r)
	if err = s.Store.DeleteCustomTLSCertificate(r.Context(), p.OrganizationID, id); err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "custom_tls_certificate.delete", "custom_tls_certificate", id.String(), r.RemoteAddr, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) customTLSCertificateFromInput(w http.ResponseWriter, r *http.Request, id uuid.UUID, revision int64, input customTLSCertificateInput) (store.CustomTLSCertificate, bool) {
	name := strings.TrimSpace(input.Name)
	if name == "" || len(name) > 100 || name != input.Name {
		writeError(w, http.StatusBadRequest, "invalid_certificate", "certificate name must contain 1 to 100 trimmed characters")
		return store.CustomTLSCertificate{}, false
	}
	certificatePEM, privateKeyPEM := []byte(input.CertificatePEM), []byte(input.PrivateKeyPEM)
	metadata, err := tlscert.Validate(certificatePEM, privateKeyPEM, time.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_certificate", err.Error())
		return store.CustomTLSCertificate{}, false
	}
	encryptedCertificate, err := s.Box.Encrypt(certificatePEM, cryptox.ResourceContext("custom-tls-certificate-certificate", id.String()))
	if err != nil {
		s.writeInternalError(w, r, http.StatusInternalServerError, "encryption_failed", "certificate could not be encrypted", err)
		return store.CustomTLSCertificate{}, false
	}
	encryptedPrivateKey, err := s.Box.Encrypt(privateKeyPEM, cryptox.ResourceContext("custom-tls-certificate-private-key", id.String()))
	if err != nil {
		s.writeInternalError(w, r, http.StatusInternalServerError, "encryption_failed", "private key could not be encrypted", err)
		return store.CustomTLSCertificate{}, false
	}
	return store.CustomTLSCertificate{ID: id, OrganizationID: principal(r).OrganizationID, Name: name, EncryptedCertificate: encryptedCertificate, EncryptedPrivateKey: encryptedPrivateKey, Fingerprint: metadata.Fingerprint, CommonName: metadata.CommonName, DNSNames: metadata.DNSNames, NotBefore: metadata.NotBefore, NotAfter: metadata.NotAfter, Revision: revision}, true
}
