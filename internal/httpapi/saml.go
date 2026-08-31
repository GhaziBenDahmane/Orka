package httpapi

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bendahma/dokploy-go/internal/auth"
	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/google/uuid"
	"github.com/russellhaering/goxmldsig"
)

const (
	maxSAMLMetadataBytes  = 1 << 20
	maxSAMLAttributeBytes = 512
)

func (s *Server) createSAMLProvider(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name              string   `json:"name"`
		MetadataXML       string   `json:"metadataXml"`
		Domains           []string `json:"domains"`
		EmailAttribute    string   `json:"emailAttribute"`
		NameAttribute     string   `json:"nameAttribute"`
		DefaultRole       string   `json:"defaultRole"`
		AllowIDPInitiated bool     `json:"allowIdpInitiated"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.EmailAttribute == "" {
		in.EmailAttribute = "email"
	}
	if in.NameAttribute == "" {
		in.NameAttribute = "name"
	}
	if in.DefaultRole == "" {
		in.DefaultRole = "developer"
	}
	if !validSAMLProviderFields(in.Name, in.MetadataXML, in.EmailAttribute, in.NameAttribute) || len(in.Domains) == 0 {
		writeError(w, 400, "invalid_provider", "name, metadataXml, and domains are required")
		return
	}
	if roleRank(in.DefaultRole) < 1 || in.DefaultRole == "owner" {
		writeError(w, 400, "invalid_role", "default role must be admin, developer, or viewer")
		return
	}
	metadata, err := samlsp.ParseMetadata([]byte(in.MetadataXML))
	if err != nil || len(metadata.IDPSSODescriptors) == 0 {
		writeError(w, 400, "invalid_metadata", "valid SAML identity-provider metadata is required")
		return
	}
	metadataValidator := saml.ServiceProvider{IDPMetadata: metadata}
	if err = validateSAMLRedirectEndpoint(metadataValidator.GetSSOBindingLocation(saml.HTTPRedirectBinding)); err != nil {
		writeError(w, 400, "invalid_metadata", err.Error())
		return
	}
	if _, err = auth.SAMLIdentityProviderCertificateExpiry(metadata, time.Now()); err != nil {
		writeError(w, 400, "invalid_metadata", err.Error())
		return
	}
	in.Domains, err = normalizeSSODomains(in.Domains)
	if err != nil {
		writeError(w, 400, "invalid_domain", err.Error())
		return
	}
	_, certificatePEM, privateKeyPEM, err := newSAMLCertificate(in.Name)
	if err != nil {
		writeError(w, 500, "certificate_failed", "could not generate SAML service-provider certificate")
		return
	}
	id := uuid.New()
	encryptedKey, err := s.Box.Encrypt(privateKeyPEM, "saml-private-key:"+id.String())
	if err != nil {
		s.writeInternalError(w, r, 500, "encryption_failed", "SAML signing key could not be encrypted", err)
		return
	}
	p := principal(r)
	provider, err := s.Store.CreateSAMLProviderWithAudit(r.Context(), p, store.SAMLProvider{ID: id, Name: in.Name, IDPMetadata: in.MetadataXML, CertificatePEM: string(certificatePEM), EncryptedPrivateKey: encryptedKey, Domains: in.Domains, EmailAttribute: in.EmailAttribute, NameAttribute: in.NameAttribute, DefaultRole: in.DefaultRole, AllowIDPInitiated: in.AllowIDPInitiated}, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setSAMLCertificateStatus(&provider, metadata, time.Now())
	writeJSON(w, 201, provider)
}

func (s *Server) listSAMLProviders(w http.ResponseWriter, r *http.Request) {
	items, err := s.Store.ListSAMLProviders(r.Context(), principal(r).OrganizationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	now := time.Now()
	for index := range items {
		metadata, parseErr := samlsp.ParseMetadata([]byte(items[index].IDPMetadata))
		if parseErr == nil {
			setSAMLCertificateStatus(&items[index], metadata, now)
		}
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) updateSAMLProvider(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("providerID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid provider id")
		return
	}
	var in struct {
		Name, MetadataXML, EmailAttribute, NameAttribute, DefaultRole string
		Domains                                                       []string
		AllowIDPInitiated                                             bool
	}
	if !decode(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.EmailAttribute == "" {
		in.EmailAttribute = "email"
	}
	if in.NameAttribute == "" {
		in.NameAttribute = "name"
	}
	if in.DefaultRole == "" {
		in.DefaultRole = "developer"
	}
	if !validSAMLProviderFields(in.Name, in.MetadataXML, in.EmailAttribute, in.NameAttribute) {
		writeError(w, 400, "invalid_provider", "SAML provider configuration exceeds a supported limit")
		return
	}
	metadata, parseErr := samlsp.ParseMetadata([]byte(in.MetadataXML))
	if in.Name == "" || len(in.Domains) == 0 || parseErr != nil || len(metadata.IDPSSODescriptors) == 0 {
		writeError(w, 400, "invalid_provider", "name, valid metadataXml, and domains are required")
		return
	}
	metadataValidator := saml.ServiceProvider{IDPMetadata: metadata}
	if err = validateSAMLRedirectEndpoint(metadataValidator.GetSSOBindingLocation(saml.HTTPRedirectBinding)); err != nil {
		writeError(w, 400, "invalid_metadata", err.Error())
		return
	}
	if _, err = auth.SAMLIdentityProviderCertificateExpiry(metadata, time.Now()); err != nil {
		writeError(w, 400, "invalid_metadata", err.Error())
		return
	}
	if roleRank(in.DefaultRole) < 1 || in.DefaultRole == "owner" {
		writeError(w, 400, "invalid_role", "default role must be admin, developer, or viewer")
		return
	}
	in.Domains, err = normalizeSSODomains(in.Domains)
	if err != nil {
		writeError(w, 400, "invalid_domain", err.Error())
		return
	}
	p := principal(r)
	provider, err := s.Store.UpdateSAMLProviderWithAudit(r.Context(), p, store.SAMLProvider{ID: id, Name: in.Name, IDPMetadata: in.MetadataXML, Domains: in.Domains, EmailAttribute: in.EmailAttribute, NameAttribute: in.NameAttribute, DefaultRole: in.DefaultRole, AllowIDPInitiated: in.AllowIDPInitiated}, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	setSAMLCertificateStatus(&provider, metadata, time.Now())
	writeJSON(w, 200, provider)
}

func validSAMLProviderFields(name, metadataXML, emailAttribute, nameAttribute string) bool {
	return name != "" && len(name) <= maxSSOProviderName && len(metadataXML) > 0 && len(metadataXML) <= maxSAMLMetadataBytes &&
		validSAMLAttributeName(emailAttribute) && validSAMLAttributeName(nameAttribute)
}

func validSAMLAttributeName(value string) bool {
	if len(value) == 0 || len(value) > maxSAMLAttributeBytes || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func (s *Server) deleteSAMLProvider(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("providerID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid provider id")
		return
	}
	p := principal(r)
	if err = s.Store.SetSSOProviderEnabledWithAudit(r.Context(), p, id, "saml", false, r.RemoteAddr); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) enableSAMLProvider(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("providerID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid provider id")
		return
	}
	p := principal(r)
	provider, err := s.Store.GetOrganizationSAMLProvider(r.Context(), p.OrganizationID, id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	metadata, err := samlsp.ParseMetadata([]byte(provider.IDPMetadata))
	if err != nil || setSAMLCertificateStatus(&provider, metadata, time.Now()) != nil {
		writeError(w, http.StatusConflict, "invalid_saml_certificates", "refresh the SAML metadata or certificate configuration before enabling this provider")
		return
	}
	metadataValidator := saml.ServiceProvider{IDPMetadata: metadata}
	if err = validateSAMLRedirectEndpoint(metadataValidator.GetSSOBindingLocation(saml.HTTPRedirectBinding)); err != nil {
		writeError(w, http.StatusConflict, "invalid_saml_endpoint", err.Error())
		return
	}
	if err = s.Store.SetSSOProviderEnabledWithAudit(r.Context(), p, id, "saml", true, r.RemoteAddr); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) beginSAMLCertificateRotation(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("providerID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid provider id")
		return
	}
	p := principal(r)
	provider, err := s.Store.GetOrganizationSAMLProvider(r.Context(), p.OrganizationID, id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	_, certificatePEM, privateKeyPEM, err := newSAMLCertificate(provider.Name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "certificate_failed", "could not generate SAML service-provider certificate")
		return
	}
	notAfter, err := auth.SAMLServiceProviderCertificateExpiry(string(certificatePEM), time.Now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "certificate_failed", "generated SAML certificate is invalid")
		return
	}
	encryptedKey, err := s.Box.Encrypt(privateKeyPEM, "saml-private-key:"+id.String())
	if err != nil {
		s.writeInternalError(w, r, http.StatusInternalServerError, "encryption_failed", "SAML signing key could not be encrypted", err)
		return
	}
	if err = s.Store.BeginSAMLCertificateRotationWithAudit(r.Context(), p, id, string(certificatePEM), encryptedKey, notAfter, r.RemoteAddr); err != nil {
		writeStoreError(w, err)
		return
	}
	provider, err = s.Store.GetOrganizationSAMLProvider(r.Context(), p.OrganizationID, id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	metadata, parseErr := samlsp.ParseMetadata([]byte(provider.IDPMetadata))
	if parseErr == nil {
		setSAMLCertificateStatus(&provider, metadata, time.Now())
	}
	writeJSON(w, http.StatusCreated, provider)
}

func (s *Server) promoteSAMLCertificateRotation(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("providerID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid provider id")
		return
	}
	var in struct {
		Confirm string `json:"confirm"`
	}
	if !decode(w, r, &in) {
		return
	}
	p := principal(r)
	provider, err := s.Store.GetOrganizationSAMLProvider(r.Context(), p.OrganizationID, id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if in.Confirm != provider.Name {
		writeError(w, http.StatusBadRequest, "confirmation_required", "confirm must exactly match the SAML provider name")
		return
	}
	if provider.PendingCertificatePEM == "" {
		writeError(w, http.StatusConflict, "rotation_not_pending", "this SAML provider has no pending certificate rotation")
		return
	}
	if _, err = auth.SAMLServiceProviderCertificateExpiry(provider.PendingCertificatePEM, time.Now()); err != nil {
		writeError(w, http.StatusConflict, "invalid_saml_certificate", "the pending SAML certificate is no longer valid")
		return
	}
	if _, _, err = s.samlSigningMaterial(id, provider.PendingCertificatePEM, provider.PendingEncryptedPrivateKey); err != nil {
		writeError(w, http.StatusConflict, "invalid_saml_certificate", "the pending SAML certificate and private key do not match")
		return
	}
	if err = s.Store.PromoteSAMLCertificateRotationWithAudit(r.Context(), p, id, r.RemoteAddr); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) cancelSAMLCertificateRotation(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("providerID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_id", "invalid provider id")
		return
	}
	p := principal(r)
	if err = s.Store.CancelSAMLCertificateRotationWithAudit(r.Context(), p, id, r.RemoteAddr); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) discoverSAML(w http.ResponseWriter, r *http.Request) {
	email := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("email")))
	parts := strings.Split(email, "@")
	if len(parts) != 2 || parts[1] == "" {
		writeError(w, 400, "invalid_email", "valid email required")
		return
	}
	if !s.allowAuthenticationAttempt(w, r, "sso-discovery-global", cryptox.Digest("instance"), 300) || !s.allowAuthenticationAttempt(w, r, "sso-discovery-domain", cryptox.Digest(parts[1]), 60) {
		return
	}
	providers, err := s.Store.DiscoverSAML(r.Context(), parts[1])
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": providers})
}

func (s *Server) samlMetadata(w http.ResponseWriter, r *http.Request) {
	providerID, err := uuid.Parse(r.PathValue("providerID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid provider id")
		return
	}
	if !s.allowAuthenticationAttempt(w, r, "sso-metadata-global", cryptox.Digest("instance"), 300) || !s.allowAuthenticationAttempt(w, r, "sso-metadata-provider", cryptox.Digest(providerID.String()), 60) {
		return
	}
	provider, sp, err := s.samlServiceProvider(r.Context(), providerID.String())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	metadata := sp.Metadata()
	if provider.PendingCertificatePEM != "" {
		block, _ := pem.Decode([]byte(provider.PendingCertificatePEM))
		if block == nil || block.Type != "CERTIFICATE" {
			writeError(w, http.StatusInternalServerError, "metadata_failed", "pending SAML certificate is invalid")
			return
		}
		pending := saml.KeyDescriptor{Use: "signing", KeyInfo: saml.KeyInfo{X509Data: saml.X509Data{X509Certificates: []saml.X509Certificate{{Data: base64.StdEncoding.EncodeToString(block.Bytes)}}}}}
		metadata.SPSSODescriptors[0].KeyDescriptors = append(metadata.SPSSODescriptors[0].KeyDescriptors, pending)
	}
	data, err := xml.MarshalIndent(metadata, "", "  ")
	if err != nil {
		writeError(w, 500, "metadata_failed", "could not generate service-provider metadata")
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append([]byte(xml.Header), data...))
}

func (s *Server) startSAML(w http.ResponseWriter, r *http.Request) {
	providerID, err := uuid.Parse(r.PathValue("providerID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid provider id")
		return
	}
	if !s.allowAuthenticationAttempt(w, r, "sso-start-global", cryptox.Digest("instance"), 300) || !s.allowAuthenticationAttempt(w, r, "sso-start-provider", cryptox.Digest(providerID.String()), 60) {
		return
	}
	provider, sp, err := s.samlServiceProvider(r.Context(), r.PathValue("providerID"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	request, err := sp.MakeAuthenticationRequest(sp.GetSSOBindingLocation(saml.HTTPRedirectBinding), saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		writeError(w, 502, "saml_request_failed", "identity provider has no compatible SSO endpoint")
		return
	}
	relayState, err := auth.NewToken()
	if err != nil {
		s.writeInternalError(w, r, 500, "state_failed", "SAML login state could not be generated", err)
		return
	}
	if err = s.Store.CreateSAMLState(r.Context(), cryptox.Digest(relayState), provider.ID, request.ID); err != nil {
		writeStoreError(w, err)
		return
	}
	if err = s.setLoginStateCookie(w, "saml", relayState, http.SameSiteNoneMode); err != nil {
		writeError(w, 500, "state_failed", "could not bind login state")
		return
	}
	redirectURL, err := request.Redirect(relayState, sp)
	if err != nil {
		writeError(w, 500, "saml_request_failed", "could not encode authentication request")
		return
	}
	writeJSON(w, 200, map[string]string{"url": redirectURL.String()})
}

func (s *Server) callbackSAML(w http.ResponseWriter, r *http.Request) {
	providerID, err := uuid.Parse(r.PathValue("providerID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid provider id")
		return
	}
	if !s.allowAuthenticationAttempt(w, r, "sso-callback-global", cryptox.Digest("instance"), 300) || !s.allowAuthenticationAttempt(w, r, "sso-callback-provider", cryptox.Digest(providerID.String()), 60) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	if err = r.ParseForm(); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large", "SAML response exceeds 2 MiB")
		} else {
			writeError(w, 400, "invalid_callback", "invalid SAML response")
		}
		return
	}
	relayState := r.Form.Get("RelayState")
	if r.Form.Get("SAMLResponse") == "" {
		writeError(w, 400, "invalid_callback", "SAMLResponse is required")
		return
	}
	provider, sp, err := s.samlServiceProvider(r.Context(), providerID.String())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	requestIDs := []string(nil)
	if relayState != "" {
		if !s.consumeLoginStateCookie(w, r, "saml", relayState, http.SameSiteNoneMode) {
			writeError(w, 400, "invalid_state", "RelayState is not bound to this browser")
			return
		}
		requestID, stateErr := s.Store.ConsumeSAMLState(r.Context(), cryptox.Digest(relayState), providerID)
		if stateErr != nil {
			writeError(w, 400, "invalid_state", "state is invalid or expired")
			return
		}
		requestIDs = []string{requestID}
	} else if !provider.AllowIDPInitiated {
		writeError(w, 400, "invalid_state", "RelayState is required")
		return
	}
	assertion, err := sp.ParseResponse(r, requestIDs)
	if err != nil {
		writeError(w, 401, "invalid_saml_response", "SAML response verification failed")
		return
	}
	notOnOrAfter := time.Time{}
	if assertion.Conditions != nil {
		notOnOrAfter = assertion.Conditions.NotOnOrAfter
	}
	expiresAt, validLifetime := samlReplayExpiry(notOnOrAfter, time.Now())
	if !validLifetime {
		writeError(w, 401, "invalid_saml_response", "SAML assertion lifetime is invalid")
		return
	}
	if !validFederatedIdentifier(assertion.ID) {
		writeError(w, 401, "invalid_saml_response", "SAML assertion identifier is invalid")
		return
	}
	if assertion.Subject == nil || assertion.Subject.NameID == nil || !validFederatedIdentifier(assertion.Subject.NameID.Value) {
		writeError(w, 401, "invalid_claims", "SAML assertion lacks a subject")
		return
	}
	if s.Store.RecordSAMLAssertion(r.Context(), provider.ID, assertion.ID, expiresAt) != nil {
		writeError(w, 401, "saml_replay", "SAML assertion was already used")
		return
	}
	email := samlAttribute(assertion, provider.EmailAttribute)
	if email == "" {
		email = samlAttribute(assertion, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")
	}
	if email == "" {
		email = assertion.Subject.NameID.Value
	}
	email, domain, validEmail := canonicalEmail(email)
	if !validEmail {
		writeError(w, 401, "invalid_claims", "SAML assertion lacks a valid email address")
		return
	}
	if !contains(provider.Domains, domain) {
		writeError(w, 403, "domain_not_allowed", "email domain is not allowed")
		return
	}
	name, validName := canonicalDisplayName(samlAttribute(assertion, provider.NameAttribute))
	if !validName {
		writeError(w, 401, "invalid_claims", "SAML display name is too long")
		return
	}
	userID, err := s.Store.JITSAMLUser(r.Context(), provider, assertion.Subject.NameID.Value, email, name)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	token, err := s.newSession(r, userID, &provider.OrganizationID, &provider.ID, "saml", "", map[string]any{"providerId": provider.ID})
	if err != nil {
		s.writeInternalError(w, r, 500, "session_failed", "session could not be created", err)
		return
	}
	writeLoginSuccess(w, r, token)
}

func (s *Server) samlServiceProvider(ctx context.Context, rawID string) (store.SAMLProvider, *saml.ServiceProvider, error) {
	id, err := uuid.Parse(rawID)
	if err != nil {
		return store.SAMLProvider{}, nil, store.ErrNotFound
	}
	provider, err := s.Store.GetSAMLProvider(ctx, id)
	if err != nil {
		return store.SAMLProvider{}, nil, err
	}
	idpMetadata, err := samlsp.ParseMetadata([]byte(provider.IDPMetadata))
	if err != nil {
		return store.SAMLProvider{}, nil, err
	}
	if err = setSAMLCertificateStatus(&provider, idpMetadata, time.Now()); err != nil {
		return store.SAMLProvider{}, nil, err
	}
	metadataValidator := saml.ServiceProvider{IDPMetadata: idpMetadata}
	if err = validateSAMLRedirectEndpoint(metadataValidator.GetSSOBindingLocation(saml.HTTPRedirectBinding)); err != nil {
		return store.SAMLProvider{}, nil, err
	}
	certificate, signer, err := s.samlSigningMaterial(provider.ID, provider.CertificatePEM, provider.EncryptedPrivateKey)
	if err != nil {
		return store.SAMLProvider{}, nil, err
	}
	base := strings.TrimRight(s.PublicURL, "/") + "/v1/auth/saml/" + provider.ID.String()
	metadataURL, _ := url.Parse(base + "/metadata")
	acsURL, _ := url.Parse(base + "/acs")
	return provider, &saml.ServiceProvider{EntityID: metadataURL.String(), Key: signer, Certificate: certificate, MetadataURL: *metadataURL, AcsURL: *acsURL, IDPMetadata: idpMetadata, AuthnNameIDFormat: saml.PersistentNameIDFormat, SignatureMethod: dsig.RSASHA256SignatureMethod, AllowIDPInitiated: provider.AllowIDPInitiated, DefaultRedirectURI: strings.TrimRight(s.PublicURL, "/")}, nil
}

func validateSAMLRedirectEndpoint(raw string) error {
	endpoint, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || endpoint.Scheme != "https" || !validSSOURLHost(endpoint) || endpoint.User != nil || endpoint.Fragment != "" || endpoint.Opaque != "" {
		return errors.New("identity-provider metadata must advertise an absolute HTTPS HTTP-Redirect SSO endpoint")
	}
	return nil
}

func (s *Server) samlSigningMaterial(providerID uuid.UUID, certificatePEM, encryptedPrivateKey string) (*x509.Certificate, crypto.Signer, error) {
	certificateBlock, _ := pem.Decode([]byte(certificatePEM))
	if certificateBlock == nil || certificateBlock.Type != "CERTIFICATE" {
		return nil, nil, errors.New("invalid SAML certificate")
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	privateKeyPEM, err := s.Box.Decrypt(encryptedPrivateKey, "saml-private-key:"+providerID.String())
	if err != nil {
		return nil, nil, err
	}
	defer clear(privateKeyPEM)
	privateKeyBlock, _ := pem.Decode(privateKeyPEM)
	if privateKeyBlock == nil || privateKeyBlock.Type != "PRIVATE KEY" {
		return nil, nil, errors.New("invalid SAML private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, nil, errors.New("SAML private key cannot sign")
	}
	certificateKey, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	signerKey, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(certificateKey, signerKey) {
		return nil, nil, errors.New("SAML certificate and private key do not match")
	}
	return certificate, signer, nil
}

func samlAttribute(assertion *saml.Assertion, name string) string {
	for _, statement := range assertion.AttributeStatements {
		for _, attribute := range statement.Attributes {
			if strings.EqualFold(attribute.Name, name) || strings.EqualFold(attribute.FriendlyName, name) {
				for _, value := range attribute.Values {
					if strings.TrimSpace(value.Value) != "" {
						return strings.TrimSpace(value.Value)
					}
				}
			}
		}
	}
	return ""
}

func samlReplayExpiry(notOnOrAfter, now time.Time) (time.Time, bool) {
	if notOnOrAfter.IsZero() {
		return time.Time{}, false
	}
	if !notOnOrAfter.After(now) || notOnOrAfter.After(now.Add(24*time.Hour)) {
		return time.Time{}, false
	}
	return notOnOrAfter, true
}

func newSAMLCertificate(name string) (*rsa.PrivateKey, []byte, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, nil, err
	}
	now := time.Now()
	template := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{Organization: []string{"Dockyard"}, CommonName: name}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(10, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	encodedKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedKey}), nil
}

func setSAMLCertificateStatus(provider *store.SAMLProvider, metadata *saml.EntityDescriptor, now time.Time) error {
	spExpiry, spErr := auth.SAMLServiceProviderCertificateExpiry(provider.CertificatePEM, now)
	if !spExpiry.IsZero() {
		provider.SPCertificateNotAfter = &spExpiry
	}
	idpExpiry, idpErr := auth.SAMLIdentityProviderCertificateExpiry(metadata, now)
	if !idpExpiry.IsZero() {
		provider.IDPCertificateNotAfter = &idpExpiry
	}
	provider.CertificateConfigurationOK = spErr == nil && idpErr == nil
	return errors.Join(spErr, idpErr)
}
