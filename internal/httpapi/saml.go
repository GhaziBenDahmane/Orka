package httpapi

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"math/big"
	"net/http"
	"net/mail"
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
	if in.Name == "" || len(in.MetadataXML) == 0 || len(in.Domains) == 0 {
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
	if metadataValidator.GetSSOBindingLocation(saml.HTTPRedirectBinding) == "" {
		writeError(w, 400, "invalid_metadata", "identity-provider metadata must advertise HTTP-Redirect SSO")
		return
	}
	for i, domain := range in.Domains {
		in.Domains[i] = strings.ToLower(strings.TrimSpace(domain))
		if !strings.Contains(in.Domains[i], ".") {
			writeError(w, 400, "invalid_domain", "valid email domains are required")
			return
		}
	}
	_, certificatePEM, privateKeyPEM, err := newSAMLCertificate(in.Name)
	if err != nil {
		writeError(w, 500, "certificate_failed", "could not generate SAML service-provider certificate")
		return
	}
	id := uuid.New()
	encryptedKey, err := s.Box.Encrypt(privateKeyPEM, "saml-private-key:"+id.String())
	if err != nil {
		writeError(w, 500, "encryption_failed", err.Error())
		return
	}
	p := principal(r)
	provider, err := s.Store.CreateSAMLProvider(r.Context(), store.SAMLProvider{ID: id, OrganizationID: p.OrganizationID, Name: in.Name, IDPMetadata: in.MetadataXML, CertificatePEM: string(certificatePEM), EncryptedPrivateKey: encryptedKey, Domains: in.Domains, EmailAttribute: in.EmailAttribute, NameAttribute: in.NameAttribute, DefaultRole: in.DefaultRole, AllowIDPInitiated: in.AllowIDPInitiated})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "sso.saml.create", "saml_provider", id.String(), r.RemoteAddr, nil)
	writeJSON(w, 201, provider)
}

func (s *Server) listSAMLProviders(w http.ResponseWriter, r *http.Request) {
	items, err := s.Store.ListSAMLProviders(r.Context(), principal(r).OrganizationID)
	if err != nil {
		writeStoreError(w, err)
		return
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
	metadata, parseErr := samlsp.ParseMetadata([]byte(in.MetadataXML))
	if in.Name == "" || len(in.Domains) == 0 || parseErr != nil || len(metadata.IDPSSODescriptors) == 0 {
		writeError(w, 400, "invalid_provider", "name, valid metadataXml, and domains are required")
		return
	}
	metadataValidator := saml.ServiceProvider{IDPMetadata: metadata}
	if metadataValidator.GetSSOBindingLocation(saml.HTTPRedirectBinding) == "" {
		writeError(w, 400, "invalid_metadata", "identity-provider metadata must advertise HTTP-Redirect SSO")
		return
	}
	if roleRank(in.DefaultRole) < 1 || in.DefaultRole == "owner" {
		writeError(w, 400, "invalid_role", "default role must be admin, developer, or viewer")
		return
	}
	for i, domain := range in.Domains {
		in.Domains[i] = strings.ToLower(strings.TrimSpace(domain))
		if !strings.Contains(in.Domains[i], ".") {
			writeError(w, 400, "invalid_domain", "valid email domains are required")
			return
		}
	}
	p := principal(r)
	provider, err := s.Store.UpdateSAMLProvider(r.Context(), p.OrganizationID, store.SAMLProvider{ID: id, Name: in.Name, IDPMetadata: in.MetadataXML, Domains: in.Domains, EmailAttribute: in.EmailAttribute, NameAttribute: in.NameAttribute, DefaultRole: in.DefaultRole, AllowIDPInitiated: in.AllowIDPInitiated})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "sso.saml.update", "saml_provider", id.String(), r.RemoteAddr, nil)
	writeJSON(w, 200, provider)
}

func (s *Server) deleteSAMLProvider(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("providerID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid provider id")
		return
	}
	p := principal(r)
	if err = s.Store.DisableSAMLProvider(r.Context(), p.OrganizationID, id); err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "sso.saml.disable", "saml_provider", id.String(), r.RemoteAddr, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) discoverSAML(w http.ResponseWriter, r *http.Request) {
	email := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("email")))
	parts := strings.Split(email, "@")
	if len(parts) != 2 || parts[1] == "" {
		writeError(w, 400, "invalid_email", "valid email required")
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
	provider, sp, err := s.samlServiceProvider(r.Context(), r.PathValue("providerID"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	data, err := xml.MarshalIndent(sp.Metadata(), "", "  ")
	if err != nil {
		writeError(w, 500, "metadata_failed", "could not generate service-provider metadata")
		return
	}
	_ = provider
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append([]byte(xml.Header), data...))
}

func (s *Server) startSAML(w http.ResponseWriter, r *http.Request) {
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
		writeError(w, 500, "state_failed", err.Error())
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
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	if err = r.ParseForm(); err != nil {
		writeError(w, 400, "invalid_callback", "invalid SAML response")
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
	expiresAt := time.Now().Add(10 * time.Minute)
	if assertion.Conditions != nil && !assertion.Conditions.NotOnOrAfter.IsZero() {
		expiresAt = assertion.Conditions.NotOnOrAfter
	}
	if assertion.ID == "" || s.Store.RecordSAMLAssertion(r.Context(), provider.ID, assertion.ID, expiresAt) != nil {
		writeError(w, 401, "saml_replay", "SAML assertion was already used")
		return
	}
	if assertion.Subject == nil || assertion.Subject.NameID == nil || strings.TrimSpace(assertion.Subject.NameID.Value) == "" {
		writeError(w, 401, "invalid_claims", "SAML assertion lacks a subject")
		return
	}
	email := samlAttribute(assertion, provider.EmailAttribute)
	if email == "" {
		email = samlAttribute(assertion, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")
	}
	if email == "" {
		email = assertion.Subject.NameID.Value
	}
	parsedEmail, err := mail.ParseAddress(strings.TrimSpace(email))
	if err != nil || parsedEmail.Address != strings.TrimSpace(email) {
		writeError(w, 401, "invalid_claims", "SAML assertion lacks a valid email address")
		return
	}
	email = strings.ToLower(parsedEmail.Address)
	domainParts := strings.SplitN(email, "@", 2)
	if len(domainParts) != 2 || !contains(provider.Domains, domainParts[1]) {
		writeError(w, 403, "domain_not_allowed", "email domain is not allowed")
		return
	}
	name := samlAttribute(assertion, provider.NameAttribute)
	userID, err := s.Store.JITSAMLUser(r.Context(), provider, assertion.Subject.NameID.Value, email, name)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	token, err := s.newSession(r, userID, "saml")
	if err != nil {
		writeError(w, 500, "session_failed", err.Error())
		return
	}
	s.Store.AuditOrganization(r.Context(), provider.OrganizationID, "auth.saml.login", "user", userID.String(), r.RemoteAddr, map[string]any{"providerId": provider.ID})
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
	certificateBlock, _ := pem.Decode([]byte(provider.CertificatePEM))
	if certificateBlock == nil || certificateBlock.Type != "CERTIFICATE" {
		return store.SAMLProvider{}, nil, errors.New("invalid SAML certificate")
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		return store.SAMLProvider{}, nil, err
	}
	privateKeyPEM, err := s.Box.Decrypt(provider.EncryptedPrivateKey, "saml-private-key:"+provider.ID.String())
	if err != nil {
		return store.SAMLProvider{}, nil, err
	}
	privateKeyBlock, _ := pem.Decode(privateKeyPEM)
	if privateKeyBlock == nil || privateKeyBlock.Type != "PRIVATE KEY" {
		return store.SAMLProvider{}, nil, errors.New("invalid SAML private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return store.SAMLProvider{}, nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return store.SAMLProvider{}, nil, errors.New("SAML private key cannot sign")
	}
	base := strings.TrimRight(s.PublicURL, "/") + "/v1/auth/saml/" + provider.ID.String()
	metadataURL, _ := url.Parse(base + "/metadata")
	acsURL, _ := url.Parse(base + "/acs")
	return provider, &saml.ServiceProvider{EntityID: metadataURL.String(), Key: signer, Certificate: certificate, MetadataURL: *metadataURL, AcsURL: *acsURL, IDPMetadata: idpMetadata, AuthnNameIDFormat: saml.PersistentNameIDFormat, SignatureMethod: dsig.RSASHA256SignatureMethod, AllowIDPInitiated: provider.AllowIDPInitiated, DefaultRedirectURI: strings.TrimRight(s.PublicURL, "/")}, nil
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
