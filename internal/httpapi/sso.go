package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bendahma/dokploy-go/internal/auth"
	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/netpolicy"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

const (
	oidcRequestTimeout   = 15 * time.Second
	maxOIDCResponseBytes = 4 << 20
	maxSSOProviderName   = 120
	maxOIDCIssuerBytes   = 2048
	maxOIDCClientIDBytes = 1024
	maxOIDCSecretBytes   = 16 << 10
	maxOIDCScopes        = 32
	maxOIDCScopeBytes    = 128
)

var errOIDCResponseTooLarge = errors.New("OIDC response exceeds 4 MiB")
var errOIDCEmailUnverified = errors.New("OIDC email claim is not verified")
var ssoDomainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
var ssoHostnameLabelPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$`)

func (s *Server) createOIDCProvider(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name         string   `json:"name"`
		Issuer       string   `json:"issuer"`
		ClientID     string   `json:"clientId"`
		ClientSecret string   `json:"clientSecret"`
		Domains      []string `json:"domains"`
		Scopes       []string `json:"scopes"`
		DefaultRole  string   `json:"defaultRole"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	issuer, err := normalizedOIDCIssuer(in.Issuer)
	if err != nil {
		writeError(w, 400, "invalid_issuer", "issuer must be an absolute HTTPS URL")
		return
	}
	if in.Name == "" || in.ClientID == "" || in.ClientSecret == "" || len(in.Domains) == 0 {
		writeError(w, 400, "invalid_provider", "name, client credentials and domains are required")
		return
	}
	if in.DefaultRole == "" {
		in.DefaultRole = "developer"
	}
	if len(in.Scopes) == 0 {
		in.Scopes = []string{"openid", "profile", "email"}
	}
	in.Scopes, err = normalizeOIDCScopes(in.Scopes)
	if err != nil || !validOIDCProviderFields(in.Name, in.ClientID, in.ClientSecret) {
		writeError(w, 400, "invalid_provider", "OIDC provider configuration exceeds a supported limit or has invalid scopes")
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
	id := uuid.New()
	encrypted, err := s.Box.Encrypt([]byte(in.ClientSecret), "oidc-client-secret:"+id.String())
	if err != nil {
		s.writeInternalError(w, r, 500, "encryption_failed", "OIDC client secret could not be encrypted", err)
		return
	}
	principal := principal(r)
	provider, err := s.Store.CreateOIDCProviderWithAudit(r.Context(), principal, store.OIDCProvider{ID: id, Name: in.Name, Issuer: issuer, ClientID: in.ClientID, EncryptedClientSecret: encrypted, Domains: in.Domains, Scopes: in.Scopes, DefaultRole: in.DefaultRole}, r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 201, provider)
}

func (s *Server) listOIDCProviders(w http.ResponseWriter, r *http.Request) {
	items, err := s.Store.ListOIDCProviders(r.Context(), principal(r).OrganizationID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) updateOIDCProvider(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("providerID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid provider id")
		return
	}
	var in struct {
		Name, Issuer, ClientID, ClientSecret, DefaultRole string
		Domains, Scopes                                   []string
	}
	if !decode(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	issuer, err := normalizedOIDCIssuer(in.Issuer)
	if err != nil || in.Name == "" || in.ClientID == "" || len(in.Domains) == 0 {
		writeError(w, 400, "invalid_provider", "name, HTTPS issuer, client ID, and domains are required")
		return
	}
	if in.DefaultRole == "" {
		in.DefaultRole = "developer"
	}
	if len(in.Scopes) == 0 {
		in.Scopes = []string{"openid", "profile", "email"}
	}
	in.Scopes, err = normalizeOIDCScopes(in.Scopes)
	if err != nil || !validOIDCProviderFields(in.Name, in.ClientID, in.ClientSecret) {
		writeError(w, 400, "invalid_provider", "OIDC provider configuration exceeds a supported limit or has invalid scopes")
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
	encrypted := ""
	if in.ClientSecret != "" {
		encrypted, err = s.Box.Encrypt([]byte(in.ClientSecret), "oidc-client-secret:"+id.String())
		if err != nil {
			s.writeInternalError(w, r, 500, "encryption_failed", "OIDC client secret could not be encrypted", err)
			return
		}
	}
	p := principal(r)
	provider, err := s.Store.UpdateOIDCProviderWithAudit(r.Context(), p, store.OIDCProvider{ID: id, Name: strings.TrimSpace(in.Name), Issuer: issuer, ClientID: in.ClientID, EncryptedClientSecret: encrypted, Domains: in.Domains, Scopes: in.Scopes, DefaultRole: in.DefaultRole}, in.ClientSecret != "", r.RemoteAddr)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, provider)
}

func (s *Server) deleteOIDCProvider(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("providerID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid provider id")
		return
	}
	p := principal(r)
	if err = s.Store.SetSSOProviderEnabledWithAudit(r.Context(), p, id, "oidc", false, r.RemoteAddr); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(204)
}

func (s *Server) enableOIDCProvider(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("providerID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid provider id")
		return
	}
	p := principal(r)
	if err = s.Store.SetSSOProviderEnabledWithAudit(r.Context(), p, id, "oidc", true, r.RemoteAddr); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) discoverOIDC(w http.ResponseWriter, r *http.Request) {
	_, domain, validEmail := canonicalEmail(r.URL.Query().Get("email"))
	if !validEmail {
		writeError(w, 400, "invalid_email", "valid email required")
		return
	}
	if !s.allowAuthenticationAttempt(w, r, "sso-discovery-client", authenticationClientKey(r), 300) || !s.allowAuthenticationAttempt(w, r, "sso-discovery-domain", cryptox.Digest(domain), 60) {
		return
	}
	providers, err := s.Store.DiscoverOIDC(r.Context(), domain)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": providers})
}

func (s *Server) startOIDC(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("providerID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid provider id")
		return
	}
	if !s.allowAuthenticationAttempt(w, r, "sso-start-client", authenticationClientKey(r), 300) || !s.allowAuthenticationAttempt(w, r, "sso-start-provider", cryptox.Digest(id.String()), 60) {
		return
	}
	provider, err := s.Store.GetOIDCProvider(r.Context(), id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	providerContext, cancel := context.WithTimeout(r.Context(), oidcRequestTimeout)
	defer cancel()
	providerContext = oidc.ClientContext(providerContext, s.oidcHTTPClient())
	discovery, err := oidc.NewProvider(providerContext, provider.Issuer)
	if err != nil {
		writeError(w, 502, "oidc_discovery_failed", "identity provider discovery failed")
		return
	}
	if err = validateOIDCProviderEndpoints(discovery); err != nil {
		writeError(w, 502, "oidc_discovery_failed", "identity provider discovery contains an unsafe endpoint")
		return
	}
	state, err := auth.NewToken()
	if err != nil {
		s.writeInternalError(w, r, 500, "state_failed", "OIDC login state could not be generated", err)
		return
	}
	verifier := oauth2.GenerateVerifier()
	nonce, err := auth.NewToken()
	if err != nil {
		s.writeInternalError(w, r, 500, "nonce_failed", "OIDC nonce could not be generated", err)
		return
	}
	if err = s.Store.CreateOIDCState(r.Context(), cryptox.Digest(state), provider.ID, provider.Revision, verifier, nonce); err != nil {
		writeStoreError(w, err)
		return
	}
	if err = s.setLoginStateCookie(w, "oidc", state, http.SameSiteLaxMode); err != nil {
		writeError(w, 500, "state_failed", "could not bind login state")
		return
	}
	cfg := oauth2.Config{ClientID: provider.ClientID, Endpoint: discovery.Endpoint(), RedirectURL: s.PublicURL + "/v1/auth/sso/callback", Scopes: provider.Scopes}
	writeJSON(w, 200, map[string]string{"url": cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce))})
}

func (s *Server) callbackOIDC(w http.ResponseWriter, r *http.Request) {
	stateValue, code := r.URL.Query().Get("state"), r.URL.Query().Get("code")
	if !validPublicOpaqueValue(stateValue, maxPublicCredentialBytes) || !validPublicOpaqueValue(code, maxAuthorizationCodeBytes) {
		writeError(w, 400, "invalid_callback", "state and code are required")
		return
	}
	if !s.allowAuthenticationAttempt(w, r, "sso-callback-client", authenticationClientKey(r), 300) {
		return
	}
	if !s.consumeLoginStateCookie(w, r, "oidc", stateValue, http.SameSiteLaxMode) {
		writeError(w, 400, "invalid_state", "state is not bound to this browser")
		return
	}
	providerID, providerRevision, verifierValue, nonce, err := s.Store.ConsumeOIDCState(r.Context(), cryptox.Digest(stateValue))
	if err != nil {
		writeError(w, 400, "invalid_state", "state is invalid or expired")
		return
	}
	provider, err := s.Store.GetOIDCProvider(r.Context(), providerID)
	if err != nil {
		if writeFederatedStateError(w, err) {
			return
		}
		writeStoreError(w, err)
		return
	}
	if provider.Revision != providerRevision {
		writeError(w, 400, "invalid_state", "identity provider configuration changed during login")
		return
	}
	secret, err := s.Box.Decrypt(provider.EncryptedClientSecret, "oidc-client-secret:"+provider.ID.String())
	if err != nil {
		s.writeInternalError(w, r, 500, "decryption_failed", "OIDC provider configuration could not be decrypted", err)
		return
	}
	defer clear(secret)
	providerContext, cancel := context.WithTimeout(r.Context(), oidcRequestTimeout)
	defer cancel()
	providerContext = oidc.ClientContext(providerContext, s.oidcHTTPClient())
	discovery, err := oidc.NewProvider(providerContext, provider.Issuer)
	if err != nil {
		writeError(w, 502, "oidc_discovery_failed", "identity provider discovery failed")
		return
	}
	if err = validateOIDCProviderEndpoints(discovery); err != nil {
		writeError(w, 502, "oidc_discovery_failed", "identity provider discovery contains an unsafe endpoint")
		return
	}
	cfg := oauth2.Config{ClientID: provider.ClientID, ClientSecret: string(secret), Endpoint: discovery.Endpoint(), RedirectURL: s.PublicURL + "/v1/auth/sso/callback", Scopes: provider.Scopes}
	oauthToken, err := cfg.Exchange(providerContext, code, oauth2.VerifierOption(verifierValue))
	if err != nil {
		writeError(w, 401, "oidc_exchange_failed", "identity provider rejected the authorization code")
		return
	}
	rawIDToken, ok := oauthToken.Extra("id_token").(string)
	if !ok {
		writeError(w, 401, "missing_id_token", "identity provider did not return an ID token")
		return
	}
	idToken, err := discovery.Verifier(&oidc.Config{ClientID: provider.ClientID}).Verify(providerContext, rawIDToken)
	if err != nil {
		writeError(w, 401, "invalid_id_token", "identity token verification failed")
		return
	}
	var claims oidcIdentityClaims
	if err = idToken.Claims(&claims); err != nil || !validFederatedIdentifier(claims.Subject) {
		writeError(w, 401, "invalid_claims", "identity token lacks required claims")
		return
	}
	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(nonce)) != 1 {
		writeError(w, 401, "invalid_nonce", "identity token nonce does not match the login request")
		return
	}
	email, domain, err := claims.loginEmail()
	if errors.Is(err, errOIDCEmailUnverified) {
		writeError(w, 403, "email_unverified", "verified email is required")
		return
	}
	if err != nil {
		writeError(w, 401, "invalid_claims", "identity token lacks a valid email address")
		return
	}
	if !contains(provider.Domains, domain) {
		writeError(w, 403, "domain_not_allowed", "email domain is not allowed")
		return
	}
	name, validName := canonicalDisplayName(claims.Name)
	if !validName {
		writeError(w, 401, "invalid_claims", "identity token display name is too long")
		return
	}
	userID, err := s.Store.JITOIDCUser(r.Context(), provider, claims.Subject, email, name)
	if writeFederatedStateError(w, err) {
		return
	}
	if err != nil {
		writeStoreError(w, err)
		return
	}
	token, err := s.newSession(r, userID, &provider.OrganizationID, &provider.ID, providerRevision, "oidc", "", map[string]any{"providerId": provider.ID})
	if writeFederatedStateError(w, err) {
		return
	}
	if err != nil {
		s.writeInternalError(w, r, 500, "session_failed", "session could not be created", err)
		return
	}
	writeLoginSuccess(w, r, token)
}

func writeFederatedStateError(w http.ResponseWriter, err error) bool {
	if !errors.Is(err, store.ErrAuthenticationStateChanged) && !errors.Is(err, store.ErrNotFound) {
		return false
	}
	writeError(w, http.StatusBadRequest, "invalid_state", "identity provider configuration changed during login")
	return true
}

func normalizedOIDCIssuer(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if len(raw) == 0 || len(raw) > maxOIDCIssuerBytes {
		return "", errors.New("OIDC issuer must be an absolute HTTPS URL without credentials, query, or fragment")
	}
	issuer, err := url.Parse(raw)
	if err != nil || issuer.Scheme != "https" || !validSSOURLHost(issuer) || !validSSOURLCharacters(raw, issuer) || issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" || issuer.Opaque != "" {
		return "", errors.New("OIDC issuer must be an absolute HTTPS URL without credentials, query, or fragment")
	}
	issuer.Path = strings.TrimRight(issuer.Path, "/")
	issuer.RawPath = strings.TrimRight(issuer.RawPath, "/")
	return issuer.String(), nil
}

func normalizeOIDCScopes(scopes []string) ([]string, error) {
	if len(scopes) == 0 || len(scopes) > maxOIDCScopes {
		return nil, errors.New("OIDC scopes must contain between 1 and 32 values")
	}
	normalized := make([]string, 0, len(scopes))
	seen := make(map[string]struct{}, len(scopes))
	for _, raw := range scopes {
		scope := strings.TrimSpace(raw)
		if len(scope) == 0 || len(scope) > maxOIDCScopeBytes {
			return nil, errors.New("OIDC scope is empty or too long")
		}
		for _, character := range []byte(scope) {
			if character < 0x21 || character > 0x7e || character == '"' || character == '\\' {
				return nil, errors.New("OIDC scope contains an invalid character")
			}
		}
		if _, duplicate := seen[scope]; duplicate {
			continue
		}
		seen[scope] = struct{}{}
		normalized = append(normalized, scope)
	}
	if _, ok := seen["openid"]; !ok {
		return nil, errors.New("OIDC scopes must include openid")
	}
	return normalized, nil
}

func validOIDCProviderFields(name, clientID, clientSecret string) bool {
	return validDisplayLabel(name, maxSSOProviderName) && validSSOConfigurationText(name, maxSSOProviderName) &&
		validSSOConfigurationText(clientID, maxOIDCClientIDBytes) && len(clientSecret) <= maxOIDCSecretBytes
}

func validateOIDCProviderEndpoints(provider *oidc.Provider) error {
	var metadata struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		JWKSURI               string `json:"jwks_uri"`
	}
	if err := provider.Claims(&metadata); err != nil {
		return errors.New("decode OIDC provider endpoints")
	}
	for name, raw := range map[string]string{
		"authorization_endpoint": metadata.AuthorizationEndpoint,
		"token_endpoint":         metadata.TokenEndpoint,
		"jwks_uri":               metadata.JWKSURI,
	} {
		raw = strings.TrimSpace(raw)
		endpoint, err := url.Parse(raw)
		if err != nil || endpoint.Scheme != "https" || !validSSOURLHost(endpoint) || !validSSOURLCharacters(raw, endpoint) || endpoint.User != nil || endpoint.Fragment != "" || endpoint.Opaque != "" {
			return errors.New(name + " must be an absolute HTTPS URL")
		}
	}
	return nil
}

func validSSOURLHost(endpoint *url.URL) bool {
	host := endpoint.Hostname()
	if strings.HasPrefix(endpoint.Host, "[") && net.ParseIP(host) == nil {
		return false
	}
	if net.ParseIP(host) == nil {
		if len(host) == 0 || len(host) > 253 {
			return false
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || !ssoHostnameLabelPattern.MatchString(label) {
				return false
			}
		}
	}
	if strings.HasSuffix(endpoint.Host, ":") {
		return false
	}
	if port := endpoint.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return false
		}
	}
	return true
}

func validSSOConfigurationText(value string, maxBytes int) bool {
	return value != "" && len(value) <= maxBytes && value == strings.TrimSpace(value) && utf8.ValidString(value) &&
		strings.IndexFunc(value, func(character rune) bool {
			return unicode.IsControl(character) || unicode.Is(unicode.Cf, character)
		}) < 0
}

func validSSOURLCharacters(raw string, endpoint *url.URL) bool {
	if !validSSOText(raw) || !validSSOText(endpoint.Path) {
		return false
	}
	query, err := url.QueryUnescape(endpoint.RawQuery)
	return err == nil && validSSOText(query)
}

func validSSOText(value string) bool {
	return utf8.ValidString(value) && strings.IndexFunc(value, func(character rune) bool {
		return unicode.IsControl(character) || unicode.Is(unicode.Cf, character)
	}) < 0
}

func (s *Server) oidcHTTPClient() *http.Client {
	client := s.OIDCHTTPClient
	if client == nil {
		client = &http.Client{Timeout: oidcRequestTimeout, Transport: s.EgressTransport}
	}
	secured := *client
	if secured.Transport == nil {
		secured.Transport = s.EgressTransport
	}
	if secured.Transport == nil {
		secured.Transport = (&netpolicy.Policy{}).Transport()
	}
	secured.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("OIDC redirects are disabled")
	}
	secured.Transport = oidcResponseLimitTransport{base: secured.Transport}
	return &secured
}

type oidcResponseLimitTransport struct {
	base http.RoundTripper
}

func (t oidcResponseLimitTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	response, err := base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if response.ContentLength > maxOIDCResponseBytes {
		_ = response.Body.Close()
		return nil, errOIDCResponseTooLarge
	}
	response.Body = &oidcBoundedBody{body: response.Body, remaining: maxOIDCResponseBytes}
	return response, nil
}

type oidcBoundedBody struct {
	body      io.ReadCloser
	remaining int64
}

func (b *oidcBoundedBody) Read(buffer []byte) (int, error) {
	if b.remaining == 0 {
		var probe [1]byte
		n, err := b.body.Read(probe[:])
		if n > 0 {
			return 0, errOIDCResponseTooLarge
		}
		return 0, err
	}
	if int64(len(buffer)) > b.remaining {
		buffer = buffer[:b.remaining]
	}
	n, err := b.body.Read(buffer)
	b.remaining -= int64(n)
	return n, err
}

func (b *oidcBoundedBody) Close() error { return b.body.Close() }

type oidcIdentityClaims struct {
	Subject           string `json:"sub"`
	Email             string `json:"email"`
	PreferredUsername string `json:"preferred_username"`
	EmailVerified     *bool  `json:"email_verified"`
	Name              string `json:"name"`
	Nonce             string `json:"nonce"`
}

// loginEmail accepts the standard email claim first and falls back to
// preferred_username for providers such as Microsoft Entra ID that commonly
// omit email for workforce accounts. Both values still pass the same strict
// address and organization-domain validation before JIT provisioning.
func (claims oidcIdentityClaims) loginEmail() (string, string, error) {
	if strings.TrimSpace(claims.Email) != "" {
		if claims.EmailVerified == nil || !*claims.EmailVerified {
			return "", "", errOIDCEmailUnverified
		}
		email, domain, ok := oidcEmail(claims.Email)
		if !ok {
			return "", "", errors.New("OIDC email claim is invalid")
		}
		return email, domain, nil
	}
	email, domain, ok := oidcEmail(claims.PreferredUsername)
	if !ok {
		return "", "", errors.New("OIDC preferred_username claim is invalid")
	}
	return email, domain, nil
}

func normalizeSSODomains(domains []string) ([]string, error) {
	if len(domains) == 0 || len(domains) > 100 {
		return nil, errors.New("between 1 and 100 valid email domains are required")
	}
	normalized := make([]string, 0, len(domains))
	seen := make(map[string]struct{}, len(domains))
	for _, raw := range domains {
		domain := strings.ToLower(strings.TrimSpace(raw))
		if len(domain) > 253 || !ssoDomainPattern.MatchString(domain) {
			return nil, errors.New("valid DNS email domains are required")
		}
		if _, duplicate := seen[domain]; duplicate {
			continue
		}
		seen[domain] = struct{}{}
		normalized = append(normalized, domain)
	}
	return normalized, nil
}

func (s *Server) setLoginStateCookie(w http.ResponseWriter, kind, state string, sameSite http.SameSite) error {
	name := loginStateCookieName(kind, state)
	value, err := s.Box.Encrypt([]byte(state), "login-state:"+name)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/v1/auth/", MaxAge: 600, HttpOnly: true, Secure: strings.HasPrefix(strings.ToLower(s.PublicURL), "https://"), SameSite: sameSite})
	return nil
}

func (s *Server) consumeLoginStateCookie(w http.ResponseWriter, r *http.Request, kind, state string, sameSite http.SameSite) bool {
	name := loginStateCookieName(kind, state)
	cookie, err := r.Cookie(name)
	s.setExpiredLoginStateCookie(w, name, sameSite)
	if err != nil {
		return false
	}
	plain, err := s.Box.Decrypt(cookie.Value, "login-state:"+name)
	if err != nil {
		return false
	}
	valid := subtle.ConstantTimeCompare(plain, []byte(state)) == 1
	clear(plain)
	return valid
}

func (s *Server) setExpiredLoginStateCookie(w http.ResponseWriter, name string, sameSite http.SameSite) {
	http.SetCookie(w, &http.Cookie{Name: name, Path: "/v1/auth/", MaxAge: -1, HttpOnly: true, Secure: strings.HasPrefix(strings.ToLower(s.PublicURL), "https://"), SameSite: sameSite})
}

func loginStateCookieName(kind, state string) string {
	digest := cryptox.Digest(state)
	return "dockyard_" + kind + "_state_" + hex.EncodeToString(digest[:8])
}

func oidcEmail(raw string) (string, string, bool) {
	return canonicalEmail(raw)
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if strings.EqualFold(item, want) {
			return true
		}
	}
	return false
}
