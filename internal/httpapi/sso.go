package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/bendahma/dokploy-go/internal/auth"
	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

const oidcRequestTimeout = 15 * time.Second

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
	id := uuid.New()
	encrypted, err := s.Box.Encrypt([]byte(in.ClientSecret), "oidc-client-secret:"+id.String())
	if err != nil {
		writeError(w, 500, "encryption_failed", err.Error())
		return
	}
	principal := principal(r)
	provider, err := s.Store.CreateOIDCProvider(r.Context(), store.OIDCProvider{ID: id, OrganizationID: principal.OrganizationID, Name: in.Name, Issuer: issuer, ClientID: in.ClientID, EncryptedClientSecret: encrypted, Domains: in.Domains, Scopes: in.Scopes, DefaultRole: in.DefaultRole})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &principal, "sso.oidc.create", "oidc_provider", id.String(), r.RemoteAddr, nil)
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
	encrypted := ""
	if in.ClientSecret != "" {
		encrypted, err = s.Box.Encrypt([]byte(in.ClientSecret), "oidc-client-secret:"+id.String())
		if err != nil {
			writeError(w, 500, "encryption_failed", err.Error())
			return
		}
	}
	p := principal(r)
	provider, err := s.Store.UpdateOIDCProvider(r.Context(), p.OrganizationID, store.OIDCProvider{ID: id, Name: strings.TrimSpace(in.Name), Issuer: issuer, ClientID: in.ClientID, EncryptedClientSecret: encrypted, Domains: in.Domains, Scopes: in.Scopes, DefaultRole: in.DefaultRole})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "sso.oidc.update", "oidc_provider", id.String(), r.RemoteAddr, map[string]any{"rotatedSecret": in.ClientSecret != ""})
	writeJSON(w, 200, provider)
}

func (s *Server) deleteOIDCProvider(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("providerID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid provider id")
		return
	}
	p := principal(r)
	if err = s.Store.DisableOIDCProvider(r.Context(), p.OrganizationID, id); err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "sso.oidc.disable", "oidc_provider", id.String(), r.RemoteAddr, nil)
	w.WriteHeader(204)
}

func (s *Server) enableOIDCProvider(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("providerID"))
	if err != nil {
		writeError(w, 400, "invalid_id", "invalid provider id")
		return
	}
	p := principal(r)
	if err = s.Store.SetOIDCProviderEnabled(r.Context(), p.OrganizationID, id, true); err != nil {
		writeStoreError(w, err)
		return
	}
	s.Store.Audit(r.Context(), &p, "sso.oidc.enable", "oidc_provider", id.String(), r.RemoteAddr, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) discoverOIDC(w http.ResponseWriter, r *http.Request) {
	email := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("email")))
	parts := strings.Split(email, "@")
	if len(parts) != 2 || parts[1] == "" {
		writeError(w, 400, "invalid_email", "valid email required")
		return
	}
	if !s.allowAuthenticationAttempt(w, r, "sso-discovery-global", cryptox.Digest("instance"), 300) || !s.allowAuthenticationAttempt(w, r, "sso-discovery-domain", cryptox.Digest(parts[1]), 60) {
		return
	}
	providers, err := s.Store.DiscoverOIDC(r.Context(), parts[1])
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
	if !s.allowAuthenticationAttempt(w, r, "sso-start-global", cryptox.Digest("instance"), 300) || !s.allowAuthenticationAttempt(w, r, "sso-start-provider", cryptox.Digest(id.String()), 60) {
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
	state, err := auth.NewToken()
	if err != nil {
		writeError(w, 500, "state_failed", err.Error())
		return
	}
	verifier := oauth2.GenerateVerifier()
	nonce, err := auth.NewToken()
	if err != nil {
		writeError(w, 500, "nonce_failed", err.Error())
		return
	}
	if err = s.Store.CreateOIDCState(r.Context(), cryptox.Digest(state), provider.ID, verifier, nonce); err != nil {
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
	if stateValue == "" || code == "" {
		writeError(w, 400, "invalid_callback", "state and code are required")
		return
	}
	if !s.allowAuthenticationAttempt(w, r, "sso-callback-global", cryptox.Digest("instance"), 300) {
		return
	}
	if !s.consumeLoginStateCookie(w, r, "oidc", stateValue, http.SameSiteLaxMode) {
		writeError(w, 400, "invalid_state", "state is not bound to this browser")
		return
	}
	providerID, verifierValue, nonce, err := s.Store.ConsumeOIDCState(r.Context(), cryptox.Digest(stateValue))
	if err != nil {
		writeError(w, 400, "invalid_state", "state is invalid or expired")
		return
	}
	provider, err := s.Store.GetOIDCProvider(r.Context(), providerID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	secret, err := s.Box.Decrypt(provider.EncryptedClientSecret, "oidc-client-secret:"+provider.ID.String())
	if err != nil {
		writeError(w, 500, "decryption_failed", err.Error())
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
	if err = idToken.Claims(&claims); err != nil || claims.Subject == "" {
		writeError(w, 401, "invalid_claims", "identity token lacks required claims")
		return
	}
	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(nonce)) != 1 {
		writeError(w, 401, "invalid_nonce", "identity token nonce does not match the login request")
		return
	}
	if claims.EmailVerified != nil && !*claims.EmailVerified {
		writeError(w, 403, "email_unverified", "verified email is required")
		return
	}
	email, domain, ok := claims.loginEmail()
	if !ok {
		writeError(w, 401, "invalid_claims", "identity token lacks a valid email address")
		return
	}
	if !contains(provider.Domains, domain) {
		writeError(w, 403, "domain_not_allowed", "email domain is not allowed")
		return
	}
	userID, err := s.Store.JITOIDCUser(r.Context(), provider, claims.Subject, email, claims.Name)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	token, err := s.newSession(r, userID, &provider.OrganizationID, "oidc")
	if err != nil {
		writeError(w, 500, "session_failed", err.Error())
		return
	}
	s.Store.AuditOrganization(r.Context(), provider.OrganizationID, "auth.oidc.login", "user", userID.String(), r.RemoteAddr, map[string]any{"providerId": provider.ID})
	writeLoginSuccess(w, r, token)
}

func normalizedOIDCIssuer(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	issuer, err := url.Parse(raw)
	if err != nil || issuer.Scheme != "https" || issuer.Hostname() == "" || issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" || issuer.Opaque != "" {
		return "", errors.New("OIDC issuer must be an absolute HTTPS URL without credentials, query, or fragment")
	}
	issuer.Path = strings.TrimRight(issuer.Path, "/")
	issuer.RawPath = strings.TrimRight(issuer.RawPath, "/")
	return issuer.String(), nil
}

func (s *Server) oidcHTTPClient() *http.Client {
	client := s.OIDCHTTPClient
	if client == nil {
		client = &http.Client{Timeout: oidcRequestTimeout}
	}
	secured := *client
	secured.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("OIDC redirects are disabled")
	}
	return &secured
}

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
func (claims oidcIdentityClaims) loginEmail() (string, string, bool) {
	if strings.TrimSpace(claims.Email) != "" {
		return oidcEmail(claims.Email)
	}
	return oidcEmail(claims.PreferredUsername)
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
	return err == nil && subtle.ConstantTimeCompare(plain, []byte(state)) == 1
}

func (s *Server) setExpiredLoginStateCookie(w http.ResponseWriter, name string, sameSite http.SameSite) {
	http.SetCookie(w, &http.Cookie{Name: name, Path: "/v1/auth/", MaxAge: -1, HttpOnly: true, Secure: strings.HasPrefix(strings.ToLower(s.PublicURL), "https://"), SameSite: sameSite})
}

func loginStateCookieName(kind, state string) string {
	digest := cryptox.Digest(state)
	return "dockyard_" + kind + "_state_" + hex.EncodeToString(digest[:8])
}

func oidcEmail(raw string) (string, string, bool) {
	raw = strings.TrimSpace(raw)
	parsed, err := mail.ParseAddress(raw)
	if err != nil || parsed.Address != raw {
		return "", "", false
	}
	parts := strings.SplitN(strings.ToLower(parsed.Address), "@", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return strings.ToLower(parsed.Address), parts[1], true
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if strings.EqualFold(item, want) {
			return true
		}
	}
	return false
}
