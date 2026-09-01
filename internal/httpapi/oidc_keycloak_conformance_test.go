package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/GhaziBenDahmane/Orka/internal/cryptox"
	"github.com/GhaziBenDahmane/Orka/internal/store"
	"github.com/google/uuid"
	xhtml "golang.org/x/net/html"
)

// TestKeycloakOIDCConformance is deliberately opt-in: it talks to a real
// Keycloak process. scripts/ci/test-keycloak-oidc.sh provisions the provider,
// its TLS certificate, realm, client, and test user before running this test.
func TestKeycloakOIDCConformance(t *testing.T) {
	issuer := strings.TrimRight(os.Getenv("DOCKYARD_TEST_KEYCLOAK_ISSUER"), "/")
	if issuer == "" {
		t.Skip("DOCKYARD_TEST_KEYCLOAK_ISSUER is not set")
	}
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("DOCKYARD_TEST_DATABASE_URL is required for Keycloak conformance")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	db, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)
	box, err := cryptox.New(bytes.Repeat([]byte{11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	var existingUserCount int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE lower(email)='conformance@example.test'`).Scan(&existingUserCount); err != nil {
		t.Fatal(err)
	}
	if existingUserCount != 0 {
		t.Fatal("conformance database already contains conformance@example.test; use an isolated database")
	}

	organizationID, ownerID, localDeveloperID := uuid.New(), uuid.New(), uuid.New()
	ownerToken := "keycloak-owner-" + uuid.NewString()
	localDeveloperToken := "keycloak-local-developer-" + uuid.NewString()
	if _, err = db.Pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Keycloak conformance',$2)`, organizationID, "keycloak-"+organizationID.String()); err == nil {
		_, err = db.Pool.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test'),($3,$4,'!test')`, ownerID, ownerID.String()+"@owner.example.test", localDeveloperID, localDeveloperID.String()+"@developer.example.test")
	}
	if err == nil {
		_, err = db.Pool.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner'),($1,$3,'developer')`, organizationID, ownerID, localDeveloperID)
	}
	if err == nil {
		_, err = db.Pool.Exec(ctx, `INSERT INTO sessions(id,user_id,token_hash,expires_at,auth_method) VALUES($1,$2,$3,now()+interval '10 minutes','local'),($4,$5,$6,now()+interval '10 minutes','local')`, uuid.New(), ownerID, cryptox.Digest(ownerToken), uuid.New(), localDeveloperID, cryptox.Digest(localDeveloperToken))
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1 OR id=$2 OR email='conformance@example.test'`, ownerID, localDeveloperID)
	})

	api := &Server{Store: db, Box: box, SessionTTL: time.Hour, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	server := httptest.NewServer(api.Handler())
	defer server.Close()
	api.PublicURL = server.URL

	providerID := createConformanceOIDCProvider(t, server.URL, ownerToken, organizationID, issuer)
	startResponse, err := http.Get(server.URL + "/v1/auth/sso/" + providerID.String() + "/start")
	if err != nil {
		t.Fatal(err)
	}
	stateCookies := startResponse.Cookies()
	var started map[string]string
	decodeResponse(t, startResponse, http.StatusOK, &started)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser := &http.Client{Jar: jar, Timeout: 30 * time.Second, CheckRedirect: func(request *http.Request, _ []*http.Request) error {
		if strings.HasPrefix(request.URL.String(), server.URL+"/v1/auth/sso/callback") {
			return http.ErrUseLastResponse
		}
		return nil
	}}
	loginPage, err := browser.Get(started["url"])
	if err != nil {
		t.Fatal(err)
	}
	action := keycloakLoginAction(t, loginPage)
	loginResponse, err := browser.PostForm(action, url.Values{
		"username":     {"conformance"},
		"password":     {"correct-horse-battery-staple"},
		"credentialId": {""},
	})
	if err != nil {
		t.Fatal(err)
	}
	loginResponse.Body.Close()
	callbackURL := loginResponse.Header.Get("Location")
	if loginResponse.StatusCode/100 != 3 || !strings.HasPrefix(callbackURL, server.URL+"/v1/auth/sso/callback") {
		t.Fatalf("Keycloak login status=%d location=%q", loginResponse.StatusCode, callbackURL)
	}

	callbackRequest, _ := http.NewRequest(http.MethodGet, callbackURL, nil)
	for _, cookie := range stateCookies {
		callbackRequest.AddCookie(cookie)
	}
	callbackResponse, err := http.DefaultClient.Do(callbackRequest)
	if err != nil {
		t.Fatal(err)
	}
	var login struct {
		Token string `json:"token"`
	}
	decodeResponse(t, callbackResponse, http.StatusOK, &login)
	if login.Token == "" {
		t.Fatal("OIDC callback did not create a session")
	}
	req, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+login.Token)
	req.Header.Set("X-Organization-ID", organizationID.String())
	meResponse, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var me store.Principal
	decodeResponse(t, meResponse, http.StatusOK, &me)
	if me.Email != "conformance@example.test" || me.OrganizationID != organizationID || me.Role != "developer" {
		t.Fatalf("unexpected JIT principal: %#v", me)
	}
	otherOrganizationID := uuid.New()
	if _, err = db.Pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Other Keycloak tenant',$2)`, otherOrganizationID, "other-keycloak-"+otherOrganizationID.String()); err == nil {
		_, err = db.Pool.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'admin')`, otherOrganizationID, me.UserID)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, otherOrganizationID)
	})
	assertConformanceSession(t, server.URL, otherOrganizationID, login.Token, http.StatusUnauthorized, "")
	localSessionID, err := db.CreateSessionWithMetadata(ctx, me.UserID, nil, nil, cryptox.Digest("other-tenant-local-session"), time.Now().Add(time.Hour), "local", "local-agent", "127.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	sessionsRequest, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/sessions", nil)
	sessionsRequest.Header.Set("Authorization", "Bearer "+login.Token)
	sessionsRequest.Header.Set("X-Organization-ID", organizationID.String())
	sessionsResponse, err := http.DefaultClient.Do(sessionsRequest)
	if err != nil {
		t.Fatal(err)
	}
	var sessions struct {
		Items []store.Session `json:"items"`
	}
	decodeResponse(t, sessionsResponse, http.StatusOK, &sessions)
	if len(sessions.Items) != 1 || !sessions.Items[0].Current || sessions.Items[0].OrganizationID == nil || *sessions.Items[0].OrganizationID != organizationID {
		t.Fatalf("federated session list escaped organization scope: %#v", sessions.Items)
	}
	revokeRequest, _ := http.NewRequest(http.MethodDelete, server.URL+"/v1/sessions/"+localSessionID.String(), nil)
	revokeRequest.Header.Set("Authorization", "Bearer "+login.Token)
	revokeRequest.Header.Set("X-Organization-ID", organizationID.String())
	revokeResponse, err := http.DefaultClient.Do(revokeRequest)
	if err != nil {
		t.Fatal(err)
	}
	revokeResponse.Body.Close()
	if revokeResponse.StatusCode != http.StatusNotFound {
		t.Fatalf("federated session revoked an account-wide local session: status=%d", revokeResponse.StatusCode)
	}

	settingsBody, _ := json.Marshal(map[string]bool{"requireSso": true})
	settingsRequest, _ := http.NewRequest(http.MethodPut, server.URL+"/v1/sso/settings", bytes.NewReader(settingsBody))
	settingsRequest.Header.Set("Authorization", "Bearer "+ownerToken)
	settingsRequest.Header.Set("X-Organization-ID", organizationID.String())
	settingsRequest.Header.Set("Content-Type", "application/json")
	settingsResponse, err := http.DefaultClient.Do(settingsRequest)
	if err != nil {
		t.Fatal(err)
	}
	var settings store.OrganizationAuthSettings
	decodeResponse(t, settingsResponse, http.StatusOK, &settings)
	if !settings.RequireSSO {
		t.Fatal("mandatory SSO was not enabled")
	}

	assertConformanceSession(t, server.URL, organizationID, ownerToken, http.StatusOK, "owner")
	assertConformanceSession(t, server.URL, organizationID, localDeveloperToken, http.StatusUnauthorized, "")
	assertConformanceSession(t, server.URL, organizationID, login.Token, http.StatusOK, "developer")

	replayResponse, err := http.Get(callbackURL)
	if err != nil {
		t.Fatal(err)
	}
	replayResponse.Body.Close()
	if replayResponse.StatusCode != http.StatusBadRequest {
		t.Fatalf("replayed callback status=%d, want 400", replayResponse.StatusCode)
	}
}

func assertConformanceSession(t *testing.T, baseURL string, organizationID uuid.UUID, token string, expectedStatus int, expectedRole string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, baseURL+"/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Organization-ID", organizationID.String())
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if expectedStatus != http.StatusOK {
		defer response.Body.Close()
		if response.StatusCode != expectedStatus {
			data, _ := io.ReadAll(response.Body)
			t.Fatalf("session status=%d, want %d: %s", response.StatusCode, expectedStatus, data)
		}
		return
	}
	var principal store.Principal
	decodeResponse(t, response, expectedStatus, &principal)
	if principal.OrganizationID != organizationID || principal.Role != expectedRole {
		t.Fatalf("session principal = %#v, want organization %s role %s", principal, organizationID, expectedRole)
	}
}

func createConformanceOIDCProvider(t *testing.T, baseURL, token string, organizationID uuid.UUID, issuer string) uuid.UUID {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"name": "Keycloak", "issuer": issuer, "clientId": "dockyard-conformance",
		"clientSecret": "dockyard-conformance-secret", "domains": []string{"example.test"},
		"scopes": []string{"openid", "profile", "email"}, "defaultRole": "developer",
	})
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/v1/sso/oidc-providers", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Organization-ID", organizationID.String())
	req.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var provider store.OIDCProvider
	decodeResponse(t, response, http.StatusCreated, &provider)
	return provider.ID
}

func keycloakLoginAction(t *testing.T, response *http.Response) string {
	t.Helper()
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(response.Body)
		t.Fatalf("Keycloak authorization status=%d: %s", response.StatusCode, data)
	}
	document, err := xhtml.Parse(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		t.Fatal(err)
	}
	var visit func(*xhtml.Node) string
	visit = func(node *xhtml.Node) string {
		if node.Type == xhtml.ElementNode && node.Data == "form" {
			var id, action string
			for _, attribute := range node.Attr {
				if attribute.Key == "id" {
					id = attribute.Val
				}
				if attribute.Key == "action" {
					action = attribute.Val
				}
			}
			if id == "kc-form-login" {
				return action
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			if action := visit(child); action != "" {
				return action
			}
		}
		return ""
	}
	if action := visit(document); action != "" {
		return action
	}
	t.Fatal("Keycloak response did not contain the login form")
	return ""
}

func decodeResponse(t *testing.T, response *http.Response, expectedStatus int, target any) {
	t.Helper()
	defer response.Body.Close()
	if response.StatusCode != expectedStatus {
		data, _ := io.ReadAll(response.Body)
		t.Fatalf("status=%d, want %d: %s", response.StatusCode, expectedStatus, data)
	}
	if err := json.NewDecoder(response.Body).Decode(target); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}
