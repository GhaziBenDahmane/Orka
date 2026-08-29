package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
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

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/google/uuid"
	xhtml "golang.org/x/net/html"
)

// TestKeycloakSAMLConformance is deliberately opt-in. The conformance script
// provisions a real TLS Keycloak realm, then this test imports Dockyard's
// generated SP metadata so ephemeral test-server URLs remain exact.
func TestKeycloakSAMLConformance(t *testing.T) {
	issuer := strings.TrimRight(os.Getenv("DOCKYARD_TEST_KEYCLOAK_ISSUER"), "/")
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if issuer == "" {
		t.Skip("DOCKYARD_TEST_KEYCLOAK_ISSUER is not set")
	}
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
	box, err := cryptox.New(bytes.Repeat([]byte{12}, 32))
	if err != nil {
		t.Fatal(err)
	}

	organizationID, ownerID := uuid.New(), uuid.New()
	ownerToken := "keycloak-saml-owner-" + uuid.NewString()
	if _, err = db.Pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'Keycloak SAML conformance',$2)`, organizationID, "keycloak-saml-"+organizationID.String()); err == nil {
		_, err = db.Pool.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, ownerID, ownerID.String()+"@owner.example.test")
	}
	if err == nil {
		_, err = db.Pool.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')`, organizationID, ownerID)
	}
	if err == nil {
		_, err = db.Pool.Exec(ctx, `INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '10 minutes')`, uuid.New(), ownerID, cryptox.Digest(ownerToken))
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, organizationID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1 OR email='conformance@example.test'`, ownerID)
	})

	api := &Server{Store: db, Box: box, SessionTTL: time.Hour, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	server := httptest.NewServer(api.Handler())
	defer server.Close()
	api.PublicURL = server.URL

	idpMetadata := keycloakSAMLMetadata(t, issuer)
	providerID := createConformanceSAMLProvider(t, server.URL, ownerToken, organizationID, idpMetadata)
	spMetadata := fetchConformanceSPMetadata(t, server.URL, providerID)
	adminToken := keycloakAdminToken(t, issuer)
	clientID := importKeycloakSAMLClient(t, issuer, adminToken, spMetadata)
	t.Cleanup(func() { deleteKeycloakClient(t, issuer, adminToken, clientID) })

	startResponse, err := http.Get(server.URL + "/v1/auth/saml/" + providerID.String() + "/start")
	if err != nil {
		t.Fatal(err)
	}
	stateCookies := startResponse.Cookies()
	var started map[string]string
	decodeResponse(t, startResponse, http.StatusOK, &started)
	if !strings.Contains(started["url"], "SAMLRequest=") || !strings.Contains(started["url"], "Signature=") {
		t.Fatalf("SAML authorization URL is not signed: %q", started["url"])
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	loginPage, err := browser.Get(started["url"])
	if err != nil {
		t.Fatal(err)
	}
	loginAction := keycloakLoginAction(t, loginPage)
	loginResponse, err := browser.PostForm(loginAction, url.Values{"username": {"conformance"}, "password": {"correct-horse-battery-staple"}, "credentialId": {""}})
	if err != nil {
		t.Fatal(err)
	}
	acsURL, samlValues := keycloakSAMLPost(t, loginResponse)
	if !strings.HasPrefix(acsURL, server.URL+"/v1/auth/saml/") || samlValues.Get("SAMLResponse") == "" || samlValues.Get("RelayState") == "" {
		t.Fatalf("unexpected Keycloak SAML form action=%q values=%v", acsURL, samlValues)
	}
	assertSignedSAMLResponse(t, samlValues.Get("SAMLResponse"))

	request, _ := http.NewRequest(http.MethodPost, acsURL, strings.NewReader(samlValues.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range stateCookies {
		request.AddCookie(cookie)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var login struct {
		Token string `json:"token"`
	}
	decodeResponse(t, response, http.StatusOK, &login)
	if login.Token == "" {
		t.Fatal("SAML callback did not create a session")
	}
	meRequest, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/me", nil)
	meRequest.Header.Set("Authorization", "Bearer "+login.Token)
	meRequest.Header.Set("X-Organization-ID", organizationID.String())
	meResponse, err := http.DefaultClient.Do(meRequest)
	if err != nil {
		t.Fatal(err)
	}
	var me store.Principal
	decodeResponse(t, meResponse, http.StatusOK, &me)
	if me.Email != "conformance@example.test" || me.OrganizationID != organizationID || me.Role != "developer" {
		t.Fatalf("unexpected SAML JIT principal: %#v", me)
	}

	replayResponse, err := http.PostForm(acsURL, url.Values{"SAMLResponse": {samlValues.Get("SAMLResponse")}})
	if err != nil {
		t.Fatal(err)
	}
	var replayError struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	decodeResponse(t, replayResponse, http.StatusUnauthorized, &replayError)
	if replayError.Error.Code != "saml_replay" {
		t.Fatalf("replayed SAML callback code=%q, want saml_replay", replayError.Error.Code)
	}

	idpJar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	idpBrowser := &http.Client{Jar: idpJar, Timeout: 30 * time.Second}
	idpLoginPage, err := idpBrowser.Get(issuer + "/protocol/saml/clients/dockyard-conformance")
	if err != nil {
		t.Fatal(err)
	}
	idpLoginAction := keycloakLoginAction(t, idpLoginPage)
	idpLoginResponse, err := idpBrowser.PostForm(idpLoginAction, url.Values{"username": {"conformance"}, "password": {"correct-horse-battery-staple"}, "credentialId": {""}})
	if err != nil {
		t.Fatal(err)
	}
	idpACSURL, idpValues := keycloakSAMLPost(t, idpLoginResponse)
	if !strings.HasPrefix(idpACSURL, server.URL+"/v1/auth/saml/") || idpValues.Get("SAMLResponse") == "" || idpValues.Get("RelayState") != "" {
		t.Fatalf("unexpected IdP-initiated SAML form action=%q values=%v", idpACSURL, idpValues)
	}
	assertSignedSAMLResponse(t, idpValues.Get("SAMLResponse"))
	idpResponse, err := http.PostForm(idpACSURL, idpValues)
	if err != nil {
		t.Fatal(err)
	}
	var idpLogin struct {
		Token string `json:"token"`
	}
	decodeResponse(t, idpResponse, http.StatusOK, &idpLogin)
	if idpLogin.Token == "" {
		t.Fatal("IdP-initiated SAML callback did not create a session")
	}
	assertConformanceSession(t, server.URL, organizationID, idpLogin.Token, http.StatusOK, "developer")

	idpReplayResponse, err := http.PostForm(idpACSURL, idpValues)
	if err != nil {
		t.Fatal(err)
	}
	decodeResponse(t, idpReplayResponse, http.StatusUnauthorized, &replayError)
	if replayError.Error.Code != "saml_replay" {
		t.Fatalf("replayed IdP-initiated SAML callback code=%q, want saml_replay", replayError.Error.Code)
	}
}

func keycloakSAMLMetadata(t *testing.T, issuer string) []byte {
	t.Helper()
	response, err := http.Get(issuer + "/protocol/saml/descriptor")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("Keycloak SAML metadata status=%d err=%v: %s", response.StatusCode, err, data)
	}
	return data
}

func createConformanceSAMLProvider(t *testing.T, baseURL, token string, organizationID uuid.UUID, metadata []byte) uuid.UUID {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"name": "Keycloak SAML", "metadataXml": string(metadata), "domains": []string{"example.test"}, "emailAttribute": "email", "nameAttribute": "displayName", "defaultRole": "developer", "allowIdpInitiated": true})
	request, _ := http.NewRequest(http.MethodPost, baseURL+"/v1/sso/saml-providers", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-Organization-ID", organizationID.String())
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var provider store.SAMLProvider
	decodeResponse(t, response, http.StatusCreated, &provider)
	return provider.ID
}

func fetchConformanceSPMetadata(t *testing.T, baseURL string, providerID uuid.UUID) []byte {
	t.Helper()
	response, err := http.Get(baseURL + "/v1/auth/saml/" + providerID.String() + "/metadata")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("Dockyard SAML metadata status=%d err=%v: %s", response.StatusCode, err, data)
	}
	return data
}

func keycloakAdminToken(t *testing.T, issuer string) string {
	t.Helper()
	endpoint := strings.Split(issuer, "/realms/")[0] + "/realms/master/protocol/openid-connect/token"
	response, err := http.PostForm(endpoint, url.Values{"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {"admin"}, "password": {"admin"}})
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		AccessToken string `json:"access_token"`
	}
	decodeResponse(t, response, http.StatusOK, &result)
	if result.AccessToken == "" {
		t.Fatal("Keycloak admin token was empty")
	}
	return result.AccessToken
}

func importKeycloakSAMLClient(t *testing.T, issuer, token string, metadata []byte) string {
	t.Helper()
	adminBase := strings.Split(issuer, "/realms/")[0] + "/admin/realms/dockyard-conformance"
	request, _ := http.NewRequest(http.MethodPost, adminBase+"/client-description-converter", bytes.NewReader(metadata))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/xml")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var client map[string]any
	decodeResponse(t, response, http.StatusOK, &client)
	client["enabled"] = true
	attributes, _ := client["attributes"].(map[string]any)
	if attributes == nil {
		attributes = map[string]any{}
	}
	attributes["saml_idp_initiated_sso_url_name"] = "dockyard-conformance"
	client["attributes"] = attributes
	client["protocolMappers"] = []map[string]any{
		{"name": "email", "protocol": "saml", "protocolMapper": "saml-user-property-mapper", "consentRequired": false, "config": map[string]string{"attribute.name": "email", "attribute.nameformat": "Basic", "user.attribute": "email"}},
		{"name": "displayName", "protocol": "saml", "protocolMapper": "saml-user-property-mapper", "consentRequired": false, "config": map[string]string{"attribute.name": "displayName", "attribute.nameformat": "Basic", "user.attribute": "firstName"}},
	}
	body, _ := json.Marshal(client)
	request, _ = http.NewRequest(http.MethodPost, adminBase+"/clients", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		data, _ := io.ReadAll(response.Body)
		t.Fatalf("create Keycloak SAML client status=%d: %s", response.StatusCode, data)
	}
	location := response.Header.Get("Location")
	parts := strings.Split(strings.TrimRight(location, "/"), "/")
	if location == "" || len(parts) == 0 || parts[len(parts)-1] == "" {
		t.Fatalf("Keycloak client response omitted location: %q", location)
	}
	return parts[len(parts)-1]
}

func deleteKeycloakClient(t *testing.T, issuer, token, clientID string) {
	t.Helper()
	endpoint := strings.Split(issuer, "/realms/")[0] + "/admin/realms/dockyard-conformance/clients/" + url.PathEscape(clientID)
	request, _ := http.NewRequest(http.MethodDelete, endpoint, nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Errorf("delete Keycloak SAML client: %v", err)
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Errorf("delete Keycloak SAML client status=%d", response.StatusCode)
	}
}

func keycloakSAMLPost(t *testing.T, response *http.Response) (string, url.Values) {
	t.Helper()
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(response.Body)
		t.Fatalf("Keycloak SAML response status=%d: %s", response.StatusCode, data)
	}
	document, err := xhtml.Parse(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		t.Fatal(err)
	}
	action, values := "", url.Values{}
	var visit func(*xhtml.Node)
	visit = func(node *xhtml.Node) {
		if node.Type == xhtml.ElementNode && node.Data == "form" {
			for _, attribute := range node.Attr {
				if attribute.Key == "action" {
					action = attribute.Val
				}
			}
		}
		if node.Type == xhtml.ElementNode && node.Data == "input" {
			name, value := "", ""
			for _, attribute := range node.Attr {
				switch attribute.Key {
				case "name":
					name = attribute.Val
				case "value":
					value = attribute.Val
				}
			}
			if name != "" {
				values.Set(name, value)
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(document)
	if action == "" {
		t.Fatal("Keycloak SAML response omitted POST form")
	}
	return action, values
}

func assertSignedSAMLResponse(t *testing.T, encoded string) {
	t.Helper()
	payload, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode Keycloak SAML response: %v", err)
	}
	decoder := xml.NewDecoder(bytes.NewReader(payload))
	for {
		token, decodeErr := decoder.Token()
		if decodeErr == io.EOF {
			break
		}
		if decodeErr != nil {
			t.Fatalf("parse Keycloak SAML response: %v", decodeErr)
		}
		if start, ok := token.(xml.StartElement); ok && start.Name.Local == "Signature" {
			return
		}
	}
	t.Fatal("Keycloak SAML response was not signed")
}
