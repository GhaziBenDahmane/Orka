package httpapi

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bendahma/dokploy-go/internal/cryptox"
	"github.com/bendahma/dokploy-go/internal/store"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/google/uuid"
	dsig "github.com/russellhaering/goxmldsig"
)

type fixedServiceProviderMetadata struct{ metadata *saml.EntityDescriptor }

func (p fixedServiceProviderMetadata) GetServiceProvider(_ *http.Request, entityID string) (*saml.EntityDescriptor, error) {
	if entityID == p.metadata.EntityID {
		return p.metadata, nil
	}
	return nil, os.ErrNotExist
}

func TestSAMLProviderCreationMetadataAndStart(t *testing.T) {
	databaseURL := os.Getenv("DOCKYARD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DOCKYARD_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)
	box, err := cryptox.New(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}

	orgID, userID := uuid.New(), uuid.New()
	token := "saml-session-" + uuid.NewString()
	_, err = db.Pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'SAML API',$2)`, orgID, "saml-api-"+orgID.String())
	if err == nil {
		_, err = db.Pool.Exec(ctx, `INSERT INTO users(id,email,password_hash) VALUES($1,$2,'!test')`, userID, userID.String()+"@example.test")
	}
	if err == nil {
		_, err = db.Pool.Exec(ctx, `INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'owner')`, orgID, userID)
	}
	if err == nil {
		_, err = db.Pool.Exec(ctx, `INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '5 minutes')`, uuid.New(), userID, cryptox.Digest(token))
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, orgID)
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})

	idpKey, idpCertificatePEM, _, err := newSAMLCertificate("Test IdP")
	if err != nil {
		t.Fatal(err)
	}
	idpCertificateBlock, _ := pem.Decode(idpCertificatePEM)
	idpCertificate, err := x509.ParseCertificate(idpCertificateBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	idpMetadataURL, _ := url.Parse("https://idp.example.test/metadata")
	idpSSOURL, _ := url.Parse("https://idp.example.test/sso")
	idp := saml.IdentityProvider{Key: idpKey, Signer: idpKey, Certificate: idpCertificate, MetadataURL: *idpMetadataURL, SSOURL: *idpSSOURL, SignatureMethod: dsig.RSASHA256SignatureMethod}
	metadataXML, err := xml.Marshal(idp.Metadata())
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer((&Server{Store: db, Box: box, PublicURL: "https://dockyard.example.test", Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler())
	defer server.Close()
	body, _ := json.Marshal(map[string]any{"name": "workforce", "metadataXml": string(metadataXML), "domains": []string{"example.test"}, "emailAttribute": "mail", "nameAttribute": "displayName", "defaultRole": "developer", "allowIdpInitiated": true})
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/sso/saml-providers", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Organization-ID", orgID.String())
	req.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d: %s", response.StatusCode, data)
	}
	if strings.Contains(string(data), "PRIVATE KEY") || strings.Contains(string(data), "metadataXml") {
		t.Fatalf("provider response leaked configuration: %s", data)
	}
	var provider store.SAMLProvider
	if err = json.Unmarshal(data, &provider); err != nil {
		t.Fatal(err)
	}
	var encryptedKey string
	if err = db.Pool.QueryRow(ctx, `SELECT encrypted_private_key FROM saml_providers WHERE id=$1`, provider.ID).Scan(&encryptedKey); err != nil {
		t.Fatal(err)
	}
	if encryptedKey == "" || strings.Contains(encryptedKey, "PRIVATE KEY") {
		t.Fatal("SAML private key was not encrypted")
	}
	provider, err = db.UpdateSAMLProvider(ctx, orgID, store.SAMLProvider{ID: provider.ID, Name: "workforce-updated", IDPMetadata: string(metadataXML), Domains: []string{"example.test"}, EmailAttribute: "mail", NameAttribute: "displayName", DefaultRole: "developer", AllowIDPInitiated: true})
	if err != nil || provider.Name != "workforce-updated" {
		t.Fatalf("SAML provider update = %#v, %v", provider, err)
	}
	var preservedKey string
	if err = db.Pool.QueryRow(ctx, `SELECT encrypted_private_key FROM saml_providers WHERE id=$1`, provider.ID).Scan(&preservedKey); err != nil || preservedKey != encryptedKey {
		t.Fatalf("SAML update replaced the SP key: %v", err)
	}

	response, err = http.Get(server.URL + "/v1/auth/saml/" + provider.ID.String() + "/metadata")
	if err != nil {
		t.Fatal(err)
	}
	data, _ = io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !bytes.Contains(data, []byte(`AuthnRequestsSigned="true"`)) || !bytes.Contains(data, []byte("dockyard.example.test")) {
		t.Fatalf("SP metadata status = %d: %s", response.StatusCode, data)
	}
	spMetadata, err := samlsp.ParseMetadata(data)
	if err != nil {
		t.Fatal(err)
	}
	idp.ServiceProviderProvider = fixedServiceProviderMetadata{metadata: spMetadata}

	response, err = http.Get(server.URL + "/v1/auth/saml/" + provider.ID.String() + "/start")
	if err != nil {
		t.Fatal(err)
	}
	stateCookies := response.Cookies()
	data, _ = io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("start status = %d: %s", response.StatusCode, data)
	}
	var started map[string]string
	if err = json.Unmarshal(data, &started); err != nil {
		t.Fatal(err)
	}
	redirect, err := url.Parse(started["url"])
	if err != nil || redirect.Host != "idp.example.test" || redirect.Query().Get("SAMLRequest") == "" || redirect.Query().Get("RelayState") == "" || redirect.Query().Get("Signature") == "" {
		t.Fatalf("SAML redirect = %q, err = %v", started["url"], err)
	}

	authnHTTPRequest := &http.Request{Method: http.MethodGet, URL: redirect, RemoteAddr: "127.0.0.1:1234"}
	authnRequest, err := saml.NewIdpAuthnRequest(&idp, authnHTTPRequest)
	if err != nil {
		t.Fatal(err)
	}
	if err = authnRequest.Validate(); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err = (saml.DefaultAssertionMaker{}).MakeAssertion(authnRequest, &saml.Session{ID: uuid.NewString(), CreateTime: now, ExpireTime: now.Add(time.Hour), NameID: "person@example.test", NameIDFormat: string(saml.EmailAddressNameIDFormat), UserEmail: "person@example.test", UserCommonName: "Test Person", CustomAttributes: []saml.Attribute{{Name: "mail", Values: []saml.AttributeValue{{Type: "xs:string", Value: "person@example.test"}}}, {Name: "displayName", Values: []saml.AttributeValue{{Type: "xs:string", Value: "Test Person"}}}}}); err != nil {
		t.Fatal(err)
	}
	if err = authnRequest.MakeAssertionEl(); err != nil {
		t.Fatal(err)
	}
	form, err := authnRequest.PostBinding()
	if err != nil {
		t.Fatal(err)
	}
	callbackURL, _ := url.Parse(form.URL)
	postValues := url.Values{"SAMLResponse": {form.SAMLResponse}, "RelayState": {form.RelayState}}
	request, err := http.NewRequest(http.MethodPost, server.URL+callbackURL.Path, strings.NewReader(postValues.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range stateCookies {
		request.AddCookie(cookie)
	}
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	data, _ = io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !bytes.Contains(data, []byte(`"token"`)) {
		t.Fatalf("callback status = %d: %s", response.StatusCode, data)
	}

	response, err = http.PostForm(server.URL+callbackURL.Path, postValues)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("replayed callback status = %d, want 400", response.StatusCode)
	}
}
