package tfprovider

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	resourceschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestProviderMetadataSchemaAndResources(t *testing.T) {
	instance := New("1.2.3")()
	var metadata provider.MetadataResponse
	instance.Metadata(context.Background(), provider.MetadataRequest{}, &metadata)
	if metadata.TypeName != "dockyard" || metadata.Version != "1.2.3" {
		t.Fatalf("metadata = %#v", metadata)
	}
	var schemaResponse provider.SchemaResponse
	instance.Schema(context.Background(), provider.SchemaRequest{}, &schemaResponse)
	if schemaResponse.Diagnostics.HasError() || len(schemaResponse.Schema.GetAttributes()) != 3 {
		t.Fatalf("provider schema diagnostics = %v", schemaResponse.Diagnostics)
	}
	if len(instance.Resources(context.Background())) != 17 {
		t.Fatal("provider must expose the core hierarchy, credentials, backup policies, template repositories, and SSO resources")
	}
	resourceTypes := make([]string, 0, len(instance.Resources(context.Background())))
	for _, factory := range instance.Resources(context.Background()) {
		var resourceMetadata resource.MetadataResponse
		factory().Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "dockyard"}, &resourceMetadata)
		resourceTypes = append(resourceTypes, resourceMetadata.TypeName)
		var response resource.SchemaResponse
		factory().Schema(context.Background(), resource.SchemaRequest{}, &response)
		if diagnostics := response.Schema.ValidateImplementation(context.Background()); diagnostics.HasError() {
			t.Fatalf("invalid resource schema: %v", diagnostics)
		}
	}
	if !slices.Contains(resourceTypes, "dockyard_template_repository") {
		t.Fatalf("provider resource types = %v", resourceTypes)
	}
	if !slices.Contains(resourceTypes, "dockyard_oidc_provider") {
		t.Fatalf("provider resource types = %v", resourceTypes)
	}
	if !slices.Contains(resourceTypes, "dockyard_saml_provider") {
		t.Fatalf("provider resource types = %v", resourceTypes)
	}
	if !slices.Contains(resourceTypes, "dockyard_scim_token") {
		t.Fatalf("provider resource types = %v", resourceTypes)
	}
	if !slices.Contains(resourceTypes, "dockyard_access_grant") {
		t.Fatalf("provider resource types = %v", resourceTypes)
	}
	if !slices.Contains(resourceTypes, "dockyard_resource_policy") {
		t.Fatalf("provider resource types = %v", resourceTypes)
	}
	if !slices.Contains(resourceTypes, "dockyard_cluster") {
		t.Fatalf("provider resource types = %v", resourceTypes)
	}
	if !slices.Contains(resourceTypes, "dockyard_auth_settings") {
		t.Fatalf("provider resource types = %v", resourceTypes)
	}
}

func TestTemplateRepositoryResponsePreservesOptionalConfiguration(t *testing.T) {
	model := templateRepositoryModel{CatalogPath: types.StringNull(), TrustedPublicKey: types.StringNull(), CredentialID: types.StringValue("")}
	setTemplateRepository(&model, templateRepositoryResponse{ID: "repository-id", Name: "Community", Slug: "community", RepositoryURL: "https://github.com/acme/templates", GitRef: "main", SyncIntervalSeconds: 3600})
	if !model.CatalogPath.IsNull() || !model.TrustedPublicKey.IsNull() || model.CredentialID.IsNull() || model.CredentialID.ValueString() != "" {
		t.Fatalf("optional repository state was not preserved: %#v", model)
	}
}

func TestTemplateRepositoryInputsSeparateIdentityFromSettings(t *testing.T) {
	model := templateRepositoryModel{
		Name: types.StringValue("Community"), Slug: types.StringValue("community"), RepositoryURL: types.StringValue("https://github.com/acme/templates"),
		GitRef: types.StringValue("main"), CatalogPath: types.StringValue("catalog"), TrustedPublicKey: types.StringValue("public-key"),
		RequireSignature: types.BoolValue(true), CredentialID: types.StringValue("credential-id"), SyncIntervalSeconds: types.Int64Value(3600),
	}
	created := templateRepositoryInput(model, true)
	updated := templateRepositoryInput(model, false)
	if created["repositoryUrl"] != "https://github.com/acme/templates" || created["catalogPath"] != "catalog" {
		t.Fatalf("create input = %#v", created)
	}
	if _, exists := updated["repositoryUrl"]; exists || updated["trustedPublicKey"] != "public-key" || updated["syncIntervalSeconds"] != int64(3600) {
		t.Fatalf("update input = %#v", updated)
	}
}

func TestOIDCProviderInputAndSecretRetention(t *testing.T) {
	model := oidcProviderModel{
		Name: types.StringValue("Workforce"), Issuer: types.StringValue("https://identity.example.com"), ClientID: types.StringValue("dockyard"), ClientSecret: types.StringValue("state-secret"),
		Domains: stringSet([]string{"example.com"}), Scopes: stringSet([]string{"openid", "email"}), DefaultRole: types.StringValue("developer"), Enabled: types.BoolValue(true),
	}
	var diagnostics diag.Diagnostics
	input := oidcProviderInput(context.Background(), model, "rotated-secret", &diagnostics)
	if diagnostics.HasError() || input["clientSecret"] != "rotated-secret" || input["defaultRole"] != "developer" {
		t.Fatalf("OIDC input=%#v diagnostics=%v", input, diagnostics)
	}
	setOIDCProvider(&model, oidcProviderResponse{ID: "provider-id", Name: "Workforce", Issuer: "https://identity.example.com", ClientID: "dockyard", Domains: []string{"example.com"}, Scopes: []string{"openid", "email"}, DefaultRole: "developer", Enabled: true})
	if model.ClientSecret.ValueString() != "state-secret" || model.Domains.IsNull() || model.Scopes.IsNull() {
		t.Fatalf("OIDC state did not retain its write-only secret: %#v", model)
	}
	if secret := oidcClientSecretForUpdate(types.StringValue("state-secret"), types.StringValue("state-secret")); secret != "" {
		t.Fatalf("unchanged OIDC secret would be resent: %q", secret)
	}
	if secret := oidcClientSecretForUpdate(types.StringValue("rotated-secret"), types.StringValue("state-secret")); secret != "rotated-secret" {
		t.Fatalf("rotated OIDC secret = %q", secret)
	}
}

func TestOIDCProviderClientSecretIsSensitive(t *testing.T) {
	var response resource.SchemaResponse
	newOIDCProviderResource().Schema(context.Background(), resource.SchemaRequest{}, &response)
	secret, ok := response.Schema.Attributes["client_secret"].(resourceschema.StringAttribute)
	if !ok || !secret.Sensitive || !secret.Required {
		t.Fatalf("client_secret schema = %#v", response.Schema.Attributes["client_secret"])
	}
}

func TestSAMLProviderMetadataIsSensitiveAndRetained(t *testing.T) {
	var schemaResponse resource.SchemaResponse
	newSAMLProviderResource().Schema(context.Background(), resource.SchemaRequest{}, &schemaResponse)
	metadata, ok := schemaResponse.Schema.Attributes["metadata_xml"].(resourceschema.StringAttribute)
	if !ok || !metadata.Sensitive || !metadata.Required {
		t.Fatalf("metadata_xml schema = %#v", schemaResponse.Schema.Attributes["metadata_xml"])
	}
	model := samlProviderModel{
		Name: types.StringValue("Workforce"), MetadataXML: types.StringValue("<EntityDescriptor/>"), Domains: stringSet([]string{"example.com"}),
		EmailAttribute: types.StringValue("email"), NameAttribute: types.StringValue("name"), DefaultRole: types.StringValue("developer"), AllowIDPInitiated: types.BoolValue(true),
	}
	var diagnostics diag.Diagnostics
	input := samlProviderInput(context.Background(), model, &diagnostics)
	if diagnostics.HasError() || input["metadataXml"] != "<EntityDescriptor/>" || input["allowIdpInitiated"] != true {
		t.Fatalf("SAML input=%#v diagnostics=%v", input, diagnostics)
	}
	setSAMLProvider(&model, samlProviderResponse{ID: "provider-id", Name: "Workforce", Domains: []string{"example.com"}, EmailAttribute: "email", NameAttribute: "name", DefaultRole: "developer", Enabled: true})
	if model.MetadataXML.ValueString() != "<EntityDescriptor/>" || model.Domains.IsNull() || !model.SPCertificateNotAfter.IsNull() {
		t.Fatalf("SAML state did not retain write-only metadata: %#v", model)
	}
}

func TestSCIMTokenSecretRetentionAndExpiry(t *testing.T) {
	var schemaResponse resource.SchemaResponse
	newSCIMTokenResource().Schema(context.Background(), resource.SchemaRequest{}, &schemaResponse)
	token, ok := schemaResponse.Schema.Attributes["token"].(resourceschema.StringAttribute)
	if !ok || !token.Sensitive || !token.Computed {
		t.Fatalf("token schema = %#v", schemaResponse.Schema.Attributes["token"])
	}
	now := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	model := scimTokenModel{Token: types.StringValue("one-time-secret"), BaseURL: types.StringValue("https://dockyard.example.com/scim/v2")}
	item := scimTokenResponse{ID: "token-id", Name: "Workforce", DefaultRole: "developer", CreatedAt: now.Add(-time.Hour).Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano)}
	setSCIMToken(&model, item)
	if model.Token.ValueString() != "one-time-secret" || model.BaseURL.ValueString() != "https://dockyard.example.com/scim/v2" {
		t.Fatalf("SCIM state did not retain its write-only values: %#v", model)
	}
	if usable, err := usableSCIMToken(item, now, 0); err != nil || !usable {
		t.Fatalf("active SCIM token usable=%v err=%v", usable, err)
	}
	if usable, err := usableSCIMToken(item, now, 1); err != nil || usable {
		t.Fatalf("SCIM token inside renewal window usable=%v err=%v", usable, err)
	}
	item.ExpiresAt = now.Format(time.RFC3339Nano)
	if usable, err := usableSCIMToken(item, now, 0); err != nil || usable {
		t.Fatalf("expired SCIM token usable=%v err=%v", usable, err)
	}
	revoked := now.Add(-time.Minute).Format(time.RFC3339Nano)
	item.ExpiresAt, item.RevokedAt = now.Add(time.Hour).Format(time.RFC3339Nano), &revoked
	if usable, err := usableSCIMToken(item, now, 0); err != nil || usable {
		t.Fatalf("revoked SCIM token usable=%v err=%v", usable, err)
	}
	for _, values := range [][2]int64{{0, 0}, {366, 0}, {90, -1}, {90, 90}} {
		if _, err := validateSCIMTokenWindow(values[0], values[1]); err == nil {
			t.Errorf("SCIM token window %v accepted", values)
		}
	}
	if _, err := validateSCIMTokenWindow(90, 7); err != nil {
		t.Fatalf("valid SCIM token window rejected: %v", err)
	}
}

func TestAccessGrantIdentityAndImport(t *testing.T) {
	scopeID := "0cc565f8-6b40-4bd7-a6ff-f2f00d3b7ae4"
	userID := "d8b11458-2a53-48fb-9e1f-140f536da253"
	model := accessGrantModel{}
	setAccessGrant(&model, accessGrantResponse{ScopeType: "project", ScopeID: scopeID, UserID: userID, Role: "developer", Email: "member@example.test", CreatedAt: "2026-08-30T12:00:00Z", UpdatedAt: "2026-08-30T12:00:00Z"})
	if model.ID.ValueString() != "project/"+scopeID+"/"+userID || model.Role.ValueString() != "developer" || model.Email.ValueString() != "member@example.test" {
		t.Fatalf("access grant state = %#v", model)
	}
	scopeType, parsedScopeID, parsedUserID, err := splitAccessGrantImportID(model.ID.ValueString())
	if err != nil || scopeType != "project" || parsedScopeID != scopeID || parsedUserID != userID {
		t.Fatalf("split access grant = %q %q %q %v", scopeType, parsedScopeID, parsedUserID, err)
	}
	for _, invalid := range []string{"", "service/" + scopeID + "/" + userID, "project/not-a-uuid/" + userID, "project/" + scopeID + "/not-a-uuid", "project/" + scopeID} {
		if _, _, _, err = splitAccessGrantImportID(invalid); err == nil {
			t.Errorf("splitAccessGrantImportID(%q) succeeded", invalid)
		}
	}
	if !validAccessGrantRole("admin") || validAccessGrantRole("owner") {
		t.Fatal("access grant role validation mismatch")
	}
}

func TestResourcePolicyStateInputAndImport(t *testing.T) {
	limit := int64(10)
	model := resourcePolicyModel{ScopeType: types.StringValue("organization"), ScopeID: types.StringNull(), MaintenanceReason: types.StringNull()}
	setResourcePolicy(&model, resourcePolicyResponse{ScopeType: "organization", ScopeID: "server-organization-id", MaxProjects: &limit, UpdatedAt: "2026-08-30T12:00:00Z"})
	if model.ID.ValueString() != "organization" || !model.ScopeID.IsNull() || !model.MaintenanceReason.IsNull() || model.MaxProjects.ValueInt64() != 10 || !model.MaxServices.IsNull() {
		t.Fatalf("organization policy state = %#v", model)
	}
	model.Maintenance = types.BoolValue(true)
	model.MaintenanceReason = types.StringValue("planned maintenance")
	model.MaxProjects = types.Int64Value(10)
	model.MaxEnvironments = types.Int64Null()
	model.MaxServices = types.Int64Null()
	model.MaxDatabases = types.Int64Null()
	input := resourcePolicyInput(model)
	if input["maintenance"] != true || input["maintenanceReason"] != "planned maintenance" || input["maxProjects"] != int64(10) || input["maxServices"] != nil {
		t.Fatalf("resource policy input = %#v", input)
	}
	scopeID := "0cc565f8-6b40-4bd7-a6ff-f2f00d3b7ae4"
	scopeType, parsedID, err := splitResourcePolicyImportID("environment/" + scopeID)
	if err != nil || scopeType != "environment" || parsedID != scopeID {
		t.Fatalf("split resource policy = %q %q %v", scopeType, parsedID, err)
	}
	for _, invalid := range []string{"", "service/" + scopeID, "project/not-a-uuid", "organization/" + scopeID} {
		if _, _, err = splitResourcePolicyImportID(invalid); err == nil {
			t.Errorf("splitResourcePolicyImportID(%q) succeeded", invalid)
		}
	}
}

func TestClusterStateUsesStringLabelsAndComputedPosture(t *testing.T) {
	model := clusterModel{}
	err := setCluster(&model, clusterResponse{
		ID: "cluster-id", Name: "Paris", Slug: "paris", State: "active", Labels: map[string]any{"region": "eu-west"}, Capacity: map[string]any{"nodes": float64(3)},
		AgentVersion: "1.2.3", DockerVersion: "28.0", CertificateAuthorityFingerprint: "sha256:abc", CreatedAt: "2026-08-30T12:00:00Z", UpdatedAt: "2026-08-30T12:00:00Z",
	})
	if err != nil || model.ID.ValueString() != "cluster-id" || model.State.ValueString() != "active" || model.Labels.IsNull() || model.CapacityJSON.ValueString() != `{"nodes":3}` || !model.LastSeenAt.IsNull() {
		t.Fatalf("cluster state=%#v err=%v", model, err)
	}
	if err = setCluster(&model, clusterResponse{Labels: map[string]any{"region": float64(1)}}); err == nil {
		t.Fatal("non-string cluster label was accepted")
	}
}

func TestSplitVolumeBackupPolicyImportID(t *testing.T) {
	serviceID, volumeName, err := splitVolumeBackupPolicyImportID("0cc565f8-6b40-4bd7-a6ff-f2f00d3b7ae4/uploads")
	if err != nil || serviceID != "0cc565f8-6b40-4bd7-a6ff-f2f00d3b7ae4" || volumeName != "uploads" {
		t.Fatalf("split import ID = %q %q %v", serviceID, volumeName, err)
	}
	for _, invalid := range []string{"", "service", "/uploads", "service/", "service/uploads", "0cc565f8-6b40-4bd7-a6ff-f2f00d3b7ae4/uploads/nested"} {
		if _, _, err = splitVolumeBackupPolicyImportID(invalid); err == nil {
			t.Errorf("splitVolumeBackupPolicyImportID(%q) succeeded", invalid)
		}
	}
}
