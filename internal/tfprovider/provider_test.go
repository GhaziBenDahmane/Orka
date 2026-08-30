package tfprovider

import (
	"context"
	"slices"
	"testing"

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
	if len(instance.Resources(context.Background())) != 12 {
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
