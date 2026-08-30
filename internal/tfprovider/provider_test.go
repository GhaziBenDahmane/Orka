package tfprovider

import (
	"context"
	"slices"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
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
	if len(instance.Resources(context.Background())) != 10 {
		t.Fatal("provider must expose the core hierarchy, credentials, backup policies, and template repository resources")
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
