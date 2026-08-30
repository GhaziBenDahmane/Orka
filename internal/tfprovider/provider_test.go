package tfprovider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
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
	if len(instance.Resources(context.Background())) != 9 {
		t.Fatal("provider must expose project, environment, service, route, database, source credential, backup destination, database backup policy, and volume backup policy resources")
	}
	for _, factory := range instance.Resources(context.Background()) {
		var response resource.SchemaResponse
		factory().Schema(context.Background(), resource.SchemaRequest{}, &response)
		if diagnostics := response.Schema.ValidateImplementation(context.Background()); diagnostics.HasError() {
			t.Fatalf("invalid resource schema: %v", diagnostics)
		}
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
