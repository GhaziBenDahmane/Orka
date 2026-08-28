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
	if len(instance.Resources(context.Background())) != 3 {
		t.Fatal("provider must expose project, environment, and service resources")
	}
	for _, factory := range instance.Resources(context.Background()) {
		var response resource.SchemaResponse
		factory().Schema(context.Background(), resource.SchemaRequest{}, &response)
		if diagnostics := response.Schema.ValidateImplementation(context.Background()); diagnostics.HasError() {
			t.Fatalf("invalid resource schema: %v", diagnostics)
		}
	}
}
