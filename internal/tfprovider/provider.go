package tfprovider

import (
	"context"
	"os"

	"github.com/bendahma/dokploy-go/internal/apiclient"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	providerschema "github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type dockyardProvider struct{ version string }

type providerModel struct {
	URL            types.String `tfsdk:"url"`
	Token          types.String `tfsdk:"token"`
	OrganizationID types.String `tfsdk:"organization_id"`
}

func New(version string) func() provider.Provider {
	return func() provider.Provider { return &dockyardProvider{version: version} }
}

func (p *dockyardProvider) Metadata(_ context.Context, _ provider.MetadataRequest, response *provider.MetadataResponse) {
	response.TypeName = "dockyard"
	response.Version = p.version
}

func (p *dockyardProvider) Schema(_ context.Context, _ provider.SchemaRequest, response *provider.SchemaResponse) {
	response.Schema = providerschema.Schema{Attributes: map[string]providerschema.Attribute{
		"url":             providerschema.StringAttribute{Optional: true, Description: "Dockyard API URL. May be set with DOCKYARD_URL."},
		"token":           providerschema.StringAttribute{Optional: true, Sensitive: true, Description: "Dockyard bearer token. May be set with DOCKYARD_TOKEN."},
		"organization_id": providerschema.StringAttribute{Optional: true, Description: "Organization override. May be set with DOCKYARD_ORGANIZATION_ID."},
	}}
}

func (p *dockyardProvider) Configure(ctx context.Context, request provider.ConfigureRequest, response *provider.ConfigureResponse) {
	var config providerModel
	response.Diagnostics.Append(request.Config.Get(ctx, &config)...)
	if response.Diagnostics.HasError() {
		return
	}
	url := configured(config.URL, "DOCKYARD_URL")
	token := configured(config.Token, "DOCKYARD_TOKEN")
	organizationID := configured(config.OrganizationID, "DOCKYARD_ORGANIZATION_ID")
	if url == "" {
		response.Diagnostics.AddError("Missing Dockyard URL", "Set the provider url attribute or DOCKYARD_URL.")
	}
	if token == "" {
		response.Diagnostics.AddError("Missing Dockyard token", "Set the provider token attribute or DOCKYARD_TOKEN.")
	}
	if response.Diagnostics.HasError() {
		return
	}
	client, err := apiclient.New(url, token, organizationID)
	if err != nil {
		response.Diagnostics.AddError("Invalid Dockyard configuration", err.Error())
		return
	}
	response.ResourceData = client
	response.DataSourceData = client
}

func configured(value types.String, environment string) string {
	if !value.IsNull() && !value.IsUnknown() && value.ValueString() != "" {
		return value.ValueString()
	}
	return os.Getenv(environment)
}

func (p *dockyardProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{newProjectResource, newEnvironmentResource, newServiceResource, newRouteResource, newDatabaseResource, newSourceCredentialResource, newBackupDestinationResource, newBackupPolicyResource, newVolumeBackupPolicyResource, newTemplateRepositoryResource, newOIDCProviderResource, newSAMLProviderResource, newSCIMTokenResource, newServiceAccountResource, newAccessGrantResource, newResourcePolicyResource, newClusterResource, newNotificationEndpointResource, newAuthSettingsResource}
}

func (p *dockyardProvider) DataSources(_ context.Context) []func() datasource.DataSource { return nil }

func configureResource(request resource.ConfigureRequest, responseDiagnostics *diag.Diagnostics) *apiclient.Client {
	if request.ProviderData == nil {
		return nil
	}
	client, ok := request.ProviderData.(*apiclient.Client)
	if !ok {
		responseDiagnostics.AddError("Unexpected provider configuration", "The Dockyard provider received an invalid API client.")
		return nil
	}
	return client
}
