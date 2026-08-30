package tfprovider

import (
	"context"
	"net/http"

	"github.com/bendahma/dokploy-go/internal/apiclient"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type authSettingsResource struct{ client *apiclient.Client }

type authSettingsModel struct {
	ID         types.String `tfsdk:"id"`
	RequireSSO types.Bool   `tfsdk:"require_sso"`
}

type authSettingsResponse struct {
	OrganizationID string `json:"organizationId"`
	RequireSSO     bool   `json:"requireSso"`
}

func newAuthSettingsResource() resource.Resource { return &authSettingsResource{} }

func (r *authSettingsResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_auth_settings"
}

func (r *authSettingsResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	response.Schema = schema.Schema{Description: "Organization-wide interactive authentication policy.", Attributes: map[string]schema.Attribute{
		"id":          schema.StringAttribute{Computed: true, Description: "Organization ID."},
		"require_sso": schema.BoolAttribute{Required: true, Description: "Require OIDC or SAML for interactive users while retaining the owner break-glass account."},
	}}
}

func (r *authSettingsResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	r.client = configureResource(request, &response.Diagnostics)
}

func (r *authSettingsResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var plan authSettingsModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := r.put(ctx, plan.RequireSSO.ValueBool())
	if err != nil {
		response.Diagnostics.AddError("Unable to update authentication settings", err.Error())
		return
	}
	plan.ID = types.StringValue(item.OrganizationID)
	plan.RequireSSO = types.BoolValue(item.RequireSSO)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *authSettingsResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	item, err := call[authSettingsResponse](ctx, r.client, http.MethodGet, "/v1/sso/settings", nil)
	if err != nil {
		response.Diagnostics.AddError("Unable to read authentication settings", err.Error())
		return
	}
	state := authSettingsModel{ID: types.StringValue(item.OrganizationID), RequireSSO: types.BoolValue(item.RequireSSO)}
	response.Diagnostics.Append(response.State.Set(ctx, &state)...)
}

func (r *authSettingsResource) Update(ctx context.Context, request resource.UpdateRequest, response *resource.UpdateResponse) {
	var plan authSettingsModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := r.put(ctx, plan.RequireSSO.ValueBool())
	if err != nil {
		response.Diagnostics.AddError("Unable to update authentication settings", err.Error())
		return
	}
	plan.ID = types.StringValue(item.OrganizationID)
	plan.RequireSSO = types.BoolValue(item.RequireSSO)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *authSettingsResource) Delete(ctx context.Context, _ resource.DeleteRequest, response *resource.DeleteResponse) {
	_, err := call[authSettingsResponse](ctx, r.client, http.MethodPut, "/v1/sso/settings", map[string]bool{"requireSso": false})
	if err != nil {
		response.Diagnostics.AddError("Unable to disable mandatory SSO", err.Error())
	}
}

func (r *authSettingsResource) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), request, response)
}

func (r *authSettingsResource) put(ctx context.Context, requireSSO bool) (authSettingsResponse, error) {
	return call[authSettingsResponse](ctx, r.client, http.MethodPut, "/v1/sso/settings", map[string]bool{"requireSso": requireSSO})
}

var _ resource.ResourceWithConfigure = (*authSettingsResource)(nil)
var _ resource.ResourceWithImportState = (*authSettingsResource)(nil)
