package tfprovider

import (
	"context"
	"net/http"

	"github.com/bendahma/dokploy-go/internal/apiclient"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type oidcProviderResource struct{ client *apiclient.Client }

type oidcProviderModel struct {
	ID           types.String `tfsdk:"id"`
	Name         types.String `tfsdk:"name"`
	Issuer       types.String `tfsdk:"issuer"`
	ClientID     types.String `tfsdk:"client_id"`
	ClientSecret types.String `tfsdk:"client_secret"`
	Domains      types.Set    `tfsdk:"domains"`
	Scopes       types.Set    `tfsdk:"scopes"`
	DefaultRole  types.String `tfsdk:"default_role"`
	Enabled      types.Bool   `tfsdk:"enabled"`
}

type oidcProviderResponse struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Issuer      string   `json:"issuer"`
	ClientID    string   `json:"clientId"`
	Domains     []string `json:"domains"`
	Scopes      []string `json:"scopes"`
	DefaultRole string   `json:"defaultRole"`
	Enabled     bool     `json:"enabled"`
}

func newOIDCProviderResource() resource.Resource { return &oidcProviderResource{} }

func (r *oidcProviderResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_oidc_provider"
}

func (r *oidcProviderResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	response.Schema = schema.Schema{Description: "An organization-scoped OpenID Connect identity provider with an encrypted client secret.", Attributes: map[string]schema.Attribute{
		"id":            schema.StringAttribute{Computed: true},
		"name":          schema.StringAttribute{Required: true},
		"issuer":        schema.StringAttribute{Required: true, Description: "Absolute HTTPS OIDC issuer URL."},
		"client_id":     schema.StringAttribute{Required: true},
		"client_secret": schema.StringAttribute{Required: true, Sensitive: true, Description: "Encrypted by Dockyard and never returned by the API."},
		"domains":       schema.SetAttribute{Required: true, ElementType: types.StringType, Description: "Allowed email domains for discovery and JIT provisioning."},
		"scopes":        schema.SetAttribute{Required: true, ElementType: types.StringType},
		"default_role":  schema.StringAttribute{Required: true, Description: "One of viewer, developer, or admin."},
		"enabled":       schema.BoolAttribute{Required: true},
	}}
}

func (r *oidcProviderResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	r.client = configureResource(request, &response.Diagnostics)
}

func (r *oidcProviderResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var plan oidcProviderModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	enabled := plan.Enabled.ValueBool()
	input := oidcProviderInput(ctx, plan, plan.ClientSecret.ValueString(), &response.Diagnostics)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := call[oidcProviderResponse](ctx, r.client, http.MethodPost, "/v1/sso/oidc-providers", input)
	if err != nil {
		response.Diagnostics.AddError("Unable to create OIDC provider", err.Error())
		return
	}
	setOIDCProvider(&plan, item)
	if !enabled {
		if _, err = call[struct{}](ctx, r.client, http.MethodDelete, "/v1/sso/oidc-providers/"+plan.ID.ValueString(), nil); err != nil {
			response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
			response.Diagnostics.AddError("Unable to disable created OIDC provider", err.Error())
			return
		}
		plan.Enabled = types.BoolValue(false)
	}
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *oidcProviderResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var state oidcProviderModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, found, err := r.read(ctx, state.ID.ValueString())
	if err != nil {
		response.Diagnostics.AddError("Unable to read OIDC provider", err.Error())
		return
	}
	if !found {
		response.State.RemoveResource(ctx)
		return
	}
	setOIDCProvider(&state, item)
	response.Diagnostics.Append(response.State.Set(ctx, &state)...)
}

func (r *oidcProviderResource) Update(ctx context.Context, request resource.UpdateRequest, response *resource.UpdateResponse) {
	var plan, state oidcProviderModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	secret := oidcClientSecretForUpdate(plan.ClientSecret, state.ClientSecret)
	input := oidcProviderInput(ctx, plan, secret, &response.Diagnostics)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := call[oidcProviderResponse](ctx, r.client, http.MethodPut, "/v1/sso/oidc-providers/"+plan.ID.ValueString(), input)
	if err != nil {
		response.Diagnostics.AddError("Unable to update OIDC provider", err.Error())
		return
	}
	if plan.Enabled.ValueBool() != item.Enabled {
		method, suffix := http.MethodPost, "/enable"
		if !plan.Enabled.ValueBool() {
			method, suffix = http.MethodDelete, ""
		}
		if _, err = call[struct{}](ctx, r.client, method, "/v1/sso/oidc-providers/"+plan.ID.ValueString()+suffix, nil); err != nil {
			response.Diagnostics.AddError("Unable to update OIDC provider status", err.Error())
			return
		}
		item.Enabled = plan.Enabled.ValueBool()
	}
	setOIDCProvider(&plan, item)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *oidcProviderResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var state oidcProviderModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	_, err := call[struct{}](ctx, r.client, http.MethodDelete, "/v1/sso/oidc-providers/"+state.ID.ValueString(), nil)
	if err != nil && !notFound(err) {
		response.Diagnostics.AddError("Unable to disable OIDC provider", err.Error())
	}
}

func (r *oidcProviderResource) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), request, response)
}

func (r *oidcProviderResource) read(ctx context.Context, id string) (oidcProviderResponse, bool, error) {
	result, err := call[struct {
		Items []oidcProviderResponse `json:"items"`
	}](ctx, r.client, http.MethodGet, "/v1/sso/oidc-providers", nil)
	if err != nil {
		return oidcProviderResponse{}, false, err
	}
	for _, item := range result.Items {
		if item.ID == id {
			return item, true, nil
		}
	}
	return oidcProviderResponse{}, false, nil
}

func oidcProviderInput(ctx context.Context, model oidcProviderModel, clientSecret string, diagnostics *diag.Diagnostics) map[string]any {
	var domains, scopes []string
	diagnostics.Append(model.Domains.ElementsAs(ctx, &domains, false)...)
	diagnostics.Append(model.Scopes.ElementsAs(ctx, &scopes, false)...)
	return map[string]any{
		"name": model.Name.ValueString(), "issuer": model.Issuer.ValueString(), "clientId": model.ClientID.ValueString(), "clientSecret": clientSecret,
		"domains": domains, "scopes": scopes, "defaultRole": model.DefaultRole.ValueString(),
	}
}

func oidcClientSecretForUpdate(planned, current types.String) string {
	if planned.Equal(current) {
		return ""
	}
	return planned.ValueString()
}

func setOIDCProvider(model *oidcProviderModel, item oidcProviderResponse) {
	model.ID = types.StringValue(item.ID)
	model.Name = types.StringValue(item.Name)
	model.Issuer = types.StringValue(item.Issuer)
	model.ClientID = types.StringValue(item.ClientID)
	model.Domains = stringSet(item.Domains)
	model.Scopes = stringSet(item.Scopes)
	model.DefaultRole = types.StringValue(item.DefaultRole)
	model.Enabled = types.BoolValue(item.Enabled)
}

func stringSet(values []string) types.Set {
	elements := make([]attr.Value, 0, len(values))
	for _, value := range values {
		elements = append(elements, types.StringValue(value))
	}
	return types.SetValueMust(types.StringType, elements)
}

var _ resource.ResourceWithConfigure = (*oidcProviderResource)(nil)
var _ resource.ResourceWithImportState = (*oidcProviderResource)(nil)
