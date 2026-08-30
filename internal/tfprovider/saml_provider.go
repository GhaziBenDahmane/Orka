package tfprovider

import (
	"context"
	"net/http"

	"github.com/bendahma/dokploy-go/internal/apiclient"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type samlProviderResource struct{ client *apiclient.Client }

type samlProviderModel struct {
	ID                         types.String `tfsdk:"id"`
	Name                       types.String `tfsdk:"name"`
	MetadataXML                types.String `tfsdk:"metadata_xml"`
	Domains                    types.Set    `tfsdk:"domains"`
	EmailAttribute             types.String `tfsdk:"email_attribute"`
	NameAttribute              types.String `tfsdk:"name_attribute"`
	DefaultRole                types.String `tfsdk:"default_role"`
	AllowIDPInitiated          types.Bool   `tfsdk:"allow_idp_initiated"`
	Enabled                    types.Bool   `tfsdk:"enabled"`
	CertificateConfigurationOK types.Bool   `tfsdk:"certificate_configuration_ok"`
	SPCertificateNotAfter      types.String `tfsdk:"sp_certificate_not_after"`
	IDPCertificateNotAfter     types.String `tfsdk:"idp_certificate_not_after"`
	PendingCertificateNotAfter types.String `tfsdk:"pending_certificate_not_after"`
	PendingCertificateCreated  types.String `tfsdk:"pending_certificate_created_at"`
}

type samlProviderResponse struct {
	ID                         string   `json:"id"`
	Name                       string   `json:"name"`
	Domains                    []string `json:"domains"`
	EmailAttribute             string   `json:"emailAttribute"`
	NameAttribute              string   `json:"nameAttribute"`
	DefaultRole                string   `json:"defaultRole"`
	AllowIDPInitiated          bool     `json:"allowIdpInitiated"`
	Enabled                    bool     `json:"enabled"`
	CertificateConfigurationOK bool     `json:"certificateConfigurationOk"`
	SPCertificateNotAfter      *string  `json:"spCertificateNotAfter"`
	IDPCertificateNotAfter     *string  `json:"idpCertificateNotAfter"`
	PendingCertificateNotAfter *string  `json:"pendingCertificateNotAfter"`
	PendingCertificateCreated  *string  `json:"pendingCertificateCreatedAt"`
}

func newSAMLProviderResource() resource.Resource { return &samlProviderResource{} }

func (r *samlProviderResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_saml_provider"
}

func (r *samlProviderResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	response.Schema = schema.Schema{Description: "An organization-scoped SAML 2.0 identity provider with server-managed signing keys.", Attributes: map[string]schema.Attribute{
		"id":                             schema.StringAttribute{Computed: true},
		"name":                           schema.StringAttribute{Required: true},
		"metadata_xml":                   schema.StringAttribute{Required: true, Sensitive: true, Description: "Identity-provider metadata XML; retained in sensitive state because the API does not return it."},
		"domains":                        schema.SetAttribute{Required: true, ElementType: types.StringType},
		"email_attribute":                schema.StringAttribute{Required: true},
		"name_attribute":                 schema.StringAttribute{Required: true},
		"default_role":                   schema.StringAttribute{Required: true, Description: "One of viewer, developer, or admin."},
		"allow_idp_initiated":            schema.BoolAttribute{Required: true},
		"enabled":                        schema.BoolAttribute{Required: true},
		"certificate_configuration_ok":   schema.BoolAttribute{Computed: true},
		"sp_certificate_not_after":       schema.StringAttribute{Computed: true},
		"idp_certificate_not_after":      schema.StringAttribute{Computed: true},
		"pending_certificate_not_after":  schema.StringAttribute{Computed: true},
		"pending_certificate_created_at": schema.StringAttribute{Computed: true},
	}}
}

func (r *samlProviderResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	r.client = configureResource(request, &response.Diagnostics)
}

func (r *samlProviderResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var plan samlProviderModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	enabled := plan.Enabled.ValueBool()
	input := samlProviderInput(ctx, plan, &response.Diagnostics)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := call[samlProviderResponse](ctx, r.client, http.MethodPost, "/v1/sso/saml-providers", input)
	if err != nil {
		response.Diagnostics.AddError("Unable to create SAML provider", err.Error())
		return
	}
	setSAMLProvider(&plan, item)
	if !enabled {
		if _, err = call[struct{}](ctx, r.client, http.MethodDelete, "/v1/sso/saml-providers/"+plan.ID.ValueString(), nil); err != nil {
			response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
			response.Diagnostics.AddError("Unable to disable created SAML provider", err.Error())
			return
		}
		plan.Enabled = types.BoolValue(false)
	}
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *samlProviderResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var state samlProviderModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, found, err := r.read(ctx, state.ID.ValueString())
	if err != nil {
		response.Diagnostics.AddError("Unable to read SAML provider", err.Error())
		return
	}
	if !found {
		response.State.RemoveResource(ctx)
		return
	}
	setSAMLProvider(&state, item)
	response.Diagnostics.Append(response.State.Set(ctx, &state)...)
}

func (r *samlProviderResource) Update(ctx context.Context, request resource.UpdateRequest, response *resource.UpdateResponse) {
	var plan samlProviderModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	input := samlProviderInput(ctx, plan, &response.Diagnostics)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := call[samlProviderResponse](ctx, r.client, http.MethodPut, "/v1/sso/saml-providers/"+plan.ID.ValueString(), input)
	if err != nil {
		response.Diagnostics.AddError("Unable to update SAML provider", err.Error())
		return
	}
	if plan.Enabled.ValueBool() != item.Enabled {
		method, suffix := http.MethodPost, "/enable"
		if !plan.Enabled.ValueBool() {
			method, suffix = http.MethodDelete, ""
		}
		if _, err = call[struct{}](ctx, r.client, method, "/v1/sso/saml-providers/"+plan.ID.ValueString()+suffix, nil); err != nil {
			response.Diagnostics.AddError("Unable to update SAML provider status", err.Error())
			return
		}
		item.Enabled = plan.Enabled.ValueBool()
	}
	setSAMLProvider(&plan, item)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *samlProviderResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var state samlProviderModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	_, err := call[struct{}](ctx, r.client, http.MethodDelete, "/v1/sso/saml-providers/"+state.ID.ValueString(), nil)
	if err != nil && !notFound(err) {
		response.Diagnostics.AddError("Unable to disable SAML provider", err.Error())
	}
}

func (r *samlProviderResource) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), request, response)
}

func (r *samlProviderResource) read(ctx context.Context, id string) (samlProviderResponse, bool, error) {
	result, err := call[struct {
		Items []samlProviderResponse `json:"items"`
	}](ctx, r.client, http.MethodGet, "/v1/sso/saml-providers", nil)
	if err != nil {
		return samlProviderResponse{}, false, err
	}
	for _, item := range result.Items {
		if item.ID == id {
			return item, true, nil
		}
	}
	return samlProviderResponse{}, false, nil
}

func samlProviderInput(ctx context.Context, model samlProviderModel, diagnostics *diag.Diagnostics) map[string]any {
	var domains []string
	diagnostics.Append(model.Domains.ElementsAs(ctx, &domains, false)...)
	return map[string]any{
		"name": model.Name.ValueString(), "metadataXml": model.MetadataXML.ValueString(), "domains": domains,
		"emailAttribute": model.EmailAttribute.ValueString(), "nameAttribute": model.NameAttribute.ValueString(),
		"defaultRole": model.DefaultRole.ValueString(), "allowIdpInitiated": model.AllowIDPInitiated.ValueBool(),
	}
}

func setSAMLProvider(model *samlProviderModel, item samlProviderResponse) {
	model.ID = types.StringValue(item.ID)
	model.Name = types.StringValue(item.Name)
	model.Domains = stringSet(item.Domains)
	model.EmailAttribute = types.StringValue(item.EmailAttribute)
	model.NameAttribute = types.StringValue(item.NameAttribute)
	model.DefaultRole = types.StringValue(item.DefaultRole)
	model.AllowIDPInitiated = types.BoolValue(item.AllowIDPInitiated)
	model.Enabled = types.BoolValue(item.Enabled)
	model.CertificateConfigurationOK = types.BoolValue(item.CertificateConfigurationOK)
	model.SPCertificateNotAfter = optionalComputedString(item.SPCertificateNotAfter)
	model.IDPCertificateNotAfter = optionalComputedString(item.IDPCertificateNotAfter)
	model.PendingCertificateNotAfter = optionalComputedString(item.PendingCertificateNotAfter)
	model.PendingCertificateCreated = optionalComputedString(item.PendingCertificateCreated)
}

func optionalComputedString(value *string) types.String {
	if value == nil {
		return types.StringNull()
	}
	return types.StringValue(*value)
}

var _ resource.ResourceWithConfigure = (*samlProviderResource)(nil)
var _ resource.ResourceWithImportState = (*samlProviderResource)(nil)
