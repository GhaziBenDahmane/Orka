package tfprovider

import (
	"context"
	"net/http"

	"github.com/bendahma/dokploy-go/internal/apiclient"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type routeResource struct{ client *apiclient.Client }

type routeModel struct {
	ID                  types.String `tfsdk:"id"`
	ServiceID           types.String `tfsdk:"service_id"`
	ServiceName         types.String `tfsdk:"service_name"`
	Host                types.String `tfsdk:"host"`
	PathPrefix          types.String `tfsdk:"path_prefix"`
	InternalPath        types.String `tfsdk:"internal_path"`
	StripPath           types.Bool   `tfsdk:"strip_path"`
	Enabled             types.Bool   `tfsdk:"enabled"`
	RedirectRegex       types.String `tfsdk:"redirect_regex"`
	RedirectReplacement types.String `tfsdk:"redirect_replacement"`
	RedirectPermanent   types.Bool   `tfsdk:"redirect_permanent"`
	TargetPort          types.Int64  `tfsdk:"target_port"`
	TLS                 types.Bool   `tfsdk:"tls"`
	CertificateResolver types.String `tfsdk:"certificate_resolver"`
	CustomCertificateID types.String `tfsdk:"custom_certificate_id"`
}

type routeResponse struct {
	ID                  string  `json:"id"`
	ComposeServiceID    string  `json:"composeServiceId"`
	ServiceName         string  `json:"serviceName"`
	Host                string  `json:"host"`
	PathPrefix          string  `json:"pathPrefix"`
	InternalPath        string  `json:"internalPath"`
	StripPath           bool    `json:"stripPath"`
	Enabled             bool    `json:"enabled"`
	RedirectRegex       string  `json:"redirectRegex"`
	RedirectReplacement string  `json:"redirectReplacement"`
	RedirectPermanent   bool    `json:"redirectPermanent"`
	TargetPort          int64   `json:"targetPort"`
	TLS                 bool    `json:"tls"`
	CertificateResolver string  `json:"certificateResolver"`
	CustomCertificateID *string `json:"customCertificateId"`
}

func newRouteResource() resource.Resource { return &routeResource{} }

func (r *routeResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_route"
}

func (r *routeResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	stringReplace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	response.Schema = schema.Schema{Description: "A Traefik HTTP(S) route for a Compose service.", Attributes: map[string]schema.Attribute{
		"id":                    schema.StringAttribute{Computed: true},
		"service_id":            schema.StringAttribute{Required: true, PlanModifiers: stringReplace},
		"service_name":          schema.StringAttribute{Required: true},
		"host":                  schema.StringAttribute{Required: true},
		"path_prefix":           schema.StringAttribute{Required: true},
		"internal_path":         schema.StringAttribute{Optional: true, Computed: true},
		"strip_path":            schema.BoolAttribute{Optional: true, Computed: true},
		"enabled":               schema.BoolAttribute{Optional: true, Computed: true},
		"redirect_regex":        schema.StringAttribute{Optional: true, Computed: true},
		"redirect_replacement":  schema.StringAttribute{Optional: true, Computed: true},
		"redirect_permanent":    schema.BoolAttribute{Optional: true, Computed: true},
		"target_port":           schema.Int64Attribute{Required: true},
		"tls":                   schema.BoolAttribute{Required: true},
		"certificate_resolver":  schema.StringAttribute{Required: true},
		"custom_certificate_id": schema.StringAttribute{Optional: true, Description: "Organization custom TLS certificate ID. When set, certificate_resolver must be empty."},
	}}
}

func (r *routeResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	r.client = configureResource(request, &response.Diagnostics)
}

func (r *routeResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var plan routeModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := call[routeResponse](ctx, r.client, http.MethodPost, "/v1/services/"+plan.ServiceID.ValueString()+"/routes", routeRequest(plan))
	if err != nil {
		response.Diagnostics.AddError("Unable to create route", err.Error())
		return
	}
	setRoute(&plan, item)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *routeResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var state routeModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := call[routeResponse](ctx, r.client, http.MethodGet, "/v1/routes/"+state.ID.ValueString(), nil)
	if notFound(err) {
		response.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		response.Diagnostics.AddError("Unable to read route", err.Error())
		return
	}
	setRoute(&state, item)
	response.Diagnostics.Append(response.State.Set(ctx, &state)...)
}

func (r *routeResource) Update(ctx context.Context, request resource.UpdateRequest, response *resource.UpdateResponse) {
	var plan routeModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := call[routeResponse](ctx, r.client, http.MethodPut, "/v1/routes/"+plan.ID.ValueString(), routeRequest(plan))
	if err != nil {
		response.Diagnostics.AddError("Unable to update route", err.Error())
		return
	}
	setRoute(&plan, item)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *routeResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var state routeModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	_, err := call[struct{}](ctx, r.client, http.MethodDelete, "/v1/routes/"+state.ID.ValueString(), nil)
	if err != nil && !notFound(err) {
		response.Diagnostics.AddError("Unable to delete route", err.Error())
	}
}

func (r *routeResource) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), request, response)
}

func setRoute(model *routeModel, item routeResponse) {
	model.ID = types.StringValue(item.ID)
	model.ServiceID = types.StringValue(item.ComposeServiceID)
	model.ServiceName = types.StringValue(item.ServiceName)
	model.Host = types.StringValue(item.Host)
	model.PathPrefix = types.StringValue(item.PathPrefix)
	model.InternalPath = types.StringValue(item.InternalPath)
	model.StripPath = types.BoolValue(item.StripPath)
	model.Enabled = types.BoolValue(item.Enabled)
	model.RedirectRegex = types.StringValue(item.RedirectRegex)
	model.RedirectReplacement = types.StringValue(item.RedirectReplacement)
	model.RedirectPermanent = types.BoolValue(item.RedirectPermanent)
	model.TargetPort = types.Int64Value(item.TargetPort)
	model.TLS = types.BoolValue(item.TLS)
	model.CertificateResolver = types.StringValue(item.CertificateResolver)
	if item.CustomCertificateID == nil {
		model.CustomCertificateID = types.StringNull()
	} else {
		model.CustomCertificateID = types.StringValue(*item.CustomCertificateID)
	}
}

func routeRequest(model routeModel) map[string]any {
	internalPath := "/"
	if !model.InternalPath.IsNull() && !model.InternalPath.IsUnknown() {
		internalPath = model.InternalPath.ValueString()
	}
	enabled := true
	if !model.Enabled.IsNull() && !model.Enabled.IsUnknown() {
		enabled = model.Enabled.ValueBool()
	}
	body := map[string]any{
		"serviceName": model.ServiceName.ValueString(), "host": model.Host.ValueString(), "pathPrefix": model.PathPrefix.ValueString(),
		"internalPath": internalPath, "stripPath": model.StripPath.ValueBool(), "enabled": enabled,
		"redirectRegex": model.RedirectRegex.ValueString(), "redirectReplacement": model.RedirectReplacement.ValueString(), "redirectPermanent": model.RedirectPermanent.ValueBool(),
		"targetPort": model.TargetPort.ValueInt64(), "tls": model.TLS.ValueBool(), "certificateResolver": model.CertificateResolver.ValueString(),
	}
	if !model.CustomCertificateID.IsNull() && !model.CustomCertificateID.IsUnknown() && model.CustomCertificateID.ValueString() != "" {
		body["customCertificateId"] = model.CustomCertificateID.ValueString()
	}
	return body
}

var _ resource.ResourceWithConfigure = (*routeResource)(nil)
var _ resource.ResourceWithImportState = (*routeResource)(nil)
