package tfprovider

import (
	"context"
	"net/http"

	"github.com/bendahma/dokploy-go/internal/apiclient"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
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
	TargetPort          types.Int64  `tfsdk:"target_port"`
	TLS                 types.Bool   `tfsdk:"tls"`
	CertificateResolver types.String `tfsdk:"certificate_resolver"`
}

type routeResponse struct {
	ID                  string `json:"id"`
	ComposeServiceID    string `json:"composeServiceId"`
	ServiceName         string `json:"serviceName"`
	Host                string `json:"host"`
	PathPrefix          string `json:"pathPrefix"`
	TargetPort          int64  `json:"targetPort"`
	TLS                 bool   `json:"tls"`
	CertificateResolver string `json:"certificateResolver"`
}

func newRouteResource() resource.Resource { return &routeResource{} }

func (r *routeResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_route"
}

func (r *routeResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	stringReplace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	response.Schema = schema.Schema{Description: "A Traefik HTTP(S) route for a Compose service.", Attributes: map[string]schema.Attribute{
		"id":                   schema.StringAttribute{Computed: true},
		"service_id":           schema.StringAttribute{Required: true, PlanModifiers: stringReplace},
		"service_name":         schema.StringAttribute{Required: true, PlanModifiers: stringReplace},
		"host":                 schema.StringAttribute{Required: true, PlanModifiers: stringReplace},
		"path_prefix":          schema.StringAttribute{Required: true, PlanModifiers: stringReplace},
		"target_port":          schema.Int64Attribute{Required: true, PlanModifiers: []planmodifier.Int64{int64planmodifier.RequiresReplace()}},
		"tls":                  schema.BoolAttribute{Required: true, PlanModifiers: []planmodifier.Bool{boolplanmodifier.RequiresReplace()}},
		"certificate_resolver": schema.StringAttribute{Required: true, PlanModifiers: stringReplace},
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
	item, err := call[routeResponse](ctx, r.client, http.MethodPost, "/v1/services/"+plan.ServiceID.ValueString()+"/routes", map[string]any{
		"serviceName": plan.ServiceName.ValueString(), "host": plan.Host.ValueString(), "pathPrefix": plan.PathPrefix.ValueString(), "targetPort": plan.TargetPort.ValueInt64(), "tls": plan.TLS.ValueBool(), "certificateResolver": plan.CertificateResolver.ValueString(),
	})
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

func (r *routeResource) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {}

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
	model.TargetPort = types.Int64Value(item.TargetPort)
	model.TLS = types.BoolValue(item.TLS)
	model.CertificateResolver = types.StringValue(item.CertificateResolver)
}

var _ resource.ResourceWithConfigure = (*routeResource)(nil)
var _ resource.ResourceWithImportState = (*routeResource)(nil)
