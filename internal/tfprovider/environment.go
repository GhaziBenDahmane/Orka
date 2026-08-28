package tfprovider

import (
	"context"
	"fmt"
	"net/http"

	"github.com/bendahma/dokploy-go/internal/apiclient"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type environmentResource struct{ client *apiclient.Client }
type environmentModel struct {
	ID                types.String `tfsdk:"id"`
	ProjectID         types.String `tfsdk:"project_id"`
	ClusterID         types.String `tfsdk:"cluster_id"`
	PlacementSelector types.Map    `tfsdk:"placement_selector"`
	MinimumNodes      types.Int64  `tfsdk:"minimum_nodes"`
	Name              types.String `tfsdk:"name"`
	Slug              types.String `tfsdk:"slug"`
}
type environmentResponse struct {
	ID                string            `json:"id"`
	ProjectID         string            `json:"projectId"`
	ClusterID         *string           `json:"clusterId"`
	PlacementSelector map[string]string `json:"placementSelector"`
	MinimumNodes      int64             `json:"minimumNodes"`
	Name              string            `json:"name"`
	Slug              string            `json:"slug"`
}

func newEnvironmentResource() resource.Resource { return &environmentResource{} }
func (r *environmentResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_environment"
}
func (r *environmentResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	response.Schema = schema.Schema{Description: "A Dockyard deployment environment.", Attributes: map[string]schema.Attribute{
		"id": schema.StringAttribute{Computed: true}, "project_id": schema.StringAttribute{Required: true, PlanModifiers: replace}, "cluster_id": schema.StringAttribute{Optional: true, PlanModifiers: replace},
		"placement_selector": schema.MapAttribute{Optional: true, Computed: true, ElementType: types.StringType, PlanModifiers: []planmodifier.Map{mapplanmodifier.RequiresReplace()}}, "minimum_nodes": schema.Int64Attribute{Optional: true, Computed: true, PlanModifiers: []planmodifier.Int64{int64planmodifier.RequiresReplace()}},
		"name": schema.StringAttribute{Required: true, PlanModifiers: replace}, "slug": schema.StringAttribute{Optional: true, Computed: true, PlanModifiers: replace},
	}}
}
func (r *environmentResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	r.client = configureResource(request, &response.Diagnostics)
}
func (r *environmentResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var plan environmentModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	body := map[string]any{"name": plan.Name.ValueString(), "slug": plan.Slug.ValueString()}
	if !plan.ClusterID.IsNull() && !plan.ClusterID.IsUnknown() {
		body["clusterId"] = plan.ClusterID.ValueString()
	}
	if !plan.PlacementSelector.IsNull() && !plan.PlacementSelector.IsUnknown() {
		selector := map[string]string{}
		response.Diagnostics.Append(plan.PlacementSelector.ElementsAs(ctx, &selector, false)...)
		body["placementSelector"] = selector
	}
	if !plan.MinimumNodes.IsNull() && !plan.MinimumNodes.IsUnknown() {
		body["minimumNodes"] = plan.MinimumNodes.ValueInt64()
	}
	item, err := call[environmentResponse](ctx, r.client, http.MethodPost, "/v1/projects/"+plan.ProjectID.ValueString()+"/environments", body)
	if err != nil {
		response.Diagnostics.AddError("Unable to create environment", err.Error())
		return
	}
	setEnvironment(&plan, item)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}
func (r *environmentResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var state environmentModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := call[environmentResponse](ctx, r.client, http.MethodGet, "/v1/environments/"+state.ID.ValueString(), nil)
	if notFound(err) {
		response.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		response.Diagnostics.AddError("Unable to read environment", err.Error())
		return
	}
	setEnvironment(&state, item)
	response.Diagnostics.Append(response.State.Set(ctx, &state)...)
}
func (r *environmentResource) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {
}
func (r *environmentResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var state environmentModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	_, err := call[struct{}](ctx, r.client, http.MethodDelete, "/v1/environments/"+state.ID.ValueString(), nil)
	if err != nil && !notFound(err) {
		response.Diagnostics.AddError("Unable to delete environment", fmt.Sprintf("%v. Remove services first.", err))
	}
}
func (r *environmentResource) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), request, response)
}
func setEnvironment(model *environmentModel, item environmentResponse) {
	model.ID = types.StringValue(item.ID)
	model.ProjectID = types.StringValue(item.ProjectID)
	model.Name = types.StringValue(item.Name)
	model.Slug = types.StringValue(item.Slug)
	elements := make(map[string]attr.Value, len(item.PlacementSelector))
	for key, value := range item.PlacementSelector {
		elements[key] = types.StringValue(value)
	}
	model.PlacementSelector = types.MapValueMust(types.StringType, elements)
	model.MinimumNodes = types.Int64Value(item.MinimumNodes)
	if item.ClusterID == nil {
		model.ClusterID = types.StringNull()
	} else {
		model.ClusterID = types.StringValue(*item.ClusterID)
	}
}

var _ resource.ResourceWithConfigure = (*environmentResource)(nil)
var _ resource.ResourceWithImportState = (*environmentResource)(nil)
