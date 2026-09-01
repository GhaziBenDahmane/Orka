package tfprovider

import (
	"context"
	"net/http"

	"github.com/GhaziBenDahmane/Orka/internal/apiclient"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type serviceNetworksResource struct{ client *apiclient.Client }
type serviceNetworksModel struct {
	ID         types.String `tfsdk:"id"`
	ServiceID  types.String `tfsdk:"service_id"`
	NetworkIDs types.Set    `tfsdk:"network_ids"`
}

func newServiceNetworksResource() resource.Resource { return &serviceNetworksResource{} }
func (r *serviceNetworksResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_service_networks"
}
func (r *serviceNetworksResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	response.Schema = schema.Schema{Description: "The complete managed-network assignment set for a Compose service.", Attributes: map[string]schema.Attribute{"id": schema.StringAttribute{Computed: true}, "service_id": schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}}, "network_ids": schema.SetAttribute{Required: true, ElementType: types.StringType, Description: "Up to 16 ready overlay network UUIDs on the service's Swarm."}}}
}
func (r *serviceNetworksResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	r.client = configureResource(request, &response.Diagnostics)
}
func (r *serviceNetworksResource) ValidateConfig(ctx context.Context, request resource.ValidateConfigRequest, response *resource.ValidateConfigResponse) {
	var config serviceNetworksModel
	response.Diagnostics.Append(request.Config.Get(ctx, &config)...)
	if response.Diagnostics.HasError() {
		return
	}
	if !config.ServiceID.IsNull() && !config.ServiceID.IsUnknown() {
		if _, err := uuid.Parse(config.ServiceID.ValueString()); err != nil {
			response.Diagnostics.AddAttributeError(path.Root("service_id"), "Invalid service ID", "service_id must be a UUID.")
		}
	}
	if !config.NetworkIDs.IsNull() && !config.NetworkIDs.IsUnknown() {
		var ids []string
		response.Diagnostics.Append(config.NetworkIDs.ElementsAs(ctx, &ids, false)...)
		if len(ids) > 16 {
			response.Diagnostics.AddAttributeError(path.Root("network_ids"), "Too many networks", "A service may have at most 16 networks.")
		}
		for _, id := range ids {
			if _, err := uuid.Parse(id); err != nil {
				response.Diagnostics.AddAttributeError(path.Root("network_ids"), "Invalid network ID", "Every network_id must be a UUID.")
				break
			}
		}
	}
}
func (r *serviceNetworksResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var plan serviceNetworksModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	if err := r.put(ctx, &plan, &response.Diagnostics); err != nil {
		response.Diagnostics.AddError("Unable to assign service networks", err.Error())
		return
	}
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}
func (r *serviceNetworksResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var state serviceNetworksModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	result, err := call[struct {
		Items []networkResponse `json:"items"`
	}](ctx, r.client, http.MethodGet, "/v1/services/"+state.ServiceID.ValueString()+"/networks", nil)
	if notFound(err) {
		response.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		response.Diagnostics.AddError("Unable to read service networks", err.Error())
		return
	}
	ids := make([]string, 0, len(result.Items))
	for _, item := range result.Items {
		ids = append(ids, item.ID)
	}
	state.ID = types.StringValue(state.ServiceID.ValueString())
	var diagnostics diag.Diagnostics
	state.NetworkIDs, diagnostics = types.SetValueFrom(ctx, types.StringType, ids)
	response.Diagnostics.Append(diagnostics...)
	if !response.Diagnostics.HasError() {
		response.Diagnostics.Append(response.State.Set(ctx, &state)...)
	}
}
func (r *serviceNetworksResource) Update(ctx context.Context, request resource.UpdateRequest, response *resource.UpdateResponse) {
	var plan serviceNetworksModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	if err := r.put(ctx, &plan, &response.Diagnostics); err != nil {
		response.Diagnostics.AddError("Unable to update service networks", err.Error())
		return
	}
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}
func (r *serviceNetworksResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var state serviceNetworksModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	_, err := call[struct {
		Items []networkResponse `json:"items"`
	}](ctx, r.client, http.MethodPut, "/v1/services/"+state.ServiceID.ValueString()+"/networks", map[string]any{"networkIds": []string{}})
	if err != nil && !notFound(err) {
		response.Diagnostics.AddError("Unable to clear service networks", err.Error())
	}
}
func (r *serviceNetworksResource) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	response.Diagnostics.Append(response.State.SetAttribute(ctx, path.Root("id"), request.ID)...)
	response.Diagnostics.Append(response.State.SetAttribute(ctx, path.Root("service_id"), request.ID)...)
}
func (r *serviceNetworksResource) put(ctx context.Context, model *serviceNetworksModel, diagnostics *diag.Diagnostics) error {
	var ids []string
	diagnostics.Append(model.NetworkIDs.ElementsAs(ctx, &ids, false)...)
	if diagnostics.HasError() {
		return nil
	}
	_, err := call[struct {
		Items []networkResponse `json:"items"`
	}](ctx, r.client, http.MethodPut, "/v1/services/"+model.ServiceID.ValueString()+"/networks", map[string]any{"networkIds": ids})
	if err == nil {
		model.ID = types.StringValue(model.ServiceID.ValueString())
	}
	return err
}

var _ resource.ResourceWithConfigure = (*serviceNetworksResource)(nil)
var _ resource.ResourceWithValidateConfig = (*serviceNetworksResource)(nil)
var _ resource.ResourceWithImportState = (*serviceNetworksResource)(nil)
