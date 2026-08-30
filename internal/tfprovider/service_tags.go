package tfprovider

import (
	"context"
	"net/http"

	"github.com/bendahma/dokploy-go/internal/apiclient"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type serviceTagsResource struct{ client *apiclient.Client }
type serviceTagsModel struct {
	ID        types.String `tfsdk:"id"`
	ServiceID types.String `tfsdk:"service_id"`
	TagIDs    types.Set    `tfsdk:"tag_ids"`
}

func newServiceTagsResource() resource.Resource { return &serviceTagsResource{} }
func (r *serviceTagsResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_service_tags"
}
func (r *serviceTagsResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	response.Schema = schema.Schema{Description: "The complete tag assignment set for one Compose service.", Attributes: map[string]schema.Attribute{
		"id":         schema.StringAttribute{Computed: true},
		"service_id": schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"tag_ids":    schema.SetAttribute{Required: true, ElementType: types.StringType, Description: "Up to 32 organization tag UUIDs."},
	}}
}
func (r *serviceTagsResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	r.client = configureResource(request, &response.Diagnostics)
}
func (r *serviceTagsResource) ValidateConfig(ctx context.Context, request resource.ValidateConfigRequest, response *resource.ValidateConfigResponse) {
	var config serviceTagsModel
	response.Diagnostics.Append(request.Config.Get(ctx, &config)...)
	if response.Diagnostics.HasError() {
		return
	}
	if !config.ServiceID.IsNull() && !config.ServiceID.IsUnknown() {
		if _, err := uuid.Parse(config.ServiceID.ValueString()); err != nil {
			response.Diagnostics.AddAttributeError(path.Root("service_id"), "Invalid service ID", "service_id must be a UUID.")
		}
	}
	if !config.TagIDs.IsNull() && !config.TagIDs.IsUnknown() {
		var ids []string
		response.Diagnostics.Append(config.TagIDs.ElementsAs(ctx, &ids, false)...)
		if len(ids) > 32 {
			response.Diagnostics.AddAttributeError(path.Root("tag_ids"), "Too many tags", "A service may have at most 32 tags.")
		}
		for _, id := range ids {
			if _, err := uuid.Parse(id); err != nil {
				response.Diagnostics.AddAttributeError(path.Root("tag_ids"), "Invalid tag ID", "Every tag_id must be a UUID.")
				break
			}
		}
	}
}
func (r *serviceTagsResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var plan serviceTagsModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	err := r.put(ctx, &plan, &response.Diagnostics)
	if response.Diagnostics.HasError() {
		return
	}
	if err != nil {
		response.Diagnostics.AddError("Unable to assign service tags", err.Error())
		return
	}
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}
func (r *serviceTagsResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var state serviceTagsModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	result, err := call[struct {
		Items []tagResponse `json:"items"`
	}](ctx, r.client, http.MethodGet, "/v1/services/"+state.ServiceID.ValueString()+"/tags", nil)
	if notFound(err) {
		response.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		response.Diagnostics.AddError("Unable to read service tags", err.Error())
		return
	}
	ids := make([]string, 0, len(result.Items))
	for _, item := range result.Items {
		ids = append(ids, item.ID)
	}
	state.ID = types.StringValue(state.ServiceID.ValueString())
	var diagnostics diag.Diagnostics
	state.TagIDs, diagnostics = types.SetValueFrom(ctx, types.StringType, ids)
	response.Diagnostics.Append(diagnostics...)
	if response.Diagnostics.HasError() {
		return
	}
	response.Diagnostics.Append(response.State.Set(ctx, &state)...)
}
func (r *serviceTagsResource) Update(ctx context.Context, request resource.UpdateRequest, response *resource.UpdateResponse) {
	var plan serviceTagsModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	err := r.put(ctx, &plan, &response.Diagnostics)
	if response.Diagnostics.HasError() {
		return
	}
	if err != nil {
		response.Diagnostics.AddError("Unable to update service tags", err.Error())
		return
	}
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}
func (r *serviceTagsResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var state serviceTagsModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	_, err := call[struct {
		Items []tagResponse `json:"items"`
	}](ctx, r.client, http.MethodPut, "/v1/services/"+state.ServiceID.ValueString()+"/tags", map[string]any{"tagIds": []string{}})
	if err != nil && !notFound(err) {
		response.Diagnostics.AddError("Unable to clear service tags", err.Error())
	}
}
func (r *serviceTagsResource) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	response.Diagnostics.Append(response.State.SetAttribute(ctx, path.Root("id"), request.ID)...)
	response.Diagnostics.Append(response.State.SetAttribute(ctx, path.Root("service_id"), request.ID)...)
}
func (r *serviceTagsResource) put(ctx context.Context, model *serviceTagsModel, diagnostics *diag.Diagnostics) error {
	var ids []string
	diagnostics.Append(model.TagIDs.ElementsAs(ctx, &ids, false)...)
	if diagnostics.HasError() {
		return nil
	}
	_, err := call[struct {
		Items []tagResponse `json:"items"`
	}](ctx, r.client, http.MethodPut, "/v1/services/"+model.ServiceID.ValueString()+"/tags", map[string]any{"tagIds": ids})
	if err == nil {
		model.ID = types.StringValue(model.ServiceID.ValueString())
	}
	return err
}

var _ resource.ResourceWithConfigure = (*serviceTagsResource)(nil)
var _ resource.ResourceWithValidateConfig = (*serviceTagsResource)(nil)
var _ resource.ResourceWithImportState = (*serviceTagsResource)(nil)
