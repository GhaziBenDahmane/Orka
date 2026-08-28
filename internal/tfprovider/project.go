package tfprovider

import (
	"context"
	"fmt"
	"net/http"

	"github.com/bendahma/dokploy-go/internal/apiclient"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type projectResource struct{ client *apiclient.Client }
type projectModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Slug        types.String `tfsdk:"slug"`
	Description types.String `tfsdk:"description"`
}
type projectResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Description string `json:"description"`
}

func newProjectResource() resource.Resource { return &projectResource{} }
func (r *projectResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_project"
}
func (r *projectResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	response.Schema = schema.Schema{Description: "A Dockyard project.", Attributes: map[string]schema.Attribute{
		"id": schema.StringAttribute{Computed: true}, "name": schema.StringAttribute{Required: true, PlanModifiers: replace},
		"slug": schema.StringAttribute{Optional: true, Computed: true, PlanModifiers: replace}, "description": schema.StringAttribute{Optional: true, PlanModifiers: replace},
	}}
}
func (r *projectResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	r.client = configureResource(request, &response.Diagnostics)
}
func (r *projectResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var plan projectModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := call[projectResponse](ctx, r.client, http.MethodPost, "/v1/projects", map[string]string{"name": plan.Name.ValueString(), "slug": plan.Slug.ValueString(), "description": plan.Description.ValueString()})
	if err != nil {
		response.Diagnostics.AddError("Unable to create project", err.Error())
		return
	}
	setProject(&plan, item)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}
func (r *projectResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var state projectModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := call[projectResponse](ctx, r.client, http.MethodGet, "/v1/projects/"+state.ID.ValueString(), nil)
	if notFound(err) {
		response.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		response.Diagnostics.AddError("Unable to read project", err.Error())
		return
	}
	setProject(&state, item)
	response.Diagnostics.Append(response.State.Set(ctx, &state)...)
}
func (r *projectResource) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {}
func (r *projectResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var state projectModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	_, err := call[struct{}](ctx, r.client, http.MethodDelete, "/v1/projects/"+state.ID.ValueString(), nil)
	if err != nil && !notFound(err) {
		response.Diagnostics.AddError("Unable to delete project", fmt.Sprintf("%v. Remove environments first.", err))
	}
}
func (r *projectResource) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), request, response)
}
func setProject(model *projectModel, item projectResponse) {
	model.ID = types.StringValue(item.ID)
	model.Name = types.StringValue(item.Name)
	model.Slug = types.StringValue(item.Slug)
	model.Description = types.StringValue(item.Description)
}

var _ resource.ResourceWithConfigure = (*projectResource)(nil)
var _ resource.ResourceWithImportState = (*projectResource)(nil)
