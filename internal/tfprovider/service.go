package tfprovider

import (
	"context"
	"net/http"
	"time"

	"github.com/bendahma/dokploy-go/internal/apiclient"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type serviceResource struct{ client *apiclient.Client }
type serviceModel struct {
	ID            types.String `tfsdk:"id"`
	EnvironmentID types.String `tfsdk:"environment_id"`
	Name          types.String `tfsdk:"name"`
	Slug          types.String `tfsdk:"slug"`
	ComposeYAML   types.String `tfsdk:"compose_yaml"`
	Environment   types.Map    `tfsdk:"environment"`
	Revision      types.Int64  `tfsdk:"revision"`
}
type serviceResponse struct {
	ID            string `json:"id"`
	EnvironmentID string `json:"environmentId"`
	Name          string `json:"name"`
	Slug          string `json:"slug"`
	ComposeYAML   string `json:"composeYaml"`
	Revision      int64  `json:"revision"`
}

func newServiceResource() resource.Resource { return &serviceResource{} }
func (r *serviceResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_service"
}
func (r *serviceResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	response.Schema = schema.Schema{Description: "A Docker Compose service deployed by Dockyard.", Attributes: map[string]schema.Attribute{
		"id":             schema.StringAttribute{Computed: true},
		"environment_id": schema.StringAttribute{Required: true, PlanModifiers: replace},
		"name":           schema.StringAttribute{Required: true, PlanModifiers: replace},
		"slug":           schema.StringAttribute{Optional: true, Computed: true, PlanModifiers: replace},
		"compose_yaml":   schema.StringAttribute{Required: true},
		"environment":    schema.MapAttribute{Optional: true, Sensitive: true, ElementType: types.StringType},
		"revision":       schema.Int64Attribute{Computed: true},
	}}
}
func (r *serviceResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	r.client = configureResource(request, &response.Diagnostics)
}
func (r *serviceResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var plan serviceModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	environment := map[string]string{}
	if !plan.Environment.IsNull() && !plan.Environment.IsUnknown() {
		response.Diagnostics.Append(plan.Environment.ElementsAs(ctx, &environment, false)...)
	}
	if response.Diagnostics.HasError() {
		return
	}
	item, err := call[serviceResponse](ctx, r.client, http.MethodPost, "/v1/environments/"+plan.EnvironmentID.ValueString()+"/services", map[string]any{"name": plan.Name.ValueString(), "slug": plan.Slug.ValueString(), "composeYaml": plan.ComposeYAML.ValueString(), "environment": environment})
	if err != nil {
		response.Diagnostics.AddError("Unable to create service", err.Error())
		return
	}
	setService(&plan, item)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}
func (r *serviceResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var state serviceModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	result, err := call[struct {
		Service serviceResponse `json:"service"`
	}](ctx, r.client, http.MethodGet, "/v1/services/"+state.ID.ValueString(), nil)
	if notFound(err) {
		response.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		response.Diagnostics.AddError("Unable to read service", err.Error())
		return
	}
	setService(&state, result.Service)
	response.Diagnostics.Append(response.State.Set(ctx, &state)...)
}
func (r *serviceResource) Update(ctx context.Context, request resource.UpdateRequest, response *resource.UpdateResponse) {
	var plan serviceModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	environment := map[string]string{}
	if !plan.Environment.IsNull() && !plan.Environment.IsUnknown() {
		response.Diagnostics.Append(plan.Environment.ElementsAs(ctx, &environment, false)...)
	}
	if response.Diagnostics.HasError() {
		return
	}
	item, err := call[serviceResponse](ctx, r.client, http.MethodPatch, "/v1/services/"+plan.ID.ValueString(), map[string]any{"composeYaml": plan.ComposeYAML.ValueString(), "environment": environment})
	if err != nil {
		response.Diagnostics.AddError("Unable to update service", err.Error())
		return
	}
	setService(&plan, item)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}
func (r *serviceResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var state serviceModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	servicePath := "/v1/services/" + state.ID.ValueString()
	_, err := call[struct{}](ctx, r.client, http.MethodDelete, servicePath, nil)
	if err != nil && !notFound(err) {
		response.Diagnostics.AddError("Unable to delete service", err.Error())
		return
	}
	if notFound(err) {
		return
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			response.Diagnostics.AddError("Timed out deleting service", ctx.Err().Error())
			return
		case <-ticker.C:
			_, err = call[struct {
				Service serviceResponse `json:"service"`
			}](ctx, r.client, http.MethodGet, servicePath, nil)
			if notFound(err) {
				return
			}
			if err != nil {
				response.Diagnostics.AddError("Unable to verify service deletion", err.Error())
				return
			}
		}
	}
}
func (r *serviceResource) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), request, response)
}
func setService(model *serviceModel, item serviceResponse) {
	model.ID = types.StringValue(item.ID)
	model.EnvironmentID = types.StringValue(item.EnvironmentID)
	model.Name = types.StringValue(item.Name)
	model.Slug = types.StringValue(item.Slug)
	model.ComposeYAML = types.StringValue(item.ComposeYAML)
	model.Revision = types.Int64Value(item.Revision)
}

var _ resource.ResourceWithConfigure = (*serviceResource)(nil)
var _ resource.ResourceWithImportState = (*serviceResource)(nil)
