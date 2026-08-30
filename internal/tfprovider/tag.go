package tfprovider

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/bendahma/dokploy-go/internal/apiclient"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type tagResource struct{ client *apiclient.Client }

type tagModel struct {
	ID           types.String `tfsdk:"id"`
	Name         types.String `tfsdk:"name"`
	Color        types.String `tfsdk:"color"`
	ServiceCount types.Int64  `tfsdk:"service_count"`
	CreatedAt    types.String `tfsdk:"created_at"`
	UpdatedAt    types.String `tfsdk:"updated_at"`
}

type tagResponse struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Color        string `json:"color"`
	ServiceCount int64  `json:"serviceCount"`
	CreatedAt    string `json:"createdAt"`
	UpdatedAt    string `json:"updatedAt"`
}

func newTagResource() resource.Resource { return &tagResource{} }

func (r *tagResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_tag"
}

func (r *tagResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	response.Schema = schema.Schema{Description: "A reusable organization-scoped service tag.", Attributes: map[string]schema.Attribute{
		"id":            schema.StringAttribute{Computed: true},
		"name":          schema.StringAttribute{Required: true},
		"color":         schema.StringAttribute{Required: true, Description: "Six-digit hexadecimal color such as #2563EB."},
		"service_count": schema.Int64Attribute{Computed: true},
		"created_at":    schema.StringAttribute{Computed: true},
		"updated_at":    schema.StringAttribute{Computed: true},
	}}
}

func (r *tagResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	r.client = configureResource(request, &response.Diagnostics)
}

func (r *tagResource) ValidateConfig(ctx context.Context, request resource.ValidateConfigRequest, response *resource.ValidateConfigResponse) {
	var config tagModel
	response.Diagnostics.Append(request.Config.Get(ctx, &config)...)
	if response.Diagnostics.HasError() {
		return
	}
	if !config.Name.IsNull() && !config.Name.IsUnknown() {
		name := config.Name.ValueString()
		if name != strings.TrimSpace(name) || name == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > 64 || strings.ContainsAny(name, "\x00\r\n\t") {
			response.Diagnostics.AddAttributeError(path.Root("name"), "Invalid tag name", "name must be 1-64 trimmed characters without control whitespace.")
		}
	}
	if !config.Color.IsNull() && !config.Color.IsUnknown() && !regexp.MustCompile(`^#[0-9A-Fa-f]{6}$`).MatchString(config.Color.ValueString()) {
		response.Diagnostics.AddAttributeError(path.Root("color"), "Invalid tag color", "color must be a six-digit hexadecimal value such as #2563EB.")
	}
}

func (r *tagResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var plan tagModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := call[tagResponse](ctx, r.client, http.MethodPost, "/v1/tags", map[string]string{"name": plan.Name.ValueString(), "color": plan.Color.ValueString()})
	if err != nil {
		response.Diagnostics.AddError("Unable to create tag", err.Error())
		return
	}
	setTag(&plan, item)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *tagResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var state tagModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := call[tagResponse](ctx, r.client, http.MethodGet, "/v1/tags/"+state.ID.ValueString(), nil)
	if notFound(err) {
		response.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		response.Diagnostics.AddError("Unable to read tag", err.Error())
		return
	}
	setTag(&state, item)
	response.Diagnostics.Append(response.State.Set(ctx, &state)...)
}

func (r *tagResource) Update(ctx context.Context, request resource.UpdateRequest, response *resource.UpdateResponse) {
	var plan tagModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := call[tagResponse](ctx, r.client, http.MethodPut, "/v1/tags/"+plan.ID.ValueString(), map[string]string{"name": plan.Name.ValueString(), "color": plan.Color.ValueString()})
	if err != nil {
		response.Diagnostics.AddError("Unable to update tag", err.Error())
		return
	}
	setTag(&plan, item)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *tagResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var state tagModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	_, err := call[struct{}](ctx, r.client, http.MethodDelete, "/v1/tags/"+state.ID.ValueString(), nil)
	if err != nil && !notFound(err) {
		response.Diagnostics.AddError("Unable to delete tag", err.Error())
	}
}

func (r *tagResource) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), request, response)
}

func setTag(model *tagModel, item tagResponse) {
	model.ID, model.Name, model.Color = types.StringValue(item.ID), types.StringValue(item.Name), types.StringValue(item.Color)
	model.ServiceCount = types.Int64Value(item.ServiceCount)
	model.CreatedAt, model.UpdatedAt = types.StringValue(item.CreatedAt), types.StringValue(item.UpdatedAt)
}

var _ resource.ResourceWithConfigure = (*tagResource)(nil)
var _ resource.ResourceWithValidateConfig = (*tagResource)(nil)
var _ resource.ResourceWithImportState = (*tagResource)(nil)
