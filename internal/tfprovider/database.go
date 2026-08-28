package tfprovider

import (
	"context"
	"encoding/json"
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

type databaseResource struct{ client *apiclient.Client }

type databaseModel struct {
	ID               types.String `tfsdk:"id"`
	EnvironmentID    types.String `tfsdk:"environment_id"`
	ComposeServiceID types.String `tfsdk:"compose_service_id"`
	Name             types.String `tfsdk:"name"`
	Slug             types.String `tfsdk:"slug"`
	Engine           types.String `tfsdk:"engine"`
	Version          types.String `tfsdk:"version"`
	ConfigJSON       types.String `tfsdk:"config_json"`
	Status           types.String `tfsdk:"status"`
}

type databaseResponse struct {
	ID               string         `json:"id"`
	EnvironmentID    string         `json:"environmentId"`
	ComposeServiceID string         `json:"composeServiceId"`
	Name             string         `json:"name"`
	Slug             string         `json:"slug"`
	Engine           string         `json:"engine"`
	Version          string         `json:"version"`
	Config           map[string]any `json:"config"`
	Status           string         `json:"status"`
}

func newDatabaseResource() resource.Resource { return &databaseResource{} }

func (r *databaseResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_database"
}

func (r *databaseResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	response.Schema = schema.Schema{Description: "A managed database running as a Docker Compose workload on Swarm.", Attributes: map[string]schema.Attribute{
		"id":                 schema.StringAttribute{Computed: true},
		"environment_id":     schema.StringAttribute{Required: true, PlanModifiers: replace},
		"compose_service_id": schema.StringAttribute{Computed: true},
		"name":               schema.StringAttribute{Required: true, PlanModifiers: replace},
		"slug":               schema.StringAttribute{Optional: true, Computed: true, PlanModifiers: replace},
		"engine":             schema.StringAttribute{Required: true, PlanModifiers: replace},
		"version":            schema.StringAttribute{Required: true, PlanModifiers: replace},
		"config_json":        schema.StringAttribute{Optional: true, Sensitive: true, PlanModifiers: replace, Description: "JSON driver configuration. Secrets are sent once and retained only in sensitive Terraform state."},
		"status":             schema.StringAttribute{Computed: true},
	}}
}

func (r *databaseResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	r.client = configureResource(request, &response.Diagnostics)
}

func (r *databaseResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var plan databaseModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	config := map[string]any{}
	if !plan.ConfigJSON.IsNull() && !plan.ConfigJSON.IsUnknown() && plan.ConfigJSON.ValueString() != "" {
		if err := json.Unmarshal([]byte(plan.ConfigJSON.ValueString()), &config); err != nil {
			response.Diagnostics.AddError("Invalid database config_json", err.Error())
			return
		}
	} else {
		plan.ConfigJSON = types.StringValue("{}")
	}
	result, err := call[struct {
		Database databaseResponse `json:"database"`
	}](ctx, r.client, http.MethodPost, "/v1/environments/"+plan.EnvironmentID.ValueString()+"/databases", map[string]any{"name": plan.Name.ValueString(), "slug": plan.Slug.ValueString(), "engine": plan.Engine.ValueString(), "version": plan.Version.ValueString(), "config": config})
	if err != nil {
		response.Diagnostics.AddError("Unable to create database", err.Error())
		return
	}
	setDatabase(&plan, result.Database)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *databaseResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var state databaseModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := call[databaseResponse](ctx, r.client, http.MethodGet, "/v1/databases/"+state.ID.ValueString(), nil)
	if notFound(err) {
		response.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		response.Diagnostics.AddError("Unable to read database", err.Error())
		return
	}
	setDatabase(&state, item)
	if state.ConfigJSON.IsNull() || state.ConfigJSON.IsUnknown() {
		data, marshalErr := json.Marshal(item.Config)
		if marshalErr != nil {
			response.Diagnostics.AddError("Unable to decode database configuration", marshalErr.Error())
			return
		}
		state.ConfigJSON = types.StringValue(string(data))
	}
	response.Diagnostics.Append(response.State.Set(ctx, &state)...)
}

func (r *databaseResource) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {
}

func (r *databaseResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var state databaseModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	path := "/v1/databases/" + state.ID.ValueString()
	_, err := call[struct{}](ctx, r.client, http.MethodDelete, path, nil)
	if err != nil && !notFound(err) {
		response.Diagnostics.AddError("Unable to delete database", err.Error())
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
			response.Diagnostics.AddError("Timed out deleting database", ctx.Err().Error())
			return
		case <-ticker.C:
			_, err = call[databaseResponse](ctx, r.client, http.MethodGet, path, nil)
			if notFound(err) {
				return
			}
			if err != nil {
				response.Diagnostics.AddError("Unable to verify database deletion", err.Error())
				return
			}
		}
	}
}

func (r *databaseResource) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), request, response)
}

func setDatabase(model *databaseModel, item databaseResponse) {
	model.ID = types.StringValue(item.ID)
	model.EnvironmentID = types.StringValue(item.EnvironmentID)
	model.ComposeServiceID = types.StringValue(item.ComposeServiceID)
	model.Name = types.StringValue(item.Name)
	model.Slug = types.StringValue(item.Slug)
	model.Engine = types.StringValue(item.Engine)
	model.Version = types.StringValue(item.Version)
	model.Status = types.StringValue(item.Status)
}

var _ resource.ResourceWithConfigure = (*databaseResource)(nil)
var _ resource.ResourceWithImportState = (*databaseResource)(nil)
