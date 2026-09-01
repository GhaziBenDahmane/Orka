package tfprovider

import (
	"context"
	"net/http"
	"time"

	"github.com/GhaziBenDahmane/Orka/internal/apiclient"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type linkedDatabaseResource struct{ client *apiclient.Client }

type linkedDatabaseModel struct {
	ID                    types.String `tfsdk:"id"`
	ComposeServiceID      types.String `tfsdk:"compose_service_id"`
	Name                  types.String `tfsdk:"name"`
	Slug                  types.String `tfsdk:"slug"`
	Engine                types.String `tfsdk:"engine"`
	Version               types.String `tfsdk:"version"`
	ConnectionServiceName types.String `tfsdk:"connection_service_name"`
	Database              types.String `tfsdk:"database"`
	Username              types.String `tfsdk:"username"`
	Password              types.String `tfsdk:"password"`
	Port                  types.Int64  `tfsdk:"port"`
	Status                types.String `tfsdk:"status"`
}

type linkedDatabaseResponse struct {
	ID                    string         `json:"id"`
	ComposeServiceID      string         `json:"composeServiceId"`
	Name                  string         `json:"name"`
	Slug                  string         `json:"slug"`
	Engine                string         `json:"engine"`
	Version               string         `json:"version"`
	ManagementKind        string         `json:"managementKind"`
	ConnectionServiceName string         `json:"connectionServiceName"`
	Config                map[string]any `json:"config"`
	Status                string         `json:"status"`
}

func newLinkedDatabaseResource() resource.Resource { return &linkedDatabaseResource{} }

func (r *linkedDatabaseResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_linked_database"
}

func (r *linkedDatabaseResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	response.Schema = schema.Schema{Description: "An existing database service inside a Docker Compose workload, managed for backup and restore without owning its stack.", Attributes: map[string]schema.Attribute{
		"id":                      schema.StringAttribute{Computed: true},
		"compose_service_id":      schema.StringAttribute{Required: true, PlanModifiers: replace},
		"name":                    schema.StringAttribute{Required: true, PlanModifiers: replace},
		"slug":                    schema.StringAttribute{Computed: true},
		"engine":                  schema.StringAttribute{Required: true, PlanModifiers: replace},
		"version":                 schema.StringAttribute{Optional: true, Computed: true, Description: "Database utility version. The registered driver default is used when omitted."},
		"connection_service_name": schema.StringAttribute{Required: true, Description: "Service key declared in the owning Compose document."},
		"database":                schema.StringAttribute{Optional: true, Description: "Database name. Required for relational, MongoDB, libSQL, and external drivers that use named databases."},
		"username":                schema.StringAttribute{Optional: true, Description: "Database username. Required for engines that use user identities."},
		"password":                schema.StringAttribute{Required: true, Sensitive: true, Description: "Write-only database password retained only in sensitive Terraform state."},
		"port":                    schema.Int64Attribute{Optional: true, Description: "Optional container port override; zero uses the engine default."},
		"status":                  schema.StringAttribute{Computed: true},
	}}
}

func (r *linkedDatabaseResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	r.client = configureResource(request, &response.Diagnostics)
}

func (r *linkedDatabaseResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var plan linkedDatabaseModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := call[linkedDatabaseResponse](ctx, r.client, http.MethodPost, "/v1/services/"+plan.ComposeServiceID.ValueString()+"/databases", linkedDatabaseInput(plan))
	if err != nil {
		response.Diagnostics.AddError("Unable to link Compose database", err.Error())
		return
	}
	setLinkedDatabase(&plan, item)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *linkedDatabaseResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var state linkedDatabaseModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := call[linkedDatabaseResponse](ctx, r.client, http.MethodGet, "/v1/databases/"+state.ID.ValueString(), nil)
	if notFound(err) {
		response.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		response.Diagnostics.AddError("Unable to read linked database", err.Error())
		return
	}
	if item.ManagementKind != "compose" {
		response.Diagnostics.AddError("Database is not Compose-linked", "The remote database is managed as its own workload and cannot be adopted by dockyard_linked_database.")
		return
	}
	setLinkedDatabase(&state, item)
	response.Diagnostics.Append(response.State.Set(ctx, &state)...)
}

func (r *linkedDatabaseResource) Update(ctx context.Context, request resource.UpdateRequest, response *resource.UpdateResponse) {
	var plan linkedDatabaseModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := call[linkedDatabaseResponse](ctx, r.client, http.MethodPut, "/v1/databases/"+plan.ID.ValueString()+"/credentials", linkedDatabaseInput(plan))
	if err != nil {
		response.Diagnostics.AddError("Unable to rotate linked database credentials", err.Error())
		return
	}
	setLinkedDatabase(&plan, item)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *linkedDatabaseResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var state linkedDatabaseModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	path := "/v1/databases/" + state.ID.ValueString()
	_, err := call[struct{}](ctx, r.client, http.MethodDelete, path+"/link", nil)
	if err != nil && !notFound(err) {
		response.Diagnostics.AddError("Unable to unlink Compose database", err.Error())
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
			response.Diagnostics.AddError("Timed out unlinking Compose database", ctx.Err().Error())
			return
		case <-ticker.C:
			_, err = call[linkedDatabaseResponse](ctx, r.client, http.MethodGet, path, nil)
			if notFound(err) {
				return
			}
			if err != nil {
				response.Diagnostics.AddError("Unable to verify linked database removal", err.Error())
				return
			}
		}
	}
}

func (r *linkedDatabaseResource) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), request, response)
}

func linkedDatabaseInput(model linkedDatabaseModel) map[string]any {
	return map[string]any{"name": model.Name.ValueString(), "engine": model.Engine.ValueString(), "version": model.Version.ValueString(), "connectionServiceName": model.ConnectionServiceName.ValueString(), "database": model.Database.ValueString(), "username": model.Username.ValueString(), "password": model.Password.ValueString(), "port": model.Port.ValueInt64()}
}

func setLinkedDatabase(model *linkedDatabaseModel, item linkedDatabaseResponse) {
	model.ID = types.StringValue(item.ID)
	model.ComposeServiceID = types.StringValue(item.ComposeServiceID)
	model.Name = types.StringValue(item.Name)
	model.Slug = types.StringValue(item.Slug)
	model.Engine = types.StringValue(item.Engine)
	model.Version = types.StringValue(item.Version)
	model.ConnectionServiceName = types.StringValue(item.ConnectionServiceName)
	if value, ok := item.Config["database"].(string); ok {
		model.Database = types.StringValue(value)
	}
	if value, ok := item.Config["username"].(string); ok {
		model.Username = types.StringValue(value)
	}
	if value, ok := item.Config["port"].(float64); ok {
		model.Port = types.Int64Value(int64(value))
	}
	model.Status = types.StringValue(item.Status)
}

var _ resource.ResourceWithConfigure = (*linkedDatabaseResource)(nil)
var _ resource.ResourceWithImportState = (*linkedDatabaseResource)(nil)
