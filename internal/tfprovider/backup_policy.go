package tfprovider

import (
	"context"
	"net/http"

	"github.com/GhaziBenDahmane/Orka/internal/apiclient"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type backupPolicyResource struct{ client *apiclient.Client }

type backupPolicyModel struct {
	ID              types.String `tfsdk:"id"`
	DatabaseID      types.String `tfsdk:"database_id"`
	IntervalSeconds types.Int64  `tfsdk:"interval_seconds"`
	RetentionCount  types.Int64  `tfsdk:"retention_count"`
	Enabled         types.Bool   `tfsdk:"enabled"`
	VerifyRestore   types.Bool   `tfsdk:"verify_restore"`
	DestinationID   types.String `tfsdk:"destination_id"`
}

type backupPolicyResponse struct {
	ID                 string  `json:"id"`
	DatabaseInstanceID string  `json:"databaseInstanceId"`
	IntervalSeconds    int64   `json:"intervalSeconds"`
	RetentionCount     int64   `json:"retentionCount"`
	Enabled            bool    `json:"enabled"`
	VerifyRestore      bool    `json:"verifyRestore"`
	DestinationID      *string `json:"destinationId"`
}

func newBackupPolicyResource() resource.Resource { return &backupPolicyResource{} }

func (r *backupPolicyResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_backup_policy"
}

func (r *backupPolicyResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	response.Schema = schema.Schema{Description: "A scheduled native backup policy for a Dockyard database.", Attributes: map[string]schema.Attribute{
		"id":               schema.StringAttribute{Computed: true},
		"database_id":      schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"interval_seconds": schema.Int64Attribute{Required: true},
		"retention_count":  schema.Int64Attribute{Required: true},
		"enabled":          schema.BoolAttribute{Required: true},
		"verify_restore":   schema.BoolAttribute{Required: true},
		"destination_id":   schema.StringAttribute{Optional: true},
	}}
}

func (r *backupPolicyResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	r.client = configureResource(request, &response.Diagnostics)
}

func (r *backupPolicyResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var plan backupPolicyModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := r.put(ctx, plan)
	if err != nil {
		response.Diagnostics.AddError("Unable to create backup policy", err.Error())
		return
	}
	setBackupPolicy(&plan, item)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *backupPolicyResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var state backupPolicyModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := call[backupPolicyResponse](ctx, r.client, http.MethodGet, "/v1/databases/"+state.DatabaseID.ValueString()+"/backup-policy", nil)
	if notFound(err) {
		response.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		response.Diagnostics.AddError("Unable to read backup policy", err.Error())
		return
	}
	setBackupPolicy(&state, item)
	response.Diagnostics.Append(response.State.Set(ctx, &state)...)
}

func (r *backupPolicyResource) Update(ctx context.Context, request resource.UpdateRequest, response *resource.UpdateResponse) {
	var plan backupPolicyModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := r.put(ctx, plan)
	if err != nil {
		response.Diagnostics.AddError("Unable to update backup policy", err.Error())
		return
	}
	setBackupPolicy(&plan, item)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *backupPolicyResource) put(ctx context.Context, model backupPolicyModel) (backupPolicyResponse, error) {
	body := map[string]any{
		"intervalSeconds": model.IntervalSeconds.ValueInt64(),
		"retentionCount":  model.RetentionCount.ValueInt64(),
		"enabled":         model.Enabled.ValueBool(),
		"verifyRestore":   model.VerifyRestore.ValueBool(),
	}
	if !model.DestinationID.IsNull() && !model.DestinationID.IsUnknown() {
		body["destinationId"] = model.DestinationID.ValueString()
	}
	return call[backupPolicyResponse](ctx, r.client, http.MethodPut, "/v1/databases/"+model.DatabaseID.ValueString()+"/backup-policy", body)
}

func (r *backupPolicyResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var state backupPolicyModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	_, err := call[struct{}](ctx, r.client, http.MethodDelete, "/v1/databases/"+state.DatabaseID.ValueString()+"/backup-policy", nil)
	if err != nil && !notFound(err) {
		response.Diagnostics.AddError("Unable to delete backup policy", err.Error())
	}
}

func (r *backupPolicyResource) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	response.Diagnostics.Append(response.State.SetAttribute(ctx, path.Root("database_id"), request.ID)...)
}

func setBackupPolicy(model *backupPolicyModel, item backupPolicyResponse) {
	model.ID = types.StringValue(item.ID)
	model.DatabaseID = types.StringValue(item.DatabaseInstanceID)
	model.IntervalSeconds = types.Int64Value(item.IntervalSeconds)
	model.RetentionCount = types.Int64Value(item.RetentionCount)
	model.Enabled = types.BoolValue(item.Enabled)
	model.VerifyRestore = types.BoolValue(item.VerifyRestore)
	if item.DestinationID == nil {
		model.DestinationID = types.StringNull()
	} else {
		model.DestinationID = types.StringValue(*item.DestinationID)
	}
}

var _ resource.ResourceWithConfigure = (*backupPolicyResource)(nil)
var _ resource.ResourceWithImportState = (*backupPolicyResource)(nil)
