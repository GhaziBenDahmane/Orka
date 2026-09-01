package tfprovider

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/GhaziBenDahmane/Orka/internal/apiclient"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type volumeBackupPolicyResource struct{ client *apiclient.Client }

type volumeBackupPolicyModel struct {
	ID              types.String `tfsdk:"id"`
	ServiceID       types.String `tfsdk:"service_id"`
	VolumeName      types.String `tfsdk:"volume_name"`
	DestinationID   types.String `tfsdk:"destination_id"`
	IntervalSeconds types.Int64  `tfsdk:"interval_seconds"`
	RetentionCount  types.Int64  `tfsdk:"retention_count"`
	Quiesce         types.Bool   `tfsdk:"quiesce"`
	Enabled         types.Bool   `tfsdk:"enabled"`
}

type volumeBackupPolicyResponse struct {
	ID               string `json:"id"`
	ComposeServiceID string `json:"composeServiceId"`
	VolumeName       string `json:"volumeName"`
	DestinationID    string `json:"destinationId"`
	IntervalSeconds  int64  `json:"intervalSeconds"`
	RetentionCount   int64  `json:"retentionCount"`
	Quiesce          bool   `json:"quiesce"`
	Enabled          bool   `json:"enabled"`
}

func newVolumeBackupPolicyResource() resource.Resource { return &volumeBackupPolicyResource{} }

func (r *volumeBackupPolicyResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_volume_backup_policy"
}

func (r *volumeBackupPolicyResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	response.Schema = schema.Schema{Description: "A scheduled encrypted backup policy for a named Docker volume mounted by a Dockyard Compose service.", Attributes: map[string]schema.Attribute{
		"id":               schema.StringAttribute{Computed: true},
		"service_id":       schema.StringAttribute{Required: true, PlanModifiers: replace},
		"volume_name":      schema.StringAttribute{Required: true, PlanModifiers: replace},
		"destination_id":   schema.StringAttribute{Required: true},
		"interval_seconds": schema.Int64Attribute{Required: true},
		"retention_count":  schema.Int64Attribute{Required: true},
		"quiesce":          schema.BoolAttribute{Required: true},
		"enabled":          schema.BoolAttribute{Required: true},
	}}
}

func (r *volumeBackupPolicyResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	r.client = configureResource(request, &response.Diagnostics)
}

func (r *volumeBackupPolicyResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var plan volumeBackupPolicyModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := r.put(ctx, plan)
	if err != nil {
		response.Diagnostics.AddError("Unable to create volume backup policy", err.Error())
		return
	}
	setVolumeBackupPolicy(&plan, item)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *volumeBackupPolicyResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var state volumeBackupPolicyModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	result, err := call[struct {
		Items []volumeBackupPolicyResponse `json:"items"`
	}](ctx, r.client, http.MethodGet, "/v1/services/"+state.ServiceID.ValueString()+"/volume-backup-policies", nil)
	if notFound(err) {
		response.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		response.Diagnostics.AddError("Unable to read volume backup policy", err.Error())
		return
	}
	for _, item := range result.Items {
		if item.VolumeName == state.VolumeName.ValueString() {
			setVolumeBackupPolicy(&state, item)
			response.Diagnostics.Append(response.State.Set(ctx, &state)...)
			return
		}
	}
	response.State.RemoveResource(ctx)
}

func (r *volumeBackupPolicyResource) Update(ctx context.Context, request resource.UpdateRequest, response *resource.UpdateResponse) {
	var plan volumeBackupPolicyModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := r.put(ctx, plan)
	if err != nil {
		response.Diagnostics.AddError("Unable to update volume backup policy", err.Error())
		return
	}
	setVolumeBackupPolicy(&plan, item)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *volumeBackupPolicyResource) put(ctx context.Context, model volumeBackupPolicyModel) (volumeBackupPolicyResponse, error) {
	body := map[string]any{
		"destinationId":   model.DestinationID.ValueString(),
		"intervalSeconds": model.IntervalSeconds.ValueInt64(),
		"retentionCount":  model.RetentionCount.ValueInt64(),
		"quiesce":         model.Quiesce.ValueBool(),
		"enabled":         model.Enabled.ValueBool(),
	}
	return call[volumeBackupPolicyResponse](ctx, r.client, http.MethodPut, volumeBackupPolicyPath(model.ServiceID.ValueString(), model.VolumeName.ValueString()), body)
}

func (r *volumeBackupPolicyResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var state volumeBackupPolicyModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	_, err := call[struct{}](ctx, r.client, http.MethodDelete, volumeBackupPolicyPath(state.ServiceID.ValueString(), state.VolumeName.ValueString()), nil)
	if err != nil && !notFound(err) {
		response.Diagnostics.AddError("Unable to delete volume backup policy", err.Error())
	}
}

func (r *volumeBackupPolicyResource) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	serviceID, volumeName, err := splitVolumeBackupPolicyImportID(request.ID)
	if err != nil {
		response.Diagnostics.AddError("Invalid volume backup policy import ID", err.Error())
		return
	}
	response.Diagnostics.Append(response.State.SetAttribute(ctx, path.Root("service_id"), serviceID)...)
	response.Diagnostics.Append(response.State.SetAttribute(ctx, path.Root("volume_name"), volumeName)...)
}

func volumeBackupPolicyPath(serviceID, volumeName string) string {
	return "/v1/services/" + serviceID + "/volume-backup-policies/" + url.PathEscape(volumeName)
}

func splitVolumeBackupPolicyImportID(id string) (string, string, error) {
	serviceID, volumeName, ok := strings.Cut(id, "/")
	if !ok || volumeName == "" || strings.Contains(volumeName, "/") {
		return "", "", fmt.Errorf("expected SERVICE_UUID/VOLUME_NAME")
	}
	if _, err := uuid.Parse(serviceID); err != nil {
		return "", "", fmt.Errorf("service ID must be a UUID: %w", err)
	}
	return serviceID, volumeName, nil
}

func setVolumeBackupPolicy(model *volumeBackupPolicyModel, item volumeBackupPolicyResponse) {
	model.ID = types.StringValue(item.ID)
	model.ServiceID = types.StringValue(item.ComposeServiceID)
	model.VolumeName = types.StringValue(item.VolumeName)
	model.DestinationID = types.StringValue(item.DestinationID)
	model.IntervalSeconds = types.Int64Value(item.IntervalSeconds)
	model.RetentionCount = types.Int64Value(item.RetentionCount)
	model.Quiesce = types.BoolValue(item.Quiesce)
	model.Enabled = types.BoolValue(item.Enabled)
}

var _ resource.ResourceWithConfigure = (*volumeBackupPolicyResource)(nil)
var _ resource.ResourceWithImportState = (*volumeBackupPolicyResource)(nil)
