package tfprovider

import (
	"context"
	"fmt"
	"net/http"
	pathpkg "path"
	"strings"

	"github.com/GhaziBenDahmane/Orka/internal/apiclient"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type auditArchiveResource struct{ client *apiclient.Client }

type auditArchiveModel struct {
	ID                  types.String `tfsdk:"id"`
	Name                types.String `tfsdk:"name"`
	BackupDestinationID types.String `tfsdk:"backup_destination_id"`
	ObjectPrefix        types.String `tfsdk:"object_prefix"`
	RetentionDays       types.Int64  `tfsdk:"retention_days"`
	Enabled             types.Bool   `tfsdk:"enabled"`
	LastArchivedID      types.Int64  `tfsdk:"last_archived_id"`
	LastChainHash       types.String `tfsdk:"last_chain_hash"`
	CreatedAt           types.String `tfsdk:"created_at"`
	UpdatedAt           types.String `tfsdk:"updated_at"`
}

type auditArchiveResponse struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	BackupDestinationID string `json:"backupDestinationId"`
	ObjectPrefix        string `json:"objectPrefix"`
	RetentionDays       int64  `json:"retentionDays"`
	Enabled             bool   `json:"enabled"`
	LastArchivedID      int64  `json:"lastArchivedId"`
	LastChainHash       string `json:"lastChainHash"`
	CreatedAt           string `json:"createdAt"`
	UpdatedAt           string `json:"updatedAt"`
}

func newAuditArchiveResource() resource.Resource { return &auditArchiveResource{} }

func (r *auditArchiveResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_audit_archive"
}

func (r *auditArchiveResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	stringReplace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	response.Schema = schema.Schema{Description: "An immutable, hash-chained audit archive in a TLS S3 Object Lock destination.", Attributes: map[string]schema.Attribute{
		"id":                    schema.StringAttribute{Computed: true},
		"name":                  schema.StringAttribute{Required: true, PlanModifiers: stringReplace},
		"backup_destination_id": schema.StringAttribute{Required: true, PlanModifiers: stringReplace, Description: "TLS S3 backup destination with Object Lock enabled."},
		"object_prefix":         schema.StringAttribute{Required: true, PlanModifiers: stringReplace},
		"retention_days":        schema.Int64Attribute{Required: true, PlanModifiers: []planmodifier.Int64{int64planmodifier.RequiresReplace()}, Description: "S3 COMPLIANCE retention from 30 to 3650 days."},
		"enabled":               schema.BoolAttribute{Computed: true},
		"last_archived_id":      schema.Int64Attribute{Computed: true},
		"last_chain_hash":       schema.StringAttribute{Computed: true},
		"created_at":            schema.StringAttribute{Computed: true},
		"updated_at":            schema.StringAttribute{Computed: true},
	}}
}

func (r *auditArchiveResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	r.client = configureResource(request, &response.Diagnostics)
}

func (r *auditArchiveResource) ValidateConfig(ctx context.Context, request resource.ValidateConfigRequest, response *resource.ValidateConfigResponse) {
	var config auditArchiveModel
	response.Diagnostics.Append(request.Config.Get(ctx, &config)...)
	if response.Diagnostics.HasError() {
		return
	}
	if !config.Name.IsNull() && !config.Name.IsUnknown() && (config.Name.ValueString() == "" || strings.TrimSpace(config.Name.ValueString()) != config.Name.ValueString()) {
		response.Diagnostics.AddAttributeError(path.Root("name"), "Invalid audit archive name", "name must be non-empty and must not have leading or trailing whitespace.")
	}
	if !config.BackupDestinationID.IsNull() && !config.BackupDestinationID.IsUnknown() {
		if id, err := uuid.Parse(config.BackupDestinationID.ValueString()); err != nil || id == uuid.Nil {
			response.Diagnostics.AddAttributeError(path.Root("backup_destination_id"), "Invalid backup destination ID", "backup_destination_id must be a UUID.")
		}
	}
	if !config.ObjectPrefix.IsNull() && !config.ObjectPrefix.IsUnknown() {
		if err := validateAuditArchivePrefix(config.ObjectPrefix.ValueString()); err != nil {
			response.Diagnostics.AddAttributeError(path.Root("object_prefix"), "Invalid audit archive prefix", err.Error())
		}
	}
	if !config.RetentionDays.IsNull() && !config.RetentionDays.IsUnknown() {
		if days := config.RetentionDays.ValueInt64(); days < 30 || days > 3650 {
			response.Diagnostics.AddAttributeError(path.Root("retention_days"), "Invalid audit archive retention", "retention_days must be from 30 to 3650.")
		}
	}
}

func (r *auditArchiveResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var plan auditArchiveModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := call[auditArchiveResponse](ctx, r.client, http.MethodPost, "/v1/audit-archives", map[string]any{
		"name": plan.Name.ValueString(), "backupDestinationId": plan.BackupDestinationID.ValueString(), "objectPrefix": plan.ObjectPrefix.ValueString(), "retentionDays": plan.RetentionDays.ValueInt64(),
	})
	if err != nil {
		response.Diagnostics.AddError("Unable to create audit archive", err.Error())
		return
	}
	setAuditArchive(&plan, item)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *auditArchiveResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var state auditArchiveModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := call[auditArchiveResponse](ctx, r.client, http.MethodGet, "/v1/audit-archives/"+state.ID.ValueString(), nil)
	if err != nil {
		if notFound(err) {
			response.State.RemoveResource(ctx)
			return
		}
		response.Diagnostics.AddError("Unable to read audit archive", err.Error())
		return
	}
	if !item.Enabled {
		response.State.RemoveResource(ctx)
		return
	}
	setAuditArchive(&state, item)
	response.Diagnostics.Append(response.State.Set(ctx, &state)...)
}

func (r *auditArchiveResource) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {
}

func (r *auditArchiveResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var state auditArchiveModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	_, err := call[struct{}](ctx, r.client, http.MethodDelete, "/v1/audit-archives/"+state.ID.ValueString(), nil)
	if err != nil && !notFound(err) {
		response.Diagnostics.AddError("Unable to disable audit archive", err.Error())
	}
}

func (r *auditArchiveResource) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), request, response)
}

func setAuditArchive(model *auditArchiveModel, item auditArchiveResponse) {
	model.ID = types.StringValue(item.ID)
	model.Name = types.StringValue(item.Name)
	model.BackupDestinationID = types.StringValue(item.BackupDestinationID)
	model.ObjectPrefix = types.StringValue(item.ObjectPrefix)
	model.RetentionDays = types.Int64Value(item.RetentionDays)
	model.Enabled = types.BoolValue(item.Enabled)
	model.LastArchivedID = types.Int64Value(item.LastArchivedID)
	model.LastChainHash = types.StringValue(item.LastChainHash)
	model.CreatedAt = types.StringValue(item.CreatedAt)
	model.UpdatedAt = types.StringValue(item.UpdatedAt)
}

func validateAuditArchivePrefix(prefix string) error {
	if prefix == "" || len(prefix) > 200 || strings.TrimSpace(prefix) != prefix || strings.Trim(prefix, "/") != prefix || pathpkg.Clean(prefix) != prefix || strings.Contains(prefix, "..") {
		return fmt.Errorf("object_prefix must be a non-empty, normalized relative object prefix without '..'")
	}
	return nil
}

var _ resource.ResourceWithConfigure = (*auditArchiveResource)(nil)
var _ resource.ResourceWithValidateConfig = (*auditArchiveResource)(nil)
var _ resource.ResourceWithImportState = (*auditArchiveResource)(nil)
