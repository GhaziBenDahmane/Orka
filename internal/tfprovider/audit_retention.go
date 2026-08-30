package tfprovider

import (
	"context"
	"net/http"

	"github.com/bendahma/dokploy-go/internal/apiclient"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type auditRetentionResource struct{ client *apiclient.Client }

type auditRetentionModel struct {
	ID            types.String `tfsdk:"id"`
	RetentionDays types.Int64  `tfsdk:"retention_days"`
	UpdatedAt     types.String `tfsdk:"updated_at"`
}

type auditRetentionResponse struct {
	OrganizationID string `json:"organizationId"`
	RetentionDays  int64  `json:"retentionDays"`
	UpdatedAt      string `json:"updatedAt"`
}

func newAuditRetentionResource() resource.Resource { return &auditRetentionResource{} }

func (r *auditRetentionResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_audit_retention"
}

func (r *auditRetentionResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	response.Schema = schema.Schema{Description: "The organization audit-event retention policy.", Attributes: map[string]schema.Attribute{
		"id":             schema.StringAttribute{Computed: true, Description: "Organization ID."},
		"retention_days": schema.Int64Attribute{Required: true, Description: "Retain audit events and completed AI audit runs for 30 to 3650 days."},
		"updated_at":     schema.StringAttribute{Computed: true},
	}}
}

func (r *auditRetentionResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	r.client = configureResource(request, &response.Diagnostics)
}

func (r *auditRetentionResource) ValidateConfig(ctx context.Context, request resource.ValidateConfigRequest, response *resource.ValidateConfigResponse) {
	var config auditRetentionModel
	response.Diagnostics.Append(request.Config.Get(ctx, &config)...)
	if response.Diagnostics.HasError() || config.RetentionDays.IsNull() || config.RetentionDays.IsUnknown() {
		return
	}
	if days := config.RetentionDays.ValueInt64(); days < 30 || days > 3650 {
		response.Diagnostics.AddAttributeError(path.Root("retention_days"), "Invalid audit retention", "retention_days must be from 30 to 3650.")
	}
}

func (r *auditRetentionResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var plan auditRetentionModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := r.put(ctx, plan.RetentionDays.ValueInt64())
	if err != nil {
		response.Diagnostics.AddError("Unable to update audit retention", err.Error())
		return
	}
	setAuditRetention(&plan, item)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *auditRetentionResource) Read(ctx context.Context, _ resource.ReadRequest, response *resource.ReadResponse) {
	item, err := call[auditRetentionResponse](ctx, r.client, http.MethodGet, "/v1/audit-retention", nil)
	if err != nil {
		response.Diagnostics.AddError("Unable to read audit retention", err.Error())
		return
	}
	state := auditRetentionModel{}
	setAuditRetention(&state, item)
	response.Diagnostics.Append(response.State.Set(ctx, &state)...)
}

func (r *auditRetentionResource) Update(ctx context.Context, request resource.UpdateRequest, response *resource.UpdateResponse) {
	var plan auditRetentionModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := r.put(ctx, plan.RetentionDays.ValueInt64())
	if err != nil {
		response.Diagnostics.AddError("Unable to update audit retention", err.Error())
		return
	}
	setAuditRetention(&plan, item)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *auditRetentionResource) Delete(ctx context.Context, _ resource.DeleteRequest, response *resource.DeleteResponse) {
	_, err := call[auditRetentionResponse](ctx, r.client, http.MethodPut, "/v1/audit-retention", map[string]int64{"retentionDays": 365})
	if err != nil {
		response.Diagnostics.AddError("Unable to reset audit retention", err.Error())
	}
}

func (r *auditRetentionResource) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), request, response)
}

func (r *auditRetentionResource) put(ctx context.Context, retentionDays int64) (auditRetentionResponse, error) {
	return call[auditRetentionResponse](ctx, r.client, http.MethodPut, "/v1/audit-retention", map[string]int64{"retentionDays": retentionDays})
}

func setAuditRetention(model *auditRetentionModel, item auditRetentionResponse) {
	model.ID = types.StringValue(item.OrganizationID)
	model.RetentionDays = types.Int64Value(item.RetentionDays)
	model.UpdatedAt = types.StringValue(item.UpdatedAt)
}

var _ resource.ResourceWithConfigure = (*auditRetentionResource)(nil)
var _ resource.ResourceWithValidateConfig = (*auditRetentionResource)(nil)
var _ resource.ResourceWithImportState = (*auditRetentionResource)(nil)
