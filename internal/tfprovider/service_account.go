package tfprovider

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/GhaziBenDahmane/Orka/internal/apiclient"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type serviceAccountResource struct{ client *apiclient.Client }

type serviceAccountModel struct {
	ID              types.String `tfsdk:"id"`
	Name            types.String `tfsdk:"name"`
	Role            types.String `tfsdk:"role"`
	ExpiresInDays   types.Int64  `tfsdk:"expires_in_days"`
	RenewBeforeDays types.Int64  `tfsdk:"renew_before_days"`
	Token           types.String `tfsdk:"token"`
	Enabled         types.Bool   `tfsdk:"enabled"`
	TokenExpiresAt  types.String `tfsdk:"token_expires_at"`
	LastUsedAt      types.String `tfsdk:"last_used_at"`
	CreatedAt       types.String `tfsdk:"created_at"`
	UpdatedAt       types.String `tfsdk:"updated_at"`
}

type serviceAccountResponse struct {
	ID             string  `json:"id"`
	Name           string  `json:"name"`
	Role           string  `json:"role"`
	Enabled        bool    `json:"enabled"`
	TokenExpiresAt *string `json:"tokenExpiresAt"`
	LastUsedAt     *string `json:"lastUsedAt"`
	CreatedAt      string  `json:"createdAt"`
	UpdatedAt      string  `json:"updatedAt"`
}

func newServiceAccountResource() resource.Resource { return &serviceAccountResource{} }

func (r *serviceAccountResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_service_account"
}

func (r *serviceAccountResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	stringReplace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	intReplace := []planmodifier.Int64{int64planmodifier.RequiresReplace()}
	response.Schema = schema.Schema{Description: "An expiring organization-scoped automation identity. Replacement creates a new credential and disables the previous identity.", Attributes: map[string]schema.Attribute{
		"id":                schema.StringAttribute{Computed: true},
		"name":              schema.StringAttribute{Required: true, PlanModifiers: stringReplace},
		"role":              schema.StringAttribute{Required: true, PlanModifiers: stringReplace, Description: "One of viewer, developer, admin, or auditor."},
		"expires_in_days":   schema.Int64Attribute{Required: true, PlanModifiers: intReplace, Description: "Credential lifetime from 1 to 365 days."},
		"renew_before_days": schema.Int64Attribute{Required: true, PlanModifiers: intReplace, Description: "Replace the identity when fewer than this many days remain."},
		"token":             schema.StringAttribute{Computed: true, Sensitive: true, Description: "The bearer token returned once at creation and retained only in sensitive state."},
		"enabled":           schema.BoolAttribute{Computed: true},
		"token_expires_at":  schema.StringAttribute{Computed: true},
		"last_used_at":      schema.StringAttribute{Computed: true},
		"created_at":        schema.StringAttribute{Computed: true},
		"updated_at":        schema.StringAttribute{Computed: true},
	}}
}

func (r *serviceAccountResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	r.client = configureResource(request, &response.Diagnostics)
}

func (r *serviceAccountResource) ValidateConfig(ctx context.Context, request resource.ValidateConfigRequest, response *resource.ValidateConfigResponse) {
	var config serviceAccountModel
	response.Diagnostics.Append(request.Config.Get(ctx, &config)...)
	if response.Diagnostics.HasError() {
		return
	}
	if !config.Role.IsNull() && !config.Role.IsUnknown() && !validServiceAccountRole(config.Role.ValueString()) {
		response.Diagnostics.AddAttributeError(path.Root("role"), "Invalid service account role", "role must be viewer, developer, admin, or auditor.")
	}
	if config.ExpiresInDays.IsNull() || config.ExpiresInDays.IsUnknown() || config.RenewBeforeDays.IsNull() || config.RenewBeforeDays.IsUnknown() {
		return
	}
	if attribute, err := validateServiceAccountWindow(config.ExpiresInDays.ValueInt64(), config.RenewBeforeDays.ValueInt64()); err != nil {
		response.Diagnostics.AddAttributeError(path.Root(attribute), "Invalid service account lifetime", err.Error())
	}
}

func (r *serviceAccountResource) ModifyPlan(ctx context.Context, request resource.ModifyPlanRequest, response *resource.ModifyPlanResponse) {
	if request.State.Raw.IsNull() || request.Plan.Raw.IsNull() {
		return
	}
	var state, plan serviceAccountModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() || plan.RenewBeforeDays.IsNull() || plan.RenewBeforeDays.IsUnknown() {
		return
	}
	renew, err := serviceAccountRequiresRenewal(state.TokenExpiresAt, time.Now(), plan.RenewBeforeDays.ValueInt64())
	if err != nil {
		response.Diagnostics.AddAttributeError(path.Root("token_expires_at"), "Invalid service account expiry", err.Error())
		return
	}
	if renew {
		response.RequiresReplace = append(response.RequiresReplace, path.Root("token_expires_at"))
	}
}

func (r *serviceAccountResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var plan serviceAccountModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	created, err := call[struct {
		ServiceAccount serviceAccountResponse `json:"serviceAccount"`
		Token          string                 `json:"token"`
	}](ctx, r.client, http.MethodPost, "/v1/service-accounts", map[string]any{
		"name": plan.Name.ValueString(), "role": plan.Role.ValueString(), "expiresInDays": plan.ExpiresInDays.ValueInt64(),
	})
	if err != nil {
		response.Diagnostics.AddError("Unable to create service account", err.Error())
		return
	}
	setServiceAccount(&plan, created.ServiceAccount)
	plan.Token = types.StringValue(created.Token)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *serviceAccountResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var state serviceAccountModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	result, err := call[struct {
		Items []serviceAccountResponse `json:"items"`
	}](ctx, r.client, http.MethodGet, "/v1/service-accounts", nil)
	if err != nil {
		response.Diagnostics.AddError("Unable to read service account", err.Error())
		return
	}
	for _, item := range result.Items {
		if item.ID != state.ID.ValueString() {
			continue
		}
		if !item.Enabled {
			response.State.RemoveResource(ctx)
			return
		}
		setServiceAccount(&state, item)
		response.Diagnostics.Append(response.State.Set(ctx, &state)...)
		return
	}
	response.State.RemoveResource(ctx)
}

func (r *serviceAccountResource) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {
}

func (r *serviceAccountResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var state serviceAccountModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	_, err := call[struct{}](ctx, r.client, http.MethodDelete, "/v1/service-accounts/"+state.ID.ValueString(), nil)
	if err != nil && !notFound(err) {
		response.Diagnostics.AddError("Unable to disable service account", err.Error())
	}
}

func setServiceAccount(model *serviceAccountModel, item serviceAccountResponse) {
	model.ID = types.StringValue(item.ID)
	model.Name = types.StringValue(item.Name)
	model.Role = types.StringValue(item.Role)
	model.Enabled = types.BoolValue(item.Enabled)
	model.TokenExpiresAt = optionalString(item.TokenExpiresAt)
	model.LastUsedAt = optionalString(item.LastUsedAt)
	model.CreatedAt = types.StringValue(item.CreatedAt)
	model.UpdatedAt = types.StringValue(item.UpdatedAt)
}

func optionalString(value *string) types.String {
	if value == nil {
		return types.StringNull()
	}
	return types.StringValue(*value)
}

func validServiceAccountRole(role string) bool {
	return role == "viewer" || role == "developer" || role == "admin" || role == "auditor"
}

func validateServiceAccountWindow(expiresInDays, renewBeforeDays int64) (string, error) {
	if expiresInDays < 1 || expiresInDays > 365 {
		return "expires_in_days", fmt.Errorf("expires_in_days must be from 1 to 365")
	}
	if renewBeforeDays < 0 || renewBeforeDays >= expiresInDays {
		return "renew_before_days", fmt.Errorf("renew_before_days must be at least 0 and less than expires_in_days")
	}
	return "", nil
}

func serviceAccountRequiresRenewal(expiresAt types.String, now time.Time, renewBeforeDays int64) (bool, error) {
	if expiresAt.IsNull() || expiresAt.IsUnknown() || expiresAt.ValueString() == "" {
		return true, nil
	}
	expires, err := time.Parse(time.RFC3339Nano, expiresAt.ValueString())
	if err != nil {
		return false, err
	}
	return !expires.After(now.Add(time.Duration(renewBeforeDays) * 24 * time.Hour)), nil
}

var _ resource.ResourceWithConfigure = (*serviceAccountResource)(nil)
var _ resource.ResourceWithValidateConfig = (*serviceAccountResource)(nil)
var _ resource.ResourceWithModifyPlan = (*serviceAccountResource)(nil)
