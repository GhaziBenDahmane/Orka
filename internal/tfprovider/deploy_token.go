package tfprovider

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/bendahma/dokploy-go/internal/apiclient"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type deployTokenResource struct{ client *apiclient.Client }

type deployTokenModel struct {
	ID              types.String `tfsdk:"id"`
	ServiceID       types.String `tfsdk:"service_id"`
	Name            types.String `tfsdk:"name"`
	ExpiresInDays   types.Int64  `tfsdk:"expires_in_days"`
	RenewBeforeDays types.Int64  `tfsdk:"renew_before_days"`
	Token           types.String `tfsdk:"token"`
	URL             types.String `tfsdk:"url"`
	CreatedAt       types.String `tfsdk:"created_at"`
	ExpiresAt       types.String `tfsdk:"expires_at"`
	LastUsedAt      types.String `tfsdk:"last_used_at"`
}

type deployTokenResponse struct {
	ID               string  `json:"id"`
	ComposeServiceID string  `json:"composeServiceId"`
	Name             string  `json:"name"`
	ExpiresAt        string  `json:"expiresAt"`
	LastUsedAt       *string `json:"lastUsedAt"`
	RevokedAt        *string `json:"revokedAt"`
	CreatedAt        string  `json:"createdAt"`
}

func newDeployTokenResource() resource.Resource { return &deployTokenResource{} }

func (r *deployTokenResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_deploy_token"
}

func (r *deployTokenResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	stringReplace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	intReplace := []planmodifier.Int64{int64planmodifier.RequiresReplace()}
	response.Schema = schema.Schema{Description: "An expiring CI deployment hook scoped to one Compose service. Replacing or destroying the resource revokes the previous hook.", Attributes: map[string]schema.Attribute{
		"id":                schema.StringAttribute{Computed: true},
		"service_id":        schema.StringAttribute{Required: true, PlanModifiers: stringReplace},
		"name":              schema.StringAttribute{Required: true, PlanModifiers: stringReplace},
		"expires_in_days":   schema.Int64Attribute{Required: true, PlanModifiers: intReplace, Description: "Credential lifetime from 1 to 365 days."},
		"renew_before_days": schema.Int64Attribute{Required: true, PlanModifiers: intReplace, Description: "Replace the hook when fewer than this many days remain."},
		"token":             schema.StringAttribute{Computed: true, Sensitive: true, Description: "The bearer token returned once at creation and retained only in sensitive state."},
		"url":               schema.StringAttribute{Computed: true, Sensitive: true, Description: "The complete one-time deployment-hook URL retained only in sensitive state."},
		"created_at":        schema.StringAttribute{Computed: true},
		"expires_at":        schema.StringAttribute{Computed: true},
		"last_used_at":      schema.StringAttribute{Computed: true},
	}}
}

func (r *deployTokenResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	r.client = configureResource(request, &response.Diagnostics)
}

func (r *deployTokenResource) ValidateConfig(ctx context.Context, request resource.ValidateConfigRequest, response *resource.ValidateConfigResponse) {
	var config deployTokenModel
	response.Diagnostics.Append(request.Config.Get(ctx, &config)...)
	if response.Diagnostics.HasError() || config.ExpiresInDays.IsNull() || config.ExpiresInDays.IsUnknown() || config.RenewBeforeDays.IsNull() || config.RenewBeforeDays.IsUnknown() {
		return
	}
	if attribute, err := validateDeployTokenWindow(config.ExpiresInDays.ValueInt64(), config.RenewBeforeDays.ValueInt64()); err != nil {
		response.Diagnostics.AddAttributeError(path.Root(attribute), "Invalid deploy-token lifetime", err.Error())
	}
}

func (r *deployTokenResource) ModifyPlan(ctx context.Context, request resource.ModifyPlanRequest, response *resource.ModifyPlanResponse) {
	if request.State.Raw.IsNull() || request.Plan.Raw.IsNull() {
		return
	}
	var state, plan deployTokenModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() || plan.RenewBeforeDays.IsNull() || plan.RenewBeforeDays.IsUnknown() {
		return
	}
	renew, err := deployTokenRequiresRenewal(state.ExpiresAt, time.Now(), plan.RenewBeforeDays.ValueInt64())
	if err != nil {
		response.Diagnostics.AddAttributeError(path.Root("expires_at"), "Invalid deploy-token expiry", err.Error())
		return
	}
	if renew {
		response.RequiresReplace = append(response.RequiresReplace, path.Root("expires_at"))
	}
}

func (r *deployTokenResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var plan deployTokenModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	created, err := call[struct {
		DeployToken deployTokenResponse `json:"deployToken"`
		Token       string              `json:"token"`
		URL         string              `json:"url"`
	}](ctx, r.client, http.MethodPost, "/v1/services/"+plan.ServiceID.ValueString()+"/deploy-tokens", map[string]any{
		"name": plan.Name.ValueString(), "expiresInDays": plan.ExpiresInDays.ValueInt64(),
	})
	if err != nil {
		response.Diagnostics.AddError("Unable to create deploy token", err.Error())
		return
	}
	setDeployToken(&plan, created.DeployToken)
	plan.Token = types.StringValue(created.Token)
	plan.URL = types.StringValue(created.URL)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *deployTokenResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var state deployTokenModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	result, err := call[struct {
		Items []deployTokenResponse `json:"items"`
	}](ctx, r.client, http.MethodGet, "/v1/services/"+state.ServiceID.ValueString()+"/deploy-tokens", nil)
	if err != nil {
		if notFound(err) {
			response.State.RemoveResource(ctx)
			return
		}
		response.Diagnostics.AddError("Unable to read deploy token", err.Error())
		return
	}
	for _, item := range result.Items {
		if item.ID != state.ID.ValueString() {
			continue
		}
		usable, parseErr := usableDeployToken(item, time.Now())
		if parseErr != nil {
			response.Diagnostics.AddError("Unable to read deploy-token expiry", parseErr.Error())
			return
		}
		if !usable {
			response.State.RemoveResource(ctx)
			return
		}
		setDeployToken(&state, item)
		response.Diagnostics.Append(response.State.Set(ctx, &state)...)
		return
	}
	response.State.RemoveResource(ctx)
}

func (r *deployTokenResource) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {
}

func (r *deployTokenResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var state deployTokenModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	_, err := call[struct{}](ctx, r.client, http.MethodDelete, "/v1/services/"+state.ServiceID.ValueString()+"/deploy-tokens/"+state.ID.ValueString(), nil)
	if err != nil && !notFound(err) {
		response.Diagnostics.AddError("Unable to revoke deploy token", err.Error())
	}
}

func setDeployToken(model *deployTokenModel, item deployTokenResponse) {
	model.ID = types.StringValue(item.ID)
	model.ServiceID = types.StringValue(item.ComposeServiceID)
	model.Name = types.StringValue(item.Name)
	model.CreatedAt = types.StringValue(item.CreatedAt)
	model.ExpiresAt = types.StringValue(item.ExpiresAt)
	model.LastUsedAt = optionalString(item.LastUsedAt)
}

func usableDeployToken(item deployTokenResponse, now time.Time) (bool, error) {
	if item.RevokedAt != nil {
		return false, nil
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, item.ExpiresAt)
	if err != nil {
		return false, err
	}
	return expiresAt.After(now), nil
}

func validateDeployTokenWindow(expiresInDays, renewBeforeDays int64) (string, error) {
	if expiresInDays < 1 || expiresInDays > 365 {
		return "expires_in_days", fmt.Errorf("expires_in_days must be from 1 to 365")
	}
	if renewBeforeDays < 0 || renewBeforeDays >= expiresInDays {
		return "renew_before_days", fmt.Errorf("renew_before_days must be at least 0 and less than expires_in_days")
	}
	return "", nil
}

func deployTokenRequiresRenewal(expiresAt types.String, now time.Time, renewBeforeDays int64) (bool, error) {
	if expiresAt.IsNull() || expiresAt.IsUnknown() || expiresAt.ValueString() == "" {
		return true, nil
	}
	expires, err := time.Parse(time.RFC3339Nano, expiresAt.ValueString())
	if err != nil {
		return false, err
	}
	return !expires.After(now.Add(time.Duration(renewBeforeDays) * 24 * time.Hour)), nil
}

var _ resource.ResourceWithConfigure = (*deployTokenResource)(nil)
var _ resource.ResourceWithValidateConfig = (*deployTokenResource)(nil)
var _ resource.ResourceWithModifyPlan = (*deployTokenResource)(nil)
