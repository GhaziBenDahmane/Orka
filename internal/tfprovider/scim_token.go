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

type scimTokenResource struct{ client *apiclient.Client }

type scimTokenModel struct {
	ID            types.String `tfsdk:"id"`
	Name          types.String `tfsdk:"name"`
	DefaultRole   types.String `tfsdk:"default_role"`
	ExpiresInDays types.Int64  `tfsdk:"expires_in_days"`
	RenewBefore   types.Int64  `tfsdk:"renew_before_days"`
	Token         types.String `tfsdk:"token"`
	BaseURL       types.String `tfsdk:"base_url"`
	CreatedAt     types.String `tfsdk:"created_at"`
	ExpiresAt     types.String `tfsdk:"expires_at"`
}

type scimTokenResponse struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	DefaultRole string  `json:"defaultRole"`
	CreatedAt   string  `json:"createdAt"`
	ExpiresAt   string  `json:"expiresAt"`
	RevokedAt   *string `json:"revokedAt"`
}

func newSCIMTokenResource() resource.Resource { return &scimTokenResource{} }

func (r *scimTokenResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_scim_token"
}

func (r *scimTokenResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	stringReplace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	response.Schema = schema.Schema{Description: "A time-limited, organization-scoped SCIM provisioning credential. Replacing or destroying the resource revokes the previous token.", Attributes: map[string]schema.Attribute{
		"id":                schema.StringAttribute{Computed: true},
		"name":              schema.StringAttribute{Required: true, PlanModifiers: stringReplace},
		"default_role":      schema.StringAttribute{Required: true, PlanModifiers: stringReplace, Description: "One of viewer, developer, or admin."},
		"expires_in_days":   schema.Int64Attribute{Required: true, PlanModifiers: []planmodifier.Int64{int64planmodifier.RequiresReplace()}, Description: "Credential lifetime from 1 to 365 days."},
		"renew_before_days": schema.Int64Attribute{Required: true, PlanModifiers: []planmodifier.Int64{int64planmodifier.RequiresReplace()}, Description: "Recreate the credential when fewer than this many days remain."},
		"token":             schema.StringAttribute{Computed: true, Sensitive: true, Description: "The bearer token returned once at creation and retained only in sensitive state."},
		"base_url":          schema.StringAttribute{Computed: true, Description: "The organization SCIM 2.0 endpoint."},
		"created_at":        schema.StringAttribute{Computed: true},
		"expires_at":        schema.StringAttribute{Computed: true},
	}}
}

func (r *scimTokenResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	r.client = configureResource(request, &response.Diagnostics)
}

func (r *scimTokenResource) ValidateConfig(ctx context.Context, request resource.ValidateConfigRequest, response *resource.ValidateConfigResponse) {
	var config scimTokenModel
	response.Diagnostics.Append(request.Config.Get(ctx, &config)...)
	if response.Diagnostics.HasError() {
		return
	}
	if !config.DefaultRole.IsNull() && !config.DefaultRole.IsUnknown() {
		role := config.DefaultRole.ValueString()
		if role != "viewer" && role != "developer" && role != "admin" {
			response.Diagnostics.AddAttributeError(path.Root("default_role"), "Invalid SCIM default role", "default_role must be viewer, developer, or admin.")
		}
	}
	if config.ExpiresInDays.IsNull() || config.ExpiresInDays.IsUnknown() || config.RenewBefore.IsNull() || config.RenewBefore.IsUnknown() {
		return
	}
	if attribute, err := validateSCIMTokenWindow(config.ExpiresInDays.ValueInt64(), config.RenewBefore.ValueInt64()); err != nil {
		response.Diagnostics.AddAttributeError(path.Root(attribute), "Invalid SCIM token lifetime", err.Error())
	}
}

func (r *scimTokenResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var plan scimTokenModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	created, err := call[struct {
		SCIMToken scimTokenResponse `json:"scimToken"`
		Token     string            `json:"token"`
		BaseURL   string            `json:"baseUrl"`
	}](ctx, r.client, http.MethodPost, "/v1/scim/tokens", map[string]any{
		"name": plan.Name.ValueString(), "defaultRole": plan.DefaultRole.ValueString(), "expiresInDays": plan.ExpiresInDays.ValueInt64(),
	})
	if err != nil {
		response.Diagnostics.AddError("Unable to create SCIM token", err.Error())
		return
	}
	setSCIMToken(&plan, created.SCIMToken)
	plan.Token = types.StringValue(created.Token)
	plan.BaseURL = types.StringValue(created.BaseURL)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *scimTokenResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var state scimTokenModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	result, err := call[struct {
		Items []scimTokenResponse `json:"items"`
	}](ctx, r.client, http.MethodGet, "/v1/scim/tokens", nil)
	if err != nil {
		response.Diagnostics.AddError("Unable to read SCIM token", err.Error())
		return
	}
	for _, item := range result.Items {
		if item.ID != state.ID.ValueString() {
			continue
		}
		usable, parseErr := usableSCIMToken(item, time.Now(), state.RenewBefore.ValueInt64())
		if parseErr != nil {
			response.Diagnostics.AddError("Unable to read SCIM token expiry", parseErr.Error())
			return
		}
		if !usable {
			response.State.RemoveResource(ctx)
			return
		}
		setSCIMToken(&state, item)
		response.Diagnostics.Append(response.State.Set(ctx, &state)...)
		return
	}
	response.State.RemoveResource(ctx)
}

func (r *scimTokenResource) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {
}

func (r *scimTokenResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var state scimTokenModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	_, err := call[struct{}](ctx, r.client, http.MethodDelete, "/v1/scim/tokens/"+state.ID.ValueString(), nil)
	if err != nil && !notFound(err) {
		response.Diagnostics.AddError("Unable to revoke SCIM token", err.Error())
	}
}

func setSCIMToken(model *scimTokenModel, item scimTokenResponse) {
	model.ID = types.StringValue(item.ID)
	model.Name = types.StringValue(item.Name)
	model.DefaultRole = types.StringValue(item.DefaultRole)
	model.CreatedAt = types.StringValue(item.CreatedAt)
	model.ExpiresAt = types.StringValue(item.ExpiresAt)
}

func usableSCIMToken(item scimTokenResponse, now time.Time, renewBeforeDays int64) (bool, error) {
	if item.RevokedAt != nil {
		return false, nil
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, item.ExpiresAt)
	if err != nil {
		return false, err
	}
	return expiresAt.After(now.Add(time.Duration(renewBeforeDays) * 24 * time.Hour)), nil
}

func validateSCIMTokenWindow(expiresInDays, renewBeforeDays int64) (string, error) {
	if expiresInDays < 1 || expiresInDays > 365 {
		return "expires_in_days", fmt.Errorf("expires_in_days must be from 1 to 365")
	}
	if renewBeforeDays < 0 || renewBeforeDays >= expiresInDays {
		return "renew_before_days", fmt.Errorf("renew_before_days must be at least 0 and less than expires_in_days")
	}
	return "", nil
}

var _ resource.ResourceWithConfigure = (*scimTokenResource)(nil)
var _ resource.ResourceWithValidateConfig = (*scimTokenResource)(nil)
