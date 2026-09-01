package tfprovider

import (
	"context"
	"fmt"
	"net/http"
	"net/mail"
	"strings"
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

type invitationResource struct{ client *apiclient.Client }

type invitationModel struct {
	ID              types.String `tfsdk:"id"`
	Email           types.String `tfsdk:"email"`
	Role            types.String `tfsdk:"role"`
	ExpiresInDays   types.Int64  `tfsdk:"expires_in_days"`
	RenewBeforeDays types.Int64  `tfsdk:"renew_before_days"`
	Token           types.String `tfsdk:"token"`
	AcceptURL       types.String `tfsdk:"accept_url"`
	Status          types.String `tfsdk:"status"`
	ExpiresAt       types.String `tfsdk:"expires_at"`
	AcceptedAt      types.String `tfsdk:"accepted_at"`
	RevokedAt       types.String `tfsdk:"revoked_at"`
	CreatedAt       types.String `tfsdk:"created_at"`
}

type invitationResponse struct {
	ID         string  `json:"id"`
	Email      string  `json:"email"`
	Role       string  `json:"role"`
	ExpiresAt  string  `json:"expiresAt"`
	AcceptedAt *string `json:"acceptedAt"`
	RevokedAt  *string `json:"revokedAt"`
	CreatedAt  string  `json:"createdAt"`
}

func newInvitationResource() resource.Resource { return &invitationResource{} }

func (r *invitationResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_invitation"
}

func (r *invitationResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	stringReplace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	intReplace := []planmodifier.Int64{int64planmodifier.RequiresReplace()}
	response.Schema = schema.Schema{Description: "A one-time organization invitation. Accepted invitations remain as historical state; pending invitations are replaced near expiry.", Attributes: map[string]schema.Attribute{
		"id":                schema.StringAttribute{Computed: true},
		"email":             schema.StringAttribute{Required: true, PlanModifiers: stringReplace, Description: "Normalized lowercase recipient email address."},
		"role":              schema.StringAttribute{Required: true, PlanModifiers: stringReplace, Description: "One of viewer, developer, admin, or owner."},
		"expires_in_days":   schema.Int64Attribute{Required: true, PlanModifiers: intReplace, Description: "Invitation lifetime from 1 to 30 days."},
		"renew_before_days": schema.Int64Attribute{Required: true, PlanModifiers: intReplace, Description: "Replace an unaccepted invitation when fewer than this many days remain."},
		"token":             schema.StringAttribute{Computed: true, Sensitive: true, Description: "The invitation token returned once at creation and retained only in sensitive state."},
		"accept_url":        schema.StringAttribute{Computed: true, Sensitive: true, Description: "The one-time invitation URL returned at creation."},
		"status":            schema.StringAttribute{Computed: true, Description: "One of pending, accepted, revoked, or expired."},
		"expires_at":        schema.StringAttribute{Computed: true},
		"accepted_at":       schema.StringAttribute{Computed: true},
		"revoked_at":        schema.StringAttribute{Computed: true},
		"created_at":        schema.StringAttribute{Computed: true},
	}}
}

func (r *invitationResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	r.client = configureResource(request, &response.Diagnostics)
}

func (r *invitationResource) ValidateConfig(ctx context.Context, request resource.ValidateConfigRequest, response *resource.ValidateConfigResponse) {
	var config invitationModel
	response.Diagnostics.Append(request.Config.Get(ctx, &config)...)
	if response.Diagnostics.HasError() {
		return
	}
	if !config.Email.IsNull() && !config.Email.IsUnknown() {
		if err := validateInvitationEmail(config.Email.ValueString()); err != nil {
			response.Diagnostics.AddAttributeError(path.Root("email"), "Invalid invitation email", err.Error())
		}
	}
	if !config.Role.IsNull() && !config.Role.IsUnknown() && !validInvitationRole(config.Role.ValueString()) {
		response.Diagnostics.AddAttributeError(path.Root("role"), "Invalid invitation role", "role must be viewer, developer, admin, or owner.")
	}
	if config.ExpiresInDays.IsNull() || config.ExpiresInDays.IsUnknown() || config.RenewBeforeDays.IsNull() || config.RenewBeforeDays.IsUnknown() {
		return
	}
	if attribute, err := validateInvitationWindow(config.ExpiresInDays.ValueInt64(), config.RenewBeforeDays.ValueInt64()); err != nil {
		response.Diagnostics.AddAttributeError(path.Root(attribute), "Invalid invitation lifetime", err.Error())
	}
}

func (r *invitationResource) ModifyPlan(ctx context.Context, request resource.ModifyPlanRequest, response *resource.ModifyPlanResponse) {
	if request.State.Raw.IsNull() || request.Plan.Raw.IsNull() {
		return
	}
	var state, plan invitationModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() || plan.RenewBeforeDays.IsNull() || plan.RenewBeforeDays.IsUnknown() {
		return
	}
	renew, err := invitationRequiresRenewal(state.ExpiresAt, state.AcceptedAt, time.Now(), plan.RenewBeforeDays.ValueInt64())
	if err != nil {
		response.Diagnostics.AddAttributeError(path.Root("expires_at"), "Invalid invitation expiry", err.Error())
		return
	}
	if renew {
		response.RequiresReplace = append(response.RequiresReplace, path.Root("expires_at"))
	}
}

func (r *invitationResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var plan invitationModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	created, err := call[struct {
		Invitation invitationResponse `json:"invitation"`
		Token      string             `json:"token"`
		AcceptURL  string             `json:"acceptUrl"`
	}](ctx, r.client, http.MethodPost, "/v1/invitations", map[string]any{
		"email": plan.Email.ValueString(), "role": plan.Role.ValueString(), "expiresInDays": plan.ExpiresInDays.ValueInt64(),
	})
	if err != nil {
		response.Diagnostics.AddError("Unable to create invitation", err.Error())
		return
	}
	setInvitation(&plan, created.Invitation, time.Now())
	plan.Token = types.StringValue(created.Token)
	plan.AcceptURL = types.StringValue(created.AcceptURL)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *invitationResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var state invitationModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := call[invitationResponse](ctx, r.client, http.MethodGet, "/v1/invitations/"+state.ID.ValueString(), nil)
	if err != nil {
		if notFound(err) {
			response.State.RemoveResource(ctx)
			return
		}
		response.Diagnostics.AddError("Unable to read invitation", err.Error())
		return
	}
	if item.RevokedAt != nil {
		response.State.RemoveResource(ctx)
		return
	}
	setInvitation(&state, item, time.Now())
	response.Diagnostics.Append(response.State.Set(ctx, &state)...)
}

func (r *invitationResource) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {
}

func (r *invitationResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var state invitationModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	_, err := call[struct{}](ctx, r.client, http.MethodDelete, "/v1/invitations/"+state.ID.ValueString(), nil)
	if err != nil && !notFound(err) {
		response.Diagnostics.AddError("Unable to revoke invitation", err.Error())
	}
}

func setInvitation(model *invitationModel, item invitationResponse, now time.Time) {
	model.ID = types.StringValue(item.ID)
	model.Email = types.StringValue(item.Email)
	model.Role = types.StringValue(item.Role)
	model.ExpiresAt = types.StringValue(item.ExpiresAt)
	model.AcceptedAt = optionalString(item.AcceptedAt)
	model.RevokedAt = optionalString(item.RevokedAt)
	model.CreatedAt = types.StringValue(item.CreatedAt)
	model.Status = types.StringValue(invitationStatus(item, now))
}

func invitationStatus(item invitationResponse, now time.Time) string {
	if item.AcceptedAt != nil {
		return "accepted"
	}
	if item.RevokedAt != nil {
		return "revoked"
	}
	expires, err := time.Parse(time.RFC3339Nano, item.ExpiresAt)
	if err == nil && !expires.After(now) {
		return "expired"
	}
	return "pending"
}

func invitationRequiresRenewal(expiresAt, acceptedAt types.String, now time.Time, renewBeforeDays int64) (bool, error) {
	if !acceptedAt.IsNull() && !acceptedAt.IsUnknown() && acceptedAt.ValueString() != "" {
		return false, nil
	}
	if expiresAt.IsNull() || expiresAt.IsUnknown() || expiresAt.ValueString() == "" {
		return true, nil
	}
	expires, err := time.Parse(time.RFC3339Nano, expiresAt.ValueString())
	if err != nil {
		return false, err
	}
	return !expires.After(now.Add(time.Duration(renewBeforeDays) * 24 * time.Hour)), nil
}

func validateInvitationEmail(value string) error {
	address, err := mail.ParseAddress(value)
	normalized := strings.ToLower(strings.TrimSpace(value))
	if err != nil || address.Address != value || value != normalized || len(value) > 320 {
		return fmt.Errorf("email must be a normalized lowercase plain address")
	}
	return nil
}

func validInvitationRole(role string) bool {
	return role == "viewer" || role == "developer" || role == "admin" || role == "owner"
}

func validateInvitationWindow(expiresInDays, renewBeforeDays int64) (string, error) {
	if expiresInDays < 1 || expiresInDays > 30 {
		return "expires_in_days", fmt.Errorf("expires_in_days must be from 1 to 30")
	}
	if renewBeforeDays < 0 || renewBeforeDays >= expiresInDays {
		return "renew_before_days", fmt.Errorf("renew_before_days must be at least 0 and less than expires_in_days")
	}
	return "", nil
}

var _ resource.ResourceWithConfigure = (*invitationResource)(nil)
var _ resource.ResourceWithValidateConfig = (*invitationResource)(nil)
var _ resource.ResourceWithModifyPlan = (*invitationResource)(nil)
