package tfprovider

import (
	"context"
	"fmt"
	"net/http"
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

type accessGrantResource struct{ client *apiclient.Client }

type accessGrantModel struct {
	ID        types.String `tfsdk:"id"`
	ScopeType types.String `tfsdk:"scope_type"`
	ScopeID   types.String `tfsdk:"scope_id"`
	UserID    types.String `tfsdk:"user_id"`
	Role      types.String `tfsdk:"role"`
	Email     types.String `tfsdk:"email"`
	CreatedAt types.String `tfsdk:"created_at"`
	UpdatedAt types.String `tfsdk:"updated_at"`
}

type accessGrantResponse struct {
	ScopeType string `json:"scopeType"`
	ScopeID   string `json:"scopeId"`
	UserID    string `json:"userId"`
	Role      string `json:"role"`
	Email     string `json:"email"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

func newAccessGrantResource() resource.Resource { return &accessGrantResource{} }

func (r *accessGrantResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_access_grant"
}

func (r *accessGrantResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	response.Schema = schema.Schema{Description: "A per-user project or environment role grant. Organization membership remains the lower access boundary.", Attributes: map[string]schema.Attribute{
		"id":         schema.StringAttribute{Computed: true, Description: "Composite scope_type/scope_id/user_id identity."},
		"scope_type": schema.StringAttribute{Required: true, PlanModifiers: replace, Description: "Either project or environment."},
		"scope_id":   schema.StringAttribute{Required: true, PlanModifiers: replace},
		"user_id":    schema.StringAttribute{Required: true, PlanModifiers: replace},
		"role":       schema.StringAttribute{Required: true, Description: "One of viewer, developer, or admin."},
		"email":      schema.StringAttribute{Computed: true},
		"created_at": schema.StringAttribute{Computed: true},
		"updated_at": schema.StringAttribute{Computed: true},
	}}
}

func (r *accessGrantResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	r.client = configureResource(request, &response.Diagnostics)
}

func (r *accessGrantResource) ValidateConfig(ctx context.Context, request resource.ValidateConfigRequest, response *resource.ValidateConfigResponse) {
	var config accessGrantModel
	response.Diagnostics.Append(request.Config.Get(ctx, &config)...)
	if response.Diagnostics.HasError() {
		return
	}
	if !config.ScopeType.IsNull() && !config.ScopeType.IsUnknown() {
		if _, err := accessGrantCollection(config.ScopeType.ValueString()); err != nil {
			response.Diagnostics.AddAttributeError(path.Root("scope_type"), "Invalid grant scope", err.Error())
		}
	}
	for attribute, value := range map[string]types.String{"scope_id": config.ScopeID, "user_id": config.UserID} {
		if !value.IsNull() && !value.IsUnknown() {
			if _, err := uuid.Parse(value.ValueString()); err != nil {
				response.Diagnostics.AddAttributeError(path.Root(attribute), "Invalid UUID", attribute+" must be a UUID.")
			}
		}
	}
	if !config.Role.IsNull() && !config.Role.IsUnknown() && !validAccessGrantRole(config.Role.ValueString()) {
		response.Diagnostics.AddAttributeError(path.Root("role"), "Invalid grant role", "role must be viewer, developer, or admin.")
	}
}

func (r *accessGrantResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var plan accessGrantModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := r.put(ctx, plan)
	if err != nil {
		response.Diagnostics.AddError("Unable to create access grant", err.Error())
		return
	}
	setAccessGrant(&plan, item)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *accessGrantResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var state accessGrantModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	collection, err := accessGrantCollection(state.ScopeType.ValueString())
	if err != nil {
		response.Diagnostics.AddError("Unable to read access grant", err.Error())
		return
	}
	result, err := call[struct {
		Items []accessGrantResponse `json:"items"`
	}](ctx, r.client, http.MethodGet, "/v1/"+collection+"/"+state.ScopeID.ValueString()+"/grants", nil)
	if notFound(err) {
		response.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		response.Diagnostics.AddError("Unable to read access grant", err.Error())
		return
	}
	for _, item := range result.Items {
		if item.UserID == state.UserID.ValueString() {
			setAccessGrant(&state, item)
			response.Diagnostics.Append(response.State.Set(ctx, &state)...)
			return
		}
	}
	response.State.RemoveResource(ctx)
}

func (r *accessGrantResource) Update(ctx context.Context, request resource.UpdateRequest, response *resource.UpdateResponse) {
	var plan accessGrantModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := r.put(ctx, plan)
	if err != nil {
		response.Diagnostics.AddError("Unable to update access grant", err.Error())
		return
	}
	setAccessGrant(&plan, item)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *accessGrantResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var state accessGrantModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	collection, err := accessGrantCollection(state.ScopeType.ValueString())
	if err == nil {
		_, err = call[struct{}](ctx, r.client, http.MethodDelete, "/v1/"+collection+"/"+state.ScopeID.ValueString()+"/grants/"+state.UserID.ValueString(), nil)
	}
	if err != nil && !notFound(err) {
		response.Diagnostics.AddError("Unable to delete access grant", err.Error())
	}
}

func (r *accessGrantResource) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	scopeType, scopeID, userID, err := splitAccessGrantImportID(request.ID)
	if err != nil {
		response.Diagnostics.AddError("Invalid access grant import ID", err.Error())
		return
	}
	response.Diagnostics.Append(response.State.SetAttribute(ctx, path.Root("id"), request.ID)...)
	response.Diagnostics.Append(response.State.SetAttribute(ctx, path.Root("scope_type"), scopeType)...)
	response.Diagnostics.Append(response.State.SetAttribute(ctx, path.Root("scope_id"), scopeID)...)
	response.Diagnostics.Append(response.State.SetAttribute(ctx, path.Root("user_id"), userID)...)
}

func (r *accessGrantResource) put(ctx context.Context, model accessGrantModel) (accessGrantResponse, error) {
	collection, err := accessGrantCollection(model.ScopeType.ValueString())
	if err != nil {
		return accessGrantResponse{}, err
	}
	return call[accessGrantResponse](ctx, r.client, http.MethodPut, "/v1/"+collection+"/"+model.ScopeID.ValueString()+"/grants/"+model.UserID.ValueString(), map[string]string{"role": model.Role.ValueString()})
}

func setAccessGrant(model *accessGrantModel, item accessGrantResponse) {
	model.ID = types.StringValue(accessGrantID(item.ScopeType, item.ScopeID, item.UserID))
	model.ScopeType = types.StringValue(item.ScopeType)
	model.ScopeID = types.StringValue(item.ScopeID)
	model.UserID = types.StringValue(item.UserID)
	model.Role = types.StringValue(item.Role)
	model.Email = types.StringValue(item.Email)
	model.CreatedAt = types.StringValue(item.CreatedAt)
	model.UpdatedAt = types.StringValue(item.UpdatedAt)
}

func accessGrantCollection(scopeType string) (string, error) {
	switch scopeType {
	case "project":
		return "projects", nil
	case "environment":
		return "environments", nil
	default:
		return "", fmt.Errorf("scope_type must be project or environment")
	}
}

func validAccessGrantRole(role string) bool {
	return role == "viewer" || role == "developer" || role == "admin"
}

func accessGrantID(scopeType, scopeID, userID string) string {
	return strings.Join([]string{scopeType, scopeID, userID}, "/")
}

func splitAccessGrantImportID(id string) (string, string, string, error) {
	parts := strings.Split(id, "/")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("expected scope_type/scope_id/user_id")
	}
	if _, err := accessGrantCollection(parts[0]); err != nil {
		return "", "", "", err
	}
	if _, err := uuid.Parse(parts[1]); err != nil {
		return "", "", "", fmt.Errorf("scope_id must be a UUID")
	}
	if _, err := uuid.Parse(parts[2]); err != nil {
		return "", "", "", fmt.Errorf("user_id must be a UUID")
	}
	return parts[0], parts[1], parts[2], nil
}

var _ resource.ResourceWithConfigure = (*accessGrantResource)(nil)
var _ resource.ResourceWithValidateConfig = (*accessGrantResource)(nil)
var _ resource.ResourceWithImportState = (*accessGrantResource)(nil)
