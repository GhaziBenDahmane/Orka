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

type resourcePolicyResource struct{ client *apiclient.Client }

type resourcePolicyModel struct {
	ID                types.String `tfsdk:"id"`
	ScopeType         types.String `tfsdk:"scope_type"`
	ScopeID           types.String `tfsdk:"scope_id"`
	Maintenance       types.Bool   `tfsdk:"maintenance"`
	MaintenanceReason types.String `tfsdk:"maintenance_reason"`
	MaxProjects       types.Int64  `tfsdk:"max_projects"`
	MaxEnvironments   types.Int64  `tfsdk:"max_environments"`
	MaxServices       types.Int64  `tfsdk:"max_services"`
	MaxDatabases      types.Int64  `tfsdk:"max_databases"`
	UpdatedAt         types.String `tfsdk:"updated_at"`
}

type resourcePolicyResponse struct {
	ScopeType         string `json:"scopeType"`
	ScopeID           string `json:"scopeId"`
	Maintenance       bool   `json:"maintenance"`
	MaintenanceReason string `json:"maintenanceReason"`
	MaxProjects       *int64 `json:"maxProjects"`
	MaxEnvironments   *int64 `json:"maxEnvironments"`
	MaxServices       *int64 `json:"maxServices"`
	MaxDatabases      *int64 `json:"maxDatabases"`
	UpdatedAt         string `json:"updatedAt"`
}

func newResourcePolicyResource() resource.Resource { return &resourcePolicyResource{} }

func (r *resourcePolicyResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_resource_policy"
}

func (r *resourcePolicyResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	response.Schema = schema.Schema{Description: "Maintenance mode and resource quotas for an organization, project, or environment.", Attributes: map[string]schema.Attribute{
		"id":                 schema.StringAttribute{Computed: true},
		"scope_type":         schema.StringAttribute{Required: true, PlanModifiers: replace, Description: "One of organization, project, or environment."},
		"scope_id":           schema.StringAttribute{Optional: true, PlanModifiers: replace, Description: "Required for project and environment; omit for the provider organization."},
		"maintenance":        schema.BoolAttribute{Required: true},
		"maintenance_reason": schema.StringAttribute{Optional: true},
		"max_projects":       schema.Int64Attribute{Optional: true, Description: "Organization-only project quota."},
		"max_environments":   schema.Int64Attribute{Optional: true, Description: "Organization or project environment quota."},
		"max_services":       schema.Int64Attribute{Optional: true},
		"max_databases":      schema.Int64Attribute{Optional: true},
		"updated_at":         schema.StringAttribute{Computed: true},
	}}
}

func (r *resourcePolicyResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	r.client = configureResource(request, &response.Diagnostics)
}

func (r *resourcePolicyResource) ValidateConfig(ctx context.Context, request resource.ValidateConfigRequest, response *resource.ValidateConfigResponse) {
	var config resourcePolicyModel
	response.Diagnostics.Append(request.Config.Get(ctx, &config)...)
	if response.Diagnostics.HasError() || config.ScopeType.IsNull() || config.ScopeType.IsUnknown() {
		return
	}
	scopeType := config.ScopeType.ValueString()
	scopeIDKnown := !config.ScopeID.IsNull() && !config.ScopeID.IsUnknown() && config.ScopeID.ValueString() != ""
	if scopeType == "organization" {
		if scopeIDKnown {
			response.Diagnostics.AddAttributeError(path.Root("scope_id"), "Invalid organization policy scope", "scope_id must be omitted for an organization policy.")
		}
	} else if scopeType == "project" || scopeType == "environment" {
		if !scopeIDKnown {
			response.Diagnostics.AddAttributeError(path.Root("scope_id"), "Missing policy scope ID", "scope_id is required for project and environment policies.")
		} else if _, err := uuid.Parse(config.ScopeID.ValueString()); err != nil {
			response.Diagnostics.AddAttributeError(path.Root("scope_id"), "Invalid policy scope ID", "scope_id must be a UUID.")
		}
	} else {
		response.Diagnostics.AddAttributeError(path.Root("scope_type"), "Invalid policy scope", "scope_type must be organization, project, or environment.")
	}
	if scopeType != "organization" && !config.MaxProjects.IsNull() && !config.MaxProjects.IsUnknown() {
		response.Diagnostics.AddAttributeError(path.Root("max_projects"), "Invalid quota scope", "max_projects is valid only for organization policies.")
	}
	if scopeType == "environment" && !config.MaxEnvironments.IsNull() && !config.MaxEnvironments.IsUnknown() {
		response.Diagnostics.AddAttributeError(path.Root("max_environments"), "Invalid quota scope", "max_environments is not valid for environment policies.")
	}
	for attribute, value := range map[string]types.Int64{"max_projects": config.MaxProjects, "max_environments": config.MaxEnvironments, "max_services": config.MaxServices, "max_databases": config.MaxDatabases} {
		if !value.IsNull() && !value.IsUnknown() && (value.ValueInt64() < 1 || value.ValueInt64() > 1_000_000) {
			response.Diagnostics.AddAttributeError(path.Root(attribute), "Invalid resource quota", attribute+" must be from 1 to 1000000.")
		}
	}
	if !config.MaintenanceReason.IsNull() && !config.MaintenanceReason.IsUnknown() && len(config.MaintenanceReason.ValueString()) > 500 {
		response.Diagnostics.AddAttributeError(path.Root("maintenance_reason"), "Invalid maintenance reason", "maintenance_reason must not exceed 500 bytes.")
	}
}

func (r *resourcePolicyResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var plan resourcePolicyModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := r.put(ctx, plan, resourcePolicyInput(plan))
	if err != nil {
		response.Diagnostics.AddError("Unable to create resource policy", err.Error())
		return
	}
	setResourcePolicy(&plan, item)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *resourcePolicyResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var state resourcePolicyModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	endpoint, err := resourcePolicyPath(state.ScopeType.ValueString(), state.ScopeID.ValueString())
	if err != nil {
		response.Diagnostics.AddError("Unable to read resource policy", err.Error())
		return
	}
	item, err := call[resourcePolicyResponse](ctx, r.client, http.MethodGet, endpoint, nil)
	if notFound(err) {
		response.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		response.Diagnostics.AddError("Unable to read resource policy", err.Error())
		return
	}
	setResourcePolicy(&state, item)
	response.Diagnostics.Append(response.State.Set(ctx, &state)...)
}

func (r *resourcePolicyResource) Update(ctx context.Context, request resource.UpdateRequest, response *resource.UpdateResponse) {
	var plan resourcePolicyModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := r.put(ctx, plan, resourcePolicyInput(plan))
	if err != nil {
		response.Diagnostics.AddError("Unable to update resource policy", err.Error())
		return
	}
	setResourcePolicy(&plan, item)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *resourcePolicyResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var state resourcePolicyModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	_, err := r.put(ctx, state, map[string]any{"maintenance": false, "maintenanceReason": "", "maxProjects": nil, "maxEnvironments": nil, "maxServices": nil, "maxDatabases": nil})
	if err != nil && !notFound(err) {
		response.Diagnostics.AddError("Unable to reset resource policy", err.Error())
	}
}

func (r *resourcePolicyResource) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	scopeType, scopeID, err := splitResourcePolicyImportID(request.ID)
	if err != nil {
		response.Diagnostics.AddError("Invalid resource policy import ID", err.Error())
		return
	}
	response.Diagnostics.Append(response.State.SetAttribute(ctx, path.Root("id"), request.ID)...)
	response.Diagnostics.Append(response.State.SetAttribute(ctx, path.Root("scope_type"), scopeType)...)
	if scopeID != "" {
		response.Diagnostics.Append(response.State.SetAttribute(ctx, path.Root("scope_id"), scopeID)...)
	}
}

func (r *resourcePolicyResource) put(ctx context.Context, model resourcePolicyModel, input map[string]any) (resourcePolicyResponse, error) {
	endpoint, err := resourcePolicyPath(model.ScopeType.ValueString(), model.ScopeID.ValueString())
	if err != nil {
		return resourcePolicyResponse{}, err
	}
	return call[resourcePolicyResponse](ctx, r.client, http.MethodPut, endpoint, input)
}

func resourcePolicyInput(model resourcePolicyModel) map[string]any {
	return map[string]any{
		"maintenance": model.Maintenance.ValueBool(), "maintenanceReason": model.MaintenanceReason.ValueString(),
		"maxProjects": optionalInt64(model.MaxProjects), "maxEnvironments": optionalInt64(model.MaxEnvironments),
		"maxServices": optionalInt64(model.MaxServices), "maxDatabases": optionalInt64(model.MaxDatabases),
	}
}

func optionalInt64(value types.Int64) any {
	if value.IsNull() || value.IsUnknown() {
		return nil
	}
	return value.ValueInt64()
}

func setResourcePolicy(model *resourcePolicyModel, item resourcePolicyResponse) {
	model.ID = types.StringValue(resourcePolicyID(item.ScopeType, model.ScopeID.ValueString()))
	model.ScopeType = types.StringValue(item.ScopeType)
	if item.ScopeType != "organization" {
		model.ScopeID = types.StringValue(item.ScopeID)
	}
	model.Maintenance = types.BoolValue(item.Maintenance)
	if item.MaintenanceReason != "" || !model.MaintenanceReason.IsNull() {
		model.MaintenanceReason = types.StringValue(item.MaintenanceReason)
	}
	model.MaxProjects = optionalPolicyInt64(item.MaxProjects)
	model.MaxEnvironments = optionalPolicyInt64(item.MaxEnvironments)
	model.MaxServices = optionalPolicyInt64(item.MaxServices)
	model.MaxDatabases = optionalPolicyInt64(item.MaxDatabases)
	model.UpdatedAt = types.StringValue(item.UpdatedAt)
}

func optionalPolicyInt64(value *int64) types.Int64 {
	if value == nil {
		return types.Int64Null()
	}
	return types.Int64Value(*value)
}

func resourcePolicyPath(scopeType, scopeID string) (string, error) {
	switch scopeType {
	case "organization":
		return "/v1/policy", nil
	case "project":
		return "/v1/projects/" + scopeID + "/policy", nil
	case "environment":
		return "/v1/environments/" + scopeID + "/policy", nil
	default:
		return "", fmt.Errorf("scope_type must be organization, project, or environment")
	}
}

func resourcePolicyID(scopeType, scopeID string) string {
	if scopeType == "organization" {
		return scopeType
	}
	return scopeType + "/" + scopeID
}

func splitResourcePolicyImportID(id string) (string, string, error) {
	parts := strings.Split(id, "/")
	if len(parts) == 1 && parts[0] == "organization" {
		return "organization", "", nil
	}
	if len(parts) != 2 || (parts[0] != "project" && parts[0] != "environment") {
		return "", "", fmt.Errorf("expected organization, project/PROJECT_UUID, or environment/ENVIRONMENT_UUID")
	}
	if _, err := uuid.Parse(parts[1]); err != nil {
		return "", "", fmt.Errorf("scope ID must be a UUID")
	}
	return parts[0], parts[1], nil
}

var _ resource.ResourceWithConfigure = (*resourcePolicyResource)(nil)
var _ resource.ResourceWithValidateConfig = (*resourcePolicyResource)(nil)
var _ resource.ResourceWithImportState = (*resourcePolicyResource)(nil)
