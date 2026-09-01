package tfprovider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/GhaziBenDahmane/Orka/internal/apiclient"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type notificationEndpointResource struct{ client *apiclient.Client }

type notificationEndpointModel struct {
	ID                types.String `tfsdk:"id"`
	Name              types.String `tfsdk:"name"`
	Kind              types.String `tfsdk:"kind"`
	Events            types.Set    `tfsdk:"events"`
	ConfigurationJSON types.String `tfsdk:"configuration_json"`
	SigningSecret     types.String `tfsdk:"signing_secret"`
	Enabled           types.Bool   `tfsdk:"enabled"`
	CreatedAt         types.String `tfsdk:"created_at"`
	UpdatedAt         types.String `tfsdk:"updated_at"`
}

type notificationEndpointResponse struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Kind      string   `json:"kind"`
	Events    []string `json:"events"`
	Enabled   bool     `json:"enabled"`
	CreatedAt string   `json:"createdAt"`
	UpdatedAt string   `json:"updatedAt"`
}

func newNotificationEndpointResource() resource.Resource { return &notificationEndpointResource{} }

func (r *notificationEndpointResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_notification_endpoint"
}

func (r *notificationEndpointResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	stringReplace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	response.Schema = schema.Schema{Description: "An encrypted failure-notification endpoint. Configuration changes replace and disable the previous endpoint.", Attributes: map[string]schema.Attribute{
		"id":                 schema.StringAttribute{Computed: true},
		"name":               schema.StringAttribute{Required: true, PlanModifiers: stringReplace},
		"kind":               schema.StringAttribute{Required: true, PlanModifiers: stringReplace, Description: "One of webhook, slack, smtp, pagerduty, or opsgenie."},
		"events":             schema.SetAttribute{Optional: true, Computed: true, ElementType: types.StringType, PlanModifiers: []planmodifier.Set{setplanmodifier.RequiresReplace()}, Description: "Failure events to deliver; omit to subscribe to every supported event."},
		"configuration_json": schema.StringAttribute{Required: true, Sensitive: true, PlanModifiers: stringReplace, Description: "Provider-specific JSON such as url, pagerDutyIntegrationKey, opsgenieApiKey/opsgenieRegion, or SMTP fields."},
		"signing_secret":     schema.StringAttribute{Computed: true, Sensitive: true, Description: "Generated webhook signing secret returned only when webhook or Slack endpoints are created."},
		"enabled":            schema.BoolAttribute{Computed: true},
		"created_at":         schema.StringAttribute{Computed: true},
		"updated_at":         schema.StringAttribute{Computed: true},
	}}
}

func (r *notificationEndpointResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	r.client = configureResource(request, &response.Diagnostics)
}

func (r *notificationEndpointResource) ValidateConfig(ctx context.Context, request resource.ValidateConfigRequest, response *resource.ValidateConfigResponse) {
	var config notificationEndpointModel
	response.Diagnostics.Append(request.Config.Get(ctx, &config)...)
	if response.Diagnostics.HasError() {
		return
	}
	if !config.Kind.IsNull() && !config.Kind.IsUnknown() && !validNotificationKind(config.Kind.ValueString()) {
		response.Diagnostics.AddAttributeError(path.Root("kind"), "Invalid notification kind", "kind must be webhook, slack, smtp, pagerduty, or opsgenie.")
	}
	if !config.ConfigurationJSON.IsNull() && !config.ConfigurationJSON.IsUnknown() {
		if _, err := notificationEndpointInput(config); err != nil {
			response.Diagnostics.AddAttributeError(path.Root("configuration_json"), "Invalid notification configuration", err.Error())
		}
	}
}

func (r *notificationEndpointResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var plan notificationEndpointModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	input, err := notificationEndpointInput(plan)
	if err != nil {
		response.Diagnostics.AddError("Unable to create notification endpoint", err.Error())
		return
	}
	var events []string
	if !plan.Events.IsNull() && !plan.Events.IsUnknown() {
		response.Diagnostics.Append(plan.Events.ElementsAs(ctx, &events, false)...)
		if response.Diagnostics.HasError() {
			return
		}
		input["events"] = events
	}
	created, err := call[struct {
		Endpoint      notificationEndpointResponse `json:"endpoint"`
		SigningSecret string                       `json:"signingSecret"`
	}](ctx, r.client, http.MethodPost, "/v1/notification-endpoints", input)
	if err != nil {
		response.Diagnostics.AddError("Unable to create notification endpoint", err.Error())
		return
	}
	setNotificationEndpoint(&plan, created.Endpoint)
	if created.SigningSecret == "" {
		plan.SigningSecret = types.StringNull()
	} else {
		plan.SigningSecret = types.StringValue(created.SigningSecret)
	}
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *notificationEndpointResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var state notificationEndpointModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	result, err := call[struct {
		Items []notificationEndpointResponse `json:"items"`
	}](ctx, r.client, http.MethodGet, "/v1/notification-endpoints", nil)
	if err != nil {
		response.Diagnostics.AddError("Unable to read notification endpoint", err.Error())
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
		setNotificationEndpoint(&state, item)
		response.Diagnostics.Append(response.State.Set(ctx, &state)...)
		return
	}
	response.State.RemoveResource(ctx)
}

func (r *notificationEndpointResource) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {
}

func (r *notificationEndpointResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var state notificationEndpointModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	_, err := call[struct{}](ctx, r.client, http.MethodDelete, "/v1/notification-endpoints/"+state.ID.ValueString(), nil)
	if err != nil && !notFound(err) {
		response.Diagnostics.AddError("Unable to disable notification endpoint", err.Error())
	}
}

func notificationEndpointInput(model notificationEndpointModel) (map[string]any, error) {
	var input map[string]any
	if err := json.Unmarshal([]byte(model.ConfigurationJSON.ValueString()), &input); err != nil || input == nil {
		return nil, fmt.Errorf("configuration_json must be a JSON object")
	}
	for _, reserved := range []string{"name", "kind", "events"} {
		if _, exists := input[reserved]; exists {
			return nil, fmt.Errorf("configuration_json must not contain reserved field %q", reserved)
		}
	}
	input["name"] = model.Name.ValueString()
	input["kind"] = model.Kind.ValueString()
	return input, nil
}

func validNotificationKind(kind string) bool {
	return kind == "webhook" || kind == "slack" || kind == "smtp" || kind == "pagerduty" || kind == "opsgenie"
}

func setNotificationEndpoint(model *notificationEndpointModel, item notificationEndpointResponse) {
	model.ID = types.StringValue(item.ID)
	model.Name = types.StringValue(item.Name)
	model.Kind = types.StringValue(item.Kind)
	model.Events = stringSet(item.Events)
	model.Enabled = types.BoolValue(item.Enabled)
	model.CreatedAt = types.StringValue(item.CreatedAt)
	model.UpdatedAt = types.StringValue(item.UpdatedAt)
}

var _ resource.ResourceWithConfigure = (*notificationEndpointResource)(nil)
var _ resource.ResourceWithValidateConfig = (*notificationEndpointResource)(nil)
