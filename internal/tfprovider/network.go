package tfprovider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/bendahma/dokploy-go/internal/apiclient"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type networkResource struct{ client *apiclient.Client }
type networkModel struct {
	ID         types.String `tfsdk:"id"`
	ClusterID  types.String `tfsdk:"cluster_id"`
	Name       types.String `tfsdk:"name"`
	Driver     types.String `tfsdk:"driver"`
	Internal   types.Bool   `tfsdk:"internal"`
	Attachable types.Bool   `tfsdk:"attachable"`
	EnableIPv4 types.Bool   `tfsdk:"enable_ipv4"`
	EnableIPv6 types.Bool   `tfsdk:"enable_ipv6"`
	MTU        types.Int64  `tfsdk:"mtu"`
	IPAMJSON   types.String `tfsdk:"ipam_json"`
	DockerID   types.String `tfsdk:"docker_id"`
	Status     types.String `tfsdk:"status"`
	LastError  types.String `tfsdk:"last_error"`
	CreatedAt  types.String `tfsdk:"created_at"`
	UpdatedAt  types.String `tfsdk:"updated_at"`
}
type networkResponse struct {
	ID         string           `json:"id"`
	Name       string           `json:"name"`
	Driver     string           `json:"driver"`
	DockerID   string           `json:"dockerId"`
	Status     string           `json:"status"`
	LastError  string           `json:"lastError"`
	CreatedAt  string           `json:"createdAt"`
	UpdatedAt  string           `json:"updatedAt"`
	ClusterID  *string          `json:"clusterId"`
	Internal   bool             `json:"internal"`
	Attachable bool             `json:"attachable"`
	EnableIPv4 bool             `json:"enableIpv4"`
	EnableIPv6 bool             `json:"enableIpv6"`
	MTU        *int64           `json:"mtu"`
	IPAM       []map[string]any `json:"ipam"`
}

func newNetworkResource() resource.Resource { return &networkResource{} }
func (r *networkResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_network"
}
func (r *networkResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	boolReplace := []planmodifier.Bool{boolplanmodifier.RequiresReplace()}
	intReplace := []planmodifier.Int64{int64planmodifier.RequiresReplace()}
	response.Schema = schema.Schema{Description: "An asynchronously provisioned Docker network on the local or a remote Swarm.", Attributes: map[string]schema.Attribute{
		"id":          schema.StringAttribute{Computed: true},
		"cluster_id":  schema.StringAttribute{Optional: true, PlanModifiers: replace, Description: "Remote cluster UUID; omit for the controller's local Swarm."},
		"name":        schema.StringAttribute{Required: true, PlanModifiers: replace},
		"driver":      schema.StringAttribute{Required: true, PlanModifiers: replace, Description: "overlay or bridge; only ready overlay networks can be attached to Swarm services."},
		"internal":    schema.BoolAttribute{Required: true, PlanModifiers: boolReplace},
		"attachable":  schema.BoolAttribute{Required: true, PlanModifiers: boolReplace},
		"enable_ipv4": schema.BoolAttribute{Required: true, PlanModifiers: boolReplace},
		"enable_ipv6": schema.BoolAttribute{Required: true, PlanModifiers: boolReplace},
		"mtu":         schema.Int64Attribute{Optional: true, PlanModifiers: intReplace},
		"ipam_json":   schema.StringAttribute{Optional: true, PlanModifiers: replace, Description: `JSON array of {"subnet","gateway","ipRange"} objects.`},
		"docker_id":   schema.StringAttribute{Computed: true},
		"status":      schema.StringAttribute{Computed: true},
		"last_error":  schema.StringAttribute{Computed: true},
		"created_at":  schema.StringAttribute{Computed: true},
		"updated_at":  schema.StringAttribute{Computed: true},
	}}
}
func (r *networkResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	r.client = configureResource(request, &response.Diagnostics)
}
func (r *networkResource) ValidateConfig(ctx context.Context, request resource.ValidateConfigRequest, response *resource.ValidateConfigResponse) {
	var config networkModel
	response.Diagnostics.Append(request.Config.Get(ctx, &config)...)
	if response.Diagnostics.HasError() {
		return
	}
	if !config.ClusterID.IsNull() && !config.ClusterID.IsUnknown() && config.ClusterID.ValueString() != "" {
		if _, err := uuid.Parse(config.ClusterID.ValueString()); err != nil {
			response.Diagnostics.AddAttributeError(path.Root("cluster_id"), "Invalid cluster ID", "cluster_id must be a UUID.")
		}
	}
	if !config.IPAMJSON.IsNull() && !config.IPAMJSON.IsUnknown() && config.IPAMJSON.ValueString() != "" {
		var value []map[string]string
		if err := json.Unmarshal([]byte(config.IPAMJSON.ValueString()), &value); err != nil {
			response.Diagnostics.AddAttributeError(path.Root("ipam_json"), "Invalid IPAM JSON", err.Error())
		}
	}
}
func (r *networkResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var plan networkModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	body := map[string]any{"name": plan.Name.ValueString(), "driver": plan.Driver.ValueString(), "internal": plan.Internal.ValueBool(), "attachable": plan.Attachable.ValueBool(), "enableIpv4": plan.EnableIPv4.ValueBool(), "enableIpv6": plan.EnableIPv6.ValueBool()}
	if !plan.ClusterID.IsNull() && plan.ClusterID.ValueString() != "" {
		body["clusterId"] = plan.ClusterID.ValueString()
	}
	if !plan.MTU.IsNull() {
		body["mtu"] = plan.MTU.ValueInt64()
	}
	if !plan.IPAMJSON.IsNull() && plan.IPAMJSON.ValueString() != "" {
		var ipam []map[string]string
		_ = json.Unmarshal([]byte(plan.IPAMJSON.ValueString()), &ipam)
		body["ipam"] = ipam
	}
	item, err := call[networkResponse](ctx, r.client, http.MethodPost, "/v1/networks", body)
	if err != nil {
		response.Diagnostics.AddError("Unable to create network", err.Error())
		return
	}
	setNetwork(&plan, item)
	item, err = r.wait(ctx, item.ID, false)
	if err != nil {
		response.Diagnostics.AddError("Unable to provision network", err.Error())
		return
	}
	setNetwork(&plan, item)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}
func (r *networkResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var state networkModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := call[networkResponse](ctx, r.client, http.MethodGet, "/v1/networks/"+state.ID.ValueString(), nil)
	if notFound(err) {
		response.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		response.Diagnostics.AddError("Unable to read network", err.Error())
		return
	}
	setNetwork(&state, item)
	response.Diagnostics.Append(response.State.Set(ctx, &state)...)
}
func (r *networkResource) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {}
func (r *networkResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var state networkModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	_, err := call[struct{}](ctx, r.client, http.MethodDelete, "/v1/networks/"+state.ID.ValueString(), nil)
	if err != nil && !notFound(err) {
		response.Diagnostics.AddError("Unable to delete network", err.Error())
		return
	}
	if notFound(err) {
		return
	}
	if _, err = r.wait(ctx, state.ID.ValueString(), true); err != nil {
		response.Diagnostics.AddError("Unable to delete network", err.Error())
	}
}
func (r *networkResource) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), request, response)
}
func (r *networkResource) wait(ctx context.Context, id string, deleted bool) (networkResponse, error) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		item, err := call[networkResponse](ctx, r.client, http.MethodGet, "/v1/networks/"+id, nil)
		if deleted && notFound(err) {
			return networkResponse{}, nil
		}
		if err != nil {
			return networkResponse{}, err
		}
		if !deleted && item.Status == "ready" {
			return item, nil
		}
		if !deleted && item.Status == "error" {
			return networkResponse{}, fmt.Errorf("network provisioning failed: %s", item.LastError)
		}
		select {
		case <-ctx.Done():
			return networkResponse{}, ctx.Err()
		case <-ticker.C:
		}
	}
}
func setNetwork(model *networkModel, item networkResponse) {
	model.ID, model.Name, model.Driver = types.StringValue(item.ID), types.StringValue(item.Name), types.StringValue(item.Driver)
	if item.ClusterID == nil {
		model.ClusterID = types.StringNull()
	} else {
		model.ClusterID = types.StringValue(*item.ClusterID)
	}
	model.Internal, model.Attachable, model.EnableIPv4, model.EnableIPv6 = types.BoolValue(item.Internal), types.BoolValue(item.Attachable), types.BoolValue(item.EnableIPv4), types.BoolValue(item.EnableIPv6)
	if item.MTU == nil {
		model.MTU = types.Int64Null()
	} else {
		model.MTU = types.Int64Value(*item.MTU)
	}
	encoded, _ := json.Marshal(item.IPAM)
	model.IPAMJSON = types.StringValue(string(encoded))
	model.DockerID, model.Status, model.LastError = types.StringValue(item.DockerID), types.StringValue(item.Status), types.StringValue(item.LastError)
	model.CreatedAt, model.UpdatedAt = types.StringValue(item.CreatedAt), types.StringValue(item.UpdatedAt)
}

var _ resource.ResourceWithConfigure = (*networkResource)(nil)
var _ resource.ResourceWithValidateConfig = (*networkResource)(nil)
var _ resource.ResourceWithImportState = (*networkResource)(nil)
