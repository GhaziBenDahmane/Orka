package tfprovider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/GhaziBenDahmane/Orka/internal/apiclient"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type clusterResource struct{ client *apiclient.Client }

type clusterModel struct {
	ID                              types.String `tfsdk:"id"`
	Name                            types.String `tfsdk:"name"`
	Slug                            types.String `tfsdk:"slug"`
	Labels                          types.Map    `tfsdk:"labels"`
	State                           types.String `tfsdk:"state"`
	CapacityJSON                    types.String `tfsdk:"capacity_json"`
	AgentVersion                    types.String `tfsdk:"agent_version"`
	AgentImage                      types.String `tfsdk:"agent_image"`
	AgentUpdateState                types.String `tfsdk:"agent_update_state"`
	DockerVersion                   types.String `tfsdk:"docker_version"`
	CertificateAuthorityFingerprint types.String `tfsdk:"certificate_authority_fingerprint"`
	PendingCAFingerprint            types.String `tfsdk:"pending_certificate_authority_fingerprint"`
	CertificateNotAfter             types.String `tfsdk:"certificate_not_after"`
	LastSeenAt                      types.String `tfsdk:"last_seen_at"`
	MaintenanceStartsAt             types.String `tfsdk:"maintenance_starts_at"`
	MaintenanceEndsAt               types.String `tfsdk:"maintenance_ends_at"`
	CreatedAt                       types.String `tfsdk:"created_at"`
	UpdatedAt                       types.String `tfsdk:"updated_at"`
}

type clusterResponse struct {
	ID                              string         `json:"id"`
	Name                            string         `json:"name"`
	Slug                            string         `json:"slug"`
	Labels                          map[string]any `json:"labels"`
	State                           string         `json:"state"`
	Capacity                        map[string]any `json:"capacity"`
	AgentVersion                    string         `json:"agentVersion"`
	AgentImage                      string         `json:"agentImage"`
	AgentUpdateState                string         `json:"agentUpdateState"`
	DockerVersion                   string         `json:"dockerVersion"`
	CertificateAuthorityFingerprint string         `json:"certificateAuthorityFingerprint"`
	PendingCAFingerprint            string         `json:"pendingCertificateAuthorityFingerprint"`
	CertificateNotAfter             *string        `json:"certificateNotAfter"`
	LastSeenAt                      *string        `json:"lastSeenAt"`
	MaintenanceStartsAt             *string        `json:"maintenanceStartsAt"`
	MaintenanceEndsAt               *string        `json:"maintenanceEndsAt"`
	CreatedAt                       string         `json:"createdAt"`
	UpdatedAt                       string         `json:"updatedAt"`
}

func newClusterResource() resource.Resource { return &clusterResource{} }

func (r *clusterResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_cluster"
}

func (r *clusterResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	stringReplace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	response.Schema = schema.Schema{Description: "A registered remote Docker Swarm cluster. Enrollment and operational state transitions remain explicit operator actions.", Attributes: map[string]schema.Attribute{
		"id":                                schema.StringAttribute{Computed: true},
		"name":                              schema.StringAttribute{Required: true, PlanModifiers: stringReplace},
		"slug":                              schema.StringAttribute{Optional: true, Computed: true, PlanModifiers: stringReplace},
		"labels":                            schema.MapAttribute{Optional: true, Computed: true, ElementType: types.StringType, PlanModifiers: []planmodifier.Map{mapplanmodifier.RequiresReplace()}},
		"state":                             schema.StringAttribute{Computed: true},
		"capacity_json":                     schema.StringAttribute{Computed: true},
		"agent_version":                     schema.StringAttribute{Computed: true},
		"agent_image":                       schema.StringAttribute{Computed: true},
		"agent_update_state":                schema.StringAttribute{Computed: true},
		"docker_version":                    schema.StringAttribute{Computed: true},
		"certificate_authority_fingerprint": schema.StringAttribute{Computed: true},
		"pending_certificate_authority_fingerprint": schema.StringAttribute{Computed: true},
		"certificate_not_after":                     schema.StringAttribute{Computed: true},
		"last_seen_at":                              schema.StringAttribute{Computed: true},
		"maintenance_starts_at":                     schema.StringAttribute{Computed: true},
		"maintenance_ends_at":                       schema.StringAttribute{Computed: true},
		"created_at":                                schema.StringAttribute{Computed: true},
		"updated_at":                                schema.StringAttribute{Computed: true},
	}}
}

func (r *clusterResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	r.client = configureResource(request, &response.Diagnostics)
}

func (r *clusterResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var plan clusterModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	labels := map[string]string{}
	if !plan.Labels.IsNull() && !plan.Labels.IsUnknown() {
		response.Diagnostics.Append(plan.Labels.ElementsAs(ctx, &labels, false)...)
		if response.Diagnostics.HasError() {
			return
		}
	}
	item, err := call[clusterResponse](ctx, r.client, http.MethodPost, "/v1/clusters", map[string]any{"name": plan.Name.ValueString(), "slug": plan.Slug.ValueString(), "labels": labels})
	if err != nil {
		response.Diagnostics.AddError("Unable to register cluster", err.Error())
		return
	}
	if err = setCluster(&plan, item); err != nil {
		response.Diagnostics.AddError("Unable to store cluster state", err.Error())
		return
	}
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *clusterResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var state clusterModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, found, err := r.read(ctx, state.ID.ValueString())
	if err != nil {
		response.Diagnostics.AddError("Unable to read cluster", err.Error())
		return
	}
	if !found {
		response.State.RemoveResource(ctx)
		return
	}
	if err = setCluster(&state, item); err != nil {
		response.Diagnostics.AddError("Unable to store cluster state", err.Error())
		return
	}
	response.Diagnostics.Append(response.State.Set(ctx, &state)...)
}

func (r *clusterResource) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {}

func (r *clusterResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var state clusterModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	_, err := call[struct{}](ctx, r.client, http.MethodDelete, "/v1/clusters/"+state.ID.ValueString(), nil)
	if err != nil && !notFound(err) {
		response.Diagnostics.AddError("Unable to delete cluster", fmt.Sprintf("%v. Move or delete assigned environments first.", err))
		return
	}
	if notFound(err) {
		return
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			response.Diagnostics.AddError("Timed out deleting cluster", ctx.Err().Error())
			return
		case <-ticker.C:
			_, found, readErr := r.read(ctx, state.ID.ValueString())
			if readErr != nil {
				response.Diagnostics.AddError("Unable to verify cluster deletion", readErr.Error())
				return
			}
			if !found {
				return
			}
		}
	}
}

func (r *clusterResource) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), request, response)
}

func (r *clusterResource) read(ctx context.Context, id string) (clusterResponse, bool, error) {
	result, err := call[struct {
		Items []clusterResponse `json:"items"`
	}](ctx, r.client, http.MethodGet, "/v1/clusters", nil)
	if err != nil {
		return clusterResponse{}, false, err
	}
	for _, item := range result.Items {
		if item.ID == id {
			return item, true, nil
		}
	}
	return clusterResponse{}, false, nil
}

func setCluster(model *clusterModel, item clusterResponse) error {
	labels := make(map[string]attr.Value, len(item.Labels))
	for key, raw := range item.Labels {
		value, ok := raw.(string)
		if !ok {
			return fmt.Errorf("cluster label %q is not a string", key)
		}
		labels[key] = types.StringValue(value)
	}
	capacity, err := json.Marshal(item.Capacity)
	if err != nil {
		return fmt.Errorf("encode cluster capacity: %w", err)
	}
	model.ID = types.StringValue(item.ID)
	model.Name = types.StringValue(item.Name)
	model.Slug = types.StringValue(item.Slug)
	model.Labels = types.MapValueMust(types.StringType, labels)
	model.State = types.StringValue(item.State)
	model.CapacityJSON = types.StringValue(string(capacity))
	model.AgentVersion = types.StringValue(item.AgentVersion)
	model.AgentImage = types.StringValue(item.AgentImage)
	model.AgentUpdateState = types.StringValue(item.AgentUpdateState)
	model.DockerVersion = types.StringValue(item.DockerVersion)
	model.CertificateAuthorityFingerprint = types.StringValue(item.CertificateAuthorityFingerprint)
	model.PendingCAFingerprint = types.StringValue(item.PendingCAFingerprint)
	model.CertificateNotAfter = optionalComputedString(item.CertificateNotAfter)
	model.LastSeenAt = optionalComputedString(item.LastSeenAt)
	model.MaintenanceStartsAt = optionalComputedString(item.MaintenanceStartsAt)
	model.MaintenanceEndsAt = optionalComputedString(item.MaintenanceEndsAt)
	model.CreatedAt = types.StringValue(item.CreatedAt)
	model.UpdatedAt = types.StringValue(item.UpdatedAt)
	return nil
}

var _ resource.ResourceWithConfigure = (*clusterResource)(nil)
var _ resource.ResourceWithImportState = (*clusterResource)(nil)
