package tfprovider

import (
	"context"
	"net/http"

	"github.com/bendahma/dokploy-go/internal/apiclient"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type backupDestinationResource struct{ client *apiclient.Client }

type backupDestinationModel struct {
	ID           types.String `tfsdk:"id"`
	Name         types.String `tfsdk:"name"`
	Endpoint     types.String `tfsdk:"endpoint"`
	Region       types.String `tfsdk:"region"`
	Bucket       types.String `tfsdk:"bucket"`
	Prefix       types.String `tfsdk:"prefix"`
	UseTLS       types.Bool   `tfsdk:"use_tls"`
	AccessKey    types.String `tfsdk:"access_key"`
	SecretKey    types.String `tfsdk:"secret_key"`
	SessionToken types.String `tfsdk:"session_token"`
}

type backupDestinationResponse struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Endpoint string `json:"endpoint"`
	Region   string `json:"region"`
	Bucket   string `json:"bucket"`
	Prefix   string `json:"prefix"`
	UseTLS   bool   `json:"useTls"`
}

func newBackupDestinationResource() resource.Resource { return &backupDestinationResource{} }

func (r *backupDestinationResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_backup_destination"
}

func (r *backupDestinationResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	response.Schema = schema.Schema{Description: "An encrypted S3-compatible backup destination.", Attributes: map[string]schema.Attribute{
		"id":            schema.StringAttribute{Computed: true},
		"name":          schema.StringAttribute{Required: true, PlanModifiers: replace},
		"endpoint":      schema.StringAttribute{Required: true, PlanModifiers: replace},
		"region":        schema.StringAttribute{Optional: true, PlanModifiers: replace},
		"bucket":        schema.StringAttribute{Required: true, PlanModifiers: replace},
		"prefix":        schema.StringAttribute{Optional: true, PlanModifiers: replace},
		"use_tls":       schema.BoolAttribute{Required: true, PlanModifiers: []planmodifier.Bool{boolplanmodifier.RequiresReplace()}},
		"access_key":    schema.StringAttribute{Required: true, Sensitive: true, PlanModifiers: replace},
		"secret_key":    schema.StringAttribute{Required: true, Sensitive: true, PlanModifiers: replace},
		"session_token": schema.StringAttribute{Optional: true, Sensitive: true, PlanModifiers: replace},
	}}
}

func (r *backupDestinationResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	r.client = configureResource(request, &response.Diagnostics)
}

func (r *backupDestinationResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var plan backupDestinationModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := call[backupDestinationResponse](ctx, r.client, http.MethodPost, "/v1/backup-destinations", map[string]any{
		"name": plan.Name.ValueString(), "endpoint": plan.Endpoint.ValueString(), "region": plan.Region.ValueString(), "bucket": plan.Bucket.ValueString(), "prefix": plan.Prefix.ValueString(), "useTls": plan.UseTLS.ValueBool(), "accessKey": plan.AccessKey.ValueString(), "secretKey": plan.SecretKey.ValueString(), "sessionToken": plan.SessionToken.ValueString(),
	})
	if err != nil {
		response.Diagnostics.AddError("Unable to create backup destination", err.Error())
		return
	}
	setBackupDestination(&plan, item)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *backupDestinationResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var state backupDestinationModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	result, err := call[struct {
		Items []backupDestinationResponse `json:"items"`
	}](ctx, r.client, http.MethodGet, "/v1/backup-destinations", nil)
	if err != nil {
		response.Diagnostics.AddError("Unable to read backup destination", err.Error())
		return
	}
	for _, item := range result.Items {
		if item.ID == state.ID.ValueString() {
			setBackupDestination(&state, item)
			response.Diagnostics.Append(response.State.Set(ctx, &state)...)
			return
		}
	}
	response.State.RemoveResource(ctx)
}

func (r *backupDestinationResource) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {
}

func (r *backupDestinationResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var state backupDestinationModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	_, err := call[struct{}](ctx, r.client, http.MethodDelete, "/v1/backup-destinations/"+state.ID.ValueString(), nil)
	if err != nil && !notFound(err) {
		response.Diagnostics.AddError("Unable to delete backup destination", err.Error())
	}
}

func (r *backupDestinationResource) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), request, response)
}

func setBackupDestination(model *backupDestinationModel, item backupDestinationResponse) {
	model.ID = types.StringValue(item.ID)
	model.Name = types.StringValue(item.Name)
	model.Endpoint = types.StringValue(item.Endpoint)
	model.Region = types.StringValue(item.Region)
	model.Bucket = types.StringValue(item.Bucket)
	model.Prefix = types.StringValue(item.Prefix)
	model.UseTLS = types.BoolValue(item.UseTLS)
}

var _ resource.ResourceWithConfigure = (*backupDestinationResource)(nil)
var _ resource.ResourceWithImportState = (*backupDestinationResource)(nil)
