package tfprovider

import (
	"context"
	"net/http"

	"github.com/bendahma/dokploy-go/internal/apiclient"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type sourceCredentialResource struct{ client *apiclient.Client }

type sourceCredentialModel struct {
	ID         types.String `tfsdk:"id"`
	Kind       types.String `tfsdk:"kind"`
	Name       types.String `tfsdk:"name"`
	Server     types.String `tfsdk:"server"`
	Username   types.String `tfsdk:"username"`
	Secret     types.String `tfsdk:"secret"`
	PrivateKey types.String `tfsdk:"private_key"`
	KnownHosts types.String `tfsdk:"known_hosts"`
}

type sourceCredentialResponse struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	Server   string `json:"server"`
	Username string `json:"username"`
}

func newSourceCredentialResource() resource.Resource { return &sourceCredentialResource{} }

func (r *sourceCredentialResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_source_credential"
}

func (r *sourceCredentialResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	response.Schema = schema.Schema{Description: "An encrypted Git, SSH, or registry credential.", Attributes: map[string]schema.Attribute{
		"id":          schema.StringAttribute{Computed: true},
		"kind":        schema.StringAttribute{Required: true, PlanModifiers: replace, Description: "One of git, git-ssh, or registry."},
		"name":        schema.StringAttribute{Required: true, PlanModifiers: replace},
		"server":      schema.StringAttribute{Required: true, PlanModifiers: replace},
		"username":    schema.StringAttribute{Required: true, PlanModifiers: replace},
		"secret":      schema.StringAttribute{Optional: true, Sensitive: true, PlanModifiers: replace, Description: "HTTPS token, password, or registry secret."},
		"private_key": schema.StringAttribute{Optional: true, Sensitive: true, PlanModifiers: replace, Description: "PEM private key for git-ssh credentials."},
		"known_hosts": schema.StringAttribute{Optional: true, Sensitive: true, PlanModifiers: replace, Description: "Pinned known_hosts entries for git-ssh credentials."},
	}}
}

func (r *sourceCredentialResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	r.client = configureResource(request, &response.Diagnostics)
}

func (r *sourceCredentialResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var plan sourceCredentialModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := call[sourceCredentialResponse](ctx, r.client, http.MethodPost, "/v1/source-credentials", map[string]string{
		"kind": plan.Kind.ValueString(), "name": plan.Name.ValueString(), "server": plan.Server.ValueString(), "username": plan.Username.ValueString(), "secret": plan.Secret.ValueString(), "privateKey": plan.PrivateKey.ValueString(), "knownHosts": plan.KnownHosts.ValueString(),
	})
	if err != nil {
		response.Diagnostics.AddError("Unable to create source credential", err.Error())
		return
	}
	setSourceCredential(&plan, item)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *sourceCredentialResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var state sourceCredentialModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	result, err := call[struct {
		Items []sourceCredentialResponse `json:"items"`
	}](ctx, r.client, http.MethodGet, "/v1/source-credentials", nil)
	if err != nil {
		response.Diagnostics.AddError("Unable to read source credential", err.Error())
		return
	}
	for _, item := range result.Items {
		if item.ID == state.ID.ValueString() {
			setSourceCredential(&state, item)
			response.Diagnostics.Append(response.State.Set(ctx, &state)...)
			return
		}
	}
	response.State.RemoveResource(ctx)
}

func (r *sourceCredentialResource) Update(context.Context, resource.UpdateRequest, *resource.UpdateResponse) {
}

func (r *sourceCredentialResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var state sourceCredentialModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	_, err := call[struct{}](ctx, r.client, http.MethodDelete, "/v1/source-credentials/"+state.ID.ValueString(), nil)
	if err != nil && !notFound(err) {
		response.Diagnostics.AddError("Unable to delete source credential", err.Error())
	}
}

func (r *sourceCredentialResource) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), request, response)
}

func setSourceCredential(model *sourceCredentialModel, item sourceCredentialResponse) {
	model.ID = types.StringValue(item.ID)
	model.Kind = types.StringValue(item.Kind)
	model.Name = types.StringValue(item.Name)
	model.Server = types.StringValue(item.Server)
	model.Username = types.StringValue(item.Username)
}

var _ resource.ResourceWithConfigure = (*sourceCredentialResource)(nil)
var _ resource.ResourceWithImportState = (*sourceCredentialResource)(nil)
