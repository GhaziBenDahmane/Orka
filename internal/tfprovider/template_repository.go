package tfprovider

import (
	"context"
	"net/http"

	"github.com/GhaziBenDahmane/Orka/internal/apiclient"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type templateRepositoryResource struct{ client *apiclient.Client }

type templateRepositoryModel struct {
	ID                  types.String `tfsdk:"id"`
	Name                types.String `tfsdk:"name"`
	Slug                types.String `tfsdk:"slug"`
	RepositoryURL       types.String `tfsdk:"repository_url"`
	GitRef              types.String `tfsdk:"git_ref"`
	CatalogPath         types.String `tfsdk:"catalog_path"`
	TrustedPublicKey    types.String `tfsdk:"trusted_public_key"`
	RequireSignature    types.Bool   `tfsdk:"require_signature"`
	CredentialID        types.String `tfsdk:"credential_id"`
	SyncIntervalSeconds types.Int64  `tfsdk:"sync_interval_seconds"`
}

type templateRepositoryResponse struct {
	ID                  string  `json:"id"`
	Name                string  `json:"name"`
	Slug                string  `json:"slug"`
	RepositoryURL       string  `json:"repositoryUrl"`
	GitRef              string  `json:"gitRef"`
	CatalogPath         string  `json:"catalogPath"`
	TrustedPublicKey    string  `json:"trustedPublicKey"`
	RequireSignature    bool    `json:"requireSignature"`
	CredentialID        *string `json:"credentialId"`
	SyncIntervalSeconds int64   `json:"syncIntervalSeconds"`
}

func newTemplateRepositoryResource() resource.Resource { return &templateRepositoryResource{} }

func (r *templateRepositoryResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_template_repository"
}

func (r *templateRepositoryResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	response.Schema = schema.Schema{Description: "A namespaced Dokploy-compatible template catalog in a GitHub repository.", Attributes: map[string]schema.Attribute{
		"id":                    schema.StringAttribute{Computed: true},
		"name":                  schema.StringAttribute{Required: true, PlanModifiers: replace},
		"slug":                  schema.StringAttribute{Required: true, PlanModifiers: replace},
		"repository_url":        schema.StringAttribute{Required: true, PlanModifiers: replace, Description: "Canonical HTTPS GitHub repository URL."},
		"git_ref":               schema.StringAttribute{Required: true, PlanModifiers: replace, Description: "Branch, tag, or commit to synchronize."},
		"catalog_path":          schema.StringAttribute{Optional: true, PlanModifiers: replace, Description: "Safe relative path containing the blueprints directory."},
		"trusted_public_key":    schema.StringAttribute{Optional: true, Description: "PEM or base64 Ed25519 public key used to verify the catalog manifest."},
		"require_signature":     schema.BoolAttribute{Required: true},
		"credential_id":         schema.StringAttribute{Optional: true, Description: "Organization GitHub HTTPS-token credential ID for a private repository."},
		"sync_interval_seconds": schema.Int64Attribute{Required: true, Description: "Zero for manual synchronization, or 300 through 604800."},
	}}
}

func (r *templateRepositoryResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	r.client = configureResource(request, &response.Diagnostics)
}

func (r *templateRepositoryResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var plan templateRepositoryModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := call[templateRepositoryResponse](ctx, r.client, http.MethodPost, "/v1/template-repositories", templateRepositoryInput(plan, true))
	if err != nil {
		response.Diagnostics.AddError("Unable to create template repository", err.Error())
		return
	}
	setTemplateRepository(&plan, item)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *templateRepositoryResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var state templateRepositoryModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, found, err := r.read(ctx, state.ID.ValueString())
	if err != nil {
		response.Diagnostics.AddError("Unable to read template repository", err.Error())
		return
	}
	if !found {
		response.State.RemoveResource(ctx)
		return
	}
	setTemplateRepository(&state, item)
	response.Diagnostics.Append(response.State.Set(ctx, &state)...)
}

func (r *templateRepositoryResource) Update(ctx context.Context, request resource.UpdateRequest, response *resource.UpdateResponse) {
	var plan templateRepositoryModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	_, err := call[struct{}](ctx, r.client, http.MethodPatch, "/v1/template-repositories/"+plan.ID.ValueString(), templateRepositoryInput(plan, false))
	if err != nil {
		response.Diagnostics.AddError("Unable to update template repository", err.Error())
		return
	}
	item, found, err := r.read(ctx, plan.ID.ValueString())
	if err != nil {
		response.Diagnostics.AddError("Unable to read updated template repository", err.Error())
		return
	}
	if !found {
		response.Diagnostics.AddError("Unable to read updated template repository", "The repository disappeared after its settings were updated.")
		return
	}
	setTemplateRepository(&plan, item)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *templateRepositoryResource) read(ctx context.Context, id string) (templateRepositoryResponse, bool, error) {
	result, err := call[struct {
		Items []templateRepositoryResponse `json:"items"`
	}](ctx, r.client, http.MethodGet, "/v1/template-repositories", nil)
	if err != nil {
		return templateRepositoryResponse{}, false, err
	}
	for _, item := range result.Items {
		if item.ID == id {
			return item, true, nil
		}
	}
	return templateRepositoryResponse{}, false, nil
}

func (r *templateRepositoryResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var state templateRepositoryModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	_, err := call[struct{}](ctx, r.client, http.MethodDelete, "/v1/template-repositories/"+state.ID.ValueString(), nil)
	if err != nil && !notFound(err) {
		response.Diagnostics.AddError("Unable to delete template repository", err.Error())
	}
}

func (r *templateRepositoryResource) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), request, response)
}

func templateRepositoryInput(model templateRepositoryModel, includeIdentity bool) map[string]any {
	input := map[string]any{
		"trustedPublicKey": model.TrustedPublicKey.ValueString(), "requireSignature": model.RequireSignature.ValueBool(), "credentialId": model.CredentialID.ValueString(), "syncIntervalSeconds": model.SyncIntervalSeconds.ValueInt64(),
	}
	if includeIdentity {
		input["name"], input["slug"], input["repositoryUrl"] = model.Name.ValueString(), model.Slug.ValueString(), model.RepositoryURL.ValueString()
		input["gitRef"], input["catalogPath"] = model.GitRef.ValueString(), model.CatalogPath.ValueString()
	}
	return input
}

func setTemplateRepository(model *templateRepositoryModel, item templateRepositoryResponse) {
	model.ID = types.StringValue(item.ID)
	model.Name = types.StringValue(item.Name)
	model.Slug = types.StringValue(item.Slug)
	model.RepositoryURL = types.StringValue(item.RepositoryURL)
	model.GitRef = types.StringValue(item.GitRef)
	model.CatalogPath = optionalTemplateRepositoryString(model.CatalogPath, item.CatalogPath)
	model.TrustedPublicKey = optionalTemplateRepositoryString(model.TrustedPublicKey, item.TrustedPublicKey)
	model.RequireSignature = types.BoolValue(item.RequireSignature)
	if item.CredentialID != nil {
		model.CredentialID = types.StringValue(*item.CredentialID)
	} else {
		model.CredentialID = optionalTemplateRepositoryString(model.CredentialID, "")
	}
	model.SyncIntervalSeconds = types.Int64Value(item.SyncIntervalSeconds)
}

func optionalTemplateRepositoryString(current types.String, value string) types.String {
	if value != "" || !current.IsNull() && !current.IsUnknown() {
		return types.StringValue(value)
	}
	return types.StringNull()
}

var _ resource.ResourceWithConfigure = (*templateRepositoryResource)(nil)
var _ resource.ResourceWithImportState = (*templateRepositoryResource)(nil)
