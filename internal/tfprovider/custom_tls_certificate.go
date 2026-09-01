package tfprovider

import (
	"context"
	"net/http"

	"github.com/GhaziBenDahmane/Orka/internal/apiclient"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type customTLSCertificateResource struct{ client *apiclient.Client }

type customTLSCertificateModel struct {
	ID             types.String `tfsdk:"id"`
	Name           types.String `tfsdk:"name"`
	CertificatePEM types.String `tfsdk:"certificate_pem"`
	PrivateKeyPEM  types.String `tfsdk:"private_key_pem"`
	Fingerprint    types.String `tfsdk:"fingerprint"`
	DNSNames       types.List   `tfsdk:"dns_names"`
	NotBefore      types.String `tfsdk:"not_before"`
	NotAfter       types.String `tfsdk:"not_after"`
	Revision       types.Int64  `tfsdk:"revision"`
}

type customTLSCertificateResponse struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Fingerprint string   `json:"fingerprint"`
	DNSNames    []string `json:"dnsNames"`
	NotBefore   string   `json:"notBefore"`
	NotAfter    string   `json:"notAfter"`
	Revision    int64    `json:"revision"`
}

func newCustomTLSCertificateResource() resource.Resource { return &customTLSCertificateResource{} }

func (r *customTLSCertificateResource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = request.ProviderTypeName + "_custom_tls_certificate"
}

func (r *customTLSCertificateResource) Schema(_ context.Context, _ resource.SchemaRequest, response *resource.SchemaResponse) {
	response.Schema = schema.Schema{Description: "An encrypted custom TLS certificate reconciled to attached Traefik edge targets.", Attributes: map[string]schema.Attribute{
		"id":              schema.StringAttribute{Computed: true},
		"name":            schema.StringAttribute{Required: true},
		"certificate_pem": schema.StringAttribute{Required: true, Sensitive: true, Description: "Leaf-first PEM certificate chain. Retained only in Terraform state because the API is write-only."},
		"private_key_pem": schema.StringAttribute{Required: true, Sensitive: true, Description: "Matching unencrypted PEM private key. Retained only in Terraform state because the API is write-only."},
		"fingerprint":     schema.StringAttribute{Computed: true},
		"dns_names":       schema.ListAttribute{Computed: true, ElementType: types.StringType},
		"not_before":      schema.StringAttribute{Computed: true},
		"not_after":       schema.StringAttribute{Computed: true},
		"revision":        schema.Int64Attribute{Computed: true},
	}}
}

func (r *customTLSCertificateResource) Configure(_ context.Context, request resource.ConfigureRequest, response *resource.ConfigureResponse) {
	r.client = configureResource(request, &response.Diagnostics)
}

func (r *customTLSCertificateResource) Create(ctx context.Context, request resource.CreateRequest, response *resource.CreateResponse) {
	var plan customTLSCertificateModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if response.Diagnostics.HasError() {
		return
	}
	item, err := call[customTLSCertificateResponse](ctx, r.client, http.MethodPost, "/v1/custom-tls-certificates", customTLSCertificateRequest(plan, 0))
	if err != nil {
		response.Diagnostics.AddError("Unable to create custom TLS certificate", err.Error())
		return
	}
	setCustomTLSCertificate(ctx, &plan, item, &response.Diagnostics)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *customTLSCertificateResource) Read(ctx context.Context, request resource.ReadRequest, response *resource.ReadResponse) {
	var state customTLSCertificateModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	result, err := call[struct {
		Items []customTLSCertificateResponse `json:"items"`
	}](ctx, r.client, http.MethodGet, "/v1/custom-tls-certificates", nil)
	if err != nil {
		response.Diagnostics.AddError("Unable to read custom TLS certificate", err.Error())
		return
	}
	for _, item := range result.Items {
		if item.ID == state.ID.ValueString() {
			setCustomTLSCertificate(ctx, &state, item, &response.Diagnostics)
			response.Diagnostics.Append(response.State.Set(ctx, &state)...)
			return
		}
	}
	response.State.RemoveResource(ctx)
}

func (r *customTLSCertificateResource) Update(ctx context.Context, request resource.UpdateRequest, response *resource.UpdateResponse) {
	var plan, state customTLSCertificateModel
	response.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	plan.ID = state.ID
	item, err := call[customTLSCertificateResponse](ctx, r.client, http.MethodPut, "/v1/custom-tls-certificates/"+state.ID.ValueString(), customTLSCertificateRequest(plan, state.Revision.ValueInt64()))
	if err != nil {
		response.Diagnostics.AddError("Unable to rotate custom TLS certificate", err.Error())
		return
	}
	setCustomTLSCertificate(ctx, &plan, item, &response.Diagnostics)
	response.Diagnostics.Append(response.State.Set(ctx, &plan)...)
}

func (r *customTLSCertificateResource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	var state customTLSCertificateModel
	response.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if response.Diagnostics.HasError() {
		return
	}
	_, err := call[struct{}](ctx, r.client, http.MethodDelete, "/v1/custom-tls-certificates/"+state.ID.ValueString(), nil)
	if err != nil && !notFound(err) {
		response.Diagnostics.AddError("Unable to delete custom TLS certificate", err.Error())
	}
}

func customTLSCertificateRequest(model customTLSCertificateModel, revision int64) map[string]any {
	result := map[string]any{"name": model.Name.ValueString(), "certificatePem": model.CertificatePEM.ValueString(), "privateKeyPem": model.PrivateKeyPEM.ValueString()}
	if revision > 0 {
		result["revision"] = revision
	}
	return result
}

func setCustomTLSCertificate(ctx context.Context, model *customTLSCertificateModel, item customTLSCertificateResponse, diagnostics *diag.Diagnostics) {
	dnsNames, listDiagnostics := types.ListValueFrom(ctx, types.StringType, item.DNSNames)
	diagnostics.Append(listDiagnostics...)
	model.ID = types.StringValue(item.ID)
	model.Name = types.StringValue(item.Name)
	model.Fingerprint = types.StringValue(item.Fingerprint)
	model.DNSNames = dnsNames
	model.NotBefore = types.StringValue(item.NotBefore)
	model.NotAfter = types.StringValue(item.NotAfter)
	model.Revision = types.Int64Value(item.Revision)
}

var _ resource.ResourceWithConfigure = (*customTLSCertificateResource)(nil)
