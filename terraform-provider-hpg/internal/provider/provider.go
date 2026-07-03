package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// hpgProvider implements provider.Provider.
type hpgProvider struct {
	version string
}

type providerModel struct {
	Endpoint types.String `tfsdk:"endpoint"`
	APIKey   types.String `tfsdk:"api_key"`
}

// New returns the provider constructor used by providerserver.Serve.
func New(version string) func() provider.Provider {
	return func() provider.Provider { return &hpgProvider{version: version} }
}

func (p *hpgProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "hpg"
	resp.Version = p.version
}

func (p *hpgProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manage Hostyt Proxy Gateway resources over REST API v1.",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				MarkdownDescription: "Panel base URL, e.g. `https://panel.example.com` (no `/api/v1` suffix). Falls back to `HPG_ENDPOINT`.",
				Optional:            true,
			},
			"api_key": schema.StringAttribute{
				MarkdownDescription: "Bearer API key. Falls back to `HPG_API_KEY`. Reseller keys are scoped server-side.",
				Optional:            true,
				Sensitive:           true,
			},
		},
	}
}

func (p *hpgProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	endpoint := cfg.Endpoint.ValueString()
	if endpoint == "" {
		endpoint = os.Getenv("HPG_ENDPOINT")
	}
	apiKey := cfg.APIKey.ValueString()
	if apiKey == "" {
		apiKey = os.Getenv("HPG_API_KEY")
	}
	if endpoint == "" {
		resp.Diagnostics.AddAttributeError(pathRoot("endpoint"), "Missing endpoint", "Set the provider `endpoint` or the HPG_ENDPOINT env var.")
	}
	if apiKey == "" {
		resp.Diagnostics.AddAttributeError(pathRoot("api_key"), "Missing api_key", "Set the provider `api_key` or the HPG_API_KEY env var.")
	}
	if resp.Diagnostics.HasError() {
		return
	}

	client := NewClient(endpoint, apiKey)
	resp.ResourceData = client
	resp.DataSourceData = client
}

func (p *hpgProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewNodePoolResource,
		NewNodeResource,
		NewPlanResource,
		NewClientResource,
		NewServiceResource,
		NewRouteResource,
		NewResellerResource,
		NewResellerPlanResource,
	}
}

func (p *hpgProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}
