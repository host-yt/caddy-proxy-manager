package provider

import (
	"context"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &planResource{}
var _ resource.ResourceWithImportState = &planResource{}

type planResource struct{ client *Client }

func NewPlanResource() resource.Resource { return &planResource{} }

type planModel struct {
	ID                 types.Int64  `tfsdk:"id"`
	Name               types.String `tfsdk:"name"`
	Kind               types.String `tfsdk:"kind"`
	MaxDomains         types.Int64  `tfsdk:"max_domains"`
	MaxPorts           types.Int64  `tfsdk:"max_ports"`
	NodeGroupID        types.Int64  `tfsdk:"node_group_id"`
	SSLEnabled         types.Bool   `tfsdk:"ssl_enabled"`
	PathRoutingEnabled types.Bool   `tfsdk:"path_routing_enabled"`
	WildcardEnabled    types.Bool   `tfsdk:"wildcard_enabled"`
	WebsocketEnabled   types.Bool   `tfsdk:"websocket_enabled"`
	ExternalProxy      types.Bool   `tfsdk:"external_proxy_enabled"`
	AllowEgressIP      types.Bool   `tfsdk:"allow_egress_ip"`
	RateLimitRPM       types.Int64  `tfsdk:"rate_limit_rpm"`
	WGKeyRotationDays  types.Int64  `tfsdk:"wg_key_rotation_days"`
}

type apiPlan struct {
	ID                 int64  `json:"id"`
	Name               string `json:"name"`
	Kind               string `json:"kind"`
	MaxDomains         int64  `json:"max_domains"`
	MaxPorts           int64  `json:"max_ports"`
	NodeGroupID        int64  `json:"node_group_id"`
	SSLEnabled         bool   `json:"ssl_enabled"`
	PathRoutingEnabled bool   `json:"path_routing_enabled"`
	WildcardEnabled    bool   `json:"wildcard_enabled"`
	WebsocketEnabled   bool   `json:"websocket_enabled"`
	ExternalProxy      bool   `json:"external_proxy_enabled"`
	AllowEgressIP      bool   `json:"allow_egress_ip"`
	RateLimitRPM       *int   `json:"rate_limit_rpm"`
	WGKeyRotationDays  *int   `json:"wg_key_rotation_days"`
}

func boolAttrOptComputed() schema.BoolAttribute {
	return schema.BoolAttribute{Optional: true, Computed: true}
}

func (r *planResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_plan"
}

func (r *planResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A service plan (feature limits + node group). Reseller keys create plans owned by their reseller.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Computed:      true,
				PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"name":          schema.StringAttribute{Required: true},
			"max_domains":   schema.Int64Attribute{Required: true},
			"max_ports":     schema.Int64Attribute{Required: true},
			"node_group_id": schema.Int64Attribute{Required: true},
			"kind": schema.StringAttribute{
				Optional: true, Computed: true,
				MarkdownDescription: "`restricted` (default) or `npm`.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"ssl_enabled":            boolAttrOptComputed(),
			"path_routing_enabled":   boolAttrOptComputed(),
			"wildcard_enabled":       boolAttrOptComputed(),
			"websocket_enabled":      boolAttrOptComputed(),
			"external_proxy_enabled": boolAttrOptComputed(),
			"allow_egress_ip":        boolAttrOptComputed(),
			"rate_limit_rpm": schema.Int64Attribute{
				Optional: true, Computed: true,
				MarkdownDescription: "Requests/min cap; 0 = no limit.",
				PlanModifiers:       []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"wg_key_rotation_days": schema.Int64Attribute{
				Optional: true, Computed: true,
				MarkdownDescription: "WireGuard key rotation interval in days; 0 = inherit.",
				PlanModifiers:       []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
		},
	}
}

func (r *planResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFromResourceConfig(req, resp)
}

func (m *planModel) body() map[string]any {
	return map[string]any{
		"name":                   m.Name.ValueString(),
		"kind":                   m.Kind.ValueString(),
		"max_domains":            m.MaxDomains.ValueInt64(),
		"max_ports":              m.MaxPorts.ValueInt64(),
		"node_group_id":          m.NodeGroupID.ValueInt64(),
		"ssl_enabled":            m.SSLEnabled.ValueBool(),
		"path_routing_enabled":   m.PathRoutingEnabled.ValueBool(),
		"wildcard_enabled":       m.WildcardEnabled.ValueBool(),
		"websocket_enabled":      m.WebsocketEnabled.ValueBool(),
		"external_proxy_enabled": m.ExternalProxy.ValueBool(),
		"allow_egress_ip":        m.AllowEgressIP.ValueBool(),
		"rate_limit_rpm":         m.RateLimitRPM.ValueInt64(),
		"wg_key_rotation_days":   m.WGKeyRotationDays.ValueInt64(),
	}
}

func (r *planResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan planModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var created struct {
		ID int64 `json:"id"`
	}
	if err := r.client.Post(ctx, "/plans", plan.body(), &created); err != nil {
		resp.Diagnostics.AddError("Create plan failed", err.Error())
		return
	}
	r.read(ctx, created.ID, &plan, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *planResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state planModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.read(ctx, state.ID.ValueInt64(), &state, &resp.Diagnostics) {
		resp.State.RemoveResource(ctx)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *planResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan planModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := plan.ID.ValueInt64()
	if err := r.client.Patch(ctx, "/plans/"+strconv.FormatInt(id, 10), plan.body(), nil); err != nil {
		resp.Diagnostics.AddError("Update plan failed", err.Error())
		return
	}
	r.read(ctx, id, &plan, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *planResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state planModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.Delete(ctx, "/plans/"+strconv.FormatInt(state.ID.ValueInt64(), 10)); err != nil && !IsNotFound(err) {
		resp.Diagnostics.AddError("Delete plan failed", err.Error())
	}
}

func (r *planResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importByID(ctx, req, resp)
}

func (r *planResource) read(ctx context.Context, id int64, m *planModel, diags *diagSink) bool {
	var p apiPlan
	if err := r.client.Get(ctx, "/plans/"+strconv.FormatInt(id, 10), &p); err != nil {
		if IsNotFound(err) {
			return true
		}
		diags.AddError("Read plan failed", err.Error())
		return false
	}
	m.ID = types.Int64Value(p.ID)
	m.Name = types.StringValue(p.Name)
	m.Kind = types.StringValue(p.Kind)
	m.MaxDomains = types.Int64Value(p.MaxDomains)
	m.MaxPorts = types.Int64Value(p.MaxPorts)
	m.NodeGroupID = types.Int64Value(p.NodeGroupID)
	m.SSLEnabled = types.BoolValue(p.SSLEnabled)
	m.PathRoutingEnabled = types.BoolValue(p.PathRoutingEnabled)
	m.WildcardEnabled = types.BoolValue(p.WildcardEnabled)
	m.WebsocketEnabled = types.BoolValue(p.WebsocketEnabled)
	m.ExternalProxy = types.BoolValue(p.ExternalProxy)
	m.AllowEgressIP = types.BoolValue(p.AllowEgressIP)
	m.RateLimitRPM = types.Int64Value(intPtrVal(p.RateLimitRPM))
	m.WGKeyRotationDays = types.Int64Value(intPtrVal(p.WGKeyRotationDays))
	return false
}

func intPtrVal(p *int) int64 {
	if p == nil {
		return 0
	}
	return int64(*p)
}
