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

var _ resource.Resource = &routeResource{}
var _ resource.ResourceWithImportState = &routeResource{}

type routeResource struct{ client *Client }

func NewRouteResource() resource.Resource { return &routeResource{} }

type routeModel struct {
	ID           types.Int64  `tfsdk:"id"`
	ServiceID    types.Int64  `tfsdk:"service_id"`
	Domain       types.String `tfsdk:"domain"`
	PathPrefix   types.String `tfsdk:"path_prefix"`
	UpstreamPort types.Int64  `tfsdk:"upstream_port"`
	SSL          types.Bool   `tfsdk:"ssl"`
	WebSocket    types.Bool   `tfsdk:"websocket"`
	ForceHTTPS   types.Bool   `tfsdk:"force_https"`
	Status       types.String `tfsdk:"status"`
	CaddyNodeID  types.Int64  `tfsdk:"caddy_node_id"`
}

type apiRoute struct {
	ID           int64  `json:"id"`
	ServiceID    int64  `json:"service_id"`
	Domain       string `json:"domain"`
	PathPrefix   string `json:"path_prefix"`
	UpstreamPort int64  `json:"upstream_port"`
	SSL          bool   `json:"ssl"`
	WebSocket    bool   `json:"websocket"`
	ForceHTTPS   bool   `json:"force_https"`
	Status       string `json:"status"`
	CaddyNodeID  int64  `json:"caddy_node_id"`
}

func (r *routeResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_route"
}

func (r *routeResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Maps a domain (+ optional path prefix) to a service upstream port. SSL is provisioned asynchronously; `status` converges to `active`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Computed:      true,
				PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"service_id":    schema.Int64Attribute{Required: true, PlanModifiers: []planmodifier.Int64{int64planmodifier.RequiresReplace()}},
			"domain":        schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"upstream_port": schema.Int64Attribute{Required: true},
			"path_prefix":   schema.StringAttribute{Optional: true, Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"ssl":           schema.BoolAttribute{Optional: true, Computed: true},
			"websocket":     schema.BoolAttribute{Optional: true, Computed: true},
			"force_https":   schema.BoolAttribute{Optional: true, Computed: true},
			"status":        schema.StringAttribute{Computed: true},
			"caddy_node_id": schema.Int64Attribute{Computed: true},
		},
	}
}

func (r *routeResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFromResourceConfig(req, resp)
}

func (r *routeResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan routeModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body := map[string]any{
		"service_id":    plan.ServiceID.ValueInt64(),
		"upstream_port": plan.UpstreamPort.ValueInt64(),
		"domain":        plan.Domain.ValueString(),
		"path_prefix":   plan.PathPrefix.ValueString(),
		"ssl":           plan.SSL.ValueBool(),
		"websocket":     plan.WebSocket.ValueBool(),
		"force_https":   plan.ForceHTTPS.ValueBool(),
	}
	var created struct {
		ID int64 `json:"id"`
	}
	if err := r.client.Post(ctx, "/routes", body, &created); err != nil {
		resp.Diagnostics.AddError("Create route failed", err.Error())
		return
	}
	if r.read(ctx, created.ID, &plan, &resp.Diagnostics) {
		resp.Diagnostics.AddError("Create route failed", "route vanished immediately after create")
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *routeResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state routeModel
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

func (r *routeResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan routeModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := plan.ID.ValueInt64()
	// Update uses ssl_enabled (create uses ssl); other keys match.
	body := map[string]any{
		"upstream_port": plan.UpstreamPort.ValueInt64(),
		"ssl_enabled":   plan.SSL.ValueBool(),
		"websocket":     plan.WebSocket.ValueBool(),
		"force_https":   plan.ForceHTTPS.ValueBool(),
		"path_prefix":   plan.PathPrefix.ValueString(),
	}
	if err := r.client.Patch(ctx, "/routes/"+strconv.FormatInt(id, 10), body, nil); err != nil {
		resp.Diagnostics.AddError("Update route failed", err.Error())
		return
	}
	r.read(ctx, id, &plan, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *routeResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state routeModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.Delete(ctx, "/routes/"+strconv.FormatInt(state.ID.ValueInt64(), 10)); err != nil && !IsNotFound(err) {
		resp.Diagnostics.AddError("Delete route failed", err.Error())
	}
}

func (r *routeResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importByID(ctx, req, resp)
}

func (r *routeResource) read(ctx context.Context, id int64, m *routeModel, diags *diagSink) bool {
	var rt apiRoute
	if err := r.client.Get(ctx, "/routes/"+strconv.FormatInt(id, 10), &rt); err != nil {
		if IsNotFound(err) {
			return true
		}
		diags.AddError("Read route failed", err.Error())
		return false
	}
	m.ID = types.Int64Value(rt.ID)
	m.ServiceID = types.Int64Value(rt.ServiceID)
	m.Domain = types.StringValue(rt.Domain)
	m.PathPrefix = types.StringValue(rt.PathPrefix)
	m.UpstreamPort = types.Int64Value(rt.UpstreamPort)
	m.SSL = types.BoolValue(rt.SSL)
	m.WebSocket = types.BoolValue(rt.WebSocket)
	m.ForceHTTPS = types.BoolValue(rt.ForceHTTPS)
	m.Status = types.StringValue(rt.Status)
	m.CaddyNodeID = types.Int64Value(rt.CaddyNodeID)
	return false
}
