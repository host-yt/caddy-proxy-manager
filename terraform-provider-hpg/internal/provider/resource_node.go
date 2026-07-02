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

var _ resource.Resource = &nodeResource{}
var _ resource.ResourceWithImportState = &nodeResource{}

type nodeResource struct{ client *Client }

func NewNodeResource() resource.Resource { return &nodeResource{} }

type nodeModel struct {
	ID             types.Int64  `tfsdk:"id"`
	Name           types.String `tfsdk:"name"`
	APIURL         types.String `tfsdk:"api_url"`
	PublicHostname types.String `tfsdk:"public_hostname"`
	PublicIP       types.String `tfsdk:"public_ip"`
	NodeGroupID    types.Int64  `tfsdk:"node_group_id"`
	MaxRoutes      types.Int64  `tfsdk:"max_routes"`
	Priority       types.Int64  `tfsdk:"priority"`
	Enabled        types.Bool   `tfsdk:"is_enabled"`
	CurrentRoutes  types.Int64  `tfsdk:"current_routes"`
	Health         types.String `tfsdk:"health_status"`
}

type apiNode struct {
	ID             int64  `json:"id"`
	Name           string `json:"name"`
	APIURL         string `json:"api_url"`
	PublicHostname string `json:"public_hostname"`
	PublicIP       string `json:"public_ip"`
	NodeGroupID    int64  `json:"node_group_id"`
	MaxRoutes      int64  `json:"max_routes"`
	Priority       int64  `json:"priority"`
	Enabled        bool   `json:"is_enabled"`
	CurrentRoutes  int64  `json:"current_routes"`
	Health         string `json:"health_status"`
}

func (r *nodeResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_node"
}

func (r *nodeResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	// The API only patches name + is_enabled; everything else is immutable and
	// forces replacement. Platform-admin key only.
	replaceInt := []planmodifier.Int64{int64planmodifier.RequiresReplace()}
	replaceStr := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	resp.Schema = schema.Schema{
		MarkdownDescription: "A Caddy node in a node pool. Platform-admin key only. Only `name` and `is_enabled` are mutable in place; other changes force replacement.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Computed:      true,
				PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"name":            schema.StringAttribute{Required: true},
			"api_url":         schema.StringAttribute{Required: true, PlanModifiers: replaceStr},
			"node_group_id":   schema.Int64Attribute{Required: true, PlanModifiers: replaceInt},
			"max_routes":      schema.Int64Attribute{Required: true, PlanModifiers: replaceInt},
			"public_hostname": schema.StringAttribute{Optional: true, Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace(), stringplanmodifier.UseStateForUnknown()}},
			"public_ip":       schema.StringAttribute{Optional: true, Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace(), stringplanmodifier.UseStateForUnknown()}},
			"priority":        schema.Int64Attribute{Optional: true, Computed: true, PlanModifiers: []planmodifier.Int64{int64planmodifier.RequiresReplace(), int64planmodifier.UseStateForUnknown()}},
			"is_enabled":      schema.BoolAttribute{Optional: true, Computed: true},
			"current_routes":  schema.Int64Attribute{Computed: true},
			"health_status":   schema.StringAttribute{Computed: true},
		},
	}
}

func (r *nodeResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFromResourceConfig(req, resp)
}

func (r *nodeResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan nodeModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body := map[string]any{
		"name":            plan.Name.ValueString(),
		"api_url":         plan.APIURL.ValueString(),
		"public_hostname": plan.PublicHostname.ValueString(),
		"public_ip":       plan.PublicIP.ValueString(),
		"node_group_id":   plan.NodeGroupID.ValueInt64(),
		"max_routes":      plan.MaxRoutes.ValueInt64(),
		"priority":        plan.Priority.ValueInt64(),
	}
	var created struct {
		ID int64 `json:"id"`
	}
	if err := r.client.Post(ctx, "/nodes", body, &created); err != nil {
		resp.Diagnostics.AddError("Create node failed", err.Error())
		return
	}
	if r.read(ctx, created.ID, &plan, &resp.Diagnostics) {
		resp.Diagnostics.AddError("Create node failed", "node vanished immediately after create")
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *nodeResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state nodeModel
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

func (r *nodeResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan nodeModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := plan.ID.ValueInt64()
	body := map[string]any{
		"name":       plan.Name.ValueString(),
		"is_enabled": plan.Enabled.ValueBool(),
	}
	if err := r.client.Patch(ctx, "/nodes/"+strconv.FormatInt(id, 10), body, nil); err != nil {
		resp.Diagnostics.AddError("Update node failed", err.Error())
		return
	}
	r.read(ctx, id, &plan, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *nodeResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state nodeModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.Delete(ctx, "/nodes/"+strconv.FormatInt(state.ID.ValueInt64(), 10)); err != nil && !IsNotFound(err) {
		resp.Diagnostics.AddError("Delete node failed", err.Error())
	}
}

func (r *nodeResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importByID(ctx, req, resp)
}

func (r *nodeResource) read(ctx context.Context, id int64, m *nodeModel, diags *diagSink) bool {
	var n apiNode
	if err := r.client.Get(ctx, "/nodes/"+strconv.FormatInt(id, 10), &n); err != nil {
		if IsNotFound(err) {
			return true
		}
		diags.AddError("Read node failed", err.Error())
		return false
	}
	m.ID = types.Int64Value(n.ID)
	m.Name = types.StringValue(n.Name)
	m.APIURL = types.StringValue(n.APIURL)
	m.PublicHostname = types.StringValue(n.PublicHostname)
	m.PublicIP = types.StringValue(n.PublicIP)
	m.NodeGroupID = types.Int64Value(n.NodeGroupID)
	m.MaxRoutes = types.Int64Value(n.MaxRoutes)
	m.Priority = types.Int64Value(n.Priority)
	m.Enabled = types.BoolValue(n.Enabled)
	m.CurrentRoutes = types.Int64Value(n.CurrentRoutes)
	m.Health = types.StringValue(n.Health)
	return false
}
