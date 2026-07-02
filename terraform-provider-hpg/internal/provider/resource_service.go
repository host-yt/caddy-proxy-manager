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

var _ resource.Resource = &serviceResource{}
var _ resource.ResourceWithImportState = &serviceResource{}

type serviceResource struct{ client *Client }

func NewServiceResource() resource.Resource { return &serviceResource{} }

type serviceModel struct {
	ID                types.Int64  `tfsdk:"id"`
	ClientID          types.Int64  `tfsdk:"client_id"`
	Name              types.String `tfsdk:"name"`
	BackendIP         types.String `tfsdk:"backend_ip"`
	AllowedPortStart  types.Int64  `tfsdk:"allowed_port_start"`
	AllowedPortEnd    types.Int64  `tfsdk:"allowed_port_end"`
	PlanID            types.Int64  `tfsdk:"plan_id"`
	ExternalReference types.String `tfsdk:"external_reference"`
	Status            types.String `tfsdk:"status"`
}

type apiService struct {
	ID                int64  `json:"id"`
	ClientID          int64  `json:"client_id"`
	Name              string `json:"name"`
	BackendIP         string `json:"backend_ip"`
	AllowedPortStart  int64  `json:"allowed_port_start"`
	AllowedPortEnd    int64  `json:"allowed_port_end"`
	PlanID            int64  `json:"plan_id"`
	Status            string `json:"status"`
	ExternalReference string `json:"external_reference"`
}

func (r *serviceResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service"
}

func (r *serviceResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	// name/backend_ip/plan_id/client_id are immutable in the API (no PATCH), so
	// changing them forces replacement.
	replaceInt := []planmodifier.Int64{int64planmodifier.RequiresReplace()}
	replaceStr := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	resp.Schema = schema.Schema{
		MarkdownDescription: "A service binds a client to a backend IP + allowed port range. `client_id`/`plan_id` must be within the API key's scope.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Computed:      true,
				PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"client_id":          schema.Int64Attribute{Required: true, PlanModifiers: replaceInt},
			"name":               schema.StringAttribute{Required: true, PlanModifiers: replaceStr},
			"backend_ip":         schema.StringAttribute{Required: true, PlanModifiers: replaceStr},
			"plan_id":            schema.Int64Attribute{Required: true, PlanModifiers: replaceInt},
			"allowed_port_start": schema.Int64Attribute{Required: true},
			"allowed_port_end":   schema.Int64Attribute{Required: true},
			"external_reference": schema.StringAttribute{Optional: true, Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"status":             schema.StringAttribute{Computed: true},
		},
	}
}

func (r *serviceResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFromResourceConfig(req, resp)
}

func (r *serviceResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan serviceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body := map[string]any{
		"client_id":          plan.ClientID.ValueInt64(),
		"name":               plan.Name.ValueString(),
		"backend_ip":         plan.BackendIP.ValueString(),
		"allowed_port_start": plan.AllowedPortStart.ValueInt64(),
		"allowed_port_end":   plan.AllowedPortEnd.ValueInt64(),
		"plan_id":            plan.PlanID.ValueInt64(),
		"external_reference": plan.ExternalReference.ValueString(),
	}
	var created struct {
		ID int64 `json:"id"`
	}
	if err := r.client.Post(ctx, "/services", body, &created); err != nil {
		resp.Diagnostics.AddError("Create service failed", err.Error())
		return
	}
	if r.read(ctx, created.ID, &plan, &resp.Diagnostics) {
		resp.Diagnostics.AddError("Create service failed", "service vanished immediately after create")
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *serviceResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state serviceModel
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

func (r *serviceResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan serviceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := plan.ID.ValueInt64()
	sid := strconv.FormatInt(id, 10)
	// Port range has a dedicated endpoint; external_reference goes through PATCH.
	ports := map[string]any{
		"allowed_port_start": plan.AllowedPortStart.ValueInt64(),
		"allowed_port_end":   plan.AllowedPortEnd.ValueInt64(),
	}
	if err := r.client.Post(ctx, "/services/"+sid+"/ports", ports, nil); err != nil {
		resp.Diagnostics.AddError("Update service ports failed", err.Error())
		return
	}
	patch := map[string]any{"external_reference": plan.ExternalReference.ValueString()}
	if err := r.client.Patch(ctx, "/services/"+sid, patch, nil); err != nil {
		resp.Diagnostics.AddError("Update service failed", err.Error())
		return
	}
	r.read(ctx, id, &plan, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *serviceResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state serviceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.Delete(ctx, "/services/"+strconv.FormatInt(state.ID.ValueInt64(), 10)); err != nil && !IsNotFound(err) {
		resp.Diagnostics.AddError("Delete service failed", err.Error())
	}
}

func (r *serviceResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importByID(ctx, req, resp)
}

func (r *serviceResource) read(ctx context.Context, id int64, m *serviceModel, diags *diagSink) bool {
	var s apiService
	if err := r.client.Get(ctx, "/services/"+strconv.FormatInt(id, 10), &s); err != nil {
		if IsNotFound(err) {
			return true
		}
		diags.AddError("Read service failed", err.Error())
		return false
	}
	m.ID = types.Int64Value(s.ID)
	m.ClientID = types.Int64Value(s.ClientID)
	m.Name = types.StringValue(s.Name)
	m.BackendIP = types.StringValue(s.BackendIP)
	m.AllowedPortStart = types.Int64Value(s.AllowedPortStart)
	m.AllowedPortEnd = types.Int64Value(s.AllowedPortEnd)
	m.PlanID = types.Int64Value(s.PlanID)
	m.ExternalReference = types.StringValue(s.ExternalReference)
	m.Status = types.StringValue(s.Status)
	return false
}
