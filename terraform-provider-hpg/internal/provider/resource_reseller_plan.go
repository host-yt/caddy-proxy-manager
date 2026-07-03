package provider

import (
	"context"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &resellerPlanResource{}
var _ resource.ResourceWithImportState = &resellerPlanResource{}

type resellerPlanResource struct{ client *Client }

func NewResellerPlanResource() resource.Resource { return &resellerPlanResource{} }

type resellerPlanModel struct {
	ID              types.Int64  `tfsdk:"id"`
	Name            types.String `tfsdk:"name"`
	MaxClients      types.Int64  `tfsdk:"max_clients"`
	MaxServices     types.Int64  `tfsdk:"max_services_total"`
	MaxDomainsTotal types.Int64  `tfsdk:"max_domains_total"`
	RateLimitCap    types.Int64  `tfsdk:"rate_limit_rpm_cap"`
	NodeGroupIDs    types.List   `tfsdk:"node_group_ids"`
	Features        types.List   `tfsdk:"features"`
}

// apiResellerPlan mirrors the reseller-plan JSON shape used by
// /api/v1/reseller-plans (list/create/update).
type apiResellerPlan struct {
	ID              int64    `json:"id"`
	Name            string   `json:"name"`
	MaxClients      int64    `json:"max_clients"`
	MaxServices     int64    `json:"max_services_total"`
	MaxDomainsTotal int64    `json:"max_domains_total"`
	RateLimitCap    int64    `json:"rate_limit_rpm_cap"`
	NodeGroupIDs    []int64  `json:"node_group_ids"`
	Features        []string `json:"features"`
}

func (r *resellerPlanResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_reseller_plan"
}

func (r *resellerPlanResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	intOptComputed := schema.Int64Attribute{
		Optional:      true,
		Computed:      true,
		PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
	}
	listOptComputed := func(elem attr.Type) schema.ListAttribute {
		return schema.ListAttribute{
			ElementType:   elem,
			Optional:      true,
			Computed:      true,
			PlanModifiers: []planmodifier.List{listplanmodifier.UseStateForUnknown()},
		}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "An aggregate quota package assignable to a reseller. Platform-admin key only.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Computed:      true,
				PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"name":               schema.StringAttribute{Required: true},
			"max_clients":        intOptComputed,
			"max_services_total": intOptComputed,
			"max_domains_total":  intOptComputed,
			"rate_limit_rpm_cap": intOptComputed,
			"node_group_ids":     listOptComputed(types.Int64Type),
			"features":           listOptComputed(types.StringType),
		},
	}
}

func (r *resellerPlanResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFromResourceConfig(req, resp)
}

func (m *resellerPlanModel) body(ctx context.Context) (map[string]any, diagSink) {
	var diags diagSink
	nodeGroupIDs := []int64{}
	if !m.NodeGroupIDs.IsNull() && !m.NodeGroupIDs.IsUnknown() {
		diags.Append(m.NodeGroupIDs.ElementsAs(ctx, &nodeGroupIDs, false)...)
	}
	features := []string{}
	if !m.Features.IsNull() && !m.Features.IsUnknown() {
		diags.Append(m.Features.ElementsAs(ctx, &features, false)...)
	}
	return map[string]any{
		"name":               m.Name.ValueString(),
		"max_clients":        m.MaxClients.ValueInt64(),
		"max_services_total": m.MaxServices.ValueInt64(),
		"max_domains_total":  m.MaxDomainsTotal.ValueInt64(),
		"rate_limit_rpm_cap": m.RateLimitCap.ValueInt64(),
		"node_group_ids":     nodeGroupIDs,
		"features":           features,
	}, diags
}

func (r *resellerPlanResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan resellerPlanModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body, diags := plan.body(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	var created struct {
		ID int64 `json:"id"`
	}
	if err := r.client.Post(ctx, "/reseller-plans", body, &created); err != nil {
		resp.Diagnostics.AddError("Create reseller plan failed", err.Error())
		return
	}
	if r.read(ctx, created.ID, &plan, &resp.Diagnostics) {
		resp.Diagnostics.AddError("Create reseller plan failed", "reseller plan vanished immediately after create")
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *resellerPlanResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state resellerPlanModel
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

func (r *resellerPlanResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan resellerPlanModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body, diags := plan.body(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := plan.ID.ValueInt64()
	if err := r.client.Patch(ctx, "/reseller-plans/"+strconv.FormatInt(id, 10), body, nil); err != nil {
		resp.Diagnostics.AddError("Update reseller plan failed", err.Error())
		return
	}
	r.read(ctx, id, &plan, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *resellerPlanResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state resellerPlanModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.Delete(ctx, "/reseller-plans/"+strconv.FormatInt(state.ID.ValueInt64(), 10)); err != nil && !IsNotFound(err) {
		resp.Diagnostics.AddError("Delete reseller plan failed", err.Error())
	}
}

func (r *resellerPlanResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importByID(ctx, req, resp)
}

// read fetches by listing: reseller-plans has no singular GET endpoint.
func (r *resellerPlanResource) read(ctx context.Context, id int64, m *resellerPlanModel, diags *diagSink) bool {
	var out struct {
		ResellerPlans []apiResellerPlan `json:"reseller_plans"`
	}
	if err := r.client.Get(ctx, "/reseller-plans", &out); err != nil {
		diags.AddError("Read reseller plan failed", err.Error())
		return false
	}
	for _, p := range out.ResellerPlans {
		if p.ID != id {
			continue
		}
		m.ID = types.Int64Value(p.ID)
		m.Name = types.StringValue(p.Name)
		m.MaxClients = types.Int64Value(p.MaxClients)
		m.MaxServices = types.Int64Value(p.MaxServices)
		m.MaxDomainsTotal = types.Int64Value(p.MaxDomainsTotal)
		m.RateLimitCap = types.Int64Value(p.RateLimitCap)
		nodeGroupIDs, d := types.ListValueFrom(ctx, types.Int64Type, nonNilInt64(p.NodeGroupIDs))
		diags.Append(d...)
		m.NodeGroupIDs = nodeGroupIDs
		features, d2 := types.ListValueFrom(ctx, types.StringType, nonNilString(p.Features))
		diags.Append(d2...)
		m.Features = features
		return false
	}
	return true // not found -> gone
}

// nonNilInt64/nonNilString force a non-nil (possibly empty) slice so
// types.ListValueFrom produces an empty list rather than a null one.
func nonNilInt64(s []int64) []int64 {
	if s == nil {
		return []int64{}
	}
	return s
}

func nonNilString(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
