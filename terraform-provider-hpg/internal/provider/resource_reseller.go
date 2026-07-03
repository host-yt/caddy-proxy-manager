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

var _ resource.Resource = &resellerResource{}
var _ resource.ResourceWithImportState = &resellerResource{}

type resellerResource struct{ client *Client }

func NewResellerResource() resource.Resource { return &resellerResource{} }

type resellerModel struct {
	ID             types.Int64  `tfsdk:"id"`
	Name           types.String `tfsdk:"name"`
	Slug           types.String `tfsdk:"slug"`
	OwnerEmail     types.String `tfsdk:"owner_email"`
	OwnerPassword  types.String `tfsdk:"owner_password"`
	OwnerUserID    types.Int64  `tfsdk:"owner_user_id"`
	Status         types.String `tfsdk:"status"`
	BrandName      types.String `tfsdk:"brand_name"`
	SupportEmail   types.String `tfsdk:"support_email"`
	ResellerPlanID types.Int64  `tfsdk:"reseller_plan_id"`
	Overselling    types.Bool   `tfsdk:"overselling_allowed"`
	CanCreatePlans types.Bool   `tfsdk:"can_create_plans"`
}

// apiReseller mirrors the GET/PATCH response shape of /api/v1/resellers.
type apiReseller struct {
	ID             int64  `json:"id"`
	Name           string `json:"name"`
	Slug           string `json:"slug"`
	Status         string `json:"status"`
	BrandName      string `json:"brand_name"`
	SupportEmail   string `json:"support_email"`
	ResellerPlanID int64  `json:"reseller_plan_id"`
	Overselling    bool   `json:"overselling_allowed"`
	CanCreatePlans bool   `json:"can_create_plans"`
	OwnerUserID    int64  `json:"owner_user_id"`
}

func (r *resellerResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_reseller"
}

func (r *resellerResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A reseller tenant, provisioned atomically with its initial reseller-admin login. Platform-admin key only.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Computed:      true,
				PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{Required: true},
			"slug": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Lowercase alphanumeric/dashes. Immutable: the API has no slug-update field, so changes force replacement.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"owner_email": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Login email for the initial reseller-admin. Immutable: the update endpoint does not accept it, so changes force replacement.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"owner_password": schema.StringAttribute{
				Required:            true,
				Sensitive:           true,
				MarkdownDescription: "Initial reseller-admin password (>= 12 chars). Create-only: the API has no owner-password rotate endpoint, so later changes are ignored (rotate in-panel).",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"owner_user_id": schema.Int64Attribute{
				Computed:      true,
				PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"status": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "`active` (default at creation) or `suspended`. Not settable at create time; applied via a follow-up update.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"brand_name":    schema.StringAttribute{Optional: true, Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"support_email": schema.StringAttribute{Optional: true, Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"reseller_plan_id": schema.Int64Attribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Aggregate quota package id. Not settable at create time; applied via a follow-up update.",
				PlanModifiers:       []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"overselling_allowed": boolAttrOptComputed(),
			"can_create_plans":    boolAttrOptComputed(),
		},
	}
}

func (r *resellerResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFromResourceConfig(req, resp)
}

func (r *resellerResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan resellerModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body := map[string]any{
		"name":           plan.Name.ValueString(),
		"slug":           plan.Slug.ValueString(),
		"owner_email":    plan.OwnerEmail.ValueString(),
		"owner_password": plan.OwnerPassword.ValueString(),
		"brand_name":     plan.BrandName.ValueString(),
		"support_email":  plan.SupportEmail.ValueString(),
	}
	var created struct {
		ID          int64 `json:"id"`
		OwnerUserID int64 `json:"owner_user_id"`
	}
	if err := r.client.Post(ctx, "/resellers", body, &created); err != nil {
		resp.Diagnostics.AddError("Create reseller failed", err.Error())
		return
	}
	// status/policy fields aren't accepted by create; apply them now if the
	// user configured them, so the first apply already converges.
	patch := map[string]any{}
	if !plan.Status.IsUnknown() {
		patch["status"] = plan.Status.ValueString()
	}
	if !plan.ResellerPlanID.IsUnknown() {
		patch["reseller_plan_id"] = plan.ResellerPlanID.ValueInt64()
	}
	if !plan.Overselling.IsUnknown() {
		patch["overselling_allowed"] = plan.Overselling.ValueBool()
	}
	if !plan.CanCreatePlans.IsUnknown() {
		patch["can_create_plans"] = plan.CanCreatePlans.ValueBool()
	}
	if len(patch) > 0 {
		if err := r.client.Patch(ctx, "/resellers/"+strconv.FormatInt(created.ID, 10), patch, nil); err != nil {
			resp.Diagnostics.AddError("Apply initial reseller policy failed", err.Error())
			return
		}
	}
	pw := plan.OwnerPassword // preserve write-only value in state
	if r.read(ctx, created.ID, &plan, &resp.Diagnostics) {
		resp.Diagnostics.AddError("Create reseller failed", "reseller vanished immediately after create")
		return
	}
	plan.OwnerPassword = pw
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *resellerResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state resellerModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	pw := state.OwnerPassword // read never returns the password; keep prior state value
	if r.read(ctx, state.ID.ValueInt64(), &state, &resp.Diagnostics) {
		resp.State.RemoveResource(ctx)
		return
	}
	state.OwnerPassword = pw
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *resellerResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state resellerModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if plan.OwnerPassword.ValueString() != state.OwnerPassword.ValueString() {
		resp.Diagnostics.AddWarning("Owner password change ignored",
			"The API has no owner-password rotate endpoint on reseller update; rotate it in the panel. State is kept in sync with config to avoid a perpetual diff.")
	}
	id := plan.ID.ValueInt64()
	body := map[string]any{
		"name":                plan.Name.ValueString(),
		"status":              plan.Status.ValueString(),
		"brand_name":          plan.BrandName.ValueString(),
		"support_email":       plan.SupportEmail.ValueString(),
		"reseller_plan_id":    plan.ResellerPlanID.ValueInt64(),
		"overselling_allowed": plan.Overselling.ValueBool(),
		"can_create_plans":    plan.CanCreatePlans.ValueBool(),
	}
	if err := r.client.Patch(ctx, "/resellers/"+strconv.FormatInt(id, 10), body, nil); err != nil {
		resp.Diagnostics.AddError("Update reseller failed", err.Error())
		return
	}
	pw := plan.OwnerPassword
	r.read(ctx, id, &plan, &resp.Diagnostics)
	plan.OwnerPassword = pw
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *resellerResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state resellerModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.Delete(ctx, "/resellers/"+strconv.FormatInt(state.ID.ValueInt64(), 10)); err != nil && !IsNotFound(err) {
		resp.Diagnostics.AddError("Delete reseller failed", err.Error())
	}
}

func (r *resellerResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importByID(ctx, req, resp)
}

func (r *resellerResource) read(ctx context.Context, id int64, m *resellerModel, diags *diagSink) bool {
	var rs apiReseller
	if err := r.client.Get(ctx, "/resellers/"+strconv.FormatInt(id, 10), &rs); err != nil {
		if IsNotFound(err) {
			return true
		}
		diags.AddError("Read reseller failed", err.Error())
		return false
	}
	m.ID = types.Int64Value(rs.ID)
	m.Name = types.StringValue(rs.Name)
	m.Slug = types.StringValue(rs.Slug)
	m.Status = types.StringValue(rs.Status)
	m.BrandName = types.StringValue(rs.BrandName)
	m.SupportEmail = types.StringValue(rs.SupportEmail)
	m.ResellerPlanID = types.Int64Value(rs.ResellerPlanID)
	m.Overselling = types.BoolValue(rs.Overselling)
	m.CanCreatePlans = types.BoolValue(rs.CanCreatePlans)
	m.OwnerUserID = types.Int64Value(rs.OwnerUserID)
	return false
}
