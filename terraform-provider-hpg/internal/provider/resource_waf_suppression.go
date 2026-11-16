package provider

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &wafSuppressionResource{}
var _ resource.ResourceWithImportState = &wafSuppressionResource{}

// wafSuppressionResource manages one route-scoped WAF rule suppression
// (/api/v1/routes/{id}/waf-suppressions). The API has no update, so every
// attribute forces a new suppression.
type wafSuppressionResource struct{ client *Client }

func NewWAFSuppressionResource() resource.Resource { return &wafSuppressionResource{} }

type wafSuppressionModel struct {
	ID        types.Int64  `tfsdk:"id"`
	RouteID   types.Int64  `tfsdk:"route_id"`
	RuleID    types.String `tfsdk:"rule_id"`
	Reason    types.String `tfsdk:"reason"`
	ExpiresAt types.String `tfsdk:"expires_at"`
	CreatedAt types.String `tfsdk:"created_at"`
}

type apiWAFSuppression struct {
	ID        int64      `json:"id"`
	RouteID   int64      `json:"route_id"`
	RuleID    string     `json:"rule_id"`
	Reason    string     `json:"reason"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at"`
}

func (r *wafSuppressionResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_waf_suppression"
}

func (r *wafSuppressionResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replaceStr := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	resp.Schema = schema.Schema{
		MarkdownDescription: "Stops one WAF rule (or rule-ID range) from firing on a route. Needs an admin API key " +
			"whose scope covers the route. Deleting it restores the rule. An expired suppression disappears from " +
			"the API, so the next plan recreates it; set a later `expires_at` or none.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Computed:      true,
				PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"route_id": schema.Int64Attribute{
				Required:      true,
				PlanModifiers: []planmodifier.Int64{int64planmodifier.RequiresReplace()},
			},
			"rule_id": schema.StringAttribute{
				Required: true, PlanModifiers: replaceStr,
				MarkdownDescription: "Numeric rule ID or inclusive range, e.g. `942100` or `942100-942199`.",
			},
			"reason": schema.StringAttribute{
				Optional: true, Computed: true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace(), stringplanmodifier.UseStateForUnknown()},
			},
			"expires_at": schema.StringAttribute{
				Optional: true, PlanModifiers: replaceStr,
				MarkdownDescription: "RFC 3339 time or `YYYY-MM-DD` (end of that day, UTC). Omit for a permanent suppression.",
			},
			"created_at": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

func (r *wafSuppressionResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFromResourceConfig(req, resp)
}

func wafSuppressionsPath(routeID int64) string {
	return "/routes/" + strconv.FormatInt(routeID, 10) + "/waf-suppressions"
}

func (r *wafSuppressionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan wafSuppressionModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body := map[string]any{"rule_id": plan.RuleID.ValueString()}
	setKnownString(body, "reason", plan.Reason)
	setKnownString(body, "expires_at", plan.ExpiresAt)
	var created apiWAFSuppression
	if err := r.client.Post(ctx, wafSuppressionsPath(plan.RouteID.ValueInt64()), body, &created); err != nil {
		resp.Diagnostics.AddError("Create WAF suppression failed", err.Error())
		return
	}
	plan.ID = types.Int64Value(created.ID)
	plan.Reason = types.StringValue(created.Reason)
	plan.CreatedAt = types.StringValue(created.CreatedAt.UTC().Format(time.RFC3339))
	// expires_at stays as configured: the server normalises a bare date to the
	// end of that day, and echoing that back would show a diff on every plan.
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *wafSuppressionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state wafSuppressionModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var list struct {
		Sups []apiWAFSuppression `json:"waf_suppressions"`
	}
	if err := r.client.Get(ctx, wafSuppressionsPath(state.RouteID.ValueInt64()), &list); err != nil {
		if IsNotFound(err) { // route gone: its suppressions went with it
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Read WAF suppression failed", err.Error())
		return
	}
	for _, s := range list.Sups {
		if s.ID != state.ID.ValueInt64() {
			continue
		}
		state.RuleID = types.StringValue(s.RuleID)
		state.Reason = types.StringValue(s.Reason)
		state.CreatedAt = types.StringValue(s.CreatedAt.UTC().Format(time.RFC3339))
		// Keep a configured value as written (the server turns a bare date into
		// end-of-day); fill it only when state has none, e.g. after import.
		switch {
		case s.ExpiresAt == nil:
			state.ExpiresAt = types.StringNull()
		case state.ExpiresAt.IsNull() || state.ExpiresAt.IsUnknown():
			state.ExpiresAt = types.StringValue(s.ExpiresAt.UTC().Format(time.RFC3339))
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
		return
	}
	// Deleted elsewhere, or expired: the API lists only active suppressions.
	resp.State.RemoveResource(ctx)
}

// Update is never called with a real change: every attribute requires replace.
func (r *wafSuppressionResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan wafSuppressionModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *wafSuppressionResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state wafSuppressionModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	p := wafSuppressionsPath(state.RouteID.ValueInt64()) + "/" + strconv.FormatInt(state.ID.ValueInt64(), 10)
	if err := r.client.Delete(ctx, p); err != nil && !IsNotFound(err) {
		resp.Diagnostics.AddError("Delete WAF suppression failed", err.Error())
	}
}

// ImportState takes "<route_id>/<suppression_id>".
func (r *wafSuppressionResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	routePart, idPart, ok := strings.Cut(req.ID, "/")
	routeID, err1 := strconv.ParseInt(routePart, 10, 64)
	id, err2 := strconv.ParseInt(idPart, 10, 64)
	if !ok || err1 != nil || err2 != nil {
		resp.Diagnostics.AddError("Invalid import ID", "Expected <route_id>/<suppression_id>, got "+req.ID)
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("route_id"), routeID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("id"), id)...)
}
