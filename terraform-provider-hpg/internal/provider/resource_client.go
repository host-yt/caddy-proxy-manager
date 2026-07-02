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

var _ resource.Resource = &clientResource{}
var _ resource.ResourceWithImportState = &clientResource{}

type clientResource struct{ client *Client }

func NewClientResource() resource.Resource { return &clientResource{} }

type clientModel struct {
	ID          types.Int64  `tfsdk:"id"`
	UserID      types.Int64  `tfsdk:"user_id"`
	Email       types.String `tfsdk:"email"`
	Name        types.String `tfsdk:"name"`
	Password    types.String `tfsdk:"password"`
	ExternalRef types.String `tfsdk:"external_ref"`
}

type apiClient struct {
	ID          int64  `json:"id"`
	UserID      int64  `json:"user_id"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
	ExternalRef string `json:"external_ref"`
}

func (r *clientResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_client"
}

func (r *clientResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A tenant (client account + login user). A reseller-admin key stamps its reseller_id automatically.",
		Attributes: map[string]schema.Attribute{
			"id": schema.Int64Attribute{
				Computed:      true,
				PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"user_id": schema.Int64Attribute{
				Computed:      true,
				PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"email": schema.StringAttribute{Required: true},
			"name":  schema.StringAttribute{Required: true},
			"password": schema.StringAttribute{
				Required:            true,
				Sensitive:           true,
				MarkdownDescription: "Initial password (>= 12 chars). Create-only: the API has no password-update endpoint, so later changes are ignored (rotate in-panel).",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"external_ref": schema.StringAttribute{Optional: true, Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
		},
	}
}

func (r *clientResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFromResourceConfig(req, resp)
}

func (r *clientResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan clientModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body := map[string]any{
		"email":        plan.Email.ValueString(),
		"name":         plan.Name.ValueString(),
		"password":     plan.Password.ValueString(),
		"external_ref": plan.ExternalRef.ValueString(),
	}
	var created struct {
		UserID int64 `json:"user_id"`
	}
	if err := r.client.Post(ctx, "/clients", body, &created); err != nil {
		resp.Diagnostics.AddError("Create client failed", err.Error())
		return
	}
	// The create response returns user_id; resolve the client id via the list.
	clientID, err := r.clientIDForUser(ctx, created.UserID)
	if err != nil {
		resp.Diagnostics.AddError("Resolve client id failed", err.Error())
		return
	}
	pw := plan.Password // preserve write-only value in state
	if r.read(ctx, clientID, &plan, &resp.Diagnostics) {
		resp.Diagnostics.AddError("Create client failed", "client vanished immediately after create")
		return
	}
	plan.Password = pw
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *clientResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state clientModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	pw := state.Password // read never returns the password; keep prior state value
	if r.read(ctx, state.ID.ValueInt64(), &state, &resp.Diagnostics) {
		resp.State.RemoveResource(ctx)
		return
	}
	state.Password = pw
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *clientResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state clientModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if plan.Password.ValueString() != state.Password.ValueString() {
		resp.Diagnostics.AddWarning("Password change ignored",
			"The API has no client password-update endpoint; rotate the password in the panel. State is kept in sync with config to avoid a perpetual diff.")
	}
	id := plan.ID.ValueInt64()
	body := map[string]any{
		"name":         plan.Name.ValueString(),
		"email":        plan.Email.ValueString(),
		"external_ref": plan.ExternalRef.ValueString(),
	}
	if err := r.client.Patch(ctx, "/clients/"+strconv.FormatInt(id, 10), body, nil); err != nil {
		resp.Diagnostics.AddError("Update client failed", err.Error())
		return
	}
	pw := plan.Password
	r.read(ctx, id, &plan, &resp.Diagnostics)
	plan.Password = pw
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *clientResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state clientModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.Delete(ctx, "/clients/"+strconv.FormatInt(state.ID.ValueInt64(), 10)); err != nil && !IsNotFound(err) {
		resp.Diagnostics.AddError("Delete client failed", err.Error())
	}
}

func (r *clientResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importByID(ctx, req, resp)
}

// clientIDForUser resolves a client id from the user_id returned by create.
func (r *clientResource) clientIDForUser(ctx context.Context, userID int64) (int64, error) {
	var out struct {
		Clients []apiClient `json:"clients"`
	}
	if err := r.client.Get(ctx, "/clients", &out); err != nil {
		return 0, err
	}
	for _, c := range out.Clients {
		if c.UserID == userID {
			return c.ID, nil
		}
	}
	return 0, &APIError{Status: 404, Method: "GET", Path: "/clients", Body: "no client for user_id " + strconv.FormatInt(userID, 10)}
}

func (r *clientResource) read(ctx context.Context, id int64, m *clientModel, diags *diagSink) bool {
	var c apiClient
	if err := r.client.Get(ctx, "/clients/"+strconv.FormatInt(id, 10), &c); err != nil {
		if IsNotFound(err) {
			return true
		}
		diags.AddError("Read client failed", err.Error())
		return false
	}
	m.ID = types.Int64Value(c.ID)
	m.UserID = types.Int64Value(c.UserID)
	m.Email = types.StringValue(c.Email)
	m.Name = types.StringValue(c.DisplayName)
	m.ExternalRef = types.StringValue(c.ExternalRef)
	return false
}
