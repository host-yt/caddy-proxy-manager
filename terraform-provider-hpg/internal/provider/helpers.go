package provider

import (
	"context"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// diagSink lets resource read() helpers append errors to the caller's diags.
type diagSink = diag.Diagnostics

// pathRoot is a thin alias so provider.go reads cleanly.
func pathRoot(name string) path.Path { return path.Root(name) }

// clientFromResourceConfig pulls the shared *Client set in provider.Configure.
// Returns nil (and records a diagnostic) if the provider was not configured.
func clientFromResourceConfig(req resource.ConfigureRequest, resp *resource.ConfigureResponse) *Client {
	if req.ProviderData == nil {
		return nil // provider not yet configured; framework calls Configure again later
	}
	c, ok := req.ProviderData.(*Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", "Expected *provider.Client. This is a provider bug.")
		return nil
	}
	return c
}

// importByID is the shared ImportState for numeric-id resources: it parses the
// import string into the int64 `id` attribute; a follow-up Read fills the rest.
func importByID(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, err := strconv.ParseInt(req.ID, 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", "Expected a numeric id, got "+req.ID)
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("id"), id)...)
}
