package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

// TestProviderSchema is a smoke test: the provider and every resource must
// produce a valid schema (no duplicate/invalid attributes) via the framework's
// GetProviderSchema RPC. This catches schema wiring bugs without a live server.
func TestProviderSchema(t *testing.T) {
	ctx := context.Background()
	srv := providerserver.NewProtocol6(New("test")())()
	resp, err := srv.GetProviderSchema(ctx, &tfprotov6.GetProviderSchemaRequest{})
	if err != nil {
		t.Fatalf("GetProviderSchema: %v", err)
	}
	for _, d := range resp.Diagnostics {
		if d.Severity == tfprotov6.DiagnosticSeverityError {
			t.Fatalf("schema diagnostic: %s - %s", d.Summary, d.Detail)
		}
	}
	want := []string{
		"hpg_node_pool", "hpg_node", "hpg_plan",
		"hpg_client", "hpg_service", "hpg_route",
	}
	for _, name := range want {
		if _, ok := resp.ResourceSchemas[name]; !ok {
			t.Errorf("missing resource schema %q", name)
		}
	}
	if len(resp.ResourceSchemas) != len(want) {
		t.Errorf("resource count = %d, want %d", len(resp.ResourceSchemas), len(want))
	}
}

// TestAccPlaceholder documents the acceptance-test entry point. Real acceptance
// tests (resource.Test with TF_ACC=1) require a live panel + admin API key at
// HPG_ENDPOINT/HPG_API_KEY; they live here once a CI panel is available.
func TestAccPlaceholder(t *testing.T) {
	t.Skip("acceptance tests need TF_ACC=1 + a live HPG panel (HPG_ENDPOINT/HPG_API_KEY)")
}
