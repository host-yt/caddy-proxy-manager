package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// A failure after the reseller exists must still leave its id in state, and the
// initial policy must ride on the create call rather than a second request.
func TestResellerCreateKeepsIDWhenReadFails(t *testing.T) {
	ctx := context.Background()
	var body map[string]any
	var patched bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			_ = json.NewDecoder(r.Body).Decode(&body)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":7,"owner_user_id":9}`))
		case http.MethodPatch:
			patched = true
		default:
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"boom"}`))
		}
	}))
	defer srv.Close()

	res := &resellerResource{client: NewClient(srv.URL, "k")}
	var sr resource.SchemaResponse
	res.Schema(ctx, resource.SchemaRequest{}, &sr)
	typ := sr.Schema.Type().TerraformType(ctx).(tftypes.Object)

	vals := map[string]tftypes.Value{}
	for name, at := range typ.AttributeTypes {
		vals[name] = tftypes.NewValue(at, tftypes.UnknownValue)
	}
	vals["name"] = tftypes.NewValue(tftypes.String, "Acme")
	vals["slug"] = tftypes.NewValue(tftypes.String, "acme")
	vals["owner_email"] = tftypes.NewValue(tftypes.String, "o@acme.test")
	vals["owner_password"] = tftypes.NewValue(tftypes.String, "correct-horse-1")
	vals["status"] = tftypes.NewValue(tftypes.String, "suspended")
	vals["reseller_plan_id"] = tftypes.NewValue(tftypes.Number, 3)

	req := resource.CreateRequest{Plan: tfsdk.Plan{Schema: sr.Schema, Raw: tftypes.NewValue(typ, vals)}}
	resp := resource.CreateResponse{State: tfsdk.State{Schema: sr.Schema, Raw: tftypes.NewValue(typ, nil)}}
	res.Create(ctx, req, &resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected the failing read to surface an error")
	}
	var id int64
	resp.State.GetAttribute(ctx, pathRoot("id"), &id)
	if id != 7 {
		t.Fatalf("state id = %d, want 7 (created reseller must stay tracked)", id)
	}
	if patched {
		t.Error("initial policy sent as a separate PATCH")
	}
	if body["status"] != "suspended" || body["reseller_plan_id"] != float64(3) {
		t.Errorf("create body missing initial policy: %v", body)
	}
	if _, ok := body["overselling_allowed"]; ok {
		t.Error("unknown overselling_allowed must be omitted")
	}
}
