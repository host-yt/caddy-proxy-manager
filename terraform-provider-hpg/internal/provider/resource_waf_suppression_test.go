package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// fakeWAFAPI keeps route 7's suppressions in memory, like the panel does.
type fakeWAFAPI struct {
	mu      sync.Mutex
	sups    map[int64]map[string]any
	created map[string]any
	deleted []string
}

func (f *fakeWAFAPI) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/routes/7/waf-suppressions":
		_ = json.NewDecoder(r.Body).Decode(&f.created)
		s := map[string]any{"id": 11, "route_id": 7, "rule_id": f.created["rule_id"],
			"reason": f.created["reason"], "created_at": "2026-11-16T10:00:00Z", "expires_at": nil}
		if s["reason"] == nil {
			s["reason"] = ""
		}
		f.sups[11] = s
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(s)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/routes/7/waf-suppressions":
		out := []map[string]any{}
		for _, s := range f.sups {
			out = append(out, s)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"waf_suppressions": out})
	case r.Method == http.MethodDelete:
		f.deleted = append(f.deleted, r.URL.Path)
		delete(f.sups, 11)
		_, _ = w.Write([]byte(`{"deleted":true}`))
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not found"}`))
	}
}

func wafSchema(t *testing.T) (resource.SchemaResponse, tftypes.Object) {
	t.Helper()
	var sr resource.SchemaResponse
	(&wafSuppressionResource{}).Schema(context.Background(), resource.SchemaRequest{}, &sr)
	if sr.Diagnostics.HasError() {
		t.Fatalf("schema: %v", sr.Diagnostics)
	}
	return sr, sr.Schema.Type().TerraformType(context.Background()).(tftypes.Object)
}

func TestWAFSuppressionLifecycle(t *testing.T) {
	ctx := context.Background()
	api := &fakeWAFAPI{sups: map[int64]map[string]any{}}
	srv := httptest.NewServer(http.HandlerFunc(api.handler))
	defer srv.Close()
	res := &wafSuppressionResource{client: NewClient(srv.URL, "k")}
	sr, typ := wafSchema(t)

	vals := map[string]tftypes.Value{}
	for name, at := range typ.AttributeTypes {
		vals[name] = tftypes.NewValue(at, tftypes.UnknownValue)
	}
	vals["route_id"] = tftypes.NewValue(tftypes.Number, 7)
	vals["rule_id"] = tftypes.NewValue(tftypes.String, "942100-942199")
	vals["reason"] = tftypes.NewValue(tftypes.String, "false positive on search")
	vals["expires_at"] = tftypes.NewValue(tftypes.String, nil)
	raw := tftypes.NewValue(typ, vals)

	cresp := resource.CreateResponse{State: tfsdk.State{Schema: sr.Schema, Raw: tftypes.NewValue(typ, nil)}}
	res.Create(ctx, resource.CreateRequest{Plan: tfsdk.Plan{Schema: sr.Schema, Raw: raw}}, &cresp)
	if cresp.Diagnostics.HasError() {
		t.Fatalf("create: %v", cresp.Diagnostics)
	}
	if api.created["rule_id"] != "942100-942199" || api.created["reason"] != "false positive on search" {
		t.Fatalf("create body = %v", api.created)
	}
	if _, sent := api.created["expires_at"]; sent {
		t.Error("null expires_at must be omitted, not sent")
	}
	var st wafSuppressionModel
	cresp.State.Get(ctx, &st)
	if st.ID.ValueInt64() != 11 || st.CreatedAt.ValueString() != "2026-11-16T10:00:00Z" {
		t.Fatalf("state after create = %+v", st)
	}

	// Read keeps it while the API lists it.
	rresp := resource.ReadResponse{State: cresp.State}
	res.Read(ctx, resource.ReadRequest{State: cresp.State}, &rresp)
	if rresp.Diagnostics.HasError() || rresp.State.Raw.IsNull() {
		t.Fatalf("read dropped a live suppression: %v", rresp.Diagnostics)
	}

	// Deleted outside Terraform (or expired): Read removes it from state.
	api.mu.Lock()
	delete(api.sups, 11)
	api.mu.Unlock()
	gone := resource.ReadResponse{State: cresp.State}
	res.Read(ctx, resource.ReadRequest{State: cresp.State}, &gone)
	if !gone.State.Raw.IsNull() {
		t.Fatal("suppression missing from the API stayed in state")
	}

	// Delete targets the route-scoped endpoint.
	dresp := resource.DeleteResponse{State: cresp.State}
	res.Delete(ctx, resource.DeleteRequest{State: cresp.State}, &dresp)
	if dresp.Diagnostics.HasError() || len(api.deleted) != 1 || api.deleted[0] != "/api/v1/routes/7/waf-suppressions/11" {
		t.Fatalf("delete: %v %v", dresp.Diagnostics, api.deleted)
	}
}

func TestWAFSuppressionImportID(t *testing.T) {
	ctx := context.Background()
	sr, typ := wafSchema(t)
	for id, ok := range map[string]bool{"7/11": true, "11": false, "a/b": false} {
		resp := resource.ImportStateResponse{State: tfsdk.State{Schema: sr.Schema, Raw: tftypes.NewValue(typ, nil)}}
		(&wafSuppressionResource{}).ImportState(ctx, resource.ImportStateRequest{ID: id}, &resp)
		if resp.Diagnostics.HasError() == ok {
			t.Errorf("import %q: error=%v, want ok=%v", id, resp.Diagnostics.HasError(), ok)
		}
		if ok {
			var route, sid types.Int64
			resp.State.GetAttribute(ctx, pathRoot("route_id"), &route)
			resp.State.GetAttribute(ctx, pathRoot("id"), &sid)
			if route.ValueInt64() != 7 || sid.ValueInt64() != 11 {
				t.Errorf("import 7/11 -> route=%v id=%v", route, sid)
			}
		}
	}
}

// Route create sends upstream_scheme and upstream_skip_tls_verify only when set.
func TestRouteCreateSendsUpstreamTLS(t *testing.T) {
	ctx := context.Background()
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_ = json.NewDecoder(r.Body).Decode(&body)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":5}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":5,"service_id":1,"domain":"a.example","upstream_port":30001,
			"ssl":true,"force_https":true,"upstream_scheme":"https","upstream_skip_tls_verify":true,"status":"active"}`))
	}))
	defer srv.Close()
	res := &routeResource{client: NewClient(srv.URL, "k")}
	var sr resource.SchemaResponse
	res.Schema(ctx, resource.SchemaRequest{}, &sr)
	typ := sr.Schema.Type().TerraformType(ctx).(tftypes.Object)
	vals := map[string]tftypes.Value{}
	for name, at := range typ.AttributeTypes {
		vals[name] = tftypes.NewValue(at, tftypes.UnknownValue)
	}
	vals["service_id"] = tftypes.NewValue(tftypes.Number, 1)
	vals["domain"] = tftypes.NewValue(tftypes.String, "a.example")
	vals["upstream_port"] = tftypes.NewValue(tftypes.Number, 30001)
	vals["upstream_scheme"] = tftypes.NewValue(tftypes.String, "https")
	vals["upstream_skip_tls_verify"] = tftypes.NewValue(tftypes.Bool, true)
	raw := tftypes.NewValue(typ, vals)
	resp := resource.CreateResponse{State: tfsdk.State{Schema: sr.Schema, Raw: tftypes.NewValue(typ, nil)}}
	res.Create(ctx, resource.CreateRequest{Plan: tfsdk.Plan{Schema: sr.Schema, Raw: raw}}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("create: %v", resp.Diagnostics)
	}
	if body["upstream_scheme"] != "https" || body["upstream_skip_tls_verify"] != true {
		t.Fatalf("create body = %v", body)
	}
	if _, sent := body["websocket"]; sent {
		t.Error("unknown websocket must be omitted")
	}
	var m routeModel
	resp.State.Get(ctx, &m)
	if m.Scheme.ValueString() != "https" || !m.SkipTLS.ValueBool() {
		t.Fatalf("state = scheme %v skip %v", m.Scheme, m.SkipTLS)
	}
}

// After import state has no expires_at; Read fills it from the API, while a
// configured value (e.g. a bare date) is kept as written.
func TestWAFSuppressionReadExpiresAt(t *testing.T) {
	ctx := context.Background()
	api := &fakeWAFAPI{sups: map[int64]map[string]any{11: {"id": 11, "route_id": 7, "rule_id": "942100",
		"reason": "", "created_at": "2026-11-16T10:00:00Z", "expires_at": "2026-12-31T23:59:59Z"}}}
	srv := httptest.NewServer(http.HandlerFunc(api.handler))
	defer srv.Close()
	res := &wafSuppressionResource{client: NewClient(srv.URL, "k")}
	sr, typ := wafSchema(t)
	for configured, want := range map[string]string{"": "2026-12-31T23:59:59Z", "2026-12-31": "2026-12-31"} {
		vals := map[string]tftypes.Value{}
		for name, at := range typ.AttributeTypes {
			vals[name] = tftypes.NewValue(at, nil)
		}
		vals["id"] = tftypes.NewValue(tftypes.Number, 11)
		vals["route_id"] = tftypes.NewValue(tftypes.Number, 7)
		if configured != "" {
			vals["expires_at"] = tftypes.NewValue(tftypes.String, configured)
		}
		st := tfsdk.State{Schema: sr.Schema, Raw: tftypes.NewValue(typ, vals)}
		resp := resource.ReadResponse{State: st}
		res.Read(ctx, resource.ReadRequest{State: st}, &resp)
		var m wafSuppressionModel
		resp.State.Get(ctx, &m)
		if m.ExpiresAt.ValueString() != want {
			t.Errorf("configured %q: expires_at = %q, want %q", configured, m.ExpiresAt.ValueString(), want)
		}
	}
}
