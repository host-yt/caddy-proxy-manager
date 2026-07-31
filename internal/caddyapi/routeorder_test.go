package caddyapi

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// routeIDs extracts the @id of every emitted srv0 route, in emission order.
func routeIDs(t *testing.T, cfg map[string]any) []string {
	t.Helper()
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var parsed struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Routes []struct {
						ID string `json:"@id"`
					} `json:"routes"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	srv, ok := parsed.Apps.HTTP.Servers["srv0"]
	if !ok {
		t.Fatalf("no srv0 in config: %s", string(b))
	}
	out := make([]string, 0, len(srv.Routes))
	for _, r := range srv.Routes {
		out = append(out, r.ID)
	}
	return out
}

// An older catch-all on the same host (lower DB id, emitted first) must not
// shadow a newer protected subpath: every route is terminal, so first match wins.
func TestEmissionOrderProtectedSubpathBeatsOlderCatchAll(t *testing.T) {
	catchAll := Route{
		ID: "1", Hosts: []string{"example.com", "www.example.com"},
		UpstreamIP: "10.0.0.1", UpstreamPort: 8080,
	}
	// Newer, higher-id protected path whose portal verifier is unavailable.
	protected := Route{
		ID: "2", Hosts: []string{"example.com", "www.example.com"},
		PathPrefix: "/secure", UpstreamIP: "10.0.0.1", UpstreamPort: 8080,
		PortalProtect: true, PortalDenyOnMisconfig: true,
	}

	got := routeIDs(t, BuildNodeConfig([]Route{catchAll, protected}, NodeSettings{ACMEEmail: "x@x"}))
	want := []string{"route_2", "route_1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("catch-all still precedes protected subpath: got %v want %v", got, want)
	}

	// The deny route must be the one that owns /secure, not the proxy.
	b, _ := json.Marshal(BuildRoute(protected))
	if s := string(b); strings.Contains(s, "reverse_proxy") || !strings.Contains(s, `"status_code":503`) {
		t.Fatalf("protected route is not fail-closed: %s", s)
	}
}

// Overlap via an alias only (the primary hosts differ) must still reorder.
func TestEmissionOrderAliasOverlap(t *testing.T) {
	catchAll := Route{ID: "10", Hosts: []string{"shop.example.com"}, UpstreamIP: "10.0.0.1", UpstreamPort: 80}
	sub := Route{ID: "11", Hosts: []string{"other.example.com", "shop.example.com"},
		PathPrefix: "/admin", UpstreamIP: "10.0.0.2", UpstreamPort: 80,
		BasicAuthUser: "u", BasicAuthBcrypt: "$2a$10$abc"}
	got := routeIDs(t, BuildNodeConfig([]Route{catchAll, sub}, NodeSettings{ACMEEmail: "x@x"}))
	want := []string{"route_11", "route_10"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("alias overlap not reordered: got %v want %v", got, want)
	}
}

// A wildcard host covers its one-label children, so it is a catch-all for them.
func TestEmissionOrderWildcardHostOverlap(t *testing.T) {
	wild := Route{ID: "20", Hosts: []string{"*.example.com"}, UpstreamIP: "10.0.0.1", UpstreamPort: 80}
	sub := Route{ID: "21", Hosts: []string{"app.example.com"}, PathPrefix: "/api",
		UpstreamIP: "10.0.0.2", UpstreamPort: 80}
	got := routeIDs(t, BuildNodeConfig([]Route{wild, sub}, NodeSettings{ACMEEmail: "x@x"}))
	want := []string{"route_21", "route_20"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("wildcard overlap not reordered: got %v want %v", got, want)
	}
}

// Backward compat: with no shared host, emission order is the input order and
// the config bytes are unchanged (drift hashes must not move for everyone).
func TestEmissionOrderStableWithoutOverlap(t *testing.T) {
	rs := []Route{
		{ID: "1", Hosts: []string{"a.example.com"}, PathPrefix: "/api", UpstreamIP: "10.0.0.1", UpstreamPort: 80},
		{ID: "2", Hosts: []string{"b.example.com"}, UpstreamIP: "10.0.0.2", UpstreamPort: 80},
		{ID: "3", Hosts: []string{"c.example.com"}, PathPrefix: "/x", UpstreamIP: "10.0.0.3", UpstreamPort: 80},
		{ID: "4", Hosts: []string{"d.example.com"}, UpstreamIP: "10.0.0.4", UpstreamPort: 80},
	}
	for i, v := range EmissionOrder(rs) {
		if v != i {
			t.Fatalf("non-overlapping routes reordered: %v", EmissionOrder(rs))
		}
	}
	got := routeIDs(t, BuildNodeConfig(rs, NodeSettings{ACMEEmail: "x@x"}))
	want := []string{"route_1", "route_2", "route_3", "route_4"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("emission order changed: got %v want %v", got, want)
	}
}

// Same host, already narrow-to-broad: nothing moves.
func TestEmissionOrderKeepsAlreadyCorrectOverlap(t *testing.T) {
	rs := []Route{
		{ID: "1", Hosts: []string{"e.example.com"}, PathPrefix: "/deep/path", UpstreamIP: "10.0.0.1", UpstreamPort: 80},
		{ID: "2", Hosts: []string{"e.example.com"}, PathPrefix: "/deep", UpstreamIP: "10.0.0.2", UpstreamPort: 80},
		{ID: "3", Hosts: []string{"e.example.com"}, UpstreamIP: "10.0.0.3", UpstreamPort: 80},
	}
	for i, v := range EmissionOrder(rs) {
		if v != i {
			t.Fatalf("already-correct overlap reordered: %v", EmissionOrder(rs))
		}
	}
}

// Equal specificity: the fail-closed deny twin wins over the plain proxy.
func TestEmissionOrderDenyBeatsEqualSibling(t *testing.T) {
	rs := []Route{
		{ID: "1", Hosts: []string{"f.example.com"}, PathPrefix: "/a", UpstreamIP: "10.0.0.1", UpstreamPort: 80},
		{ID: "2", Hosts: []string{"f.example.com"}, PathPrefix: "/a", UpstreamIP: "10.0.0.2", UpstreamPort: 80,
			RequireClientCert: true, MTLSDenyOnMisconfig: true},
	}
	if got := EmissionOrder(rs); !reflect.DeepEqual(got, []int{1, 0}) {
		t.Fatalf("deny route not hoisted: %v", got)
	}
}

func TestHostsOverlap(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"app.example.com", "app.example.com", true},
		{"App.Example.com", " app.example.com ", true},
		{"*.example.com", "app.example.com", true},
		{"app.example.com", "*.example.com", true},
		{"*.example.com", "*.example.com", true},
		{"*.example.com", "a.b.example.com", false},
		{"*.example.com", "example.com", false},
		{"*.example.com", "*.other.com", false},
		{"app.example.com", "other.example.com", false},
		{"", "app.example.com", false},
	}
	for _, c := range cases {
		if got := HostsOverlap(c.a, c.b); got != c.want {
			t.Errorf("HostsOverlap(%q,%q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
	if !HostSetsOverlap([]string{"x.test", "app.example.com"}, []string{"*.example.com"}) {
		t.Error("HostSetsOverlap should find the wildcard pair")
	}
	if HostSetsOverlap([]string{"x.test"}, []string{"*.example.com"}) {
		t.Error("HostSetsOverlap false positive")
	}
}
