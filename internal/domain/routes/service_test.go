package routes

import (
	"encoding/json"
	"testing"
)

func TestValidDomain(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"example.com", true},
		{"app.customer.io", true},
		{"a.b.c.d.example.com", true},
		{"foo-bar.example.com", true},
		{"FOO.example.com", true}, // accepted; caller lowercases first
		{"", false},
		{"nodot", false},
		{"-leading.example.com", false},
		{"trailing-.example.com", false},
		{"double..dot.example.com", false},
		{"1.2.3.4", false}, // raw IPv4 rejected
		{"foo bar.example.com", false},
		{"foo_bar.example.com", false},
		{string(make([]byte, 254)) + ".com", false}, // length > 253
	}
	for _, c := range cases {
		got := validDomain(c.in)
		if got != c.want {
			t.Errorf("validDomain(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestHashRoutesStable(t *testing.T) {
	a := []routeFixture{
		{1, "app.example.com", "/", 30000},
		{2, "api.example.com", "", 30001},
	}
	b := []routeFixture{
		{1, "app.example.com", "/", 30000},
		{2, "api.example.com", "", 30001},
	}
	if hashRoutesFixture(a) != hashRoutesFixture(b) {
		t.Fatal("identical inputs hash differently")
	}
	c := []routeFixture{
		{1, "app.example.com", "/", 30000},
		{2, "api.example.com", "", 30002}, // port changed
	}
	if hashRoutesFixture(a) == hashRoutesFixture(c) {
		t.Fatal("different inputs hash to the same value")
	}
}

// Local fixture wrapper. The production hashRoutes signature is internal;
// we exercise it through a typed adapter so the test stays decoupled from
// internal/caddyapi imports here.
type routeFixture struct {
	ID   int64
	Host string
	Path string
	Port int
}

func hashRoutesFixture(fs []routeFixture) string {
	return hashRoutesViaCaddy(fs)
}

func TestFilterVirtualRoutes(t *testing.T) {
	// actual srv0/routes as Caddy returns them: panel + wstunnel infra + customers
	actual := []byte(`[` +
		`{"@id":"route_panel_self","x":1},` +
		`{"@id":"hpg_wstunnel_7","y":2},` +
		`{"@id":"route_42","z":3},` +
		`{"@id":"route_99","z":4}` +
		`]`)
	got := filterVirtualRoutes(actual)
	var arr []map[string]any
	if err := json.Unmarshal(got, &arr); err != nil {
		t.Fatalf("result not valid json: %v", err)
	}
	if len(arr) != 2 {
		t.Fatalf("want 2 customer routes after filter, got %d: %s", len(arr), got)
	}
	for _, r := range arr {
		id, _ := r["@id"].(string)
		if id != "route_42" && id != "route_99" {
			t.Fatalf("unexpected route survived filter: %q", id)
		}
	}
	// non-array input is returned untouched (don't corrupt unknown shapes)
	weird := []byte(`{"not":"an array"}`)
	if string(filterVirtualRoutes(weird)) != string(weird) {
		t.Fatalf("non-array input should pass through unchanged")
	}
}
