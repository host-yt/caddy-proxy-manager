package routes

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
)

func TestRouteMatchHosts(t *testing.T) {
	// Shape mirrors what Caddy returns for a route object's match[].
	obj := map[string]any{
		"@id": "route_7",
		"match": []any{
			map[string]any{"host": []any{"a.example.com", "b.example.com"}},
		},
	}
	got := routeMatchHosts(obj)
	if len(got) != 2 || got[0] != "a.example.com" || got[1] != "b.example.com" {
		t.Fatalf("routeMatchHosts = %v, want [a.example.com b.example.com]", got)
	}
	// Missing/!malformed match must not panic and returns no hosts.
	if h := routeMatchHosts(map[string]any{}); len(h) != 0 {
		t.Fatalf("empty obj should yield no hosts, got %v", h)
	}
	if h := routeMatchHosts(map[string]any{"match": "nope"}); len(h) != 0 {
		t.Fatalf("malformed match should yield no hosts, got %v", h)
	}
}

func TestIsNotFound(t *testing.T) {
	if isNotFound(nil) {
		t.Error("nil err is not a 404")
	}
	if !isNotFound(errors.New("caddy DELETE /id/route_1: 404 Not Found")) {
		t.Error("404 error should be detected")
	}
	if isNotFound(errors.New("caddy DELETE /id/route_1: 500 Internal Server Error")) {
		t.Error("500 is not a 404")
	}
}

// A permissive "*.example.com" catch-all already on the node must be detected as
// a clash for a new concrete "app.example.com" route, forcing a full resync -
// otherwise the append lands after the wildcard and the gate never runs.
func TestRoutePresenceAndHostClashWildcardOverlap(t *testing.T) {
	node := []map[string]any{
		{"@id": "route_1", "match": []any{map[string]any{"host": []any{"*.example.com"}}}},
		{"@id": "route_9", "match": []any{map[string]any{"host": []any{"other.test"}}}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/config/apps/http/servers/srv0/routes" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(node)
	}))
	defer srv.Close()

	s := &Service{}
	client := caddyapi.New(srv.URL)

	cases := []struct {
		name  string
		hosts []string
		want  bool
	}{
		{"concrete under existing wildcard", []string{"app.example.com"}, true},
		{"case-insensitive", []string{"APP.Example.COM"}, true},
		{"exact wildcard twin", []string{"*.example.com"}, true},
		{"deeper label not covered", []string{"a.b.example.com"}, false},
		{"unrelated host", []string{"nope.test"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, sharesHost, err := s.routePresenceAndHostClash(context.Background(), client, 42, tc.hosts)
			if err != nil {
				t.Fatalf("probe: %v", err)
			}
			if sharesHost != tc.want {
				t.Fatalf("sharesHost = %v, want %v", sharesHost, tc.want)
			}
		})
	}
}

// Full-config ordering must put the gated concrete host ahead of the permissive
// wildcard - the invariant the incremental clash probe falls back to.
func TestEmissionOrderGatedHostBeforeWildcard(t *testing.T) {
	rs := []caddyapi.Route{
		{Hosts: []string{"*.example.com"}},
		{Hosts: []string{"app.example.com"}, PathPrefix: "/secure", BasicAuthUser: "admin"},
	}
	got := caddyapi.SortRoutesForEmission(rs)
	if got[0].PathPrefix != "/secure" {
		t.Fatalf("gated route must be emitted first, got %+v", got[0].Hosts)
	}
}
