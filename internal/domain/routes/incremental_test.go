package routes

import (
	"errors"
	"testing"
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
