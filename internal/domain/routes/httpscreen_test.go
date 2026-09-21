package routes

import (
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
)

// HPG-SEC-001: rows stored before HTTP target screening existed must not be
// re-emitted by boot push, resync or drift recovery - and a poisoned extra
// upstream or path rule must not take the whole route with it.
func TestScreenHTTPSetDropsInfraTargets(t *testing.T) {
	infra := screenTestInfra(t)
	built := []caddyapi.Route{
		{ID: "1", UpstreamIP: "10.0.0.5", UpstreamPort: 8080}, // customer origin, kept
		{ID: "2", UpstreamIP: "203.0.113.7", UpstreamPort: 8080},
		{ID: "3", UpstreamIP: "10.0.0.5", UpstreamPort: 2019},
		{ID: "4", UpstreamIP: "10.0.0.5", UpstreamPort: 8080,
			Upstreams: []caddyapi.Upstream{
				{Host: "10.0.0.6", Port: 8080},
				{Host: "127.0.0.1", Port: 2019},
			},
			LocationRules: []caddyapi.LocationRule{
				{Path: "/a", Action: "proxy", UpstreamHost: "10.0.0.7", UpstreamPort: 80},
				{Path: "/b", Action: "proxy", UpstreamHost: "10.66.0.4", UpstreamPort: 80},
			}},
		{ID: "5", Kind: "redirect", UpstreamIP: "0.0.0.0"}, // never dialed
	}
	out, ids, drops := screenHTTPSet(infra, built, []int64{1, 2, 3, 4, 5})
	if len(out) != 3 || len(ids) != 3 {
		t.Fatalf("want 3 emitted routes, got %d (%v)", len(out), ids)
	}
	if ids[0] != 1 || ids[1] != 4 || ids[2] != 5 {
		t.Fatalf("ids must stay paired with routes, got %v", ids)
	}
	if len(drops) != 4 { // routes 2 and 3, plus one upstream and one rule of route 4
		t.Fatalf("want 4 drops, got %d", len(drops))
	}
	survivor := out[1]
	if len(survivor.Upstreams) != 1 || survivor.Upstreams[0].Host != "10.0.0.6" {
		t.Errorf("only the admin-API upstream may be dropped, got %+v", survivor.Upstreams)
	}
	if len(survivor.LocationRules) != 1 || survivor.LocationRules[0].Path != "/a" {
		t.Errorf("only the control-plane path rule may be dropped, got %+v", survivor.LocationRules)
	}
}
