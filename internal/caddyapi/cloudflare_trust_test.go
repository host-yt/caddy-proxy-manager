package caddyapi

import (
	"strings"
	"testing"
)

// Behind Cloudflare, Caddy must resolve the real client IP from
// CF-Connecting-IP instead of logging/forwarding the CF edge IP (issue #8).
func TestBuildNodeConfigTrustsCloudflareIP(t *testing.T) {
	ranges := []string{"173.245.48.0/20", "2400:cb00::/32"}
	cfg := BuildNodeConfig([]Route{
		{ID: "1", Hosts: []string{"a.example.com"}, UpstreamIP: "10.0.0.1", UpstreamPort: 8080},
	}, NodeSettings{ACMEEmail: "x@x", TrustCloudflareIP: true, CloudflareRanges: ranges})

	srv0 := srv0Of(cfg)
	tp, ok := srv0["trusted_proxies"].(map[string]any)
	if !ok {
		t.Fatalf("trusted_proxies missing, got %s", jsonStr(srv0))
	}
	if tp["source"] != "static" {
		t.Errorf("trusted_proxies source must be static, got %v", tp["source"])
	}
	got := jsonStr(tp["ranges"])
	for _, r := range ranges {
		if !strings.Contains(got, r) {
			t.Errorf("range %s missing from trusted_proxies: %s", r, got)
		}
	}
	if h := jsonStr(srv0["client_ip_headers"]); h != `["CF-Connecting-IP"]` {
		t.Errorf("client_ip_headers must be CF-Connecting-IP, got %s", h)
	}
}

// Off by default: existing nodes must see byte-identical JSON, so neither key
// may appear when the toggle is off or the range list is empty.
func TestBuildNodeConfigOmitsCloudflareTrustWhenOff(t *testing.T) {
	for _, tc := range []struct {
		name   string
		trust  bool
		ranges []string
	}{
		{"toggle off", false, []string{"173.245.48.0/20"}},
		{"no ranges", true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := BuildNodeConfig([]Route{
				{ID: "1", Hosts: []string{"a.example.com"}, UpstreamIP: "10.0.0.1", UpstreamPort: 8080},
			}, NodeSettings{ACMEEmail: "x@x", TrustCloudflareIP: tc.trust, CloudflareRanges: tc.ranges})
			srv0 := srv0Of(cfg)
			if _, ok := srv0["trusted_proxies"]; ok {
				t.Error("trusted_proxies must be omitted entirely")
			}
			if _, ok := srv0["client_ip_headers"]; ok {
				t.Error("client_ip_headers must be omitted entirely")
			}
		})
	}
}
