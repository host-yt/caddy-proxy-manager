package caddyapi

import (
	"encoding/json"
	"strings"
	"testing"
)

// A node without Coraza must not silently serve a blocking-mode WAF route
// unfiltered, and must not take the rest of the node down with it.
func TestWAFModuleMissingQuarantinesBlockingRoute(t *testing.T) {
	waf := Route{ID: "1", Hosts: []string{"waf.example.com"}, UpstreamIP: "10.0.0.5", UpstreamPort: 30000,
		WAFEnabled: true, WAFBlocking: true}
	plain := Route{ID: "2", Hosts: []string{"plain.example.com"}, UpstreamIP: "10.0.0.6", UpstreamPort: 30001}
	detect := waf
	detect.ID, detect.Hosts, detect.WAFBlocking = "3", []string{"detect.example.com"}, false

	render := func(s NodeSettings) []string {
		cfg := BuildNodeConfig([]Route{waf, plain, detect}, s)
		routes := cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["srv0"].(map[string]any)["routes"].([]any)
		byID := map[string]string{}
		for _, r := range routes {
			b, _ := json.Marshal(r)
			byID[r.(map[string]any)["@id"].(string)] = string(b)
		}
		return []string{byID["route_1"], byID["route_2"], byID["route_3"]}
	}

	got := render(NodeSettings{})
	if !strings.Contains(got[0], "web application firewall is unavailable") || strings.Contains(got[0], "reverse_proxy") {
		t.Fatalf("blocking WAF route without module not quarantined: %s", got[0])
	}
	if !strings.Contains(got[1], "reverse_proxy") || !strings.Contains(got[2], "reverse_proxy") {
		t.Fatalf("unrelated or detection-only routes must keep serving: %v", got[1:])
	}
	for _, r := range got {
		if strings.Contains(r, `"handler":"waf"`) {
			t.Fatalf("waf handler emitted to a node without the module: %s", r)
		}
	}

	got = render(NodeSettings{WAFFailOpen: true})
	if !strings.Contains(got[0], "reverse_proxy") {
		t.Fatalf("explicit fail-open must serve the route: %s", got[0])
	}

	got = render(NodeSettings{WAFModuleAvailable: true})
	if !strings.Contains(got[0], `"handler":"waf"`) {
		t.Fatalf("waf handler missing with module available: %s", got[0])
	}
}
