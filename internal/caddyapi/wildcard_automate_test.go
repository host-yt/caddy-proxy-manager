package caddyapi

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func wildcardSettings(dns bool) NodeSettings {
	return NodeSettings{
		ACMEEmail:            "ops@example.test",
		AskURL:               "http://panel/ask",
		DNS01ModuleAvailable: dns,
		WildcardPolicies: []WildcardPolicy{{
			Zone: "shop.example", Provider: "cloudflare",
			Fields: map[string]string{"api_token": "tok"},
		}},
	}
}

func wildcardRoute() Route {
	return Route{ID: "r1", Hosts: []string{"shop.example"}, UpstreamIP: "10.0.0.5", UpstreamPort: 80,
		WildcardZone: "shop.example"}
}

func automateOf(cfg map[string]any) []string {
	tls := cfg["apps"].(map[string]any)["tls"].(map[string]any)
	certs, _ := tls["certificates"].(map[string]any)
	auto, _ := certs["automate"].([]string)
	return auto
}

func routesJSON(t *testing.T, cfg map[string]any) string {
	t.Helper()
	srv := cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["srv0"].(map[string]any)
	b, err := json.Marshal(srv["routes"])
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The wildcard cert must be ordered up front (automate) and the route must
// match its subdomains; without a working DNS-01 path neither may appear.
func TestWildcardAutomateAndHostMatcher(t *testing.T) {
	routes := []Route{wildcardRoute()}
	cfg := BuildNodeConfig(routes, wildcardSettings(true))
	if auto := automateOf(cfg); !slices.Equal(auto, []string{"*.shop.example", "shop.example"}) {
		t.Errorf("automate = %v, want [*.shop.example shop.example]", auto)
	}
	if !strings.Contains(routesJSON(t, cfg), `"*.shop.example"`) {
		t.Error("route host matcher lacks *.shop.example")
	}
	if len(routes[0].Hosts) != 1 {
		t.Errorf("caller's route mutated: %v", routes[0].Hosts)
	}

	for name, s := range map[string]NodeSettings{
		"no DNS module":    wildcardSettings(false),
		"unknown provider": func() NodeSettings { s := wildcardSettings(true); s.WildcardPolicies[0].Provider = "nope"; return s }(),
		"no policy":        {ACMEEmail: "ops@example.test", DNS01ModuleAvailable: true},
	} {
		cfg := BuildNodeConfig([]Route{wildcardRoute()}, s)
		if auto := automateOf(cfg); len(auto) != 0 {
			t.Errorf("%s: automate = %v, want empty", name, auto)
		}
		if strings.Contains(routesJSON(t, cfg), "*.shop.example") {
			t.Errorf("%s: *.zone host emitted without a DNS-01 policy", name)
		}
	}
}

// A lower-id wildcard route must not shadow a sibling's exact host.
func TestWildcardSortsAfterExactHost(t *testing.T) {
	wild := Route{ID: "w", Hosts: []string{"shop.example", "*.shop.example"}}
	exact := Route{ID: "e", Hosts: []string{"demo.shop.example"}}
	got := SortRoutesForEmission([]Route{wild, exact})
	if got[0].ID != "e" {
		t.Errorf("order = %s,%s; exact host must come first", got[0].ID, got[1].ID)
	}
}
