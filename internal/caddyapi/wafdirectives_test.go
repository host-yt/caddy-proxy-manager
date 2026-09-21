package caddyapi

import (
	"strings"
	"testing"
)

// HPG-SEC-006: a scoped admin may only suppress rule ids; nobody may store a
// line Coraza cannot parse, because the node compiles them all into one config.
func TestValidateWAFDirectives(t *testing.T) {
	cases := []struct {
		name         string
		raw          string
		unrestricted bool
		wantErr      bool
	}{
		{"scoped removebyid", "SecRuleRemoveById 942100", false, false},
		{"scoped several ids and a range", "SecRuleRemoveById 942100 942110-942120\n# note", false, false},
		{"scoped arbitrary seclang", "SecRule REQUEST_URI \"@rx x\" \"id:1,deny\"", false, true},
		{"scoped rule engine off", "SecRuleEngine Off", false, true},
		{"scoped non-numeric id", "SecRuleRemoveById foo", false, true},
		{"admin arbitrary seclang", "SecRule REQUEST_URI \"@rx x\" \"id:1,deny\"", true, false},
		{"include is never a directive", "Include /etc/passwd", true, true},
		{"unbalanced quote breaks the parser", "SecRule REQUEST_URI \"@rx x", true, true},
		{"junk line", "not a directive at all", true, true},
		{"blank and comments", "\n# hello\n", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateWAFDirectives(tc.raw, tc.unrestricted)
			if tc.wantErr != (err != nil) {
				t.Fatalf("ValidateWAFDirectives(%q, %v) = %v, wantErr=%v", tc.raw, tc.unrestricted, err, tc.wantErr)
			}
		})
	}
}

// A poisoned legacy row must not reach the node config: it would fail /load
// for every tenant on that node, not just its own route.
func TestBuildRouteDropsUnparseableWAFDirectives(t *testing.T) {
	r := Route{
		ID: "9", Hosts: []string{"w.example.com"}, UpstreamIP: "10.0.0.9", UpstreamPort: 8080,
		WAFEnabled: true, WAFModuleAvailable: true,
		WAFDirectives: "Include /etc/passwd\nSecRuleRemoveById 942100\ngarbage \"",
	}
	s := mustJSON(r)
	if strings.Contains(s, "/etc/passwd") || strings.Contains(s, "garbage") {
		t.Errorf("unparseable WAF directives must be dropped\nfull: %s", s)
	}
	if !strings.Contains(s, "SecRuleRemoveById 942100") {
		t.Errorf("valid directive must survive\nfull: %s", s)
	}
}

// HPG-SEC-004: header values reach Caddy's replacer, same as custom handlers.
func TestScreenReplacerValue(t *testing.T) {
	for _, bad := range []string{"{env.APP_SECRET}", "x {FILE./etc/passwd} y", "{SYSTEM.hostname}", "{$APP_SECRET}"} {
		if err := ScreenReplacerValue(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
	for _, ok := range []string{"{http.request.host}", "{http.request.remote.host}", "static-value", ""} {
		if err := ScreenReplacerValue(ok); err != nil {
			t.Errorf("%q must be allowed: %v", ok, err)
		}
	}
}
