package handlers

import "testing"

// Tools expose client/service/route/traffic data; only admin roles may use them.
// Regression guard for the 2026-06-27 adversarial review finding: support (which
// can open the chat via the read-only allow-list) must NOT reach the tools.
func TestRoleCanUseAITools(t *testing.T) {
	cases := map[string]bool{
		"super_admin": true,
		"admin":       true,
		"support":     false,
		"client":      false,
		"":            false,
	}
	for role, want := range cases {
		if got := roleCanUseAITools(role); got != want {
			t.Errorf("roleCanUseAITools(%q) = %v, want %v", role, got, want)
		}
	}
}
