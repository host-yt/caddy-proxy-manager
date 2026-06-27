package handlers

import "testing"

// Tool access by role. super_admin/admin get the full-or-scoped tool set;
// client gets a strictly scoped tool set (own tenant only, enforced in aitools).
// Support must NOT reach any tools even though it can open the chat via the
// read-only allow-list (2026-06-27 adversarial review finding).
func TestRoleCanUseAITools(t *testing.T) {
	cases := map[string]bool{
		"super_admin": true,
		"admin":       true,
		"client":      true,
		"support":     false,
		"":            false,
	}
	for role, want := range cases {
		if got := roleCanUseAITools(role); got != want {
			t.Errorf("roleCanUseAITools(%q) = %v, want %v", role, got, want)
		}
	}
}
