package handlers

import (
	"net/url"
	"testing"
)

// Permissive SSO must be a choice, never a side effect of a save that did not
// mention it: the checkbox alone would read "absent" as "off".
func TestSSOStrictFromForm(t *testing.T) {
	cases := []struct {
		name   string
		form   url.Values
		stored bool
		want   bool
	}{
		{"field absent keeps a strict route strict", url.Values{}, true, true},
		{"field absent keeps a permissive route permissive", url.Values{}, false, false},
		{"form posts marker + checked box", url.Values{"sso_strict_mode": {"0", "1"}}, false, true},
		{"form posts marker only", url.Values{"sso_strict_mode": {"0"}}, true, false},
		{"bare checkbox on", url.Values{"sso_strict_mode": {"1"}}, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ssoStrictFromForm(tc.form, tc.stored); got != tc.want {
				t.Fatalf("ssoStrictFromForm(%v, %v) = %v, want %v", tc.form, tc.stored, got, tc.want)
			}
		})
	}
}
