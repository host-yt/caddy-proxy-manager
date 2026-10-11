package caddyapi

import (
	"strings"
	"testing"
)

var screenSeeds = []string{
	"https://{http.request.host}/x", "{env.SECRET}", "{file./etc/passwd}", "{{env.X}}", "{", "}", "{}",
	"{http.request.uri:", "a{b{c}d}", `\{env.X}`, "{ENV.X}", "{system.hostname}", "plain", "",
}

func FuzzScreenTenantTemplate(f *testing.F) {
	for _, s := range screenSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n := NeutralizeTenantTemplate(s)
		// A value that screens clean needs no escaping.
		if ScreenTenantTemplate(s) == nil && n != s {
			t.Fatalf("clean value rewritten: %q", s)
		}
		// Neutralizing is idempotent.
		if NeutralizeTenantTemplate(n) != n {
			t.Fatalf("neutralize not idempotent: %q", s)
		}
	})
}

func FuzzScreenReplacerValue(f *testing.F) {
	for _, s := range screenSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if ScreenReplacerValue(s) != nil {
			return
		}
		low := strings.ToLower(s)
		for _, tok := range unsafePlaceholderTokens {
			if strings.Contains(low, tok) {
				t.Fatalf("passed with %q: %q", tok, s)
			}
		}
	})
}
