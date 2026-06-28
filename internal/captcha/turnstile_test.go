package captcha

import "testing"

// Enabled must accept every known provider (when a secret is set) and reject
// unknown/empty providers - the latter is the safety net that keeps a stale or
// misconfigured provider string from enforcing CAPTCHA with no working verify.
func TestEnabledByProvider(t *testing.T) {
	cases := []struct {
		provider string
		secret   string
		want     bool
	}{
		{"turnstile", "s", true},
		{"hcaptcha", "s", true},
		{"recaptcha", "s", true},
		{"turnstile", "", false},  // no secret
		{"", "s", false},          // disabled
		{"bogus", "s", false},     // unknown provider
		{"Turnstile", "s", false}, // case-sensitive: not a known id
	}
	for _, c := range cases {
		v := New(c.provider, c.secret) // DB nil -> maybeReload is a no-op
		if got := v.Enabled(); got != c.want {
			t.Errorf("provider=%q secret=%q: Enabled()=%v want %v", c.provider, c.secret, got, c.want)
		}
	}
}

func TestProviderGetter(t *testing.T) {
	if p := New("hcaptcha", "s").Provider(); p != "hcaptcha" {
		t.Fatalf("Provider() = %q, want hcaptcha", p)
	}
}

// Every known provider must have a distinct, https siteverify endpoint, or
// Verify would silently treat it as disabled.
func TestVerifyURLsComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range []string{"turnstile", "hcaptcha", "recaptcha"} {
		u := verifyURLs[p]
		if u == "" {
			t.Errorf("provider %q has no verify URL", p)
		}
		if seen[u] {
			t.Errorf("provider %q reuses verify URL %q", p, u)
		}
		seen[u] = true
		if !knownProvider(p) {
			t.Errorf("knownProvider(%q) = false", p)
		}
	}
	if knownProvider("") || knownProvider("nope") {
		t.Error("knownProvider accepted an unknown provider")
	}
}
