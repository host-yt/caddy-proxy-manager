package handlers

import "testing"

// captchaSecretRequired guards the provider-switch lockout: a CAPTCHA secret is
// provider-specific, so it may only be reused when the provider is unchanged and
// a secret already exists.
func TestCaptchaSecretRequired(t *testing.T) {
	cases := []struct {
		name                    string
		newProvider, curProvider string
		hasSecret, secretProvided bool
		want                    bool
	}{
		{"fresh secret always ok", "hcaptcha", "turnstile", true, true, false},
		{"switch provider, no new secret -> required", "hcaptcha", "turnstile", true, false, true},
		{"same provider, secret exists -> reuse ok", "turnstile", "turnstile", true, false, false},
		{"same provider, no secret yet -> required", "turnstile", "turnstile", false, false, true},
		{"first-time enable, no secret -> required", "turnstile", "", false, false, true},
		{"switch from none with new secret -> ok", "turnstile", "", false, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := captchaSecretRequired(c.newProvider, c.curProvider, c.hasSecret, c.secretProvided)
			if got != c.want {
				t.Errorf("captchaSecretRequired(%q,%q,%v,%v) = %v, want %v",
					c.newProvider, c.curProvider, c.hasSecret, c.secretProvided, got, c.want)
			}
		})
	}
}
