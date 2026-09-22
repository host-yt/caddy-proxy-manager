package handlers

import "testing"

// A 2FA login may only complete with a factor the user enrolled: an email or
// SMS code must not stand in for an authenticator app.
func TestTwoFAMethodEnrolled(t *testing.T) {
	cases := []struct {
		method                  string
		totp, sms, email, allow bool
	}{
		{"totp", true, false, false, true},
		{"totp", false, false, true, false},
		{"email", true, false, false, false},
		{"email", false, false, true, true},
		{"sms", true, false, true, false},
		{"sms", false, true, false, true},
		{"recovery", true, false, false, true},
	}
	for _, c := range cases {
		if got := twoFAMethodEnrolled(c.method, c.totp, c.sms, c.email); got != c.allow {
			t.Errorf("twoFAMethodEnrolled(%q, totp=%v sms=%v email=%v) = %v, want %v",
				c.method, c.totp, c.sms, c.email, got, c.allow)
		}
	}
}
