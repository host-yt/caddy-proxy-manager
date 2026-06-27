package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// portalSafeBack is the load-bearing open-redirect guard for the login
// handshake. Anything that isn't a same-origin absolute path must collapse to
// "/" so a crafted ?back= can't bounce the user to an attacker origin.
func TestPortalSafeBack(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", "/"},
		{"simple path", "/dashboard", "/dashboard"},
		{"path with query", "/app?tab=2", "/app?tab=2"},
		{"absolute http", "http://evil.com/x", "/"},
		{"absolute https", "https://evil.com/x", "/"},
		{"protocol relative", "//evil.com/x", "/"},
		{"backslash trick", "/\\evil.com", "/"},
		{"scheme relative with backslash", "\\/evil.com", "/"},
		{"host only", "evil.com/x", "/"},
		{"javascript scheme", "javascript:alert(1)", "/"},
		{"relative no slash", "foo/bar", "/"},
		{"root", "/", "/"},
		{"deep path", "/a/b/c?x=1&y=2", "/a/b/c?x=1&y=2"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := portalSafeBack(c.in, "app.example.com")
			if got != c.want {
				t.Errorf("portalSafeBack(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestPortalSafeBackTooLong(t *testing.T) {
	long := "/" + string(make([]byte, portalMaxBackLen+10))
	if got := portalSafeBack(long, "h"); got != "/" {
		t.Errorf("over-length back not rejected: %q", got)
	}
}

func TestPortal2FAStateRoundTrip(t *testing.T) {
	st := portal2FAState{
		UserID: 42, Email: "u@example.com", Username: "Alice",
		Back: "/dash", Host: "app.example.com", RememberMe: true,
		Attempts: 2, ExpiresAt: 1800000000,
	}
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	var st2 portal2FAState
	if err := json.Unmarshal(b, &st2); err != nil {
		t.Fatal(err)
	}
	if st2.Attempts != 2 || st2.ExpiresAt != 1800000000 {
		t.Errorf("round-trip lost fields: %+v", st2)
	}
	// Zero Attempts must be omitted (omitempty) so old states still unmarshal cleanly.
	st3 := portal2FAState{UserID: 1, ExpiresAt: 1800000000}
	b2, _ := json.Marshal(st3)
	if strings.Contains(string(b2), `"a":`) {
		t.Errorf("zero Attempts should be omitted from JSON: %s", b2)
	}
	if portal2FAMaxAttempts != 3 {
		t.Errorf("portal2FAMaxAttempts = %d, want 3", portal2FAMaxAttempts)
	}
}

func TestParseSameSite(t *testing.T) {
	if ParseSameSite("strict") != http.SameSiteStrictMode {
		t.Error("strict should map to SameSiteStrictMode")
	}
	if ParseSameSite("none") != http.SameSiteNoneMode {
		t.Error("none should map to SameSiteNoneMode")
	}
	// Default (unknown) must be Lax to match the panel session cookie.
	if ParseSameSite("bogus") != http.SameSiteLaxMode {
		t.Error("unknown SameSite should default to Lax")
	}
}
