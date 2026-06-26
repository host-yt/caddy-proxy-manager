package handlers

import (
	"net/http"
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
