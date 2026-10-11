package accesslog

import "testing"

func TestRedactURI(t *testing.T) {
	for in, want := range map[string]string{
		"/api/wg/install.sh?token=abc": "/api/wg/install.sh",
		"/api/wg/status":               "/api/wg/status",
		"/search?q=token":              "/search?q=token",
	} {
		if got := RedactURI(in); got != want {
			t.Errorf("RedactURI(%q) = %q, want %q", in, got, want)
		}
	}
}
