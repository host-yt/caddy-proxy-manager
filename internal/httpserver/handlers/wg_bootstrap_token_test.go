package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// validBootstrapToken is the last gate before a token is interpolated into a
// root shell script (renderInstallScript). A length-only check let a 192-char
// $(...) payload through to RCE - the charset must be locked to hex.
func TestValidBootstrapToken(t *testing.T) {
	hex192 := func(fill byte) string {
		b := make([]byte, 192)
		for i := range b {
			b[i] = fill
		}
		return string(b)
	}

	cases := []struct {
		name  string
		token string
		want  bool
	}{
		{name: "valid hex 192", token: hex192('a'), want: true},
		{name: "valid hex digits", token: hex192('0'), want: true},
		{name: "too short", token: hex192('a')[:191], want: false},
		{name: "too long", token: hex192('a') + "a", want: false},
		{name: "empty", token: "", want: false},
		{
			name:  "command substitution payload",
			token: "$(id)" + hex192('a')[5:],
			want:  false,
		},
		{
			name:  "backtick payload",
			token: "`id`" + hex192('a')[4:],
			want:  false,
		},
		{
			name:  "uppercase hex rejected",
			token: "A" + hex192('a')[1:],
			want:  false,
		},
		{
			name:  "semicolon injection",
			token: hex192('a')[:191] + ";",
			want:  false,
		},
		{
			name:  "space injection",
			token: hex192('a')[:191] + " ",
			want:  false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := validBootstrapToken(c.token); got != c.want {
				t.Errorf("validBootstrapToken(%q) = %v, want %v", c.token, got, c.want)
			}
		})
	}
}

// The query string is never a token channel: URLs end up in access logs.
func TestBootstrapTokenChannels(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/wg/status?token=q", nil)
	if got := bootstrapToken(r); got != "" {
		t.Fatalf("query token accepted: %q", got)
	}
	r.Header.Set("Authorization", "Bearer h")
	if got := bootstrapToken(r); got != "h" {
		t.Fatalf("header token = %q", got)
	}
	r = httptest.NewRequest(http.MethodPost, "/api/wg/bootstrap?token=q", strings.NewReader("token=f"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if got := bootstrapToken(r); got != "f" {
		t.Fatalf("form token = %q", got)
	}
}
