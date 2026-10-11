package middleware

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInstallTransportGuard(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	cases := []struct {
		name      string
		host      string
		tls       bool
		xfp       string
		installed bool
		allow     bool
		want      int
	}{
		{"remote plain http", "203.0.113.5:8080", false, "", false, false, http.StatusForbidden},
		{"proxy over plain http", "panel.example.com", false, "http", false, false, http.StatusForbidden},
		{"ssh forward ipv4", "127.0.0.1:8080", false, "", false, false, http.StatusOK},
		{"ssh forward localhost", "localhost:8080", false, "", false, false, http.StatusOK},
		{"ssh forward ipv6", "[::1]:8080", false, "", false, false, http.StatusOK},
		{"direct tls", "panel.example.com", true, "", false, false, http.StatusOK},
		{"tls at proxy", "panel.example.com", false, "https", false, false, http.StatusOK},
		{"explicit opt-out", "203.0.113.5:8080", false, "", false, true, http.StatusOK},
		{"already installed", "203.0.113.5:8080", false, "", true, false, http.StatusOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := InstallTransportGuard(func() bool { return c.installed }, c.allow)(ok)
			r := httptest.NewRequest(http.MethodGet, "/install", nil)
			r.Host = c.host
			if c.tls {
				r.TLS = &tls.ConnectionState{}
			}
			if c.xfp != "" {
				r.Header.Set("X-Forwarded-Proto", c.xfp)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != c.want {
				t.Fatalf("got %d, want %d", w.Code, c.want)
			}
		})
	}
}
