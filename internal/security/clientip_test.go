package security

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientIPStripsPort(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.5:55555"
	if got := ClientIP(r); got != "203.0.113.5" {
		t.Fatalf("want 203.0.113.5, got %q", got)
	}
}

func TestClientIPIPv6(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "[2001:db8::1]:55555"
	if got := ClientIP(r); got != "2001:db8::1" {
		t.Fatalf("want 2001:db8::1, got %q", got)
	}
}

func TestClientIPIgnoresXForwardedFor(t *testing.T) {
	// The whole point of centralisation: XFF must NOT be read here.
	// chimw.RealIP + cf_ip middleware are the only writers to RemoteAddr.
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.5:443"
	r.Header.Set("X-Forwarded-For", "9.9.9.9, 8.8.8.8")
	if got := ClientIP(r); got != "203.0.113.5" {
		t.Fatalf("ClientIP must trust RemoteAddr only; got %q", got)
	}
}

func TestClientIPEmpty(t *testing.T) {
	r := &http.Request{}
	if got := ClientIP(r); got != "" {
		t.Fatalf("want empty, got %q", got)
	}
}
