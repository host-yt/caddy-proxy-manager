package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func trustedPeerReq(headers map[string]string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "172.18.0.5:12345" // inside the trusted docker bridge
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func finalRemoteAddr(t *testing.T, mwFn func(http.Handler) http.Handler, r *http.Request) string {
	t.Helper()
	var got string
	h := mwFn(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.RemoteAddr
	}))
	h.ServeHTTP(httptest.NewRecorder(), r)
	return got
}

// TestTrustedRealIP_IgnoresClientHeadersByDefault is the regression for
// HPG-SEC-005: from a trusted peer, an attacker-controlled True-Client-IP or
// X-Real-IP must not override RemoteAddr unless the operator explicitly
// opted that exact header in.
func TestTrustedRealIP_IgnoresClientHeadersByDefault(t *testing.T) {
	cidrs := ParseCIDRList([]string{"172.18.0.0/16"})
	mwFn := TrustedRealIP(cidrs, nil)

	r := trustedPeerReq(map[string]string{
		"True-Client-IP": "9.9.9.9",
		"X-Real-IP":      "8.8.8.8",
	})
	got := finalRemoteAddr(t, mwFn, r)
	if got == "9.9.9.9" || got == "8.8.8.8" {
		t.Fatalf("RemoteAddr = %q, must not trust client-set True-Client-IP/X-Real-IP by default", got)
	}
}

// TestTrustedRealIP_PrefersVerifiedXFFEntry: the right-hand non-trusted XFF
// hop wins even when a spoofable header is also present.
func TestTrustedRealIP_PrefersVerifiedXFFEntry(t *testing.T) {
	cidrs := ParseCIDRList([]string{"172.18.0.0/16"})
	mwFn := TrustedRealIP(cidrs, nil)

	r := trustedPeerReq(map[string]string{
		"X-Forwarded-For": "203.0.113.7, 172.18.0.9",
		"True-Client-IP":  "9.9.9.9", // attacker-set, must lose
	})
	got := finalRemoteAddr(t, mwFn, r)
	if got != "203.0.113.7" {
		t.Fatalf("RemoteAddr = %q, want the verified XFF entry 203.0.113.7", got)
	}
}

// TestTrustedRealIP_HonorsExplicitlyTrustedHeader: an operator who names
// X-Real-IP (their edge appliance overwrites it) gets it honored - but only
// that header, not True-Client-IP, which stays untrusted.
func TestTrustedRealIP_HonorsExplicitlyTrustedHeader(t *testing.T) {
	cidrs := ParseCIDRList([]string{"172.18.0.0/16"})
	mwFn := TrustedRealIP(cidrs, ParseTrustHeaders([]string{"X-Real-IP"}))

	r := trustedPeerReq(map[string]string{"X-Real-IP": "198.51.100.4"})
	if got := finalRemoteAddr(t, mwFn, r); got != "198.51.100.4" {
		t.Fatalf("RemoteAddr = %q, want the explicitly trusted X-Real-IP", got)
	}

	r2 := trustedPeerReq(map[string]string{"True-Client-IP": "198.51.100.4"})
	if got := finalRemoteAddr(t, mwFn, r2); got == "198.51.100.4" {
		t.Fatalf("RemoteAddr = %q, True-Client-IP must stay untrusted (only X-Real-IP was opted in)", got)
	}
}

// TestTrustedRealIP_UntrustedPeerIgnoresEverything: a peer outside the
// trusted CIDRs never gets any header honored, regardless of opt-in.
func TestTrustedRealIP_UntrustedPeerIgnoresEverything(t *testing.T) {
	cidrs := ParseCIDRList([]string{"172.18.0.0/16"})
	mwFn := TrustedRealIP(cidrs, ParseTrustHeaders([]string{"True-Client-IP", "X-Real-IP"}))

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.50:1234" // outside the trusted range
	r.Header.Set("True-Client-IP", "9.9.9.9")
	got := finalRemoteAddr(t, mwFn, r)
	if got != "203.0.113.50:1234" {
		t.Fatalf("RemoteAddr = %q, untrusted peer must keep its own address", got)
	}
}
