package oauth2x

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIsSupported(t *testing.T) {
	for _, ok := range []string{"github", "google"} {
		if !IsSupported(ok) {
			t.Errorf("%q should be supported", ok)
		}
	}
	for _, bad := range []string{"", "oidc", "facebook", "GitHub"} {
		if IsSupported(bad) {
			t.Errorf("%q should NOT be supported", bad)
		}
	}
}

func TestResolvedScopesAlwaysRequestsEmail(t *testing.T) {
	gh := Config{Provider: ProviderGitHub}.resolvedScopes()
	if !contains(gh, "user:email") || !contains(gh, "read:user") {
		t.Errorf("github base scopes missing email: %v", gh)
	}
	g := Config{Provider: ProviderGoogle}.resolvedScopes()
	if !contains(g, "email") || !contains(g, "openid") {
		t.Errorf("google base scopes missing email/openid: %v", g)
	}
	// Extra scopes appended, no duplicates (case-insensitive).
	withExtra := Config{Provider: ProviderGoogle, Scopes: "email https://www.googleapis.com/auth/calendar"}.resolvedScopes()
	if countEqual(withExtra, "email") != 1 {
		t.Errorf("duplicate email scope: %v", withExtra)
	}
	if !contains(withExtra, "https://www.googleapis.com/auth/calendar") {
		t.Errorf("extra scope not appended: %v", withExtra)
	}
}

func TestOAuthConfigGatesAndEndpoints(t *testing.T) {
	// Disabled -> error.
	if _, err := (Config{Provider: ProviderGitHub, Enabled: false}).oauthConfig("https://x/cb"); err == nil {
		t.Error("disabled provider must error")
	}
	// Enabled but missing secret -> error (no public-client fallthrough).
	if _, err := (Config{Provider: ProviderGitHub, Enabled: true, ClientID: "id"}).oauthConfig("https://x/cb"); err == nil {
		t.Error("missing client secret must error")
	}
	// Ready github -> github endpoint.
	oc, err := (Config{Provider: ProviderGitHub, Enabled: true, ClientID: "id", ClientSecret: "s"}).oauthConfig("https://x/cb")
	if err != nil {
		t.Fatalf("github config: %v", err)
	}
	if !strings.Contains(oc.Endpoint.AuthURL, "github.com") {
		t.Errorf("expected github endpoint, got %q", oc.Endpoint.AuthURL)
	}
	// Ready google -> google endpoint.
	oc2, err := (Config{Provider: ProviderGoogle, Enabled: true, ClientID: "id", ClientSecret: "s"}).oauthConfig("https://x/cb")
	if err != nil {
		t.Fatalf("google config: %v", err)
	}
	if !strings.Contains(oc2.Endpoint.AuthURL, "google.com") && !strings.Contains(oc2.Endpoint.AuthURL, "accounts.google") {
		t.Errorf("expected google endpoint, got %q", oc2.Endpoint.AuthURL)
	}
}

func TestGetJSONCapsBodyAndChecksStatus(t *testing.T) {
	// Non-200 surfaces an error without panicking.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()
	if _, err := getJSON(context.Background(), srv.Client(), srv.URL); err == nil {
		t.Error("expected error on HTTP 401")
	}

	// Oversized body is truncated to the cap (no OOM, returns bytes).
	big := strings.Repeat("a", maxUserInfoBytes+1024)
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(big))
	}))
	defer srv2.Close()
	body, err := getJSON(context.Background(), srv2.Client(), srv2.URL)
	if err != nil {
		t.Fatalf("getJSON: %v", err)
	}
	if len(body) > maxUserInfoBytes {
		t.Errorf("body not capped: got %d want <= %d", len(body), maxUserInfoBytes)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func countEqual(s []string, v string) int {
	n := 0
	for _, x := range s {
		if strings.EqualFold(x, v) {
			n++
		}
	}
	return n
}
