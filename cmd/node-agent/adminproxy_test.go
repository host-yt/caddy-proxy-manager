package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testProxyKey = "0123456789abcdef0123456789abcdef01"

// TestAdminProxy_RequiresTheKey: the whole point of the proxy is that reaching
// the port is no longer authorization.
func TestAdminProxy_RequiresTheKey(t *testing.T) {
	upstreamHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	h := adminProxyHandler(adminProxyConfig{Key: testProxyKey, AdminURL: upstream.URL}, slog.Default())

	for _, tok := range []string{"", "Bearer ", "Bearer wrong", "Bearer " + testProxyKey[:20]} {
		req := httptest.NewRequest(http.MethodPost, "/load", strings.NewReader("{}"))
		if tok != "" {
			req.Header.Set("Authorization", tok)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Authorization %q: status = %d, want 401", tok, rec.Code)
		}
	}
	if upstreamHit {
		t.Fatal("an unauthenticated request reached Caddy")
	}
}

// TestAdminProxy_ForwardsAllowedRequests covers the happy path end to end:
// method, path, body and status all survive the hop.
func TestAdminProxy_ForwardsAllowedRequests(t *testing.T) {
	var gotMethod, gotPath, gotBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotMethod, gotPath, gotBody = r.Method, r.URL.Path, string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	h := adminProxyHandler(adminProxyConfig{Key: testProxyKey, AdminURL: upstream.URL}, slog.Default())
	req := httptest.NewRequest(http.MethodPost, "/load", strings.NewReader(`{"apps":{}}`))
	req.Header.Set("Authorization", "Bearer "+testProxyKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", rec.Code)
	}
	if gotMethod != http.MethodPost || gotPath != "/load" || gotBody != `{"apps":{}}` {
		t.Errorf("upstream saw %s %s body=%q", gotMethod, gotPath, gotBody)
	}
	if rec.Body.String() != `{"ok":true}` {
		t.Errorf("response body = %q", rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q", ct)
	}
}

// TestAdminProxyAllowed pins the allow-list: a leaked key must not be able to
// stop the node or rewrite its admin configuration.
func TestAdminProxyAllowed(t *testing.T) {
	allowed := []struct{ method, path string }{
		{http.MethodPost, "/load"},
		{http.MethodGet, "/config/apps/http/servers/srv0/routes"},
		{http.MethodPost, "/config/apps/http/servers/srv0/routes"},
		{http.MethodPatch, "/config/apps/cache"},
		{http.MethodPatch, "/id/route_42"},
		{http.MethodDelete, "/id/route_42"},
		{http.MethodPost, "/souin-api/souin/"},
	}
	for _, c := range allowed {
		if !adminProxyAllowed(c.method, c.path) {
			t.Errorf("%s %s refused; the control plane needs it", c.method, c.path)
		}
	}
	refused := []struct{ method, path string }{
		{http.MethodPost, "/stop"},
		{http.MethodPost, "/adapt"},
		{http.MethodPut, "/config/apps"},
		{http.MethodGet, "/pki/ca/local"},
		{http.MethodPost, "/load/../stop"},
		{http.MethodDelete, "/config/../stop"},
		{http.MethodPost, "/"},
		{http.MethodGet, "/reverse_proxy/upstreams"},
	}
	for _, c := range refused {
		if adminProxyAllowed(c.method, c.path) {
			t.Errorf("%s %s allowed; it is outside what the panel does", c.method, c.path)
		}
	}
}

// TestAdminProxy_RefusesOutsideAllowListEvenWithKey pairs the unit above with
// the handler, so the check cannot be bypassed by the request path.
func TestAdminProxy_RefusesOutsideAllowListEvenWithKey(t *testing.T) {
	upstreamHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
	}))
	defer upstream.Close()

	h := adminProxyHandler(adminProxyConfig{Key: testProxyKey, AdminURL: upstream.URL}, slog.Default())
	req := httptest.NewRequest(http.MethodPost, "/stop", nil)
	req.Header.Set("Authorization", "Bearer "+testProxyKey)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if upstreamHit {
		t.Error("/stop reached Caddy")
	}
}

// A misconfiguration must stop the agent, not start a listener that only looks
// authenticated.
func TestAdminProxyConfigValidation(t *testing.T) {
	ok := adminProxyConfig{Listen: "10.66.0.2:2021", Key: testProxyKey, AdminURL: "http://127.0.0.1:2019"}
	if err := ok.validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	bad := map[string]adminProxyConfig{
		"short key":       {Listen: "10.66.0.2:2021", Key: "tooshort", AdminURL: "http://127.0.0.1:2019"},
		"wildcard bind":   {Listen: "0.0.0.0:2021", Key: testProxyKey, AdminURL: "http://127.0.0.1:2019"},
		"v6 wildcard":     {Listen: ":::2021", Key: testProxyKey, AdminURL: "http://127.0.0.1:2019"},
		"port only":       {Listen: ":2021", Key: testProxyKey, AdminURL: "http://127.0.0.1:2019"},
		"not host:port":   {Listen: "10.66.0.2", Key: testProxyKey, AdminURL: "http://127.0.0.1:2019"},
		"bad upstream":    {Listen: "10.66.0.2:2021", Key: testProxyKey, AdminURL: "notaurl"},
		"https upstream":  {Listen: "10.66.0.2:2021", Key: testProxyKey, AdminURL: "https://127.0.0.1:2019"},
		"empty upstream":  {Listen: "10.66.0.2:2021", Key: testProxyKey, AdminURL: ""},
		"missing scheme2": {Listen: "10.66.0.2:2021", Key: testProxyKey, AdminURL: "127.0.0.1:2019"},
	}
	for name, c := range bad {
		if err := c.validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// enabled() gates the whole feature: both halves or nothing.
	if (adminProxyConfig{}).enabled() {
		t.Error("empty config reported as enabled")
	}
	if (adminProxyConfig{Listen: "10.66.0.2:2021"}).enabled() {
		t.Error("listener without a key reported as enabled")
	}
	if !ok.enabled() {
		t.Error("fully configured proxy reported as disabled")
	}
}
