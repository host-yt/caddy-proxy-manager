package routes

import (
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
)

// The SSO gate is dialed by the node like any backend. A route whose gate
// points at control-plane infrastructure is dropped whole - emitting it
// without the gate would publish the app unauthenticated.
func TestScreenHTTPSetScreensSSOProvider(t *testing.T) {
	infra := screenTestInfra(t)
	built := []caddyapi.Route{
		{ID: "1", UpstreamIP: "10.0.0.5", UpstreamPort: 8080, SSOProviderURL: "http://10.0.0.9:9000"},
		{ID: "2", UpstreamIP: "10.0.0.5", UpstreamPort: 8080, SSOProviderURL: "http://127.0.0.1:2019"},
		{ID: "3", UpstreamIP: "10.0.0.5", UpstreamPort: 8080, SSOProviderURL: "https://10.66.0.4/"},
		{ID: "4", UpstreamIP: "10.0.0.5", UpstreamPort: 8080, SSOProviderURL: "https://"},
		{ID: "5", UpstreamIP: "10.0.0.5", UpstreamPort: 8080, SSOProviderURL: "https://auth.tenant.example"},
	}
	pin := func(host string, _ int) (string, error) {
		if host == "auth.tenant.example" {
			return "198.51.100.30", nil
		}
		return host, nil
	}
	out, ids, drops := screenHTTPSet(infra, built, []int64{1, 2, 3, 4, 5}, pin)
	if len(out) != 2 || ids[0] != 1 || ids[1] != 5 {
		t.Fatalf("want routes 1 and 5 kept, got %v", ids)
	}
	if len(drops) != 3 {
		t.Fatalf("want 3 drops, got %d", len(drops))
	}
	for _, d := range drops {
		if d.part != "sso provider" {
			t.Errorf("drop part = %q", d.part)
		}
	}
	// The gate keeps its name: the IdP needs it for Host and TLS.
	if out[1].SSOProviderURL != "https://auth.tenant.example" {
		t.Errorf("sso provider URL rewritten: %q", out[1].SSOProviderURL)
	}
}
