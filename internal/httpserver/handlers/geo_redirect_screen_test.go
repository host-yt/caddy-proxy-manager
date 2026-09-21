package handlers

import (
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
)

// SEC-004: geo_block_redirect_url is emitted into the node config, so it must
// answer to the same placeholder policy as every other emitted string. Before
// the fix both writers only checked isHTTPURL, which parses happily.
func TestGeoRedirectScreenMatchesEmission(t *testing.T) {
	unsafe := "https://x.example/{env.APP_SECRET}"
	if isHTTPURL(unsafe) != true {
		t.Fatalf("precondition: isHTTPURL should still accept %q", unsafe)
	}
	if err := caddyapi.ScreenTenantTemplate(unsafe); err == nil {
		t.Error("emitted geo redirect with a node-state placeholder must be refused")
	}
	for _, ok := range []string{
		"",
		"https://blocked.example/sorry",
		"https://blocked.example/?from={http.request.host}",
	} {
		if err := caddyapi.ScreenTenantTemplate(ok); err != nil {
			t.Errorf("legitimate redirect %q refused: %v", ok, err)
		}
	}
}
