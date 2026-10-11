package caddyapi

import (
	"encoding/json"
	"strings"
	"testing"
)

// A missing GeoIP module/DB must not turn a country policy into public access,
// and the fallback must stay stock-Caddy loadable (no maxmind matcher).
func TestGeoBlockModuleMissing(t *testing.T) {
	r := Route{GeoMode: "allow", GeoCountries: "PL", GeoAllowCIDRs: "10.0.0.0/8", GeoFailClosed: true}
	m := buildGeoBlock(r)
	if m == nil {
		t.Fatal("fail-closed route served unfiltered")
	}
	b, _ := json.Marshal(m)
	js := string(b)
	if strings.Contains(js, geoMatcherName) {
		t.Fatalf("fallback references the missing module: %s", js)
	}
	if !strings.Contains(js, `"10.0.0.0/8"`) {
		t.Fatalf("allow-list not honoured in fallback: %s", js)
	}

	r.GeoFailClosed = false
	if buildGeoBlock(r) != nil {
		t.Fatal("explicit fail-open still emitted a block")
	}
	if buildGeoBlock(Route{GeoMode: "allow", GeoFailClosed: true}) != nil {
		t.Fatal("empty country list must not block everything")
	}
}
