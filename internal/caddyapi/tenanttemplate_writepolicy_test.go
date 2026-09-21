package caddyapi

import "testing"

// HPG-SEC-004: write-time and emission-time screening must be ONE policy. A
// value that quarantines the route at push has to be refused at save, and a
// value that saves has to survive emission. The bug this pins: the write path
// used the {env./file./system.} denylist while emission used the
// http.request.* allow-list, so `X-A: {vars.x}` saved clean and then killed
// the host at the next push with no operator feedback.
func TestWriteAndEmissionPolicyAgree(t *testing.T) {
	values := []string{
		"{http.request.host}",
		"https://x.example{http.request.uri}",
		"plain-value",
		"{vars.leaked}",
		"{time.now}",
		"{env.APP_SECRET}",
		"{file./etc/passwd}",
		"{system.hostname}",
		"{$SHELL}",
		"{http.request.header.X-Api-Key}",
		"pre {vars.x} post",
	}
	for _, v := range values {
		writeOK := ScreenTenantTemplate(v) == nil

		for name, r := range map[string]Route{
			"header":         {Headers: map[string]string{"X-A": v}},
			"redirect_url":   {RedirectURL: v},
			"host_header":    {UpstreamHostHeader: v},
			"loc_redirect":   {LocationRules: []LocationRule{{Path: "/a", RedirectURL: v}}},
			"loc_rewrite":    {LocationRules: []LocationRule{{Path: "/a", RewriteURI: v}}},
			"geo_redirect":   {GeoRedirectURL: v},
			"upstream_sni_f": {UpstreamSNI: v},
		} {
			emitOK := TenantTemplateQuarantine(r) == ""
			if writeOK != emitOK {
				t.Errorf("%s %q: write-time accepts=%v but emission accepts=%v", name, v, writeOK, emitOK)
			}
		}
	}
}

// The rate-limit key is the deliberate exception: the host editor offers
// {http.request.header.X-API-Key} as a custom key, so the allow-list would
// break a documented feature. Write and emission still share one function.
func TestScreenTenantRateKey(t *testing.T) {
	for _, ok := range []string{
		"{http.request.remote.host}", "static", "{http.request.header.X-API-Key}",
	} {
		if err := ScreenTenantRateKey(ok); err != nil {
			t.Errorf("rate key %q must stay allowed: %v", ok, err)
		}
		if q := TenantTemplateQuarantine(Route{RateLimitKey: ok}); q != "" {
			t.Errorf("rate key %q accepted at write but quarantined at emission: %s", ok, q)
		}
	}
	for _, bad := range []string{"{env.APP_SECRET}", "{file./etc/passwd}", "{system.hostname}", "{$HOME}"} {
		if err := ScreenTenantRateKey(bad); err == nil {
			t.Errorf("rate key %q must be refused", bad)
		}
	}
}
