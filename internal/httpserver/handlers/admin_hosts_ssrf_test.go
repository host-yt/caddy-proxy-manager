package handlers

import (
	"net/url"
	"strings"
	"testing"
)

// HPG-SEC-004: values in these fields are expanded by Caddy's replacer on the
// node, so an env/file/system placeholder is node-secret exfiltration.
func TestTenantStringsRejectUnsafePlaceholders(t *testing.T) {
	if _, err := parseHeaderLines("X-Leak: {env.APP_SECRET}"); err == nil {
		t.Error("custom header with {env.} must be rejected")
	}
	if _, err := parseHeaderLines("X-Leak: {file./etc/passwd}"); err == nil {
		t.Error("custom header with {file.} must be rejected")
	}
	got, err := parseHeaderLines("X-Forwarded-Host: {http.request.host}")
	if err != nil || !strings.Contains(got, "http.request.host") {
		t.Errorf("request placeholders must stay allowed: %q %v", got, err)
	}

	form := url.Values{
		"loc_path[]":        {"/a"},
		"loc_action[]":      {"rewrite"},
		"loc_rewrite_uri[]": {"/x?leak={env.APP_SECRET}"},
	}
	if _, err := sanitizeLocationRules(form); err == nil {
		t.Error("rewrite URI with {env.} must be rejected")
	}
	form = url.Values{
		"loc_path[]":         {"/a"},
		"loc_action[]":       {"redirect"},
		"loc_redirect_url[]": {"https://x.example/{env.APP_SECRET}"},
	}
	if _, err := sanitizeLocationRules(form); err == nil {
		t.Error("redirect destination with {env.} must be rejected")
	}
}
