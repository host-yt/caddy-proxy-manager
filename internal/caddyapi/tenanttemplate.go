package caddyapi

import (
	"fmt"
	"strings"
)

// tenantPlaceholderNS is the ALLOW-LIST: the only Caddy replacer namespace a
// route owner may reach. Everything under it is derived from the request the
// node is already serving for that tenant, so it discloses nothing new. Every
// other namespace is node state or another tenant's - {file.*} reads the
// filesystem, {env.*}/{$...} the process environment, {system.*} the host,
// {vars.*} whatever an earlier handler stashed.
const tenantPlaceholderNS = "http.request."

// allowedTenantPlaceholder reports whether Caddy may expand this key for a
// tenant-supplied string.
func allowedTenantPlaceholder(key string) bool {
	return strings.HasPrefix(key, tenantPlaceholderNS) && len(key) > len(tenantPlaceholderNS)
}

// phSpan is one `{...}` run Caddy's replacer would treat as a placeholder.
type phSpan struct {
	start int    // index of '{'
	key   string // name before the ':' default separator
}

// scanPlaceholderSpans finds what Caddy's replacer would expand. It mirrors the
// replacer's own scan: `\{` is an escaped literal, an unterminated `{` is
// literal text, and an inner `{` restarts the run.
func scanPlaceholderSpans(s string) []phSpan {
	var out []phSpan
	for i := 0; i < len(s); i++ {
		if s[i] != '{' {
			continue
		}
		if i > 0 && s[i-1] == '\\' {
			continue
		}
		rel := strings.IndexAny(s[i+1:], "{}")
		if rel < 0 {
			break // no closing brace: the replacer leaves the rest alone
		}
		if s[i+1+rel] == '{' {
			continue // the inner brace opens the real placeholder
		}
		key := s[i+1 : i+1+rel]
		if c := strings.IndexByte(key, ':'); c >= 0 {
			key = key[:c]
		}
		out = append(out, phSpan{start: i, key: strings.TrimSpace(key)})
		i += rel + 1
	}
	return out
}

// ScreenTenantTemplate rejects the first placeholder in a tenant-supplied
// string that Caddy would expand and the allow-list does not permit. Use it for
// values where a stray `{` is never meaningful (URLs, URIs, header values); a
// free-text or HTML value must go through NeutralizeTenantTemplate instead,
// because CSS braces are legitimate there.
func ScreenTenantTemplate(s string) error {
	for _, sp := range scanPlaceholderSpans(s) {
		if !allowedTenantPlaceholder(sp.key) {
			return fmt.Errorf("placeholder %q is not permitted", "{"+sp.key+"}")
		}
	}
	return nil
}

// NeutralizeTenantTemplate escapes every placeholder the allow-list does not
// permit so Caddy's replacer emits it as literal text. Used for bodies that
// legitimately carry braces (CSS in a custom error page) where rejecting the
// whole document would be wrong.
func NeutralizeTenantTemplate(s string) string {
	spans := scanPlaceholderSpans(s)
	if len(spans) == 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + len(spans))
	prev, escaped := 0, false
	for _, sp := range spans {
		if allowedTenantPlaceholder(sp.key) {
			continue
		}
		b.WriteString(s[prev:sp.start])
		b.WriteByte('\\')
		prev, escaped = sp.start, true
	}
	if !escaped {
		return s
	}
	b.WriteString(s[prev:])
	return b.String()
}

// TenantTemplateQuarantine returns why a route's stored strings cannot be
// emitted, or "" when they are safe. Every field listed here ends up in a
// static_response header/body or a rewrite target, all of which Caddy expands
// through the replacer - so one unsafe value quarantines the whole route
// rather than publishing a placeholder that reads the node's disk or env.
func TenantTemplateQuarantine(r Route) string {
	check := func(what, v string) string {
		if err := ScreenTenantTemplate(v); err != nil {
			return what + ": " + err.Error()
		}
		return ""
	}
	for _, c := range []struct{ what, v string }{
		{"redirect_url", r.RedirectURL},
		{"geo_redirect_url", r.GeoRedirectURL},
		{"upstream_host_header", r.UpstreamHostHeader},
		{"upstream_sni", r.UpstreamSNI},
		{"upstream_path", r.UpstreamPathPrefix},
	} {
		if reason := check(c.what, c.v); reason != "" {
			return reason
		}
	}
	for k, v := range r.Headers {
		if reason := check("custom header "+k, k+": "+v); reason != "" {
			return reason
		}
	}
	for _, rule := range r.LocationRules {
		for _, c := range []struct{ what, v string }{
			{"location " + rule.Path + " redirect_url", rule.RedirectURL},
			{"location " + rule.Path + " rewrite_uri", rule.RewriteURI},
		} {
			if reason := check(c.what, c.v); reason != "" {
				return reason
			}
		}
	}
	if err := ScreenTenantRateKey(r.RateLimitKey); err != nil {
		return "rate_key: " + err.Error()
	}
	return ""
}

// ScreenTenantRateKey is the rate-limit key policy for BOTH write and emission.
// The key is a placeholder by design (the host editor offers
// {http.request.header.X-API-Key}), so the allow-list would break a documented
// feature; only the node-state providers are refused.
func ScreenTenantRateKey(s string) error { return ScreenReplacerValue(s) }
