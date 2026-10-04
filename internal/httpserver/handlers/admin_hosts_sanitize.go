package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/host-yt/caddy-proxy-manager/internal/caddyapi"
	"github.com/host-yt/caddy-proxy-manager/internal/domain/routes"
)

// nullableInt64 returns a sql.NullInt64 (0 → NULL) so the UPDATE
// statement sets via_wg_peer_id back to NULL when the operator clears
// the dropdown.
func nullableInt64(v int64) sql.NullInt64 {
	if v == 0 {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: v, Valid: true}
}

func nullableString(v string) sql.NullString {
	if v == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: v, Valid: true}
}

func nullableInt(v int) sql.NullInt64 {
	if v == 0 {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(v), Valid: true}
}

func sanitizeLocationRules(form url.Values) ([]locationRuleRow, error) {
	paths := form["loc_path[]"]
	actions := form["loc_action[]"]
	schemes := form["loc_upstream_scheme[]"]
	hosts := form["loc_upstream_host[]"]
	ports := form["loc_upstream_port[]"]
	redirects := form["loc_redirect_url[]"]
	codes := form["loc_redirect_code[]"]
	rewrites := form["loc_rewrite_uri[]"]
	if len(paths) > 50 {
		return nil, fmt.Errorf("max 50 rules")
	}
	out := make([]locationRuleRow, 0, len(paths))
	for i, rawPath := range paths {
		path, err := sanitizeLocationPath(rawPath)
		if err != nil {
			return nil, err
		}
		if path == "" {
			continue
		}
		action := fieldAt(actions, i)
		switch action {
		case "", "proxy":
			action = "proxy"
		case "redirect", "block", "rewrite":
		default:
			return nil, fmt.Errorf("invalid action for %s", path)
		}
		scheme := fieldAt(schemes, i)
		if scheme != "https" {
			scheme = "http"
		}
		rule := locationRuleRow{
			Path:           path,
			Action:         action,
			UpstreamScheme: scheme,
			RedirectCode:   308,
		}
		switch action {
		case "proxy":
			rule.UpstreamHost = strings.TrimSpace(fieldAt(hosts, i))
			rule.UpstreamPort = atoiDefault(fieldAt(ports, i), 0)
			if !isValidUpstreamHost(rule.UpstreamHost) || rule.UpstreamPort < 1 || rule.UpstreamPort > 65535 {
				return nil, fmt.Errorf("%s proxy requires a valid host and port", path)
			}
		case "redirect":
			rule.RedirectURL = strings.TrimSpace(fieldAt(redirects, i))
			if rule.RedirectURL == "" {
				return nil, fmt.Errorf("%s redirect requires a destination", path)
			}
			if !(strings.HasPrefix(rule.RedirectURL, "http://") || strings.HasPrefix(rule.RedirectURL, "https://") || strings.HasPrefix(rule.RedirectURL, "/")) {
				return nil, fmt.Errorf("%s redirect destination must be http(s):// or /relative", path)
			}
			if err := caddyapi.ScreenTenantTemplate(rule.RedirectURL); err != nil {
				return nil, fmt.Errorf("%s redirect destination: %w", path, err)
			}
			rule.RedirectCode = atoiDefault(fieldAt(codes, i), 308)
			switch rule.RedirectCode {
			case 301, 302, 307, 308:
			default:
				return nil, fmt.Errorf("%s redirect code must be 301/302/307/308", path)
			}
		case "rewrite":
			rule.RewriteURI = strings.TrimSpace(fieldAt(rewrites, i))
			if !strings.HasPrefix(rule.RewriteURI, "/") {
				return nil, fmt.Errorf("%s rewrite URI must start with /", path)
			}
			if len(rule.RewriteURI) > 1024 {
				return nil, fmt.Errorf("%s rewrite URI too long", path)
			}
			// Same allow-list emission applies, so a save cannot quarantine later.
			if err := caddyapi.ScreenTenantTemplate(rule.RewriteURI); err != nil {
				return nil, fmt.Errorf("%s rewrite URI: %w", path, err)
			}
		}
		out = append(out, rule)
	}
	return out, nil
}

func sanitizeLocationPath(raw string) (string, error) {
	path := strings.TrimSpace(raw)
	if path == "" {
		return "", nil
	}
	if strings.Contains(path, "://") || strings.ContainsAny(path, "?#") || strings.Contains(path, "..") {
		return "", fmt.Errorf("invalid path %q", raw)
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if len(path) > 255 {
		return "", fmt.Errorf("path too long")
	}
	if strings.Contains(path, "*") {
		if path != "/*" && !strings.HasSuffix(path, "/*") {
			return "", fmt.Errorf("wildcard must be a trailing /* in %q", raw)
		}
		if strings.Count(path, "*") > 1 {
			return "", fmt.Errorf("only one wildcard is supported in %q", raw)
		}
		return path, nil
	}
	if path != "/" {
		path += "/*"
	}
	return path, nil
}

func fieldAt(values []string, i int) string {
	if i < 0 || i >= len(values) {
		return ""
	}
	return strings.TrimSpace(values[i])
}

// sanitizeAliases parses the operator-supplied alias textarea (comma /
// whitespace / semicolon separated), lowercases, dedupes, and validates
// each as a DNS hostname. Rejects entries equal to the primary domain so
// /ask lookups stay unambiguous.
func sanitizeAliases(raw, primary string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", nil
	}
	splitter := func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == ';'
	}
	out := make([]string, 0, 4)
	seen := map[string]bool{}
	for _, p := range strings.FieldsFunc(raw, splitter) {
		d := strings.ToLower(strings.TrimSpace(p))
		if d == "" || d == primary || seen[d] {
			continue
		}
		// Aliases become host matchers too, so they must satisfy the same
		// shape rules as a primary domain and stay modellable for overlap.
		if !routes.ValidDomain(d) || !caddyapi.ValidHostMatcher(d) {
			return "", fmt.Errorf("invalid alias %q", p)
		}
		seen[d] = true
		out = append(out, d)
	}
	return strings.Join(out, ","), nil
}

// splitHostCSV explodes a stored comma/space separated hostname list.
func splitHostCSV(raw string) []string {
	out := []string{}
	for _, p := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == ';'
	}) {
		if v := strings.ToLower(strings.TrimSpace(p)); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// addedHosts returns entries present in next but not in prev. Only additions
// are a hostname claim - dropping an alias releases one.
func addedHosts(prev, next string) []string {
	had := map[string]bool{}
	for _, v := range splitHostCSV(prev) {
		had[v] = true
	}
	added := []string{}
	for _, v := range splitHostCSV(next) {
		if !had[v] {
			added = append(added, v)
		}
	}
	return added
}

// matcherChangedForUpdate reports whether a save claims a hostname/path the
// route did not already serve. Aliases land in the same Caddy host matcher as
// the primary domain, so adding one is a claim and must re-arm ownership proof.
func matcherChangedForUpdate(oldDomain, oldPath, oldAliases, domain, path, aliases string) bool {
	return domain != oldDomain || path != oldPath || len(addedHosts(oldAliases, aliases)) > 0
}

// keepProvenHosts intersects the previously proven set with the new alias list,
// so a removed alias drops its proof and an added one starts unproven.
func keepProvenHosts(proven, next string) string {
	ok := map[string]bool{}
	for _, v := range splitHostCSV(proven) {
		ok[v] = true
	}
	out := []string{}
	for _, v := range splitHostCSV(next) {
		if ok[v] {
			out = append(out, v)
		}
	}
	return strings.Join(out, ",")
}

// sanitizeHeaderList accepts an operator-supplied comma- or whitespace-
// separated header name list (e.g. "Accept-Encoding, Accept-Language")
// and returns a canonical comma-joined form with invalid chars stripped.
// Used by the cache_vary form field - Souin reads this list as the
// Vary-like cache-key contribution.
func sanitizeHeaderList(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	// Split on both commas and whitespace so admins can paste either form.
	splitter := func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}
	out := make([]string, 0, 4)
	seen := map[string]bool{}
	for _, p := range strings.FieldsFunc(raw, splitter) {
		// Header names: tokens per RFC 7230 - letters, digits, and
		// !#$%&'*+-.^_`|~ . Reject anything else conservatively so this
		// can't smuggle weird characters into Caddy config.
		ok := true
		for _, c := range p {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
				c >= '0' && c <= '9' || c == '-' || c == '_') {
				ok = false
				break
			}
		}
		if !ok || len(p) > 64 {
			continue
		}
		k := strings.ToLower(p)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, p)
	}
	if len(out) == 0 {
		return ""
	}
	joined := strings.Join(out, ",")
	if len(joined) > 255 {
		joined = joined[:255]
	}
	return joined
}

// sanitizePathList accepts newline- / comma- / space-separated paths
// (e.g. "/dashboard/*", "/api/admin") and returns a comma-joined,
// deduped form. Each token must start with "/" and stay under 200
// chars. Used by per-route SSO scope.
func sanitizePathList(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	splitter := func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}
	seen := map[string]bool{}
	out := make([]string, 0, 8)
	for _, p := range strings.FieldsFunc(raw, splitter) {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		if len(p) > 200 || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return strings.Join(out, ",")
}

// sanitizeHostList accepts comma/space/newline-separated host names.
// Lower-cased + deduped; per-token <=253 chars. Used by per-route SSO
// scope so the operator can gate just one alias.
func sanitizeHostList(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	splitter := func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == ';'
	}
	seen := map[string]bool{}
	out := make([]string, 0, 4)
	for _, h := range strings.FieldsFunc(raw, splitter) {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" || len(h) > 253 || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return strings.Join(out, ",")
}

// sanitizeCIDRList parses an operator-supplied CIDR list (newline-,
// comma-, or space-separated) and returns a normalised comma-joined
// form. Each token must be a valid IP or CIDR; otherwise the whole
// list is rejected (caller flashes the error). Caps the result at
// 4 KiB to keep TEXT columns honest.
func sanitizeCIDRList(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", nil
	}
	splitter := func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}
	out := make([]string, 0, 8)
	seen := map[string]bool{}
	for _, p := range strings.FieldsFunc(raw, splitter) {
		// Accept either a bare IP or a CIDR; expand bare IPs to /32 (v4)
		// or /128 (v6) so Caddy's remote_ip matcher gets consistent input.
		token := p
		if !strings.Contains(token, "/") {
			if ip := net.ParseIP(token); ip != nil {
				if ip.To4() != nil {
					token += "/32"
				} else {
					token += "/128"
				}
			}
		}
		if _, _, err := net.ParseCIDR(token); err != nil {
			return "", fmt.Errorf("invalid CIDR: %q", p)
		}
		if seen[token] {
			continue
		}
		seen[token] = true
		out = append(out, token)
	}
	joined := strings.Join(out, ",")
	if len(joined) > 4096 {
		return "", fmt.Errorf("list too long (max 4 KiB)")
	}
	return joined, nil
}

// isValidUpstreamHost accepts an IP literal or a DNS hostname.
// atoiDefault parses s as int, returning def on any error.
func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}

// int64Default parses s as int64, defaulting to 0 on error (form IDs: 0 = unset).
func int64Default(s string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n
}

// firstErr returns the first non-nil error.
func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

// recoverBg logs and swallows a panic in a fire-and-forget handler goroutine.
// These have no Recoverer middleware (that only wraps the request goroutine),
// so one panic in a detached push would otherwise crash the whole process.
func recoverBg(logger *slog.Logger, name string) {
	if r := recover(); r != nil && logger != nil {
		logger.Error("background goroutine panicked", "task", name, "panic", r, "stack", string(debug.Stack()))
	}
}

// isTabSlug accepts only a short [a-z0-9-] tab id, so an attacker-supplied
// active_tab can never inject CRLF/markup into the redirect Location header.
func isTabSlug(s string) bool {
	if s == "" || len(s) > 24 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

// clampInt bounds n to [lo, hi].
func clampInt(n, lo, hi int) int {
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}

// parseHeaderLines turns textarea content ("Name: value\nOther: x")
// into a compact JSON object the routes.custom_headers column stores.
// Empty lines and lines without ":" are skipped silently. Returns "" if
// no valid lines so we keep a NULL column instead of an empty {}.
// Values are screened with the SAME allow-list the emission path applies, so a
// header that would quarantine the host at push cannot be saved silently.
func parseHeaderLines(raw string) (string, error) {
	out := parseHeaderMap(raw)
	if len(out) == 0 {
		return "", nil
	}
	for k, v := range out {
		if err := caddyapi.ScreenTenantTemplate(k + ": " + v); err != nil {
			return "", fmt.Errorf("custom header %q: %w", k, err)
		}
	}
	b, _ := json.Marshal(out)
	return string(b), nil
}

// parseHeaderMap splits the textarea into name/value pairs.
func parseHeaderMap(raw string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		i := strings.IndexByte(line, ':')
		if i <= 0 || i == len(line)-1 {
			continue
		}
		name := strings.TrimSpace(line[:i])
		value := strings.TrimSpace(line[i+1:])
		if name == "" || value == "" {
			continue
		}
		out[name] = value
	}
	return out
}
