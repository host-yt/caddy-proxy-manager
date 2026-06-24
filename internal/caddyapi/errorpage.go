package caddyapi

import (
	"strconv"
	"strings"
)

// renderErrorPage returns a self-contained HTML doc for error /
// maintenance responses. Single source of truth so 404 / 503 / 502 etc.
// look like siblings, not strangers.
//
// status: HTTP code shown big at the top.
// title:  short headline (e.g. "Service under maintenance").
// msg:    operator-supplied detail (escaped before splicing).
func renderErrorPage(status int, title, msg string, b ErrorBranding) string {
	bg := b.BgColor
	if bg == "" {
		bg = "#1f2937" // slate-800 deep gray
	}
	brand := b.Brand
	if brand == "" {
		brand = "Hostyt"
	}
	logoHTML := ""
	switch {
	case b.LogoURL != "" && b.LogoLink != "":
		logoHTML = `<a href="` + htmlEscape(b.LogoLink) + `" class="logo"><img src="` +
			htmlEscape(b.LogoURL) + `" alt="` + htmlEscape(brand) + `"></a>`
	case b.LogoURL != "":
		logoHTML = `<img class="logo" src="` + htmlEscape(b.LogoURL) + `" alt="` + htmlEscape(brand) + `">`
	default:
		if b.LogoLink != "" {
			logoHTML = `<a href="` + htmlEscape(b.LogoLink) + `" class="brand">` + htmlEscape(brand) + `</a>`
		} else {
			logoHTML = `<span class="brand">` + htmlEscape(brand) + `</span>`
		}
	}
	statusStr := strconv.Itoa(status)
	return `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
		`<meta name="viewport" content="width=device-width,initial-scale=1">` +
		`<title>` + statusStr + ` · ` + htmlEscape(title) + `</title>` +
		`<style>` +
		`*{box-sizing:border-box}` +
		`html,body{margin:0;padding:0;min-height:100%;}` +
		`body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,system-ui,sans-serif;` +
		`background:` + bg + `;color:#e2e8f0;` +
		`display:flex;align-items:center;justify-content:center;padding:2rem;line-height:1.5;}` +
		`.wrap{max-width:32rem;width:100%;text-align:center;}` +
		`.logo,.brand{display:inline-block;margin:0 0 2rem;text-decoration:none;color:#f1f5f9;font-weight:600;font-size:1.25rem;letter-spacing:.02em;}` +
		`.logo img,img.logo{max-height:48px;max-width:240px;display:block;margin:0 auto;}` +
		`.status{font-size:4.5rem;font-weight:700;color:#f8fafc;margin:0 0 .5rem;letter-spacing:-.04em;line-height:1;}` +
		`h1{font-size:1.5rem;font-weight:600;color:#f1f5f9;margin:0 0 1rem;}` +
		`p{color:#94a3b8;margin:0;font-size:1rem;}` +
		`</style></head><body><div class="wrap">` +
		logoHTML +
		`<div class="status">` + statusStr + `</div>` +
		`<h1>` + htmlEscape(title) + `</h1>` +
		`<p>` + htmlEscape(msg) + `</p>` +
		`</div></body></html>`
}

// maintenanceBody is the short-circuit branded 503 served by routes in
// Kind=maintenance. Kept as a thin wrapper so the call site stays
// readable.
func maintenanceBody(msg string, b ErrorBranding) string {
	return renderErrorPage(503, "Service under maintenance", msg, b)
}

// routeErrorBranding returns the per-route override branding when set, else the
// node-wide branding propagated onto the route.
func routeErrorBranding(r Route) ErrorBranding {
	if r.CustomErrorOverride {
		return r.CustomErrorBranding
	}
	return r.ErrorBranding
}

// routeMaintenanceBody renders a route's maintenance 503 body: a verbatim
// admin-supplied HTML page when provided, else the branded shell. The HTML is
// admin-scoped and capped at save time, so it is emitted as-is (not templated).
func routeMaintenanceBody(r Route, msg string) string {
	if r.CustomErrorOverride && strings.TrimSpace(r.CustomErrorHTML) != "" {
		return r.CustomErrorHTML
	}
	return maintenanceBody(msg, routeErrorBranding(r))
}

// errorPageSpec drives buildErrorRoutes: one entry per HTTP status we
// want to brand. The default catch-all (status=0) handles everything we
// didn't explicitly list so even oddballs (418, 451) get the branded
// shell instead of Caddy's plaintext default.
type errorPageSpec struct {
	status int
	title  string
	msg    string
}

var brandedErrors = []errorPageSpec{
	{400, "Bad request", "The request was malformed."},
	{401, "Authentication required", "Please sign in to access this resource."},
	{403, "Access denied", "You don't have permission to view this page."},
	{404, "Page not found", "The page you're looking for doesn't exist or has moved."},
	{405, "Method not allowed", "This endpoint does not accept the request method you used."},
	{408, "Request timeout", "The server gave up waiting for the request to complete."},
	{429, "Too many requests", "You've hit the rate limit. Please slow down and try again shortly."},
	{500, "Server error", "Something went wrong on our side. Please try again in a moment."},
	{502, "Bad gateway", "The upstream service responded with an error."},
	{503, "Service unavailable", "The service is temporarily unavailable. Please try again shortly."},
	{504, "Gateway timeout", "The upstream service took too long to respond."},
}

// buildErrorRoutes emits one Caddy handle_errors route per branded
// status + a catch-all so every error response leaves Caddy as the
// same-looking HTML shell.
func buildErrorRoutes(b ErrorBranding) []any {
	routes := make([]any, 0, len(brandedErrors)+1)
	for _, e := range brandedErrors {
		body := renderErrorPage(e.status, e.title, e.msg, b)
		routes = append(routes, map[string]any{
			"match": []any{map[string]any{
				"expression": "{http.error.status_code} == " + strconv.Itoa(e.status),
			}},
			"handle": []any{map[string]any{
				"handler":     "static_response",
				"status_code": e.status,
				"headers": map[string]any{
					"Content-Type":  []string{"text/html; charset=utf-8"},
					"Cache-Control": []string{"no-store"},
				},
				"body": body,
			}},
			"terminal": true,
		})
	}
	// Catch-all for any status we didn't list. {http.error.status_code}
	// lets the response keep the original code; body is generic.
	routes = append(routes, map[string]any{
		"handle": []any{map[string]any{
			"handler":     "static_response",
			"status_code": "{http.error.status_code}",
			"headers": map[string]any{
				"Content-Type":  []string{"text/html; charset=utf-8"},
				"Cache-Control": []string{"no-store"},
			},
			"body": renderErrorPage(0, "Something went wrong", "An unexpected error occurred.", b),
		}},
		"terminal": true,
	})
	return routes
}
