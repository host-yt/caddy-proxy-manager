package handlers

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/installstate"
	mw "github.com/host-yt/caddy-proxy-manager/internal/httpserver/middleware"
)

//go:embed openapi.json
var openapiSpec []byte

// APIDocsHandler gates /api-docs by the settings.apidocs.public_enabled
// flag. When the flag is '0' anonymous visitors get 404; admins (any
// role) still see it via the active session check. Default '1' for
// backwards-compat with deploys created before mig 28.
type APIDocsHandler struct {
	DB    func() *sql.DB
	State *installstate.Manager // for the real server URL (operator AppURL)
}

func (h *APIDocsHandler) public(ctx context.Context) bool {
	db := h.DB()
	if db == nil {
		return true
	}
	qctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	var v string
	_ = db.QueryRowContext(qctx,
		"SELECT value FROM settings WHERE `key` = 'apidocs.public_enabled' LIMIT 1").Scan(&v)
	return v != "0"
}

func (h *APIDocsHandler) allow(r *http.Request) bool {
	if h.public(r.Context()) {
		return true
	}
	if sess := mw.SessionFromContext(r.Context()); sess != nil && sess.Role != "" {
		return true
	}
	return false
}

// Page renders the Scalar API Reference UI (CDN-hosted, zero deps).
func (h *APIDocsHandler) Page(w http.ResponseWriter, r *http.Request) {
	if !h.allow(r) {
		http.NotFound(w, r)
		return
	}
	nonce := mw.CSPNonce(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>API Reference — Hostyt Proxy Gateway</title>
</head>
<body>
<script id="api-reference" data-url="/api-docs/openapi.json" nonce="` + nonce + `"></script>
<script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference" nonce="` + nonce + `"></script>
</body>
</html>`))
}

// Spec serves the OpenAPI 3.1 JSON spec, rewritten per request: the
// server URL points at this instance and paths are filtered to what the
// viewer's role can actually call (docs visibility only - the endpoints
// still enforce their own auth).
func (h *APIDocsHandler) Spec(w http.ResponseWriter, r *http.Request) {
	if !h.allow(r) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, max-age=60")

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(openapiSpec, &doc); err != nil {
		_, _ = w.Write(openapiSpec) // fall back to the raw spec
		return
	}
	// Server URL = operator AppURL, else the browsed host.
	base := publicBaseURL(r, appURLFromInstallState(h.State))
	if srv, err := json.Marshal([]map[string]string{{"url": base, "description": "This instance"}}); err == nil {
		doc["servers"] = srv
	}
	// Drop paths the viewer can't reach.
	aud := h.audienceSet(r)
	var paths map[string]json.RawMessage
	if err := json.Unmarshal(doc["paths"], &paths); err == nil {
		for p := range paths {
			if !aud[audienceOf(p)] {
				delete(paths, p)
			}
		}
		if filtered, err := json.Marshal(paths); err == nil {
			doc["paths"] = filtered
		}
	}
	if out, err := json.Marshal(doc); err == nil {
		_, _ = w.Write(out)
		return
	}
	_, _ = w.Write(openapiSpec)
}

// audienceSet returns the doc audiences the requester may see. Public is
// always included; a session widens it by role.
func (h *APIDocsHandler) audienceSet(r *http.Request) map[string]bool {
	set := map[string]bool{"public": true}
	sess := mw.SessionFromContext(r.Context())
	if sess == nil {
		return set
	}
	switch sess.Role {
	case "client":
		set["key"] = true
	case "admin", "super_admin":
		set["key"] = true
		set["admin"] = true
		// Platform admin (not a reseller-scoped admin) sees everything.
		if sess.ResellerID == 0 {
			set["platform"] = true
			set["node"] = true
		}
	}
	return set
}

// audienceOf classifies a path by who may call it, mirroring the route
// guards in server.go. Keep in sync when API routes change.
func audienceOf(p string) string {
	switch {
	case p == "/api/v1/health", strings.HasPrefix(p, "/api/wg/"):
		return "public"
	case p == "/api/v1/nodes/join", strings.HasPrefix(p, "/api/node/"):
		return "node"
	case strings.HasPrefix(p, "/api/v1/resellers"),
		strings.HasPrefix(p, "/api/v1/reseller-plans"),
		strings.HasPrefix(p, "/api/v1/provisioning"):
		return "platform"
	case strings.HasPrefix(p, "/api/v1/services"), strings.HasPrefix(p, "/api/v1/routes"):
		return "key"
	default:
		// nodes, node-pools, plans, clients and anything new: admin-scoped.
		return "admin"
	}
}

// Package-level fallbacks kept for legacy callers/tests that bind
// before the handler struct is wired. Always render (public).
func APIDocsPage(w http.ResponseWriter, r *http.Request) {
	(&APIDocsHandler{}).Page(w, r)
}
func APIDocsSpec(w http.ResponseWriter, r *http.Request) {
	(&APIDocsHandler{}).Spec(w, r)
}
