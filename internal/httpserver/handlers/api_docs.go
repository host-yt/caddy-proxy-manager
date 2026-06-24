package handlers

import (
	"context"
	"database/sql"
	_ "embed"
	"net/http"
	"time"

	mw "github.com/hostyt/proxy-gateway/internal/httpserver/middleware"
)

//go:embed openapi.json
var openapiSpec []byte

// APIDocsHandler gates /api-docs by the settings.apidocs.public_enabled
// flag. When the flag is '0' anonymous visitors get 404; admins (any
// role) still see it via the active session check. Default '1' for
// backwards-compat with deploys created before mig 28.
type APIDocsHandler struct {
	DB func() *sql.DB
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

// Spec serves the raw OpenAPI 3.1 JSON spec.
func (h *APIDocsHandler) Spec(w http.ResponseWriter, r *http.Request) {
	if !h.allow(r) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(openapiSpec)
}

// Package-level fallbacks kept for legacy callers/tests that bind
// before the handler struct is wired. Always render (public).
func APIDocsPage(w http.ResponseWriter, r *http.Request) {
	(&APIDocsHandler{}).Page(w, r)
}
func APIDocsSpec(w http.ResponseWriter, r *http.Request) {
	(&APIDocsHandler{}).Spec(w, r)
}
