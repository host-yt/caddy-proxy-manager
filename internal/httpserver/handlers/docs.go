package handlers

import (
	"embed"
	"html"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

//go:embed customer_docs/*.md
var customerDocsFS embed.FS

// PublicDoc serves a customer-facing markdown doc from internal embedded
// FS. Rendering is intentionally minimal: monospace block with HTML escape
// + a few markdown-ish replacements. We avoid pulling in a full markdown
// parser to keep the binary small; the docs are short.
func PublicDoc() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slug := chi.URLParam(r, "slug")
		if slug == "" || strings.ContainsAny(slug, "./\\") {
			http.NotFound(w, r)
			return
		}
		body, err := customerDocsFS.ReadFile("customer_docs/" + slug + ".md")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html><html lang="en"><head><meta charset="utf-8">` +
			`<title>` + html.EscapeString(slug) + ` — Hostyt Proxy</title>` +
			`<style>body{max-width:760px;margin:2rem auto;font-family:system-ui;line-height:1.6;color:#222;padding:0 1rem}pre,code{background:#f3f4f6;padding:.15rem .35rem;border-radius:3px}pre{padding:1rem;overflow:auto}h1,h2,h3{line-height:1.25}</style>` +
			`</head><body><pre style="white-space:pre-wrap;font-family:inherit;background:none;padding:0">`))
		_, _ = w.Write([]byte(html.EscapeString(string(body))))
		_, _ = w.Write([]byte(`</pre></body></html>`))
	}
}
