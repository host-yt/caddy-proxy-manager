package handlers

import (
	"html/template"
	"io/fs"
	"sync"
)

var (
	worldSVGOnce  sync.Once
	worldSVGCache template.HTML
	// WorldSVGFS is wired at startup from the embedded proxygateway.StaticFS.
	// When nil, loadWorldSVG returns empty and the template shows a placeholder.
	WorldSVGFS fs.FS
)

// loadWorldSVG returns the world SVG for inline embedding into HTML.
// CSP sets object-src 'none', so <object>/<embed> are blocked; the SVG must
// be inlined. Loaded once from the embedded static FS.
func loadWorldSVG() template.HTML {
	worldSVGOnce.Do(func() {
		if WorldSVGFS == nil {
			return
		}
		b, err := fs.ReadFile(WorldSVGFS, "img/world.svg")
		if err != nil {
			return
		}
		worldSVGCache = template.HTML(b) //nolint:gosec // self-hosted asset, not user input
	})
	return worldSVGCache
}
