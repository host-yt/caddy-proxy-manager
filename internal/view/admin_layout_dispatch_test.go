package view

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// TestAdminLayoutDispatchesEveryPage guards the failure mode that shipped a
// blank Manual Certificates page: a handler calls h.render(w, "manual_certs",
// ...) but _layout.html.tmpl has no `{{if eq .Page "manual_certs"}}` line, so
// the content template is never executed and the page renders as bare chrome
// with HTTP 200 and no error. Parse-only tests can't see this.
//
// Heuristic: a "page" template is a file whose basename (sans _ prefix and
// .html.tmpl) is also a {{define}} in that file. Every such page must appear
// in the layout's .Page dispatch. Partials (leading _) and helper sub-defines
// are ignored because their name never equals the filename.
func TestAdminLayoutDispatchesEveryPage(t *testing.T) {
	layout, err := fs.ReadFile(adminFS, "admin/_layout.html.tmpl")
	if err != nil {
		t.Fatalf("read layout: %v", err)
	}
	dispatched := map[string]bool{}
	for _, m := range regexp.MustCompile(`eq \.Page "([a-z0-9_]+)"`).FindAllStringSubmatch(string(layout), -1) {
		dispatched[m[1]] = true
	}

	// Pages that are deliberately not rendered through the admin layout.
	skip := map[string]bool{"_layout": true, "_pagination": true}

	entries, err := fs.ReadDir(adminFS, "admin")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	defineRe := regexp.MustCompile(`{{\s*define\s+"([a-z0-9_]+)"`)
	for _, e := range entries {
		name := e.Name()
		base := strings.TrimSuffix(name, ".html.tmpl")
		if skip[base] || strings.HasPrefix(base, "_") {
			continue
		}
		body, err := fs.ReadFile(adminFS, "admin/"+name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		// Only treat the file as a page when it defines a template named after
		// itself - that is the page block the layout is expected to dispatch.
		definesSelf := false
		for _, m := range defineRe.FindAllStringSubmatch(string(body), -1) {
			if m[1] == base {
				definesSelf = true
				break
			}
		}
		if definesSelf && !dispatched[base] {
			t.Errorf("admin page template %q is never dispatched in _layout.html.tmpl "+
				"(add `{{if eq .Page %q}}{{template %q .Data}}{{end}}`) - the page would render blank", base, base, base)
		}
	}
}
