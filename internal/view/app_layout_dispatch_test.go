package view

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// TestAppLayoutDispatchesEveryPage: each app page file (no _ prefix) defines a page
// template the layout must dispatch, otherwise the page renders blank with HTTP 200.
func TestAppLayoutDispatchesEveryPage(t *testing.T) {
	layout, err := fs.ReadFile(appFS, "app/_layout.html.tmpl")
	if err != nil {
		t.Fatalf("read layout: %v", err)
	}
	entries, err := fs.ReadDir(appFS, "app")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	defineRe := regexp.MustCompile(`{{\s*define\s+"([a-z0-9_]+)"`)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "_") {
			continue
		}
		body, err := fs.ReadFile(appFS, "app/"+e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		m := defineRe.FindStringSubmatch(string(body))
		if m == nil {
			continue
		}
		if !strings.Contains(string(layout), `{{template "`+m[1]+`" .Data}}`) {
			t.Errorf("app page template %q (%s) is never dispatched in _layout.html.tmpl", m[1], e.Name())
		}
	}
}
