package handlers

import (
	"bytes"
	"html"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/view"
)

// Public status page gets the nonce-only CSP: it must carry no inline script.
func TestStatusPageHasNoInlineScript(t *testing.T) {
	st, err := view.LoadStatusTemplates()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	d := statusPageData{ClientName: "c", GeneratedAt: time.Now(), ShowTraffic: true, TrafficValues: "[1,2,3]"}
	if err := st.Render(&buf, "status_page", d); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, tag := range regexp.MustCompile(`<script[^>]*>`).FindAllString(out, -1) {
		if !strings.Contains(tag, "src=") {
			t.Errorf("inline script blocked by CSP: %s", tag)
		}
	}
	m := regexp.MustCompile(`data-values="([^"]*)"`).FindStringSubmatch(out)
	if m == nil || html.UnescapeString(m[1]) != "[1,2,3]" {
		t.Errorf("sparkline data-values = %v", m)
	}
}
