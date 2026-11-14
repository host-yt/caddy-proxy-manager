package view

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// TestHostLogsLiveTailMatchesColumns guards #133: the live-tail JS builds rows
// by hand, and once it emitted fewer cells than the table has headers, so
// every streamed row slid under the wrong columns. The number of cells
// prependRow appends must equal the <th> count of #log-table.
func TestHostLogsLiveTailMatchesColumns(t *testing.T) {
	b, err := fs.ReadFile(adminFS, "admin/host_logs.html.tmpl")
	if err != nil {
		t.Fatalf("read template: %v", err)
	}
	src := string(b)

	start := strings.Index(src, `id="log-table"`)
	if start < 0 {
		t.Fatal("log-table not found")
	}
	thead := src[start:]
	end := strings.Index(thead, "</thead>")
	if end < 0 {
		t.Fatal("log-table thead not closed")
	}
	headers := len(regexp.MustCompile(`<th[\s>]`).FindAllString(thead[:end], -1))

	fn := strings.Index(src, "function prependRow(")
	if fn < 0 {
		t.Fatal("prependRow not found")
	}
	body := src[fn:]
	if stop := strings.Index(body, "tbody.insertBefore("); stop > 0 {
		body = body[:stop]
	}
	cells := strings.Count(body, "tr.appendChild(")

	if headers == 0 || cells != headers {
		t.Fatalf("live tail appends %d cells, table has %d headers", cells, headers)
	}
}
