package accesslog

import (
	"strings"
	"testing"
)

func FuzzRedactURI(f *testing.F) {
	for _, s := range []string{"/api/wg/join?token=abc", "/api/wg/", "/api/wg/x?", "/x?a=b", "", "?", "/api/wg", "/api/wg/\x00?t"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, uri string) {
		out := RedactURI(uri)
		if strings.HasPrefix(uri, "/api/wg/") && strings.Contains(out, "?") {
			t.Fatalf("query kept: %q -> %q", uri, out)
		}
		if RedactURI(out) != out {
			t.Fatalf("not idempotent: %q", uri)
		}
	})
}
