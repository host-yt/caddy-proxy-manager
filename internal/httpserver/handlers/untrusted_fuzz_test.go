package handlers

import (
	"net"
	"path"
	"strings"
	"testing"
)

func FuzzPortalSafeBack(f *testing.F) {
	for _, s := range []string{"/dash", "/a?b=c", "//evil.com", "/\\evil", "https://evil.com", "/%2F/evil.com", "/%5Cevil", "", " /x", "javascript:alert(1)", "/%252F/x", "\t//x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		out := portalSafeBack(raw, "panel.example.com")
		if !strings.HasPrefix(out, "/") || strings.HasPrefix(out, "//") || strings.Contains(out, "\\") {
			t.Fatalf("unsafe redirect %q -> %q", raw, out)
		}
	})
}

func FuzzRBACPathForms(f *testing.F) {
	for _, s := range []string{"/admin", "/a/../b", "/%2e%2e/x", "/a%252f..%252fb", "/x/", "//x", "*", "/a\\b", "/a%00b", "", "/%zz"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, uri string) {
		forms, ok := rbacPathForms(uri)
		if !ok {
			return
		}
		if len(forms) != 2 {
			t.Fatalf("want 2 forms, got %d", len(forms))
		}
		for _, p := range forms {
			if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\\\x00") {
				t.Fatalf("bad form %q from %q", p, uri)
			}
		}
		if path.Clean(forms[1]) != path.Clean(forms[0]) {
			t.Fatalf("forms disagree: %q", forms)
		}
	})
}

func FuzzParseCIDRList(f *testing.F) {
	for _, s := range []string{"10.0.0.0/8", "10.0.0.1/24,fd00::/8", "1.2.3.4/33", "a\nb", ",,", " 10.0.0.0/8 ,\n::/0", "", "1.2.3.4"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		out, err := parseCIDRList(raw)
		if err != nil {
			return
		}
		for _, c := range out {
			if c != strings.TrimSpace(c) || c == "" || strings.ContainsAny(c, ",\n") {
				t.Fatalf("bad entry %q", c)
			}
			if _, _, e := net.ParseCIDR(c); e != nil && !strings.Contains(c, ":") {
				t.Fatalf("accepted invalid CIDR %q", c)
			}
		}
	})
}
