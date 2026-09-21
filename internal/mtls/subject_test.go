package mtls

import (
	"crypto/x509/pkix"
	"testing"
)

func TestSubjectCN(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"CN=device-42", "device-42"},
		{"device-42", "device-42"},                   // already bare, left alone
		{"CN=ops,OU=infra,O=acme", "ops"},            // extra RDNs ignored
		{"CN=Smith\\, Alice,O=acme", "Smith, Alice"}, // escaped comma is part of the CN
		{"  CN=padded  ", "padded"},
		{"", ""},
		{"O=acme", "O=acme"}, // not a CN DN, returned unchanged
	} {
		if got := SubjectCN(tc.in); got != tc.want {
			t.Errorf("SubjectCN(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// The DN we must parse is whatever crypto/x509 renders for an issued cert, so
// pin that rather than a hand-written string.
func TestSubjectCNMatchesIssuedName(t *testing.T) {
	for _, cn := range []string{"device-42", "Smith, Alice", "a+b", "x=y"} {
		dn := pkix.Name{CommonName: cn}.String()
		if got := SubjectCN(dn); got != cn {
			t.Errorf("issued %q rendered as %q, SubjectCN gave %q", cn, dn, got)
		}
	}
}
