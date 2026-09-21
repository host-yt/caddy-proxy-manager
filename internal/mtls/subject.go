package mtls

import "strings"

// SubjectCN pulls the common name out of an RFC 2253 distinguished name.
//
// Certificates are issued with the operator-typed string as the sole CN and
// that bare string is what `mtls_issued_certs.subject` stores, but Caddy's
// {http.request.tls.client.subject} placeholder renders the full DN - "CN=x".
// Comparing the two directly never matched, which made path RBAC deny every
// request including legitimate ones.
//
// Input that is not a DN is returned unchanged, so callers can compare against
// both forms and keep working for subjects stored either way.
func SubjectCN(dn string) string {
	s := strings.TrimSpace(dn)
	if !strings.HasPrefix(s, "CN=") {
		return s
	}
	s = s[len("CN="):]

	// Walk to the first unescaped comma: Go's pkix.Name.String() backslash-
	// escapes any comma inside the value itself.
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			b.WriteByte(s[i])
			continue
		}
		if s[i] == ',' {
			break
		}
		b.WriteByte(s[i])
	}
	return strings.TrimSpace(b.String())
}
