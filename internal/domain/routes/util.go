// Small helpers shared across the package.
package routes

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"strings"
)

// splitCSV splits a comma-separated string into trimmed non-empty tokens.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// splitHostList explodes a stored comma/space separated hostname list.
func splitHostList(raw string) []string {
	out := []string{}
	for _, p := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == ';'
	}) {
		if v := strings.ToLower(strings.TrimSpace(p)); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// newVerifyToken returns a 32-hex-char (128-bit) random nonce the domain owner
// publishes as a TXT record to prove control. Hex so it is DNS-TXT-safe.
func newVerifyToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func validDomain(d string) bool {
	if len(d) == 0 || len(d) > 253 {
		return false
	}
	if net.ParseIP(d) != nil {
		return false // IPs not allowed as hostnames
	}
	if strings.Contains(d, "..") {
		return false
	}
	if !strings.Contains(d, ".") {
		return false
	}
	for _, c := range d {
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '-', c == '.':
		default:
			return false
		}
	}
	// Each DNS label: 1-63 chars, no leading or trailing hyphen (RFC 1035 §2.3.1).
	for _, label := range strings.Split(d, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

// ValidDomain exposes the internal hostname validator so handlers editing a
// route (not via Create) enforce the same shape check.
func ValidDomain(d string) bool { return validDomain(d) }

// NewVerifyToken exposes the DNS-TXT ownership nonce generator so an
// out-of-service domain change can re-arm verification.
func NewVerifyToken() (string, error) { return newVerifyToken() }

// looksLikeIP reports whether s parses as IPv4/IPv6 (not a hostname).
func looksLikeIP(s string) bool {
	return net.ParseIP(strings.TrimSpace(s)) != nil
}

func truncErr(e error) string {
	s := e.Error()
	if len(s) > 240 {
		s = s[:240] + "..."
	}
	return s
}
