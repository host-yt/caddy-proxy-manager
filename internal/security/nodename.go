package security

import (
	"regexp"
	"strings"
)

// nodeNameRE is the accepted shape of a Caddy node name: it ends up in
// generated WireGuard config comments and in operator-facing UI, so it stays a
// conservative hostname-ish token.
var nodeNameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$`)

// ValidNodeName reports whether name is safe to store as caddy_nodes.name.
// The rendered wg0.conf writes "# Node #<id> (<name>)", so a name carrying a
// newline could otherwise append arbitrary directives - a [Peer] block of the
// attacker's choosing - to the manager's WireGuard config (NODE-02).
func ValidNodeName(name string) bool {
	return nodeNameRE.MatchString(name)
}

// SanitizeConfigComment strips anything that could break out of a single-line
// config comment: CR, LF, NUL and other control characters, capped at 64 runes.
// Applied at render time so a row that predates ValidNodeName - or one written
// by a path that bypasses it - still cannot inject config directives.
func SanitizeConfigComment(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
		if n++; n >= 64 {
			break
		}
	}
	return b.String()
}
