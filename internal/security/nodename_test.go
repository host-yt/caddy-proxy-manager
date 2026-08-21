package security

import "strings"

import "testing"

func TestValidNodeName(t *testing.T) {
	good := []string{"edge1", "edge-01", "node_a.eu", "A1", strings.Repeat("a", 63)}
	for _, s := range good {
		if !ValidNodeName(s) {
			t.Errorf("ValidNodeName(%q) = false, want true", s)
		}
	}
	bad := []string{
		"", "-edge", ".edge", "_edge", "edge 1", "edge#1",
		strings.Repeat("a", 64),
		"edge\nPublicKey = attacker", // the wg0.conf injection shape
		"edge\r\n[Peer]",
		"edge\x00",
	}
	for _, s := range bad {
		if ValidNodeName(s) {
			t.Errorf("ValidNodeName(%q) = true, want false", s)
		}
	}
}

func TestSanitizeConfigComment(t *testing.T) {
	in := "edge\nPublicKey = attacker\r\nAllowedIPs = 0.0.0.0/0"
	got := SanitizeConfigComment(in)
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("sanitized value still contains a newline: %q", got)
	}
	if !strings.HasPrefix(got, "edge") {
		t.Errorf("sanitize dropped the readable prefix: %q", got)
	}
	if n := len([]rune(SanitizeConfigComment(strings.Repeat("x", 200)))); n != 64 {
		t.Errorf("length cap = %d runes, want 64", n)
	}
	if got := SanitizeConfigComment("edge\x00\x7f1"); got != "edge1" {
		t.Errorf("control chars survived: %q", got)
	}
}
