package handlers

import (
	"strings"
	"testing"
)

// caddy-l4 v0.1.1 has no upstream weight, so only weight 1 (or none) is accepted.
func TestParseUpstreamsRawWeights(t *testing.T) {
	out, msg := parseUpstreamsRaw("10.0.0.1:3306\n10.0.0.2:3306 1")
	if msg != "" || len(out) != 2 {
		t.Fatalf("plain/weight-1 lines must parse: %v %q", out, msg)
	}
	if _, msg := parseUpstreamsRaw("10.0.0.1:3306 2"); !strings.Contains(msg, "weights are not supported") {
		t.Errorf("weight 2 must be rejected, got %q", msg)
	}
	if _, msg := parseUpstreamsRaw("nope"); !strings.HasPrefix(msg, "invalid upstream address") {
		t.Errorf("bad address message, got %q", msg)
	}
}
