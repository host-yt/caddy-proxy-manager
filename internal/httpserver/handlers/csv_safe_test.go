package handlers

import "testing"

func TestCSVSafeRow(t *testing.T) {
	for _, c := range []string{"=HYPERLINK(1)", "+1", "-1", "@SUM(1)", "\t=1", "\r=1"} {
		if got := csvSafeRow([]string{c})[0]; got != "'"+c {
			t.Errorf("csvSafeRow(%q) = %q, want quoted", c, got)
		}
	}
	if got := csvSafeRow([]string{"Acme", ""}); got[0] != "Acme" || got[1] != "" {
		t.Errorf("benign cells changed: %q", got)
	}
}
