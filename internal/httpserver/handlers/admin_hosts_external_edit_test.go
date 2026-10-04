package handlers

import (
	"strings"
	"testing"
)

// A wildcard-only allowlist hit on the edit path must get the same public
// address screen as create (it used to pass with only the RFC1918-tolerant
// backend screen). .invalid never resolves, so the screen refuses it.
func TestHostsUpdate_ExternalWildcardScreenedPublic(t *testing.T) {
	db := mtlsTLSEditDB(t)
	form := baseEditForm()
	form.Set("ssl", "1")
	form.Set("upstream_external", "1")
	form.Set("external_host", "vps1.console.invalid")
	form.Set("port", "443")
	loc := postHostEdit(t, db, form, "*.console.invalid")
	if !strings.Contains(loc, "non-public") {
		t.Fatalf("Location = %q, want the wildcard public-address refusal", loc)
	}
	var ext int
	if err := db.QueryRow("SELECT upstream_external FROM routes WHERE id = 7").Scan(&ext); err != nil {
		t.Fatal(err)
	}
	if ext != 0 {
		t.Fatal("route switched to external despite the refusal")
	}
}

// Switching a route off external drops the origin path rewrite with it.
func TestHostsUpdate_NonExternalClearsPathRewrite(t *testing.T) {
	db := mtlsTLSEditDB(t)
	if _, err := db.Exec(`UPDATE routes SET strip_path_prefix = 1, upstream_path = '/kvm/tok' WHERE id = 7`); err != nil {
		t.Fatal(err)
	}
	form := baseEditForm()
	form.Set("ssl", "1")
	if loc := postHostEdit(t, db, form); strings.Contains(loc, "err=") {
		t.Fatalf("save refused: %q", loc)
	}
	var strip int
	var up *string
	if err := db.QueryRow("SELECT strip_path_prefix, upstream_path FROM routes WHERE id = 7").Scan(&strip, &up); err != nil {
		t.Fatal(err)
	}
	if strip != 0 || up != nil {
		t.Fatalf("rewrite survived: strip=%d upstream_path=%v", strip, *up)
	}
}
