package main

import "testing"

// A rotation must reproduce whatever envelope form the row already has:
// re-sealing a v2 purpose envelope as legacy (or vice versa) makes the value
// undecryptable for the panel even though the tool reports success.
func TestEnvelopeRoundTripPreservesForm(t *testing.T) {
	oldKey := deriveStateKey("old-secret-that-is-long-enough-32")
	newKey := deriveStateKey("new-secret-that-is-long-enough-32")

	for _, purpose := range []string{"", "wg", "route"} {
		stored, err := encEnvelope(purpose, "s3cret", oldKey)
		if err != nil {
			t.Fatalf("purpose %q seal: %v", purpose, err)
		}
		gotPurpose, pt, err := decEnvelope(stored, oldKey)
		if err != nil {
			t.Fatalf("purpose %q open: %v", purpose, err)
		}
		if gotPurpose != purpose || pt != "s3cret" {
			t.Fatalf("purpose %q: got (%q, %q)", purpose, gotPurpose, pt)
		}
		rotated, err := encEnvelope(gotPurpose, pt, newKey)
		if err != nil {
			t.Fatalf("purpose %q reseal: %v", purpose, err)
		}
		if _, _, err := decEnvelope(rotated, oldKey); err == nil {
			t.Fatalf("purpose %q: old key still opens the rotated value", purpose)
		}
		p2, pt2, err := decEnvelope(rotated, newKey)
		if err != nil || p2 != purpose || pt2 != "s3cret" {
			t.Fatalf("purpose %q after rotate: (%q, %q, %v)", purpose, p2, pt2, err)
		}
	}
}

// Every encColumn must be reachable in the schema lookup, and a column whose
// migration has not run must read as absent (it is then skipped, not fatal).
func TestHasColumn(t *testing.T) {
	have := map[string]bool{"caddy_nodes.admin_proxy_key_enc": true}
	if !hasColumn(have, "caddy_nodes", "admin_proxy_key_enc") {
		t.Fatal("present column reported absent")
	}
	if !hasColumn(have, "CADDY_NODES", "Admin_Proxy_Key_Enc") {
		t.Fatal("lookup must be case-insensitive (information_schema casing varies)")
	}
	if hasColumn(have, "caddy_nodes", "wg_psk_enc") {
		t.Fatal("unmigrated column reported present")
	}
}

// Guards against a copy-paste duplicate in encColumns, which would re-seal the
// same row twice and leave it encrypted under the new key twice over.
func TestEncColumnsUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range encColumns {
		k := c.table + "." + c.col + "|" + c.where
		if seen[k] {
			t.Fatalf("duplicate encColumn entry: %s", k)
		}
		seen[k] = true
		if c.idCol == "" || c.table == "" || c.col == "" {
			t.Fatalf("incomplete encColumn entry: %+v", c)
		}
	}
}
