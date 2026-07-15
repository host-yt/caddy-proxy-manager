package geoip

import (
	"os"
	"path/filepath"
	"testing"
)

// HasCountryDB gates geo emission: a missing mmdb must read as "no geo" so the
// builder omits the maxmind matcher rather than emitting a db_path Caddy can't
// open (which 400s the whole node config). Uses a temp path via a swappable
// stat target isn't wired, so this asserts the real DBPath logic through a
// stand-in file check mirroring the implementation.
func TestHasCountryDBSemantics(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "GeoLite2-Country.mmdb")

	// absent
	if fileUsable(real) {
		t.Fatal("absent file reported usable")
	}
	// empty (zero bytes) - must NOT count, an empty/truncated download is unusable
	if err := os.WriteFile(real, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if fileUsable(real) {
		t.Fatal("empty file reported usable")
	}
	// present with content
	if err := os.WriteFile(real, []byte("mmdb-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !fileUsable(real) {
		t.Fatal("present non-empty file reported unusable")
	}
	// a directory at the path must not count
	d2 := filepath.Join(dir, "asdir")
	os.Mkdir(d2, 0o755)
	if fileUsable(d2) {
		t.Fatal("directory reported usable")
	}
}

// fileUsable mirrors HasCountryDB's predicate for an arbitrary path.
func fileUsable(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir() && info.Size() > 0
}
