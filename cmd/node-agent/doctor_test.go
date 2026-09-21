package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDoctorGeoIPAt covers the three states OPS-005 cares about: mount
// missing entirely, mount present but file not synced yet, and healthy.
func TestDoctorGeoIPAt(t *testing.T) {
	base := t.TempDir()

	t.Run("dir missing", func(t *testing.T) {
		c := doctorGeoIPAt(filepath.Join(base, "nope", "GeoLite2-Country.mmdb"))
		if c.status != statusFail {
			t.Fatalf("status = %s, want FAIL", c.status)
		}
	})

	t.Run("dir present, file missing", func(t *testing.T) {
		dir := filepath.Join(base, "empty")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		c := doctorGeoIPAt(filepath.Join(dir, "GeoLite2-Country.mmdb"))
		if c.status != statusWarn {
			t.Fatalf("status = %s, want WARN", c.status)
		}
	})

	t.Run("dir present, file empty", func(t *testing.T) {
		dir := filepath.Join(base, "zerobyte")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "GeoLite2-Country.mmdb")
		if err := os.WriteFile(path, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		c := doctorGeoIPAt(path)
		if c.status != statusWarn {
			t.Fatalf("status = %s, want WARN", c.status)
		}
	})

	t.Run("file present", func(t *testing.T) {
		dir := filepath.Join(base, "ok")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "GeoLite2-Country.mmdb")
		if err := os.WriteFile(path, []byte("mmdb-bytes"), 0o644); err != nil {
			t.Fatal(err)
		}
		c := doctorGeoIPAt(path)
		if c.status != statusPass {
			t.Fatalf("status = %s, want PASS", c.status)
		}
	})
}
