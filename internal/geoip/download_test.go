package geoip

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"testing"
)

// makeTarGz builds an in-memory tar.gz with one entry name->content.
func makeTarGz(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range entries {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatalf("write content: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gz: %v", err)
	}
	return buf.Bytes()
}

// fakeMMDB returns bytes that pass the MaxMind marker sanity check.
func fakeMMDB() []byte {
	return append([]byte("fake-geoip-db-payload"), maxMindMarker...)
}

func TestExtractMMDBFromTarGz_OK(t *testing.T) {
	mmdb := fakeMMDB()
	archive := makeTarGz(t, map[string][]byte{
		"GeoLite2-Country_20260626/COPYRIGHT.txt":         []byte("(c) maxmind"),
		"GeoLite2-Country_20260626/GeoLite2-Country.mmdb": mmdb,
	})
	got, err := ExtractMMDBFromTarGz(bytes.NewReader(archive))
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if !bytes.Equal(got, mmdb) {
		t.Fatalf("extracted bytes mismatch")
	}
	// sha256 must be stable + match the input.
	if SHA256Hex(got) != SHA256Hex(mmdb) {
		t.Fatalf("sha mismatch")
	}
	want := SHA256Hex(mmdb)
	if got2 := SHA256Hex(got); got2 != want {
		t.Fatalf("sha not stable: %s != %s", got2, want)
	}
}

func TestExtractMMDBFromTarGz_NoMMDB(t *testing.T) {
	archive := makeTarGz(t, map[string][]byte{"readme.txt": []byte("hi")})
	if _, err := ExtractMMDBFromTarGz(bytes.NewReader(archive)); err == nil {
		t.Fatal("expected error for archive with no mmdb")
	}
}

func TestExtractMMDBFromTarGz_TwoMMDB(t *testing.T) {
	archive := makeTarGz(t, map[string][]byte{
		"a.mmdb": fakeMMDB(),
		"b.mmdb": fakeMMDB(),
	})
	if _, err := ExtractMMDBFromTarGz(bytes.NewReader(archive)); err == nil {
		t.Fatal("expected error for archive with two mmdb files")
	}
}

func TestExtractMMDBFromTarGz_NotMMDBContent(t *testing.T) {
	archive := makeTarGz(t, map[string][]byte{"x.mmdb": []byte("not a real db")})
	if _, err := ExtractMMDBFromTarGz(bytes.NewReader(archive)); err == nil {
		t.Fatal("expected error when mmdb lacks MaxMind marker")
	}
}
