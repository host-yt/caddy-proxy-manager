package backup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// TestStreamToTempFileSmallArtifact is a regression guard: a normal small
// artifact under the cap must still succeed with a correct hash and a
// readable temp file.
func TestStreamToTempFileSmallArtifact(t *testing.T) {
	data := []byte("hello backup artifact")
	path, n, sum, err := streamToTempFile(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer os.Remove(path)

	if n != int64(len(data)) {
		t.Fatalf("size mismatch: got %d want %d", n, len(data))
	}
	want := sha256.Sum256(data)
	if sum != hex.EncodeToString(want[:]) {
		t.Fatalf("sha256 mismatch: got %s want %x", sum, want)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("temp file content mismatch: got %q want %q", got, data)
	}
}

// unboundedReader never returns io.EOF, standing in for a hostile or
// malfunctioning destination that streams far more than the recorded size.
type unboundedReader struct {
	read int64
}

func (r *unboundedReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	r.read += int64(len(p))
	return len(p), nil
}

// TestStreamToTempFileCutsOversizedReadShort asserts that a source larger
// than the recorded expected size is rejected without being buffered whole:
// the reader must stop shortly after the cap, not after gigabytes streamed
// (BACKUP-VERIFY-01).
func TestStreamToTempFileCutsOversizedReadShort(t *testing.T) {
	const limit = 4096
	r := &unboundedReader{}

	path, n, sum, err := streamToTempFile(r, limit)
	if err == nil {
		t.Fatalf("expected size-limit error, got n=%d sum=%s", n, sum)
	}
	if path != "" {
		t.Fatalf("expected no temp path on failure, got %q", path)
	}
	// Only limit+1 bytes should ever have been pulled from the source.
	if r.read > limit+1 {
		t.Fatalf("reader drained past the cap: read %d bytes for a %d byte limit", r.read, limit)
	}
}

// TestStreamToTempFileCleansUpOnRejection makes sure no temp file survives
// a rejected (oversized) download.
func TestStreamToTempFileCleansUpOnRejection(t *testing.T) {
	before, _ := filepath.Glob(filepath.Join(os.TempDir(), "hpg-verify-*"))
	r := &unboundedReader{}
	if _, _, _, err := streamToTempFile(r, 1024); err == nil {
		t.Fatal("expected error")
	}
	after, _ := filepath.Glob(filepath.Join(os.TempDir(), "hpg-verify-*"))
	if len(after) != len(before) {
		t.Fatalf("leftover temp files after rejection: before=%v after=%v", before, after)
	}
}
