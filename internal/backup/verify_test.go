package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/store"
	"github.com/host-yt/caddy-proxy-manager/internal/store/sqlitetest"
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

// openMigratedSQLite returns a migrated SQLite panel DB with one local
// destination rooted at a temp dir.
func openMigratedSQLite(t *testing.T) (*sql.DB, int64, string) {
	t.Helper()
	prev := store.Driver()
	store.SetDriver("sqlite3")
	t.Cleanup(func() { store.SetDriver(prev) })
	db, err := store.Open(context.Background(), "sqlite3", sqlitetest.MigratedCopy(t, "panel.db"), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	root := t.TempDir()
	res, err := db.Exec(`INSERT INTO backup_destinations (name, kind, config_enc) VALUES ('loc', 'local', ?)`,
		`plain:{"path":"`+root+`"}`)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	return db, id, root
}

// writeTestArtifact stores a minimal valid backup artifact and its succeeded job row.
func writeTestArtifact(t *testing.T, db *sql.DB, destID int64, root, key string) {
	t.Helper()
	var art bytes.Buffer
	gz := gzip.NewWriter(&art)
	tw := tar.NewWriter(gz)
	body := []byte("-- Hostyt Proxy Gateway logical dump\nSELECT 1;\n")
	_ = tw.WriteHeader(&tar.Header{Name: "dump.sql", Mode: 0o600, Size: int64(len(body))})
	_, _ = tw.Write(body)
	_ = tw.Close()
	_ = gz.Close()
	if err := os.WriteFile(filepath.Join(root, key), art.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(art.Bytes())
	if _, err := db.Exec(`INSERT INTO backup_jobs (destination_id, kind, status, artifact_key, size_bytes, sha256, encrypted)
		VALUES (?, 'manual', 'succeeded', ?, ?, ?, 0)`, destID, key, art.Len(), hex.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}
}

// A successful verification must not become the next run's source backup.
func TestVerifyIgnoresEarlierVerificationRows(t *testing.T) {
	db, destID, root := openMigratedSQLite(t)
	writeTestArtifact(t, db, destID, root, "hpg-job-1.tgz")

	svc := &Service{DB: func() *sql.DB { return db }}
	for i := 0; i < 2; i++ {
		if err := svc.Verify(context.Background(), destID); err != nil {
			t.Fatalf("verify #%d: %v", i+1, err)
		}
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM backup_jobs WHERE kind = 'verification'
		AND status = 'succeeded' AND COALESCE(artifact_key, '') = ''`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("want 2 keyless verification rows, got %d", n)
	}
}
