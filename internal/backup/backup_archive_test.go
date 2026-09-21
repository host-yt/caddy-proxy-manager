package backup

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

func newArchiveTestService(t *testing.T, statePath, wgDir string) (*Service, context.Context) {
	t.Helper()
	prev := store.Driver()
	store.SetDriver("sqlite3")
	t.Cleanup(func() { store.SetDriver(prev) })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	dir := t.TempDir()
	db := openRoundTripDB(t, ctx, filepath.Join(dir, "src.db"))
	seedRoundTripData(t, db)

	return &Service{DB: func() *sql.DB { return db }, StateFilePath: statePath, WGConfigDir: wgDir}, ctx
}

// HPG-013: a required component that exists but cannot be read (here,
// install_state.json is a directory, not a file) must fail the whole
// backup. The old code only checked `err == nil` and silently produced an
// archive missing the file the panel needs to decrypt everything else.
func TestWriteArchiveRequiredStateFileUnreadableFails(t *testing.T) {
	dir := t.TempDir()
	// A directory where a file was expected - os.ReadFile errors, but not
	// with IsNotExist, so this must not be treated as "absent and optional".
	statePath := filepath.Join(dir, "install_state.json")
	if err := os.Mkdir(statePath, 0o700); err != nil {
		t.Fatal(err)
	}
	svc, ctx := newArchiveTestService(t, statePath, "")

	var buf bytes.Buffer
	if err := svc.writeArchive(ctx, &buf); err == nil {
		t.Fatal("expected writeArchive to fail when install_state.json cannot be read")
	}
}

// HPG-013: an absent wg_config directory is a legitimate, non-fatal skip
// (not every install uses WireGuard), and the manifest must say so instead
// of just quietly omitting it.
func TestWriteArchiveOptionalWGDirAbsentIsSkippedNotFatal(t *testing.T) {
	dir := t.TempDir()
	svc, ctx := newArchiveTestService(t, "", filepath.Join(dir, "does-not-exist"))

	var buf bytes.Buffer
	if err := svc.writeArchive(ctx, &buf); err != nil {
		t.Fatalf("absent optional wg dir must not fail the backup: %v", err)
	}
	members := readArchive(t, buf.Bytes())
	var manifest struct {
		Components []struct {
			Name     string `json:"name"`
			Required bool   `json:"required"`
			Status   string `json:"status"`
		} `json:"components"`
	}
	if err := json.Unmarshal(members["manifest.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range manifest.Components {
		if c.Name == "wg/*" {
			found = true
			if c.Required || c.Status != "skipped" {
				t.Errorf("wg/* component = %+v, want required=false status=skipped", c)
			}
		}
	}
	if !found {
		t.Fatal("manifest has no wg/* component entry")
	}
}

// HPG-013: once the wg_config directory exists, a file inside it that can't
// be read (here, a broken symlink) is real data loss - not an absent
// component - and must fail the backup instead of being silently `continue`d.
func TestWriteArchiveWGFileUnreadableFails(t *testing.T) {
	dir := t.TempDir()
	wgDir := filepath.Join(dir, "wg")
	if err := os.Mkdir(wgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(wgDir, "missing-target"), filepath.Join(wgDir, "peer1.conf")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	svc, ctx := newArchiveTestService(t, "", wgDir)

	var buf bytes.Buffer
	if err := svc.writeArchive(ctx, &buf); err == nil {
		t.Fatal("expected writeArchive to fail when an existing wg config file can't be read")
	}
}

// HPG-013: a deferred tar/gzip Close alone discards its error, and a gzip
// flush error can land on the very last write - after every explicit Write
// in the body already returned nil. Cut the output off one byte short of a
// known-good run (guaranteeing every body Write still succeeds and only the
// close-time flush fails) and require that error to come back from
// writeArchive.
func TestWriteArchiveCloseErrorPropagates(t *testing.T) {
	svc, ctx := newArchiveTestService(t, "", "")

	var good bytes.Buffer
	if err := svc.writeArchive(ctx, &good); err != nil {
		t.Fatalf("baseline writeArchive: %v", err)
	}
	total := int64(good.Len())
	if total < 2 {
		t.Fatalf("baseline archive too small to test: %d bytes", total)
	}

	fw := &failAfterWriter{limit: total - 1}
	if err := svc.writeArchive(ctx, fw); err == nil {
		t.Fatal("expected the close-time write failure to propagate as an error")
	}
}

// failAfterWriter accepts exactly `limit` bytes across any number of Write
// calls, then errors - simulating a flush failure exactly at Close time
// without needing to hook gzip/tar internals directly.
type failAfterWriter struct {
	limit int64
	n     int64
}

func (f *failAfterWriter) Write(p []byte) (int, error) {
	if f.n >= f.limit {
		return 0, errors.New("simulated write failure at close")
	}
	remain := f.limit - f.n
	if int64(len(p)) > remain {
		w := int(remain)
		f.n += int64(w)
		return w, errors.New("simulated write failure at close")
	}
	f.n += int64(len(p))
	return len(p), nil
}

// HPG-014: dump.sql is staged through a temp file (not buffered in RAM), and
// that file must not survive a completed run - neither on success nor on a
// failure partway through.
func TestWriteArchiveNoLeftoverDumpTempFile(t *testing.T) {
	before, _ := filepath.Glob(filepath.Join(os.TempDir(), "hpg-dump-*"))

	svc, ctx := newArchiveTestService(t, "", "")
	var buf bytes.Buffer
	if err := svc.writeArchive(ctx, &buf); err != nil {
		t.Fatalf("writeArchive: %v", err)
	}

	after, _ := filepath.Glob(filepath.Join(os.TempDir(), "hpg-dump-*"))
	if len(after) > len(before) {
		t.Fatalf("dump temp file leaked: before=%v after=%v", before, after)
	}
}
