package backup

import (
	"context"
	"database/sql"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Retention must remove the artifact with its row; an undeletable artifact keeps its row for retry.
func TestPruneOldJobsDeletesArtifacts(t *testing.T) {
	db, destID, root := openMigratedSQLite(t)
	writeTestArtifact(t, db, destID, root, "old.tgz")
	writeTestArtifact(t, db, destID, root, "stuck.tgz")
	writeTestArtifact(t, db, destID, root, "new.tgz")
	// A non-empty directory makes os.Remove fail, standing in for a remote delete error.
	if err := os.Remove(filepath.Join(root, "stuck.tgz")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "stuck.tgz", "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE backup_jobs SET created_at = '2000-01-01 00:00:00' WHERE artifact_key <> 'new.tgz'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO settings (` + "`key`" + `, value) VALUES ('backup.retention_days', '7')`); err != nil {
		t.Fatal(err)
	}

	s := &Scheduler{Service: &Service{DB: func() *sql.DB { return db }, Logger: slog.Default()}}
	s.pruneOldJobs(context.Background())

	if _, err := os.Stat(filepath.Join(root, "old.tgz")); !os.IsNotExist(err) {
		t.Errorf("expired artifact not deleted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "new.tgz")); err != nil {
		t.Errorf("fresh artifact touched: %v", err)
	}
	var keys []string
	rows, err := db.Query(`SELECT artifact_key FROM backup_jobs ORDER BY artifact_key`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		_ = rows.Scan(&k)
		keys = append(keys, k)
	}
	if len(keys) != 2 || keys[0] != "new.tgz" || keys[1] != "stuck.tgz" {
		t.Fatalf("remaining job rows = %v, want [new.tgz stuck.tgz]", keys)
	}
}

// HPG-014: a process killed mid-backup skips the dump tempfile's defer
// cleanup. sweepOrphanedTemp is the safety net - it must remove a stale
// leftover but leave a fresh one (a backup that might still be running)
// alone.
func TestSweepOrphanedTempRemovesOnlyStaleFiles(t *testing.T) {
	stale, err := os.CreateTemp("", "hpg-dump-*.sql")
	if err != nil {
		t.Fatal(err)
	}
	stalePath := stale.Name()
	stale.Close()
	t.Cleanup(func() { os.Remove(stalePath) })
	oldTime := time.Now().Add(-3 * time.Hour)
	if err := os.Chtimes(stalePath, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}

	fresh, err := os.CreateTemp("", "hpg-dump-*.sql")
	if err != nil {
		t.Fatal(err)
	}
	freshPath := fresh.Name()
	fresh.Close()
	t.Cleanup(func() { os.Remove(freshPath) })

	sweepOrphanedTemp(2 * time.Hour)

	if _, err := os.Stat(stalePath); !os.IsNotExist(err) {
		t.Errorf("stale temp file was not removed: %v", err)
	}
	if _, err := os.Stat(freshPath); err != nil {
		t.Errorf("fresh temp file was incorrectly removed: %v", err)
	}
}

func TestSweepOrphanedTempIgnoresUnrelatedFiles(t *testing.T) {
	unrelated, err := os.CreateTemp("", "some-other-app-*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	path := unrelated.Name()
	unrelated.Close()
	t.Cleanup(func() { os.Remove(path) })
	old := time.Now().Add(-24 * time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}

	sweepOrphanedTemp(2 * time.Hour)

	if _, err := os.Stat(path); err != nil {
		t.Errorf("unrelated temp file must not be touched: %v", err)
	}
}
