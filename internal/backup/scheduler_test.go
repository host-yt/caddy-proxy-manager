package backup

import (
	"os"
	"testing"
	"time"
)

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
