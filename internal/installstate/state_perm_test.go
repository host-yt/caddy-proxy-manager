package installstate

import (
	"os"
	"path/filepath"
	"testing"
)

// Save must leave the state file unreadable by other local accounts even when
// an earlier, looser file is already in place (OPS-003).
func TestSaveTightensPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "install_state.json")
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := New(dir, "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Save(&State{CurrentStep: StepWelcome}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := fi.Mode().Perm(); mode&0o077 != 0 {
		t.Fatalf("state file mode %04o is group/other readable", mode)
	}
}
