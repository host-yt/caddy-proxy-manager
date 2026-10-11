package handlers

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/installstate"
	_ "modernc.org/sqlite"
)

// A failed final state save must not report completion, and a resubmit of
// the same node must then finish instead of failing on "name exists".
func TestCaddySubmitFinalSaveFailureIsRecoverable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the read-only dir used to fail Save")
	}
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	for _, q := range []string{
		`CREATE TABLE node_groups (id INTEGER PRIMARY KEY, name TEXT UNIQUE, mode TEXT)`,
		`CREATE TABLE caddy_nodes (id INTEGER PRIMARY KEY, name TEXT UNIQUE, api_url TEXT, public_hostname TEXT,
			public_ip TEXT, node_group_id INTEGER, max_routes INTEGER, is_enabled INTEGER, health_status TEXT, approved_at TEXT)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	wiz := newTestWizard(t)
	if wiz.State, err = installstate.New(dir, "12345678901234567890123456789012"); err != nil {
		t.Fatal(err)
	}
	if err := wiz.State.Save(&installstate.State{Admin: &installstate.AdminState{Email: "a@b.c"}}); err != nil {
		t.Fatal(err)
	}
	wiz.db = db

	submit := func() *httptest.ResponseRecorder {
		form := url.Values{"name": {"edge1"}, "api_url": {"http://10.0.0.2:2019"}, "public_hostname": {"edge1.example.com"}}
		req := httptest.NewRequest(http.MethodPost, "/install/caddy", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		wiz.CaddySubmit(rr, req)
		return rr
	}

	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	rr := submit()
	_ = os.Chmod(dir, 0o700)
	if strings.Contains(rr.Header().Get("Location"), "step=done") || wiz.State.IsInstalled() {
		t.Fatalf("completion reported despite failed save: %d %q", rr.Code, rr.Header().Get("Location"))
	}

	rr = submit()
	if !strings.Contains(rr.Header().Get("Location"), "step=done") || !wiz.State.IsInstalled() {
		t.Fatalf("retry did not complete: %d %q", rr.Code, rr.Header().Get("Location"))
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM caddy_nodes`).Scan(&n)
	if n != 1 {
		t.Fatalf("want 1 node, got %d", n)
	}
}
