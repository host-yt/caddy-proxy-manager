package handlers

import (
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/view"
)

// A failed clients insert must roll back the user row, not leave an
// activatable account without a client record.
func TestRegisterSubmitAtomic(t *testing.T) {
	db := openTestDBHandlers(t)
	tpls, err := view.LoadAuthTemplates()
	if err != nil {
		t.Fatal(err)
	}
	mustExec := func(q string, args ...any) {
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	mustExec("REPLACE INTO settings (`key`, value) VALUES ('auth.allow_self_registration', '1')")
	mustExec("DROP TRIGGER IF EXISTS w2_reg_fail")
	mustExec(`CREATE TRIGGER w2_reg_fail BEFORE INSERT ON clients FOR EACH ROW
		BEGIN IF NEW.display_name LIKE 'regfail%' THEN SIGNAL SQLSTATE '45000'; END IF; END`)
	t.Cleanup(func() { _, _ = db.Exec("DROP TRIGGER IF EXISTS w2_reg_fail") })

	h := &AuthHandlers{
		DB:        func() *sql.DB { return db },
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Templates: tpls,
	}
	submit := func(email string, n int) int {
		form := url.Values{"email": {email}, "password": {"correct-horse-1"}, "confirm_password": {"correct-horse-1"}}
		r := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.RemoteAddr = fmt.Sprintf("192.0.2.%d:1234", n)
		w := httptest.NewRecorder()
		h.RegisterSubmit(w, r)
		return w.Code
	}
	count := func(q, email string) int {
		var n int
		if err := db.QueryRow(q, email).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	stamp := time.Now().UnixNano()
	bad := fmt.Sprintf("regfail%d@example.com", stamp)
	good := fmt.Sprintf("regok%d@example.com", stamp)
	t.Cleanup(func() {
		for _, e := range []string{bad, good} {
			_, _ = db.Exec("DELETE FROM email_verifications WHERE user_id IN (SELECT id FROM users WHERE email = ?)", e)
			_, _ = db.Exec("DELETE FROM clients WHERE display_name = ?", e)
			_, _ = db.Exec("DELETE FROM users WHERE email = ?", e)
		}
	})

	if code := submit(bad, int(stamp%200)+1); code != http.StatusInternalServerError {
		t.Fatalf("failing client insert: status %d, want 500", code)
	}
	if n := count("SELECT COUNT(*) FROM users WHERE email = ?", bad); n != 0 {
		t.Fatalf("user row left behind after rollback: %d", n)
	}

	if code := submit(good, int(stamp%200)+2); code != http.StatusSeeOther {
		t.Fatalf("happy path: status %d, want 303", code)
	}
	if n := count("SELECT COUNT(*) FROM clients c JOIN users u ON u.id = c.user_id WHERE u.email = ?", good); n != 1 {
		t.Fatalf("client rows = %d, want 1", n)
	}
	if n := count("SELECT COUNT(*) FROM email_verifications v JOIN users u ON u.id = v.user_id WHERE u.email = ?", good); n != 1 {
		t.Fatalf("verify tokens = %d, want 1", n)
	}
}
