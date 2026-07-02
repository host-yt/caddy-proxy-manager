package adminscope

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

// TestExplicitRestrictionNoFootgun proves the fix: restriction is driven by the
// explicit users.is_restricted flag, not the admin_client_scope row count. A
// restricted admin with ZERO assignments must see nothing (fail-safe), and
// removing the last assignment must NOT escalate to full access.
func TestExplicitRestrictionNoFootgun(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	for _, s := range []string{
		`CREATE TABLE users (id INTEGER PRIMARY KEY, reseller_id INTEGER, is_restricted INTEGER DEFAULT 0, role TEXT DEFAULT 'admin')`,
		`CREATE TABLE admin_client_scope (admin_user_id INTEGER, client_id INTEGER)`,
		// user 1 = restricted with ZERO assignments (the footgun case).
		// user 2 = restricted with one assignment.
		// user 3 = unrestricted (default flag), no assignments.
		`INSERT INTO users (id, reseller_id, is_restricted) VALUES (1, NULL, 1), (2, NULL, 1), (3, NULL, 0)`,
		`INSERT INTO admin_client_scope (admin_user_id, client_id) VALUES (2, 500)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec %q: %v", s, err)
		}
	}
	svc := New(func() *sql.DB { return db })
	ctx := context.Background()

	// Restricted + no rows: sees nothing (all=false, empty), NOT everything.
	ids, all, err := svc.ScopeFilter(ctx, 1)
	if err != nil || all || len(ids) != 0 {
		t.Fatalf("restricted-with-no-rows: got ids=%v all=%v err=%v; want empty+false", ids, all, err)
	}
	// Restricted + one row: scoped to that client.
	ids, all, err = svc.ScopeFilter(ctx, 2)
	if err != nil || all || len(ids) != 1 || ids[0] != 500 {
		t.Fatalf("restricted-with-one-row: got ids=%v all=%v err=%v; want [500]+false", ids, all, err)
	}
	// Unrestricted: full access.
	_, all, err = svc.ScopeFilter(ctx, 3)
	if err != nil || !all {
		t.Fatalf("unrestricted: got all=%v err=%v; want true", all, err)
	}
}
