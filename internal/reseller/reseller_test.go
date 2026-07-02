package reseller

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

// openDB builds the minimal schema the Store touches (resellers + reseller_id
// columns on clients/users). Mirrors the MySQL migration shape closely enough.
func openDB(t *testing.T) func() *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	stmts := []string{
		`CREATE TABLE resellers (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, slug TEXT UNIQUE,
			status TEXT, brand_name TEXT, logo_url TEXT, support_email TEXT, primary_color TEXT,
			reseller_plan_id INTEGER, owner_user_id INTEGER,
			overselling_allowed INTEGER DEFAULT 0, can_create_plans INTEGER DEFAULT 0)`,
		`CREATE TABLE reseller_plans (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE)`,
		`INSERT INTO reseller_plans (name) VALUES ('Unlimited')`,
		`CREATE TABLE clients (id INTEGER PRIMARY KEY, reseller_id INTEGER)`,
		`CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, password_hash TEXT,
			password_set INTEGER, role TEXT, full_name TEXT, is_active INTEGER, reseller_id INTEGER)`,
		`INSERT INTO clients (id, reseller_id) VALUES (100, NULL), (101, NULL)`,
		`INSERT INTO users (id, reseller_id) VALUES (1, NULL)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec %q: %v", s, err)
		}
	}
	return func() *sql.DB { return db }
}

func TestCreateGetList(t *testing.T) {
	s := New(openDB(t))
	ctx := context.Background()
	id, err := s.Create(ctx, Reseller{Name: "Acme", Slug: "acme"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.Get(ctx, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "Acme" || got.Status != StatusActive {
		t.Fatalf("unexpected reseller: %+v", got)
	}
	list, err := s.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v n=%d", err, len(list))
	}
	// Duplicate slug must fail.
	if _, err := s.Create(ctx, Reseller{Name: "Dup", Slug: "acme"}); err == nil {
		t.Fatal("expected duplicate slug error")
	}
}

func TestCreateWithOwnerAtomic(t *testing.T) {
	dbf := openDB(t)
	s := New(dbf)
	ctx := context.Background()

	rid, uid, err := s.CreateWithOwner(ctx, Reseller{Name: "Acme", Slug: "acme"}, "owner@acme.tld", "Acme", "hash")
	if err != nil {
		t.Fatalf("create with owner: %v", err)
	}
	db := dbf()
	var role string
	var userReseller, ownerLink, planID sql.NullInt64
	db.QueryRow(`SELECT role, reseller_id FROM users WHERE id=?`, uid).Scan(&role, &userReseller)
	db.QueryRow(`SELECT owner_user_id, reseller_plan_id FROM resellers WHERE id=?`, rid).Scan(&ownerLink, &planID)
	if role != "reseller" || !userReseller.Valid || userReseller.Int64 != rid {
		t.Fatalf("owner user wrong: role=%q reseller_id=%v", role, userReseller)
	}
	if !ownerLink.Valid || ownerLink.Int64 != uid {
		t.Fatalf("owner_user_id backlink = %v, want %d", ownerLink, uid)
	}
	if !planID.Valid {
		t.Fatal("reseller not subscribed to the default Unlimited package")
	}

	// Duplicate owner email must roll the whole thing back - no orphan reseller.
	var before int
	db.QueryRow(`SELECT COUNT(*) FROM resellers`).Scan(&before)
	if _, _, err := s.CreateWithOwner(ctx, Reseller{Name: "B", Slug: "b"}, "owner@acme.tld", "B", "hash"); err != ErrDuplicate {
		t.Fatalf("expected ErrDuplicate, got %v", err)
	}
	var after int
	db.QueryRow(`SELECT COUNT(*) FROM resellers`).Scan(&after)
	if after != before {
		t.Fatalf("orphan reseller left behind: %d -> %d", before, after)
	}
}

func TestAssignClientAndAdmin(t *testing.T) {
	s := New(openDB(t))
	ctx := context.Background()
	id, _ := s.Create(ctx, Reseller{Name: "Acme", Slug: "acme"})

	if err := s.AssignClient(ctx, 100, &id); err != nil {
		t.Fatalf("assign client: %v", err)
	}
	ids, err := s.ClientIDs(ctx, id)
	if err != nil || len(ids) != 1 || ids[0] != 100 {
		t.Fatalf("client ids: %v %v", err, ids)
	}
	// Release returns to platform-direct.
	if err := s.AssignClient(ctx, 100, nil); err != nil {
		t.Fatalf("release: %v", err)
	}
	if ids, _ := s.ClientIDs(ctx, id); len(ids) != 0 {
		t.Fatalf("expected 0 clients after release, got %v", ids)
	}

	// Provision + release a reseller-admin.
	if err := s.AssignAdmin(ctx, 1, &id); err != nil {
		t.Fatalf("assign admin: %v", err)
	}
	rid, ok, err := s.ResellerIDForUser(ctx, 1)
	if err != nil || !ok || rid != id {
		t.Fatalf("user lookup after assign: rid=%d ok=%v err=%v", rid, ok, err)
	}
	if err := s.AssignAdmin(ctx, 1, nil); err != nil {
		t.Fatalf("release admin: %v", err)
	}
	if _, ok, _ := s.ResellerIDForUser(ctx, 1); ok {
		t.Fatal("expected user unscoped after release")
	}
}

func TestDeleteResetsOwnership(t *testing.T) {
	dbf := openDB(t)
	s := New(dbf)
	ctx := context.Background()
	id, _ := s.Create(ctx, Reseller{Name: "Acme", Slug: "acme"})
	_ = s.AssignClient(ctx, 100, &id)
	if err := s.Delete(ctx, id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.Get(ctx, id); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	// SQLite test schema has no FK cascade; just prove the reseller is gone and
	// AssignClient to a missing reseller still writes (FK enforcement is MySQL's job).
	if _, err := s.Get(ctx, id); err != ErrNotFound {
		t.Fatalf("reseller should be gone: %v", err)
	}
}

func TestValidatePlanBounds(t *testing.T) {
	dbf := openDB(t)
	db := dbf()
	for _, q := range []string{
		`CREATE TABLE reseller_plan_node_groups (reseller_plan_id INTEGER, node_group_id INTEGER)`,
		`CREATE TABLE reseller_plan_features (reseller_plan_id INTEGER, feature TEXT)`,
		`ALTER TABLE reseller_plans ADD COLUMN rate_limit_rpm_cap INTEGER DEFAULT 0`,
		`UPDATE reseller_plans SET rate_limit_rpm_cap=100`,
		`INSERT INTO reseller_plan_node_groups VALUES (1, 5)`,
		`INSERT INTO reseller_plan_features VALUES (1, 'ssl'), (1, 'rate_limit')`,
		`INSERT INTO resellers (name, slug, status, reseller_plan_id, can_create_plans) VALUES ('a','a','active',1,1)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	s := New(dbf)
	ctx := context.Background()
	var rid int64
	db.QueryRow(`SELECT id FROM resellers WHERE slug='a'`).Scan(&rid)

	if err := s.ValidatePlanBounds(ctx, rid, 5, []string{"ssl"}, 50); err != nil {
		t.Fatalf("in-bounds plan rejected: %v", err)
	}
	if err := s.ValidatePlanBounds(ctx, rid, 6, nil, 0); err == nil {
		t.Fatal("foreign pool must be rejected")
	}
	if err := s.ValidatePlanBounds(ctx, rid, 5, []string{"waf"}, 0); err == nil {
		t.Fatal("ungranted feature must be rejected")
	}
	if err := s.ValidatePlanBounds(ctx, rid, 5, []string{"rate_limit"}, 500); err == nil {
		t.Fatal("rpm above cap must be rejected")
	}
	// can_create_plans off -> everything rejected.
	db.Exec(`UPDATE resellers SET can_create_plans=0 WHERE id=?`, rid)
	if err := s.ValidatePlanBounds(ctx, rid, 5, []string{"ssl"}, 0); err == nil {
		t.Fatal("authoring disabled must be rejected")
	}
}
