package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// A rotation must reproduce whatever envelope form the row already has:
// re-sealing a v2 purpose envelope as legacy (or vice versa) makes the value
// undecryptable for the panel even though the tool reports success.
func TestEnvelopeRoundTripPreservesForm(t *testing.T) {
	oldKey := deriveStateKey("old-secret-that-is-long-enough-32")
	newKey := deriveStateKey("new-secret-that-is-long-enough-32")

	for _, purpose := range []string{"", "wg", "route"} {
		stored, err := encEnvelope(purpose, "s3cret", oldKey)
		if err != nil {
			t.Fatalf("purpose %q seal: %v", purpose, err)
		}
		gotPurpose, pt, err := decEnvelope(stored, oldKey)
		if err != nil {
			t.Fatalf("purpose %q open: %v", purpose, err)
		}
		if gotPurpose != purpose || pt != "s3cret" {
			t.Fatalf("purpose %q: got (%q, %q)", purpose, gotPurpose, pt)
		}
		rotated, err := encEnvelope(gotPurpose, pt, newKey)
		if err != nil {
			t.Fatalf("purpose %q reseal: %v", purpose, err)
		}
		if _, _, err := decEnvelope(rotated, oldKey); err == nil {
			t.Fatalf("purpose %q: old key still opens the rotated value", purpose)
		}
		p2, pt2, err := decEnvelope(rotated, newKey)
		if err != nil || p2 != purpose || pt2 != "s3cret" {
			t.Fatalf("purpose %q after rotate: (%q, %q, %v)", purpose, p2, pt2, err)
		}
	}
}

// Every encColumn must be reachable in the schema lookup, and a column whose
// migration has not run must read as absent (it is then skipped, not fatal).
func TestHasColumn(t *testing.T) {
	have := map[string]bool{"caddy_nodes.admin_proxy_key_enc": true}
	if !hasColumn(have, "caddy_nodes", "admin_proxy_key_enc") {
		t.Fatal("present column reported absent")
	}
	if !hasColumn(have, "CADDY_NODES", "Admin_Proxy_Key_Enc") {
		t.Fatal("lookup must be case-insensitive (information_schema casing varies)")
	}
	if hasColumn(have, "caddy_nodes", "wg_psk_enc") {
		t.Fatal("unmigrated column reported present")
	}
}

// Guards against a copy-paste duplicate in encColumns, which would re-seal the
// same row twice and leave it encrypted under the new key twice over.
func TestEncColumnsUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range encColumns {
		k := c.table + "." + c.col + "|" + c.where
		if seen[k] {
			t.Fatalf("duplicate encColumn entry: %s", k)
		}
		seen[k] = true
		if c.idCol == "" || c.table == "" || c.col == "" {
			t.Fatalf("incomplete encColumn entry: %+v", c)
		}
	}
}

// HPG-011: a journal for a different secret pair must never be silently
// skipped or silently resumed - either would mix a third key into the mess.
func TestDecideResumeRefusesDifferentSecrets(t *testing.T) {
	j := &rotateJournal{OldHash: secretHash("a"), NewHash: secretHash("b"), Stage: stageDBDone}
	if _, err := decideResume(j, secretHash("a"), secretHash("c"), "/tmp/x"); err == nil {
		t.Fatal("expected refusal for a journal belonging to a different secret pair")
	}
}

// HPG-011: no journal means a fresh rotation - nothing to resume.
func TestDecideResumeNoJournal(t *testing.T) {
	resume, err := decideResume(nil, secretHash("a"), secretHash("b"), "/tmp/x")
	if err != nil || resume {
		t.Fatalf("expected (false, nil) for no journal, got (%v, %v)", resume, err)
	}
}

// HPG-011: a matching journal at stage db_done must be recognized so a
// resumed run does not retry (and fail) decrypting the DB under the old key.
func TestDecideResumeSkipsCompletedDBStage(t *testing.T) {
	oh, nh := secretHash("old-secret-32-chars-long-enough!!"), secretHash("new-secret-32-chars-long-enough!!")
	j := &rotateJournal{OldHash: oh, NewHash: nh, Stage: stageDBDone}
	resume, err := decideResume(j, oh, nh, "/tmp/x")
	if err != nil || !resume {
		t.Fatalf("expected (true, nil), got (%v, %v)", resume, err)
	}
}

func TestJournalRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json.rotate-journal")
	want := rotateJournal{OldHash: "aa", NewHash: "bb", Stage: stageDBDone}
	if err := writeJournal(path, want); err != nil {
		t.Fatalf("writeJournal: %v", err)
	}
	got, err := readJournal(path)
	if err != nil {
		t.Fatalf("readJournal: %v", err)
	}
	if got == nil || *got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if _, err := readJournal(filepath.Join(t.TempDir(), "missing")); err != nil {
		t.Fatalf("missing journal must read as (nil, nil): %v", err)
	}
}

func writeStateFile(t *testing.T, dir string, m map[string]any) string {
	t.Helper()
	path := filepath.Join(dir, "install_state.json")
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// HPG-011: a preflight failure (bad --old-secret) must leave the state file
// byte-for-byte untouched. The old code rewrote the file before any check
// of the DB side, so a later DB failure reported "rotation failed" while the
// file was already re-encrypted under the new key.
func TestRunRotationPreflightFailureLeavesFileUntouched(t *testing.T) {
	dir := t.TempDir()
	realOld := deriveStateKey("real-old-secret-32-chars-long!!!!")
	sealed, err := encrypt("db-password", realOld)
	if err != nil {
		t.Fatal(err)
	}
	path := writeStateFile(t, dir, map[string]any{"db": map[string]any{"password_cipher": sealed}})
	before, _ := os.ReadFile(path)

	wrongOld := deriveStateKey("wrong-old-secret-32-chars-long!!!")
	newKey := deriveStateKey("brand-new-secret-32-chars-long!!!")
	err = runRotation(path, "wrong-old-secret-32-chars-long!!!", "brand-new-secret-32-chars-long!!!",
		wrongOld, newKey, nil, true, io.Discard)
	if err == nil {
		t.Fatal("expected preflight decrypt failure")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("state file was mutated despite a failed preflight")
	}
}

// openIsolatedTestDB spins up a throw-away database next to TEST_DB_DSN's
// target and drops it on cleanup. rotateDB scans whole tables (every
// is_encrypted secret, all of `users`, all of `api_keys`) so it cannot be
// pointed at the shared fixture DB other packages' tests rely on - a test
// key would neither decrypt nor be allowed to touch those real-shaped rows.
func openIsolatedTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set - skipping DB-backed test")
	}
	base, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := base.Ping(); err != nil {
		base.Close()
		t.Skipf("DB not reachable: %v", err)
	}

	name := fmt.Sprintf("hpg_rotate_secret_test_%d", time.Now().UnixNano())
	if _, err := base.Exec("CREATE DATABASE " + name); err != nil {
		base.Close()
		t.Skipf("cannot create isolated test database (need CREATE privilege): %v", err)
	}
	// DROP before Close - a deferred Close before this point ran at this
	// function's return and left the cleanup below dropping through an
	// already-closed *sql.DB, leaking every isolated test database this
	// ever created.
	t.Cleanup(func() {
		base.Exec("DROP DATABASE IF EXISTS " + name)
		base.Close()
	})

	dbNameRe := regexp.MustCompile(`/[^/?]+(\?|$)`)
	testDSN := dbNameRe.ReplaceAllString(dsn, "/"+name+"$1")
	db, err := sql.Open("mysql", testDSN)
	if err != nil {
		t.Fatalf("sql.Open isolated db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	for _, stmt := range []string{
		"CREATE TABLE settings (`key` VARCHAR(191) PRIMARY KEY, value TEXT NOT NULL, is_encrypted TINYINT(1) NOT NULL DEFAULT 0)",
		"CREATE TABLE users (id BIGINT PRIMARY KEY AUTO_INCREMENT, totp_secret_enc TEXT NULL, totp_pending_secret TEXT NULL, totp_pending_exp DATETIME NULL)",
		"CREATE TABLE api_keys (id BIGINT PRIMARY KEY AUTO_INCREMENT, key_hmac VARCHAR(64) NULL)",
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("schema setup %q: %v", stmt, err)
		}
	}
	return db
}

// HPG-011 end-to-end: if the process dies after the DB half of a rotation
// commits but before the state file is rewritten, re-running the SAME
// command must finish the file step, not fail trying to decrypt DB rows
// that are no longer under --old-secret.
func TestRunRotationResumesAfterDBCommit(t *testing.T) {
	db := openIsolatedTestDB(t)

	const oldSecret = "resume-old-secret-32-chars-long!!"
	const newSecret = "resume-new-secret-32-chars-long!!"
	oldKey := deriveStateKey(oldSecret)
	newKey := deriveStateKey(newSecret)

	testKey := "__rotate_secret_test__"
	sealed, err := encrypt("s3cret-value", oldKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO settings (`key`, value, is_encrypted) VALUES (?, ?, 1)", testKey, sealed); err != nil {
		t.Fatalf("insert test row: %v", err)
	}

	dir := t.TempDir()
	fileSealed, err := encrypt("db-password", oldKey)
	if err != nil {
		t.Fatal(err)
	}
	path := writeStateFile(t, dir, map[string]any{"db": map[string]any{"password_cipher": fileSealed}})

	// Simulate stage 1 having already committed: rotate the DB for real,
	// then drop a journal claiming that, WITHOUT touching the state file -
	// exactly the state a crash between the two writes would leave behind.
	if _, err := rotateDB(db, oldKey, newKey, true); err != nil {
		t.Fatalf("simulated DB rotation: %v", err)
	}
	jPath := journalPath(path)
	if err := writeJournal(jPath, rotateJournal{OldHash: secretHash(oldSecret), NewHash: secretHash(newSecret), Stage: stageDBDone}); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(jPath)

	if err := runRotation(path, oldSecret, newSecret, oldKey, newKey, db, true, io.Discard); err != nil {
		t.Fatalf("resume run failed: %v", err)
	}

	data, _ := os.ReadFile(path)
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	got := m["db"].(map[string]any)["password_cipher"].(string)
	if _, _, err := decEnvelope(got, newKey); err != nil {
		t.Fatalf("state file not rotated to new key: %v", err)
	}
	if _, err := os.Stat(jPath); !os.IsNotExist(err) {
		t.Fatal("journal should be removed once the resumed rotation completes")
	}
}
