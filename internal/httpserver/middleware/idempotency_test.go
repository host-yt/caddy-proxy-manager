package middleware

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

// newIdemTestDB builds the idempotency_keys table on SQLite, using the store's
// SQLite function shims so NOW() and the date arithmetic behave as in MariaDB.
func newIdemTestDB(t *testing.T) *sql.DB {
	t.Helper()
	prev := store.Driver()
	store.SetDriver("sqlite3")
	t.Cleanup(func() { store.SetDriver(prev) })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	db, err := store.Open(ctx, "sqlite3", t.TempDir()+"/idem.db", 5*time.Second)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE TABLE idempotency_keys (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		idem_key TEXT NOT NULL,
		user_id INTEGER NOT NULL,
		method TEXT NOT NULL DEFAULT 'POST',
		path TEXT NOT NULL,
		body_hash TEXT NOT NULL DEFAULT '',
		state INTEGER NOT NULL DEFAULT 0,
		response_status INTEGER NULL,
		response_body TEXT NULL,
		response_headers TEXT NULL,
		created_at TIMESTAMP NULL,
		expires_at TIMESTAMP NOT NULL,
		UNIQUE (idem_key, user_id))`); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return db
}

// idemRequest runs one request through the middleware, counting handler runs.
func idemRequest(t *testing.T, db func() *sql.DB, key string, calls *int) *httptest.ResponseRecorder {
	t.Helper()
	h := Idempotency(db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(`{"domain":"a.example"}`))
	req.Header.Set("Idempotency-Key", key)
	req = req.WithContext(context.WithValue(req.Context(), apiCallerKey, &APICaller{UserID: 1, KeyID: 1, Role: "admin"}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestIdempotency_ReplaysStoredResponse(t *testing.T) {
	db := newIdemTestDB(t)
	get := func() *sql.DB { return db }
	calls := 0

	first := idemRequest(t, get, "key-1", &calls)
	if first.Code != http.StatusCreated || calls != 1 {
		t.Fatalf("first: status %d, calls %d", first.Code, calls)
	}
	second := idemRequest(t, get, "key-1", &calls)
	if calls != 1 {
		t.Errorf("handler ran again on replay: calls = %d", calls)
	}
	if second.Header().Get("X-Idempotency-Replayed") != "true" {
		t.Errorf("replay header missing: %v", second.Header())
	}
	if second.Body.String() != `{"ok":true}` {
		t.Errorf("replayed body = %q", second.Body.String())
	}
}

// The reservation is what makes the dedupe real. If it cannot be written, the
// middleware used to run the handler anyway - executing a mutation the caller
// explicitly asked to be deduped, and executing it again on every retry.
func TestIdempotency_FailsClosedWhenStoreUnavailable(t *testing.T) {
	db := newIdemTestDB(t)
	if _, err := db.Exec(`DROP TABLE idempotency_keys`); err != nil {
		t.Fatalf("drop: %v", err)
	}
	calls := 0
	rec := idemRequest(t, func() *sql.DB { return db }, "key-2", &calls)
	if calls != 0 {
		t.Errorf("handler ran with no reservation: calls = %d", calls)
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
}

// An expired row must not block the key forever, and must not let the request
// run unprotected either: it is reclaimed for the new request.
func TestIdempotency_ReclaimsExpiredRow(t *testing.T) {
	db := newIdemTestDB(t)
	get := func() *sql.DB { return db }
	calls := 0

	if rec := idemRequest(t, get, "key-3", &calls); rec.Code != http.StatusCreated {
		t.Fatalf("first: status %d", rec.Code)
	}
	if _, err := db.Exec(`UPDATE idempotency_keys SET expires_at = datetime('now', '-1 hour')`); err != nil {
		t.Fatalf("expire: %v", err)
	}
	rec := idemRequest(t, get, "key-3", &calls)
	if rec.Code != http.StatusCreated || calls != 2 {
		t.Fatalf("expired key: status %d, calls %d (want 201, 2)", rec.Code, calls)
	}
	var state int
	if err := db.QueryRow(`SELECT state FROM idempotency_keys WHERE user_id = 1`).Scan(&state); err != nil {
		t.Fatalf("read row: %v", err)
	}
	if state != idemStateDone {
		t.Errorf("reclaimed row state = %d, want done", state)
	}
}

// A key reused for a different body is a client error, never a replay.
func TestIdempotency_RejectsKeyReuseForDifferentRequest(t *testing.T) {
	db := newIdemTestDB(t)
	get := func() *sql.DB { return db }
	calls := 0
	if rec := idemRequest(t, get, "key-4", &calls); rec.Code != http.StatusCreated {
		t.Fatalf("first: status %d", rec.Code)
	}

	h := Idempotency(get)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusCreated)
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(`{"domain":"other.example"}`))
	req.Header.Set("Idempotency-Key", "key-4")
	req = req.WithContext(context.WithValue(req.Context(), apiCallerKey, &APICaller{UserID: 1, KeyID: 1, Role: "admin"}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", rec.Code)
	}
	if calls != 1 {
		t.Errorf("handler ran for the mismatched body: calls = %d", calls)
	}
}
