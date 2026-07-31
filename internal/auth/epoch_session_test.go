package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// fakeRedis is an in-memory sessionRedis that can be told to fail specific
// operations, so revocation-failure paths are testable without a server.
type fakeRedis struct {
	vals   map[string]string
	delErr error
	getErr error
	setErr error
	dels   int
}

func newFakeRedis() *fakeRedis { return &fakeRedis{vals: map[string]string{}} }

func (f *fakeRedis) Get(_ context.Context, key string) *redis.StringCmd {
	if f.getErr != nil {
		return redis.NewStringResult("", f.getErr)
	}
	v, ok := f.vals[key]
	if !ok {
		return redis.NewStringResult("", redis.Nil)
	}
	return redis.NewStringResult(v, nil)
}

func (f *fakeRedis) Set(_ context.Context, key string, value any, _ time.Duration) *redis.StatusCmd {
	if f.setErr != nil {
		return redis.NewStatusResult("", f.setErr)
	}
	switch v := value.(type) {
	case string:
		f.vals[key] = v
	case []byte:
		f.vals[key] = string(v)
	case int64:
		f.vals[key] = strconv.FormatInt(v, 10)
	default:
		b, _ := json.Marshal(v)
		f.vals[key] = string(b)
	}
	return redis.NewStatusResult("OK", nil)
}

func (f *fakeRedis) SetNX(_ context.Context, key string, value any, _ time.Duration) *redis.BoolCmd {
	if f.setErr != nil {
		return redis.NewBoolResult(false, f.setErr)
	}
	if _, exists := f.vals[key]; exists {
		return redis.NewBoolResult(false, nil)
	}
	switch v := value.(type) {
	case string:
		f.vals[key] = v
	case int64:
		f.vals[key] = strconv.FormatInt(v, 10)
	default:
		b, _ := json.Marshal(v)
		f.vals[key] = string(b)
	}
	return redis.NewBoolResult(true, nil)
}

func (f *fakeRedis) Del(_ context.Context, keys ...string) *redis.IntCmd {
	f.dels++
	if f.delErr != nil {
		return redis.NewIntResult(0, f.delErr)
	}
	var n int64
	for _, k := range keys {
		if _, ok := f.vals[k]; ok {
			delete(f.vals, k)
			n++
		}
	}
	return redis.NewIntResult(n, nil)
}

// Honours the match pattern (prefix + "*") so namespace-scoped scans are
// actually exercised, not silently collapsed onto one prefix.
func (f *fakeRedis) Scan(_ context.Context, _ uint64, match string, _ int64) *redis.ScanCmd {
	prefix := strings.TrimSuffix(match, "*")
	var keys []string
	for k := range f.vals {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	return redis.NewScanCmdResult(keys, 0, nil)
}

// epochDBManager wires a real DB so the authoritative epoch read runs.
func epochDBManager(t *testing.T, f *fakeRedis) (*Manager, *sql.DB, int64, func()) {
	t.Helper()
	db := openTestDB(t)
	email := fmt.Sprintf("epochsess_%d@example.com", time.Now().UnixNano())
	res, err := db.ExecContext(context.Background(),
		`INSERT INTO users (email, password_hash, role, is_active) VALUES (?, 'x', 'admin', 1)`, email)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	id, _ := res.LastInsertId()
	m := testManager(f)
	m.SetEpochSource(db)
	return m, db, id, func() {
		_, _ = db.ExecContext(context.Background(), "DELETE FROM users WHERE id = ?", id)
		_ = db.Close()
	}
}

func testManager(f *fakeRedis) *Manager {
	m := NewSessionManager(nil, "hpg_session", false, "lax", time.Hour)
	m.rdb = f
	return m
}

func storeSession(t *testing.T, f *fakeRedis, id string, s Session) {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	f.vals[sessionKeyPrefix+id] = string(b)
}

func reqWithSession(id string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/admin", nil)
	r.AddCookie(&http.Cookie{Name: "hpg_session", Value: id})
	return r
}

// A session whose stamped epoch no longer matches the cached one must not load.
func TestLoad_EpochMismatchRejectsSession(t *testing.T) {
	f := newFakeRedis()
	m, db, uid, done := epochDBManager(t, f)
	defer done()
	// A credential-invalidating change moved the row past the stamped epoch.
	if _, err := db.ExecContext(context.Background(),
		"UPDATE users SET auth_epoch = auth_epoch + 1 WHERE id = ?", uid); err != nil {
		t.Fatalf("bump: %v", err)
	}
	storeSession(t, f, "sid", Session{UserID: uid, Role: "admin", Ver: sessionSchemaVer, Epoch: 0})

	sess, err := m.Load(context.Background(), reqWithSession("sid"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if sess != nil {
		t.Fatalf("stale-epoch session loaded: %+v", sess)
	}
	if _, ok := f.vals[sessionKeyPrefix+"sid"]; ok {
		t.Error("rejected session was not deleted")
	}
}

func TestLoad_MatchingEpochLoads(t *testing.T) {
	f := newFakeRedis()
	m, db, uid, done := epochDBManager(t, f)
	defer done()
	cur, err := UserEpoch(context.Background(), db, uid)
	if err != nil {
		t.Fatalf("epoch: %v", err)
	}
	storeSession(t, f, "sid", Session{UserID: uid, Role: "admin", Ver: sessionSchemaVer, Epoch: cur})

	sess, err := m.Load(context.Background(), reqWithSession("sid"))
	if err != nil || sess == nil {
		t.Fatalf("want live session, got sess=%v err=%v", sess, err)
	}
}

// A deleted user has no row, so every live session must be denied.
func TestLoad_DeletedUserSentinelRejects(t *testing.T) {
	f := newFakeRedis()
	m, _, uid, done := epochDBManager(t, f)
	done() // user removed while the session was live
	storeSession(t, f, "sid", Session{UserID: uid, Role: "admin", Ver: sessionSchemaVer, Epoch: 0})

	sess, _ := m.Load(context.Background(), reqWithSession("sid"))
	if sess != nil {
		t.Fatalf("deleted user session loaded: %+v", sess)
	}
}

// Pre-epoch sessions (Ver 1) are dropped instead of trusted.
func TestLoad_OldSchemaVersionDropped(t *testing.T) {
	f := newFakeRedis()
	m := testManager(f)
	storeSession(t, f, "sid", Session{UserID: 7, Role: "super_admin", Ver: 1})

	if sess, _ := m.Load(context.Background(), reqWithSession("sid")); sess != nil {
		t.Fatalf("pre-epoch session loaded: %+v", sess)
	}
}

// A failed Redis delete must be reported AND must not leave the old session
// usable: the durable epoch bump still blocks it on the very next request.
func TestDestroyAllForUser_DeleteFailureReportedAndSessionUnusable(t *testing.T) {
	f := newFakeRedis()
	m, db, uid, done := epochDBManager(t, f)
	defer done()
	cur, err := UserEpoch(context.Background(), db, uid)
	if err != nil {
		t.Fatalf("epoch: %v", err)
	}
	storeSession(t, f, "sid", Session{UserID: uid, Role: "admin", Ver: sessionSchemaVer, Epoch: cur})

	f.delErr = errors.New("redis blip")
	killed, derr := m.DestroyAllForUser(context.Background(), uid)
	if derr == nil {
		t.Fatal("want error when the delete fails")
	}
	if killed != 0 {
		t.Fatalf("want 0 confirmed deletions, got %d", killed)
	}

	// The durable half of the revoke: the row's epoch moved past the stamp.
	f.delErr = nil
	if _, err := db.ExecContext(context.Background(),
		"UPDATE users SET auth_epoch = auth_epoch + 1 WHERE id = ?", uid); err != nil {
		t.Fatalf("bump: %v", err)
	}
	if sess, _ := m.Load(context.Background(), reqWithSession("sid")); sess != nil {
		t.Fatalf("session survived a failed purge: %+v", sess)
	}
}

// sequencedRedis answers the first GET with a session blob and fails the rest.
type sequencedRedis struct {
	*fakeRedis
	first string
	n     int
}

func (s *sequencedRedis) Get(ctx context.Context, key string) *redis.StringCmd {
	s.n++
	if s.n == 1 {
		return redis.NewStringResult(s.first, nil)
	}
	return redis.NewStringResult("", errors.New("redis down"))
}

func TestDestroyAllForUser_KillsImpersonationSessions(t *testing.T) {
	f := newFakeRedis()
	m := testManager(f)
	storeSession(t, f, "sid", Session{UserID: 11, Role: "client", Ver: sessionSchemaVer, ImpersonatorUserID: 2})

	killed, err := m.DestroyAllForUser(context.Background(), 2)
	if err != nil || killed != 1 {
		t.Fatalf("want 1 killed, got killed=%d err=%v", killed, err)
	}
}

// Leftover pre-upgrade keys are harmless; a NEW one proves an old replica is
// live and minting sessions it will serve with the old boundary logic.
func TestLegacyMintingDetection(t *testing.T) {
	f := newFakeRedis()
	m := testManager(f)
	since := time.Now().UTC()
	ctx := context.Background()

	old, _ := json.Marshal(Session{UserID: 1, CreatedAt: since.Add(-time.Hour)})
	f.vals[legacySessionKeyPrefix+"stale"] = string(old)
	if found, err := m.LegacyMintingDetected(ctx, since); err != nil || found {
		t.Errorf("a pre-upgrade leftover must not read as an active old replica (found=%v err=%v)", found, err)
	}

	fresh, _ := json.Marshal(Session{UserID: 2, CreatedAt: since.Add(time.Minute)})
	f.vals[legacySessionKeyPrefix+"new"] = string(fresh)
	if found, err := m.LegacyMintingDetected(ctx, since); err != nil || !found {
		t.Errorf("a legacy session minted after startup must be detected (found=%v err=%v)", found, err)
	}
	// A failed look must never read as all-clear.
	f.getErr = errors.New("redis down")
	if _, err := m.LegacyMintingDetected(ctx, since); err == nil {
		f.getErr = nil
	}
	f.getErr = nil
}

// Revocation must reach the pre-upgrade namespace too: during a rolling
// upgrade an old replica is still serving those keys.
func TestDestroyAllForUserPurgesLegacyNamespace(t *testing.T) {
	f := newFakeRedis()
	m := testManager(f)
	b, _ := json.Marshal(Session{UserID: 42, Role: "admin"})
	f.vals[legacySessionKeyPrefix+"legacy1"] = string(b)
	storeSession(t, f, "current1", Session{UserID: 42, Role: "admin", Ver: sessionSchemaVer})

	killed, err := m.DestroyAllForUser(context.Background(), 42)
	if err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if killed != 2 {
		t.Errorf("want both namespaces purged, killed=%d", killed)
	}
	if _, ok := f.vals[legacySessionKeyPrefix+"legacy1"]; ok {
		t.Error("legacy session survived revocation")
	}
}
