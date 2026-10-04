package routes

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type pendingRow struct {
	seq, attempts int64
	lastErr       sql.NullString
	next          time.Time
}

func readPending(t *testing.T, db *sql.DB, nodeID int64) (pendingRow, bool) {
	t.Helper()
	var r pendingRow
	err := db.QueryRow(`SELECT seq, attempts, last_error, next_attempt_at FROM node_push_pending WHERE node_id = ?`, nodeID).
		Scan(&r.seq, &r.attempts, &r.lastErr, &r.next)
	if err == sql.ErrNoRows {
		return r, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return r, true
}

func outboxSvc(db *sql.DB) *Service {
	// An hour-long debounce stands in for a crash: the in-memory push never fires.
	return &Service{DB: db, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), PushDebounceMs: 3600_000}
}

func countingNode(t *testing.T, status int) (*httptest.Server, *atomic.Int32) {
	var loads atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/load" {
			loads.Add(1)
			if status != http.StatusOK {
				http.Error(w, "loading config: boom", status)
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &loads
}

// Commit, then "crash" before the push: the marker survives and the next
// leader's drain delivers it.
func TestOutbox_CrashThenDrain(t *testing.T) {
	db := newPushTestDB(t)
	ctx := context.Background()
	srv, loads := countingNode(t, http.StatusOK)
	nodeID := seedNodeAndRoute(t, db, srv.URL, "crash.example")

	if err := outboxSvc(db).SuspendService(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if _, ok := readPending(t, db, nodeID); !ok {
		t.Fatal("no marker after committed change")
	}
	if loads.Load() != 0 {
		t.Fatal("pushed before crash")
	}

	restarted := outboxSvc(db)
	restarted.DrainPendingPushes(ctx)
	if loads.Load() != 1 {
		t.Fatalf("loads after drain = %d, want 1", loads.Load())
	}
	if _, ok := readPending(t, db, nodeID); ok {
		t.Fatal("marker not cleared after successful push")
	}
}

func TestOutbox_DuplicateRequestsCoalesce(t *testing.T) {
	db := newPushTestDB(t)
	ctx := context.Background()
	srv, loads := countingNode(t, http.StatusOK)
	nodeID := seedNodeAndRoute(t, db, srv.URL, "dup.example")
	svc := outboxSvc(db)

	svc.SchedulePush(nodeID)
	first, _ := readPending(t, db, nodeID)
	svc.SchedulePush(nodeID)
	svc.SchedulePush(nodeID)
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM node_push_pending`).Scan(&n)
	if r, _ := readPending(t, db, nodeID); n != 1 || r.seq != first.seq+2 {
		t.Fatalf("rows=%d seq=%d first=%d", n, r.seq, first.seq)
	}
	svc.DrainPendingPushes(ctx)
	if loads.Load() != 1 {
		t.Fatalf("loads = %d, want 1", loads.Load())
	}
}

// A request that lands while a push is in flight is newer than its snapshot,
// so the push's delete must leave it.
func TestOutbox_NewerRequestSurvivesInflightPush(t *testing.T) {
	db := newPushTestDB(t)
	ctx := context.Background()
	hit, release := make(chan struct{}), make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/load" {
			select {
			case hit <- struct{}{}:
				<-release
			default:
			}
		}
	}))
	defer srv.Close()
	nodeID := seedNodeAndRoute(t, db, srv.URL, "inflight.example")
	svc := outboxSvc(db)
	svc.SchedulePush(nodeID)

	done := make(chan error, 1)
	go func() { done <- svc.Resync(ctx, nodeID) }()
	<-hit
	if err := svc.markPushPending(ctx, db, nodeID); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, ok := readPending(t, db, nodeID); !ok {
		t.Fatal("newer request deleted by the older push")
	}
}

func TestOutbox_FailureBacksOff(t *testing.T) {
	db := newPushTestDB(t)
	ctx := context.Background()
	srv, loads := countingNode(t, http.StatusBadRequest)
	nodeID := seedNodeAndRoute(t, db, srv.URL, "fail.example")
	svc := outboxSvc(db)
	svc.SchedulePush(nodeID)

	svc.DrainPendingPushes(ctx)
	r, ok := readPending(t, db, nodeID)
	if !ok || r.attempts != 1 || !r.lastErr.Valid || !r.next.After(time.Now().Add(20*time.Second)) {
		t.Fatalf("after failure: ok=%v %+v", ok, r)
	}
	svc.DrainPendingPushes(ctx) // not due yet
	if loads.Load() != 1 {
		t.Fatalf("loads = %d, want 1 (backoff ignored)", loads.Load())
	}
	st, _ := svc.NodeApplyStates(ctx, []int64{1})
	if len(st[1]) != 1 || st[1][0].Attempts != 1 {
		t.Fatalf("attempts not visible: %+v", st[1])
	}

	// Due again: the second failure doubles the delay.
	if _, err := db.Exec(`UPDATE node_push_pending SET next_attempt_at = ?`, time.Now().UTC().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	svc.DrainPendingPushes(ctx)
	r, _ = readPending(t, db, nodeID)
	if r.attempts != 2 || !r.next.After(time.Now().Add(50*time.Second)) {
		t.Fatalf("second failure: %+v", r)
	}
}

func TestOutbox_FollowerDoesNotDrain(t *testing.T) {
	db := newPushTestDB(t)
	ctx := context.Background()
	srv, loads := countingNode(t, http.StatusOK)
	nodeID := seedNodeAndRoute(t, db, srv.URL, "follower.example")
	svc := outboxSvc(db)
	svc.IsLeader = func() bool { return false }
	svc.SchedulePush(nodeID)

	svc.DrainPendingPushes(ctx)
	if loads.Load() != 0 {
		t.Fatal("follower drained")
	}
	if _, ok := readPending(t, db, nodeID); !ok {
		t.Fatal("follower touched the marker")
	}
}
