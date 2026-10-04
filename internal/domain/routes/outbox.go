package routes

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

// Durable push markers (node_push_pending). Pushes are full-config and
// idempotent, so "node X needs a push" is the whole outbox: one row per node.

const (
	pendingBackoffBase = 30 * time.Second
	pendingBackoffCap  = 15 * time.Minute
	// pendingGrace exceeds the 30s push timeout, so a fresh marker is only due if its push never finished.
	pendingGrace = 45 * time.Second
)

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func outboxNow() time.Time { return time.Now().UTC().Truncate(time.Second) }

// markPushPending upserts the marker for each node. Pass the write's tx so the
// marker commits (or rolls back) with the change itself.
func (s *Service) markPushPending(ctx context.Context, ex execer, nodeIDs ...int64) error {
	// Due only after the fast path had its chance: the drain is for crashes and
	// failures, and racing another replica's debounced push could land an older /load last.
	q := `INSERT INTO node_push_pending (node_id, seq, requested_at, next_attempt_at) VALUES (?, 1, ?, ?) `
	if store.Driver() == "sqlite3" {
		q += `ON CONFLICT(node_id) DO UPDATE SET seq=seq+1, requested_at=excluded.requested_at, next_attempt_at=excluded.next_attempt_at`
	} else {
		q += `ON DUPLICATE KEY UPDATE seq=seq+1, requested_at=VALUES(requested_at), next_attempt_at=VALUES(next_attempt_at)`
	}
	now := outboxNow()
	due := now.Add(time.Duration(s.PushDebounceMs)*time.Millisecond + pendingGrace)
	// Ascending order: concurrent transactions lock marker rows in the same order (no 1213).
	ids := append([]int64(nil), nodeIDs...)
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for i, id := range ids {
		if id == 0 || (i > 0 && id == ids[i-1]) {
			continue
		}
		if _, err := ex.ExecContext(ctx, q, id, now, due); err != nil {
			return err
		}
	}
	return nil
}

// pendingSeq reads the marker's seq before a snapshot is built; 0 = none.
func (s *Service) pendingSeq(ctx context.Context, nodeID int64) int64 {
	var seq int64
	if err := s.DB.QueryRowContext(ctx,
		`SELECT seq FROM node_push_pending WHERE node_id = ?`, nodeID).Scan(&seq); err != nil && !errors.Is(err, sql.ErrNoRows) && s.Logger != nil {
		s.Logger.Warn("push marker read failed", "node_id", nodeID, "err", err)
	}
	return seq
}

// settlePending records that the snapshot built at seq is live (pushed_seq only
// moves forward), or backs the next drain attempt off when the push failed.
func (s *Service) settlePending(ctx context.Context, nodeID, seq int64, pushErr error) {
	if s.DB == nil {
		return
	}
	var err error
	if pushErr == nil {
		_, err = s.DB.ExecContext(ctx,
			`UPDATE node_push_pending SET pushed_seq = ?, attempts = 0, last_error = NULL
			  WHERE node_id = ? AND pushed_seq < ?`, seq, nodeID, seq)
	} else {
		var attempts int
		if s.DB.QueryRowContext(ctx,
			`SELECT attempts FROM node_push_pending WHERE node_id = ? AND seq > pushed_seq`, nodeID).Scan(&attempts) != nil {
			return // nothing pending: the caller (drift, boot push) retries on its own
		}
		attempts++
		backoff := pendingBackoffCap
		if attempts < 10 && pendingBackoffBase<<(attempts-1) < pendingBackoffCap {
			backoff = pendingBackoffBase << (attempts - 1)
		}
		msg := pushErr.Error()
		if len(msg) > maxApplyErrLen {
			msg = strings.ToValidUTF8(msg[:maxApplyErrLen], "")
		}
		_, err = s.DB.ExecContext(ctx,
			`UPDATE node_push_pending SET attempts = ?, last_error = ?, next_attempt_at = ? WHERE node_id = ?`,
			attempts, msg, outboxNow().Add(backoff), nodeID)
	}
	if err != nil && s.Logger != nil {
		s.Logger.Warn("push marker not settled", "node_id", nodeID, "err", err)
	}
}

// DrainPendingPushes pushes every enabled node whose marker is due. Leader
// only: a follower draining would double every push.
func (s *Service) DrainPendingPushes(ctx context.Context) {
	if s.DB == nil || (s.IsLeader != nil && !s.IsLeader()) {
		return
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT p.node_id FROM node_push_pending p JOIN caddy_nodes n ON n.id = p.node_id
		  WHERE n.is_enabled = 1 AND p.seq > p.pushed_seq AND p.next_attempt_at <= ?`, outboxNow())
	if err != nil {
		s.Logger.Warn("push drain: list markers", "err", err)
		return
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	if len(ids) == 0 {
		return
	}
	s.pushNodesConcurrent(ctx, ids, "pending push drain")
	if s.AfterPush != nil {
		s.AfterPush(ctx)
	}
}

// DropPushMarker removes a deleted node's marker. SQLite runs without
// foreign_keys, so the CASCADE is inert and a reused node id would inherit it.
func DropPushMarker(ctx context.Context, ex execer, nodeID int64) {
	_, _ = ex.ExecContext(ctx, `DELETE FROM node_push_pending WHERE node_id = ?`, nodeID)
}
