package routes

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/host-yt/caddy-proxy-manager/internal/store"
)

// Durable push markers (node_push_pending). Pushes are full-config and
// idempotent, so "node X needs a push" is the whole outbox: one row per node.

const (
	pendingBackoffBase = 30 * time.Second
	pendingBackoffCap  = 15 * time.Minute
)

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func outboxNow() time.Time { return time.Now().UTC().Truncate(time.Second) }

// markPushPending upserts the marker for each node. Pass the write's tx so the
// marker commits (or rolls back) with the change itself.
func (s *Service) markPushPending(ctx context.Context, ex execer, nodeIDs ...int64) error {
	// A fresh row starts at wall-clock nanos, not 1, so a re-created marker
	// never matches a seq read by another replica's push before the delete.
	q := `INSERT INTO node_push_pending (node_id, seq, requested_at, next_attempt_at) VALUES (?, ?, ?, ?) `
	if store.Driver() == "sqlite3" {
		q += `ON CONFLICT(node_id) DO UPDATE SET seq=seq+1, requested_at=excluded.requested_at, next_attempt_at=excluded.next_attempt_at`
	} else {
		q += `ON DUPLICATE KEY UPDATE seq=seq+1, requested_at=VALUES(requested_at), next_attempt_at=VALUES(next_attempt_at)`
	}
	now := outboxNow()
	for _, id := range nodeIDs {
		if id == 0 {
			continue
		}
		if _, err := ex.ExecContext(ctx, q, id, time.Now().UnixNano(), now, now); err != nil {
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

// settlePending clears the marker after a successful /load, but only up to the
// seq the snapshot covered; on failure it backs the next drain attempt off.
func (s *Service) settlePending(ctx context.Context, nodeID, seq int64, loadErr error) {
	if s.DB == nil {
		return
	}
	var err error
	if loadErr == nil {
		_, err = s.DB.ExecContext(ctx,
			`DELETE FROM node_push_pending WHERE node_id = ? AND seq <= ?`, nodeID, seq)
	} else {
		var attempts int
		if s.DB.QueryRowContext(ctx,
			`SELECT attempts FROM node_push_pending WHERE node_id = ?`, nodeID).Scan(&attempts) != nil {
			return // no marker: the caller (drift, boot push) retries on its own
		}
		attempts++
		backoff := pendingBackoffCap
		if attempts < 10 && pendingBackoffBase<<(attempts-1) < pendingBackoffCap {
			backoff = pendingBackoffBase << (attempts - 1)
		}
		msg := loadErr.Error()
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
		  WHERE n.is_enabled = 1 AND p.next_attempt_at <= ?`, outboxNow())
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
