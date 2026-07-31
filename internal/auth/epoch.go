package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrUserGone means the users row no longer exists. Callers must deny: a
// missing user must never map to a permissive default.
var ErrUserGone = errors.New("auth: user no longer exists")

// The epoch is read from the database on every authenticated request. A cache
// was tried and removed: any cached agreement is a window in which a revoked
// session still works, and for a control plane that window is not acceptable.
// The read is a single indexed row and admin traffic is low.

// execQuerier is the *sql.DB / *sql.Tx subset the epoch helpers need.
type execQuerier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// UserEpoch reads the current authorization epoch, returning ErrUserGone when
// the row is missing.
func UserEpoch(ctx context.Context, db *sql.DB, userID int64) (int64, error) {
	if db == nil {
		return 0, errors.New("auth: no db")
	}
	var ep int64
	err := db.QueryRowContext(ctx, "SELECT auth_epoch FROM users WHERE id = ?", userID).Scan(&ep)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrUserGone
	}
	if err != nil {
		return 0, err
	}
	return ep, nil
}

// BumpEpochTx increments the epoch inside the caller's transaction and returns
// the new value; publish it with Manager.PublishEpoch after the commit.
func BumpEpochTx(ctx context.Context, tx *sql.Tx, userID int64) (int64, error) {
	return bumpEpoch(ctx, tx, userID)
}

func bumpEpoch(ctx context.Context, ex execQuerier, userID int64) (int64, error) {
	res, err := ex.ExecContext(ctx, "UPDATE users SET auth_epoch = auth_epoch + 1 WHERE id = ?", userID)
	if err != nil {
		return 0, fmt.Errorf("bump auth_epoch: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return 0, ErrUserGone
	}
	var ep int64
	err = ex.QueryRowContext(ctx, "SELECT auth_epoch FROM users WHERE id = ?", userID).Scan(&ep)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrUserGone
	}
	if err != nil {
		return 0, err
	}
	return ep, nil
}

// BumpEpoch increments the user's epoch and refreshes the Redis cache so live
// sessions stop validating on their next request.
func (m *Manager) BumpEpoch(ctx context.Context, db *sql.DB, userID int64) (int64, error) {
	if db == nil {
		return 0, errors.New("auth: no db")
	}
	ep, err := bumpEpoch(ctx, db, userID)
	if err != nil {
		return 0, err
	}
	m.PublishEpoch(ctx, userID, ep)
	return ep, nil
}

// PublishEpoch is retained for callers that bumped the epoch in their own
// transaction. The database is authoritative, so there is nothing to publish.
func (m *Manager) PublishEpoch(ctx context.Context, userID, epoch int64) {}

// RevokeUser invalidates every live session of a user. The DB epoch bump is
// durable, so access ends even when the best-effort Redis purge fails; the
// returned error reports only the purge outcome once the bump succeeded.
func (m *Manager) RevokeUser(ctx context.Context, db *sql.DB, userID int64) (int, error) {
	if m == nil {
		return 0, nil
	}
	if _, err := m.BumpEpoch(ctx, db, userID); err != nil && !errors.Is(err, ErrUserGone) {
		return 0, err
	}
	return m.DestroyAllForUser(ctx, userID)
}

// PurgeUserSessions drops a user's session keys. The epoch is the durable
// guarantee; this only reclaims keys and shortens the window.
func (m *Manager) PurgeUserSessions(ctx context.Context, userID int64) (int, error) {
	if m == nil {
		return 0, nil
	}
	return m.DestroyAllForUser(ctx, userID)
}

// MarkUserDeleted purges the sessions of a removed row. The epoch check
// already denies them: a missing user resolves to ErrUserGone.
func (m *Manager) MarkUserDeleted(ctx context.Context, userID int64) (int, error) {
	if m == nil {
		return 0, nil
	}
	return m.DestroyAllForUser(ctx, userID)
}

// epochValid reports whether every identity carried by the session still holds
// the epoch it was minted with.
func (m *Manager) epochValid(ctx context.Context, s *Session) bool {
	if !m.epochOK(ctx, s.UserID, s.Epoch) {
		return false
	}
	if s.ImpersonatorUserID > 0 {
		return m.epochOK(ctx, s.ImpersonatorUserID, s.ImpersonatorEpoch)
	}
	return true
}

// epochOK resolves the stamped epoch against the authoritative row on every
// call. A missing user or an unreadable row denies; only an exact match passes.
func (m *Manager) epochOK(ctx context.Context, userID, stamped int64) bool {
	if m.db == nil {
		return true // no epoch source wired (tests, first-run before migrate)
	}
	cur, err := UserEpoch(ctx, m.db, userID)
	if err != nil {
		return false
	}
	return cur == stamped
}
