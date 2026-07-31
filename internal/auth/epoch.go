package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// ErrUserGone means the users row no longer exists. Callers must deny: a
// missing user must never map to a permissive default.
var ErrUserGone = errors.New("auth: user no longer exists")

// epochKeyPrefix caches users.auth_epoch so the per-request check costs a
// Redis GET instead of a DB round-trip.
const epochKeyPrefix = "hpg:uepoch:"

// epochCacheTTL bounds how long a lost invalidation can go unnoticed. The
// cache is best-effort, so a dropped SET must decay into a cache miss (which
// re-reads the DB) rather than linger as agreement for the session's lifetime.
// Costs one DB read per active user per interval, not per request.
const epochCacheTTL = 30 * time.Second

// epochDeleted is cached for a user whose row was removed; it can never equal
// a stamped epoch (those are >= 0), so every live session fails the check.
const epochDeleted = int64(-1)

func epochKey(userID int64) string { return epochKeyPrefix + strconv.FormatInt(userID, 10) }

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

// PublishEpoch refreshes the cached epoch after a bump.
func (m *Manager) PublishEpoch(ctx context.Context, userID, epoch int64) {
	_ = m.confirmEpoch(ctx, userID, epoch)
}

// confirmEpoch writes the epoch and reports whether Redis acknowledged it.
// An unacknowledged write must not leave a stale entry readable as agreement:
// the key is dropped, this process marks the user unresolved, and epochCacheTTL
// caps how long any other replica can keep trusting its copy.
func (m *Manager) confirmEpoch(ctx context.Context, userID, epoch int64) bool {
	if m == nil || m.rdb == nil {
		return false
	}
	if err := m.rdb.Set(ctx, epochKey(userID), epoch, epochCacheTTL).Err(); err != nil {
		m.rdb.Del(ctx, epochKey(userID))
		m.epochUnresolved.Store(userID, struct{}{})
		return false
	}
	m.epochUnresolved.Delete(userID)
	return true
}

// fillEpoch caches a value read from the DB without clobbering an existing
// entry: a request that read a pre-revoke epoch must never overwrite the newer
// value a concurrent bump already confirmed.
func (m *Manager) fillEpoch(ctx context.Context, userID, epoch int64) {
	if m == nil || m.rdb == nil {
		return
	}
	m.rdb.SetNX(ctx, epochKey(userID), epoch, epochCacheTTL)
}

// epochPending reports an invalidation this process could not confirm.
func (m *Manager) epochPending(userID int64) bool {
	_, pending := m.epochUnresolved.Load(userID)
	return pending
}

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

// MarkUserDeleted poisons the epoch cache for a row that no longer exists so
// no live session can validate against a missing user.
func (m *Manager) MarkUserDeleted(ctx context.Context, userID int64) (int, error) {
	if m == nil {
		return 0, nil
	}
	m.PublishEpoch(ctx, userID, epochDeleted)
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

// epochOK checks the stamped epoch against the Redis cache; only a miss or a
// mismatch pays a DB read, so the hot path stays at one GET.
func (m *Manager) epochOK(ctx context.Context, userID, stamped int64) bool {
	if m.rdb == nil {
		return m.epochOKFromDB(ctx, userID, stamped, true)
	}
	// An invalidation we could not confirm means the cache may still hold the
	// pre-revoke value: never read that as agreement.
	if m.epochPending(userID) {
		return m.epochOKFromDB(ctx, userID, stamped, false)
	}
	cached, err := m.rdb.Get(ctx, epochKey(userID)).Int64()
	switch {
	case err == nil && cached == stamped:
		return true
	case err == nil:
		return m.epochOKFromDB(ctx, userID, stamped, false)
	case isRedisMiss(err):
		return m.epochOKFromDB(ctx, userID, stamped, true)
	default:
		return false // Redis trouble: fail closed, the user re-authenticates
	}
}

// epochOKFromDB resolves the check against the authoritative row. cacheMissing
// says the cache had nothing, which is the only case where an unwired DB may
// keep the session (nothing has been revoked that we could have missed).
func (m *Manager) epochOKFromDB(ctx context.Context, userID, stamped int64, cacheMissing bool) bool {
	if m.db == nil {
		return cacheMissing
	}
	cur, err := UserEpoch(ctx, m.db, userID)
	if errors.Is(err, ErrUserGone) {
		m.confirmEpoch(ctx, userID, epochDeleted)
		return false
	}
	if err != nil {
		return false
	}
	m.fillEpoch(ctx, userID, cur)
	return cur == stamped
}
