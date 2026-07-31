package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
)

// insertEpochTestUser creates an admin user and returns id + cleanup.
func insertEpochTestUser(t *testing.T, db *sql.DB, role string) (int64, string, func()) {
	t.Helper()
	email := fmt.Sprintf("epochtest_%d@example.com", time.Now().UnixNano())
	res, err := db.ExecContext(context.Background(),
		`INSERT INTO users (email, password_hash, role, is_active) VALUES (?, 'x', ?, 1)`, email, role)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	id, _ := res.LastInsertId()
	return id, email, func() { _, _ = db.ExecContext(context.Background(), "DELETE FROM users WHERE id = ?", id) }
}

func epochTestHandlers(db *sql.DB) *AuthHandlers {
	return &AuthHandlers{
		DB:     func() *sql.DB { return db },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// A pre-issued 2FA ticket must not mint a session after the user is deleted:
// the missing row is an explicit denial, never a permissive default.
func TestClaimsForPending_DeletedUserDenied(t *testing.T) {
	db := openTestDBHandlers(t)
	id, email, cleanup := insertEpochTestUser(t, db, "admin")
	ctx := context.Background()

	epoch, err := auth.UserEpoch(ctx, db, id)
	if err != nil {
		t.Fatalf("user epoch: %v", err)
	}
	pend := pending2FA{UserID: id, Email: email, Role: "admin", Epoch: epoch}
	cleanup() // user deleted while the challenge was outstanding

	h := epochTestHandlers(db)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/2fa", nil)
	if _, ok := h.claimsForPending(ctx, rr, req, pend); ok {
		t.Fatal("deleted user completed 2FA")
	}
	if rr.Code != http.StatusSeeOther {
		t.Errorf("want redirect to login, got %d", rr.Code)
	}

	// And the scope lookup must not map the missing row to a global admin.
	if _, err := loadSessionClaims(ctx, db, id); !errors.Is(err, auth.ErrUserGone) {
		t.Errorf("want ErrUserGone for a missing user, got %v", err)
	}
}

// A demotion during the challenge must invalidate the ticket, and the fresh
// read must carry the new lower role.
func TestClaimsForPending_DemotedUser(t *testing.T) {
	db := openTestDBHandlers(t)
	id, email, cleanup := insertEpochTestUser(t, db, "super_admin")
	defer cleanup()
	ctx := context.Background()

	epoch, _ := auth.UserEpoch(ctx, db, id)
	pend := pending2FA{UserID: id, Email: email, Role: "super_admin", Epoch: epoch}

	// Demotion the way the admin handler does it: role change + epoch bump.
	if _, err := db.ExecContext(ctx,
		"UPDATE users SET role = 'support', auth_epoch = auth_epoch + 1 WHERE id = ?", id); err != nil {
		t.Fatalf("demote: %v", err)
	}

	h := epochTestHandlers(db)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/2fa", nil)
	if _, ok := h.claimsForPending(ctx, rr, req, pend); ok {
		t.Fatal("stale ticket accepted after demotion")
	}

	// A ticket issued after the demotion carries the new role, never the cached one.
	fresh, err := loadSessionClaims(ctx, db, id)
	if err != nil {
		t.Fatalf("load claims: %v", err)
	}
	if fresh.Role != "support" {
		t.Errorf("want role support from the fresh read, got %q", fresh.Role)
	}
	if fresh.Epoch == epoch {
		t.Error("epoch did not move on demotion")
	}
	pend.Epoch = fresh.Epoch
	got, ok := h.claimsForPending(ctx, httptest.NewRecorder(), req, pend)
	if !ok {
		t.Fatal("current ticket rejected")
	}
	if got.Role != "support" {
		t.Errorf("session would be minted with role %q", got.Role)
	}
}

// A deactivated user must not complete an outstanding challenge either.
func TestClaimsForPending_DeactivatedUserDenied(t *testing.T) {
	db := openTestDBHandlers(t)
	id, email, cleanup := insertEpochTestUser(t, db, "admin")
	defer cleanup()
	ctx := context.Background()

	epoch, _ := auth.UserEpoch(ctx, db, id)
	if _, err := db.ExecContext(ctx, "UPDATE users SET is_active = 0 WHERE id = ?", id); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	h := epochTestHandlers(db)
	if _, ok := h.claimsForPending(ctx, httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/auth/2fa", nil),
		pending2FA{UserID: id, Email: email, Role: "admin", Epoch: epoch}); ok {
		t.Fatal("deactivated user completed 2FA")
	}
}
