package handlers

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/host-yt/caddy-proxy-manager/internal/auth"
)

func TestRecoveryCodeSingleUseUnderConcurrency(t *testing.T) {
	db := openTestDBHandlers(t)
	uid, cleanup := insertPendingTOTPUser(t, db, "x")
	defer cleanup()
	hash, err := auth.HashPassword("abcd-efgh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)", uid, hash); err != nil {
		t.Fatal(err)
	}
	h := &AuthHandlers{}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if h.tryRecoveryCode(context.Background(), db, uid, "abcd-efgh") {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("recovery code redeemed %d times, want 1", wins.Load())
	}
}
